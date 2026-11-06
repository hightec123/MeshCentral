//! Native loopback client for dashboard-authorized TCP and UDP forwards.
use crate::remote::UDP_LIMIT;
use anyhow::{Context, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest},
};

type Relay = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn run(args: &[String]) -> Result<()> {
    let [kind, endpoint, rest @ ..] = args else {
        bail!("usage: meshcentral-server forward tcp|udp WEBSOCKET_URL [LOCAL_PORT]");
    };
    ensure!(
        matches!(kind.as_str(), "tcp" | "udp") && rest.len() <= 1,
        "usage: meshcentral-server forward tcp|udp WEBSOCKET_URL [LOCAL_PORT]"
    );
    let port: u16 = rest
        .first()
        .map(|port| port.parse())
        .transpose()?
        .unwrap_or(0);
    let mut request = endpoint.as_str().into_client_request()?;
    let uri = request.uri();
    ensure!(
        uri.query().is_none()
            && uri
                .path()
                .strip_prefix("/api/v1/forward/")
                .is_some_and(valid_token),
        "Use the forwarding URL from the dashboard."
    );
    let host = uri.host().context("The forwarding URL needs a host.")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    ensure!(
        uri.scheme_str() == Some("wss") || (uri.scheme_str() == Some("ws") && loopback),
        "Unencrypted forwarding requires a loopback console URL."
    );

    eprint!("Paste the dashboard's bridge token and press Enter: ");
    std::io::stderr().flush()?;
    let mut token = String::new();
    BufReader::new(std::io::stdin().lock().take(48)).read_line(&mut token)?;
    let token = token.trim_end_matches(['\r', '\n']);
    ensure!(valid_token(token), "Invalid bridge token.");
    let mut authorization: axum::http::HeaderValue = format!("Bearer {token}").parse()?;
    authorization.set_sensitive(true);
    request
        .headers_mut()
        .insert(axum::http::header::AUTHORIZATION, authorization);

    let connector = match std::env::var_os("MCR_FORWARD_CA") {
        Some(path) if uri_is_secure(endpoint) => Some(custom_connector(&path)?),
        _ => None,
    };
    let bind = (Ipv4Addr::LOCALHOST, port);
    // Bind first so a port collision does not consume the one-use credential.
    let tcp = if kind == "tcp" {
        Some(TcpListener::bind(bind).await?)
    } else {
        None
    };
    let udp = if tcp.is_none() {
        Some(UdpSocket::bind(bind).await?)
    } else {
        None
    };
    let (mut relay, _) = timeout(
        Duration::from_secs(10),
        connect_async_tls_with_config(request, None, true, connector),
    )
    .await
    .context("The console did not answer.")?
    .context("Could not attach forwarding client.")?;
    let notice = timeout(Duration::from_secs(120), relay.next()).await?;
    let Some(Ok(Message::Text(notice))) = notice else {
        bail!("Forwarding ended before the agent attached.");
    };
    let notice: serde_json::Value = serde_json::from_str(&notice)?;
    ensure!(
        notice["event"] == "connected" && notice["kind"] == kind.as_str(),
        "The dashboard forwarding protocol does not match the client command."
    );
    let address = if let Some(listener) = &tcp {
        listener.local_addr()?
    } else {
        udp.as_ref()
            .context("missing local UDP socket")?
            .local_addr()?
    };
    println!("{} forward listening on {address}", kind.to_uppercase());
    std::io::stdout().flush()?;
    tokio::select! {
        result = async {
            if let Some(listener) = tcp {
                let (stream, pending) = await_tcp(listener, &mut relay).await?;
                copy_tcp(stream, &mut relay, &pending).await
            } else {
                copy_udp(udp.context("missing local UDP socket")?, &mut relay).await
            }
        } => result,
        signal = tokio::signal::ctrl_c() => { signal?; Ok(()) }
    }
}

fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn uri_is_secure(endpoint: &str) -> bool {
    endpoint.starts_with("wss://")
}

fn custom_connector(path: &std::ffi::OsStr) -> Result<Connector> {
    let pem = std::fs::read(path)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in openssl::x509::X509::stack_from_pem(&pem)? {
        roots.add(rustls::pki_types::CertificateDer::from(cert.to_der()?))?;
    }
    ensure!(
        !roots.is_empty(),
        "MCR_FORWARD_CA contains no certificates."
    );
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

async fn await_tcp(listener: TcpListener, relay: &mut Relay) -> Result<(TcpStream, Vec<u8>)> {
    let mut pending = Vec::new();
    loop {
        tokio::select! {
            result = listener.accept() => return Ok((result?.0, pending)),
            message = relay.next() => match message.transpose()? {
                Some(Message::Binary(bytes)) => {
                    ensure!(pending.len() + bytes.len() <= 1024 * 1024, "Target sent too much before a local TCP client connected.");
                    pending.extend_from_slice(&bytes);
                }
                Some(Message::Ping(_)) => relay.flush().await?,
                Some(Message::Close(_)) | None => bail!("Forwarding ended before a local TCP client connected."),
                _ => {}
            }
        }
    }
}

async fn copy_tcp(mut stream: TcpStream, relay: &mut Relay, pending: &[u8]) -> Result<()> {
    timeout(Duration::from_secs(10), stream.write_all(pending)).await??;
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            read = stream.read(&mut buffer) => {
                let len = read?;
                if len == 0 { return Ok(()); }
                send(relay, &buffer[..len]).await?;
            }
            message = relay.next() => match message.transpose()? {
                Some(Message::Binary(bytes)) => timeout(Duration::from_secs(10), stream.write_all(&bytes)).await??,
                Some(Message::Ping(_)) => relay.flush().await?,
                Some(Message::Close(_)) | None => return Ok(()),
                _ => {}
            }
        }
    }
}

async fn copy_udp(socket: UdpSocket, relay: &mut Relay) -> Result<()> {
    let mut buffer = vec![0u8; UDP_LIMIT + 1];
    let mut peer: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            packet = socket.recv_from(&mut buffer) => {
                let (len, address) = packet?;
                if (1..=UDP_LIMIT).contains(&len) && *peer.get_or_insert(address) == address {
                    send(relay, &buffer[..len]).await?;
                }
            }
            message = relay.next() => match message.transpose()? {
                Some(Message::Binary(bytes)) => {
                    if let Some(address) = peer {
                        socket.send_to(&bytes, address).await?;
                    }
                }
                Some(Message::Ping(_)) => relay.flush().await?,
                Some(Message::Close(_)) | None => return Ok(()),
                _ => {}
            }
        }
    }
}

async fn send(relay: &mut Relay, bytes: &[u8]) -> Result<()> {
    timeout(
        Duration::from_secs(10),
        relay.send(Message::Binary(bytes.to_vec().into())),
    )
    .await??;
    Ok(())
}
