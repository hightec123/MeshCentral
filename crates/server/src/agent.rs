use crate::{
    auth::{AdmissionPolicy, AuthenticatedPeer, Handshake},
    identity::Identity,
    registry::Registry,
    storage,
};
use anyhow::{Result, bail, ensure};
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::Value;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{
    sync::Semaphore,
    time::{Instant, interval, timeout},
};

pub struct AgentRuntime {
    _state_lock: std::fs::File,
    pub identity: Arc<Identity>,
    pub policy: Arc<AdmissionPolicy>,
    pub registry: Arc<Registry>,
    sockets: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}

impl AgentRuntime {
    pub fn open(directory: &Path) -> Result<Arc<Self>> {
        let state_lock = storage::lock_directory(directory)?;
        Ok(Arc::new(Self {
            _state_lock: state_lock,
            identity: Arc::new(Identity::load(&directory.join("identity.json"))?),
            policy: Arc::new(AdmissionPolicy::load(&directory.join("admission.json"))?),
            registry: Registry::open(directory.join("inventory.json"))?,
            sockets: Arc::new(Semaphore::new(32)),
            handshakes: Arc::new(Semaphore::new(8)),
        }))
    }
}

pub fn router(runtime: Arc<AgentRuntime>) -> Router {
    Router::new()
        .route("/agent.ashx", get(upgrade))
        .with_state(runtime)
}

async fn upgrade(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // This is a native-agent listener. Browser-origin WebSockets are not admitted.
    if headers.contains_key("origin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(socket_permit) = runtime.sockets.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(handshake_permit) = runtime.handshakes.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(16 * 1024).max_frame_size(16 * 1024).on_upgrade(move |mut socket| async move {
        let _socket_permit = socket_permit;
        let result = timeout(Duration::from_secs(15), authenticate(&mut socket, &runtime)).await;
        drop(handshake_permit);
        let peer = match result {
            Ok(Ok(peer)) => peer,
            Ok(Err(error)) => { tracing::warn!(%error, "agent authentication rejected"); let _ = socket.send(Message::Close(None)).await; return; }
            Err(_) => { tracing::warn!("agent authentication timed out"); let _ = socket.send(Message::Close(None)).await; return; }
        };
        let node_id = peer.node_id.clone();
        let presence = match runtime.registry.connect(peer) {
            Ok(presence) => presence,
            Err(error) => { tracing::warn!(%error, "agent admission rejected"); let _ = socket.send(Message::Close(None)).await; return; }
        };
        if socket.send(Message::Binary(vec![0, 4].into())).await.is_err() { return; }
        tracing::info!(%node_id, "authenticated lab agent online");
        let mut ping = interval(Duration::from_secs(30));
        let mut last_received = Instant::now();
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    if last_received.elapsed() > Duration::from_secs(150) { break; }
                    if socket.send(Message::Ping(vec![0x4d, 0x43].into())).await.is_err() { break; }
                }
                message = socket.recv() => {
                    match message {
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(Message::Ping(bytes))) => { if socket.send(Message::Pong(bytes)).await.is_err() { break; } }
                        Some(Ok(Message::Text(text))) => { if is_ping(text.as_bytes()) && socket.send(Message::Text("{\"action\":\"pong\"}".into())).await.is_err() { break; } }
                        Some(Ok(Message::Binary(bytes))) => { if is_ping(&bytes) && socket.send(Message::Binary(b"{\"action\":\"pong\"}".to_vec().into())).await.is_err() { break; } }
                        Some(Ok(Message::Pong(_))) => {}
                    }
                    last_received = Instant::now();
                    presence.touch();
                    // No core update, remote command, or relay instruction is sent.
                }
            }
        }
        drop(presence);
        tracing::info!(%node_id, "lab agent offline");
        let _ = socket.send(Message::Close(None)).await;
    }).into_response()
}

fn is_ping(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'{')
        && serde_json::from_slice::<Value>(bytes).is_ok_and(|value| value["action"] == "ping")
}

async fn authenticate(socket: &mut WebSocket, runtime: &AgentRuntime) -> Result<AuthenticatedPeer> {
    let mut handshake = Handshake::new(runtime.identity.clone(), runtime.policy.clone())?;
    let mut agent_name_seen = false;
    for _ in 0..12 {
        let bytes = match socket.recv().await {
            Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
            Some(Ok(Message::Ping(bytes))) => {
                socket.send(Message::Pong(bytes)).await?;
                continue;
            }
            Some(Ok(Message::Text(text))) => text.as_bytes().to_vec(),
            _ => bail!("agent disconnected during authentication"),
        };
        if bytes.first() == Some(&b'{') {
            let value: Value = serde_json::from_slice(&bytes)?;
            ensure!(
                !agent_name_seen
                    && value["action"] == "agentName"
                    && value["value"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty() && name.len() <= 255),
                "unsupported unauthenticated JSON"
            );
            agent_name_seen = true;
            continue;
        }
        // RSA operations run outside the async executor. Socket/handshake limits,
        // frame/key bounds, duplicate rejection and the deadline bound this work.
        let result = tokio::task::spawn_blocking(move || -> Result<_> {
            let replies = handshake.receive(&bytes)?;
            let peer = handshake.finish()?;
            Ok((handshake, replies, peer))
        })
        .await??;
        handshake = result.0;
        for reply in result.1 {
            socket.send(Message::Binary(reply.into())).await?;
        }
        if let Some(peer) = result.2 {
            return Ok(peer);
        }
    }
    bail!("too many authentication messages")
}
