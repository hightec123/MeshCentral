use anyhow::{Context, Result, ensure};
use axum_server::tls_rustls::RustlsConfig;
use meshcentral_server::{
    Config,
    agent::AgentRuntime,
    app_with_runtime,
    auth::AdmissionPolicy,
    identity::{Identity, decode_hex, hex},
    storage,
};
use std::{path::Path, time::Duration};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let config = Config::from_env().map_err(anyhow::Error::msg)?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        ensure!(
            args.len() == 3 && args[0] == "init-lab",
            "usage: meshcentral-server [init-lab NODE_ID_HEX AGENT_MSH_PATH]"
        );
        initialize_lab(&config, &args[1], Path::new(&args[2]))?;
        println!(
            "Lab identity and explicit node policy ready. Agent configuration: {}",
            args[2]
        );
        return Ok(());
    }
    let initialized = config.data_dir.join("identity.json").exists();
    ensure!(
        initialized || !config.data_dir.join("admission.json").exists(),
        "admission policy exists without server identity"
    );
    let runtime = if initialized {
        Some(AgentRuntime::open(&config.data_dir)?)
    } else {
        None
    };
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(address = %listener.local_addr()?, enrollment = runtime.is_some(), "MeshCentral Rust local lab console");
    if !config.web_dir.join("index.html").is_file() {
        tracing::warn!("Frontend not built; run npm --prefix web run build or use Vite.");
    }

    let tls_handle = axum_server::Handle::new();
    let tls_task = if let Some(runtime) = runtime.clone() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let tls = RustlsConfig::from_pem(
            runtime.identity.tls_certificate.to_pem()?,
            runtime.identity.tls_key.private_key_to_pem_pkcs8()?,
        )
        .await?;
        let native_listener = std::net::TcpListener::bind(config.agent_listen)?;
        native_listener.set_nonblocking(true)?;
        tracing::info!(address = %native_listener.local_addr()?, "native lab agent TLS listener");
        let handle = tls_handle.clone();
        Some(tokio::spawn(async move {
            axum_server::from_tcp_rustls(native_listener, tls)
                .handle(handle)
                .serve(meshcentral_server::agent::router(runtime).into_make_service())
                .await
        }))
    } else {
        None
    };

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut http_task = tokio::spawn(async move {
        axum::serve(listener, app_with_runtime(config.web_dir, runtime))
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await
    });

    if let Some(mut native) = tls_task {
        tokio::select! {
            () = shutdown() => {
                tls_handle.graceful_shutdown(Some(Duration::from_secs(2)));
                let _ = stop_tx.send(());
                http_task.await??;
                native.await??;
            }
            result = &mut http_task => { tls_handle.shutdown(); native.abort(); result??; anyhow::bail!("HTTP listener stopped unexpectedly"); }
            result = &mut native => { let _ = stop_tx.send(()); http_task.await??; result??; anyhow::bail!("native agent listener stopped unexpectedly"); }
        }
    } else {
        tokio::select! {
            () = shutdown() => { let _ = stop_tx.send(()); http_task.await??; }
            result = &mut http_task => { result??; anyhow::bail!("HTTP listener stopped unexpectedly"); }
        }
    }
    Ok(())
}

fn initialize_lab(config: &Config, node: &str, msh_path: &Path) -> Result<()> {
    ensure!(
        config.agent_listen.port() != 0,
        "lab configuration requires a fixed agent port"
    );
    let node = hex(&decode_hex::<48>(node)?);
    let _state_lock = storage::lock_directory(&config.data_dir)?;
    let identity_path = config.data_dir.join("identity.json");
    ensure!(
        identity_path.exists()
            || (!config.data_dir.join("admission.json").exists()
                && !config.data_dir.join("inventory.json").exists()),
        "server identity is missing from an existing lab; restore it instead of generating new trust"
    );
    let identity = if identity_path.exists() {
        Identity::load(&identity_path)?
    } else {
        let identity = Identity::generate()?;
        identity.save_new(&identity_path)?;
        identity
    };
    let policy_path = config.data_dir.join("admission.json");
    let policy = if policy_path.exists() {
        AdmissionPolicy::load(&policy_path)?
    } else {
        let policy = AdmissionPolicy::lab(&node)?;
        storage::write_new(&policy_path, &serde_json::to_vec_pretty(&policy)?)?;
        policy
    };
    ensure!(
        policy
            .allowed_node_ids_hex
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&node)),
        "node is not in the existing lab policy; no automatic policy expansion"
    );
    storage::private_directory(
        msh_path
            .parent()
            .context("agent configuration needs a parent directory")?,
    )?;
    let msh = format!(
        "MeshName={}\r\nMeshType=2\r\nMeshID=0x{}\r\nServerID={}\r\nMeshServer=wss://{}/agent.ashx\r\nignoreProxyFile=1\r\n",
        policy.group_name,
        policy.mesh_id_hex,
        hex(&identity.server_id),
        config.agent_listen
    );
    if msh_path.exists() {
        ensure!(
            std::fs::read(msh_path)? == msh.as_bytes(),
            "agent configuration already exists with different contents; refusing to overwrite"
        );
    } else {
        storage::write_new(msh_path, msh.as_bytes())?;
    }
    Ok(())
}

async fn shutdown() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "could not install terminate handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = interrupt => {}, () = terminate => {}, }
}
