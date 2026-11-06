use anyhow::{Context, Result, ensure};
use axum_server::tls_rustls::RustlsConfig;
use meshcentral_server::{
    Config,
    agent::AgentRuntime,
    app_with_console_origin,
    auth::AdmissionPolicy,
    identity::{Identity, decode_hex, hex},
    storage,
};
use std::{path::Path, time::Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|argument| argument == "forward") {
        return meshcentral_server::forward::run(&args[1..]).await;
    }
    let config = Config::from_env().map_err(anyhow::Error::msg)?;
    if !args.is_empty() {
        if (args.len() == 2 && args[0] == "backup") || (args.len() == 3 && args[0] == "restore") {
            use std::io::Read;
            let mut password = String::new();
            std::io::stdin().take(130).read_to_string(&mut password)?;
            let password = password.trim_end_matches(['\r', '\n']);
            if args[0] == "backup" {
                meshcentral_server::backup::create(
                    &config.data_dir,
                    Path::new(&args[1]),
                    password,
                )?;
                println!("Encrypted offline backup created.");
            } else {
                meshcentral_server::backup::restore(
                    Path::new(&args[1]),
                    Path::new(&args[2]),
                    password,
                )?;
                println!(
                    "Backup restored into a new private state directory. All devices start offline; sign in again."
                );
            }
            return Ok(());
        }
        if args.len() == 2 && args[0] == "init-user" {
            use std::io::Read;
            let _lock = storage::lock_directory(&config.data_dir)?;
            let mut password = String::new();
            std::io::stdin().take(130).read_to_string(&mut password)?;
            let operators = meshcentral_server::operators::Operators::open(&config.data_dir)?;
            operators.bootstrap(&args[1], password.trim_end_matches(['\r', '\n']))?;
            let mut auth = meshcentral_server::dashboard_auth::AuthProcess::start(
                &config.data_dir,
                &config.console_origin(),
                &operators,
            )
            .await?;
            auth.shutdown().await;
            println!("Administrator created. Sign in through the local console.");
            return Ok(());
        }
        ensure!(
            args.len() == 3 && args[0] == "init-lab",
            "usage: meshcentral-server [init-user USERNAME | init-lab NODE_ID_HEX AGENT_MSH_PATH | backup ARCHIVE | restore ARCHIVE NEW_DATA_DIR | forward tcp|udp WEBSOCKET_URL [LOCAL_PORT]]"
        );
        initialize_lab(&config, &args[1], Path::new(&args[2]))?;
        println!(
            "Lab identity and explicit node policy ready. Agent configuration: {}",
            args[2]
        );
        return Ok(());
    }
    let console_origin = config.console_origin();
    let console_tls = if let Some(tls) = &config.console_tls {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        Some(
            RustlsConfig::from_pem_file(&tls.cert, &tls.key)
                .await
                .context("loading console TLS certificate and key")?,
        )
    } else {
        None
    };
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
    let _console_lock = if !initialized {
        Some(storage::lock_directory(&config.data_dir)?)
    } else {
        None
    };
    let operators = meshcentral_server::operators::Operators::open(&config.data_dir)?;
    // Keep the state lock until the auth database has closed, even after both
    // public listeners and their router state have been dropped.
    let _runtime_lifetime = runtime.clone();
    let mut auth = meshcentral_server::dashboard_auth::AuthProcess::start(
        &config.data_dir,
        &console_origin,
        &operators,
    )
    .await?;
    let monitor_store = operators.clone();
    let monitor_runtime = runtime.clone();
    let monitor = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tick.tick().await;
            monitor_store.revalidate_dashboard_sessions().await;
            if let Some(rt) = &monitor_runtime {
                rt.relays.close_inactive(&monitor_store);
            }
        }
    });
    if let Some(runtime) = &runtime {
        *runtime
            .agent_address
            .write()
            .unwrap_or_else(|e| e.into_inner()) = config.agent_listen;
        *runtime.audit.write().unwrap_or_else(|e| e.into_inner()) = Some(operators.audit.clone());
    }
    let listener = std::net::TcpListener::bind(config.listen)?;
    listener.set_nonblocking(true)?;
    tracing::info!(address = %listener.local_addr()?, origin = %console_origin, enrollment = runtime.is_some(), "MeshCentral Rust console");
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

    let scheduler = runtime.clone().map(|agent| {
        tokio::spawn(meshcentral_server::schedules::worker(
            operators.clone(),
            agent,
        ))
    });
    let console_handle = axum_server::Handle::new();
    let handle = console_handle.clone();
    let mut console_task = tokio::spawn(async move {
        let app = app_with_console_origin(
            config.web_dir,
            runtime,
            Some(operators),
            config.console_tls.map(|tls| tls.origin),
        )
        .into_make_service();
        match console_tls {
            Some(tls) => {
                axum_server::from_tcp_rustls(listener, tls)
                    .handle(handle)
                    .serve(app)
                    .await
            }
            None => {
                axum_server::from_tcp(listener)
                    .handle(handle)
                    .serve(app)
                    .await
            }
        }
    });

    if let Some(mut native) = tls_task {
        tokio::select! {
            () = shutdown() => {
                tls_handle.graceful_shutdown(Some(Duration::from_secs(2)));
                console_handle.graceful_shutdown(Some(Duration::from_secs(2)));
                console_task.await??;
                native.await??;
            }
            result = &mut console_task => { tls_handle.shutdown(); native.abort(); result??; anyhow::bail!("console listener stopped unexpectedly"); }
            result = &mut native => { console_handle.graceful_shutdown(Some(Duration::from_secs(2))); console_task.await??; result??; anyhow::bail!("native agent listener stopped unexpectedly"); }
            result=auth.wait()=>{tls_handle.shutdown();console_task.abort();native.abort();monitor.abort();result?;}
        }
    } else {
        tokio::select! {
            () = shutdown() => { console_handle.graceful_shutdown(Some(Duration::from_secs(2))); console_task.await??; }
            result = &mut console_task => { result??; anyhow::bail!("console listener stopped unexpectedly"); }
            result=auth.wait()=>{console_task.abort();monitor.abort();result?;}
        }
    }
    monitor.abort();
    if let Some(scheduler) = scheduler {
        scheduler.abort();
        let _ = scheduler.await;
    }
    auth.shutdown().await;
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
