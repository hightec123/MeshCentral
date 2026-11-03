use std::{error::Error, io};

use meshcentral_server::{Config, app};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env().map_err(io::Error::other)?;
    let listener = TcpListener::bind(config.listen).await?;
    let address = listener.local_addr()?;
    tracing::info!(%address, "MeshCentral Rust development server; enrollment disabled");
    if !config.web_dir.join("index.html").is_file() {
        tracing::warn!(
            "Frontend not built. Run npm --prefix web ci and npm --prefix web run build, or use the Vite development server."
        );
    }
    axum::serve(listener, app(config.web_dir))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "could not install the interrupt handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "could not install the terminate handler"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {},
        () = terminate => {},
    }
}
