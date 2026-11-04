use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

pub mod agent;
pub mod auth;
pub mod identity;
pub mod registry;
pub mod storage;

use axum::{
    Json, Router,
    extract::Request,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{any, get},
};
use serde::{Deserialize, Serialize};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer, trace::TraceLayer};

#[derive(Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub agent_listen: SocketAddr,
    pub data_dir: PathBuf,
    pub web_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let address = std::env::var("MCR_LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".into());
        let listen = address
            .parse::<SocketAddr>()
            .map_err(|_| "MCR_LISTEN must be an IP address and port, such as 127.0.0.1:3000")?;
        validate_listen(listen)?;
        let agent_listen = std::env::var("MCR_AGENT_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8443".into())
            .parse::<SocketAddr>()
            .map_err(|_| "invalid MCR_AGENT_LISTEN")?;
        validate_listen(agent_listen)?;
        let data_dir = std::env::var_os("MCR_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| ".local/server".into());
        let web_dir = std::env::var_os("MCR_WEB_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("web/dist"));
        Ok(Self {
            listen,
            agent_listen,
            data_dir,
            web_dir,
        })
    }
}

/// The first slice has no user authentication. Do not expose its HTTP interface
/// on a network until that boundary is implemented; there is no override switch.
pub fn validate_listen(address: SocketAddr) -> Result<(), String> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err("this development preview only accepts a loopback MCR_LISTEN address".into())
    }
}

#[derive(Clone)]
struct AppState {
    started: Instant,
    runtime: Option<Arc<agent::AgentRuntime>>,
}

#[derive(Serialize)]
pub struct Capabilities {
    pub agent_enrollment: bool,
    pub remote_desktop: bool,
    pub terminal: bool,
    pub file_transfer: bool,
}

#[derive(Serialize)]
pub struct ServerInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub api_version: u32,
    pub uptime_seconds: u64,
    pub capabilities: Capabilities,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Online,
    Offline,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub group: String,
    pub platform: String,
    pub status: DeviceStatus,
    pub last_seen: Option<String>,
}

#[derive(Serialize)]
struct Inventory {
    devices: Vec<Device>,
}

#[derive(Serialize)]
struct ApiError {
    code: &'static str,
    message: &'static str,
}

pub fn app(web_dir: PathBuf) -> Router {
    app_with_runtime(web_dir, None)
}

pub fn app_with_runtime(web_dir: PathBuf, runtime: Option<Arc<agent::AgentRuntime>>) -> Router {
    let api = Router::new()
        .route("/v1/server", get(server_info))
        .route("/v1/devices", get(inventory))
        .fallback(api_not_found);

    Router::new()
        .route("/healthz", get(health))
        .nest("/api", api)
        .route("/agent.ashx", any(agent_unavailable))
        .route("/meshrelay.ashx", any(relay_unavailable))
        .fallback_service(ServeDir::new(web_dir))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            ),
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(local_host_only))
        .with_state(AppState {
            started: Instant::now(),
            runtime,
        })
}

async fn local_host_only(request: Request, next: Next) -> axum::response::Response {
    // Binding to loopback alone does not prevent browser DNS rebinding.
    if let Some(host) = request.headers().get(header::HOST) {
        let valid = host
            .to_str()
            .ok()
            .and_then(|host| host.parse::<axum::http::uri::Authority>().ok())
            .is_some_and(|authority| {
                let host = authority.host().trim_matches(['[', ']']);
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
        if !valid {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    next.run(request).await
}

async fn health() -> Json<impl Serialize> {
    #[derive(Serialize)]
    struct Health {
        status: &'static str,
    }
    Json(Health { status: "ok" })
}

async fn server_info(State(state): State<AppState>) -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "MeshCentral Rust",
        version: env!("CARGO_PKG_VERSION"),
        api_version: 1,
        uptime_seconds: state.started.elapsed().as_secs(),
        capabilities: Capabilities {
            agent_enrollment: state.runtime.is_some(),
            remote_desktop: false,
            terminal: false,
            file_transfer: false,
        },
    })
}

async fn inventory(State(state): State<AppState>) -> Json<Inventory> {
    Json(Inventory {
        devices: state
            .runtime
            .map(|runtime| runtime.registry.snapshot())
            .unwrap_or_default(),
    })
}

async fn agent_unavailable() -> impl IntoResponse {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "agent_enrollment_unavailable",
        "Agent enrollment is not available in this development preview.",
    )
}

async fn relay_unavailable() -> impl IntoResponse {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "remote_sessions_unavailable",
        "Remote sessions are not available in this development preview.",
    )
}

async fn api_not_found() -> impl IntoResponse {
    error(StatusCode::NOT_FOUND, "not_found", "API route not found.")
}

fn error(status: StatusCode, code: &'static str, message: &'static str) -> impl IntoResponse {
    (status, Json(ApiError { code, message }))
}
