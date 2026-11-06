use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

pub mod agent;
pub mod auth;
pub mod backup;
pub mod console;
pub mod core;
pub mod dashboard_auth;
pub mod identity;
pub mod management;
pub mod operators;
pub mod registry;
pub mod remote;
pub mod storage;

use axum::{
    Json, Router,
    extract::Request,
    extract::State,
    http::{HeaderValue, StatusCode, Uri, header},
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
    pub console_tls: Option<ConsoleTls>,
}

#[derive(Debug)]
pub struct ConsoleTls {
    pub origin: Uri,
    pub cert: PathBuf,
    pub key: PathBuf,
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
        let console_tls = match (
            std::env::var_os("MCR_CONSOLE_ORIGIN"),
            std::env::var_os("MCR_CONSOLE_CERT"),
            std::env::var_os("MCR_CONSOLE_KEY"),
        ) {
            (None, None, None) => None,
            (Some(origin), Some(cert), Some(key)) => {
                let raw = origin.to_str().ok_or("Invalid console origin")?;
                let url = reqwest::Url::parse(raw).map_err(|_| "Invalid console origin")?;
                let canonical = url.origin().ascii_serialization();
                if url.scheme() != "https" || canonical != raw {
                    return Err("MCR_CONSOLE_ORIGIN must be a canonical HTTPS origin without a path, such as https://localhost:3443".into());
                }
                Some(ConsoleTls {
                    origin: canonical.parse().map_err(|_| "Invalid console origin")?,
                    cert: cert.into(),
                    key: key.into(),
                })
            }
            _ => {
                return Err(
                    "Set MCR_CONSOLE_ORIGIN, MCR_CONSOLE_CERT and MCR_CONSOLE_KEY together".into(),
                );
            }
        };
        Ok(Self {
            listen,
            agent_listen,
            data_dir,
            web_dir,
            console_tls,
        })
    }

    pub fn console_origin(&self) -> String {
        self.console_tls.as_ref().map_or_else(
            || format!("http://{}", self.listen),
            |tls| format!("https://{}", tls.origin.authority().unwrap()),
        )
    }
}

/// Both console transports and the native agent listener bind to loopback.
pub fn validate_listen(address: SocketAddr) -> Result<(), String> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err("this development preview only accepts a loopback MCR_LISTEN address".into())
    }
}

#[derive(Clone)]
pub struct AppState {
    started: Instant,
    runtime: Option<Arc<agent::AgentRuntime>>,
    operators: Option<Arc<operators::Operators>>,
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
    #[serde(default)]
    pub group_id: String,
    #[serde(default)]
    pub node_id_hex: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub details: serde_json::Value,
    #[serde(default)]
    pub core_ready: bool,
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
    app_with_services(web_dir, runtime, None)
}

pub fn app_with_services(
    web_dir: PathBuf,
    runtime: Option<Arc<agent::AgentRuntime>>,
    operators: Option<Arc<operators::Operators>>,
) -> Router {
    app_with_console_origin(web_dir, runtime, operators, None)
}

pub fn app_with_console_origin(
    web_dir: PathBuf,
    runtime: Option<Arc<agent::AgentRuntime>>,
    operators: Option<Arc<operators::Operators>>,
    console_origin: Option<Uri>,
) -> Router {
    let state = AppState {
        started: Instant::now(),
        runtime,
        operators,
    };
    let protected = Router::new()
        .route("/v1/devices", get(inventory))
        .merge(management::routes())
        .merge(remote::routes())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            console::require_operator,
        ));
    let api = Router::new()
        .route("/v1/server", get(server_info))
        .merge(console::public_routes())
        .merge(console::protected_routes(state.clone()))
        .merge(protected)
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
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            ),
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(console_origin, validate_authority))
        .layer(axum::extract::DefaultBodyLimit::max(64*1024))
        .with_state(state)
}

async fn validate_authority(
    State(console_origin): State<Option<Uri>>,
    mut request: Request,
    next: Next,
) -> axum::response::Response {
    // HTTP/2 clients can split cookies across fields. Reassemble them before
    // session checks or proxying a WebAuthn challenge to Better Auth.
    let cookies = request.headers().get_all(header::COOKIE);
    if cookies.iter().nth(1).is_some() {
        let bytes = cookies
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>()
            .join(b"; ".as_slice());
        let Ok(mut cookie) = HeaderValue::from_bytes(&bytes) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        cookie.set_sensitive(true);
        request.headers_mut().insert(header::COOKIE, cookie);
    }
    if let Some(origin) = console_origin {
        let authority = origin.authority().expect("configured console authority");
        let target = request.uri().authority();
        let host = request.headers().get(header::HOST);
        // HTTP/2 supplies :authority. Check both fields when both are present.
        if (target.is_none() && host.is_none())
            || target.is_some_and(|value| value.as_str() != authority.as_str())
            || host.is_some_and(|value| value.as_bytes() != authority.as_str().as_bytes())
            || request
                .headers()
                .get(header::ORIGIN)
                .is_some_and(|value| value.as_bytes() != format!("https://{authority}").as_bytes())
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        request.headers_mut().insert(
            header::HOST,
            HeaderValue::from_str(authority.as_str()).expect("validated console authority"),
        );
        return next.run(request).await;
    }
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
            remote_desktop: state.runtime.as_ref().is_some_and(|r| r.cores.available()),
            terminal: state.runtime.as_ref().is_some_and(|r| r.cores.available()),
            file_transfer: state.runtime.as_ref().is_some_and(|r| r.cores.available()),
        },
    })
}

async fn inventory(
    State(state): State<AppState>,
    axum::Extension(principal): axum::Extension<operators::Principal>,
) -> Json<Inventory> {
    Json(Inventory {
        devices: state
            .runtime
            .map(|runtime| {
                let policy = runtime.policy.read().unwrap_or_else(|e| e.into_inner());
                runtime
                    .registry
                    .snapshot()
                    .into_iter()
                    .map(|mut device| {
                        if let Some(group) = policy.group(&device.group_id) {
                            device.group = group.group_name;
                        }
                        device
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .filter(|d| principal.user.can_view(&d.group_id))
            .collect(),
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
