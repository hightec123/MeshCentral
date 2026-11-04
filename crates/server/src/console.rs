use crate::{
    AppState,
    operators::{Operators, Principal, User},
};
use axum::{
    Json, Router,
    extract::{Extension, Path, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub type ApiResult<T> = Result<T, ApiFailure>;
pub struct ApiFailure(pub StatusCode, pub String);
impl IntoResponse for ApiFailure {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(json!({"code":"request_failed","message":self.1})),
        )
            .into_response()
    }
}
pub fn bad(error: impl std::fmt::Display) -> ApiFailure {
    ApiFailure(StatusCode::BAD_REQUEST, error.to_string())
}
pub fn forbidden() -> ApiFailure {
    ApiFailure(StatusCode::FORBIDDEN, "Permission denied.".into())
}
pub fn unauthorized() -> ApiFailure {
    ApiFailure(StatusCode::UNAUTHORIZED, "Sign in to continue.".into())
}
pub fn operators(state: &AppState) -> ApiResult<Arc<Operators>> {
    state.operators.clone().ok_or_else(unauthorized)
}

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/auth/session", get(session))
        .route("/v1/auth/login", post(login))
}
pub fn protected_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/password", post(password))
        .route("/v1/users", get(users).post(save_user))
        .route("/v1/users/{username}", delete(delete_user))
        .route("/v1/audit", get(audit))
        .route_layer(middleware::from_fn_with_state(state, require_operator))
}
pub fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("mcr_session="))
}
pub fn same_origin(headers: &HeaderMap) -> bool {
    if headers
        .get("sec-fetch-site")
        .is_some_and(|v| v == "cross-site")
    {
        return false;
    }
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin
        .to_str()
        .ok()
        .and_then(|v| v.parse::<axum::http::Uri>().ok())
        .is_some_and(|origin| {
            matches!(origin.scheme_str(), Some("http" | "https"))
                && origin.authority().is_some_and(|a| a.as_str() == host)
        })
}
pub async fn require_operator(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(store) = state.operators.as_ref() else {
        return unauthorized().into_response();
    };
    let Some(principal) = token(request.headers()).and_then(|t| store.authenticate(t)) else {
        return unauthorized().into_response();
    };
    if !same_origin(request.headers()) {
        return forbidden().into_response();
    }
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        let csrf = request
            .headers()
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if csrf.len() != principal.csrf.len()
            || !openssl::memcmp::eq(csrf.as_bytes(), principal.csrf.as_bytes())
        {
            return forbidden().into_response();
        }
    }
    request.extensions_mut().insert(principal);
    next.run(request).await
}
async fn session(State(state): State<AppState>, headers: HeaderMap) -> Json<serde_json::Value> {
    let principal = state
        .operators
        .as_ref()
        .and_then(|store| token(&headers).and_then(|t| store.authenticate(t)));
    Json(match principal {
        Some(p) => json!({"user":p.user,"csrf":p.csrf,"setup_required":false}),
        None => {
            json!({"user":null,"csrf":null,"setup_required":state.operators.as_ref().is_none_or(|s|!s.initialized())})
        }
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> ApiResult<Response> {
    if !same_origin(&headers) {
        return Err(forbidden());
    }
    let store = operators(&state)?;
    let (cookie,p)=store.login(&body.username,body.password).await.map_err(|_|ApiFailure(StatusCode::UNAUTHORIZED,"Sign-in failed. Check your credentials, or wait one minute after repeated attempts.".into()))?;
    let mut response =
        Json(json!({"user":p.user,"csrf":p.csrf,"setup_required":false})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("mcr_session={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800")
            .parse()
            .unwrap(),
    );
    Ok(response)
}
async fn logout(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Response> {
    operators(&state)?.logout(&p).map_err(bad)?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        "mcr_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok(response)
}
#[derive(Deserialize)]
struct Password {
    current: String,
    new: String,
}
async fn password(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(body): Json<Password>,
) -> ApiResult<StatusCode> {
    operators(&state)?
        .change_password(&p, body.current, body.new)
        .await
        .map_err(bad)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn users(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<serde_json::Value>> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    Ok(Json(json!({"users":operators(&state)?.users()})))
}
#[derive(Deserialize)]
struct SaveUser {
    user: User,
    password: Option<String>,
}
async fn save_user(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(body): Json<SaveUser>,
) -> ApiResult<StatusCode> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    let store = operators(&state)?;
    tokio::task::spawn_blocking(move || store.save_user(&p, body.user, body.password.as_deref()))
        .await
        .map_err(bad)?
        .map_err(bad)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn delete_user(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(username): Path<String>,
) -> ApiResult<StatusCode> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    operators(&state)?.delete_user(&p, &username).map_err(bad)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn audit(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<serde_json::Value>> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    Ok(Json(json!({"events":operators(&state)?.audit.snapshot()})))
}
