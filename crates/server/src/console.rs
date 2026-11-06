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
        .route("/auth/{*path}", axum::routing::any(auth_proxy))
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
    let principal = if store.auth().is_some() {
        match store.dashboard_principal(cookie(request.headers())).await {
            Ok(value) => value,
            Err(_) => return auth_unavailable().into_response(),
        }
    } else {
        token(request.headers()).and_then(|t| store.authenticate(t))
    };
    let Some(principal) = principal else {
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
async fn session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let principal = if let Some(store) = &state.operators {
        if store.auth().is_some() {
            store
                .dashboard_principal(cookie(&headers))
                .await
                .map_err(|_| auth_unavailable())?
        } else {
            token(&headers).and_then(|t| store.authenticate(t))
        }
    } else {
        None
    };
    let mut view = match principal {
        Some(p) => json!({"user":p.user,"csrf":p.csrf,"setup_required":false}),
        None => {
            json!({"user":null,"csrf":null,"setup_required":state.operators.as_ref().is_none_or(|s|!s.initialized())})
        }
    };
    view["email_recovery"] = json!(
        state
            .operators
            .as_ref()
            .and_then(|store| store.auth())
            .is_some_and(|auth| auth.email_recovery)
    );
    Ok(Json(view))
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
    if let Some(auth) = store.auth() {
        let mut reply = auth
            .request(
                "sign-in/username",
                "POST",
                &headers,
                serde_json::to_vec(&json!({"username":body.username,"password":body.password}))
                    .map_err(bad)?,
            )
            .await
            .map_err(|_| auth_unavailable())?;
        let challenge = is_mfa_challenge(&reply);
        if challenge {
            reply.status = StatusCode::ACCEPTED;
        } else if reply.status.is_success() {
            let principal = store
                .dashboard_principal(&reply_cookie(&reply))
                .await
                .map_err(|_| auth_unavailable())?
                .ok_or_else(forbidden)?;
            reply.body = serde_json::to_vec(
                &json!({"user":principal.user,"csrf":principal.csrf,"setup_required":false}),
            )
            .map_err(bad)?;
        }
        let _ = store.audit.record(
            &body.username,
            "account.login",
            "",
            if challenge {
                "challenge"
            } else if reply.status.is_success() {
                "success"
            } else {
                "denied"
            },
        );
        return Ok(reply_response(reply));
    }
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
    headers: HeaderMap,
) -> ApiResult<Response> {
    if operators(&state)?.auth().is_some() {
        return proxy(&state, "sign-out", "POST", &headers, b"{}".to_vec()).await;
    }
    operators(&state)?.logout(&p).map_err(bad)?;
    if let Some(rt) = &state.runtime {
        rt.relays.close_owner(&p.session_key);
    }
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
    headers: HeaderMap,
    Json(body): Json<Password>,
) -> ApiResult<StatusCode> {
    if operators(&state)?.auth().is_some() {
        let response=proxy(&state,"change-password","POST",&headers,serde_json::to_vec(&json!({"currentPassword":body.current,"newPassword":body.new,"revokeOtherSessions":true})).map_err(bad)?).await?;
        if response.status().is_success() {
            return Ok(StatusCode::NO_CONTENT);
        } else {
            return Err(bad("Password change failed. Check your current password."));
        }
    }
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
    if store.auth().is_some() {
        store
            .save_dashboard_user(&p, body.user.clone(), body.password)
            .await
            .map_err(bad)?;
        if let Some(rt) = &state.runtime {
            rt.relays.close_username(&body.user.username);
        }
        return Ok(StatusCode::NO_CONTENT);
    }
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
    let store = operators(&state)?;
    let id = store.auth_user_id(&username);
    store.delete_user(&p, &username).map_err(bad)?;
    if let Some(rt) = &state.runtime {
        rt.relays.close_username(&username);
    }
    if let (Some(auth), Some(id)) = (store.auth(), id) {
        auth.internal("delete-user", json!({"user_id":id}))
            .await
            .map_err(bad)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub fn cookie(headers: &HeaderMap) -> &str {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}
fn auth_unavailable() -> ApiFailure {
    ApiFailure(
        StatusCode::SERVICE_UNAVAILABLE,
        "Dashboard authentication is unavailable. Retry shortly.".into(),
    )
}
fn reply_response(reply: crate::dashboard_auth::Reply) -> Response {
    (reply.status, reply.headers, reply.body).into_response()
}
fn reply_cookie(reply: &crate::dashboard_auth::Reply) -> String {
    reply
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}
fn is_mfa_challenge(reply: &crate::dashboard_auth::Reply) -> bool {
    reply.status.is_success()
        && serde_json::from_slice::<serde_json::Value>(&reply.body)
            .is_ok_and(|value| value["twoFactorRedirect"] == true)
}
async fn auth_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let method = request.method().as_str().to_owned();
    let headers = request.headers().clone();
    let body = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(bad)?;
    proxy(&state, &path, &method, &headers, body.to_vec()).await
}
async fn proxy(
    state: &AppState,
    path: &str,
    method: &str,
    headers: &HeaderMap,
    mut body: Vec<u8>,
) -> ApiResult<Response> {
    if !crate::dashboard_auth::allowed_path(path) {
        return Err(ApiFailure(
            StatusCode::NOT_FOUND,
            "Unknown authentication endpoint.".into(),
        ));
    }
    if !same_origin(headers) {
        return Err(forbidden());
    }
    let store = operators(state)?;
    let auth = store.auth().ok_or_else(auth_unavailable)?;
    let mfa_settings = matches!(
        path,
        "two-factor/enable" | "two-factor/disable" | "two-factor/generate-backup-codes"
    );
    let mfa_verify = matches!(
        path,
        "two-factor/verify-totp" | "two-factor/verify-backup-code"
    );
    let recovery_settings = path == "recovery-email";
    let recovery_post = matches!(
        path,
        "verify-recovery-email" | "request-password-reset" | "reset-password"
    );
    let passkey_settings = matches!(
        path,
        "passkey/generate-register-options"
            | "passkey/verify-registration"
            | "passkey/list-user-passkeys"
            | "passkey/delete-passkey"
    );
    let passkey_get = matches!(
        path,
        "passkey/generate-register-options"
            | "passkey/generate-authenticate-options"
            | "passkey/list-user-passkeys"
    );
    let mutation = [
        "sign-out",
        "change-password",
        "revoke-session",
        "revoke-sessions",
        "revoke-other-sessions",
    ]
    .contains(&path);
    if !["GET", "POST"].contains(&method)
        || ((mutation || mfa_settings || mfa_verify || recovery_post) && method != "POST")
        || (path.starts_with("passkey/") && passkey_get != (method == "GET"))
    {
        return Err(bad("Unsupported auth method."));
    }
    let principal = if mfa_settings || mfa_verify || passkey_settings || recovery_settings {
        store
            .dashboard_principal(cookie(headers))
            .await
            .map_err(|_| auth_unavailable())?
    } else if mutation {
        store
            .dashboard_principal(cookie(headers))
            .await
            .ok()
            .flatten()
            .or_else(|| store.cached_dashboard(cookie(headers)))
    } else {
        None
    };
    if (mfa_settings || passkey_settings || recovery_settings) && principal.is_none() {
        return Err(unauthorized());
    }
    if path == "sign-out"
        && let Some(p) = &principal
    {
        store.revoke_key(&p.session_key);
        if let Some(rt) = &state.runtime {
            rt.relays.close_owner(&p.session_key);
        }
        let _ = store
            .audit
            .record(&p.user.username, "account.logout", "", "requested");
    }
    if path == "change-password" {
        let mut value: serde_json::Value = serde_json::from_slice(&body).map_err(bad)?;
        value
            .as_object_mut()
            .ok_or_else(|| bad("Password request must be a JSON object."))?
            .insert("revokeOtherSessions".into(), true.into());
        body = serde_json::to_vec(&value).map_err(bad)?;
    }
    let mut reply = auth
        .request(path, method, headers, body.clone())
        .await
        .map_err(|_| auth_unavailable())?;
    let reset_user = reply.headers.remove("x-mcr-reset-user");
    if reply.status.is_success() && path == "reset-password" {
        store.revalidate_dashboard_sessions().await;
        if let Some(rt) = &state.runtime {
            rt.relays.close_inactive(&store);
        }
        if let Some(username) = reset_user.as_ref().and_then(|value| value.to_str().ok()) {
            let _ = store
                .audit
                .record(username, "account.recovery.reset", "", "success");
        }
    }
    if reply.status.is_success() && path == "passkey/verify-authentication" {
        let principal = store
            .dashboard_principal(&reply_cookie(&reply))
            .await
            .map_err(|_| auth_unavailable())?
            .ok_or_else(forbidden)?;
        let _ = store.audit.record(
            &principal.user.username,
            "account.passkey.login",
            "",
            "success",
        );
        // Better Auth includes a session token in the JSON result. The browser
        // only needs the HttpOnly cookie and Rust's permission view.
        reply.body = br#"{"ok":true}"#.to_vec();
    }
    if reply.status.is_success() && (mutation || mfa_settings || mfa_verify || passkey_settings) {
        if path == "change-password"
            && let Some(p) = &principal
        {
            store.revoke_user(&p.user.username);
            if let Some(rt) = &state.runtime {
                rt.relays.close_username(&p.user.username);
            }
            if let Some(id) = store.auth_user_id(&p.user.username) {
                auth.internal("revoke-user", json!({"user_id":id}))
                    .await
                    .map_err(|_| auth_unavailable())?;
            }
            let _ = store
                .audit
                .record(&p.user.username, "account.password", "", "success");
        }
        let rotated_mfa_session = path == "two-factor/disable"
            || (path == "two-factor/verify-totp"
                && principal.is_some()
                && reply.headers.contains_key(header::SET_COOKIE));
        if mutation || rotated_mfa_session || path == "passkey/delete-passkey" {
            store.revalidate_dashboard_sessions().await;
            if let Some(rt) = &state.runtime {
                rt.relays.close_inactive(&store);
            }
        }
        let action = match path {
            "two-factor/disable" => Some("account.mfa.disable"),
            "two-factor/generate-backup-codes" => Some("account.mfa.recovery-codes"),
            "passkey/verify-registration" => Some("account.passkey.add"),
            "passkey/delete-passkey" => Some("account.passkey.remove"),
            "two-factor/verify-totp" if !reply_cookie(&reply).is_empty() => {
                Some("account.mfa.verify")
            }
            "two-factor/verify-backup-code" if !reply_cookie(&reply).is_empty() => {
                Some("account.mfa.recovery")
            }
            _ => None,
        };
        if let Some(action) = action {
            let verified = if principal.is_some() {
                principal
            } else {
                store
                    .dashboard_principal(&reply_cookie(&reply))
                    .await
                    .ok()
                    .flatten()
            };
            if let Some(p) = verified {
                let _ = store.audit.record(&p.user.username, action, "", "success");
            }
        }
    }
    if path == "sign-in/username" {
        let username = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value["username"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let _ = store.audit.record(
            &username,
            "account.login",
            "",
            if is_mfa_challenge(&reply) {
                "challenge"
            } else if reply.status.is_success() {
                "success"
            } else {
                "denied"
            },
        );
    }
    Ok(reply_response(reply))
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
