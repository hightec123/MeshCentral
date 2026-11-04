use axum::{body::Body, http::Request};
use meshcentral_server::{dashboard_auth::AuthProcess, operators::Operators, storage};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn external_authentication_fails_closed_without_falling_back_to_legacy_cookies() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    storage::private_directory(&state).unwrap();
    let operators = Operators::open(&state).unwrap();
    operators.bootstrap("admin", "legacy-password-123").unwrap();
    let (legacy_cookie, _) = operators
        .login("admin", "legacy-password-123".into())
        .await
        .unwrap();
    let mut auth = AuthProcess::start(&state, "http://127.0.0.1:3300", &operators)
        .await
        .unwrap();
    assert!(
        operators
            .login("admin", "legacy-password-123".into())
            .await
            .is_err()
    );
    let app =
        meshcentral_server::app_with_services("missing-web".into(), None, Some(operators.clone()));
    let request = Request::builder()
        .uri("/api/v1/devices")
        .header("host", "127.0.0.1:3300")
        .header("cookie", format!("mcr_session={legacy_cookie}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(request).await.unwrap().status(), 401);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("origin", "http://127.0.0.1:3300".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    let login = auth
        .bridge
        .request(
            "sign-in/username",
            "POST",
            &headers,
            serde_json::to_vec(&json!({"username":"admin","password":"legacy-password-123"}))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status, 200);
    let cookie = login
        .headers
        .get_all("set-cookie")
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("; ");
    let principal = operators
        .dashboard_principal(&cookie)
        .await
        .unwrap()
        .unwrap();
    assert!(operators.active(&principal.session_key));
    let invalid = Request::builder()
        .method("POST")
        .uri("/api/auth/change-password")
        .header("host", "127.0.0.1:3300")
        .header("origin", "http://127.0.0.1:3300")
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .body(Body::from("[]"))
        .unwrap();
    assert_eq!(app.clone().oneshot(invalid).await.unwrap().status(), 400);
    let signup = Request::builder()
        .method("POST")
        .uri("/api/auth/sign-up/email")
        .header("host", "127.0.0.1:3300")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(app.clone().oneshot(signup).await.unwrap().status(), 404);
    auth.shutdown().await;
    let request = Request::builder()
        .uri("/api/v1/devices")
        .header("host", "127.0.0.1:3300")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(request).await.unwrap().status(), 503);
    operators.revalidate_dashboard_sessions().await;
    assert!(!operators.active(&principal.session_key));
}
