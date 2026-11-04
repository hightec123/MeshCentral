use std::{net::SocketAddr, path::PathBuf};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use meshcentral_server::{app, validate_listen};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn request(path: &str) -> (StatusCode, Value) {
    let response = app(PathBuf::from("nonexistent-web-build"))
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn liveness_does_not_claim_agent_readiness() {
    let (status, health) = request("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health, json!({"status": "ok"}));
    let (status, server) = request("/api/v1/server").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(server["api_version"], 1);
    assert_eq!(
        server["capabilities"],
        json!({
            "agent_enrollment": false,
            "remote_desktop": false,
            "terminal": false,
            "file_transfer": false,
        })
    );
}

#[tokio::test]
async fn inventory_is_not_publicly_readable() {
    let (status, inventory) = request("/api/v1/devices").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(inventory["code"], "request_failed");
}

#[tokio::test]
async fn native_agent_and_relay_endpoints_fail_closed() {
    for (path, code) in [
        ("/agent.ashx", "agent_enrollment_unavailable"),
        ("/meshrelay.ashx", "remote_sessions_unavailable"),
    ] {
        let (status, body) = request(path).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["code"], code);
    }
}

#[tokio::test]
async fn unknown_api_routes_return_json_instead_of_the_frontend() {
    for path in ["/api/v1/missing", "/api/v2/devices", "/api/nope"] {
        let (status, body) = request(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "not_found");
    }
}

#[tokio::test]
async fn websocket_upgrade_cannot_bypass_the_disabled_enrollment_gate() {
    let response = app(PathBuf::from("nonexistent-web-build"))
        .oneshot(
            Request::builder()
                .uri("/agent.ashx")
                .header("connection", "Upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("sec-websocket-accept"));
}

#[test]
fn development_server_rejects_network_exposure() {
    for address in ["0.0.0.0:3000", "[::]:3000", "192.168.1.10:3000"] {
        assert!(validate_listen(address.parse::<SocketAddr>().unwrap()).is_err());
    }
    for address in ["127.0.0.1:3000", "[::1]:3000"] {
        assert!(validate_listen(address.parse::<SocketAddr>().unwrap()).is_ok());
    }
}

#[tokio::test]
async fn browser_dns_rebinding_hosts_are_rejected() {
    for (host, status) in [
        ("attacker.example:3000", StatusCode::FORBIDDEN),
        ("127.0.0.1:3000", StatusCode::UNAUTHORIZED),
        ("localhost:3000", StatusCode::UNAUTHORIZED),
        ("[::1]:3000", StatusCode::UNAUTHORIZED),
    ] {
        let response = app(PathBuf::from("nonexistent-web-build"))
            .oneshot(
                Request::builder()
                    .uri("/api/v1/devices")
                    .header("host", host)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
}
