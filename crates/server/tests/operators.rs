use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use meshcentral_server::{
    operators::{Operators, Role, User},
    storage,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn setup() -> (
    tempfile::TempDir,
    Arc<Operators>,
    String,
    meshcentral_server::operators::Principal,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("operators");
    storage::private_directory(&path).unwrap();
    let store = Operators::open(&path).unwrap();
    store.bootstrap("admin", "test-password-12345").unwrap();
    let (cookie, p) = store
        .login("admin", "test-password-12345".into())
        .await
        .unwrap();
    (directory, store, cookie, p)
}
#[tokio::test]
async fn login_has_opaque_revocable_sessions_and_hashed_passwords() {
    let (dir, store, cookie, p) = setup().await;
    assert_eq!(cookie.len(), 43);
    assert!(store.authenticate(&cookie).unwrap().user.admin());
    assert!(store.authenticate("forged-token").is_none());
    let source = std::fs::read_to_string(dir.path().join("operators/operators.json")).unwrap();
    assert!(!source.contains("test-password-12345"));
    assert!(source.contains("$argon2id$"));
    store.logout(&p).unwrap();
    assert!(store.authenticate(&cookie).is_none());
    assert!(!store.active(&p.session_key));
    assert!(
        store
            .login("admin", "wrong-password-123".into())
            .await
            .is_err()
    );
    assert!(
        store
            .login("absent", "wrong-password-123".into())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn roles_and_group_grants_are_enforced_and_changes_revoke_sessions() {
    let (_dir, store, _cookie, admin) = setup().await;
    let group = "A1".repeat(48);
    store
        .save_user(
            &admin,
            User {
                username: "viewer".into(),
                role: Role::Viewer,
                groups: vec![group.clone()],
            },
            Some("viewer-password-123"),
        )
        .unwrap();
    let (cookie, p) = store
        .login("viewer", "viewer-password-123".into())
        .await
        .unwrap();
    assert!(p.user.can_view(&group));
    assert!(!p.user.can_view(&"B2".repeat(48)));
    assert!(!p.user.can_control(&group));
    assert!(
        store
            .save_user(
                &p,
                User {
                    username: "evil".into(),
                    role: Role::Administrator,
                    groups: vec![]
                },
                Some("evil-password-123")
            )
            .is_err()
    );
    store
        .save_user(
            &admin,
            User {
                username: "viewer".into(),
                role: Role::Operator,
                groups: vec![group.clone()],
            },
            None,
        )
        .unwrap();
    assert!(store.authenticate(&cookie).is_none());
    let (_, operator) = store
        .login("viewer", "viewer-password-123".into())
        .await
        .unwrap();
    assert!(operator.user.can_control(&group));
    assert!(!operator.user.can_control(&"B2".repeat(48)));
}
#[tokio::test]
async fn last_administrator_cannot_be_deleted_or_demoted() {
    let (_dir, store, _, p) = setup().await;
    assert!(store.delete_user(&p, "admin").is_err());
    assert!(
        store
            .save_user(
                &p,
                User {
                    username: "admin".into(),
                    role: Role::Viewer,
                    groups: vec![]
                },
                None
            )
            .is_err()
    );
}
#[tokio::test]
async fn password_change_checks_old_password_and_revokes_all_sessions() {
    let (_dir, store, cookie, p) = setup().await;
    assert!(
        store
            .change_password(
                &p,
                "not-the-password".into(),
                "replacement-password-123".into()
            )
            .await
            .is_err()
    );
    store
        .change_password(
            &p,
            "test-password-12345".into(),
            "replacement-password-123".into(),
        )
        .await
        .unwrap();
    assert!(store.authenticate(&cookie).is_none());
    assert!(
        store
            .login("admin", "test-password-12345".into())
            .await
            .is_err()
    );
    assert!(
        store
            .login("admin", "replacement-password-123".into())
            .await
            .is_ok()
    );
}

async fn request(
    app: axum::Router,
    path: &str,
    method: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    origin: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .uri(path)
        .method(method)
        .header("host", "127.0.0.1:3000");
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("mcr_session={cookie}"));
    }
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    request = request.header("content-type", "application/json");
    let response = app
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[tokio::test]
async fn http_inventory_requires_login_and_mutations_require_csrf_and_origin() {
    let (_dir, store, cookie, p) = setup().await;
    let app =
        meshcentral_server::app_with_services("missing-web".into(), None, Some(store.clone()));
    assert_eq!(
        request(
            app.clone(),
            "/api/v1/devices",
            "GET",
            None,
            None,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            app.clone(),
            "/api/v1/devices",
            "GET",
            Some(&cookie),
            None,
            None,
            Value::Null
        )
        .await,
        (StatusCode::OK, json!({"devices":[]}))
    );
    assert_eq!(
        request(
            app.clone(),
            "/api/v1/auth/logout",
            "POST",
            Some(&cookie),
            None,
            None,
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            app.clone(),
            "/api/v1/auth/logout",
            "POST",
            Some(&cookie),
            Some(&p.csrf),
            Some("https://attacker.example"),
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(store.authenticate(&cookie).is_some());
    assert_eq!(
        request(
            app,
            "/api/v1/auth/logout",
            "POST",
            Some(&cookie),
            Some(&p.csrf),
            Some("http://127.0.0.1:3000"),
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(store.authenticate(&cookie).is_none());
}
#[tokio::test]
async fn viewers_cannot_read_accounts_audit_or_promote_themselves() {
    let (_dir, store, _, p) = setup().await;
    store
        .save_user(
            &p,
            User {
                username: "viewer".into(),
                role: Role::Viewer,
                groups: vec![],
            },
            Some("viewer-password-123"),
        )
        .unwrap();
    let (cookie, viewer) = store
        .login("viewer", "viewer-password-123".into())
        .await
        .unwrap();
    let app = meshcentral_server::app_with_services("missing-web".into(), None, Some(store));
    for path in ["/api/v1/users", "/api/v1/audit"] {
        assert_eq!(
            request(
                app.clone(),
                path,
                "GET",
                Some(&cookie),
                None,
                None,
                Value::Null
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        request(
            app,
            "/api/v1/users",
            "POST",
            Some(&cookie),
            Some(&viewer.csrf),
            None,
            json!({"user":{"username":"viewer","role":"administrator","groups":[]}})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn revoked_principals_cannot_finish_account_or_password_mutations() {
    let (_dir, store, _, admin) = setup().await;
    store
        .save_user(
            &admin,
            User {
                username: "viewer".into(),
                role: Role::Viewer,
                groups: vec![],
            },
            Some("viewer-password-123"),
        )
        .unwrap();
    store.logout(&admin).unwrap();
    assert!(
        store
            .save_user(
                &admin,
                User {
                    username: "intruder".into(),
                    role: Role::Administrator,
                    groups: vec![]
                },
                Some("intruder-password-123")
            )
            .is_err()
    );
    assert!(store.delete_user(&admin, "viewer").is_err());
    assert!(
        store
            .change_password(
                &admin,
                "test-password-12345".into(),
                "hijacked-password-123".into()
            )
            .await
            .is_err()
    );
    assert!(store.users().iter().any(|user| user.username == "viewer"));
    assert!(!store.users().iter().any(|user| user.username == "intruder"));
    assert!(
        store
            .login("admin", "test-password-12345".into())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn group_management_and_device_apis_enforce_scoped_permissions() {
    use meshcentral_server::{
        agent::AgentRuntime,
        auth::{AdmissionPolicy, AuthenticatedPeer},
        identity::Identity,
    };
    let (dir, store, cookie, admin) = setup().await;
    let state = dir.path().join("operators");
    Identity::generate()
        .unwrap()
        .save_new(&state.join("identity.json"))
        .unwrap();
    let node = "A1".repeat(48);
    let policy = AdmissionPolicy::lab(&node).unwrap();
    storage::write_new(
        &state.join("admission.json"),
        &serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let rt = AgentRuntime::open(&state).unwrap();
    let presence = rt
        .registry
        .connect(AuthenticatedPeer {
            node_id: "test-device".into(),
            node_id_hex: node,
            mesh_id_hex: policy.mesh_id_hex.clone(),
            name: "Lab fixture".into(),
            group: policy.group_name.clone(),
            architecture: 29,
        })
        .unwrap();
    let app = meshcentral_server::app_with_services(
        "missing-web".into(),
        Some(rt.clone()),
        Some(store.clone()),
    );
    macro_rules! admin_request {
        ($path:expr,$method:expr,$body:expr) => {
            request(
                app.clone(),
                $path,
                $method,
                Some(&cookie),
                Some(&admin.csrf),
                None,
                $body,
            )
            .await
        };
    }
    let (status, group) = admin_request!("/api/v1/groups", "POST", json!({"name":"Second lab"}));
    assert_eq!(status, StatusCode::OK);
    let group_id = group["mesh_id_hex"].as_str().unwrap();
    let group_path = format!("/api/v1/groups/{group_id}");
    assert_eq!(
        admin_request!(&format!("{group_path}/configuration"), "GET", Value::Null).0,
        StatusCode::OK
    );
    assert_eq!(
        admin_request!(
            "/api/v1/groups",
            "POST",
            json!({"name":"Injected\r\nMeshServer=bad"})
        )
        .0,
        StatusCode::BAD_REQUEST
    );
    for (name, role, grants) in [
        ("viewer", Role::Viewer, vec![policy.mesh_id_hex.clone()]),
        ("operator", Role::Operator, vec![group_id.to_string()]),
    ] {
        store
            .save_user(
                &admin,
                User {
                    username: name.into(),
                    role,
                    groups: grants,
                },
                Some("scoped-password-123"),
            )
            .unwrap();
        let (token, principal) = store
            .login(name, "scoped-password-123".into())
            .await
            .unwrap();
        let (status, inventory) = request(
            app.clone(),
            "/api/v1/devices",
            "GET",
            Some(&token),
            None,
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            inventory["devices"].as_array().unwrap().len(),
            if name == "viewer" { 1 } else { 0 }
        );
        for (path, method, body) in [
            (
                "/api/v1/devices/test-device",
                "PATCH",
                json!({"alias":"forbidden","notes":"","tags":[]}),
            ),
            (
                "/api/v1/devices/test-device/sessions",
                "POST",
                json!({"kind":"terminal"}),
            ),
            (
                "/api/v1/devices/test-device/scripts/run",
                "POST",
                json!({"script":"printf fixture"}),
            ),
            (
                "/api/v1/devices/test-device/schedules",
                "POST",
                json!({"name":"Fixture","script":"exit 0","run_at":"2027-01-01T00:00:00Z","repeat":"once"}),
            ),
            ("/api/v1/groups", "POST", json!({"name":"forbidden"})),
        ] {
            assert_eq!(
                request(
                    app.clone(),
                    path,
                    method,
                    Some(&token),
                    Some(&principal.csrf),
                    None,
                    body
                )
                .await
                .0,
                StatusCode::FORBIDDEN
            );
        }
        if name == "viewer" {
            assert_eq!(
                request(
                    app.clone(),
                    &format!("{group_path}/configuration"),
                    "GET",
                    Some(&token),
                    None,
                    None,
                    Value::Null
                )
                .await
                .0,
                StatusCode::FORBIDDEN
            );
        }
    }
    // A group with an access grant cannot disappear underneath an operator.
    assert_eq!(
        admin_request!(&group_path, "DELETE", Value::Null).0,
        StatusCode::BAD_REQUEST
    );
    store.delete_user(&admin, "operator").unwrap();
    assert_eq!(
        admin_request!(&group_path, "DELETE", Value::Null).0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_request!(
            &format!("/api/v1/groups/{}", policy.mesh_id_hex),
            "DELETE",
            Value::Null
        )
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin_request!(
            "/api/v1/devices/test-device",
            "PATCH",
            json!({"alias":"Accepted name","notes":"persist me","tags":["lab"]})
        )
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin_request!("/api/v1/devices/test-device", "DELETE", Value::Null).0,
        StatusCode::BAD_REQUEST
    );
    drop(presence);
    assert_eq!(
        rt.registry.device("test-device").unwrap().notes,
        "persist me"
    );
    assert_eq!(
        admin_request!("/api/v1/devices/test-device", "DELETE", Value::Null).0,
        StatusCode::NO_CONTENT
    );
    assert!(rt.registry.snapshot().is_empty());
}
