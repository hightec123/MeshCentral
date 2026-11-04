use meshcentral_server::{
    DeviceStatus,
    auth::{AdmissionPolicy, AuthenticatedPeer},
    backup,
    identity::Identity,
    operators::Operators,
    registry::Registry,
    storage,
};
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

fn private_tempdir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn cli(state: &Path, args: &[&str], password: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_meshcentral-server"))
        .env("MCR_DATA_DIR", state)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(password.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[tokio::test]
async fn encrypted_snapshot_preserves_pinned_trust_accounts_and_metadata_but_not_presence_or_sessions()
 {
    let dir = private_tempdir();
    let state = dir.path().join("state");
    storage::private_directory(&state).unwrap();
    let identity = Identity::generate().unwrap();
    identity.save_new(&state.join("identity.json")).unwrap();
    let node = "B2".repeat(48);
    let policy = AdmissionPolicy::lab(&node).unwrap();
    storage::write_new(
        &state.join("admission.json"),
        &serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let registry = Registry::open(state.join("inventory.json")).unwrap();
    let _presence = registry
        .connect(AuthenticatedPeer {
            node_id: "backup-fixture".into(),
            name: "Fixture".into(),
            group: policy.group_name.clone(),
            architecture: 29,
            mesh_id_hex: policy.mesh_id_hex.clone(),
            node_id_hex: node,
        })
        .unwrap();
    registry
        .patch(
            "backup-fixture",
            Some("Saved alias".into()),
            "Saved notes".into(),
            vec!["lab".into()],
        )
        .unwrap();
    let accounts = Operators::open(&state).unwrap();
    accounts
        .bootstrap("admin", "operator-test-password")
        .unwrap();
    let (cookie, _) = accounts
        .login("admin", "operator-test-password".into())
        .await
        .unwrap();
    let archive = dir.path().join("backup.mcrbackup");
    backup::create(&state, &archive, "offline-backup-password").unwrap();
    let encoded = std::fs::read_to_string(&archive).unwrap();
    assert!(!encoded.contains("Saved notes"));
    assert!(!encoded.contains("PRIVATE KEY"));
    assert!(!encoded.contains("argon2id$"));
    let destination = dir.path().join("restored");
    backup::restore(&archive, &destination, "offline-backup-password").unwrap();
    let restored = Identity::load(&destination.join("identity.json")).unwrap();
    assert_eq!(restored.server_id, identity.server_id);
    assert_eq!(restored.web_hash, identity.web_hash);
    assert_eq!(
        AdmissionPolicy::load(&destination.join("admission.json"))
            .unwrap()
            .mesh_id_hex,
        policy.mesh_id_hex
    );
    let restored_accounts = Operators::open(&destination).unwrap();
    assert!(restored_accounts.authenticate(&cookie).is_none());
    assert!(
        restored_accounts
            .login("admin", "operator-test-password".into())
            .await
            .is_ok()
    );
    let devices = Registry::open(destination.join("inventory.json"))
        .unwrap()
        .snapshot();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "Saved alias");
    assert_eq!(devices[0].notes, "Saved notes");
    assert_eq!(devices[0].tags, ["lab"]);
    assert_eq!(devices[0].status, DeviceStatus::Offline);
    assert!(!devices[0].core_ready);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn cli_requires_offline_state_and_refuses_existing_paths_or_wrong_passwords() {
    let dir = private_tempdir();
    let state = dir.path().join("state");
    storage::private_directory(&state).unwrap();
    let accounts = Operators::open(&state).unwrap();
    accounts
        .bootstrap("admin", "operator-test-password")
        .unwrap();
    let archive = dir.path().join("backup.mcrbackup");
    let archive_arg = archive.to_str().unwrap();
    let lock = storage::lock_directory(&state).unwrap();
    let blocked = cli(&state, &["backup", archive_arg], "offline-backup-password");
    assert!(!blocked.status.success());
    assert!(!archive.exists());
    drop(lock);
    assert!(
        cli(&state, &["backup", archive_arg], "offline-backup-password")
            .status
            .success()
    );
    let before = std::fs::read(&archive).unwrap();
    assert!(
        !cli(&state, &["backup", archive_arg], "offline-backup-password")
            .status
            .success()
    );
    assert_eq!(std::fs::read(&archive).unwrap(), before);
    let missing = dir.path().join("wrong-password");
    assert!(
        !cli(
            &state,
            &["restore", archive_arg, missing.to_str().unwrap()],
            "wrong-backup-password"
        )
        .status
        .success()
    );
    assert!(!missing.exists());
    let destination = dir.path().join("restored");
    assert!(
        cli(
            &state,
            &["restore", archive_arg, destination.to_str().unwrap()],
            "offline-backup-password"
        )
        .status
        .success()
    );
    let before = std::fs::read(destination.join("operators.json")).unwrap();
    assert!(
        !cli(
            &state,
            &["restore", archive_arg, destination.to_str().unwrap()],
            "offline-backup-password"
        )
        .status
        .success()
    );
    assert_eq!(
        std::fs::read(destination.join("operators.json")).unwrap(),
        before
    );
    assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".restore-")
    }));
}

#[tokio::test]
async fn better_auth_database_and_secret_survive_encrypted_recovery_with_original_credentials() {
    use axum::http::HeaderMap;
    use meshcentral_server::dashboard_auth::AuthProcess;
    use serde_json::json;
    let dir = private_tempdir();
    let state = dir.path().join("state");
    storage::private_directory(&state).unwrap();
    let store = Operators::open(&state).unwrap();
    store.bootstrap("admin", "legacy-argon-password").unwrap();
    let before: serde_json::Value = storage::read_json(&state.join("operators.json")).unwrap();
    assert!(
        before["users"]["admin"]["password_hash"]
            .as_str()
            .unwrap()
            .starts_with("$argon2id$")
    );
    let mut auth = AuthProcess::start(&state, "http://127.0.0.1:3300", &store)
        .await
        .unwrap();
    let mapped_id = store.auth_user_id("admin").unwrap();
    let after: serde_json::Value = storage::read_json(&state.join("operators.json")).unwrap();
    assert!(after["users"]["admin"].get("password_hash").is_none());
    let mut headers = HeaderMap::new();
    headers.insert("origin", "http://127.0.0.1:3300".parse().unwrap());
    headers.insert("content-type", "application/json".parse().unwrap());
    let login = auth
        .bridge
        .request(
            "sign-in/username",
            "POST",
            &headers,
            serde_json::to_vec(&json!({"username":"admin","password":"legacy-argon-password"}))
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
    assert!(
        store
            .dashboard_principal(&cookie)
            .await
            .unwrap()
            .unwrap()
            .user
            .admin()
    );
    auth.shutdown().await;
    let archive = dir.path().join("better-auth.mcrbackup");
    backup::create(&state, &archive, "encrypted-auth-backup-password").unwrap();
    let destination = dir.path().join("restored");
    backup::restore(&archive, &destination, "encrypted-auth-backup-password").unwrap();
    let restored = Operators::open(&destination).unwrap();
    assert_eq!(
        restored.auth_user_id("admin").as_deref(),
        Some(mapped_id.as_str())
    );
    let mut recovered_auth = AuthProcess::start(&destination, "http://127.0.0.1:3300", &restored)
        .await
        .unwrap();
    assert!(
        restored
            .dashboard_principal(&cookie)
            .await
            .unwrap()
            .is_none(),
        "old sessions must not revive after restore"
    );
    let login = recovered_auth
        .bridge
        .request(
            "sign-in/username",
            "POST",
            &headers,
            serde_json::to_vec(&json!({"username":"admin","password":"legacy-argon-password"}))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        login.status, 200,
        "original imported password must remain usable"
    );
    recovered_auth.shutdown().await;
}
