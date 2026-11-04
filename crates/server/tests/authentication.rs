use meshcentral_server::{
    DeviceStatus,
    auth::{AdmissionPolicy, Handshake},
    identity::{Identity, generate_certificate, hex, mesh_base64, public_key_der},
    registry::Registry,
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sha::sha384,
    sign::{Signer, Verifier},
    x509::X509,
};
use std::sync::{Arc, LazyLock};

struct Fixture {
    server: Arc<Identity>,
    cert: X509,
    key: PKey<Private>,
    policy: Arc<AdmissionPolicy>,
}
static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let (cert, key) = generate_certificate("Synthetic test agent").unwrap();
    let policy = AdmissionPolicy::lab(&hex(&sha384(&public_key_der(&cert).unwrap()))).unwrap();
    Fixture {
        server: Arc::new(Identity::generate().unwrap()),
        cert,
        key,
        policy: Arc::new(policy),
    }
});

fn challenge(hash: &[u8; 48], nonce: &[u8; 48]) -> Vec<u8> {
    [vec![0, 1], hash.to_vec(), nonce.to_vec()].concat()
}

fn metadata(policy: &AdmissionPolicy) -> Vec<u8> {
    let mut frame = vec![0, 3];
    for value in [1_u32, 29, 1, 3] {
        frame.extend(value.to_be_bytes());
    }
    frame.extend(meshcentral_server::identity::decode_hex::<48>(&policy.mesh_id_hex).unwrap());
    frame.extend(16_u32.to_be_bytes());
    frame.extend(8_u16.to_be_bytes());
    frame.extend(b"Lab test");
    frame
}

fn proof(hash: &[u8], server_nonce: &[u8], agent_nonce: &[u8]) -> Vec<u8> {
    let mut signer = Signer::new(MessageDigest::sha384(), &FIXTURE.key).unwrap();
    signer.update(hash).unwrap();
    signer.update(server_nonce).unwrap();
    signer.update(agent_nonce).unwrap();
    let cert = FIXTURE.cert.to_der().unwrap();
    [
        vec![0, 2],
        (cert.len() as u16).to_be_bytes().to_vec(),
        cert,
        signer.sign_to_vec().unwrap(),
    ]
    .concat()
}

fn handshake(policy: Arc<AdmissionPolicy>) -> Handshake {
    Handshake::new(FIXTURE.server.clone(), policy).unwrap()
}

#[test]
fn mutual_rsa_proofs_and_explicit_admission_succeed() {
    let fixture = &*FIXTURE;
    let nonce = [7; 48];
    let mut state = handshake(fixture.policy.clone());
    let replies = state
        .receive(&challenge(&fixture.server.web_hash, &nonce))
        .unwrap();
    assert_eq!(replies.len(), 2);
    let cert_len = u16::from_be_bytes(replies[1][2..4].try_into().unwrap()) as usize;
    let cert = X509::from_der(&replies[1][4..4 + cert_len]).unwrap();
    assert_eq!(
        sha384(&public_key_der(&cert).unwrap()),
        fixture.server.server_id
    );
    let key = cert.public_key().unwrap();
    let mut verify = Verifier::new(MessageDigest::sha384(), &key).unwrap();
    verify.update(&fixture.server.web_hash).unwrap();
    verify.update(&nonce).unwrap();
    verify.update(&replies[0][50..]).unwrap();
    assert!(verify.verify(&replies[1][4 + cert_len..]).unwrap());
    state
        .receive(&proof(&fixture.server.web_hash, &replies[0][50..], &nonce))
        .unwrap();
    assert!(
        state.finish().unwrap().is_none(),
        "proof alone cannot admit a device"
    );
    state.receive(&metadata(&fixture.policy)).unwrap();
    let peer = state.finish().unwrap().unwrap();
    assert_eq!(
        peer.node_id,
        mesh_base64(&sha384(&public_key_der(&fixture.cert).unwrap()))
    );
    assert_eq!(peer.name, "Lab test");
    assert!(state.finish().is_err(), "authentication is single-use");
}

#[test]
fn cached_server_ack_still_requires_a_fresh_agent_proof() {
    let fixture = &*FIXTURE;
    let mut state = handshake(fixture.policy.clone());
    state.receive(&[0, 4]).unwrap();
    state.receive(&metadata(&fixture.policy)).unwrap();
    let replies = state
        .receive(&challenge(&fixture.server.web_hash, &[1; 48]))
        .unwrap();
    assert_eq!(replies.len(), 1);
    assert!(state.finish().unwrap().is_none());
    state
        .receive(&proof(
            &fixture.server.web_hash,
            &replies[0][50..],
            &[1; 48],
        ))
        .unwrap();
    assert!(state.finish().unwrap().is_some());
}

#[test]
fn signatures_cannot_be_replayed_on_another_connection() {
    let fixture = &*FIXTURE;
    let mut first = handshake(fixture.policy.clone());
    let replies = first
        .receive(&challenge(&fixture.server.web_hash, &[1; 48]))
        .unwrap();
    let captured = proof(&fixture.server.web_hash, &replies[0][50..], &[1; 48]);
    let mut second = handshake(fixture.policy.clone());
    second
        .receive(&challenge(&fixture.server.web_hash, &[1; 48]))
        .unwrap();
    second.receive(&metadata(&fixture.policy)).unwrap();
    second.receive(&captured).unwrap();
    assert!(
        second
            .finish()
            .unwrap_err()
            .to_string()
            .contains("invalid agent signature")
    );
}

#[test]
fn wrong_tls_hash_and_wrong_server_identity_are_rejected() {
    let mut state = handshake(FIXTURE.policy.clone());
    assert!(state.receive(&challenge(&[0; 48], &[0; 48])).is_err());
    for len in [32, 48] {
        let mut state = handshake(FIXTURE.policy.clone());
        assert!(state.receive(&[vec![0, 5], vec![0; len]].concat()).is_err());
    }
}

#[test]
fn both_pinned_server_fingerprint_lengths_are_accepted_without_authenticating_agent() {
    for fingerprint in [
        FIXTURE.server.server_id.to_vec(),
        FIXTURE.server.server_id_legacy.to_vec(),
    ] {
        let mut state = handshake(FIXTURE.policy.clone());
        state.receive(&[vec![0, 5], fingerprint].concat()).unwrap();
        assert!(state.finish().unwrap().is_none());
    }
}

#[test]
fn wrong_mesh_and_unknown_node_are_rejected() {
    let mut state = handshake(FIXTURE.policy.clone());
    let mut info = metadata(&FIXTURE.policy);
    info[18] ^= 1;
    assert!(state.receive(&info).is_err());
    let mut policy = (*FIXTURE.policy).clone();
    policy.allowed_node_ids_hex = vec!["00".repeat(48)];
    let mut state = handshake(Arc::new(policy));
    let replies = state
        .receive(&challenge(&FIXTURE.server.web_hash, &[1; 48]))
        .unwrap();
    state.receive(&metadata(&FIXTURE.policy)).unwrap();
    state
        .receive(&proof(
            &FIXTURE.server.web_hash,
            &replies[0][50..],
            &[1; 48],
        ))
        .unwrap();
    assert!(
        state
            .finish()
            .unwrap_err()
            .to_string()
            .contains("node is not authorized")
    );
}

#[test]
fn tampered_signature_and_pkcs7_sized_envelope_are_rejected() {
    for append in [false, true] {
        let mut state = handshake(FIXTURE.policy.clone());
        let replies = state
            .receive(&challenge(&FIXTURE.server.web_hash, &[1; 48]))
            .unwrap();
        let mut signed = proof(&FIXTURE.server.web_hash, &replies[0][50..], &[1; 48]);
        if append {
            signed.push(0);
        } else {
            *signed.last_mut().unwrap() ^= 1;
        }
        state.receive(&signed).unwrap();
        state.receive(&metadata(&FIXTURE.policy)).unwrap();
        assert!(state.finish().is_err());
    }
}

#[test]
fn duplicate_commands_are_rejected() {
    let mut state = handshake(FIXTURE.policy.clone());
    state.receive(&[0, 4]).unwrap();
    assert!(state.receive(&[0, 4]).is_err());
    let mut state = handshake(FIXTURE.policy.clone());
    let frame = challenge(&FIXTURE.server.web_hash, &[1; 48]);
    state.receive(&frame).unwrap();
    assert!(state.receive(&frame).is_err());
}

#[test]
fn persistent_identity_has_stable_keys_and_private_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.json");
    FIXTURE.server.save_new(&path).unwrap();
    let loaded = Identity::load(&path).unwrap();
    assert_eq!(loaded.server_id, FIXTURE.server.server_id);
    assert_eq!(loaded.web_hash, FIXTURE.server.web_hash);
    assert!(
        FIXTURE.server.save_new(&path).is_err(),
        "never overwrite identity"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(
        Identity::load(&path).is_err(),
        "corruption must not regenerate a trusted identity"
    );
}

#[test]
fn real_presence_handles_duplicates_disconnect_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inventory.json");
    let registry = Registry::open(path.clone()).unwrap();
    let authenticate = || {
        let mut state = handshake(FIXTURE.policy.clone());
        let replies = state
            .receive(&challenge(&FIXTURE.server.web_hash, &[1; 48]))
            .unwrap();
        state
            .receive(&proof(
                &FIXTURE.server.web_hash,
                &replies[0][50..],
                &[1; 48],
            ))
            .unwrap();
        state.receive(&metadata(&FIXTURE.policy)).unwrap();
        state.finish().unwrap().unwrap()
    };
    let presence = registry.connect(authenticate()).unwrap();
    assert_eq!(registry.snapshot()[0].status, DeviceStatus::Online);
    assert!(registry.connect(authenticate()).is_err());
    assert_eq!(registry.snapshot()[0].status, DeviceStatus::Online);
    // Simulate loading saved online state after a crash: it must load offline.
    let restarted = Registry::open(path).unwrap();
    assert_eq!(restarted.snapshot()[0].status, DeviceStatus::Offline);
    drop(presence);
    assert_eq!(registry.snapshot()[0].status, DeviceStatus::Offline);
    let reconnected = registry.connect(authenticate()).unwrap();
    assert_eq!(registry.snapshot().len(), 1);
    drop(reconnected);
}

#[test]
fn state_directory_is_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let lock = meshcentral_server::storage::lock_directory(dir.path()).unwrap();
    assert!(meshcentral_server::storage::lock_directory(dir.path()).is_err());
    drop(lock);
    assert!(meshcentral_server::storage::lock_directory(dir.path()).is_ok());
}

#[test]
fn lab_initialization_is_idempotent_and_does_not_expand_admission() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let config = dir.path().join("agent/meshagent.msh");
    let node = hex(&sha384(&public_key_der(&FIXTURE.cert).unwrap()));
    let invoke = |node: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_meshcentral-server"))
            .env("MCR_DATA_DIR", &state)
            .env("MCR_LISTEN", "127.0.0.1:0")
            .env("MCR_AGENT_LISTEN", "127.0.0.1:8443")
            .arg("init-lab")
            .arg(node)
            .arg(&config)
            .output()
            .unwrap()
    };
    assert!(invoke(&node).status.success());
    let before = std::fs::read(state.join("identity.json")).unwrap();
    let msh_before = std::fs::read(&config).unwrap();
    assert!(invoke(&node).status.success());
    assert_eq!(std::fs::read(state.join("identity.json")).unwrap(), before);
    assert_eq!(std::fs::read(&config).unwrap(), msh_before);
    assert!(!invoke(&"00".repeat(48)).status.success());
    assert_eq!(
        AdmissionPolicy::load(&state.join("admission.json"))
            .unwrap()
            .allowed_node_ids_hex,
        vec![node]
    );
}

#[test]
fn missing_server_identity_cannot_be_silently_regenerated_for_an_existing_lab() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    meshcentral_server::storage::private_directory(&state).unwrap();
    meshcentral_server::storage::write_new(
        &state.join("admission.json"),
        &serde_json::to_vec(&*FIXTURE.policy).unwrap(),
    )
    .unwrap();
    let node = hex(&sha384(&public_key_der(&FIXTURE.cert).unwrap()));
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_meshcentral-server"))
        .env("MCR_DATA_DIR", &state)
        .env("MCR_LISTEN", "127.0.0.1:0")
        .env("MCR_AGENT_LISTEN", "127.0.0.1:8443")
        .arg("init-lab")
        .arg(node)
        .arg(dir.path().join("agent/meshagent.msh"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!state.join("identity.json").exists());
}

#[tokio::test]
async fn tls_websocket_admits_verified_peer_and_cleans_up_disconnect() {
    use axum_server::tls_rustls::RustlsConfig;
    use futures_util::{SinkExt, StreamExt};
    use meshcentral_server::{
        agent::{self, AgentRuntime},
        storage,
    };
    use std::time::Duration;
    use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};

    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let directory = tempfile::tempdir().unwrap();
    let state_dir = directory.path().join("state");
    storage::private_directory(&state_dir).unwrap();
    FIXTURE
        .server
        .save_new(&state_dir.join("identity.json"))
        .unwrap();
    storage::write_new(
        &state_dir.join("admission.json"),
        &serde_json::to_vec(&*FIXTURE.policy).unwrap(),
    )
    .unwrap();
    let runtime = AgentRuntime::open(&state_dir).unwrap();
    let tls = RustlsConfig::from_pem(
        FIXTURE.server.tls_certificate.to_pem().unwrap(),
        FIXTURE.server.tls_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .await
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let app = agent::router(runtime.clone());
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            FIXTURE.server.tls_certificate.to_der().unwrap(),
        ))
        .unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(client));
    let url = format!("wss://{address}/agent.ashx");
    let (mut socket, response) =
        connect_async_tls_with_config(url.clone(), None, false, Some(connector.clone()))
            .await
            .unwrap();
    assert_eq!(response.status(), 101);
    socket
        .send(Message::Binary(
            challenge(&FIXTURE.server.web_hash, &[8; 48]).into(),
        ))
        .await
        .unwrap();
    let Message::Binary(challenge_reply) = socket.next().await.unwrap().unwrap() else {
        panic!("missing server challenge");
    };
    let Message::Binary(_) = socket.next().await.unwrap().unwrap() else {
        panic!("missing server proof");
    };
    socket
        .send(Message::Binary(metadata(&FIXTURE.policy).into()))
        .await
        .unwrap();
    socket
        .send(Message::Binary(
            proof(&FIXTURE.server.web_hash, &challenge_reply[50..], &[8; 48]).into(),
        ))
        .await
        .unwrap();
    let ack = socket.next().await.unwrap().unwrap();
    assert_eq!(ack, Message::Binary(vec![0, 4].into()));
    assert_eq!(runtime.registry.snapshot()[0].status, DeviceStatus::Online);
    socket.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while runtime.registry.snapshot()[0].status != DeviceStatus::Offline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    // A second real TLS/WebSocket connection with the wrong web hash cannot
    // upgrade an old offline record to online.
    let (mut invalid, _) =
        connect_async_tls_with_config(url.clone(), None, false, Some(connector.clone()))
            .await
            .unwrap();
    invalid
        .send(Message::Binary(challenge(&[0; 48], &[8; 48]).into()))
        .await
        .unwrap();
    assert!(matches!(
        invalid.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert_eq!(runtime.registry.snapshot()[0].status, DeviceStatus::Offline);

    // Browser-origin WebSockets are rejected before the native protocol runs.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut browser_request = url.into_client_request().unwrap();
    browser_request
        .headers_mut()
        .insert("origin", "https://example.com".parse().unwrap());
    let result = connect_async_tls_with_config(browser_request, None, false, Some(connector)).await;
    assert!(
        matches!(result, Err(tokio_tungstenite::tungstenite::Error::Http(response)) if response.status() == 403)
    );
    handle.shutdown();
    server.await.unwrap();
}
