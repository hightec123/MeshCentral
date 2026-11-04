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

#[tokio::test]
async fn better_auth_logout_closes_terminal_files_and_desktop_but_preserves_another_sign_in() {
    use axum_server::tls_rustls::RustlsConfig;
    use futures_util::{SinkExt, StreamExt};
    use meshcentral_server::{
        agent::{self, AgentRuntime},
        dashboard_auth::AuthProcess,
        operators::Operators,
        storage,
    };
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio_tungstenite::{
        Connector, connect_async, connect_async_tls_with_config,
        tungstenite::{Message, client::IntoClientRequest},
    };
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state");
    storage::private_directory(&state).unwrap();
    FIXTURE
        .server
        .save_new(&state.join("identity.json"))
        .unwrap();
    storage::write_new(
        &state.join("admission.json"),
        &serde_json::to_vec(&*FIXTURE.policy).unwrap(),
    )
    .unwrap();
    let runtime = AgentRuntime::open(&state).unwrap();
    let operators = Operators::open(&state).unwrap();
    operators
        .bootstrap("admin", "better-auth-test-password")
        .unwrap();
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_address = http_listener.local_addr().unwrap();
    let origin = format!("http://{http_address}");
    let mut auth = AuthProcess::start(&state, &origin, &operators)
        .await
        .unwrap();
    let app = meshcentral_server::app_with_services(
        "missing-web".into(),
        Some(runtime.clone()),
        Some(operators.clone()),
    );
    let http = tokio::spawn(async move {
        axum::serve(http_listener, app).await.unwrap();
    });
    let tls = RustlsConfig::from_pem(
        FIXTURE.server.tls_certificate.to_pem().unwrap(),
        FIXTURE.server.tls_key.private_key_to_pem_pkcs8().unwrap(),
    )
    .await
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let native_address = listener.local_addr().unwrap();
    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let native_app = agent::router(runtime.clone());
    let native = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .handle(server_handle)
            .serve(native_app.into_make_service())
            .await
            .unwrap();
    });
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            FIXTURE.server.tls_certificate.to_der().unwrap(),
        ))
        .unwrap();
    let connector = Connector::Rustls(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let (mut parent, _) = connect_async_tls_with_config(
        format!("wss://{native_address}/agent.ashx"),
        None,
        false,
        Some(connector.clone()),
    )
    .await
    .unwrap();
    parent
        .send(Message::Binary(
            challenge(&FIXTURE.server.web_hash, &[39; 48]).into(),
        ))
        .await
        .unwrap();
    let Message::Binary(reply) = parent.next().await.unwrap().unwrap() else {
        panic!("challenge missing")
    };
    parent.next().await.unwrap().unwrap();
    parent
        .send(Message::Binary(metadata(&FIXTURE.policy).into()))
        .await
        .unwrap();
    parent
        .send(Message::Binary(
            proof(&FIXTURE.server.web_hash, &reply[50..], &[39; 48]).into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        parent.next().await.unwrap().unwrap(),
        Message::Binary(vec![0, 4].into())
    );
    let node = runtime.registry.snapshot()[0].id.clone();
    runtime
        .registry
        .telemetry(
            &node,
            "coreinfo",
            json!({"action":"coreinfo","value":"controlled relay fixture"}),
        )
        .unwrap();
    let monitor_store = operators.clone();
    let monitor_runtime = runtime.clone();
    let monitor = tokio::spawn(async move {
        loop {
            monitor_store.revalidate_dashboard_sessions().await;
            monitor_runtime.relays.close_inactive(&monitor_store);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let client = reqwest::Client::new();
    let mut cookies = Vec::new();
    let mut csrf = Vec::new();
    for _ in 0..2 {
        let response = client
            .post(format!("{origin}/api/auth/sign-in/username"))
            .header("origin", &origin)
            .json(&json!({"username":"admin","password":"better-auth-test-password"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let cookie = response
            .headers()
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
        let session: Value = client
            .get(format!("{origin}/api/v1/auth/session"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        csrf.push(session["csrf"].as_str().unwrap().to_owned());
        cookies.push(cookie);
    }
    let mut browsers = Vec::new();
    let mut agents = Vec::new();
    for (kind, owner) in [
        ("terminal", 0),
        ("files", 0),
        ("desktop", 0),
        ("terminal", 1),
    ] {
        let response = client
            .post(format!("{origin}/api/v1/devices/{node}/sessions"))
            .header("cookie", &cookies[owner])
            .header("origin", &origin)
            .header("x-csrf-token", &csrf[owner])
            .json(&json!({"kind":kind}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let room: Value = response.json().await.unwrap();
        let ticket = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let message = parent.next().await.unwrap().unwrap();
                if let Message::Binary(bytes) = message
                    && bytes.first() == Some(&b'{')
                {
                    let command: Value = serde_json::from_slice(&bytes).unwrap();
                    if command["type"] == "tunnel" {
                        break command["value"]
                            .as_str()
                            .unwrap()
                            .trim_start_matches('*')
                            .to_owned();
                    }
                }
            }
        })
        .await
        .unwrap();
        let (agent, _) = connect_async_tls_with_config(
            format!("wss://{native_address}{ticket}"),
            None,
            false,
            Some(connector.clone()),
        )
        .await
        .unwrap();
        let mut request = format!(
            "ws://{http_address}{}",
            room["socket_path"].as_str().unwrap()
        )
        .into_client_request()
        .unwrap();
        request
            .headers_mut()
            .insert("cookie", cookies[owner].parse().unwrap());
        request
            .headers_mut()
            .insert("origin", origin.parse().unwrap());
        let (mut browser, _) = connect_async(request).await.unwrap();
        let connected = browser.next().await.unwrap().unwrap();
        assert!(matches!(connected,Message::Text(value) if value.contains("connected")));
        let mut agent = agent;
        for _ in 0..3 {
            assert!(matches!(agent.next().await, Some(Ok(Message::Text(_)))));
        }
        agent
            .send(Message::Binary(b"before logout".to_vec().into()))
            .await
            .unwrap();
        assert_eq!(
            browser.next().await.unwrap().unwrap(),
            Message::Binary(b"before logout".to_vec().into())
        );
        browsers.push(browser);
        agents.push(agent);
    }
    let response = client
        .post(format!("{origin}/api/auth/sign-out"))
        .header("cookie", &cookies[0])
        .header("origin", &origin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    for index in 0..3 {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), browsers[index].next())
                .await
                .unwrap(),
            Some(Ok(Message::Close(_))) | None
        ));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), agents[index].next())
                .await
                .unwrap(),
            Some(Ok(Message::Close(_))) | None
        ));
    }
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/devices"))
            .header("cookie", &cookies[0])
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    agents[3]
        .send(Message::Binary(b"other sign-in survives".to_vec().into()))
        .await
        .unwrap();
    assert_eq!(
        browsers[3].next().await.unwrap().unwrap(),
        Message::Binary(b"other sign-in survives".to_vec().into())
    );
    assert_eq!(
        runtime.registry.snapshot()[0].status,
        DeviceStatus::Online,
        "dashboard logout must not disconnect the certificate-authenticated agent"
    );
    // Direct upstream revocation is noticed independently of the logout route.
    let user_id = operators.auth_user_id("admin").unwrap();
    auth.bridge
        .internal("revoke-user", json!({"user_id":user_id}))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), browsers[3].next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_))) | None
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), agents[3].next())
            .await
            .unwrap(),
        Some(Ok(Message::Close(_))) | None
    ));
    monitor.abort();
    parent.close(None).await.unwrap();
    handle.shutdown();
    native.await.unwrap();
    http.abort();
    auth.shutdown().await;
}

fn handshake(policy: Arc<AdmissionPolicy>) -> Handshake {
    Handshake::new(FIXTURE.server.clone(), policy).unwrap()
}

// CryptoAPI's single-signer SignedData envelope, with an attached transcript and
// certificate. The envelope's content/certificate must never replace the fresh
// transcript or the explicitly pinned outer certificate at the trust boundary.
fn wrapped_proof(raw: &[u8], transcript: &[u8], embedded_cert: &X509) -> Vec<u8> {
    fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let length = if bytes.len() < 128 {
            vec![bytes.len() as u8]
        } else if bytes.len() <= 255 {
            vec![0x81, bytes.len() as u8]
        } else {
            vec![0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]
        };
        [vec![tag], length, bytes.to_vec()].concat()
    }
    let cert_length = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    let signature = &raw[4 + cert_length..];
    let sha384 = der(
        0x30,
        &[
            der(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2]),
            der(5, &[]),
        ]
        .concat(),
    );
    let rsa = der(
        0x30,
        &[
            der(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]),
            der(5, &[]),
        ]
        .concat(),
    );
    let mut serial = embedded_cert.serial_number().to_bn().unwrap().to_vec();
    if serial[0] & 0x80 != 0 {
        serial.insert(0, 0);
    }
    let issuer = der(
        0x30,
        &[
            embedded_cert.issuer_name().to_der().unwrap(),
            der(2, &serial),
        ]
        .concat(),
    );
    let signer = der(
        0x30,
        &[der(2, &[1]), issuer, sha384.clone(), rsa, der(4, signature)].concat(),
    );
    let data = der(
        0x30,
        &[
            der(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1]),
            der(0xa0, &der(4, transcript)),
        ]
        .concat(),
    );
    let signed = der(
        0x30,
        &[
            der(2, &[1]),
            der(0x31, &sha384),
            data,
            der(0xa0, &embedded_cert.to_der().unwrap()),
            der(0x31, &signer),
        ]
        .concat(),
    );
    let wrapped = der(
        0x30,
        &[
            der(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2]),
            der(0xa0, &signed),
        ]
        .concat(),
    );
    [&raw[..4 + cert_length], &wrapped].concat()
}

#[test]
fn legacy_pkcs7_signatures_require_the_pinned_key_and_fresh_transcript() {
    let nonce = [17; 48];
    let mut state = handshake(FIXTURE.policy.clone());
    let replies = state
        .receive(&challenge(&FIXTURE.server.web_hash, &nonce))
        .unwrap();
    let transcript = [
        FIXTURE.server.web_hash.as_slice(),
        &replies[0][50..],
        &nonce,
    ]
    .concat();
    let raw = proof(&FIXTURE.server.web_hash, &replies[0][50..], &nonce);
    let wrapped = wrapped_proof(&raw, &transcript, &FIXTURE.cert);
    state.receive(&wrapped).unwrap();
    state.receive(&metadata(&FIXTURE.policy)).unwrap();
    assert!(state.finish().unwrap().is_some());
    let mut replay = handshake(FIXTURE.policy.clone());
    replay
        .receive(&challenge(&FIXTURE.server.web_hash, &nonce))
        .unwrap();
    replay.receive(&wrapped).unwrap();
    replay.receive(&metadata(&FIXTURE.policy)).unwrap();
    assert!(replay.finish().is_err());

    let (foreign_cert, foreign_key) = generate_certificate("Unapproved embedded signer").unwrap();
    let mut state = handshake(FIXTURE.policy.clone());
    let replies = state
        .receive(&challenge(&FIXTURE.server.web_hash, &nonce))
        .unwrap();
    let transcript = [
        FIXTURE.server.web_hash.as_slice(),
        &replies[0][50..],
        &nonce,
    ]
    .concat();
    let mut signer = Signer::new(MessageDigest::sha384(), &foreign_key).unwrap();
    signer.update(&transcript).unwrap();
    let cert = FIXTURE.cert.to_der().unwrap();
    let forged = [
        vec![0, 2],
        (cert.len() as u16).to_be_bytes().to_vec(),
        cert,
        signer.sign_to_vec().unwrap(),
    ]
    .concat();
    state
        .receive(&wrapped_proof(&forged, &transcript, &foreign_cert))
        .unwrap();
    state.receive(&metadata(&FIXTURE.policy)).unwrap();
    assert!(
        state.finish().is_err(),
        "an embedded foreign key must not establish trust"
    );
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
fn additional_groups_enforce_their_own_node_allowlists() {
    let mut policy = (*FIXTURE.policy).clone();
    let second = "D4".repeat(48);
    let mut secondary = policy.clone();
    secondary.mesh_id_hex = second.clone();
    policy
        .additional_groups
        .push(meshcentral_server::auth::AgentGroup {
            mesh_id_hex: second.clone(),
            group_name: "Second group".into(),
            allowed_node_ids_hex: policy.allowed_node_ids_hex.clone(),
        });
    policy.validate().unwrap();
    let mut state = handshake(Arc::new(policy.clone()));
    let replies = state
        .receive(&challenge(&FIXTURE.server.web_hash, &[4; 48]))
        .unwrap();
    state.receive(&metadata(&secondary)).unwrap();
    state
        .receive(&proof(
            &FIXTURE.server.web_hash,
            &replies[0][50..],
            &[4; 48],
        ))
        .unwrap();
    let peer = state.finish().unwrap().unwrap();
    assert_eq!(peer.group, "Second group");
    assert_eq!(peer.mesh_id_hex, second);
    policy.additional_groups[0].allowed_node_ids_hex.clear();
    let mut state = handshake(Arc::new(policy));
    let replies = state
        .receive(&challenge(&FIXTURE.server.web_hash, &[4; 48]))
        .unwrap();
    state.receive(&metadata(&secondary)).unwrap();
    state
        .receive(&proof(
            &FIXTURE.server.web_hash,
            &replies[0][50..],
            &[4; 48],
        ))
        .unwrap();
    assert!(state.finish().is_err());
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

    // Removing an allowlisted identity while a previously valid handshake is in
    // flight must prevent admission when its final proof arrives.
    let (mut revoked, _) =
        connect_async_tls_with_config(url.clone(), None, false, Some(connector.clone()))
            .await
            .unwrap();
    revoked
        .send(Message::Binary(
            challenge(&FIXTURE.server.web_hash, &[9; 48]).into(),
        ))
        .await
        .unwrap();
    let Message::Binary(reply) = revoked.next().await.unwrap().unwrap() else {
        panic!("missing challenge");
    };
    let Message::Binary(_) = revoked.next().await.unwrap().unwrap() else {
        panic!("missing proof");
    };
    runtime.policy.write().unwrap().allowed_node_ids_hex.clear();
    revoked
        .send(Message::Binary(metadata(&FIXTURE.policy).into()))
        .await
        .unwrap();
    revoked
        .send(Message::Binary(
            proof(&FIXTURE.server.web_hash, &reply[50..], &[9; 48]).into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        revoked.next().await,
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
