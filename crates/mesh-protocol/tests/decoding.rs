use meshcentral_protocol::{DecodeError, HandshakeFrame, MAX_HANDSHAKE_FRAME, decode_handshake};

fn hex(input: &str) -> Vec<u8> {
    input
        .trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn info() -> Vec<u8> {
    hex(include_str!("fixtures/agent-info.hex"))
}

#[test]
fn upstream_encoded_challenge_preserves_hash_and_nonce() {
    let frame = hex(include_str!("fixtures/challenge.hex"));
    let HandshakeFrame::Challenge {
        web_certificate_hash,
        nonce,
    } = decode_handshake(&frame).unwrap()
    else {
        panic!("expected challenge");
    };
    assert_eq!(
        web_certificate_hash.as_slice(),
        (0..48).collect::<Vec<u8>>()
    );
    assert_eq!(nonce.as_slice(), (128..176).collect::<Vec<u8>>());
}

#[test]
fn upstream_encoded_metadata_preserves_unsigned_fields_and_utf8() {
    let frame = info();
    let HandshakeFrame::AgentInfo(info) = decode_handshake(&frame).unwrap() else {
        panic!("expected agent metadata");
    };
    assert_eq!(info.info_version, 1);
    assert_eq!(info.architecture, 29);
    assert_eq!(info.agent_version, 0x01020304);
    assert_eq!(info.platform, 6);
    assert_eq!(info.mesh_id.as_slice(), (32..80).collect::<Vec<u8>>());
    assert_eq!(info.capabilities, 0x80000011);
    assert_eq!(info.computer_name, "lab-ā");
}

#[test]
fn legacy_metadata_without_a_name_is_accepted() {
    let frame = hex(include_str!("fixtures/agent-info-legacy-no-name.hex"));
    let HandshakeFrame::AgentInfo(info) = decode_handshake(&frame).unwrap() else {
        panic!("expected agent metadata");
    };
    assert_eq!(info.computer_name, "");
}

#[test]
fn certificate_proof_is_split_but_not_authenticated() {
    let frame = hex(include_str!(
        "fixtures/certificate-proof-structure-only.hex"
    ));
    assert_eq!(
        decode_handshake(&frame),
        Ok(HandshakeFrame::CertificateProof {
            certificate_der: &[1, 2, 3],
            signature: &[4, 5, 6, 7],
        })
    );
}

#[test]
fn truncated_challenges_never_decode_or_panic() {
    let frame = hex(include_str!("fixtures/challenge.hex"));
    for length in 0..frame.len() {
        assert!(
            decode_handshake(&frame[..length]).is_err(),
            "length {length}"
        );
    }
}

#[test]
fn truncated_metadata_cannot_fabricate_a_name() {
    let frame = info();
    for length in 0..frame.len() {
        // Exactly 70 bytes is the valid legacy no-name form.
        if length != 70 {
            assert!(
                decode_handshake(&frame[..length]).is_err(),
                "length {length}"
            );
        }
    }
}

#[test]
fn invalid_utf8_and_name_lengths_are_rejected() {
    let mut frame = info();
    frame[72] = 255;
    assert_eq!(decode_handshake(&frame), Err(DecodeError::InvalidUtf8));
    frame[70..72].copy_from_slice(&65535_u16.to_be_bytes());
    assert_eq!(decode_handshake(&frame), Err(DecodeError::InvalidLength));
}

#[test]
fn certificate_lengths_cannot_escape_the_frame() {
    for frame in [&[0, 2, 255, 255][..], &[0, 2, 0, 0, 1], &[0, 2, 0, 1, 1]] {
        assert_eq!(decode_handshake(frame), Err(DecodeError::InvalidLength));
    }
}

#[test]
fn both_supported_server_fingerprint_lengths_decode() {
    for length in [32, 48] {
        let mut frame = vec![0, 5];
        frame.extend(vec![42; length]);
        assert_eq!(
            decode_handshake(&frame),
            Ok(HandshakeFrame::ExpectedServerIdentity(&frame[2..]))
        );
    }
    assert!(decode_handshake(&[0, 5, 1]).is_err());
}

#[test]
fn identity_acknowledgment_is_not_agent_authentication() {
    assert_eq!(
        decode_handshake(&[0, 4]),
        Ok(HandshakeFrame::ServerIdentityAccepted)
    );
    assert!(decode_handshake(&[0, 4, 1]).is_err());
}

#[test]
fn commit_date_is_only_untrusted_metadata() {
    assert_eq!(
        decode_handshake(b"\x00\x1e2026-10-01"),
        Ok(HandshakeFrame::AgentCommitDate("2026-10-01"))
    );
    assert!(decode_handshake(b"\x00\x1e").is_err());
}

#[test]
fn unknown_commands_and_oversized_frames_are_rejected() {
    assert_eq!(
        decode_handshake(&[0, 255]),
        Err(DecodeError::UnsupportedCommand(255))
    );
    assert_eq!(
        decode_handshake(&vec![0; MAX_HANDSHAKE_FRAME + 1]),
        Err(DecodeError::FrameTooLarge)
    );
}

#[test]
fn host_information_is_bounded_untrusted_metadata() {
    assert_eq!(
        decode_handshake(b"\x00\x1fmacOS - arm64"),
        Ok(HandshakeFrame::HostInfo("macOS - arm64"))
    );
    assert!(decode_handshake(&[vec![0, 31], vec![b'a'; 513]].concat()).is_err());
    assert!(decode_handshake(&[0, 31, 255]).is_err());
}
