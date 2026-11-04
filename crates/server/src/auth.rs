//! MeshAgent certificate possession and explicit lab admission. No TOFU enrollment.
use crate::{
    identity::{Identity, decode_hex, hex, mesh_base64, public_key_der},
    storage,
};
use anyhow::{Result, bail, ensure};
use meshcentral_protocol::{AgentInfo, HandshakeFrame, decode_handshake};
use openssl::{
    hash::MessageDigest, memcmp, rand::rand_bytes, sha::sha384, sign::Verifier, x509::X509,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionPolicy {
    pub schema_version: u32,
    pub mesh_id_hex: String,
    pub group_name: String,
    pub allowed_node_ids_hex: Vec<String>,
    #[serde(default)]
    pub additional_groups: Vec<AgentGroup>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AgentGroup {
    pub mesh_id_hex: String,
    pub group_name: String,
    pub allowed_node_ids_hex: Vec<String>,
}

impl AdmissionPolicy {
    pub fn lab(node_id_hex: &str) -> Result<Self> {
        let node_id = decode_hex::<48>(node_id_hex)?;
        let mut mesh_id = [0; 48];
        rand_bytes(&mut mesh_id)?;
        Ok(Self {
            schema_version: 1,
            mesh_id_hex: hex(&mesh_id),
            group_name: "Rust lab".into(),
            allowed_node_ids_hex: vec![hex(&node_id)],
            additional_groups: vec![],
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported policy schema");
        decode_hex::<48>(&self.mesh_id_hex)?;
        ensure!(
            !self.group_name.is_empty()
                && self.group_name.len() <= 64
                && !self.group_name.chars().any(char::is_control),
            "invalid group name"
        );
        ensure!(
            self.allowed_node_ids_hex.len() <= 32,
            "lab policy allows at most 32 explicitly allowed nodes"
        );
        for node in &self.allowed_node_ids_hex {
            decode_hex::<48>(node)?;
        }
        ensure!(self.additional_groups.len() <= 63, "too many groups");
        let mut ids = std::collections::BTreeSet::new();
        for group in self.groups() {
            decode_hex::<48>(&group.mesh_id_hex)?;
            ensure!(
                ids.insert(group.mesh_id_hex.to_ascii_uppercase()),
                "duplicate mesh ID"
            );
            ensure!(
                !group.group_name.is_empty()
                    && group.group_name.len() <= 64
                    && !group.group_name.chars().any(char::is_control),
                "invalid group name"
            );
            ensure!(
                group.allowed_node_ids_hex.len() <= 32,
                "too many group nodes"
            );
            for node in group.allowed_node_ids_hex {
                decode_hex::<48>(&node)?;
            }
        }
        Ok(())
    }

    pub fn groups(&self) -> Vec<AgentGroup> {
        let mut groups = vec![AgentGroup {
            mesh_id_hex: self.mesh_id_hex.clone(),
            group_name: self.group_name.clone(),
            allowed_node_ids_hex: self.allowed_node_ids_hex.clone(),
        }];
        groups.extend(self.additional_groups.clone());
        groups
    }
    pub fn group(&self, id: &str) -> Option<AgentGroup> {
        self.groups()
            .into_iter()
            .find(|g| g.mesh_id_hex.eq_ignore_ascii_case(id))
    }
    pub fn permits(&self, mesh: &str, node: &str) -> bool {
        self.group(mesh).is_some_and(|g| {
            g.allowed_node_ids_hex
                .iter()
                .any(|n| n.eq_ignore_ascii_case(node))
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let policy: Self = storage::read_json(path)?;
        policy.validate()?;
        Ok(policy)
    }
}

#[derive(Clone)]
struct Metadata {
    mesh_id: [u8; 48],
    name: String,
    architecture: u32,
}

impl TryFrom<AgentInfo<'_>> for Metadata {
    type Error = anyhow::Error;
    fn try_from(info: AgentInfo<'_>) -> Result<Self> {
        ensure!(
            info.computer_name.len() <= 255 && !info.computer_name.chars().any(char::is_control),
            "invalid computer name"
        );
        Ok(Self {
            mesh_id: *info.mesh_id,
            name: info.computer_name.into(),
            architecture: info.architecture,
        })
    }
}

#[derive(Debug)]
pub struct AuthenticatedPeer {
    pub node_id: String,
    pub name: String,
    pub group: String,
    pub architecture: u32,
    pub mesh_id_hex: String,
    pub node_id_hex: String,
}

/// Single-use, per-connection state. Cached-server acknowledgment never bypasses
/// TLS hash checking, a fresh signature, or node/mesh admission.
pub struct Handshake {
    identity: Arc<Identity>,
    policy: Arc<AdmissionPolicy>,
    nonce: [u8; 48],
    challenge: Option<([u8; 48], [u8; 48])>,
    proof: Option<(Vec<u8>, Vec<u8>)>,
    metadata: Option<Metadata>,
    seen: u32,
    complete: bool,
}

impl Handshake {
    pub fn new(identity: Arc<Identity>, policy: Arc<AdmissionPolicy>) -> Result<Self> {
        policy.validate()?;
        let mut nonce = [0; 48];
        rand_bytes(&mut nonce)?;
        Ok(Self {
            identity,
            policy,
            nonce,
            challenge: None,
            proof: None,
            metadata: None,
            seen: 0,
            complete: false,
        })
    }

    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        ensure!(!self.complete, "handshake is already complete");
        let frame = decode_handshake(bytes)?;
        let tag = match &frame {
            HandshakeFrame::Challenge { .. } => 1,
            HandshakeFrame::CertificateProof { .. } => 2,
            HandshakeFrame::AgentInfo(_) => 3,
            HandshakeFrame::ServerIdentityAccepted => 4,
            HandshakeFrame::ExpectedServerIdentity(_) => 5,
            HandshakeFrame::AgentCommitDate(_) => 6,
            HandshakeFrame::HostInfo(_) => 7,
        };
        ensure!(self.seen & (1 << tag) == 0, "duplicate handshake command");
        self.seen |= 1 << tag;
        match frame {
            HandshakeFrame::Challenge {
                web_certificate_hash,
                nonce,
            } => {
                ensure!(
                    memcmp::eq(web_certificate_hash, &self.identity.web_hash)
                        || memcmp::eq(web_certificate_hash, &self.identity.web_key_hash),
                    "TLS certificate hash mismatch"
                );
                self.challenge = Some((*web_certificate_hash, *nonce));
                let mut challenge = vec![0, 1];
                challenge.extend(web_certificate_hash);
                challenge.extend(self.nonce);
                // Respect the agent's cached TLS proof, but still challenge its identity.
                if self.seen & (1 << 4) != 0 {
                    return Ok(vec![challenge]);
                }
                Ok(vec![
                    challenge,
                    self.identity
                        .proof(web_certificate_hash, nonce, &self.nonce)?,
                ])
            }
            HandshakeFrame::CertificateProof {
                certificate_der,
                signature,
            } => {
                self.proof = Some((certificate_der.to_vec(), signature.to_vec()));
                Ok(vec![])
            }
            HandshakeFrame::AgentInfo(info) => {
                ensure!(
                    self.policy.group(&hex(info.mesh_id)).is_some(),
                    "mesh is not authorized"
                );
                self.metadata = Some(info.try_into()?);
                Ok(vec![])
            }
            HandshakeFrame::ExpectedServerIdentity(id) => {
                ensure!(
                    (id.len() == 48 && memcmp::eq(id, &self.identity.server_id))
                        || (id.len() == 32 && memcmp::eq(id, &self.identity.server_id_legacy)),
                    "unexpected server identity"
                );
                Ok(vec![])
            }
            HandshakeFrame::ServerIdentityAccepted
            | HandshakeFrame::AgentCommitDate(_)
            | HandshakeFrame::HostInfo(_) => Ok(vec![]),
        }
    }

    pub fn finish(&mut self) -> Result<Option<AuthenticatedPeer>> {
        ensure!(!self.complete, "handshake is already complete");
        let (Some((web_hash, agent_nonce)), Some((certificate, signature)), Some(metadata)) =
            (&self.challenge, &self.proof, &self.metadata)
        else {
            return Ok(None);
        };
        let group = self
            .policy
            .group(&hex(&metadata.mesh_id))
            .ok_or_else(|| anyhow::anyhow!("mesh is not authorized"))?;
        let cert = X509::from_der(certificate)?;
        ensure!(cert.to_der()? == *certificate, "trailing certificate bytes");
        let public_key = cert.public_key()?;
        let rsa = public_key.rsa()?;
        ensure!(
            (2048..=4096).contains(&rsa.n().num_bits()),
            "unsupported agent RSA key size"
        );
        let fingerprint = sha384(&public_key_der(&cert)?);
        ensure!(
            group
                .allowed_node_ids_hex
                .iter()
                .any(|allowed| decode_hex::<48>(allowed)
                    .is_ok_and(|id| memcmp::eq(&id, &fingerprint))),
            "node is not authorized"
        );
        // Windows CryptoAPI agents wrap the same raw signature in PKCS#7.
        // Embedded certificates/content confer no trust: verify only under the
        // allowlisted outer certificate against this fresh handshake transcript.
        let signature = if signature.len() == rsa.size() as usize {
            signature.as_slice()
        } else {
            meshcentral_protocol::pkcs7_rsa_signature(signature)?
        };
        ensure!(
            signature.len() == rsa.size() as usize,
            "signature/key size mismatch"
        );
        let mut verifier = Verifier::new(MessageDigest::sha384(), &public_key)?;
        verifier.update(web_hash)?;
        verifier.update(&self.nonce)?;
        verifier.update(agent_nonce)?;
        if !verifier.verify(signature)? {
            bail!("invalid agent signature");
        }
        self.complete = true;
        Ok(Some(AuthenticatedPeer {
            node_id: mesh_base64(&fingerprint),
            name: if metadata.name.is_empty() {
                "Unnamed device".into()
            } else {
                metadata.name.clone()
            },
            group: group.group_name,
            architecture: metadata.architecture,
            mesh_id_hex: hex(&metadata.mesh_id),
            node_id_hex: hex(&fingerprint),
        }))
    }
}
