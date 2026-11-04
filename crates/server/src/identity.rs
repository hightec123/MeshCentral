use crate::storage;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sha::{sha256, sha384},
    sign::Signer,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    schema_version: u32,
    agent_certificate: String,
    agent_key: String,
    tls_certificate: String,
    tls_key: String,
}

pub struct Identity {
    pub agent_certificate: X509,
    pub agent_key: PKey<Private>,
    pub tls_certificate: X509,
    pub tls_key: PKey<Private>,
    pub server_id: [u8; 48],
    pub server_id_legacy: [u8; 32],
    pub web_hash: [u8; 48],
    pub web_key_hash: [u8; 48],
}

pub fn public_key_der(certificate: &X509) -> Result<Vec<u8>> {
    Ok(certificate.public_key()?.rsa()?.public_key_to_der_pkcs1()?)
}

pub fn node_id(certificate: &X509) -> Result<String> {
    Ok(mesh_base64(&sha384(&public_key_der(certificate)?)))
}

pub fn mesh_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes).replace('+', "@").replace('/', "$")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

pub fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == N * 2 && text.is_ascii(),
        "invalid fingerprint length"
    );
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .context("invalid fingerprint hex")?;
    }
    Ok(result)
}

pub fn generate_certificate(name: &str) -> Result<(X509, PKey<Private>)> {
    let key = PKey::from_rsa(Rsa::generate(3072)?)?;
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("CN", name)?;
    let subject = subject.build();
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = serial.to_asn1_integer()?;
    let mut cert = X509::builder()?;
    cert.set_version(2)?;
    cert.set_serial_number(&serial)?;
    cert.set_subject_name(&subject)?;
    cert.set_issuer_name(&subject)?;
    cert.set_pubkey(&key)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    cert.set_not_before(&not_before)?;
    cert.set_not_after(&not_after)?;
    cert.append_extension(BasicConstraints::new().critical().build()?)?;
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    cert.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .ip("127.0.0.1")
        .ip("::1")
        .build(&cert.x509v3_context(None, None))?;
    cert.append_extension(san)?;
    cert.sign(&key, MessageDigest::sha384())?;
    Ok((cert.build(), key))
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let (agent_certificate, agent_key) = generate_certificate("MeshCentral Rust lab identity")?;
        let (tls_certificate, tls_key) = generate_certificate("localhost")?;
        Self::from_file(IdentityFile {
            schema_version: 1,
            agent_certificate: String::from_utf8(agent_certificate.to_pem()?)?,
            agent_key: String::from_utf8(agent_key.private_key_to_pem_pkcs8()?)?,
            tls_certificate: String::from_utf8(tls_certificate.to_pem()?)?,
            tls_key: String::from_utf8(tls_key.private_key_to_pem_pkcs8()?)?,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::from_file(storage::read_json(path)?)
    }

    fn from_file(file: IdentityFile) -> Result<Self> {
        ensure!(file.schema_version == 1, "unsupported identity schema");
        let agent_certificate = X509::from_pem(file.agent_certificate.as_bytes())?;
        let agent_key = PKey::private_key_from_pem(file.agent_key.as_bytes())?;
        let tls_certificate = X509::from_pem(file.tls_certificate.as_bytes())?;
        let tls_key = PKey::private_key_from_pem(file.tls_key.as_bytes())?;
        for (certificate, key) in [
            (&agent_certificate, &agent_key),
            (&tls_certificate, &tls_key),
        ] {
            ensure!(
                certificate.public_key()?.public_eq(key),
                "certificate/private-key mismatch"
            );
            ensure!(
                (2048..=4096).contains(&key.rsa()?.n().num_bits()),
                "unsupported RSA key size"
            );
            let now = Asn1Time::days_from_now(0)?;
            ensure!(
                certificate.not_before() <= now && certificate.not_after() > now,
                "server certificate is not currently valid"
            );
        }
        let public_key = public_key_der(&agent_certificate)?;
        Ok(Self {
            server_id: sha384(&public_key),
            server_id_legacy: sha256(&public_key),
            web_hash: sha384(&tls_certificate.to_der()?),
            web_key_hash: sha384(&public_key_der(&tls_certificate)?),
            agent_certificate,
            agent_key,
            tls_certificate,
            tls_key,
        })
    }

    pub fn save_new(&self, path: &Path) -> Result<()> {
        storage::write_new(
            path,
            &serde_json::to_vec_pretty(&IdentityFile {
                schema_version: 1,
                agent_certificate: String::from_utf8(self.agent_certificate.to_pem()?)?,
                agent_key: String::from_utf8(self.agent_key.private_key_to_pem_pkcs8()?)?,
                tls_certificate: String::from_utf8(self.tls_certificate.to_pem()?)?,
                tls_key: String::from_utf8(self.tls_key.private_key_to_pem_pkcs8()?)?,
            })?,
        )
    }

    pub fn proof(
        &self,
        web_hash: &[u8; 48],
        agent_nonce: &[u8; 48],
        server_nonce: &[u8; 48],
    ) -> Result<Vec<u8>> {
        let mut signer = Signer::new(MessageDigest::sha384(), &self.agent_key)?;
        signer.update(web_hash)?;
        signer.update(agent_nonce)?;
        signer.update(server_nonce)?;
        let certificate = self.agent_certificate.to_der()?;
        let mut frame = vec![0, 2];
        frame.extend_from_slice(&u16::try_from(certificate.len())?.to_be_bytes());
        frame.extend(certificate);
        frame.extend(signer.sign_to_vec()?);
        Ok(frame)
    }
}
