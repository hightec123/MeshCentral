//! Offline encrypted snapshots. Never import arbitrary paths or overwrite state.
use crate::{
    auth::AdmissionPolicy, identity::Identity, operators::Operators, registry::Registry, storage,
};
use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const FILES: &[&str] = &[
    "identity.json",
    "admission.json",
    "inventory.json",
    "operators.json",
    "audit.json",
    crate::schedules::FILE_NAME,
    crate::forward_routes::FILE_NAME,
    "dashboard-auth.json",
    "dashboard-auth.sqlite",
];
const FORMAT: &str = "meshcentral-rust-backup";
const KDF: &str = "argon2id-v19-m19456-t2-p1";
const AAD: &[u8] = b"meshcentral-rust-backup:v1:argon2id-v19-m19456-t2-p1:aes-256-gcm";
const MAX_ARCHIVE: u64 = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    version: u32,
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
    tag: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    created_at: String,
    files: BTreeMap<String, Value>,
}
impl Snapshot {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.schema_version, 1 | 2),
            "unsupported snapshot schema"
        );
        chrono::DateTime::parse_from_rfc3339(&self.created_at)?;
        ensure!(
            self.files.contains_key("operators.json"),
            "snapshot has no operators"
        );
        ensure!(
            self.files.contains_key("identity.json") == self.files.contains_key("admission.json"),
            "snapshot trust files are incomplete"
        );
        ensure!(
            !self.files.contains_key("inventory.json") || self.files.contains_key("identity.json"),
            "inventory has no server identity"
        );
        for (name, value) in &self.files {
            ensure!(FILES.contains(&name.as_str()), "unknown snapshot file");
            if name == "dashboard-auth.sqlite" {
                let bytes =
                    STANDARD.decode(value.as_str().context("invalid auth database encoding")?)?;
                ensure!(
                    bytes.len() <= 4 * 1024 * 1024 && bytes.starts_with(b"SQLite format 3\0"),
                    "invalid auth database snapshot"
                );
                continue;
            }
            ensure!(
                serde_json::to_vec_pretty(value)?.len() <= 1024 * 1024,
                "snapshot file is too large"
            );
        }
        let migrated = self.files["operators.json"]["users"]
            .as_object()
            .is_some_and(|users| {
                users
                    .values()
                    .any(|record| record["auth_user_id"].is_string())
            });
        ensure!(
            self.files.contains_key("dashboard-auth.json")
                == self.files.contains_key("dashboard-auth.sqlite"),
            "auth database and secrets must be backed up together"
        );
        ensure!(
            !migrated || self.files.contains_key("dashboard-auth.sqlite"),
            "Better Auth identity is missing its database"
        );
        Ok(())
    }
}
fn key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        (12..=128).contains(&password.len()),
        "backup passphrase must contain 12–128 bytes"
    );
    let mut key = [0; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, Some(32))
            .map_err(|_| anyhow::anyhow!("invalid backup KDF parameters"))?,
    )
    .hash_password_into(password.as_bytes(), salt, &mut key)
    .map_err(|_| anyhow::anyhow!("backup key derivation failed"))?;
    Ok(key)
}
fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    STANDARD
        .decode(text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid backup field length"))
}
fn encrypt(snapshot: &Snapshot, password: &str) -> Result<Vec<u8>> {
    let mut salt = [0; 16];
    let mut nonce = [0; 12];
    let mut tag = [0; 16];
    rand_bytes(&mut salt)?;
    rand_bytes(&mut nonce)?;
    let key = key(password, &salt)?;
    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        AAD,
        &serde_json::to_vec(snapshot)?,
        &mut tag,
    )?;
    Ok(serde_json::to_vec_pretty(&Envelope {
        format: FORMAT.into(),
        version: 1,
        kdf: KDF.into(),
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
        tag: STANDARD.encode(tag),
    })?)
}
fn decrypt(bytes: &[u8], password: &str) -> Result<Snapshot> {
    ensure!(bytes.len() as u64 <= MAX_ARCHIVE, "backup is too large");
    let archive: Envelope = serde_json::from_slice(bytes).context("invalid backup envelope")?;
    ensure!(
        archive.format == FORMAT && archive.version == 1 && archive.kdf == KDF,
        "unsupported backup format"
    );
    let salt = decode::<16>(&archive.salt)?;
    let nonce = decode::<12>(&archive.nonce)?;
    let tag = decode::<16>(&archive.tag)?;
    let ciphertext = STANDARD.decode(&archive.ciphertext)?;
    let key = key(password, &salt)?;
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(&nonce),
        AAD,
        &ciphertext,
        &tag,
    )
    .map_err(|_| {
        anyhow::anyhow!("backup authentication failed: wrong passphrase or modified archive")
    })?;
    let snapshot: Snapshot =
        serde_json::from_slice(&plaintext).context("invalid backup payload")?;
    snapshot.validate()?;
    Ok(snapshot)
}

/// Hold the same exclusive lock as the server, so related trust/account records
/// are captured consistently. Output is encrypted, private and create-new only.
pub fn create(data_dir: &Path, output: &Path, password: &str) -> Result<()> {
    ensure!(data_dir.is_dir(), "server state directory does not exist");
    let _lock = storage::lock_directory(data_dir)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        ensure!(
            !data_dir
                .join(format!("dashboard-auth.sqlite{suffix}"))
                .try_exists()?,
            "auth database has an active or recovery journal; stop authentication cleanly before backing up"
        );
    }
    let mut files = BTreeMap::new();
    for name in FILES {
        let file = data_dir.join(name);
        if file.try_exists()? {
            let value = if *name == "dashboard-auth.sqlite" {
                Value::String(STANDARD.encode(storage::read_private(&file, 4 * 1024 * 1024)?))
            } else {
                storage::read_json(&file)?
            };
            files.insert(name.to_string(), value);
        }
    }
    let snapshot = Snapshot {
        schema_version: 2,
        created_at: chrono::Utc::now().to_rfc3339(),
        files,
    };
    snapshot.validate()?;
    let parent = output
        .parent()
        .context("backup output needs a parent directory")?;
    storage::private_directory(parent)?;
    let encrypted = encrypt(&snapshot, password)?;
    ensure!(
        encrypted.len() as u64 <= MAX_ARCHIVE,
        "backup exceeds the size limit"
    );
    storage::write_new(output, &encrypted)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        // Remove only the exact files this restore can create. Never recursively
        // delete a destination or follow paths supplied by an archive.
        for name in FILES.iter().copied().chain(["server.lock"]) {
            let _ = fs::remove_file(self.0.join(name));
        }
        let _ = fs::remove_dir(&self.0);
    }
}
/// Decrypt/authenticate before writing; validate restored identities/accounts in
/// private staging, reset live presence, then publish a new destination only.
pub fn restore(archive: &Path, destination: &Path, password: &str) -> Result<()> {
    ensure!(
        !destination.try_exists()? && fs::symlink_metadata(destination).is_err(),
        "restore destination already exists"
    );
    let snapshot = decrypt(&storage::read_private(archive, MAX_ARCHIVE)?, password)?;
    let parent = destination
        .parent()
        .context("restore destination needs a parent directory")?;
    storage::private_directory(parent)?;
    let _parent_lock = storage::lock_directory(parent)?;
    let mut random = [0; 16];
    rand_bytes(&mut random)?;
    let staging = Staging(parent.join(format!(".restore-{}", crate::identity::hex(&random))));
    ensure!(!staging.0.try_exists()?, "restore staging already exists");
    storage::private_directory(&staging.0)?;
    for (name, value) in &snapshot.files {
        let bytes = if name == "dashboard-auth.sqlite" {
            STANDARD.decode(value.as_str().context("invalid database encoding")?)?
        } else {
            serde_json::to_vec_pretty(value)?
        };
        storage::write_new(&staging.0.join(name), &bytes)?;
    }
    if snapshot.files.contains_key("identity.json") {
        Identity::load(&staging.0.join("identity.json"))?;
        AdmissionPolicy::load(&staging.0.join("admission.json"))?;
        // A saved online flag must never resurrect a live connection after restore.
        Registry::open(staging.0.join("inventory.json"))?;
    }
    crate::schedules::Schedules::open(staging.0.join(crate::schedules::FILE_NAME), true)?;
    crate::forward_routes::load(&staging.0)?;
    let operators = Operators::open(&staging.0)?;
    ensure!(
        operators.users().iter().any(|user| user.admin()),
        "snapshot has no administrator"
    );
    drop(operators);
    ensure!(
        !destination.try_exists()? && fs::symlink_metadata(destination).is_err(),
        "restore destination already exists"
    );
    #[cfg(unix)]
    fs::File::open(&staging.0)?.sync_all()?;
    fs::rename(&staging.0, destination)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_encryption_rejects_wrong_password_and_modified_headers_or_bytes() {
        let snapshot = Snapshot {
            schema_version: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
            files: BTreeMap::from([(
                "operators.json".into(),
                serde_json::json!({"secret":"never plaintext"}),
            )]),
        };
        let bytes = encrypt(&snapshot, "backup-test-password").unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("never plaintext"));
        assert!(decrypt(&bytes, "wrong-backup-password").is_err());
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        for field in ["format", "kdf", "version"] {
            let mut altered = original.clone();
            altered[field] = if field == "version" {
                2.into()
            } else {
                "unsupported".into()
            };
            assert!(
                decrypt(
                    &serde_json::to_vec(&altered).unwrap(),
                    "backup-test-password"
                )
                .is_err()
            );
        }
        for field in ["salt", "nonce", "ciphertext", "tag"] {
            let mut altered = original.clone();
            let mut decoded = STANDARD.decode(altered[field].as_str().unwrap()).unwrap();
            decoded[0] ^= 1;
            altered[field] = STANDARD.encode(decoded).into();
            assert!(
                decrypt(
                    &serde_json::to_vec(&altered).unwrap(),
                    "backup-test-password"
                )
                .is_err()
            );
        }
        assert!(
            decrypt(
                &encrypt(&snapshot, "backup-test-password").unwrap(),
                "backup-test-password"
            )
            .is_ok()
        );
    }
    #[test]
    fn archive_paths_and_incomplete_trust_never_restore() {
        let mut snapshot = Snapshot {
            schema_version: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
            files: BTreeMap::from([("operators.json".into(), Value::Null)]),
        };
        snapshot.files.insert("../escaped.json".into(), Value::Null);
        assert!(snapshot.validate().is_err());
        snapshot.files.remove("../escaped.json");
        snapshot.files.insert("identity.json".into(), Value::Null);
        assert!(snapshot.validate().is_err());
    }
}
