//! Private Better Auth process and authenticated loopback bridge. MeshAgent TLS
//! authentication is independent of this module.
use crate::{operators::Operators, storage};
use anyhow::{Context, Result, ensure};
use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::timeout,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secrets {
    schema_version: u32,
    secret: String,
    internal_secret: String,
    cookie_prefix: String,
}

#[derive(Clone, Deserialize)]
pub struct AuthenticatedSession {
    pub user_id: String,
    pub username: String,
    pub session_id: String,
    pub expires_at: i64,
}
pub struct DashboardAuth {
    client: reqwest::Client,
    url: String,
    secrets: Secrets,
}
pub struct AuthProcess {
    child: Child,
    pub bridge: Arc<DashboardAuth>,
}
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl AuthProcess {
    pub async fn start(directory: &Path, origin: &str, operators: &Arc<Operators>) -> Result<Self> {
        let directory = std::fs::canonicalize(directory)?;
        let path = directory.join("dashboard-auth.json");
        let migrated = operators.has_external_identities();
        let database_path = directory.join("dashboard-auth.sqlite");
        if std::fs::symlink_metadata(&database_path).is_ok() {
            storage::read_private(&database_path, 4 * 1024 * 1024)?;
        }
        ensure!(
            !migrated || (path.is_file() && directory.join("dashboard-auth.sqlite").is_file()),
            "Better Auth state is missing; restore the auth database and secrets rather than regenerating identity"
        );
        let secrets: Secrets = if path.exists() {
            storage::read_json(&path)?
        } else {
            let value = Secrets {
                schema_version: 1,
                secret: crate::operators::random_token()?,
                internal_secret: crate::operators::random_token()?,
                cookie_prefix: format!(
                    "mcr-{}",
                    crate::operators::random_token()?.get(..12).unwrap()
                ),
            };
            storage::write_new(&path, &serde_json::to_vec_pretty(&value)?)?;
            value
        };
        ensure!(
            secrets.schema_version == 1
                && secrets.secret.len() >= 32
                && secrets.internal_secret.len() >= 32,
            "invalid Better Auth secrets"
        );
        let entry = std::env::var_os("MCR_AUTH_ENTRY")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../auth/src/service.ts")
            });
        let mut child = Command::new(std::env::var_os("MCR_BUN").unwrap_or_else(|| "bun".into()))
            .arg(entry)
            .env("MCR_AUTH_DATA_DIR", &directory)
            .env("MCR_AUTH_ORIGIN", origin)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("starting Better Auth: install Bun and run npm --prefix auth ci")?;
        let stdout = child
            .stdout
            .take()
            .context("auth service has no readiness pipe")?;
        let mut lines = BufReader::new(stdout).lines();
        let port = timeout(Duration::from_secs(20), async {
            while let Some(line) = lines.next_line().await? {
                if let Some(port) = line.strip_prefix("MCR_AUTH_READY=") {
                    return port.parse::<u16>().context("invalid auth service port");
                }
            }
            anyhow::bail!("Better Auth stopped before becoming ready")
        })
        .await
        .context("Better Auth startup timed out")??;
        ensure!(port != 0, "invalid auth service port");
        // Drain non-secret process output without logging response bodies/tokens.
        tokio::spawn(async move { while matches!(lines.next_line().await, Ok(Some(_))) {} });
        let bridge = Arc::new(DashboardAuth {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()?,
            url: format!("http://127.0.0.1:{port}"),
            secrets,
        });
        for (user, hash, id) in operators.identity_records() {
            let result = bridge
                .internal(
                    "identity",
                    json!({"username":user.username,"password_hash":hash,"expected_id":id}),
                )
                .await?;
            let id = result["user_id"]
                .as_str()
                .context("auth identity response missing id")?;
            operators.bind_external_identity(&user.username, id)?;
        }
        operators.attach_auth(bridge.clone());
        Ok(Self { child, bridge })
    }
    pub async fn wait(&mut self) -> Result<()> {
        let status = self.child.wait().await?;
        anyhow::bail!("Better Auth process stopped ({status})")
    }
    pub async fn shutdown(&mut self) {
        let _ = self.bridge.internal("shutdown", json!({})).await;
        if timeout(Duration::from_secs(3), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
    }
}
impl DashboardAuth {
    pub async fn internal(&self, path: &str, body: Value) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}/internal/{path}", self.url))
            .header("x-mcr-internal", &self.secrets.internal_secret)
            .json(&body)
            .send()
            .await
            .context("Better Auth unavailable")?;
        ensure!(
            response.status().is_success(),
            "Better Auth operation failed ({})",
            response.status().as_u16()
        );
        Ok(response.json().await?)
    }
    pub async fn session(&self, cookie: &str) -> Result<Option<AuthenticatedSession>> {
        if cookie.is_empty() {
            return Ok(None);
        }
        ensure!(cookie.len() <= 8192, "cookie header is too large");
        let value = self.internal("session", json!({"cookie":cookie})).await?;
        if value.is_null() {
            Ok(None)
        } else {
            Ok(Some(serde_json::from_value(value)?))
        }
    }
    pub fn csrf(&self, id: &str) -> Result<String> {
        let key = PKey::hmac(self.secrets.internal_secret.as_bytes())?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(b"dashboard-csrf:")?;
        signer.update(id.as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(signer.sign_to_vec()?))
    }
    pub async fn request(
        &self,
        path: &str,
        method: &str,
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> Result<Reply> {
        let allowed = [
            "sign-in/username",
            "sign-out",
            "get-session",
            "change-password",
            "list-sessions",
            "revoke-session",
            "revoke-sessions",
            "revoke-other-sessions",
        ];
        ensure!(
            allowed.contains(&path),
            "unsupported dashboard authentication endpoint"
        );
        let mut request = self
            .client
            .request(method.parse()?, format!("{}/api/auth/{path}", self.url))
            .header("x-mcr-internal", &self.secrets.internal_secret);
        for name in ["cookie", "origin", "content-type", "sec-fetch-site", "host"] {
            if let Some(value) = headers.get(name) {
                request = request.header(name, value);
            }
        }
        let response = request
            .body(body)
            .send()
            .await
            .context("Better Auth unavailable")?;
        let status = response.status();
        let mut output = HeaderMap::new();
        for name in ["set-cookie", "content-type", "cache-control"] {
            for value in response.headers().get_all(name) {
                output.append(name, value.clone());
            }
        }
        ensure!(
            response.content_length().unwrap_or(0) <= 64 * 1024,
            "auth response too large"
        );
        let bytes = response.bytes().await?;
        ensure!(bytes.len() <= 64 * 1024, "auth response too large");
        Ok(Reply {
            status,
            headers: output,
            body: bytes.to_vec(),
        })
    }
}
