use crate::storage;
use anyhow::{Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{rand::rand_bytes, sha::sha256};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Administrator,
    Operator,
    Viewer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub role: Role,
    pub groups: Vec<String>,
}
impl User {
    pub fn admin(&self) -> bool {
        self.role == Role::Administrator
    }
    pub fn can_view(&self, group: &str) -> bool {
        self.admin() || self.groups.iter().any(|g| g.eq_ignore_ascii_case(group))
    }
    pub fn can_control(&self, group: &str) -> bool {
        self.role != Role::Viewer && self.can_view(group)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    user: User,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    password_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_user_id: Option<String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Accounts {
    users: BTreeMap<String, Record>,
}
struct Session {
    username: String,
    csrf: String,
    created: Instant,
    last_used: Instant,
    external: Option<(String, Instant, i64)>,
}
struct Inner {
    accounts: Accounts,
    sessions: BTreeMap<[u8; 32], Session>,
    attempts: VecDeque<(Instant, u64)>,
    next_attempt: u64,
    revoked: BTreeMap<[u8; 32], Instant>,
}

fn current_principal(inner: &Inner, principal: &Principal) -> bool {
    inner
        .sessions
        .get(&principal.session_key)
        .is_some_and(|session| {
            session.username == principal.user.username
                && session.created.elapsed() < Duration::from_secs(8 * 3600)
                && session.last_used.elapsed() < Duration::from_secs(3600)
        })
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub time: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
}
pub struct Audit {
    path: PathBuf,
    events: Mutex<Vec<AuditEvent>>,
}
impl Audit {
    pub fn open(path: PathBuf) -> Result<Arc<Self>> {
        let events = if path.exists() {
            storage::read_json(&path)?
        } else {
            vec![]
        };
        Ok(Arc::new(Self {
            path,
            events: Mutex::new(events),
        }))
    }
    pub fn record(&self, actor: &str, action: &str, target: &str, outcome: &str) -> Result<()> {
        let mut events = self.events.lock().unwrap_or_else(|p| p.into_inner());
        let mut next = events.clone();
        next.push(AuditEvent {
            time: chrono::Utc::now().to_rfc3339(),
            actor: actor.chars().take(64).collect(),
            action: action.into(),
            target: target.chars().take(512).collect(),
            outcome: outcome.into(),
        });
        if next.len() > 500 {
            next.drain(..next.len() - 500);
        }
        storage::replace_json(&self.path, &next)?;
        *events = next;
        Ok(())
    }
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .rev()
            .cloned()
            .collect()
    }
}

pub struct Operators {
    path: PathBuf,
    inner: Mutex<Inner>,
    hashes: Arc<Semaphore>,
    pending_hashes: Arc<Semaphore>,
    dummy_hash: String,
    pub audit: Arc<Audit>,
    auth: RwLock<Option<Arc<crate::dashboard_auth::DashboardAuth>>>,
}
#[derive(Clone)]
pub struct Principal {
    pub user: User,
    pub csrf: String,
    pub session_key: [u8; 32],
}

pub fn random_token() -> Result<String> {
    let mut bytes = [0; 32];
    rand_bytes(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub fn normalize_username(name: &str) -> Result<String> {
    ensure!(
        (3..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "username must be 3–64 letters, digits, dots, underscores or hyphens"
    );
    Ok(name.to_ascii_lowercase())
}
pub fn hash_password(password: &str) -> Result<String> {
    ensure!(
        (12..=128).contains(&password.len()),
        "password must contain 12–128 bytes"
    );
    let mut salt = [0; 16];
    rand_bytes(&mut salt)?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string())
}
fn verify(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

impl Operators {
    pub fn auth(&self) -> Option<Arc<crate::dashboard_auth::DashboardAuth>> {
        self.auth.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn attach_auth(&self, auth: Arc<crate::dashboard_auth::DashboardAuth>) {
        *self.auth.write().unwrap_or_else(|e| e.into_inner()) = Some(auth);
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .clear();
    }
    pub fn has_external_identities(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accounts
            .users
            .values()
            .any(|record| record.auth_user_id.is_some())
    }
    pub fn identity_records(&self) -> Vec<(User, String, Option<String>)> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accounts
            .users
            .values()
            .map(|record| {
                (
                    record.user.clone(),
                    record.password_hash.clone(),
                    record.auth_user_id.clone(),
                )
            })
            .collect()
    }
    pub fn bind_external_identity(&self, username: &str, id: &str) -> Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = inner.accounts.clone();
        let record = next
            .users
            .get_mut(username)
            .ok_or_else(|| anyhow::anyhow!("operator missing"))?;
        ensure!(
            record
                .auth_user_id
                .as_deref()
                .is_none_or(|expected| expected == id),
            "auth identity mismatch"
        );
        record.auth_user_id = Some(id.into());
        record.password_hash.clear();
        storage::replace_json(&self.path, &next)?;
        inner.accounts = next;
        Ok(())
    }
    pub async fn dashboard_principal(&self, cookie: &str) -> Result<Option<Principal>> {
        let auth = self
            .auth()
            .ok_or_else(|| anyhow::anyhow!("Better Auth not configured"))?;
        let Some(session) = auth.session(cookie).await? else {
            return Ok(None);
        };
        let csrf = auth.csrf(&session.session_id)?;
        self.accept_external(session, cookie, csrf, true)
    }
    fn accept_external(
        &self,
        session: crate::dashboard_auth::AuthenticatedSession,
        cookie: &str,
        csrf: String,
        touch: bool,
    ) -> Result<Option<Principal>> {
        let key = sha256(session.session_id.as_bytes());
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .revoked
            .retain(|_, time| time.elapsed() < Duration::from_secs(8 * 3600));
        if inner.revoked.contains_key(&key) || session.expires_at <= chrono::Utc::now().timestamp()
        {
            return Ok(None);
        }
        let Some(record) = inner.accounts.users.get(&session.username) else {
            return Ok(None);
        };
        if record.auth_user_id.as_deref() != Some(&session.user_id) {
            return Ok(None);
        }
        let user = record.user.clone();
        if !inner.sessions.contains_key(&key) {
            inner.sessions.retain(|_, s| {
                s.created.elapsed() < Duration::from_secs(8 * 3600)
                    && s.last_used.elapsed() < Duration::from_secs(3600)
            });
            ensure!(inner.sessions.len() < 256, "too many dashboard sessions");
            inner.sessions.insert(
                key,
                Session {
                    username: session.username,
                    csrf: csrf.clone(),
                    created: now,
                    last_used: now,
                    external: Some((cookie.into(), now, session.expires_at)),
                },
            );
        }
        let entry = inner.sessions.get_mut(&key).unwrap();
        if touch {
            entry.last_used = now;
        }
        entry.external = Some((cookie.into(), now, session.expires_at));
        Ok(Some(Principal {
            user,
            csrf,
            session_key: key,
        }))
    }
    pub fn cached_dashboard(&self, cookie: &str) -> Option<Principal> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.sessions.iter().find_map(|(key, session)| {
            if session
                .external
                .as_ref()
                .is_some_and(|(value, _, _)| value == cookie)
            {
                Some(Principal {
                    user: inner.accounts.users.get(&session.username)?.user.clone(),
                    csrf: session.csrf.clone(),
                    session_key: *key,
                })
            } else {
                None
            }
        })
    }
    pub fn revoke_key(&self, key: &[u8; 32]) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.sessions.remove(key);
        inner.revoked.insert(*key, Instant::now());
    }
    pub fn revoke_user(&self, username: &str) {
        let keys: Vec<_> = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .iter()
            .filter(|(_, s)| s.username == username)
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            self.revoke_key(&key);
        }
    }
    pub fn auth_user_id(&self, username: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .accounts
            .users
            .get(username)
            .and_then(|record| record.auth_user_id.clone())
    }
    pub async fn revalidate_dashboard_sessions(self: &Arc<Self>) {
        use futures_util::{StreamExt, stream};
        let Some(auth) = self.auth() else { return };
        let sessions: Vec<_> = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .iter()
            .filter_map(|(key, s)| {
                s.external
                    .as_ref()
                    .map(|(cookie, _, _)| (*key, cookie.clone()))
            })
            .collect();
        stream::iter(sessions)
            .for_each_concurrent(8, |(key, cookie)| {
                let auth = auth.clone();
                async move {
                    match auth.session(&cookie).await {
                        Ok(Some(session)) if sha256(session.session_id.as_bytes()) == key => {
                            if let Ok(csrf) = auth.csrf(&session.session_id) {
                                let _ = self.accept_external(session, &cookie, csrf, false);
                            }
                        }
                        _ => self.revoke_key(&key),
                    }
                }
            })
            .await;
    }
    pub async fn save_dashboard_user(
        &self,
        actor: &Principal,
        mut user: User,
        password: Option<String>,
    ) -> Result<()> {
        let auth = self
            .auth()
            .ok_or_else(|| anyhow::anyhow!("Better Auth unavailable"))?;
        ensure!(
            actor.user.admin() && self.active(&actor.session_key),
            "administrator session required"
        );
        ensure!(
            normalize_username(&user.username)? == user.username && user.groups.len() <= 64,
            "invalid operator"
        );
        for group in &mut user.groups {
            *group = crate::identity::hex(&crate::identity::decode_hex::<48>(group)?);
        }
        if let Some(password) = &password {
            ensure!(
                (12..=128).contains(&password.len()),
                "password must contain 12–128 bytes"
            );
        }
        let name = user.username.clone();
        let previous = self.auth_user_id(&name);
        ensure!(
            previous.is_some() || password.is_some(),
            "password required for a new operator"
        );
        {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            ensure!(
                user.admin()
                    || inner
                        .accounts
                        .users
                        .iter()
                        .any(|(key, record)| key != &name && record.user.admin()),
                "cannot remove the last administrator"
            );
        }
        let value = auth
            .internal(
                "identity",
                serde_json::json!({"username":name,"password":password,"expected_id":previous}),
            )
            .await?;
        let id = value["user_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("auth identity missing"))?;
        {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            ensure!(
                current_principal(&inner, actor),
                "administrator session was revoked"
            );
            let mut next = inner.accounts.clone();
            ensure!(
                next.users.contains_key(&name) || next.users.len() < 128,
                "too many operators"
            );
            next.users.insert(
                name.clone(),
                Record {
                    user,
                    password_hash: String::new(),
                    auth_user_id: Some(id.into()),
                },
            );
            ensure!(
                next.users.values().any(|r| r.user.admin()),
                "cannot remove the last administrator"
            );
            self.audit
                .record(&actor.user.username, "account.save", &name, "success")?;
            storage::replace_json(&self.path, &next)?;
            inner.accounts = next;
        }
        self.revoke_user(&name);
        auth.internal("revoke-user", serde_json::json!({"user_id":id}))
            .await?;
        Ok(())
    }
    pub fn open(directory: &std::path::Path) -> Result<Arc<Self>> {
        storage::private_directory(directory)?;
        let path = directory.join("operators.json");
        let accounts: Accounts = if path.exists() {
            storage::read_json(&path)?
        } else {
            Accounts::default()
        };
        ensure!(accounts.users.len() <= 128, "too many operator accounts");
        Ok(Arc::new(Self {
            path,
            inner: Mutex::new(Inner {
                accounts,
                sessions: BTreeMap::new(),
                attempts: VecDeque::new(),
                next_attempt: 0,
                revoked: BTreeMap::new(),
            }),
            hashes: Arc::new(Semaphore::new(2)),
            pending_hashes: Arc::new(Semaphore::new(10)),
            dummy_hash: hash_password("dummy-not-an-account-password")?,
            audit: Audit::open(directory.join("audit.json"))?,
            auth: RwLock::new(None),
        }))
    }
    pub fn initialized(&self) -> bool {
        !self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .accounts
            .users
            .is_empty()
    }
    pub fn bootstrap(&self, username: &str, password: &str) -> Result<()> {
        let username = normalize_username(username)?;
        let password_hash = hash_password(password)?;
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            inner.accounts.users.is_empty(),
            "an administrator already exists; use account management"
        );
        let user = User {
            username: username.clone(),
            role: Role::Administrator,
            groups: vec![],
        };
        let accounts = Accounts {
            users: BTreeMap::from([(
                username.clone(),
                Record {
                    user,
                    password_hash,
                    auth_user_id: None,
                },
            )]),
        };
        self.audit
            .record(&username, "account.bootstrap", &username, "success")?;
        storage::replace_json(&self.path, &accounts)?;
        inner.accounts = accounts;
        Ok(())
    }
    pub async fn login(
        self: &Arc<Self>,
        username: &str,
        password: String,
    ) -> Result<(String, Principal)> {
        ensure!(
            self.auth().is_none(),
            "dashboard passwords are managed by Better Auth"
        );
        let _pending = self
            .pending_hashes
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("login busy; retry shortly"))?;
        ensure!(password.len() <= 128, "invalid credentials");
        let normalized = normalize_username(username).unwrap_or_default();
        let (hash, exists, attempt) = {
            let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            while inner
                .attempts
                .front()
                .is_some_and(|(t, _)| now.duration_since(*t) > Duration::from_secs(60))
            {
                inner.attempts.pop_front();
            }
            ensure!(
                inner.attempts.len() < 10,
                "login rate limit reached; retry in one minute"
            );
            let attempt = inner.next_attempt;
            inner.next_attempt = inner.next_attempt.wrapping_add(1);
            inner.attempts.push_back((now, attempt));
            let record = inner.accounts.users.get(&normalized);
            (
                record
                    .map(|r| r.password_hash.clone())
                    .unwrap_or_else(|| self.dummy_hash.clone()),
                record.is_some(),
                attempt,
            )
        };
        let permit =
            tokio::time::timeout(Duration::from_secs(5), self.hashes.clone().acquire_owned())
                .await
                .map_err(|_| anyhow::anyhow!("login busy; retry shortly"))?
                .map_err(|_| anyhow::anyhow!("login service closed"))?;
        let (valid, verified_hash) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            (verify(&password, &hash), hash)
        })
        .await?;
        if !valid || !exists {
            self.audit
                .record(&normalized, "account.login", "", "denied")?;
            anyhow::bail!("invalid credentials");
        }
        let token = random_token()?;
        let csrf = random_token()?;
        let key = sha256(token.as_bytes());
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.attempts.retain(|(_, id)| *id != attempt);
        inner.sessions.retain(|_, s| {
            now.duration_since(s.created) < Duration::from_secs(8 * 3600)
                && now.duration_since(s.last_used) < Duration::from_secs(3600)
        });
        ensure!(inner.sessions.len() < 256, "too many active sessions");
        let record = inner
            .accounts
            .users
            .get(&normalized)
            .ok_or_else(|| anyhow::anyhow!("account changed"))?;
        ensure!(
            record.password_hash == verified_hash,
            "account changed during login"
        );
        let user = record.user.clone();
        self.audit
            .record(&normalized, "account.login", "", "success")?;
        inner.sessions.insert(
            key,
            Session {
                username: normalized,
                csrf: csrf.clone(),
                created: now,
                last_used: now,
                external: None,
            },
        );
        Ok((
            token,
            Principal {
                user,
                csrf,
                session_key: key,
            },
        ))
    }
    pub fn authenticate(&self, token: &str) -> Option<Principal> {
        if token.len() != 43 {
            return None;
        }
        let key = sha256(token.as_bytes());
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let session = inner.sessions.get_mut(&key)?;
        if now.duration_since(session.created) >= Duration::from_secs(8 * 3600)
            || now.duration_since(session.last_used) >= Duration::from_secs(3600)
        {
            inner.sessions.remove(&key);
            return None;
        }
        session.last_used = now;
        let username = session.username.clone();
        let csrf = session.csrf.clone();
        Some(Principal {
            user: inner.accounts.users.get(&username)?.user.clone(),
            csrf,
            session_key: key,
        })
    }
    pub fn active(&self, key: &[u8; 32]) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.sessions.get(key).is_some_and(|s| {
            s.created.elapsed() < Duration::from_secs(8 * 3600)
                && s.last_used.elapsed() < Duration::from_secs(3600)
                && inner.accounts.users.contains_key(&s.username)
                && s.external.as_ref().is_none_or(|(_, verified, expires)| {
                    verified.elapsed() < Duration::from_secs(4)
                        && *expires > chrono::Utc::now().timestamp()
                })
        })
    }
    pub fn logout(&self, principal: &Principal) -> Result<()> {
        self.revoke_key(&principal.session_key);
        self.audit
            .record(&principal.user.username, "account.logout", "", "success")?;
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .sessions
            .remove(&principal.session_key);
        Ok(())
    }
    pub fn users(&self) -> Vec<User> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .accounts
            .users
            .values()
            .map(|r| r.user.clone())
            .collect()
    }
    pub fn save_user(
        &self,
        actor: &Principal,
        mut user: User,
        password: Option<&str>,
    ) -> Result<()> {
        ensure!(actor.user.admin(), "administrator required");
        let name = normalize_username(&user.username)?;
        ensure!(
            user.username == name && user.groups.len() <= 64,
            "invalid user or group grants"
        );
        for group in &mut user.groups {
            *group = crate::identity::hex(&crate::identity::decode_hex::<48>(group)?);
        }
        let hash = password.map(hash_password).transpose()?;
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            current_principal(&inner, actor)
                && inner
                    .accounts
                    .users
                    .get(&actor.user.username)
                    .is_some_and(|record| record.user.admin()),
            "administrator session was revoked"
        );
        let mut next = inner.accounts.clone();
        if let Some(record) = next.users.get_mut(&name) {
            record.user = user;
            if let Some(hash) = hash {
                record.password_hash = hash;
            }
        } else {
            ensure!(next.users.len() < 128, "too many accounts");
            next.users.insert(
                name.clone(),
                Record {
                    user,
                    password_hash: hash
                        .ok_or_else(|| anyhow::anyhow!("password required for a new user"))?,
                    auth_user_id: None,
                },
            );
        }
        ensure!(
            next.users.values().any(|r| r.user.admin()),
            "cannot remove the last administrator"
        );
        self.audit
            .record(&actor.user.username, "account.save", &name, "success")?;
        storage::replace_json(&self.path, &next)?;
        inner.accounts = next;
        inner.sessions.retain(|_, s| s.username != name);
        Ok(())
    }
    pub fn delete_user(&self, actor: &Principal, name: &str) -> Result<()> {
        ensure!(actor.user.admin(), "administrator required");
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            current_principal(&inner, actor)
                && inner
                    .accounts
                    .users
                    .get(&actor.user.username)
                    .is_some_and(|record| record.user.admin()),
            "administrator session was revoked"
        );
        let mut next = inner.accounts.clone();
        ensure!(next.users.remove(name).is_some(), "account not found");
        ensure!(
            next.users.values().any(|r| r.user.admin()),
            "cannot remove the last administrator"
        );
        self.audit
            .record(&actor.user.username, "account.delete", name, "success")?;
        storage::replace_json(&self.path, &next)?;
        inner.accounts = next;
        inner.sessions.retain(|_, s| s.username != name);
        Ok(())
    }
    pub async fn change_password(
        self: &Arc<Self>,
        principal: &Principal,
        current: String,
        new: String,
    ) -> Result<()> {
        let hash = {
            self.inner
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .accounts
                .users
                .get(&principal.user.username)
                .ok_or_else(|| anyhow::anyhow!("account not found"))?
                .password_hash
                .clone()
        };
        let _pending = self
            .pending_hashes
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("password service busy"))?;
        let permit =
            tokio::time::timeout(Duration::from_secs(5), self.hashes.clone().acquire_owned())
                .await
                .map_err(|_| anyhow::anyhow!("password service busy"))?
                .map_err(|_| anyhow::anyhow!("password service closed"))?;
        let original_hash = hash.clone();
        let next = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            ensure!(verify(&current, &hash), "incorrect current password");
            hash_password(&new)
        })
        .await??;
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            current_principal(&inner, principal)
                && inner
                    .accounts
                    .users
                    .get(&principal.user.username)
                    .is_some_and(|record| record.password_hash == original_hash),
            "session or password changed during verification"
        );
        let mut accounts = inner.accounts.clone();
        accounts
            .users
            .get_mut(&principal.user.username)
            .ok_or_else(|| anyhow::anyhow!("account not found"))?
            .password_hash = next;
        self.audit
            .record(&principal.user.username, "account.password", "", "success")?;
        storage::replace_json(&self.path, &accounts)?;
        inner.accounts = accounts;
        inner
            .sessions
            .retain(|_, s| s.username != principal.user.username);
        Ok(())
    }
}

#[cfg(test)]
mod external_session_tests {
    use super::*;
    #[test]
    fn an_inflight_validation_cannot_resurrect_a_signed_out_session() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        storage::private_directory(&path).unwrap();
        let store = Operators::open(&path).unwrap();
        store.bootstrap("admin", "test-password-123").unwrap();
        store
            .bind_external_identity("admin", "pinned-auth-id")
            .unwrap();
        let session = crate::dashboard_auth::AuthenticatedSession {
            user_id: "pinned-auth-id".into(),
            username: "admin".into(),
            session_id: "single-auth-session".into(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
        };
        let principal = store
            .accept_external(session.clone(), "opaque-cookie", "csrf".into(), true)
            .unwrap()
            .unwrap();
        assert!(store.active(&principal.session_key));
        store.revoke_key(&principal.session_key);
        assert!(!store.active(&principal.session_key));
        assert!(
            store
                .accept_external(session, "opaque-cookie", "csrf".into(), true)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn matching_username_with_another_identity_does_not_inherit_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        storage::private_directory(&path).unwrap();
        let store = Operators::open(&path).unwrap();
        store.bootstrap("admin", "test-password-123").unwrap();
        store
            .bind_external_identity("admin", "pinned-auth-id")
            .unwrap();
        let foreign = crate::dashboard_auth::AuthenticatedSession {
            user_id: "different-auth-id".into(),
            username: "admin".into(),
            session_id: "foreign-session".into(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
        };
        assert!(
            store
                .accept_external(foreign, "forged-cookie", "csrf".into(), true)
                .unwrap()
                .is_none()
        );
    }
}
