use crate::{
    AppState, DeviceStatus,
    console::{ApiResult, bad, forbidden},
    management,
    operators::{Audit, Operators, Principal, random_token},
    registry::Registry,
};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{
        Extension, Path, Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc},
    time::{Instant, interval, timeout},
};

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Terminal,
    Files,
    Desktop,
}
impl Kind {
    fn protocol(self) -> u8 {
        match self {
            Self::Terminal => 1,
            Self::Files => 5,
            Self::Desktop => 2,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub node_id: String,
    pub username: String,
    pub kind: Kind,
    pub started_at: String,
}
struct Sides {
    browser: bool,
    agent: bool,
    browser_rx: Option<mpsc::Receiver<Message>>,
    agent_rx: Option<mpsc::Receiver<Message>>,
}
struct Entry {
    info: SessionInfo,
    owner: [u8; 32],
    agent_ticket: [u8; 32],
    deadline: Instant,
    attach_deadline: Instant,
    closed: AtomicBool,
    ready: Notify,
    sides: Mutex<Sides>,
    to_browser: mpsc::Sender<Message>,
    to_agent: mpsc::Sender<Message>,
    operators: Arc<Operators>,
    registry: Arc<Registry>,
    audit: Arc<Audit>,
}
pub struct Hub {
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
}
impl Default for Hub {
    fn default() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }
}
impl Hub {
    fn browser_entry(&self, id: &str, p: &Principal) -> Result<Arc<Entry>> {
        let entry = self
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("session not found"))?;
        ensure!(
            entry.owner == p.session_key && entry.operators.active(&entry.owner),
            "session belongs to another sign-in"
        );
        let device = entry
            .registry
            .device(&entry.info.node_id)
            .ok_or_else(|| anyhow::anyhow!("device not found"))?;
        ensure!(p.user.can_control(&device.group_id), "group access denied");
        Ok(entry)
    }
    fn create(
        &self,
        p: &Principal,
        node: &str,
        kind: Kind,
        operators: Arc<Operators>,
        registry: Arc<Registry>,
    ) -> Result<(SessionInfo, String)> {
        let device = registry
            .device(node)
            .ok_or_else(|| anyhow::anyhow!("device not found"))?;
        ensure!(
            p.user.can_control(&device.group_id),
            "group control access denied"
        );
        ensure!(
            device.status == DeviceStatus::Online && device.core_ready,
            "device is not ready"
        );
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, entry| {
            !entry.closed.load(Ordering::Acquire)
                && entry.deadline > Instant::now()
                && (entry.attach_deadline > Instant::now() || {
                    let sides = entry.sides.lock().unwrap_or_else(|e| e.into_inner());
                    sides.browser && sides.agent
                })
        });
        ensure!(
            entries.len() < 16
                && entries
                    .values()
                    .filter(|entry| entry.owner == p.session_key)
                    .count()
                    < 8,
            "remote session limit reached"
        );
        let id = random_token()?;
        let ticket = random_token()?;
        let (to_browser, browser_rx) = mpsc::channel(8);
        let (to_agent, agent_rx) = mpsc::channel(8);
        let info = SessionInfo {
            id: id.clone(),
            node_id: node.into(),
            username: p.user.username.clone(),
            kind,
            started_at: chrono::Utc::now().to_rfc3339(),
        };
        operators
            .audit
            .record(&p.user.username, "remote.start", node, "requested")?;
        entries.insert(
            id,
            Arc::new(Entry {
                info: info.clone(),
                owner: p.session_key,
                agent_ticket: sha256(ticket.as_bytes()),
                deadline: Instant::now() + Duration::from_secs(3600),
                attach_deadline: Instant::now() + Duration::from_secs(30),
                closed: AtomicBool::new(false),
                ready: Notify::new(),
                sides: Mutex::new(Sides {
                    browser: false,
                    agent: false,
                    browser_rx: Some(browser_rx),
                    agent_rx: Some(agent_rx),
                }),
                to_browser,
                to_agent,
                operators: operators.clone(),
                registry,
                audit: operators.audit.clone(),
            }),
        );
        Ok((info, ticket))
    }
    fn close(&self, id: &str) {
        if let Some(entry) = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id)
        {
            entry.closed.store(true, Ordering::Release);
            entry.ready.notify_waiters();
            let _ = entry.audit.record(
                &entry.info.username,
                "remote.end",
                &entry.info.node_id,
                "closed",
            );
        }
    }
    pub fn close_node(&self, node: &str) {
        let ids: Vec<_> = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|e| e.info.node_id == node)
            .map(|e| e.info.id.clone())
            .collect();
        for id in ids {
            self.close(&id);
        }
    }
    fn get(&self, id: &str) -> Option<Arc<Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned()
    }
    fn by_agent_ticket(&self, ticket: &str) -> Option<Arc<Entry>> {
        if ticket.len() != 43 {
            return None;
        }
        let hash = sha256(ticket.as_bytes());
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find(|e| openssl::memcmp::eq(&hash, &e.agent_ticket))
            .cloned()
    }
    pub fn sessions(&self, p: &Principal) -> Vec<SessionInfo> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|e| {
                (p.user.admin() || e.owner == p.session_key) && !e.closed.load(Ordering::Acquire)
            })
            .map(|e| e.info.clone())
            .collect()
    }
}
struct Lease {
    hub: Arc<Hub>,
    id: String,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.hub.close(&self.id);
    }
}
fn claim(entry: &Entry, browser: bool) -> Result<mpsc::Receiver<Message>> {
    ensure!(
        !entry.closed.load(Ordering::Acquire)
            && entry.deadline > Instant::now()
            && (entry.attach_deadline > Instant::now() || {
                let sides = entry.sides.lock().unwrap_or_else(|e| e.into_inner());
                sides.browser && sides.agent
            })
            && entry.operators.active(&entry.owner),
        "session expired"
    );
    let mut sides = entry.sides.lock().unwrap_or_else(|e| e.into_inner());
    let receiver = if browser {
        ensure!(!sides.browser, "browser already attached");
        sides.browser = true;
        sides.browser_rx.take()
    } else {
        ensure!(!sides.agent, "agent already attached");
        sides.agent = true;
        sides.agent_rx.take()
    };
    entry.ready.notify_waiters();
    receiver.ok_or_else(|| anyhow::anyhow!("side already claimed"))
}
async fn relay(
    mut socket: WebSocket,
    entry: Arc<Entry>,
    mut incoming: mpsc::Receiver<Message>,
    browser: bool,
    hub: Arc<Hub>,
) {
    let _lease = Lease {
        hub,
        id: entry.info.id.clone(),
    };
    let paired = timeout(Duration::from_secs(30), async {
        loop {
            let notified = entry.ready.notified();
            if entry.closed.load(Ordering::Acquire) || !entry.operators.active(&entry.owner) {
                return false;
            }
            let ready = {
                let sides = entry.sides.lock().unwrap_or_else(|e| e.into_inner());
                sides.browser && sides.agent
            };
            if ready {
                return true;
            }
            tokio::select! { _=notified=>{}, _=tokio::time::sleep(Duration::from_millis(100))=>{} }
        }
    })
    .await;
    if !matches!(paired, Ok(true)) {
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    if browser {
        if socket
            .send(Message::Text(
                json!({"event":"connected","kind":entry.info.kind})
                    .to_string()
                    .into(),
            ))
            .await
            .is_err()
        {
            return;
        }
    } else {
        for message in [
            Message::Text("c".into()),
            Message::Text(
                json!({"ctrlChannel":"102938","type":"options","cols":100,"rows":30})
                    .to_string()
                    .into(),
            ),
            Message::Text(entry.info.kind.protocol().to_string().into()),
        ] {
            if socket.send(message).await.is_err() {
                return;
            }
        }
    }
    let destination = if browser {
        entry.to_agent.clone()
    } else {
        entry.to_browser.clone()
    };
    let mut tick = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
         _=tick.tick()=>{if entry.closed.load(Ordering::Acquire)||entry.deadline<=Instant::now()||!entry.operators.active(&entry.owner)||entry.registry.device(&entry.info.node_id).is_none_or(|d|d.status!=DeviceStatus::Online||!d.core_ready){break;}}
            message=incoming.recv()=>{let Some(message)=message else{break;};if entry.closed.load(Ordering::Acquire)||!entry.operators.active(&entry.owner){break;}
                if socket.send(message).await.is_err(){break;}}
         message=socket.recv()=>{match message{Some(Ok(Message::Ping(bytes)))=>{if socket.send(Message::Pong(bytes)).await.is_err(){break;}},Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Close(_)))|Some(Err(_))|None=>break,Some(Ok(message))=>{if entry.closed.load(Ordering::Acquire)||!entry.operators.active(&entry.owner){break;}
                if !matches!(timeout(Duration::from_secs(10),destination.send(message)).await,Ok(Ok(()))){break;}}}}
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/devices/{id}/sessions", post(start))
        .route("/v1/sessions", get(sessions))
        .route("/v1/sessions/{id}", delete(stop))
        .route("/v1/sessions/{id}/socket", get(browser_socket))
}
#[derive(Deserialize)]
struct Start {
    kind: Kind,
}
async fn start(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Json(body): Json<Start>,
) -> ApiResult<Json<serde_json::Value>> {
    let rt = management::runtime(&s)?;
    let device = management::authorized_device(&rt, &p, &id, true)?;
    // Keep admission stable until the tunnel is queued. A revocation that follows
    // closes this session through AgentRuntime::disconnect, including queued work.
    let policy = rt.policy.read().unwrap_or_else(|e| e.into_inner());
    if !policy.permits(&device.group_id, &device.node_id_hex) {
        return Err(forbidden());
    }
    if device.status != DeviceStatus::Online || !device.core_ready {
        return Err(bad(
            "Device is offline or its remote-management core is not ready.",
        ));
    }
    let operators = crate::console::operators(&s)?;
    let (info, ticket) = rt
        .relays
        .create(&p, &id, body.kind, operators, rt.registry.clone())
        .map_err(bad)?;
    let message = json!({"action":"msg","type":"tunnel","value":format!("*/meshrelay.ashx?auth={ticket}"),"rights":24,"consent":0,"userid":format!("user//{}",p.user.username),"username":p.user.username,"realname":p.user.username,"sessionid":info.id,"servertlshash":crate::identity::hex(&rt.identity.web_hash),"soptions":{"usages":[body.kind.protocol()]}});
    if let Err(error) = rt.command(&id, message) {
        rt.relays.close(&info.id);
        return Err(bad(error));
    }
    Ok(Json(
        json!({"session":info,"socket_path":format!("/api/v1/sessions/{}/socket",info.id)}),
    ))
}
async fn sessions(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<serde_json::Value>> {
    if s.runtime.is_none() {
        return Ok(Json(json!({"sessions":[]})));
    }
    Ok(Json(
        json!({"sessions":management::runtime(&s)?.relays.sessions(&p)}),
    ))
}
async fn stop(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let rt = management::runtime(&s)?;
    let Some(entry) = rt.relays.get(&id) else {
        return Ok(StatusCode::NO_CONTENT);
    };
    if !p.user.admin() && entry.owner != p.session_key {
        return Err(forbidden());
    }
    rt.relays.close(&id);
    Ok(StatusCode::NO_CONTENT)
}
async fn browser_socket(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if !crate::console::same_origin(&headers) {
        return Err(forbidden());
    }
    let rt = management::runtime(&s)?;
    let entry = rt.relays.browser_entry(&id, &p).map_err(|_| forbidden())?;
    management::authorized_device(&rt, &p, &entry.info.node_id, true)?;
    let receiver = claim(&entry, true).map_err(bad)?;
    let hub = rt.relays.clone();
    Ok(ws
        .max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .on_upgrade(move |socket| relay(socket, entry, receiver, true, hub))
        .into_response())
}
#[derive(Deserialize)]
pub struct AgentQuery {
    auth: String,
}
pub async fn agent_socket(
    State(rt): State<Arc<crate::agent::AgentRuntime>>,
    Query(query): Query<AgentQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if headers.contains_key("origin") {
        return Err(forbidden());
    }
    let entry = rt
        .relays
        .by_agent_ticket(&query.auth)
        .ok_or_else(forbidden)?;
    let receiver = claim(&entry, false).map_err(bad)?;
    let hub = rt.relays.clone();
    Ok(ws
        .max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .on_upgrade(move |socket| relay(socket, entry, receiver, false, hub))
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::AuthenticatedPeer,
        operators::{Role, User},
    };
    struct Fixture {
        _dir: tempfile::TempDir,
        operators: Arc<Operators>,
        registry: Arc<Registry>,
        owner: Principal,
        _presence: crate::registry::Presence,
    }
    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        crate::storage::private_directory(&path).unwrap();
        let operators = Operators::open(&path).unwrap();
        operators.bootstrap("admin", "relay-test-password").unwrap();
        let (_, owner) = operators
            .login("admin", "relay-test-password".into())
            .await
            .unwrap();
        let registry = Registry::open(path.join("inventory.json")).unwrap();
        let presence = registry
            .connect(AuthenticatedPeer {
                node_id: "test-node".into(),
                name: "Synthetic device".into(),
                group: "Test".into(),
                architecture: 29,
                mesh_id_hex: "A1".repeat(48),
                node_id_hex: "B2".repeat(48),
            })
            .unwrap();
        registry
            .telemetry("test-node", "coreinfo", json!({"caps":15}))
            .unwrap();
        Fixture {
            _dir: dir,
            operators,
            registry,
            owner,
            _presence: presence,
        }
    }
    #[tokio::test]
    async fn relay_tickets_and_each_side_are_single_use() {
        let f = fixture().await;
        let hub = Hub::default();
        let (info, ticket) = hub
            .create(
                &f.owner,
                "test-node",
                Kind::Files,
                f.operators.clone(),
                f.registry.clone(),
            )
            .unwrap();
        assert!(hub.by_agent_ticket("forged").is_none());
        let entry = hub.by_agent_ticket(&ticket).unwrap();
        let _browser = claim(&entry, true).unwrap();
        assert!(claim(&entry, true).is_err());
        let _agent = claim(&entry, false).unwrap();
        assert!(claim(&entry, false).is_err());
        hub.close(&info.id);
        assert!(claim(&entry, false).is_err());
        assert!(hub.get(&info.id).is_none());
    }
    #[tokio::test]
    async fn a_second_sign_in_cannot_hijack_a_browser_relay() {
        let f = fixture().await;
        let hub = Hub::default();
        let (info, _) = hub
            .create(
                &f.owner,
                "test-node",
                Kind::Terminal,
                f.operators.clone(),
                f.registry.clone(),
            )
            .unwrap();
        let (_, other) = f
            .operators
            .login("admin", "relay-test-password".into())
            .await
            .unwrap();
        assert!(hub.browser_entry(&info.id, &other).is_err());
        assert!(hub.browser_entry(&info.id, &f.owner).is_ok());
    }
    #[tokio::test]
    async fn viewers_and_operators_from_other_groups_cannot_start_a_relay() {
        let f = fixture().await;
        let hub = Hub::default();
        for (role, groups, name) in [
            (Role::Viewer, vec!["A1".repeat(48)], "viewer"),
            (Role::Operator, vec!["C3".repeat(48)], "operator"),
        ] {
            f.operators
                .save_user(
                    &f.owner,
                    User {
                        username: name.into(),
                        role,
                        groups,
                    },
                    Some("relay-user-password"),
                )
                .unwrap();
            let (_, p) = f
                .operators
                .login(name, "relay-user-password".into())
                .await
                .unwrap();
            assert!(
                hub.create(
                    &p,
                    "test-node",
                    Kind::Desktop,
                    f.operators.clone(),
                    f.registry.clone()
                )
                .is_err()
            );
        }
    }
    #[tokio::test]
    async fn logout_revokes_pending_relay_attachment() {
        let f = fixture().await;
        let hub = Hub::default();
        let (info, ticket) = hub
            .create(
                &f.owner,
                "test-node",
                Kind::Terminal,
                f.operators.clone(),
                f.registry.clone(),
            )
            .unwrap();
        f.operators.logout(&f.owner).unwrap();
        assert!(hub.browser_entry(&info.id, &f.owner).is_err());
        let entry = hub.by_agent_ticket(&ticket).unwrap();
        assert!(claim(&entry, false).is_err());
        assert!(!entry.operators.active(&entry.owner));
    }
    #[tokio::test]
    async fn pending_relays_expire_and_device_disconnect_closes_every_session() {
        let f = fixture().await;
        let hub = Hub::default();
        let (info, ticket) = hub
            .create(
                &f.owner,
                "test-node",
                Kind::Files,
                f.operators.clone(),
                f.registry.clone(),
            )
            .unwrap();
        {
            let mut entries = hub.entries.lock().unwrap();
            Arc::get_mut(entries.get_mut(&info.id).unwrap())
                .unwrap()
                .attach_deadline = Instant::now() - Duration::from_secs(1);
        }
        let entry = hub.by_agent_ticket(&ticket).unwrap();
        assert!(claim(&entry, false).is_err());
        hub.close_node("test-node");
        assert!(hub.sessions(&f.owner).is_empty());
    }
}
