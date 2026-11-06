use crate::{
    auth::{AdmissionPolicy, AuthenticatedPeer, Handshake},
    identity::Identity,
    registry::Registry,
    storage,
};
use anyhow::{Result, bail, ensure};
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, mpsc, oneshot, watch},
    time::{Instant, interval, timeout},
};

pub struct AgentRuntime {
    _state_lock: std::fs::File,
    pub identity: Arc<Identity>,
    pub policy: RwLock<AdmissionPolicy>,
    pub registry: Arc<Registry>,
    pub data_dir: PathBuf,
    pub agent_address: RwLock<SocketAddr>,
    pub cores: crate::core::Cores,
    pub audit: RwLock<Option<Arc<crate::operators::Audit>>>,
    pub relays: Arc<crate::remote::Hub>,
    commands: Mutex<BTreeMap<String, AgentControl>>,
    sockets: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}

struct AgentControl {
    group: String,
    messages: mpsc::Sender<Value>,
    stop: watch::Sender<bool>,
    script: Option<PendingScript>,
}

struct PendingScript {
    id: String,
    result: oneshot::Sender<String>,
}

impl AgentRuntime {
    pub fn open(directory: &Path) -> Result<Arc<Self>> {
        let state_lock = storage::lock_directory(directory)?;
        Ok(Arc::new(Self {
            _state_lock: state_lock,
            identity: Arc::new(Identity::load(&directory.join("identity.json"))?),
            policy: RwLock::new(AdmissionPolicy::load(&directory.join("admission.json"))?),
            registry: Registry::open(directory.join("inventory.json"))?,
            sockets: Arc::new(Semaphore::new(32)),
            handshakes: Arc::new(Semaphore::new(8)),
            data_dir: directory.into(),
            agent_address: RwLock::new("127.0.0.1:8443".parse()?),
            cores: crate::core::Cores::load(
                &std::env::var_os("MCR_CORE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| ".local/cores".into()),
            )?,
            audit: RwLock::new(None),
            commands: Mutex::new(BTreeMap::new()),
            relays: Arc::new(crate::remote::Hub::default()),
        }))
    }
    pub fn command(&self, id: &str, message: Value) -> Result<()> {
        self.commands
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("device is offline"))?
            .messages
            .try_send(message)
            .map_err(|_| anyhow::anyhow!("device command queue is full or closed"))
    }
    pub(crate) fn start_script(
        &self,
        node: &str,
        group: &str,
        id: String,
        message: Value,
    ) -> Result<oneshot::Receiver<String>> {
        let mut commands = self.commands.lock().unwrap_or_else(|e| e.into_inner());
        let agent = commands
            .get_mut(node)
            .filter(|agent| agent.group == group)
            .ok_or_else(|| anyhow::anyhow!("Device is offline."))?;
        ensure!(
            agent.script.is_none(),
            "A script is already pending on this device."
        );
        let (result, receiver) = oneshot::channel();
        agent
            .messages
            .try_send(message)
            .map_err(|_| anyhow::anyhow!("Device command queue is full or closed."))?;
        agent.script = Some(PendingScript { id, result });
        Ok(receiver)
    }
    fn script_result(&self, node: &str, response: &Value) {
        let (Some(id), Some(output)) =
            (response["responseid"].as_str(), response["result"].as_str())
        else {
            return;
        };
        if response["sessionid"].as_str() != Some(id) {
            return;
        }
        let mut commands = self.commands.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(agent) = commands.get_mut(node)
            && agent.script.as_ref().is_some_and(|script| script.id == id)
            && let Some(script) = agent.script.take()
        {
            let _ = script.result.send(output.to_owned());
        }
    }
    pub fn disconnect(&self, id: &str) -> Result<()> {
        self.relays.close_node(id);
        self.commands
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("device is offline"))?
            .stop
            .send(true)
            .map_err(|_| anyhow::anyhow!("device connection is closed"))
    }
}

pub fn router(runtime: Arc<AgentRuntime>) -> Router {
    Router::new()
        .route("/agent.ashx", get(upgrade))
        .route("/meshrelay.ashx", get(crate::remote::agent_socket))
        .with_state(runtime)
}

async fn upgrade(
    State(runtime): State<Arc<AgentRuntime>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // This is a native-agent listener. Browser-origin WebSockets are not admitted.
    if headers.contains_key("origin") {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(socket_permit) = runtime.sockets.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(handshake_permit) = runtime.handshakes.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(1024 * 1024).max_frame_size(1024 * 1024).on_upgrade(move |mut socket| async move {
        let _socket_permit = socket_permit;
        let result = timeout(Duration::from_secs(15), authenticate(&mut socket, &runtime)).await;
        drop(handshake_permit);
        let peer = match result {
            Ok(Ok(peer)) => peer,
            Ok(Err(error)) => { tracing::warn!(%error, "agent authentication rejected"); let _ = socket.send(Message::Close(None)).await; return; }
            Err(_) => { tracing::warn!("agent authentication timed out"); let _ = socket.send(Message::Close(None)).await; return; }
        };
        let node_id = peer.node_id.clone();
        let group = peer.mesh_id_hex.clone();
        let bundle=runtime.cores.for_architecture(peer.architecture);
        let (command_tx,mut command_rx)=mpsc::channel(16);
        let (stop_tx,mut stop_rx)=watch::channel(false);
        let admission = {
            let policy=runtime.policy.read().unwrap_or_else(|e|e.into_inner());
            if !policy.permits(&peer.mesh_id_hex,&peer.node_id_hex){Err(anyhow::anyhow!("admission changed during handshake"))} else {
                let presence=runtime.registry.connect(peer);
                if presence.is_ok(){runtime.commands.lock().unwrap_or_else(|e|e.into_inner()).insert(node_id.clone(),AgentControl{group,messages:command_tx,stop:stop_tx,script:None});}
                presence
            }
        };
        let presence = match admission {
            Ok(presence) => presence,
            Err(error) => { tracing::warn!(%error, "agent admission rejected"); let _ = socket.send(Message::Close(None)).await; return; }
        };
        let registration=ConnectionGuard{runtime:runtime.clone(),id:node_id.clone()};
        if socket.send(Message::Binary(vec![0, 4].into())).await.is_err() { return; }
        if bundle.is_some() && socket.send(Message::Binary(vec![0,11,0,0].into())).await.is_err(){return;}
        let mut core_attempts=0;
        tracing::info!(%node_id, "authenticated lab agent online");
        let mut ping = interval(Duration::from_secs(30));
        let mut last_received = Instant::now();
        loop {
            tokio::select! {
                biased;
                _ = stop_rx.changed()=>break,
                command=command_rx.recv()=>{
                    match command {
                        Some(message)=>{if socket.send(Message::Binary(serde_json::to_vec(&message).unwrap_or_default().into())).await.is_err(){break;}}
                        None=>break,
                    }
                }
                _ = ping.tick() => {
                    if last_received.elapsed() > Duration::from_secs(150) { break; }
                    if socket.send(Message::Ping(vec![0x4d, 0x43].into())).await.is_err() { break; }
                }
                message = socket.recv() => {
                    match message {
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(Message::Ping(bytes))) => { if socket.send(Message::Pong(bytes)).await.is_err() { break; } }
                        Some(Ok(Message::Text(text))) => { if is_ping(text.as_bytes()) {if socket.send(Message::Text("{\"action\":\"pong\"}".into())).await.is_err(){break;}} else {let _=telemetry(&runtime,&node_id,text.as_bytes());} }
                        Some(Ok(Message::Binary(bytes))) => {
                            if bytes.starts_with(&[0,11]) {
                                if let Some(bundle)=&bundle {
                                    if bytes.len()==52 && bytes[4..]==bundle.hash {
                                        if socket.send(Message::Binary(vec![0,16,0,0].into())).await.is_err(){break;}
                                    } else if core_attempts<2 {
                                        if let Some(audit)=runtime.audit.read().unwrap_or_else(|e|e.into_inner()).as_ref() && audit.record("system","agent.core",&node_id,"upload").is_err(){break;}
                                        core_attempts+=1;
                                        let mut payload=vec![0,10,0,0];payload.extend(bundle.hash);payload.extend(&bundle.bytes);
                                        if socket.send(Message::Binary(payload.into())).await.is_err(){break;}
                                    }
                                }
                            } else if is_ping(&bytes) {if socket.send(Message::Binary(b"{\"action\":\"pong\"}".to_vec().into())).await.is_err(){break;}}
                            else {let _=telemetry(&runtime,&node_id,&bytes);}
                        }
                        Some(Ok(Message::Pong(_))) => {}
                    }
                    last_received = Instant::now();
                    presence.touch();
                }
            }
        }
        drop(registration);
        drop(presence);
        tracing::info!(%node_id, "lab agent offline");
        let _ = socket.send(Message::Close(None)).await;
    }).into_response()
}

struct ConnectionGuard {
    runtime: Arc<AgentRuntime>,
    id: String,
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.runtime
            .commands
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
        self.runtime.relays.close_node(&self.id);
    }
}

fn telemetry(runtime: &AgentRuntime, node: &str, bytes: &[u8]) -> Result<()> {
    if bytes.first() != Some(&b'{') {
        return Ok(());
    }
    ensure!(bytes.len() <= 96 * 1024, "telemetry too large");
    let value: Value = serde_json::from_slice(bytes)?;
    if value["action"] == "msg" && value["type"] == "runcommands" {
        runtime.script_result(node, &value);
        return Ok(());
    }
    if let Some(action) = value["action"].as_str().map(str::to_owned)
        && ["coreinfo", "sysinfo", "netinfo", "smbios", "iplocation"].contains(&action.as_str())
    {
        runtime.registry.telemetry(node, &action, value)?;
    }
    Ok(())
}

fn is_ping(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'{')
        && serde_json::from_slice::<Value>(bytes).is_ok_and(|value| value["action"] == "ping")
}

async fn authenticate(socket: &mut WebSocket, runtime: &AgentRuntime) -> Result<AuthenticatedPeer> {
    let policy = runtime
        .policy
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut handshake = Handshake::new(runtime.identity.clone(), Arc::new(policy))?;
    let mut agent_name_seen = false;
    for _ in 0..12 {
        let bytes = match socket.recv().await {
            Some(Ok(Message::Binary(bytes))) => bytes.to_vec(),
            Some(Ok(Message::Ping(bytes))) => {
                socket.send(Message::Pong(bytes)).await?;
                continue;
            }
            Some(Ok(Message::Text(text))) => text.as_bytes().to_vec(),
            _ => bail!("agent disconnected during authentication"),
        };
        ensure!(
            bytes.len() <= meshcentral_protocol::MAX_HANDSHAKE_FRAME,
            "authentication frame too large"
        );
        if bytes.first() == Some(&b'{') {
            let value: Value = serde_json::from_slice(&bytes)?;
            ensure!(
                !agent_name_seen
                    && value["action"] == "agentName"
                    && value["value"]
                        .as_str()
                        .is_some_and(|name| !name.is_empty() && name.len() <= 255),
                "unsupported unauthenticated JSON"
            );
            agent_name_seen = true;
            continue;
        }
        // RSA operations run outside the async executor. Socket/handshake limits,
        // frame/key bounds, duplicate rejection and the deadline bound this work.
        let result = tokio::task::spawn_blocking(move || -> Result<_> {
            let replies = handshake.receive(&bytes)?;
            let peer = handshake.finish()?;
            Ok((handshake, replies, peer))
        })
        .await??;
        handshake = result.0;
        for reply in result.1 {
            socket.send(Message::Binary(reply.into())).await?;
        }
        if let Some(peer) = result.2 {
            return Ok(peer);
        }
    }
    bail!("too many authentication messages")
}
