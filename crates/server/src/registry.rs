use crate::{Device, DeviceStatus, auth::AuthenticatedPeer, storage};
use anyhow::{Result, ensure};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Records {
    devices: BTreeMap<String, Device>,
}

pub struct Registry {
    path: PathBuf,
    inner: Mutex<Inner>,
}

struct Inner {
    records: Records,
    sessions: BTreeMap<String, u64>,
    next_session: u64,
}

#[must_use = "dropping the lease removes online presence"]
pub struct Presence {
    registry: Arc<Registry>,
    node: String,
    session: u64,
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

impl Registry {
    pub fn open(path: PathBuf) -> Result<Arc<Self>> {
        let mut records: Records = if path.exists() {
            storage::read_json(&path)?
        } else {
            Records::default()
        };
        ensure!(
            records.devices.len() <= 1024,
            "lab inventory exceeds the record limit"
        );
        for device in records.devices.values_mut() {
            device.status = DeviceStatus::Offline;
        }
        // Online is a property of a live, authenticated socket, never persisted truth.
        storage::replace_json(&path, &records)?;
        Ok(Arc::new(Self {
            path,
            inner: Mutex::new(Inner {
                records,
                sessions: BTreeMap::new(),
                next_session: 0,
            }),
        }))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn snapshot(&self) -> Vec<Device> {
        self.lock().records.devices.values().cloned().collect()
    }

    pub fn connect(self: &Arc<Self>, peer: AuthenticatedPeer) -> Result<Presence> {
        let mut inner = self.lock();
        ensure!(
            !inner.sessions.contains_key(&peer.node_id),
            "node already has an active session"
        );
        ensure!(
            inner.records.devices.contains_key(&peer.node_id) || inner.records.devices.len() < 1024,
            "lab inventory is full"
        );
        let mut records = inner.records.clone();
        let platform = match peer.architecture {
            3 | 4 | 43 => "Windows".to_string(),
            16 | 29 | 10005 => "macOS".to_string(),
            5 | 6 | 24 | 25 | 26 | 27 | 28 | 30 | 32 | 37 | 40 => "Linux".to_string(),
            other => format!("Agent architecture {other}"),
        };
        records.devices.insert(
            peer.node_id.clone(),
            Device {
                id: peer.node_id.clone(),
                name: peer.name,
                group: peer.group,
                platform,
                status: DeviceStatus::Online,
                last_seen: Some(now()),
            },
        );
        storage::replace_json(&self.path, &records)?;
        inner.records = records;
        inner.next_session = inner
            .next_session
            .checked_add(1)
            .expect("session counter exhausted");
        let session = inner.next_session;
        inner.sessions.insert(peer.node_id.clone(), session);
        Ok(Presence {
            registry: self.clone(),
            node: peer.node_id,
            session,
        })
    }
}

impl Presence {
    pub fn touch(&self) {
        let mut inner = self.registry.lock();
        if inner.sessions.get(&self.node) == Some(&self.session)
            && let Some(device) = inner.records.devices.get_mut(&self.node)
        {
            device.last_seen = Some(now());
        }
    }
}

impl Drop for Presence {
    fn drop(&mut self) {
        let mut inner = self.registry.lock();
        if inner.sessions.get(&self.node) != Some(&self.session) {
            return;
        }
        inner.sessions.remove(&self.node);
        if let Some(device) = inner.records.devices.get_mut(&self.node) {
            device.status = DeviceStatus::Offline;
            device.last_seen = Some(now());
        }
        if let Err(error) = storage::replace_json(&self.registry.path, &inner.records) {
            tracing::error!(%error, "could not persist offline presence");
        }
    }
}
