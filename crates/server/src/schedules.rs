use crate::{
    AppState,
    agent::AgentRuntime,
    console::{ApiFailure, ApiResult, bad, forbidden, operators},
    management::{authorized_device, runtime},
    operators::{Operators, Principal, random_token},
    scripts, storage,
};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{delete, get},
};
use chrono::{DateTime, Days, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task::JoinSet;

pub(crate) const FILE_NAME: &str = "schedules.json";
const CAPACITY: usize = 32;
const BATCH_LIMIT: usize = 8;
const GRACE_SECONDS: i64 = 60;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Repeat {
    Once,
    Daily,
}

#[derive(Clone, Deserialize, Serialize)]
struct RunSummary {
    scheduled_for: DateTime<Utc>,
    status: String,
    exit_code: Option<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Schedule {
    id: String,
    name: String,
    owner: String,
    repeat: Repeat,
    next_run: Option<DateTime<Utc>>,
    last_run: Option<RunSummary>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Entry {
    schedule: Schedule,
    node: String,
    group: String,
    owner_id: String,
    script: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    name: String,
    script: String,
    run_at: DateTime<Utc>,
    repeat: Repeat,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBatch {
    devices: Vec<String>,
    task: Create,
}

#[derive(Serialize)]
struct DeviceSchedule {
    device_id: String,
    #[serde(flatten)]
    task: Schedule,
}

pub(crate) struct Schedules {
    path: PathBuf,
    entries: Mutex<Vec<Entry>>,
}

impl Schedules {
    pub(crate) fn open(path: PathBuf, restored: bool) -> Result<Self> {
        let mut entries: Vec<Entry> = if path.try_exists()? {
            storage::read_json(&path)?
        } else {
            vec![]
        };
        ensure!(entries.len() <= CAPACITY, "too many scheduled tasks");
        let mut changed = false;
        for entry in &mut entries {
            if let Some(run) = &mut entry.schedule.last_run
                && run.status == "running"
            {
                run.status = "interrupted".into();
                changed = true;
            }
            if restored && let Some(scheduled_for) = entry.schedule.next_run.take() {
                entry.schedule.last_run = Some(RunSummary {
                    scheduled_for,
                    status: "restored_inactive".into(),
                    exit_code: None,
                });
                changed = true;
            }
        }
        if changed {
            storage::replace_json(&path, &entries)?;
        }
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    fn update<T>(&self, change: impl FnOnce(&mut Vec<Entry>) -> ApiResult<T>) -> ApiResult<T> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = entries.clone();
        let result = change(&mut next)?;
        storage::replace_json(&self.path, &next).map_err(bad)?;
        *entries = next;
        Ok(result)
    }

    pub(crate) fn without_device_tasks<T>(
        &self,
        node: &str,
        action: impl FnOnce() -> ApiResult<T>,
    ) -> ApiResult<T> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.iter().any(|entry| entry.node == node) {
            return Err(ApiFailure(
                StatusCode::CONFLICT,
                "Remove scheduled tasks for this device before forgetting it.".into(),
            ));
        }
        action()
    }

    fn claim(&self, now: DateTime<Utc>) -> ApiResult<Option<Entry>> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(index) = entries.iter().position(|entry| {
            entry.schedule.next_run.is_some_and(|due| due <= now) && !running(&entry.schedule)
        }) else {
            return Ok(None);
        };
        let mut next = entries.clone();
        let task = &mut next[index].schedule;
        let mut due = task.next_run.expect("selected a due task");
        task.next_run = match task.repeat {
            Repeat::Once => None,
            Repeat::Daily => {
                // Collapse days missed while the server was down into the latest occurrence.
                due += TimeDelta::days((now - due).num_days());
                due.checked_add_days(Days::new(1))
            }
        };
        let status = if now - due >= TimeDelta::seconds(GRACE_SECONDS) {
            "missed"
        } else {
            "running"
        };
        task.last_run = Some(RunSummary {
            scheduled_for: due,
            status: status.into(),
            exit_code: None,
        });
        // Persist before dispatch so restart cannot replay this occurrence.
        storage::replace_json(&self.path, &next).map_err(bad)?;
        let claimed = next[index].clone();
        *entries = next;
        Ok(Some(claimed))
    }

    fn finish(&self, id: &str, status: &str, exit_code: Option<u8>) -> ApiResult<()> {
        self.update(|entries| {
            let run = entries
                .iter_mut()
                .find(|entry| entry.schedule.id == id)
                .and_then(|entry| entry.schedule.last_run.as_mut())
                .filter(|run| run.status == "running")
                .ok_or_else(|| bad("Scheduled run is no longer active."))?;
            run.status = status.into();
            run.exit_code = exit_code;
            Ok(())
        })
    }
}

fn running(task: &Schedule) -> bool {
    task.last_run
        .as_ref()
        .is_some_and(|run| run.status == "running")
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/schedules", get(list_all).post(create_batch))
        .route("/v1/devices/{node}/schedules", get(list).post(create))
        .route("/v1/devices/{node}/schedules/{id}", delete(remove))
}

async fn list(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(node): Path<String>,
) -> ApiResult<Json<Vec<Schedule>>> {
    let operators = operators(&state)?;
    if !p.user.admin() {
        let agent = runtime(&state)?;
        authorized_device(&agent, &p, &node, true)?;
    }
    let owner_id = operators.auth_user_id(&p.user.username);
    let entries = operators
        .schedules
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    Ok(Json(
        entries
            .iter()
            .filter(|entry| entry.node == node && visible(entry, &p, owner_id.as_deref()))
            .map(|entry| entry.schedule.clone())
            .collect(),
    ))
}

fn visible(entry: &Entry, p: &Principal, owner_id: Option<&str>) -> bool {
    p.user.admin()
        || (entry.schedule.owner == p.user.username && Some(entry.owner_id.as_str()) == owner_id)
}

async fn list_all(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<Vec<DeviceSchedule>>> {
    let operators = operators(&state)?;
    let owner_id = operators.auth_user_id(&p.user.username);
    let entries = operators
        .schedules
        .entries
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    Ok(Json(
        entries
            .iter()
            .filter(|entry| {
                visible(entry, &p, owner_id.as_deref())
                    && (p.user.admin()
                        || state
                            .runtime
                            .as_ref()
                            .and_then(|agent| agent.registry.device(&entry.node))
                            .is_some_and(|device| p.user.can_control(&device.group_id)))
            })
            .map(|entry| DeviceSchedule {
                device_id: entry.node.clone(),
                task: entry.schedule.clone(),
            })
            .collect(),
    ))
}

async fn create(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(node): Path<String>,
    Json(body): Json<Create>,
) -> ApiResult<(StatusCode, Json<Schedule>)> {
    let mut tasks = schedule(&state, &p, vec![node], body)?;
    Ok((StatusCode::CREATED, Json(tasks.remove(0).task)))
}

async fn create_batch(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(body): Json<CreateBatch>,
) -> ApiResult<(StatusCode, Json<Vec<DeviceSchedule>>)> {
    Ok((
        StatusCode::CREATED,
        Json(schedule(&state, &p, body.devices, body.task)?),
    ))
}

fn schedule(
    state: &AppState,
    p: &Principal,
    nodes: Vec<String>,
    body: Create,
) -> ApiResult<Vec<DeviceSchedule>> {
    if nodes.is_empty()
        || nodes.len() > BATCH_LIMIT
        || nodes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != nodes.len()
    {
        return Err(bad("Select one to eight distinct devices."));
    }
    let agent = runtime(state)?;
    let name = body.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(bad("Enter a task name of 1–80 UTF-8 bytes."));
    }
    let now = Utc::now();
    if body.run_at <= now || body.run_at > now + TimeDelta::days(366) {
        return Err(bad("Schedule a time in the next 366 days."));
    }
    let script = scripts::validate_script(&body.script)?;
    let operators = operators(state)?;
    let prepared: Vec<_> = nodes
        .into_iter()
        .map(|node| {
            let device = authorized_device(&agent, p, &node, true)?;
            if !scripts::supports_scripts(&device) {
                return Err(bad("Scheduling requires a macOS or Linux device."));
            }
            let owner_id = operators
                .schedule_owner(p, &device.group_id)
                .ok_or_else(forbidden)?;
            Ok(Entry {
                schedule: Schedule {
                    id: random_token().map_err(bad)?,
                    name: name.into(),
                    owner: p.user.username.clone(),
                    repeat: body.repeat,
                    next_run: Some(body.run_at),
                    last_run: None,
                },
                node,
                group: device.group_id,
                owner_id,
                script: script.clone(),
            })
        })
        .collect::<ApiResult<_>>()?;
    operators.schedules.update(|entries| {
        if entries.len() + prepared.len() > CAPACITY {
            return Err(ApiFailure(
                StatusCode::CONFLICT,
                "Task limit reached. Remove completed tasks to make space.".into(),
            ));
        }
        for entry in &prepared {
            if agent
                .registry
                .device(&entry.node)
                .is_none_or(|device| device.group_id != entry.group)
            {
                return Err(ApiFailure(
                    StatusCode::CONFLICT,
                    "Device list changed. Refresh and try again.".into(),
                ));
            }
        }
        for entry in &prepared {
            operators
                .audit
                .record(
                    &p.user.username,
                    "schedule.create",
                    &entry.schedule.id,
                    "requested",
                )
                .map_err(bad)?;
        }
        let results = prepared
            .iter()
            .map(|entry| DeviceSchedule {
                device_id: entry.node.clone(),
                task: entry.schedule.clone(),
            })
            .collect();
        entries.extend(prepared);
        Ok(results)
    })
}

async fn remove(
    State(state): State<AppState>,
    Extension(p): Extension<Principal>,
    Path((node, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let operators = operators(&state)?;
    if !p.user.admin() {
        let agent = runtime(&state)?;
        authorized_device(&agent, &p, &node, true)?;
    }
    if !operators.active(&p.session_key) {
        return Err(forbidden());
    }
    let owner_id = operators.auth_user_id(&p.user.username);
    operators.schedules.update(|entries| {
        let index = entries
            .iter()
            .position(|entry| {
                entry.schedule.id == id
                    && entry.node == node
                    && visible(entry, &p, owner_id.as_deref())
            })
            .ok_or_else(|| ApiFailure(StatusCode::NOT_FOUND, "Scheduled task not found.".into()))?;
        if running(&entries[index].schedule) {
            return Err(ApiFailure(
                StatusCode::CONFLICT,
                "A task is running. Wait for its result before removing it.".into(),
            ));
        }
        operators
            .audit
            .record(&p.user.username, "schedule.remove", &id, "requested")
            .map_err(bad)?;
        entries.remove(index);
        Ok(StatusCode::NO_CONTENT)
    })
}

pub async fn worker(operators: Arc<Operators>, agent: Arc<AgentRuntime>) {
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut running = JoinSet::new();
    loop {
        tokio::select! {
            _ = timer.tick() => {
                for _ in 0..CAPACITY {
                    match operators.schedules.claim(Utc::now()) {
                        Ok(Some(entry)) => {
                            running.spawn(execute(operators.clone(), agent.clone(), entry));
                        }
                        Ok(None) => break,
                        Err(error) => {
                            tracing::error!(message = %error.1, "could not claim scheduled task");
                            break;
                        }
                    }
                }
            }
            Some(result) = running.join_next() => {
                if let Err(error) = result {
                    tracing::error!(%error, "scheduled task worker failed");
                }
            }
        }
    }
}

async fn execute(operators: Arc<Operators>, agent: Arc<AgentRuntime>, entry: Entry) {
    let task = &entry.schedule;
    let outcome = if running(task) {
        let (status, exit_code) = dispatch(&operators, &agent, &entry).await;
        if let Err(error) = operators.schedules.finish(&task.id, status, exit_code) {
            tracing::error!(message = %error.1, "could not save scheduled task result");
        }
        status
    } else {
        "missed"
    };
    if let Err(error) = operators
        .audit
        .record(&task.owner, "schedule.run", &task.id, outcome)
    {
        tracing::error!(%error, "could not audit scheduled task outcome");
    }
}

async fn dispatch(
    operators: &Operators,
    agent: &AgentRuntime,
    entry: &Entry,
) -> (&'static str, Option<u8>) {
    let Some(device) = agent.registry.device(&entry.node) else {
        return ("device_unavailable", None);
    };
    if device.group_id != entry.group {
        return ("access_revoked", None);
    }
    let Some(work) = operators.with_schedule_access(
        &entry.schedule.owner,
        &entry.owner_id,
        &entry.group,
        || {
            scripts::dispatch(
                agent,
                &device,
                &entry.script,
                entry.schedule.owner.clone(),
                operators.audit.clone(),
            )
        },
    ) else {
        return ("access_revoked", None);
    };
    match work {
        Ok(work) => match work.await {
            Ok(result) => (result.outcome(), result.exit_code()),
            Err(_) => ("interrupted", None),
        },
        Err(error) if error.0 == StatusCode::FORBIDDEN => ("access_revoked", None),
        Err(error) if error.0 == StatusCode::CONFLICT => ("device_unavailable", None),
        Err(_) => ("not_dispatched", None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimed_occurrence_is_not_replayed_after_restart_and_restore_disarms_recurrence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let store = Schedules::open(path.clone(), false).unwrap();
        let now = Utc::now();
        let first = now - TimeDelta::days(3);
        store
            .update(|entries| {
                entries.push(Entry {
                    schedule: Schedule {
                        id: "fixture".into(),
                        name: "Daily task".into(),
                        owner: "admin".into(),
                        repeat: Repeat::Daily,
                        next_run: Some(first),
                        last_run: None,
                    },
                    node: "device".into(),
                    group: "group".into(),
                    owner_id: "account".into(),
                    script: "exit 0".into(),
                });
                Ok(())
            })
            .unwrap_or_else(|error| panic!("{}", error.1));
        let claimed = store
            .claim(now)
            .unwrap_or_else(|error| panic!("{}", error.1))
            .unwrap();
        assert_eq!(claimed.schedule.last_run.unwrap().scheduled_for, now);
        assert_eq!(claimed.schedule.next_run, Some(now + TimeDelta::days(1)));
        drop(store);

        let reopened = Schedules::open(path.clone(), false).unwrap();
        let entries = reopened.entries.lock().unwrap();
        assert_eq!(
            entries[0].schedule.last_run.as_ref().unwrap().status,
            "interrupted"
        );
        drop(entries);
        assert!(
            reopened
                .claim(now)
                .unwrap_or_else(|error| panic!("{}", error.1))
                .is_none()
        );
        drop(reopened);

        let restored = Schedules::open(path, true).unwrap();
        assert!(
            restored
                .claim(now + TimeDelta::days(1))
                .unwrap_or_else(|error| panic!("{}", error.1))
                .is_none()
        );
        assert_eq!(
            restored.entries.lock().unwrap()[0]
                .schedule
                .last_run
                .as_ref()
                .unwrap()
                .status,
            "restored_inactive"
        );
    }
}
