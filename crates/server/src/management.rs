use crate::{
    AppState, Device,
    agent::AgentRuntime,
    auth::AgentGroup,
    console::{self, ApiResult, bad, forbidden},
    identity::{decode_hex, hex},
    operators::Principal,
    storage,
};
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/devices/{id}", get(device).patch(patch).delete(forget))
        .route(
            "/v1/devices/{id}/disconnect",
            axum::routing::post(disconnect),
        )
        .route("/v1/groups", get(groups).post(create_group))
        .route(
            "/v1/groups/{id}",
            axum::routing::put(update_group).delete(delete_group),
        )
        .route("/v1/groups/{id}/configuration", get(configuration))
}
pub fn runtime(state: &AppState) -> ApiResult<Arc<AgentRuntime>> {
    state
        .runtime
        .clone()
        .ok_or_else(|| bad("Agent service is not initialized."))
}
pub fn authorized_device(
    runtime: &AgentRuntime,
    p: &Principal,
    id: &str,
    control: bool,
) -> ApiResult<Device> {
    let mut d = runtime
        .registry
        .device(id)
        .ok_or_else(|| console::ApiFailure(StatusCode::NOT_FOUND, "Device not found.".into()))?;
    if !p.user.can_view(&d.group_id) || (control && !p.user.can_control(&d.group_id)) {
        return Err(forbidden());
    }
    if let Some(group) = runtime
        .policy
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .group(&d.group_id)
    {
        d.group = group.group_name;
    }
    Ok(d)
}
async fn device(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Json<Device>> {
    Ok(Json(authorized_device(
        runtime(&s)?.as_ref(),
        &p,
        &id,
        false,
    )?))
}
#[derive(Deserialize)]
struct Patch {
    alias: Option<String>,
    notes: String,
    tags: Vec<String>,
}
async fn patch(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Json(body): Json<Patch>,
) -> ApiResult<StatusCode> {
    let rt = runtime(&s)?;
    authorized_device(&rt, &p, &id, true)?;
    console::operators(&s)?
        .audit
        .record(&p.user.username, "device.edit", &id, "success")
        .map_err(bad)?;
    rt.registry
        .patch(&id, body.alias, body.notes, body.tags)
        .map_err(bad)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn forget(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    let rt = runtime(&s)?;
    authorized_device(&rt, &p, &id, true)?;
    console::operators(&s)?
        .audit
        .record(&p.user.username, "device.forget", &id, "success")
        .map_err(bad)?;
    rt.registry.forget(&id).map_err(bad)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn disconnect(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let rt = runtime(&s)?;
    authorized_device(&rt, &p, &id, true)?;
    console::operators(&s)?
        .audit
        .record(&p.user.username, "device.disconnect", &id, "success")
        .map_err(bad)?;
    rt.disconnect(&id).map_err(bad)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn groups(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
) -> ApiResult<Json<serde_json::Value>> {
    if s.runtime.is_none() {
        return Ok(Json(json!({"groups":[]})));
    }
    let rt = runtime(&s)?;
    let primary = rt
        .policy
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .mesh_id_hex
        .clone();
    let groups: Vec<_> = rt
        .policy
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .groups()
        .into_iter()
        .filter(|g| p.user.can_view(&g.mesh_id_hex))
        .map(|g| {
            if p.user.admin() {
                json!({"primary":g.mesh_id_hex.eq_ignore_ascii_case(&primary),"mesh_id_hex":g.mesh_id_hex,"group_name":g.group_name,"allowed_node_ids_hex":g.allowed_node_ids_hex})
            } else {
                json!({"mesh_id_hex":g.mesh_id_hex,"group_name":g.group_name})
            }
        })
        .collect();
    Ok(Json(json!({"groups":groups})))
}
#[derive(Deserialize)]
struct NewGroup {
    name: String,
}
async fn create_group(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Json(body): Json<NewGroup>,
) -> ApiResult<Json<AgentGroup>> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    let rt = runtime(&s)?;
    let mut id = [0; 48];
    openssl::rand::rand_bytes(&mut id).map_err(bad)?;
    let group = AgentGroup {
        mesh_id_hex: hex(&id),
        group_name: body.name,
        allowed_node_ids_hex: vec![],
    };
    let mut lock = rt.policy.write().unwrap_or_else(|e| e.into_inner());
    let mut next = lock.clone();
    next.additional_groups.push(group.clone());
    next.validate().map_err(bad)?;
    console::operators(&s)?
        .audit
        .record(
            &p.user.username,
            "group.create",
            &group.mesh_id_hex,
            "success",
        )
        .map_err(bad)?;
    storage::replace_json(&rt.data_dir.join("admission.json"), &next).map_err(bad)?;
    *lock = next;
    Ok(Json(group))
}
async fn update_group(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Json(mut body): Json<AgentGroup>,
) -> ApiResult<StatusCode> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    let rt = runtime(&s)?;
    if !body.mesh_id_hex.eq_ignore_ascii_case(&id) {
        return Err(bad("Group identity cannot change."));
    }
    body.mesh_id_hex = hex(&decode_hex::<48>(&id).map_err(bad)?);
    body.allowed_node_ids_hex = body
        .allowed_node_ids_hex
        .iter()
        .map(|n| decode_hex::<48>(n).map(|n| hex(&n)))
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(bad)?;
    {
        let mut lock = rt.policy.write().unwrap_or_else(|e| e.into_inner());
        let mut next = lock.clone();
        if next.mesh_id_hex.eq_ignore_ascii_case(&body.mesh_id_hex) {
            next.group_name = body.group_name;
            next.allowed_node_ids_hex = body.allowed_node_ids_hex;
        } else {
            let group = next
                .additional_groups
                .iter_mut()
                .find(|g| g.mesh_id_hex.eq_ignore_ascii_case(&body.mesh_id_hex))
                .ok_or_else(|| bad("Group not found."))?;
            *group = body;
        }
        next.validate().map_err(bad)?;
        console::operators(&s)?
            .audit
            .record(&p.user.username, "group.update", &id, "success")
            .map_err(bad)?;
        storage::replace_json(&rt.data_dir.join("admission.json"), &next).map_err(bad)?;
        *lock = next;
    }
    for device in rt.registry.snapshot() {
        if device.group_id.eq_ignore_ascii_case(&id)
            && !rt
                .policy
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .permits(&device.group_id, &device.node_id_hex)
        {
            let _ = rt.disconnect(&device.id);
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn configuration(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    let rt = runtime(&s)?;
    let group = rt
        .policy
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .group(&id)
        .ok_or_else(|| bad("Group not found."))?;
    let config = format!(
        "MeshName={}\r\nMeshType=2\r\nMeshID=0x{}\r\nServerID={}\r\nMeshServer=wss://{}/agent.ashx\r\nignoreProxyFile=1\r\n",
        group.group_name,
        group.mesh_id_hex,
        hex(&rt.identity.server_id),
        rt.agent_address.read().unwrap_or_else(|e| e.into_inner())
    );
    console::operators(&s)?
        .audit
        .record(&p.user.username, "group.configuration", &id, "success")
        .map_err(bad)?;
    Ok(Json(json!({"configuration":config})))
}

async fn delete_group(
    State(s): State<AppState>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if !p.user.admin() {
        return Err(forbidden());
    }
    let rt = runtime(&s)?;
    let store = console::operators(&s)?;
    if rt
        .registry
        .snapshot()
        .iter()
        .any(|device| device.group_id.eq_ignore_ascii_case(&id))
    {
        return Err(bad(
            "Forget this group's device records before removing the group.",
        ));
    }
    if store.users().iter().any(|user| {
        user.groups
            .iter()
            .any(|group| group.eq_ignore_ascii_case(&id))
    }) {
        return Err(bad(
            "Remove this group from operator access grants before deleting it.",
        ));
    }
    let mut lock = rt.policy.write().unwrap_or_else(|e| e.into_inner());
    if lock.mesh_id_hex.eq_ignore_ascii_case(&id) {
        return Err(bad(
            "The initial group cannot be deleted. Rename it or revoke its approved nodes instead.",
        ));
    }
    let group = lock.group(&id).ok_or_else(|| bad("Group not found."))?;
    if !group.allowed_node_ids_hex.is_empty() {
        return Err(bad(
            "Revoke approved node identities before deleting this group.",
        ));
    }
    let mut next = lock.clone();
    next.additional_groups
        .retain(|group| !group.mesh_id_hex.eq_ignore_ascii_case(&id));
    next.validate().map_err(bad)?;
    store
        .audit
        .record(&p.user.username, "group.delete", &id, "success")
        .map_err(bad)?;
    storage::replace_json(&rt.data_dir.join("admission.json"), &next).map_err(bad)?;
    *lock = next;
    Ok(StatusCode::NO_CONTENT)
}
