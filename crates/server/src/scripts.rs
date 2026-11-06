use crate::{
    AppState, DeviceStatus,
    console::{ApiFailure, ApiResult, bad, forbidden, operators},
    management::{authorized_device, runtime},
    operators::{Principal, random_token},
};
use axum::{
    Json, Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

const SCRIPT_LIMIT: usize = 4096;
const OUTPUT_LIMIT: usize = 8192;
const REPLY_TIMEOUT: Duration = Duration::from_secs(25);

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/devices/{id}/scripts/run", post(run))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    script: String,
}

#[derive(Serialize)]
struct ScriptResult {
    id: String,
    status: &'static str,
    exit_code: Option<u8>,
    output: String,
    truncated: bool,
}

async fn run(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(node): Path<String>,
    Json(body): Json<Run>,
) -> ApiResult<Json<ScriptResult>> {
    let agent = runtime(&state)?;
    let device = authorized_device(&agent, &principal, &node, true)?;
    if device.status != DeviceStatus::Online
        || !device.core_ready
        || !matches!(device.platform.as_str(), "macOS" | "Linux")
    {
        return Err(ApiFailure(
            StatusCode::CONFLICT,
            "Scripts require an online macOS or Linux device with a ready management core.".into(),
        ));
    }
    let script = body.script.replace("\r\n", "\n");
    if script.trim().is_empty() || script.len() > SCRIPT_LIMIT || script.contains(['\0', '\r']) {
        return Err(bad(
            "Enter a shell script of 1–4096 UTF-8 bytes without control characters NUL or CR.",
        ));
    }
    let operators = operators(&state)?;
    if !operators.active(&principal.session_key) {
        return Err(forbidden());
    }
    let id = random_token().map_err(bad)?;
    let actor = principal.user.username;
    let audit = operators.audit.clone();
    let target = format!("{node}/{id}");
    audit
        .record(&actor, "script.run", &target, "requested")
        .map_err(bad)?;
    let command = json!({
        "action": "runcommands",
        "type": 3,
        "cmds": shell_command(&script, &id),
        "runAsUser": 0,
        "reply": true,
        "sessionid": id,
        "responseid": id,
    });
    let receiver = agent
        .start_script(&node, id.clone(), command)
        .map_err(|error| {
            let _ = audit.record(&actor, "script.run", &target, "not_dispatched");
            ApiFailure(StatusCode::CONFLICT, error.to_string())
        })?;
    // Keep the audit outcome even if the caller navigates away.
    let work = tokio::spawn(async move {
        let mut result = ScriptResult {
            id,
            status: "unknown",
            exit_code: None,
            output: String::new(),
            truncated: false,
        };
        match tokio::time::timeout(REPLY_TIMEOUT, receiver).await {
            Ok(Ok(output)) => decode_result(&mut result, output),
            Ok(Err(_)) => result.status = "disconnected",
            Err(_) => result.status = "timed_out",
        }
        let outcome = match result.exit_code {
            Some(0) => "success",
            Some(_) => "failed",
            None => result.status,
        };
        if let Err(error) = audit.record(&actor, "script.run", &target, outcome) {
            tracing::warn!(%error, "could not persist script outcome");
        }
        result
    });
    Ok(Json(work.await.map_err(bad)?))
}

fn shell_command(script: &str, id: &str) -> String {
    // Keep the status on a separate descriptor so it survives the output cap.
    // Drain excess output to avoid changing the script's exit status via SIGPIPE.
    let quoted = script.replace('\'', "'\"'\"'");
    format!(
        "{{ {{ /bin/sh -c '{quoted}' </dev/null 3>&-; printf '\\nMCR_SCRIPT_{id}:%s\\n' \"$?\" >&3; }} 2>&1 | {{ /usr/bin/head -c {}; /bin/cat >/dev/null; }}; }} 3>&1",
        OUTPUT_LIMIT + 1
    )
}

fn decode_result(result: &mut ScriptResult, output: String) {
    let marker = format!("\nMCR_SCRIPT_{}:", result.id);
    let output = match output.split_once(&marker) {
        Some((before, rest)) => match rest.split_once('\n') {
            Some((code, after)) if let Ok(code) = code.parse() => {
                result.status = "completed";
                result.exit_code = Some(code);
                format!("{before}{after}")
            }
            _ => output,
        },
        None => output,
    };
    result.truncated = output.len() > OUTPUT_LIMIT;
    result.output = output[..output.floor_char_boundary(OUTPUT_LIMIT)].to_owned();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn output_cap_preserves_shell_exit_status_and_quoted_input() {
        let mut result = ScriptResult {
            id: "fixture".into(),
            status: "unknown",
            exit_code: None,
            output: String::new(),
            truncated: false,
        };
        let command = shell_command(
            "printf '%s' \"it's safe\" >&2\nprintf '%09000d' 1\nexit 7",
            &result.id,
        );
        let output = Command::new("/bin/sh")
            .args(["-c", &command])
            .output()
            .unwrap();
        decode_result(&mut result, String::from_utf8(output.stdout).unwrap());
        assert_eq!(result.status, "completed");
        assert_eq!(result.exit_code, Some(7));
        assert!(result.truncated);
        assert_eq!(result.output.len(), OUTPUT_LIMIT);
        assert!(result.output.starts_with("it's safe"));
    }
}
