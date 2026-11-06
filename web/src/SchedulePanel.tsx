import { useEffect, useState, type FormEvent } from "react";
import { api, useAuth } from "./Auth";
import type { Device } from "./api";

type Schedule = {
  id: string;
  device_id?: string;
  name: string;
  owner: string;
  repeat: "once" | "daily";
  next_run: string | null;
  last_run: {
    scheduled_for: string;
    status: string;
    exit_code: number | null;
  } | null;
};

const outcomes: Record<string, string> = {
  running: "Running",
  success: "Succeeded",
  failed: "Failed",
  missed: "Missed its run window",
  access_revoked: "Device access revoked",
  device_unavailable: "Device offline, busy, or unavailable",
  interrupted: "Run interrupted; outcome unknown",
  disconnected: "Device disconnected; outcome unknown",
  timed_out: "No reply; the script may still be running",
  not_dispatched: "Could not dispatch",
  unknown: "Outcome unknown",
  restored_inactive: "Disabled on restore",
};

export function SchedulePanel({
  node,
  devices = [],
}: {
  node?: string;
  devices?: Device[];
}) {
  const { csrf } = useAuth();
  const devicePath = (id: string) =>
    "/devices/" + encodeURIComponent(id) + "/schedules";
  const path = node ? devicePath(node) : "/schedules";
  const [tasks, setTasks] = useState<Schedule[]>();
  const [name, setName] = useState("");
  const [script, setScript] = useState("");
  const [runAt, setRunAt] = useState("");
  const [repeat, setRepeat] = useState<Schedule["repeat"]>("once");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const targets = selected.filter((id) =>
    devices.some((device) => device.id === id),
  );

  useEffect(() => {
    if (busy) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    async function load() {
      try {
        const result = await api<Schedule[]>(path, csrf);
        if (active) {
          setTasks(result);
          setLoadError("");
        }
      } catch (cause) {
        if (active) setLoadError(String(cause));
      } finally {
        if (active) timer = setTimeout(load, 3000);
      }
    }
    void load();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [path, csrf, busy]);

  async function save(event: FormEvent) {
    event.preventDefault();
    const date = new Date(runAt);
    if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) {
      setError("Choose a future time.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const input = {
        name,
        script,
        run_at: date.toISOString(),
        repeat,
      };
      const created = node
        ? [await api<Schedule>(path, csrf, "POST", input)]
        : await api<Schedule[]>(path, csrf, "POST", {
            devices: targets,
            task: input,
          });
      setTasks((current) => [...(current ?? []), ...created]);
      setName("");
      setScript("");
      setRunAt("");
      setSelected([]);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function remove(task: Schedule) {
    const target = task.device_id ?? node;
    if (!target) return;
    setBusy(true);
    setError("");
    try {
      await api(
        devicePath(target) + "/" + encodeURIComponent(task.id),
        csrf,
        "DELETE",
      );
      setTasks((current) => current?.filter((entry) => entry.id !== task.id));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  const formatTime = (value: string) => new Date(value).toLocaleString();
  const bytes = new TextEncoder().encode(script).length;

  return (
    <section className="system-details schedule-panel">
      <h3>Scheduled tasks</h3>
      <p className="panel-help">
        Scripts run as the agent account. The device must be online when the
        task is due.
      </p>
      <form onSubmit={(event) => void save(event)}>
        <fieldset disabled={busy}>
          {!node && (
            <fieldset className="schedule-targets">
              <legend>Choose up to eight devices</legend>
              {devices.length === 0 && (
                <p>No supported devices in your scope.</p>
              )}
              {devices.map((device) => (
                <label key={device.id}>
                  <span>
                    <input
                      type="checkbox"
                      checked={targets.includes(device.id)}
                      disabled={
                        targets.length >= 8 && !targets.includes(device.id)
                      }
                      onChange={(event) => {
                        const checked = event.target.checked;
                        setSelected(
                          checked
                            ? [...targets, device.id]
                            : targets.filter((id) => id !== device.id),
                        );
                      }}
                    />{" "}
                    {device.name} · {device.group} · {device.status} ·{" "}
                    {device.id.slice(-8)}
                  </span>
                </label>
              ))}
            </fieldset>
          )}
          <label className="field-label">
            Task name
            <input
              required
              maxLength={80}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label className="field-label">
            First run (local time)
            <input
              required
              type="datetime-local"
              value={runAt}
              onChange={(event) => setRunAt(event.target.value)}
            />
          </label>
          <label className="field-label">
            Repeat
            <select
              value={repeat}
              onChange={(event) =>
                setRepeat(event.target.value === "daily" ? "daily" : "once")
              }
            >
              <option value="once">Once</option>
              <option value="daily">Every 24 hours</option>
            </select>
          </label>
          <label className="field-label">
            Scheduled shell script
            <textarea
              required
              rows={5}
              value={script}
              onChange={(event) => setScript(event.target.value)}
            />
          </label>
          <p className="panel-help">{bytes} / 4096 bytes</p>
          <button
            className="button primary"
            disabled={
              !name.trim() ||
              !script.trim() ||
              bytes > 4096 ||
              (!node && targets.length === 0)
            }
          >
            Schedule script
          </button>
        </fieldset>
      </form>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <h3>Task history</h3>
      {loadError && (
        <p className="form-error" role="alert">
          {loadError}
        </p>
      )}
      {!tasks && !loadError && <p>Loading tasks…</p>}
      {tasks?.length === 0 && <p>No scheduled tasks.</p>}
      {tasks?.map((task) => (
        <article key={task.id}>
          <h4>{task.name}</h4>
          {task.device_id && (
            <p>
              {devices.find((device) => device.id === task.device_id)?.name ??
                "Device"}{" "}
              · {task.device_id.slice(-8)}
            </p>
          )}
          <p>
            {task.owner} · {task.repeat === "daily" ? "Every 24 hours" : "Once"}
          </p>
          {task.next_run && <p>Next run {formatTime(task.next_run)}</p>}
          {task.last_run && (
            <p>
              {outcomes[task.last_run.status] ?? task.last_run.status}
              {task.last_run.exit_code !== null &&
                " · exit " + task.last_run.exit_code}
              {" · " + formatTime(task.last_run.scheduled_for)}
            </p>
          )}
          <button
            className="button"
            disabled={busy || task.last_run?.status === "running"}
            onClick={() => void remove(task)}
          >
            {task.next_run ? "Cancel task" : "Remove task"}
          </button>
        </article>
      ))}
    </section>
  );
}
