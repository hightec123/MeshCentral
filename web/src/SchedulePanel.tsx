import { useEffect, useState, type FormEvent } from "react";
import { api, useAuth } from "./Auth";

type Schedule = {
  id: string;
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

export function SchedulePanel({ node }: { node: string }) {
  const { csrf } = useAuth();
  const path = "/devices/" + encodeURIComponent(node) + "/schedules";
  const [tasks, setTasks] = useState<Schedule[]>();
  const [name, setName] = useState("");
  const [script, setScript] = useState("");
  const [runAt, setRunAt] = useState("");
  const [repeat, setRepeat] = useState<Schedule["repeat"]>("once");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");

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
      const task = await api<Schedule>(path, csrf, "POST", {
        name,
        script,
        run_at: date.toISOString(),
        repeat,
      });
      setTasks((current) => [...(current ?? []), task]);
      setName("");
      setScript("");
      setRunAt("");
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function remove(task: Schedule) {
    setBusy(true);
    setError("");
    try {
      await api(path + "/" + encodeURIComponent(task.id), csrf, "DELETE");
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
    <section className="system-details">
      <h3>Scheduled tasks</h3>
      <p className="panel-help">
        Scripts run as the agent account. The device must be online when the
        task is due.
      </p>
      <form onSubmit={(event) => void save(event)}>
        <fieldset disabled={busy}>
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
            disabled={!name.trim() || !script.trim() || bytes > 4096}
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
      {tasks?.length === 0 && <p>No scheduled tasks for this device.</p>}
      {tasks?.map((task) => (
        <article key={task.id}>
          <h4>{task.name}</h4>
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
