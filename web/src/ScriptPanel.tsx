import { useState, type FormEvent } from "react";
import { api, useAuth } from "./Auth";

type ScriptResult = {
  status: "completed" | "timed_out" | "disconnected" | "unknown";
  exit_code: number | null;
  output: string;
  truncated: boolean;
};

const messages = {
  completed: "Script finished",
  timed_out: "No reply within 25 seconds. The script may still be running.",
  disconnected: "The agent disconnected. The script outcome is unknown.",
  unknown: "The agent replied without a confirmed exit code.",
};

export function ScriptPanel({ node }: { node: string }) {
  const { csrf } = useAuth();
  const [script, setScript] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScriptResult>();
  const bytes = new TextEncoder().encode(script).length;

  async function run(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setResult(undefined);
    try {
      setResult(
        await api<ScriptResult>(
          "/devices/" + encodeURIComponent(node) + "/scripts/run",
          csrf,
          "POST",
          { script },
        ),
      );
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "The script request failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="system-details">
      <h3>Run a shell script</h3>
      <p className="panel-help">
        The script runs on this device with the agent’s permissions.
      </p>
      <form onSubmit={(event) => void run(event)}>
        <label className="field-label">
          Shell script
          <textarea
            rows={7}
            value={script}
            disabled={busy}
            onChange={(event) => setScript(event.target.value)}
            required
          />
        </label>
        <p className="panel-help">{bytes} / 4096 bytes</p>
        <button
          className="button primary"
          disabled={busy || !script.trim() || bytes > 4096}
        >
          {busy ? "Waiting for device…" : "Run script"}
        </button>
      </form>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {result && (
        <>
          <p role="status">
            {messages[result.status]}
            {result.exit_code === null
              ? ""
              : ` with exit code ${result.exit_code}.`}
            {result.truncated && " Output was truncated."}
          </p>
          <pre aria-label="Script output">{result.output}</pre>
        </>
      )}
    </section>
  );
}
