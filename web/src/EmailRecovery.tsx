import { useEffect, useState, type FormEvent } from "react";
import { authClient } from "./auth-client";

export type RecoveryFlow =
  | { kind: "request" }
  | { kind: "verify" | "reset"; token: string };

export function recoveryLink(): RecoveryFlow | null {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const verify = fragment.get("verify-recovery");
  if (verify) return { kind: "verify", token: verify };
  const reset = fragment.get("reset-password");
  return reset ? { kind: "reset", token: reset } : null;
}

async function recoveryApi<T>(
  path: string,
  body?: object,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch("/api/auth/" + path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal,
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error(data.message || "The recovery request failed.");
  return data;
}

export function EmailRecovery({
  flow,
  close,
}: {
  flow: RecoveryFlow;
  close: () => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (flow.kind === "request") {
        const result = await authClient.requestPasswordReset({ email });
        if (result.error)
          throw new Error("Could not request a reset link. Try again shortly.");
      } else if (flow.kind === "verify") {
        await recoveryApi("verify-recovery-email", { token: flow.token });
      } else {
        if (password !== confirmation)
          throw new Error("The passwords do not match.");
        const result = await authClient.resetPassword({
          token: flow.token,
          newPassword: password,
        });
        if (result.error)
          throw new Error(
            "Could not reset your password. Check the password requirements or request a new link.",
          );
      }
      setDone(true);
      setPassword("");
      setConfirmation("");
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "The recovery request failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  const title =
    flow.kind === "request"
      ? "Recover your account"
      : flow.kind === "verify"
        ? "Confirm your recovery email"
        : "Reset your password";
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="auth-brand">MeshCentral</div>
        <h1>{title}</h1>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {done ? (
          <p role="status">
            {flow.kind === "request"
              ? "If this address is registered for recovery, you’ll receive a reset link."
              : flow.kind === "verify"
                ? "Your recovery email is confirmed."
                : "Your password was reset. Sign in with your new password."}
          </p>
        ) : (
          <form onSubmit={(event) => void submit(event)}>
            {flow.kind === "request" && (
              <label>
                Recovery email
                <input
                  type="email"
                  autoComplete="email"
                  maxLength={254}
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                />
              </label>
            )}
            {flow.kind === "verify" && (
              <p>Confirm this address to receive password reset links.</p>
            )}
            {flow.kind === "reset" && (
              <>
                <label>
                  New password
                  <input
                    type="password"
                    autoComplete="new-password"
                    minLength={12}
                    maxLength={128}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                  />
                </label>
                <label>
                  Confirm new password
                  <input
                    type="password"
                    autoComplete="new-password"
                    minLength={12}
                    maxLength={128}
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    required
                  />
                </label>
              </>
            )}
            <button className="button primary" disabled={busy}>
              {flow.kind === "request"
                ? "Send reset link"
                : flow.kind === "verify"
                  ? "Confirm email"
                  : "Reset password"}
            </button>
          </form>
        )}
        <button
          className="button"
          type="button"
          disabled={busy}
          onClick={close}
        >
          Back to console
        </button>
      </section>
    </main>
  );
}

export function AccountRecoveryEmail() {
  const [address, setAddress] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    void recoveryApi<{ email: string | null }>(
      "recovery-email",
      undefined,
      controller.signal,
    )
      .then(({ email }) => {
        if (!controller.signal.aborted) setAddress(email);
      })
      .catch(() => {
        if (!controller.signal.aborted)
          setError("Could not load your recovery email.");
      });
    return () => controller.abort();
  }, []);
  async function save(nextEmail: string | null) {
    setBusy(true);
    setError("");
    setStatus("");
    try {
      await recoveryApi("recovery-email", { email: nextEmail, password });
      if (nextEmail === null) {
        setAddress(null);
        setStatus("Recovery email removed.");
      } else {
        setStatus("Check your inbox to confirm the recovery address.");
      }
      setEmail("");
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Could not update your recovery email.",
      );
    } finally {
      setPassword("");
      setBusy(false);
    }
  }
  return (
    <section
      className="account-form mfa-settings"
      aria-labelledby="recovery-email-title"
    >
      <h2 id="recovery-email-title">Recovery email</h2>
      <p className="panel-help">
        {address
          ? `Verified email: ${address}`
          : "Confirm an email address to receive password reset links."}
      </p>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {status && <p role="status">{status}</p>}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void save(email);
        }}
      >
        <label className="field-label">
          New recovery email
          <input
            type="email"
            autoComplete="email"
            maxLength={254}
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
        </label>
        <label className="field-label">
          Password for recovery email
          <input
            type="password"
            autoComplete="current-password"
            maxLength={128}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </label>
        <button className="button primary" disabled={busy}>
          Send confirmation
        </button>
        {address && (
          <button
            className="button"
            type="button"
            disabled={busy || !password}
            onClick={() => void save(null)}
          >
            Remove recovery email
          </button>
        )}
      </form>
    </section>
  );
}
