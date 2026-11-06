import { useEffect, useState, type FormEvent } from "react";
import { useAuth } from "./Auth";
import {
  authClient,
  localhostPasskeyUrl,
  passkeysAvailable,
} from "./auth-client";

export function AccountPasskeys() {
  const local = localhostPasskeyUrl();
  return (
    <section
      className="account-form mfa-settings"
      aria-labelledby="passkeys-title"
    >
      <h2 id="passkeys-title">Passkeys</h2>
      {passkeysAvailable() ? (
        <PasskeySettings />
      ) : (
        <p className="panel-help">
          {local ? (
            <a href={local}>Open localhost to manage passkeys</a>
          ) : (
            "Passkeys require a supported browser and an HTTPS hostname or localhost."
          )}
        </p>
      )}
    </section>
  );
}

function PasskeySettings() {
  const { refreshSession } = useAuth();
  const [keys, setKeys] = useState<
    { id: string; name?: string | null }[] | null
  >(null);
  const [loadError, setLoadError] = useState(false);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void authClient.passkey
      .listUserPasskeys({ fetchOptions: { signal: controller.signal } })
      .then(({ data, error }) => {
        if (controller.signal.aborted) return;
        if (error || !data) setLoadError(true);
        else setKeys(data);
      })
      .catch(() => {
        if (!controller.signal.aborted) setLoadError(true);
      });
    return () => controller.abort();
  }, []);

  async function add(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    try {
      const result = await authClient.passkey.addPasskey({
        name: name.trim(),
        fetchOptions: {
          onRequest(request) {
            request.body = JSON.stringify({
              ...JSON.parse(request.body),
              password,
            });
          },
        },
      });
      if (result.error || !result.data)
        throw new Error(result.error?.message || "Could not add the passkey.");
      const added = result.data;
      setKeys((current) => [
        ...(current ?? []),
        { id: added.id, name: added.name },
      ]);
      setName("");
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Could not add the passkey.",
      );
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setBusy(true);
    setError("");
    try {
      const result = await authClient.passkey.deletePasskey({ id });
      if (result.error) throw new Error("Could not remove the passkey.");
      await refreshSession();
    } catch (error) {
      setError(
        error instanceof Error
          ? error.message
          : "Could not remove the passkey.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <p className="panel-help">
        Sign in with your device’s fingerprint, PIN, or security key.
      </p>
      {!keys && !loadError && <p role="status">Loading passkeys…</p>}
      {(error || loadError) && (
        <p className="form-error" role="alert">
          {error || "Could not load passkeys."}
        </p>
      )}
      {Boolean(keys?.length) && (
        <>
          <p className="panel-help">
            Removing a passkey signs out your sessions and closes your remote
            connections.
          </p>
          <ul aria-label="Registered passkeys">
            {keys?.map((key) => (
              <li key={key.id}>
                {key.name || "Passkey"}{" "}
                <button
                  className="button"
                  type="button"
                  disabled={busy}
                  onClick={() => void remove(key.id)}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      <form onSubmit={(event) => void add(event)}>
        <label className="field-label">
          Passkey name
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={64}
            required
          />
        </label>
        <label className="field-label">
          Password for passkey setup
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            maxLength={128}
            required
          />
        </label>
        <button className="button primary" disabled={busy}>
          Add passkey
        </button>
      </form>
    </>
  );
}
