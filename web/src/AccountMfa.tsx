import { useEffect, useState, type FormEvent } from "react";
import QRCode from "react-qr-code";
import { useAuth } from "./Auth";
import { authClient } from "./auth-client";

export function AccountMfa() {
  const { refreshSession } = useAuth();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [setup, setSetup] = useState<{
    totpURI: string;
    backupCodes: string[];
  } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    void authClient
      .getSession()
      .then(({ data }) => {
        if (!active) return;
        if (data?.user) setEnabled(Boolean(data.user.twoFactorEnabled));
        else setError("Could not load your two-factor settings.");
      })
      .catch(() => {
        if (active) setError("Could not load your two-factor settings.");
      });
    return () => {
      active = false;
    };
  }, []);

  async function run(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await work();
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Two-factor request failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function configure(action: "enable" | "disable" | "regenerate") {
    if (!password) return;
    await run(async () => {
      if (action === "enable") {
        const { data, error } = await authClient.twoFactor.enable({
          password,
          method: "totp",
        });
        if (
          error ||
          !data ||
          !("totpURI" in data) ||
          !data.totpURI ||
          !data.backupCodes
        )
          throw new Error("Could not start setup. Check your password.");
        setSetup({ totpURI: data.totpURI, backupCodes: data.backupCodes });
      } else if (action === "regenerate") {
        const { data, error } = await authClient.twoFactor.generateBackupCodes({
          password,
        });
        if (error || !data)
          throw new Error(
            "Could not replace recovery codes. Check your password.",
          );
        setCodes(data.backupCodes);
      } else {
        const { error } = await authClient.twoFactor.disable({ password });
        if (error)
          throw new Error(
            "Could not disable two-factor authentication. Check your password.",
          );
        setEnabled(false);
        setCodes([]);
        await refreshSession();
      }
    });
    setPassword("");
  }

  function confirm(event: FormEvent) {
    event.preventDefault();
    if (!setup) return;
    void run(async () => {
      const { error } = await authClient.twoFactor.verifyTotp({ code });
      if (error)
        throw new Error("Verification failed. Check the code and try again.");
      setEnabled(true);
      setCodes(setup.backupCodes);
      setSetup(null);
      setCode("");
      await refreshSession();
    });
  }

  return (
    <section className="account-form mfa-settings" aria-labelledby="mfa-title">
      <h2 id="mfa-title">Two-factor authentication</h2>
      {enabled !== null && (
        <p className="panel-help">
          {enabled
            ? "Enabled. Each sign-in requires an authenticator or recovery code."
            : "Add an authenticator app to protect your dashboard sign-in."}
        </p>
      )}
      {enabled !== null && (
        <p className="panel-help">
          Changing this setting signs out your other sign-ins and ends your
          active remote sessions.
        </p>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {setup ? (
        <form onSubmit={confirm}>
          <p className="panel-help">
            Scan this QR code, then enter the six-digit code from your app.
          </p>
          <div className="mfa-qr">
            <QRCode
              value={setup.totpURI}
              size={172}
              role="img"
              aria-label="Authenticator setup QR code"
            />
          </div>
          <details>
            <summary>Enter a setup key manually</summary>
            <code className="mfa-key">
              {new URL(setup.totpURI).searchParams.get("secret")}
            </code>
          </details>
          <label className="field-label">
            Authenticator code
            <input
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              required
            />
          </label>
          <button className="button primary" disabled={busy}>
            Enable two-factor authentication
          </button>
          <button
            className="button"
            type="button"
            disabled={busy}
            onClick={() => {
              setSetup(null);
              setCode("");
              setError("");
            }}
          >
            Cancel setup
          </button>
        </form>
      ) : codes.length ? (
        <div>
          <p className="panel-help">
            Save these recovery codes now. Each code can be used once and is
            shown only here.
          </p>
          <ul className="mfa-codes" aria-label="Recovery codes">
            {codes.map((value) => (
              <li key={value}>
                <code>{value}</code>
              </li>
            ))}
          </ul>
          <button
            className="button primary"
            type="button"
            disabled={busy}
            onClick={() => setCodes([])}
          >
            Done
          </button>
        </div>
      ) : (
        enabled !== null && (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void configure(enabled ? "regenerate" : "enable");
            }}
          >
            <label className="field-label">
              Password for two-factor settings
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                maxLength={128}
              />
            </label>
            <button className="button primary" disabled={busy}>
              {enabled ? "Replace recovery codes" : "Set up authenticator"}
            </button>
            {enabled && (
              <button
                className="button"
                type="button"
                disabled={busy || !password}
                onClick={() => void configure("disable")}
              >
                Disable two-factor authentication
              </button>
            )}
          </form>
        )
      )}
    </section>
  );
}
