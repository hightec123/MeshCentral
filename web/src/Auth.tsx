import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import type { ReactNode, FormEvent } from "react";
import {
  EmailRecovery,
  recoveryLink,
  type RecoveryFlow,
} from "./EmailRecovery";
import {
  authClient,
  localhostPasskeyUrl,
  passkeysAvailable,
} from "./auth-client";
export type Operator = {
  username: string;
  role: "administrator" | "operator" | "viewer";
  groups: string[];
};
type Authentication = {
  user: Operator;
  csrf: string;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
  emailRecovery: boolean;
};
const Context = createContext<Authentication | null>(null);
export function useAuth() {
  const auth = useContext(Context);
  if (!auth) throw new Error("Authentication required");
  return auth;
}
export async function api<T = Record<string, unknown>>(
  path: string,
  csrf: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch("/api/v1" + path, {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(method !== "GET" ? { "X-CSRF-Token": csrf } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (response.status === 401) window.dispatchEvent(new Event("mcr-signout"));
  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ message: "Server request failed." }));
    throw new Error(error.message || "Server request failed.");
  }
  return (response.status === 204 ? undefined : await response.json()) as T;
}
export function AuthGate({ children }: { children: ReactNode }) {
  const localPasskeyUrl = localhostPasskeyUrl();
  const [auth, setAuth] = useState<{ user: Operator; csrf: string } | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [setup, setSetup] = useState(false);
  const [emailRecovery, setEmailRecovery] = useState(false);
  const [recoveryFlow, setRecoveryFlow] = useState<RecoveryFlow | null>(
    recoveryLink,
  );
  const [error, setError] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState(false);
  const [recovery, setRecovery] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const readSession = useCallback(async () => {
    const result = await api<{ user: Operator | null; csrf: string }>(
      "/auth/session",
      "",
    );
    setAuth(result.user ? { user: result.user, csrf: result.csrf } : null);
    return Boolean(result.user);
  }, []);
  const refreshSession = useCallback(async () => {
    await readSession();
    const channel = new BroadcastChannel("meshcentral-dashboard-auth");
    channel.postMessage("session-changed");
    channel.close();
  }, [readSession]);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/v1/auth/session", {
      signal: controller.signal,
      cache: "no-store",
    })
      .then((r) => {
        if (!r.ok) throw new Error("Cannot reach the server.");
        return r.json();
      })
      .then((data) => {
        setAuth(data.user ? data : null);
        setSetup(data.setup_required);
        setEmailRecovery(Boolean(data.email_recovery));
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    const signout = () => {
      window.dispatchEvent(new Event("mcr-auth-revoking"));
      setAuth(null);
    };
    const channel = new BroadcastChannel("meshcentral-dashboard-auth");
    channel.onmessage = (event) => {
      if (event.data === "revoking")
        window.dispatchEvent(new Event("mcr-auth-revoking"));
      if (event.data === "signed-out") signout();
      if (event.data === "session-changed") void readSession().catch(signout);
    };
    window.addEventListener("mcr-signout", signout);
    return () => {
      controller.abort();
      window.removeEventListener("mcr-signout", signout);
      channel.close();
    };
  }, [readSession]);
  useEffect(() => {
    const openRecoveryLink = () => {
      const flow = recoveryLink();
      if (!flow) return;
      setRecoveryFlow(flow);
      window.history.replaceState(
        null,
        "",
        window.location.pathname + window.location.search,
      );
    };
    openRecoveryLink();
    window.addEventListener("hashchange", openRecoveryLink);
    return () => window.removeEventListener("hashchange", openRecoveryLink);
  }, []);
  const logout = useCallback(async () => {
    window.dispatchEvent(new Event("mcr-auth-revoking"));
    const channel = new BroadcastChannel("meshcentral-dashboard-auth");
    channel.postMessage("revoking");
    try {
      const result = await authClient.signOut();
      if (result.error)
        setError(
          "Sign-out could not reach the authentication service. Remote access has been closed locally.",
        );
    } catch {
      setError("Authentication service unavailable. Retry sign-in shortly.");
    }
    setAuth(null);
    channel.postMessage("signed-out");
    channel.close();
  }, []);
  async function login(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (challenge) {
        const result = recovery
          ? await authClient.twoFactor.verifyBackupCode({ code: code.trim() })
          : await authClient.twoFactor.verifyTotp({ code: code.trim() });
        if (result.error)
          throw new Error(
            "Verification failed. Check the code or start sign-in again.",
          );
      } else {
        const signedIn = await authClient.signIn.username({
          username,
          password,
        });
        if (signedIn.error)
          throw new Error(
            "Sign-in failed. Check your credentials or retry shortly.",
          );
        setPassword("");
        if (
          signedIn.data &&
          "twoFactorRedirect" in signedIn.data &&
          signedIn.data.twoFactorRedirect
        ) {
          setChallenge(true);
          return;
        }
      }
      if (!(await readSession()))
        throw new Error("This account does not have dashboard access.");
      setChallenge(false);
      setRecovery(false);
      setCode("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }
  async function cancelChallenge() {
    setBusy(true);
    try {
      if ((await authClient.signOut()).error) throw new Error();
      setChallenge(false);
      setRecovery(false);
      setCode("");
      setError("");
    } catch {
      setError("Could not cancel this sign-in. Retry shortly.");
    } finally {
      setBusy(false);
    }
  }
  async function signInWithPasskey() {
    setBusy(true);
    setError("");
    try {
      const result = await authClient.signIn.passkey();
      if (result.error || !(await readSession()))
        throw new Error(
          "Passkey sign-in failed. Try again or sign in with your password.",
        );
      setPassword("");
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Passkey sign-in failed.",
      );
    } finally {
      setBusy(false);
    }
  }
  if (recoveryFlow)
    return (
      <EmailRecovery
        key={recoveryFlow.kind === "request" ? "request" : recoveryFlow.token}
        flow={recoveryFlow}
        close={() => {
          setRecoveryFlow(null);
          void readSession().catch(() => setAuth(null));
        }}
      />
    );
  if (loading)
    return (
      <div className="auth-shell">
        <p role="status">Connecting to your workspace…</p>
      </div>
    );
  if (auth)
    return (
      <Context.Provider
        value={{ ...auth, logout, refreshSession, emailRecovery }}
      >
        {children}
      </Context.Provider>
    );
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="auth-brand">MeshCentral</div>
        <h1>
          {setup
            ? "Set up your administrator"
            : challenge
              ? "Verify your sign-in"
              : "Sign in to your workspace"}
        </h1>
        <p>
          {setup
            ? "Create the first administrator from the server terminal. Passwords are read from standard input."
            : challenge
              ? recovery
                ? "Enter one of your unused recovery codes."
                : "Enter the current code from your authenticator app."
              : "Manage your devices with your operator account."}
        </p>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {setup ? (
          <code>meshcentral-server init-user USERNAME</code>
        ) : challenge ? (
          <form onSubmit={login}>
            <label>
              {recovery ? "Recovery code" : "Authenticator code"}
              <input
                key={String(recovery)}
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode={recovery ? "text" : "numeric"}
                autoComplete="one-time-code"
                autoCapitalize="none"
                spellCheck={false}
                pattern={recovery ? undefined : "[0-9]{6}"}
                maxLength={recovery ? 32 : 6}
                required
                autoFocus
              />
            </label>
            <button className="button primary" disabled={busy}>
              {busy ? "Verifying…" : "Verify"}
            </button>
            <button
              className="button"
              type="button"
              disabled={busy}
              onClick={() => {
                setRecovery(!recovery);
                setCode("");
                setError("");
              }}
            >
              {recovery ? "Use an authenticator code" : "Use a recovery code"}
            </button>
            <button
              className="button"
              type="button"
              disabled={busy}
              onClick={() => void cancelChallenge()}
            >
              Back to sign-in
            </button>
          </form>
        ) : (
          <form onSubmit={login}>
            <label>
              Username
              <input
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                autoFocus
              />
            </label>
            <label>
              Password
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                maxLength={128}
              />
            </label>
            <button className="button primary" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
            {passkeysAvailable() && (
              <button
                className="button"
                type="button"
                disabled={busy}
                onClick={() => void signInWithPasskey()}
              >
                Sign in with a passkey
              </button>
            )}
            {localPasskeyUrl && (
              <a href={localPasskeyUrl}>Open localhost to use a passkey</a>
            )}
            {emailRecovery && (
              <button
                className="button"
                type="button"
                disabled={busy}
                onClick={() => setRecoveryFlow({ kind: "request" })}
              >
                Forgot password?
              </button>
            )}
          </form>
        )}
        <small>Your session is private to this browser.</small>
      </section>
    </main>
  );
}
