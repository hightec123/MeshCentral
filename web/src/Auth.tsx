import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import type { ReactNode, FormEvent } from "react";
import { authClient } from "./auth-client";
export type Operator = {
  username: string;
  role: "administrator" | "operator" | "viewer";
  groups: string[];
};
type Authentication = {
  user: Operator;
  csrf: string;
  logout: () => Promise<void>;
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
  const [auth, setAuth] = useState<{ user: Operator; csrf: string } | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [setup, setSetup] = useState(false);
  const [error, setError] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
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
    };
    window.addEventListener("mcr-signout", signout);
    return () => {
      controller.abort();
      window.removeEventListener("mcr-signout", signout);
      channel.close();
    };
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
      const signedIn = await authClient.signIn.username({ username, password });
      if (signedIn.error)
        throw new Error(
          "Sign-in failed. Check your credentials or retry shortly.",
        );
      const result = await api<{ user: Operator | null; csrf: string }>(
        "/auth/session",
        "",
      );
      if (!result.user)
        throw new Error("This account does not have dashboard access.");
      setAuth({ user: result.user, csrf: result.csrf });
      setPassword("");
    } catch (error) {
      setError(error instanceof Error ? error.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }
  if (loading)
    return (
      <div className="auth-shell">
        <p role="status">Connecting to your workspace…</p>
      </div>
    );
  if (auth)
    return (
      <Context.Provider value={{ ...auth, logout }}>
        {children}
      </Context.Provider>
    );
  return (
    <main className="auth-shell">
      <section className="auth-card">
        <div className="auth-brand">MeshCentral</div>
        <h1>
          {setup ? "Set up your administrator" : "Sign in to your workspace"}
        </h1>
        <p>
          {setup
            ? "Create the first administrator from the server terminal. Passwords are read from standard input."
            : "Manage your devices with your operator account."}
        </p>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {setup ? (
          <code>meshcentral-server init-user USERNAME</code>
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
          </form>
        )}
        <small>Your session is private to this browser.</small>
      </section>
    </main>
  );
}
