import { useEffect, useState, type FormEvent } from "react";
import { api, useAuth } from "./Auth";

type Forward = {
  session: { id: string; kind: "tcp" | "udp"; target_port: number };
  socket_path: string;
  bridge_token: string;
};
type Route = {
  name: string;
  kind: "tcp" | "udp";
  address: string;
  port: number;
};

export function ForwardPanel({ node }: { node: string }) {
  const { csrf } = useAuth();
  const [kind, setKind] = useState<"tcp" | "udp">("tcp");
  const [port, setPort] = useState("");
  const [forward, setForward] = useState<Forward>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [route, setRoute] = useState("");
  const [routes, setRoutes] = useState<Route[]>([]);
  const [routesError, setRoutesError] = useState("");
  const path = "/devices/" + encodeURIComponent(node);
  const options = routes.filter((route) => route.kind === kind);

  useEffect(() => {
    let active = true;
    api<Route[]>(path + "/forward-routes", csrf).then(
      (result) => {
        if (active) setRoutes(result);
      },
      (cause) => {
        if (active) setRoutesError(String(cause));
      },
    );
    return () => {
      active = false;
    };
  }, [path, csrf]);

  async function prepare(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      setForward(
        await api<Forward>(
          path + "/sessions",
          csrf,
          "POST",
          route ? { kind, route } : { kind, port: Number(port) },
        ),
      );
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    if (!forward) return;
    setBusy(true);
    setError("");
    try {
      await api(
        "/sessions/" + encodeURIComponent(forward.session.id),
        csrf,
        "DELETE",
      );
      setForward(undefined);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  }

  const endpoint =
    forward && new URL(forward.socket_path, window.location.href);
  if (endpoint)
    endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";

  return (
    <section className="system-details">
      <h3>Forward a port</h3>
      <p className="panel-help">
        Connect a local app to a service on this device or a route configured
        for its group.
      </p>
      {forward && endpoint ? (
        <>
          <p>
            Run this command on your computer and paste the bridge token when
            prompted. The token can be used once within two minutes.
          </p>
          <pre aria-label="Forwarding command">{`meshcentral-server forward ${forward.session.kind} ${endpoint.href}`}</pre>
          <label className="field-label">
            Bridge token
            <input
              readOnly
              value={forward.bridge_token}
              onFocus={(event) => event.target.select()}
            />
          </label>
          <button
            type="button"
            className="button"
            disabled={busy}
            onClick={() => void stop()}
          >
            Stop forward
          </button>
        </>
      ) : (
        <form onSubmit={(event) => void prepare(event)}>
          <label className="field-label">
            Protocol
            <select
              value={kind}
              onChange={(event) => {
                setKind(event.target.value === "udp" ? "udp" : "tcp");
                setRoute("");
              }}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>
          {options.length > 0 && (
            <label className="field-label">
              Destination
              <select
                value={route}
                onChange={(event) => setRoute(event.target.value)}
              >
                <option value="">This device (127.0.0.1)</option>
                {options.map((option) => (
                  <option value={option.name} key={option.name}>
                    {option.name} ({option.address}:{option.port})
                  </option>
                ))}
              </select>
            </label>
          )}
          {!route && (
            <label className="field-label">
              Device port
              <input
                required
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(event) => setPort(event.target.value)}
              />
            </label>
          )}
          <button className="button primary" disabled={busy}>
            Prepare forward
          </button>
        </form>
      )}
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {routesError && (
        <p className="form-error" role="alert">
          {routesError}
        </p>
      )}
    </section>
  );
}
