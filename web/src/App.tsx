import { lazy, Suspense, useMemo, useRef, useState } from "react";
import { FleetIllustration, Icon } from "./Icons";
import { useInventory } from "./useInventory";
import { AuthGate, useAuth } from "./Auth";
const DeviceWorkspace = lazy(() =>
  import("./DeviceWorkspace").then((module) => ({
    default: module.DeviceWorkspace,
  })),
);
import { ManagementPage } from "./ManagementPage";
import { SchedulePanel } from "./SchedulePanel";

export default function App() {
  return (
    <AuthGate>
      <Workspace />
    </AuthGate>
  );
}

function Workspace() {
  const { user, logout } = useAuth();
  const [section, setSection] = useState("Devices");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { snapshot, error, loading, refresh } = useInventory();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [platform, setPlatform] = useState("all");
  const about = useRef<HTMLDialogElement>(null);
  const devices = snapshot?.devices ?? [];
  const platforms = [
    ...new Set(devices.map((device) => device.platform)),
  ].sort();
  const hasFilters = Boolean(query || status !== "all" || platform !== "all");
  const visible = useMemo(() => {
    const search = query.trim().toLocaleLowerCase();
    return (snapshot?.devices ?? []).filter(
      (device) =>
        (status === "all" || device.status === status) &&
        (platform === "all" || device.platform === platform) &&
        `${device.name} ${device.group} ${device.platform} ${device.id}`
          .toLocaleLowerCase()
          .includes(search),
    );
  }, [snapshot, query, status, platform]);
  const online = devices.filter((device) => device.status === "online").length;
  const connectionLabel = error
    ? "Connection issue"
    : snapshot
      ? "Server reachable"
      : "Connecting";

  function clearFilters() {
    setQuery("");
    setStatus("all");
    setPlatform("all");
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to devices
      </a>
      <aside className="sidebar" aria-label="Workspace navigation">
        <a className="brand" href="/" aria-label="MeshCentral home">
          <span className="brand-mark">
            <Icon name="devices" />
          </span>
          <span>
            MeshCentral<span className="brand-subtitle">Device management</span>
          </span>
        </a>
        <div className="workspace-label">
          <span className="workspace-avatar">L</span>Local workspace
        </div>
        <nav aria-label="Main navigation">
          {[
            "Devices",
            "Groups",
            ...(user.role === "administrator" ? ["People", "Activity"] : []),
            ...(user.role !== "viewer" ? ["Sessions", "Tasks"] : []),
            "Account",
          ].map((name) => (
            <button
              key={name}
              className={
                "nav-link nav-button" + (section === name ? " active" : "")
              }
              aria-current={section === name ? "page" : undefined}
              onClick={() => setSection(name)}
            >
              <Icon
                name={
                  name === "Devices"
                    ? "devices"
                    : name === "Sessions"
                      ? "server"
                      : "info"
                }
              />
              {name}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="operator-name">
            {user.username} · {user.role}
          </div>
          <button className="about-button" onClick={() => void logout()}>
            Sign out
          </button>
          <div className="sidebar-status">
            <span
              className={`presence ${error ? "warning" : snapshot ? "online" : "pending"}`}
            />
            <span>{connectionLabel}</span>
          </div>
          <button
            className="about-button"
            type="button"
            onClick={() => about.current?.showModal()}
          >
            <Icon name="info" />
            About this preview
          </button>
        </div>
      </aside>

      <main id="main" className="main-content" tabIndex={-1}>
        <header className="workspace-header">
          <span>
            Local workspace <span className="breadcrumb-divider">/</span>{" "}
            <strong>{section}</strong>
          </span>
          <span className="preview-label">Development preview</span>
        </header>

        <div className="page-content">
          {section === "Devices" ? (
            <>
              <div className="page-heading">
                <div>
                  <h1>Devices</h1>
                  <p>Your computers, together in one place.</p>
                </div>
                <button
                  className="button refresh-button"
                  type="button"
                  disabled={loading}
                  onClick={() => void refresh()}
                >
                  <Icon
                    name="refresh"
                    className={loading ? "rotating" : undefined}
                  />
                  {loading ? "Refreshing…" : "Refresh"}
                </button>
              </div>

              {error && (
                <div className="error-banner" role="alert">
                  <Icon name="info" />
                  <div>
                    <strong>
                      {snapshot
                        ? "Device information may be out of date."
                        : "Device list unavailable."}
                    </strong>
                    <span>{error}</span>
                  </div>
                  <button
                    className="button"
                    type="button"
                    disabled={loading}
                    onClick={() => void refresh()}
                  >
                    Retry
                  </button>
                </div>
              )}

              <section
                className="inventory"
                aria-label="Device inventory"
                aria-busy={loading}
              >
                <div className="inventory-summary">
                  <div className="device-count">
                    <strong>{snapshot ? devices.length : "—"}</strong>{" "}
                    {devices.length === 1 ? "device" : "devices"}
                  </div>
                  <div className="presence-counts">
                    <span>
                      <span className="presence online" />
                      {snapshot ? online : "—"} online
                    </span>
                    <span>
                      <span className="presence offline" />
                      {snapshot ? devices.length - online : "—"} offline
                    </span>
                  </div>
                </div>

                <div className="inventory-toolbar">
                  <label className="search-field">
                    <Icon name="search" />
                    <span className="sr-only">Search devices</span>
                    <input
                      type="search"
                      placeholder="Search devices…"
                      value={query}
                      onChange={(event) => setQuery(event.target.value)}
                    />
                  </label>
                  <div className="filters">
                    <label>
                      <span className="sr-only">Connection status</span>
                      <select
                        value={status}
                        onChange={(event) => setStatus(event.target.value)}
                      >
                        <option value="all">All statuses</option>
                        <option value="online">Online</option>
                        <option value="offline">Offline</option>
                      </select>
                    </label>
                    <label>
                      <span className="sr-only">Platform</span>
                      <select
                        value={platform}
                        onChange={(event) => setPlatform(event.target.value)}
                      >
                        <option value="all">All platforms</option>
                        {platforms.map((name) => (
                          <option key={name} value={name}>
                            {name}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                </div>

                <div className="table-scroll">
                  <table>
                    <caption className="sr-only">
                      Devices in the local workspace
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Device</th>
                        <th scope="col">Status</th>
                        <th scope="col">Platform</th>
                        <th scope="col">Device group</th>
                        <th scope="col">Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visible.map((device) => (
                        <tr key={device.id}>
                          <td>
                            <button
                              className="device-name device-open"
                              onClick={() => setSelectedId(device.id)}
                            >
                              <span className="device-icon">
                                <Icon name="devices" />
                              </span>
                              {device.name}
                            </button>
                          </td>
                          <td>
                            <span className="device-status">
                              <span className={`presence ${device.status}`} />
                              {device.status === "online"
                                ? "Online"
                                : "Offline"}
                            </span>
                          </td>
                          <td>{device.platform}</td>
                          <td>{device.group}</td>
                          <td>
                            {device.last_seen
                              ? new Date(device.last_seen).toLocaleString()
                              : "Not recorded"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {!snapshot ? (
                  <div className="empty-state" role="status">
                    <span className="empty-icon">
                      <Icon name={error ? "server" : "refresh"} />
                    </span>
                    <h2>
                      {error
                        ? "Waiting for the server"
                        : "Loading your devices"}
                    </h2>
                    <p>
                      {error
                        ? "Retry the connection to load your device list."
                        : "Connecting to your local workspace…"}
                    </p>
                  </div>
                ) : visible.length === 0 ? (
                  <div className="empty-state">
                    <FleetIllustration />
                    <h2>
                      {hasFilters
                        ? "No matching devices"
                        : "No devices connected yet"}
                    </h2>
                    <p>
                      {hasFilters
                        ? "Try a different search or clear your filters."
                        : snapshot.server.capabilities.agent_enrollment
                          ? "Start an approved lab agent to see it here."
                          : "Connected devices will appear here. Agent enrollment is not available in this preview."}
                    </p>
                    {hasFilters ? (
                      <button
                        className="button primary"
                        type="button"
                        onClick={clearFilters}
                      >
                        Clear filters
                      </button>
                    ) : (
                      <button
                        className="text-button"
                        type="button"
                        onClick={() => about.current?.showModal()}
                      >
                        What’s available in this preview?
                        <Icon name="arrow" />
                      </button>
                    )}
                  </div>
                ) : null}

                <footer className="inventory-footer">
                  <span>
                    {snapshot
                      ? `${visible.length} of ${devices.length} ${devices.length === 1 ? "device" : "devices"}`
                      : "Waiting for device information"}
                  </span>
                  <span role="status">
                    {snapshot
                      ? `${error ? "Last successful update" : "Updated"} ${snapshot.fetchedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
                      : "Connecting to server"}
                  </span>
                </footer>
              </section>
              <p className="page-note">
                <Icon name="info" />
                {snapshot?.server.capabilities.terminal
                  ? "Select a device to view its information or start an authorised remote session."
                  : "Remote connections become available after the approved agent’s management core is ready."}
              </p>
            </>
          ) : section === "Tasks" && user.role !== "viewer" ? (
            <>
              <div className="page-heading">
                <div><h1>Tasks</h1><p>Schedule a shell script on selected devices.</p></div>
              </div>
              <section className="group-card">
                <SchedulePanel devices={devices.filter((device) =>
                  ["macOS", "Linux"].includes(device.platform) &&
                  (user.role === "administrator" || user.groups.includes(device.group_id))
                )} />
              </section>
            </>
          ) : (
            <ManagementPage key={section} section={section} />
          )}
        </div>
      </main>
      {selectedId && devices.find((d) => d.id === selectedId) && (
        <Suspense fallback={<span role="status">Opening device…</span>}>
          <DeviceWorkspace
            device={devices.find((d) => d.id === selectedId)!}
            onClose={() => setSelectedId(null)}
            onChanged={() => void refresh()}
          />
        </Suspense>
      )}

      <dialog
        ref={about}
        className="preview-dialog"
        aria-labelledby="preview-title"
        onClick={(event) => {
          if (event.target === event.currentTarget) about.current?.close();
        }}
      >
        <div className="dialog-content">
          <button
            className="icon-button dialog-close"
            type="button"
            aria-label="Close preview information"
            onClick={() => about.current?.close()}
          >
            <Icon name="close" />
          </button>
          <span className="dialog-icon">
            <Icon name="devices" />
          </span>
          <h2 id="preview-title">A new home for your devices</h2>
          <p>
            This local preview uses MeshCentral’s Rust server and existing
            agents. Only explicitly approved lab devices can connect.
          </p>
          <dl className="capability-list">
            <div>
              <dt>Console and server connection</dt>
              <dd>Available</dd>
            </div>
            <div>
              <dt>Agent enrollment</dt>
              <dd>
                {snapshot?.server.capabilities.agent_enrollment
                  ? "Approved lab agents only"
                  : "Not available yet"}
              </dd>
            </div>
            <div>
              <dt>Remote terminal and files</dt>
              <dd>
                {snapshot?.server.capabilities.terminal
                  ? "Available on ready agents"
                  : "Not available yet"}
              </dd>
            </div>
          </dl>
          <p className="dialog-note">
            The lab uses unmodified agent binaries with separate configuration
            and keys. Keep production agents connected to your current server.
          </p>
          <div className="dialog-footer">
            <span>Version {snapshot?.server.version ?? "unavailable"}</span>
            <button
              className="button primary"
              type="button"
              onClick={() => about.current?.close()}
            >
              Got it
            </button>
          </div>
        </div>
      </dialog>
    </div>
  );
}
