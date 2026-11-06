import { useEffect, useRef, useState } from "react";
import type { Device } from "./api";
import { api, useAuth } from "./Auth";
import { DesktopPanel, FilesPanel, TerminalPanel } from "./RemotePanels";
import { ScriptPanel } from "./ScriptPanel";
import { SchedulePanel } from "./SchedulePanel";
export function DeviceWorkspace({
  device,
  onClose,
  onChanged,
}: {
  device: Device;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { user, csrf } = useAuth();
  const [tab, setTab] = useState("Overview");
  const [alias, setAlias] = useState(device.alias ?? "");
  const [notes, setNotes] = useState(device.notes);
  const [tags, setTags] = useState(device.tags.join(", "));
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [busy, setBusy] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const canControl =
    user.role !== "viewer" &&
    (user.role === "administrator" || user.groups.includes(device.group_id));
  const supportsScripts = ["macOS", "Linux"].includes(device.platform);
  const canConnect = device.status === "online" && device.core_ready;
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  async function save() {
    setBusy(true);
    setError("");
    try {
      await api("/devices/" + encodeURIComponent(device.id), csrf, "PATCH", {
        alias: alias.trim() || null,
        notes,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      });
      setSaved("Changes saved");
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <dialog
      className="device-workspace"
      ref={dialog}
      onCancel={onClose}
      aria-labelledby="device-title"
    >
      <div className="device-dialog-header">
        <div>
          <span className="panel-help">
            {device.group} / {device.platform}
          </span>
          <h2 id="device-title">{device.name}</h2>
        </div>
        <span className="device-status">
          <span className={"presence " + device.status} />
          {device.status === "online" ? "Online" : "Offline"}
        </span>
        <button className="button" onClick={onClose}>
          Close device
        </button>
      </div>
      <div className="device-tabs" role="tablist" aria-label="Device sections">
        {["Overview", "Terminal", "Files", "Desktop", "Scripts", "Tasks"].map(
          (name) => (
            <button
              key={name}
              role="tab"
              aria-selected={tab === name}
              disabled={
                name !== "Overview" &&
                (!canControl ||
                  (name !== "Tasks" && !canConnect) ||
                  (["Scripts", "Tasks"].includes(name) && !supportsScripts))
              }
              onClick={() => setTab(name)}
            >
              {name}
            </button>
          ),
        )}
      </div>
      <div className="device-body" role="tabpanel">
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        {tab === "Overview" ? (
          <div className="device-overview">
            <section>
              <h3>Device details</h3>
              <dl className="detail-list">
                <div>
                  <dt>Hostname</dt>
                  <dd>{device.hostname || device.name}</dd>
                </div>
                <div>
                  <dt>Platform</dt>
                  <dd>{device.platform}</dd>
                </div>
                <div>
                  <dt>Group</dt>
                  <dd>{device.group}</dd>
                </div>
                <div>
                  <dt>Last seen</dt>
                  <dd>
                    {device.last_seen
                      ? new Date(device.last_seen).toLocaleString()
                      : "Not recorded"}
                  </dd>
                </div>
                <div>
                  <dt>Remote management</dt>
                  <dd>
                    {device.core_ready
                      ? "Ready"
                      : device.status === "online"
                        ? "Waiting for agent core"
                        : "Agent offline"}
                  </dd>
                </div>
              </dl>
              <details>
                <summary>Certificate identity</summary>
                <code className="node-fingerprint">
                  {device.node_id_hex || device.id}
                </code>
              </details>
              <h3>System information</h3>
              {device.details && Object.keys(device.details).length ? (
                <div className="system-details">
                  {Object.entries(device.details).map(([name, data]) => (
                    <details key={name}>
                      <summary>
                        {name === "coreinfo"
                          ? "Agent information"
                          : name === "netinfo"
                            ? "Network interfaces"
                            : name === "sysinfo"
                              ? "Hardware and operating system"
                              : name}
                      </summary>
                      <pre>{JSON.stringify(data, null, 2)}</pre>
                    </details>
                  ))}
                </div>
              ) : (
                <p className="panel-help">
                  System information is not available yet.
                </p>
              )}
            </section>
            <section>
              <h3>Workspace information</h3>
              <label className="field-label">
                Display name
                <input
                  value={alias}
                  placeholder={device.hostname || device.name}
                  disabled={!canControl}
                  onChange={(e) => setAlias(e.target.value)}
                  maxLength={255}
                />
              </label>
              <label className="field-label">
                Tags
                <input
                  value={tags}
                  placeholder="Separate tags with commas"
                  disabled={!canControl}
                  onChange={(e) => setTags(e.target.value)}
                />
              </label>
              <label className="field-label">
                Notes
                <textarea
                  rows={7}
                  value={notes}
                  disabled={!canControl}
                  onChange={(e) => setNotes(e.target.value)}
                  maxLength={8192}
                />
              </label>
              {canControl && (
                <div className="form-actions">
                  <button
                    className="button primary"
                    disabled={busy}
                    onClick={() => void save()}
                  >
                    Save details
                  </button>
                  <span role="status">{saved}</span>
                </div>
              )}
              <div className="device-danger-zone">
                {canControl && device.status === "online" && (
                  <button
                    className="button"
                    onClick={async () => {
                      if (
                        !confirm(
                          "Disconnect this agent? It may reconnect automatically.",
                        )
                      )
                        return;
                      try {
                        await api(
                          "/devices/" +
                            encodeURIComponent(device.id) +
                            "/disconnect",
                          csrf,
                          "POST",
                        );
                        onChanged();
                        onClose();
                      } catch (e) {
                        setError(String(e));
                      }
                    }}
                  >
                    Disconnect agent
                  </button>
                )}
                {user.role === "administrator" &&
                  device.status === "offline" && (
                    <button
                      className="button danger"
                      onClick={async () => {
                        if (
                          !confirm(
                            "Forget this offline record? Approved agents can appear again when they reconnect.",
                          )
                        )
                          return;
                        try {
                          await api(
                            "/devices/" + encodeURIComponent(device.id),
                            csrf,
                            "DELETE",
                          );
                          onChanged();
                          onClose();
                        } catch (e) {
                          setError(String(e));
                        }
                      }}
                    >
                      Forget offline record
                    </button>
                  )}
              </div>
            </section>
          </div>
        ) : tab === "Terminal" ? (
          <TerminalPanel node={device.id} />
        ) : tab === "Files" ? (
          <FilesPanel node={device.id} />
        ) : tab === "Scripts" ? (
          <ScriptPanel key={device.id} node={device.id} />
        ) : tab === "Tasks" ? (
          <SchedulePanel key={device.id} node={device.id} />
        ) : (
          <DesktopPanel node={device.id} />
        )}
      </div>
    </dialog>
  );
}
