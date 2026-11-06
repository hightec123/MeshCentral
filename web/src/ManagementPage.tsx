import { useCallback, useEffect, useState } from "react";
import { api, useAuth } from "./Auth";
import { AccountMfa } from "./AccountMfa";
import type { Operator } from "./Auth";
type Group = {
  primary?: boolean;
  mesh_id_hex: string;
  group_name: string;
  allowed_node_ids_hex?: string[];
};
type Session = {
  id: string;
  node_id: string;
  username: string;
  kind: string;
  started_at: string;
};
type Audit = {
  time: string;
  actor: string;
  action: string;
  target: string;
  outcome: string;
};
export function ManagementPage({ section }: { section: string }) {
  const { user, csrf } = useAuth();
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<Operator[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [events, setEvents] = useState<Audit[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Operator["role"]>("viewer");
  const [grants, setGrants] = useState<string[]>([]);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const refresh = useCallback(async () => {
    setError("");
    setBusy(true);
    try {
      if (section === "Groups") {
        const data = await api<{ groups: Group[] }>("/groups", csrf);
        setGroups(data.groups);
      }
      if (section === "People") {
        const [accounts, mesh] = await Promise.all([
          api<{ users: Operator[] }>("/users", csrf),
          api<{ groups: Group[] }>("/groups", csrf),
        ]);
        setUsers(accounts.users);
        setGroups(mesh.groups);
      }
      if (section === "Sessions") {
        const data = await api<{ sessions: Session[] }>("/sessions", csrf);
        setSessions(data.sessions);
      }
      if (section === "Activity") {
        const data = await api<{ events: Audit[] }>("/audit", csrf);
        setEvents(data.events);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed.");
    } finally {
      setBusy(false);
    }
  }, [section, csrf]);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  async function run(work: () => Promise<unknown>) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await work();
      setMessage("Changes saved");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="management-page">
      <div className="page-heading">
        <div>
          <h1>{section}</h1>
          <p>
            {section === "Groups"
              ? "Organise devices and approve their certificate identities."
              : section === "People"
                ? "Control who can view and manage each device group."
                : section === "Activity"
                  ? "Account and remote-session audit history."
                  : section === "Sessions"
                    ? "Review and close active remote connections."
                    : "Update your password and manage your sign-in."}
          </p>
        </div>
        {section !== "Account" && (
          <button
            className="button"
            disabled={busy}
            onClick={() => void refresh()}
          >
            Refresh
          </button>
        )}
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="success-message">
          {message}
        </p>
      )}
      {section === "Groups" && (
        <>
          {user.role === "administrator" && (
            <form
              className="inline-form"
              onSubmit={(e) => {
                e.preventDefault();
                void run(async () => {
                  await api("/groups", csrf, "POST", { name });
                  setName("");
                });
              }}
            >
              <label className="field-label">
                New device group
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  maxLength={64}
                  required
                />
              </label>
              <button className="button primary" disabled={busy}>
                Create group
              </button>
            </form>
          )}
          <div className="group-grid">
            {groups.map((group) => (
              <GroupCard
                key={group.mesh_id_hex}
                group={group}
                admin={user.role === "administrator"}
                busy={busy}
                save={(body) =>
                  run(() =>
                    api("/groups/" + group.mesh_id_hex, csrf, "PUT", body),
                  )
                }
                remove={() =>
                  run(() => api("/groups/" + group.mesh_id_hex, csrf, "DELETE"))
                }
                configuration={async () => {
                  try {
                    const data = await api<{ configuration: string }>(
                      "/groups/" + group.mesh_id_hex + "/configuration",
                      csrf,
                    );
                    const url = URL.createObjectURL(
                      new Blob([data.configuration], { type: "text/plain" }),
                    );
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = "meshagent.msh";
                    link.click();
                    setTimeout(() => URL.revokeObjectURL(url), 5000);
                  } catch (e) {
                    setError(String(e));
                  }
                }}
              />
            ))}
          </div>
        </>
      )}
      {section === "People" && (
        <>
          <form
            className="account-form"
            onSubmit={(e) => {
              e.preventDefault();
              void run(async () => {
                await api("/users", csrf, "POST", {
                  user: { username: name.toLowerCase(), role, groups: grants },
                  password: password || null,
                });
                setName("");
                setPassword("");
              });
            }}
          >
            <h2>Create or update an operator</h2>
            <div className="form-grid">
              <label className="field-label">
                Username
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  minLength={3}
                  maxLength={64}
                  required
                />
              </label>
              <label className="field-label">
                Role
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as Operator["role"])}
                >
                  <option value="viewer">Viewer</option>
                  <option value="operator">Operator</option>
                  <option value="administrator">Administrator</option>
                </select>
              </label>
              <label className="field-label">
                Password
                <input
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  minLength={12}
                  maxLength={128}
                  placeholder="Required for new accounts"
                />
              </label>
            </div>
            <fieldset className="grant-list">
              <legend>Device groups</legend>
              {groups.map((group) => (
                <label key={group.mesh_id_hex}>
                  <input
                    type="checkbox"
                    checked={grants.includes(group.mesh_id_hex)}
                    disabled={role === "administrator"}
                    onChange={(e) =>
                      setGrants((old) =>
                        e.target.checked
                          ? [...old, group.mesh_id_hex]
                          : old.filter((id) => id !== group.mesh_id_hex),
                      )
                    }
                  />
                  {group.group_name}
                </label>
              ))}
            </fieldset>
            <p className="panel-help">
              Administrators manage every group. Viewers cannot start remote
              sessions. Updating an account revokes its existing sign-ins.
            </p>
            <button className="button primary" disabled={busy}>
              Save operator
            </button>
          </form>
          <div className="inventory table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Groups</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((account) => (
                  <tr key={account.username}>
                    <td>{account.username}</td>
                    <td>{account.role}</td>
                    <td>
                      {account.role === "administrator"
                        ? "All groups"
                        : account.groups
                            .map(
                              (id) =>
                                groups.find((g) => g.mesh_id_hex === id)
                                  ?.group_name || id.slice(0, 12),
                            )
                            .join(", ") || "None"}
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="text-button"
                          onClick={() => {
                            setName(account.username);
                            setRole(account.role);
                            setGrants(account.groups);
                            setPassword("");
                          }}
                        >
                          Edit
                        </button>
                        <button
                          className="text-button danger"
                          disabled={busy}
                          onClick={() => {
                            if (
                              confirm(
                                "Delete operator " +
                                  account.username +
                                  " and revoke their sessions?",
                              )
                            )
                              void run(() =>
                                api(
                                  "/users/" +
                                    encodeURIComponent(account.username),
                                  csrf,
                                  "DELETE",
                                ),
                              );
                          }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
      {section === "Sessions" && (
        <div className="inventory table-scroll">
          <table>
            <thead>
              <tr>
                <th>Operator</th>
                <th>Connection</th>
                <th>Started</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.id}>
                  <td>{session.username}</td>
                  <td>{session.kind}</td>
                  <td>{new Date(session.started_at).toLocaleString()}</td>
                  <td>
                    <button
                      className="text-button danger"
                      onClick={() =>
                        void run(() =>
                          api(
                            "/sessions/" + encodeURIComponent(session.id),
                            csrf,
                            "DELETE",
                          ),
                        )
                      }
                    >
                      Close session
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!sessions.length && (
            <p className="empty-list">No active remote sessions.</p>
          )}
        </div>
      )}
      {section === "Activity" && (
        <div className="inventory table-scroll">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Operator</th>
                <th>Action</th>
                <th>Target</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, index) => (
                <tr key={index}>
                  <td>{new Date(event.time).toLocaleString()}</td>
                  <td>{event.actor || "Unknown"}</td>
                  <td>{event.action}</td>
                  <td className="audit-target" title={event.target}>
                    {event.target || "—"}
                  </td>
                  <td>{event.outcome}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!events.length && (
            <p className="empty-list">No activity recorded yet.</p>
          )}
        </div>
      )}
      {section === "Account" && (
        <form
          className="account-form"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              await api("/auth/password", csrf, "POST", { current, new: next });
              window.dispatchEvent(new Event("mcr-signout"));
            });
          }}
        >
          <h2>Change your password</h2>
          <p className="panel-help">
            Changing your password signs out every existing session, including
            this one.
          </p>
          <label className="field-label">
            Current password
            <input
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              required
            />
          </label>
          <label className="field-label">
            New password
            <input
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={128}
              value={next}
              onChange={(e) => setNext(e.target.value)}
              required
            />
          </label>
          <button className="button primary" disabled={busy}>
            Change password
          </button>
        </form>
      )}
      {section === "Account" && <AccountMfa />}
    </div>
  );
}
function GroupCard({
  group,
  admin,
  busy,
  save,
  configuration,
  remove,
}: {
  group: Group;
  admin: boolean;
  busy: boolean;
  save: (group: Group) => Promise<void>;
  configuration: () => Promise<void>;
  remove: () => Promise<void>;
}) {
  const [name, setName] = useState(group.group_name);
  const [nodes, setNodes] = useState(
    group.allowed_node_ids_hex?.join("\n") ?? "",
  );
  useEffect(() => {
    setName(group.group_name);
    setNodes(group.allowed_node_ids_hex?.join("\n") ?? "");
  }, [group]);
  return (
    <section className="group-card">
      <h2>{group.group_name}</h2>
      <p className="panel-help">
        {group.allowed_node_ids_hex?.length ?? "Approved"} agent identities
      </p>
      {admin ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save({
              ...group,
              group_name: name,
              allowed_node_ids_hex: nodes.split(/\s+/).filter(Boolean),
            });
          }}
        >
          <label className="field-label">
            Group name
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={64}
              required
            />
          </label>
          <label className="field-label">
            Approved NodeIDs
            <textarea
              rows={4}
              value={nodes}
              onChange={(e) => setNodes(e.target.value)}
              placeholder="One 96-character hex fingerprint per line"
            />
          </label>
          <p className="panel-help">
            Removing an identity disconnects that agent. New agents require an
            explicit fingerprint approval.
          </p>
          <div className="form-actions">
            <button className="button primary" disabled={busy}>
              Save group
            </button>
            <button
              type="button"
              className="button"
              onClick={() => void configuration()}
            >
              Download configuration
            </button>
            {!group.primary && (
              <button
                type="button"
                className="button danger"
                disabled={busy}
                onClick={() => {
                  if (confirm("Delete this empty device group?")) void remove();
                }}
              >
                Delete group
              </button>
            )}
          </div>
        </form>
      ) : (
        <p className="panel-help">
          Your access to this group is managed by an administrator.
        </p>
      )}
    </section>
  );
}
