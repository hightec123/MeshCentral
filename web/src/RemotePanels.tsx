import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { useRemote } from "./useRemote";

function Controls({
  remote,
  title,
}: {
  remote: ReturnType<typeof useRemote>;
  title: string;
}) {
  return (
    <>
      <div className="remote-toolbar">
        <strong>{title}</strong>
        <span className="remote-status" role="status">
          {remote.status}
        </span>
        {remote.status === "Disconnected" ? (
          <button
            className="button primary"
            onClick={() => void remote.connect()}
          >
            Connect
          </button>
        ) : (
          <button className="button" onClick={remote.close}>
            Disconnect
          </button>
        )}
      </div>
      {remote.error && (
        <p role="alert" className="form-error">
          {remote.error}
        </p>
      )}
    </>
  );
}

export function TerminalPanel({ node }: { node: string }) {
  const container = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const remote = useRemote(
    node,
    "terminal",
    (data) =>
      terminal.current?.write(
        typeof data === "string" ? data : new Uint8Array(data),
      ),
    () => {
      terminal.current?.focus();
    },
  );
  const send = useRef(remote.send);
  send.current = remote.send;
  useEffect(() => {
    const term = new Terminal({
      fontSize: 13,
      fontFamily: "Menlo, Consolas, monospace",
      cursorBlink: true,
      screenReaderMode: true,
      theme: { background: "#172033", foreground: "#e3eaf9" },
      scrollback: 3000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container.current!);
    terminal.current = term;
    fit.fit();
    const input = term.onData((data) =>
      send.current(new TextEncoder().encode(data)),
    );
    const resize = term.onResize((size) =>
      send.current(
        JSON.stringify({
          ctrlChannel: "102938",
          type: "termsize",
          cols: size.cols,
          rows: size.rows,
        }),
      ),
    );
    const observer = new ResizeObserver(() => fit.fit());
    observer.observe(container.current!);
    return () => {
      observer.disconnect();
      input.dispose();
      resize.dispose();
      term.dispose();
      terminal.current = null;
    };
  }, []);
  return (
    <section>
      <Controls remote={remote} title="Remote terminal" />
      <div
        className="terminal-container"
        ref={container}
        aria-label="Remote terminal"
      />
      <p className="panel-help">
        Commands run on the selected device as the agent’s account.
      </p>
    </section>
  );
}

type Entry = { n: string; t: number; s?: number; d?: string };
export function FilesPanel({ node }: { node: string }) {
  const [path, setPath] = useState("/");
  const currentPath = useRef(path);
  currentPath.current = path;
  const [entries, setEntries] = useState<Entry[]>([]);
  const [busy, setBusy] = useState("");
  const [filter, setFilter] = useState("");
  const counter = useRef(0);
  const download = useRef<{
    id: number;
    name: string;
    chunks: Uint8Array[];
    size: number;
  } | null>(null);
  const upload = useRef<{ id: number; file: File; offset: number } | null>(
    null,
  );
  const functions = useRef<{
    list: () => void;
    sendUpload: () => Promise<void>;
  }>({ list: () => {}, sendUpload: async () => {} });
  const remote = useRemote(
    node,
    "files",
    (data) => {
      const bytes = typeof data === "string" ? null : new Uint8Array(data);
      if (bytes && bytes[0] === 1 && download.current) {
        const transfer = download.current;
        transfer.chunks.push(bytes.slice(4));
        transfer.size += bytes.length - 4;
        if (transfer.size > 100 * 1024 * 1024) {
          remote.setError("Download exceeds the 100 MB browser limit.");
          download.current = null;
          setBusy("");
          return;
        }
        if (bytes[3] === 1) {
          const blob = new Blob(
            transfer.chunks.map((chunk) => chunk.slice().buffer),
          );
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = transfer.name;
          anchor.click();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
          download.current = null;
          setBusy("");
        } else
          remote.send(
            JSON.stringify({ action: "download", sub: "ack", id: transfer.id }),
          );
        return;
      }
      let message;
      try {
        message = JSON.parse(
          typeof data === "string" ? data : new TextDecoder().decode(data),
        );
      } catch {
        return;
      }
      if (Array.isArray(message.dir)) {
        setEntries(message.dir);
        setBusy("");
      }
      if (message.action === "download" && download.current) {
        if (message.sub === "start")
          remote.send(
            JSON.stringify({
              action: "download",
              sub: "startack",
              id: download.current.id,
              ack: 1,
            }),
          );
        if (message.sub === "cancel") {
          download.current = null;
          setBusy("");
          remote.setError("The file could not be downloaded.");
        }
      }
      if (message.action === "uploadstart" || message.action === "uploadack")
        void functions.current.sendUpload();
      if (message.action === "uploaddone") {
        upload.current = null;
        setBusy("");
        functions.current.list();
      }
      if (message.action === "uploaderror") {
        upload.current = null;
        setBusy("");
        remote.setError("The agent could not write this file.");
      }
      if (message.error) remote.setError(String(message.error));
    },
    () => functions.current.list(),
  );
  function list() {
    setBusy("Loading");
    remote.send(
      JSON.stringify({
        action: "ls",
        path: currentPath.current,
        reqid: ++counter.current,
      }),
    );
  }
  async function sendUpload() {
    const transfer = upload.current;
    if (!transfer) return;
    if (transfer.offset >= transfer.file.size) {
      remote.send(JSON.stringify({ action: "uploaddone", reqid: transfer.id }));
      return;
    }
    const part = new Uint8Array(
      await transfer.file
        .slice(transfer.offset, transfer.offset + 16380)
        .arrayBuffer(),
    );
    if (upload.current !== transfer) return;
    const packet = new Uint8Array(part.length + 1);
    packet.set(part, 1);
    if (remote.send(packet)) transfer.offset += part.length;
    else {
      upload.current = null;
      setBusy("");
    }
  }
  functions.current = { list, sendUpload };
  function navigate(next: string) {
    currentPath.current = next;
    setPath(next);
    setEntries([]);
    list();
  }
  function full(name: string) {
    return currentPath.current.replace(/[\\/]$/, "") + "/" + name;
  }
  function mutate(action: string, details: Record<string, unknown>) {
    remote.send(
      JSON.stringify({ action, ...details, reqid: ++counter.current }),
    );
    list();
  }
  return (
    <section>
      <Controls remote={remote} title="Remote files" />
      <div className="file-toolbar">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            list();
          }}
        >
          <label className="sr-only" htmlFor="remote-path">
            Remote path
          </label>
          <input
            id="remote-path"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="Remote path"
          />
          <button
            className="button"
            disabled={remote.status !== "Connected" || !!busy}
          >
            Open
          </button>
        </form>
        <button
          className="button"
          disabled={remote.status !== "Connected" || !!busy}
          onClick={() =>
            navigate(path.replace(/[\\/]?[^\\/]+[\\/]?$/, "") || "/")
          }
        >
          Up
        </button>
        <button
          className="button"
          disabled={remote.status !== "Connected" || !!busy}
          onClick={() => {
            const name = prompt("New folder name");
            if (name && name !== "." && name !== ".." && !/[\\/]/.test(name))
              mutate("mkdir", { path: full(name) });
          }}
        >
          New folder
        </button>
        <label className="button">
          Upload
          <input
            className="sr-only"
            type="file"
            disabled={remote.status !== "Connected" || !!busy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (!file) return;
              if (file.size > 100 * 1024 * 1024) {
                remote.setError("Upload exceeds the 100 MB browser limit.");
                return;
              }
              if (
                entries.some((entry) => entry.n === file.name) &&
                !confirm("Replace " + file.name + "?")
              )
                return;
              const id = ++counter.current;
              upload.current = { id, file, offset: 0 };
              setBusy("Uploading " + file.name);
              remote.send(
                JSON.stringify({
                  action: "upload",
                  path: currentPath.current,
                  name: file.name,
                  size: file.size,
                  reqid: id,
                }),
              );
              e.target.value = "";
            }}
          />
        </label>
      </div>
      <label className="file-filter">
        <span className="sr-only">Filter files</span>
        <input
          placeholder="Filter files…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </label>
      <p role="status" className="panel-help">
        {busy || `${entries.length} entries`}
      </p>
      <div className="file-list table-scroll">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Size</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {entries
              .filter((entry) =>
                entry.n.toLowerCase().includes(filter.toLowerCase()),
              )
              .map((entry) => (
                <tr key={entry.n}>
                  <td>
                    {entry.t === 2 ? (
                      <button
                        className="text-button"
                        onClick={() => navigate(full(entry.n))}
                      >
                        ▸ {entry.n}
                      </button>
                    ) : (
                      entry.n
                    )}
                  </td>
                  <td>{entry.t === 2 ? "Folder" : `${entry.s ?? 0} bytes`}</td>
                  <td>
                    <div className="row-actions">
                      {entry.t !== 2 && (
                        <button
                          className="text-button"
                          disabled={!!busy}
                          onClick={() => {
                            const id = ++counter.current;
                            download.current = {
                              id,
                              name: entry.n,
                              chunks: [],
                              size: 0,
                            };
                            setBusy("Downloading " + entry.n);
                            remote.send(
                              JSON.stringify({
                                action: "download",
                                sub: "start",
                                id,
                                path: full(entry.n),
                              }),
                            );
                          }}
                        >
                          Download
                        </button>
                      )}
                      <button
                        className="text-button"
                        disabled={!!busy}
                        onClick={() => {
                          const name = prompt("Rename " + entry.n, entry.n);
                          if (
                            name &&
                            name !== "." &&
                            name !== ".." &&
                            !/[\\/]/.test(name)
                          )
                            mutate("rename", {
                              path: currentPath.current,
                              oldname: entry.n,
                              newname: name,
                            });
                        }}
                      >
                        Rename
                      </button>
                      <button
                        className="text-button danger"
                        disabled={!!busy}
                        onClick={() => {
                          if (
                            confirm(
                              "Delete " + entry.n + "? Folders must be empty.",
                            )
                          )
                            mutate("rm", {
                              path: currentPath.current,
                              delfiles: [entry.n],
                              rec: false,
                            });
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
      <p className="panel-help">
        Transfers stay within the selected agent session. Files are limited to
        100 MB per browser transfer.
      </p>
    </section>
  );
}

type Desktop = {
  parent: {
    send: (data: string | Uint8Array) => void;
    setConsoleMessage: (message: string) => void;
  };
  State: number;
  stopInput: boolean;
  Start: () => void;
  Stop: () => void;
  xxStateChange: (state: number) => void;
  SendCompressionLevel: (
    type: number,
    quality: number,
    scale: number,
    interval: number,
  ) => void;
  SendRefresh: () => void;
  ProcessBinaryCommand: (
    command: number,
    size: number,
    data: Uint8Array,
  ) => void;
  GrabMouseInput: () => void;
  UnGrabMouseInput: () => void;
  onScreenSizeChange: () => void;
  onPreDrawImage: () => void;
  xxKeyDown: (event: KeyboardEvent) => void;
  xxKeyUp: (event: KeyboardEvent) => void;
  xxKeyPress: (event: KeyboardEvent) => void;
  handleReleaseKeys: () => void;
};
declare global {
  interface Window {
    CreateAgentRemoteDesktop: (
      canvas: HTMLCanvasElement,
      scroll: HTMLElement,
    ) => Desktop;
  }
}
export function DesktopPanel({ node }: { node: string }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const scroll = useRef<HTMLDivElement>(null);
  const desktop = useRef<Desktop | null>(null);
  const [control, setControl] = useState(false);
  const [frames, setFrames] = useState(0);
  const accumulator = useRef<{
    command: number;
    size: number;
    bytes: Uint8Array;
  } | null>(null);
  const remote = useRemote(
    node,
    "desktop",
    (data) => {
      if (typeof data === "string") return;
      let bytes = new Uint8Array(data);
      if (accumulator.current) {
        const pending = accumulator.current;
        const joined = new Uint8Array(pending.bytes.length + bytes.length);
        joined.set(pending.bytes);
        joined.set(bytes, pending.bytes.length);
        pending.bytes = joined;
        if (joined.length >= pending.size) {
          desktop.current?.ProcessBinaryCommand(
            pending.command,
            pending.size,
            joined.slice(0, pending.size),
          );
          accumulator.current = null;
        }
        return;
      }
      if (bytes.length < 4) return;
      let command = (bytes[0] << 8) | bytes[1];
      let size = (bytes[2] << 8) | bytes[3];
      if (command === 27 && size === 8 && bytes.length >= 12) {
        size = new DataView(
          bytes.buffer,
          bytes.byteOffset,
          bytes.byteLength,
        ).getUint32(4);
        bytes = bytes.slice(8);
        command = (bytes[0] << 8) | bytes[1];
      }
      if (size > 4 * 1024 * 1024) {
        remote.setError("Desktop frame exceeds the supported size.");
        remote.close();
        return;
      }
      if (size > bytes.length) {
        accumulator.current = { command, size, bytes };
        return;
      }
      desktop.current?.ProcessBinaryCommand(
        command,
        size,
        bytes.slice(0, size),
      );
    },
    () => {
      desktop.current?.xxStateChange(3);
      desktop.current?.SendCompressionLevel(1, 60, 1024, 200);
      desktop.current?.SendRefresh();
    },
  );
  const remoteRef = useRef(remote);
  remoteRef.current = remote;
  useEffect(() => {
    if (!window.CreateAgentRemoteDesktop) {
      remoteRef.current.setError(
        "Desktop renderer did not load. Refresh the page.",
      );
      return;
    }
    const view = window.CreateAgentRemoteDesktop(
      canvas.current!,
      scroll.current!,
    );
    view.parent = {
      send: (data) => {
        if (typeof data === "string") {
          remoteRef.current.send(Uint8Array.from(data, (c) => c.charCodeAt(0)));
        } else remoteRef.current.send(data);
      },
      setConsoleMessage: (message) => remoteRef.current.setError(message),
    };
    view.onScreenSizeChange = () => {};
    view.onPreDrawImage = () => setFrames((n) => n + 1);
    view.stopInput = true;
    view.Start();
    desktop.current = view;
    return () => {
      view.Stop();
      desktop.current = null;
    };
  }, []);
  useEffect(() => {
    const view = desktop.current;
    if (!view) return;
    const enabled = control && remote.status === "Connected";
    view.stopInput = !enabled;
    if (enabled) view.GrabMouseInput();
    else {
      view.handleReleaseKeys();
      view.UnGrabMouseInput();
    }
  }, [control, remote.status]);
  return (
    <section>
      <Controls remote={remote} title="Remote desktop" />
      <div className="desktop-options">
        <label>
          <input
            type="checkbox"
            checked={control}
            onChange={(e) => setControl(e.target.checked)}
          />{" "}
          Allow mouse and keyboard control
        </label>
        <button
          className="button"
          disabled={remote.status !== "Connected"}
          onClick={() => desktop.current?.SendRefresh()}
        >
          Refresh screen
        </button>
        <span>{frames} frames drawn</span>
      </div>
      <div ref={scroll} className="desktop-viewport">
        <canvas
          ref={canvas}
          width={960}
          height={600}
          tabIndex={0}
          aria-label="Remote desktop"
          onMouseDownCapture={(e) => {
            if (control && remote.status === "Connected")
              e.currentTarget.focus();
          }}
          onKeyDown={(e) => {
            if (control && remote.status === "Connected")
              desktop.current?.xxKeyDown(e.nativeEvent);
          }}
          onKeyUp={(e) => {
            if (control && remote.status === "Connected")
              desktop.current?.xxKeyUp(e.nativeEvent);
          }}
          onKeyPress={(e) => {
            if (control && remote.status === "Connected")
              desktop.current?.xxKeyPress(e.nativeEvent);
          }}
          onBlur={() => desktop.current?.handleReleaseKeys()}
        />
      </div>
      {remote.status === "Connected" && frames === 0 && (
        <p className="panel-help">
          Waiting for screen data. The device may require screen-recording
          permission or a logged-in desktop session.
        </p>
      )}
    </section>
  );
}
