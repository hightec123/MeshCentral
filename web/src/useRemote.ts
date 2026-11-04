import { useCallback, useEffect, useRef, useState } from "react";
import { api, useAuth } from "./Auth";
export type RemoteKind = "terminal" | "files" | "desktop";
export function useRemote(
  node: string,
  kind: RemoteKind,
  onData: (data: string | ArrayBuffer) => void,
  onReady?: () => void,
) {
  const { csrf } = useAuth();
  const [status, setStatus] = useState("Disconnected");
  const [error, setError] = useState("");
  const socket = useRef<WebSocket | null>(null);
  const session = useRef<string | null>(null);
  const callbacks = useRef({ onData, onReady });
  callbacks.current = { onData, onReady };
  const mounted = useRef(true);
  const connecting = useRef(false);
  const revoking = useRef(false);
  const close = useCallback(() => {
    socket.current?.close();
    socket.current = null;
    const id = session.current;
    session.current = null;
    connecting.current = false;
    if (id && !revoking.current)
      void api("/sessions/" + encodeURIComponent(id), csrf, "DELETE").catch(
        () => {},
      );
    if (mounted.current) setStatus("Disconnected");
  }, [csrf]);
  const connect = useCallback(async () => {
    if (connecting.current || socket.current) return;
    connecting.current = true;
    setError("");
    setStatus("Connecting");
    try {
      const remote = await api<{
        session: { id: string };
        socket_path: string;
      }>("/devices/" + encodeURIComponent(node) + "/sessions", csrf, "POST", {
        kind,
      });
      if (!mounted.current) {
        if (!revoking.current)
          void api(
            "/sessions/" + encodeURIComponent(remote.session.id),
            csrf,
            "DELETE",
          ).catch(() => {});
        return;
      }
      session.current = remote.session.id;
      const ws = new WebSocket(
        (location.protocol === "https:" ? "wss://" : "ws://") +
          location.host +
          remote.socket_path,
      );
      ws.binaryType = "arraybuffer";
      socket.current = ws;
      ws.onmessage = (event) => {
        if (!mounted.current || socket.current !== ws) return;
        if (typeof event.data === "string") {
          try {
            const control = JSON.parse(event.data);
            if (control.event === "connected") {
              if (mounted.current) setStatus("Connected");
              callbacks.current.onReady?.();
              return;
            }
            if (control.ctrlChannel === "102938") {
              if (control.type === "console" && control.msg && mounted.current)
                setError(String(control.msg));
              return;
            }
          } catch {
            /* byte stream */
          }
        }
        callbacks.current.onData(event.data as string | ArrayBuffer);
      };
      ws.onerror = () => {
        if (mounted.current)
          setError("Remote connection failed. Check the agent and retry.");
      };
      ws.onclose = () => {
        if (socket.current !== ws) return;
        socket.current = null;
        session.current = null;
        connecting.current = false;
        // Rust's relay lease already removes the room and closes its peer.
        if (mounted.current) setStatus("Disconnected");
      };
    } catch (e) {
      connecting.current = false;
      if (mounted.current) {
        setError(e instanceof Error ? e.message : "Connection failed.");
        setStatus("Disconnected");
      }
    }
  }, [node, kind, csrf]);
  useEffect(() => {
    mounted.current = true;
    const onRevoke = () => {
      revoking.current = true;
      close();
    };
    window.addEventListener("mcr-auth-revoking", onRevoke);
    return () => {
      window.removeEventListener("mcr-auth-revoking", onRevoke);
      mounted.current = false;
      close();
    };
  }, [close]);
  const send = useCallback((data: string | ArrayBuffer | Uint8Array) => {
    if (socket.current?.readyState !== WebSocket.OPEN) return false;
    if (socket.current.bufferedAmount > 2 * 1024 * 1024) {
      setError("Connection is busy. Retry after the current transfer.");
      return false;
    }
    socket.current.send(data);
    return true;
  }, []);
  return { status, error, setError, connect, close, send };
}
