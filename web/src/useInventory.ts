import { useCallback, useEffect, useRef, useState } from 'react';
import { ConsoleApiError, fetchSnapshot } from './api';
import type { Snapshot } from './api';

export function useInventory() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const active = useRef<AbortController | null>(null);
  const mounted = useRef(false);

  const refresh = useCallback(async () => {
    if (!mounted.current || active.current) return;
    const controller = new AbortController();
    active.current = controller;
    setLoading(true);
    const timeout = window.setTimeout(() => controller.abort('timeout'), 10_000);
    try {
      const next = await fetchSnapshot(controller.signal);
      if (!mounted.current || controller.signal.aborted) return;
      setSnapshot(next);
      setError(null);
    } catch (error) {
      // Keep the last successful snapshot visible, explicitly marked as stale.
      if (mounted.current && controller.signal.reason !== 'unmount') {
        setError(error instanceof ConsoleApiError
          ? error.message
          : 'Cannot reach the server. Check that it is running, then retry.');
      }
      controller.abort('failed');
    } finally {
      window.clearTimeout(timeout);
      if (active.current === controller) {
        active.current = null;
        if (mounted.current) setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    const interval = window.setInterval(() => void refresh(), 15_000);
    return () => {
      mounted.current = false;
      window.clearInterval(interval);
      active.current?.abort('unmount');
      active.current = null;
    };
  }, [refresh]);

  return { snapshot, error, loading, refresh };
}
