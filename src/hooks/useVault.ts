import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import { asAppError, ipc } from "../lib/ipc";
import { LOCKED_STATUS, type AppError, type VaultStatus } from "../lib/types";

/**
 * Owns lock state for the whole application.
 *
 * The `data-locked` attribute on <html> is set here and nowhere else. Every
 * colour in the app derives from it via CSS variables, so warming the interface
 * is one attribute write rather than a re-render of the tree.
 */
export function useVault() {
  const [status, setStatus] = useState<VaultStatus>(LOCKED_STATUS);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AppError | null>(null);

  // Reflect lock state into the document, and run the 400 ms warming when the
  // vault opens.
  useEffect(() => {
    const root = document.documentElement;
    const wasLocked = root.dataset.locked === "true";

    if (!status.locked && wasLocked) {
      root.classList.add("kr-warming");
      root.dataset.locked = "false";
      const t = window.setTimeout(() => root.classList.remove("kr-warming"), 450);
      return () => window.clearTimeout(t);
    }

    root.dataset.locked = status.locked ? "true" : "false";
    return undefined;
  }, [status.locked]);

  useEffect(() => {
    ipc.vaultStatus().then(setStatus).catch(() => setStatus(LOCKED_STATUS));

    const unlisten = listen("vault-locked", () => setStatus(LOCKED_STATUS));
    return () => {
      void unlisten.then((f) => f());
    };
  }, []);

  const run = useCallback(
    async (fn: () => Promise<VaultStatus>) => {
      setBusy(true);
      setError(null);
      try {
        setStatus(await fn());
        return true;
      } catch (e) {
        setError(asAppError(e));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  const unlock = useCallback(
    (path: string, password: string) => run(() => ipc.openVault(path, password)),
    [run],
  );

  const unlockReadOnly = useCallback(
    (path: string, password: string) =>
      run(() => ipc.openVaultReadOnly(path, password)),
    [run],
  );

  const create = useCallback(
    (path: string, password: string, targetMs: number) =>
      run(() => ipc.createVault(path, password, targetMs)),
    [run],
  );

  const lock = useCallback(async () => {
    try {
      setStatus(await ipc.lockVault());
    } catch {
      setStatus(LOCKED_STATUS);
    }
  }, []);

  return {
    status,
    busy,
    error,
    clearError: () => setError(null),
    unlock,
    unlockReadOnly,
    create,
    lock,
  };
}
