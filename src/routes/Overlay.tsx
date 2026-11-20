import { useCallback, useEffect, useRef, useState } from "react";
import { emit, listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { CornerDownLeft, Search } from "lucide-react";

import { ClipboardToast, useClipboardToast } from "../components/Toast";
import { Kbd } from "../components/ui";
import { asAppError, ipc } from "../lib/ipc";
import { iconFor } from "../lib/recordTypes";
import type { SearchHit } from "../lib/types";

/**
 * The global hotkey overlay (UC-01, UI Spec section 3).
 *
 * The whole product is judged here: hotkey to clipboard in under two seconds
 * with no mouse. Everything on this screen is subordinate to that.
 *
 * Keyboard contract:
 *   Enter        copy the primary secret and dismiss
 *   Ctrl+Enter   copy the username instead
 *   Shift+Enter  open the record in the main window
 *   Up / Down    move the selection
 *   Escape       dismiss
 */
const MAX_RESULTS = 8;

export function Overlay() {
  const [locked, setLocked] = useState(true);
  const [password, setPassword] = useState("");
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [cursor, setCursor] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [vaultPath, setVaultPath] = useState<string | null>(null);
  const toast = useClipboardToast();
  const input = useRef<HTMLInputElement>(null);

  const refreshLockState = useCallback(async () => {
    try {
      const status = await ipc.vaultStatus();
      setLocked(status.locked);
      if (status.locked) setVaultPath(await ipc.lastVault());
    } catch {
      setLocked(true);
    }
  }, []);

  // Reset on every appearance. The overlay must never show the previous
  // query's results, both because it is confusing and because those results
  // describe a vault that may since have locked.
  useEffect(() => {
    const unlisten = listen("overlay-shown", () => {
      setQuery("");
      setHits([]);
      setCursor(0);
      setError(null);
      setPassword("");
      void refreshLockState();
      window.setTimeout(() => input.current?.focus(), 30);
    });
    void refreshLockState();
    return () => {
      void unlisten.then((f) => f());
    };
  }, [refreshLockState]);

  // FR-4.3 gives the backend 50 ms, so there is no debounce here at all -
  // every keystroke searches. Debouncing would add latency to the one
  // interaction that is not allowed to feel slow.
  useEffect(() => {
    if (locked) return;
    if (query.trim() === "") {
      setHits([]);
      setCursor(0);
      return;
    }
    let cancelled = false;
    ipc
      .search(query, MAX_RESULTS)
      .then((results) => {
        if (cancelled) return;
        setHits(results);
        setCursor(0);
      })
      .catch((e) => setError(asAppError(e).message));
    return () => {
      cancelled = true;
    };
  }, [query, locked]);

  function dismiss() {
    void emit("overlay-dismiss");
    void getCurrentWindow().hide();
  }

  async function unlock() {
    if (!vaultPath || password.length === 0) return;
    setBusy(true);
    try {
      await ipc.openVault(vaultPath, password);
      setPassword("");
      setLocked(false);
      setError(null);
      window.setTimeout(() => input.current?.focus(), 30);
    } catch (e) {
      setError(asAppError(e).message);
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  async function act(hit: SearchHit, mode: "primary" | "username" | "open") {
    try {
      if (mode === "open") {
        void emit("overlay-open-main", hit.recordId);
        return;
      }
      const status =
        mode === "username"
          ? await ipc.copyUsername(hit.recordId)
          : await ipc.copyPrimary(hit.recordId);
      toast.setStatus({ ...status, field: status.field ?? hit.title });
      dismiss();
    } catch (e) {
      setError(asAppError(e).message);
    }
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Escape") {
      e.preventDefault();
      dismiss();
      return;
    }
    if (locked) {
      if (e.key === "Enter") {
        e.preventDefault();
        void unlock();
      }
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => Math.min(c + 1, hits.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const hit = hits[cursor];
      if (!hit) return;
      if (e.shiftKey) void act(hit, "open");
      else if (e.ctrlKey) void act(hit, "username");
      else void act(hit, "primary");
    }
  }

  return (
    <div className="h-full p-2" onKeyDown={onKeyDown}>
      <div className="h-full flex flex-col rounded-overlay border border-edge-strong bg-panel/95 backdrop-blur-md shadow-2xl overflow-hidden">
        <div className="flex items-center gap-3 px-4 h-14 border-b border-edge">
          <Search size={18} strokeWidth={1.5} className="text-text-faint shrink-0" />
          <input
            ref={input}
            autoFocus
            type={locked ? "password" : "text"}
            value={locked ? password : query}
            onChange={(e) =>
              locked ? setPassword(e.target.value) : setQuery(e.target.value)
            }
            placeholder={locked ? "Master password" : "Search credentials"}
            aria-label={locked ? "Master password" : "Search credentials"}
            spellCheck={false}
            autoComplete="off"
            className="flex-1 bg-transparent text-lg text-text placeholder:text-text-faint focus:outline-none font-data"
          />
          {busy && <span className="text-xs text-text-faint">Unlocking…</span>}
        </div>

        <div className="flex-1 overflow-y-auto">
          {locked ? (
            <div className="p-4">
              <p className="text-sm text-text-dim">
                {vaultPath
                  ? "The vault is locked. Enter your master password."
                  : "No vault selected. Open the main window first."}
              </p>
              {vaultPath && (
                <p className="mt-2 text-xs text-text-faint font-data truncate">
                  {vaultPath}
                </p>
              )}
            </div>
          ) : hits.length === 0 ? (
            <p className="p-4 text-sm text-text-faint">
              {query.trim() === ""
                ? "Type to search. Prefix with type:, folder: or tag: to narrow."
                : "Nothing matches that."}
            </p>
          ) : (
            hits.map((hit, i) => {
              const Icon = iconFor(hit.recordType);
              const active = i === cursor;
              return (
                <button
                  key={hit.recordId}
                  onMouseEnter={() => setCursor(i)}
                  onClick={() => void act(hit, "primary")}
                  className={`w-full px-4 py-2.5 flex items-center gap-3 text-left border-l-2 transition-colors duration-75 ${
                    active
                      ? "bg-panel-hi border-accent"
                      : "border-transparent hover:bg-panel-hi/50"
                  }`}
                >
                  <Icon
                    size={16}
                    strokeWidth={1.5}
                    className={active ? "text-accent" : "text-text-faint"}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-base text-text">{hit.title}</span>
                    <span className="block truncate text-xs text-text-dim font-data">
                      {hit.matchedField && hit.matchedContext
                        ? `${hit.matchedField}: ${hit.matchedContext}`
                        : hit.folder || hit.typeLabel}
                    </span>
                  </span>
                  {active && (
                    <CornerDownLeft size={14} className="text-accent shrink-0" aria-hidden />
                  )}
                </button>
              );
            })
          )}
        </div>

        {error && (
          <p className="px-4 py-2 text-sm text-danger border-t border-edge">{error}</p>
        )}

        <footer className="h-9 px-4 shrink-0 flex items-center gap-3 border-t border-edge text-xs text-text-faint">
          {locked ? (
            <>
              <Kbd>Enter</Kbd> <span>unlock</span>
            </>
          ) : (
            <>
              <Kbd>↑↓</Kbd> <span>move</span>
              <Kbd>Enter</Kbd> <span>copy</span>
              <Kbd>Ctrl Enter</Kbd> <span>username</span>
              <Kbd>Shift Enter</Kbd> <span>open</span>
            </>
          )}
          <span className="flex-1" />
          <Kbd>Esc</Kbd>
        </footer>
      </div>

      <ClipboardToast status={toast.status} onDismiss={toast.clear} />
    </div>
  );
}
