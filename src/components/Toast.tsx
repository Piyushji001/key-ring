import { useEffect, useState } from "react";
import { Check, ShieldAlert } from "lucide-react";

import { ipc } from "../lib/ipc";
import type { ClipboardStatus } from "../lib/types";

/**
 * Copy confirmation with a live countdown (UI Spec section 4).
 *
 * The countdown is not decoration. A password sitting on the clipboard is a
 * live exposure, and the user should be able to see how long it lasts and end
 * it early. The bar drains so that state is visible without reading.
 */
export function ClipboardToast({
  status,
  onDismiss,
}: {
  status: ClipboardStatus | null;
  onDismiss: () => void;
}) {
  const total = status?.secondsRemaining ?? 0;
  const [remaining, setRemaining] = useState(total);

  useEffect(() => {
    setRemaining(status?.secondsRemaining ?? 0);
  }, [status]);

  useEffect(() => {
    if (!status?.active || remaining <= 0) return undefined;
    const t = window.setTimeout(() => setRemaining((r) => r - 1), 1000);
    return () => window.clearTimeout(t);
  }, [status, remaining]);

  useEffect(() => {
    if (status?.active && remaining <= 0) onDismiss();
  }, [remaining, status, onDismiss]);

  if (!status?.active || remaining <= 0) return null;

  const pct = total > 0 ? (remaining / total) * 100 : 0;

  return (
    <div
      role="status"
      className="fixed bottom-5 left-1/2 -translate-x-1/2 w-[320px] rounded-panel border border-edge bg-panel shadow-2xl overflow-hidden"
    >
      <div className="px-4 py-3 flex items-center gap-3">
        <Check size={16} strokeWidth={2} className="text-ok shrink-0" aria-hidden />
        <div className="flex-1 min-w-0">
          <p className="text-sm text-text">
            {status.field ? `${status.field} copied` : "Copied"}
          </p>
          <p className="text-xs text-text-faint">
            Clipboard clears in {remaining}s
          </p>
        </div>
        <button
          onClick={() => {
            void ipc.clearClipboard();
            onDismiss();
          }}
          className="shrink-0 text-xs text-text-dim hover:text-accent transition-colors duration-100"
        >
          Clear now
        </button>
      </div>

      {!status.excludedFromHistory && (
        <p className="px-4 pb-2 flex items-start gap-2 text-xs text-warn">
          <ShieldAlert size={12} strokeWidth={1.5} className="mt-0.5 shrink-0" />
          Windows would not exclude this from clipboard history.
        </p>
      )}

      <div
        className="h-0.5 bg-accent transition-[width] duration-1000 ease-linear"
        style={{ width: `${pct}%` }}
        aria-hidden
      />
    </div>
  );
}

/** Shared hook so the main window and the overlay behave identically. */
export function useClipboardToast() {
  const [status, setStatus] = useState<ClipboardStatus | null>(null);

  useEffect(() => {
    const unlisten = import("@tauri-apps/api/event").then(({ listen }) =>
      listen("clipboard-cleared", () => setStatus(null)),
    );
    return () => {
      void unlisten.then((f) => f());
    };
  }, []);

  return { status, setStatus, clear: () => setStatus(null) };
}
