import { useCallback, useEffect, useState } from "react";
import { Copy, RefreshCw } from "lucide-react";

import { asAppError, ipc } from "../lib/ipc";
import type { ClipboardStatus, TotpCode } from "../lib/types";

/**
 * The TOTP code with its countdown ring (UI Spec section 4).
 *
 * The ring is not ornament. A six-digit code is useless information without
 * knowing whether you have twenty-five seconds to type it or two, and reading
 * a number is slower than seeing an arc.
 *
 * The code is refetched when the window expires rather than computed here,
 * because the seed lives in Rust and is going to stay there.
 */
export function TotpField({
  recordId,
  onCopied,
}: {
  recordId: string;
  onCopied?: (status: ClipboardStatus) => void;
}) {
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [remaining, setRemaining] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const result = await ipc.totpCode(recordId);
      setTotp(result);
      setRemaining(result.secondsRemaining);
      setError(null);
    } catch (e) {
      setError(asAppError(e).message);
      setTotp(null);
    }
  }, [recordId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!totp) return undefined;
    if (remaining <= 0) {
      void refresh();
      return undefined;
    }
    const t = window.setTimeout(() => setRemaining((r) => r - 1), 1000);
    return () => window.clearTimeout(t);
  }, [remaining, totp, refresh]);

  if (error) {
    return (
      <div className="py-2 border-b border-edge/60">
        <div className="flex items-baseline gap-3">
          <span className="w-32 shrink-0 text-sm text-text-dim">One-time code</span>
          <span className="flex-1 text-sm text-danger">{error}</span>
        </div>
      </div>
    );
  }

  if (!totp) return null;

  // A 30-second period is the norm, but the record may say otherwise.
  const period = Math.max(remaining, 1);
  const fraction = remaining / Math.max(totp.secondsRemaining || period, period);
  const circumference = 2 * Math.PI * 9;
  const urgent = remaining <= 5;

  // Group as 3+3 or 4+4: humans transcribe digits in chunks.
  const half = Math.ceil(totp.code.length / 2);
  const grouped = `${totp.code.slice(0, half)} ${totp.code.slice(half)}`;

  return (
    <div className="group py-2 border-b border-edge/60">
      <div className="flex items-center gap-3">
        <span className="w-32 shrink-0 text-sm text-text-dim">One-time code</span>

        <span
          className={`font-data text-lg tracking-[0.2em] tabular-nums ${
            urgent ? "text-danger" : "text-accent"
          }`}
          data-selectable
        >
          {grouped}
        </span>

        <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden className="shrink-0">
          <circle cx="11" cy="11" r="9" fill="none" strokeWidth="2" className="stroke-edge" />
          <circle
            cx="11"
            cy="11"
            r="9"
            fill="none"
            strokeWidth="2"
            strokeLinecap="round"
            transform="rotate(-90 11 11)"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - Math.min(Math.max(fraction, 0), 1))}
            className={urgent ? "stroke-danger" : "stroke-accent"}
          />
        </svg>
        <span
          className={`w-6 text-xs tabular-nums ${urgent ? "text-danger" : "text-text-faint"}`}
        >
          {remaining}s
        </span>

        <span className="flex-1" />

        <span className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity duration-100">
          <button
            onClick={() => void refresh()}
            aria-label="Refresh code"
            className="h-7 w-7 grid place-items-center rounded-control text-text-dim hover:text-accent hover:bg-panel-hi"
          >
            <RefreshCw size={14} strokeWidth={1.5} />
          </button>
          <button
            onClick={async () => {
              try {
                await ipc.copyTotp(recordId);
                onCopied?.({
                  active: true,
                  field: "One-time code",
                  secondsRemaining: 30,
                  excludedFromHistory: true,
                });
              } catch (e) {
                setError(asAppError(e).message);
              }
            }}
            aria-label="Copy code"
            className="h-7 w-7 grid place-items-center rounded-control text-text-dim hover:text-accent hover:bg-panel-hi"
          >
            <Copy size={14} strokeWidth={1.5} />
          </button>
        </span>
      </div>
    </div>
  );
}
