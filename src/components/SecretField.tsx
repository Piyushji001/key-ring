import { useEffect, useState } from "react";
import { Copy, Eye, EyeOff } from "lucide-react";

import { asAppError, ipc } from "../lib/ipc";
import type { ClipboardStatus, FieldView } from "../lib/types";

/**
 * One field row.
 *
 * Masking is always twelve dots regardless of the real length, because the
 * length of a password is information an onlooker should not get for free.
 *
 * Reveal is the deliberate action, not the default. It calls the one command
 * that returns plaintext, holds the value in local state for fifteen seconds,
 * and then drops it. Copy will move into Rust entirely in Phase 5, at which
 * point the clipboard path stops touching JavaScript at all.
 */
export function FieldRow({
  recordId,
  field,
  readOnly,
  onEdit,
  onCopied,
}: {
  recordId: string;
  field: FieldView;
  readOnly: boolean;
  onEdit: (name: string, value: string) => void;
  onCopied?: (status: ClipboardStatus) => void;
}) {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [countdown, setCountdown] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");

  // Drop the plaintext when the countdown ends. This effect is the only thing
  // standing between a reveal and a secret sitting in memory until navigation.
  useEffect(() => {
    if (countdown <= 0) {
      setRevealed(null);
      return undefined;
    }
    const t = window.setTimeout(() => setCountdown((c) => c - 1), 1000);
    return () => window.clearTimeout(t);
  }, [countdown]);

  async function reveal() {
    if (revealed) {
      setRevealed(null);
      setCountdown(0);
      return;
    }
    try {
      const result = await ipc.revealField(recordId, field.name);
      setRevealed(result.value);
      setCountdown(Math.round(result.expiresInMs / 1000));
      setError(null);
    } catch (e) {
      setError(asAppError(e).message);
    }
  }

  async function copy() {
    // Decryption, the clipboard write and the exclusion formats all happen in
    // Rust. No plaintext enters this file. Compare with `reveal` above, which
    // is the one place it must.
    try {
      const status = await ipc.copyField(recordId, field.name);
      onCopied?.({ ...status, field: field.label });
      setError(null);
    } catch (e) {
      setError(asAppError(e).message);
    }
  }

  const displayValue = field.isSecret
    ? (revealed ?? "••••••••••••")
    : (field.value ?? "");

  return (
    <div className="group py-2 border-b border-edge/60 last:border-0">
      <div className="flex items-baseline gap-3">
        <span className="w-32 shrink-0 text-sm text-text-dim">{field.label}</span>

        {editing ? (
          <input
            autoFocus
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onBlur={() => {
              setEditing(false);
              if (draft !== (field.value ?? "")) onEdit(field.name, draft);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") e.currentTarget.blur();
              if (e.key === "Escape") setEditing(false);
            }}
            className="flex-1 h-7 px-2 rounded-control bg-panel border border-accent font-data text-sm text-text focus:outline-none"
          />
        ) : (
          <button
            disabled={readOnly}
            onClick={() => {
              setDraft(field.isSecret ? "" : (field.value ?? ""));
              setEditing(true);
            }}
            className="flex-1 min-w-0 text-left font-data text-sm text-text truncate disabled:cursor-default"
            title={field.isSecret ? "Click to replace" : "Click to edit"}
            data-selectable
          >
            {field.hasValue ? (
              <span className={revealed ? "text-accent" : ""}>{displayValue}</span>
            ) : (
              <span className="text-text-faint italic">empty</span>
            )}
          </button>
        )}

        <span className="shrink-0 flex items-center gap-1 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity duration-100">
          {field.isSecret && field.hasValue && (
            <IconButton onClick={() => void reveal()} label={revealed ? "Hide" : "Reveal"}>
              {revealed ? <EyeOff size={14} strokeWidth={1.5} /> : <Eye size={14} strokeWidth={1.5} />}
            </IconButton>
          )}
          {field.hasValue && (
            <IconButton onClick={() => void copy()} label="Copy">
              <Copy size={14} strokeWidth={1.5} />
            </IconButton>
          )}
        </span>
      </div>

      {countdown > 0 && (
        <p className="mt-1 ml-[8.75rem] text-xs text-text-faint">
          Hiding in {countdown}s
        </p>
      )}
      {error && <p className="mt-1 ml-[8.75rem] text-xs text-danger">{error}</p>}
      {field.historyCount > 0 && (
        <p className="mt-1 ml-[8.75rem] text-xs text-text-faint">
          {field.historyCount} previous {field.historyCount === 1 ? "value" : "values"}
        </p>
      )}
    </div>
  );
}

function IconButton({
  children,
  onClick,
  label,
}: {
  children: React.ReactNode;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      aria-label={label}
      title={label}
      className="h-7 w-7 grid place-items-center rounded-control text-text-dim hover:text-accent hover:bg-panel-hi transition-colors duration-100"
    >
      {children}
    </button>
  );
}
