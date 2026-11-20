import { getCurrentWindow } from "@tauri-apps/api/window";
import { Lock, Minus, Sparkles, Square, X } from "lucide-react";

import { Kbd } from "./ui";

/**
 * Window chrome is disabled in tauri.conf.json, so we draw it. The lock button
 * lives here because locking must be reachable from every screen without
 * thinking - it is the one control a user reaches for in a hurry.
 */
export function TitleBar({
  locked,
  readOnly,
  copilotOpen,
  onToggleCopilot,
  onLock,
}: {
  locked: boolean;
  readOnly: boolean;
  copilotOpen?: boolean;
  onToggleCopilot?: () => void;
  onLock: () => void;
}) {
  const win = getCurrentWindow();

  return (
    <header
      data-tauri-drag-region
      className="h-10 shrink-0 flex items-center gap-3 pl-4 pr-0 bg-panel border-b border-edge select-none"
    >
      <span
        className={`h-2 w-2 rounded-full transition-colors duration-100 ${
          locked ? "bg-text-faint" : "bg-accent"
        }`}
        aria-hidden
      />
      <span className="text-sm font-medium text-text">Keyring</span>

      {readOnly && (
        <span className="px-2 py-0.5 rounded-tag bg-panel-hi border border-edge text-xs text-text-dim">
          Read-only
        </span>
      )}

      <div className="flex-1" />

      {!locked && onToggleCopilot && (
        <button
          onClick={onToggleCopilot}
          title="Toggle Keyring Copilot (Ctrl+J)"
          className={`h-7 px-2.5 flex items-center gap-1.5 rounded-control text-xs font-medium transition-colors duration-100 ${
            copilotOpen
              ? "bg-accent/20 text-accent border border-accent/40"
              : "text-text-dim hover:text-text hover:bg-panel-hi"
          }`}
        >
          <Sparkles size={13} className={copilotOpen ? "text-accent animate-pulse" : "text-accent"} />
          <span>Copilot</span>
          <Kbd>Ctrl J</Kbd>
        </button>
      )}

      {!locked && (
        <button
          onClick={onLock}
          title="Lock the vault"
          className="h-7 px-2.5 flex items-center gap-2 rounded-control text-text-dim hover:text-text hover:bg-panel-hi transition-colors duration-100"
        >
          <Lock size={14} strokeWidth={1.5} />
          <span className="text-sm">Lock</span>
          <Kbd>Ctrl L</Kbd>
        </button>
      )}

      <div className="flex h-full">
        <WindowButton onClick={() => void win.minimize()} label="Minimise">
          <Minus size={14} strokeWidth={1.5} />
        </WindowButton>
        <WindowButton onClick={() => void win.toggleMaximize()} label="Maximise">
          <Square size={12} strokeWidth={1.5} />
        </WindowButton>
        <WindowButton onClick={() => void win.close()} label="Close" danger>
          <X size={15} strokeWidth={1.5} />
        </WindowButton>
      </div>
    </header>
  );
}

function WindowButton({
  children,
  onClick,
  label,
  danger = false,
}: {
  children: React.ReactNode;
  onClick: () => void;
  label: string;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      aria-label={label}
      className={`w-11 h-full grid place-items-center text-text-dim transition-colors duration-100 ${
        danger ? "hover:bg-danger hover:text-white" : "hover:bg-panel-hi hover:text-text"
      }`}
    >
      {children}
    </button>
  );
}
