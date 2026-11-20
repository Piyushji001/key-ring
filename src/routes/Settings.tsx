/**
 * Settings — UI Spec 3.6. Plain vertical sections, no tabs.
 *
 * Two rules this screen follows that are worth keeping:
 *
 * 1. **Every value is read from `getSettings` in one call and written one key
 *    at a time.** The backend range-checks each write, so a slider that got
 *    out of step with reality produces an error rather than a silently
 *    rejected value.
 *
 * 2. **Nothing here is optimistic.** A setting shows the value the vault
 *    actually holds. If a write fails, the field snaps back and says why.
 *    Settings that appear to have saved but did not are how people end up
 *    believing they have a backup they do not have.
 */

import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import {
  AlertTriangle,
  Check,
  FolderOpen,
  Loader2,
  RotateCw,
  ShieldCheck,
  Terminal,
} from "lucide-react";

import { ipc, asAppError } from "../lib/ipc";
import type {
  BackupStatus,
  ConnectCapabilities,
  SettingsView,
  SnapshotView,
} from "../lib/types";
import { Button, ErrorNote, Input, Kbd } from "../components/ui";
import { ActivityLog } from "../components/ActivityLog";
import { ImportExport } from "../components/ImportExport";

// ---------------------------------------------------------------- utilities

function relativeTime(unix: number | null): string {
  if (!unix) return "never";
  const secs = Math.floor(Date.now() / 1000) - unix;
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)} minutes ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} hours ago`;
  return `${Math.floor(secs / 86400)} days ago`;
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function Section({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-10">
      <h2 className="text-lg font-medium text-text font-ui">{title}</h2>
      {description && (
        <p className="mt-1 mb-4 text-sm text-text-faint font-ui max-w-prose">
          {description}
        </p>
      )}
      <div className={description ? "space-y-4" : "mt-4 space-y-4"}>
        {children}
      </div>
    </section>
  );
}

function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-6 py-1">
      <div className="min-w-0 flex-1">
        <span className="text-base text-text font-ui">{label}</span>
        {hint && (
          <p className="mt-0.5 text-sm text-text-faint font-ui">{hint}</p>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`h-6 w-11 rounded-full transition-colors duration-100 ${
        checked ? "bg-accent" : "bg-edge"
      }`}
    >
      <span
        className={`block h-5 w-5 rounded-full bg-void transition-transform duration-100 ${
          checked ? "translate-x-[22px]" : "translate-x-[2px]"
        }`}
      />
    </button>
  );
}

function NumberField({
  value,
  onCommit,
  suffix,
  min,
  max,
}: {
  value: number;
  onCommit: (v: number) => void;
  suffix?: string;
  min?: number;
  max?: number;
}) {
  const [draft, setDraft] = useState(String(value));
  useEffect(() => setDraft(String(value)), [value]);

  return (
    <div className="flex items-center gap-2">
      <Input
        type="number"
        min={min}
        max={max}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => {
          const n = Number(draft);
          if (Number.isFinite(n) && n !== value) onCommit(n);
          else setDraft(String(value));
        }}
        className="w-28 h-9 text-right"
      />
      {suffix && (
        <span className="text-sm text-text-faint font-ui w-16">{suffix}</span>
      )}
    </div>
  );
}

function Select({
  value,
  options,
  onChange,
}: {
  value: string;
  options: [string, string][];
  onChange: (v: string) => void;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 px-3 rounded-control bg-panel text-text border border-edge
                 hover:border-edge-strong focus:outline-none focus:border-accent font-ui text-base"
    >
      {options.map(([v, label]) => (
        <option key={v} value={v}>
          {label}
        </option>
      ))}
    </select>
  );
}

// ------------------------------------------------------------------- screen

export function Settings({ onClose }: { onClose: () => void }) {
  const [settings, setSettings] = useState<SettingsView | null>(null);
  const [backup, setBackup] = useState<BackupStatus | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotView[]>([]);
  const [caps, setCaps] = useState<ConnectCapabilities | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [savedKey, setSavedKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, b, snaps, c] = await Promise.all([
        ipc.getSettings(),
        ipc.backupStatus(),
        ipc.listBackups().catch(() => []),
        ipc.connectCapabilities(),
      ]);
      setSettings(s);
      setBackup(b);
      setSnapshots(snaps);
      setCaps(c);
      setError(null);
    } catch (e) {
      setError(asAppError(e).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** Write one setting, then re-read. Never assume the write landed. */
  const put = useCallback(
    async (key: string, value: string | number | boolean) => {
      setError(null);
      const encoded =
        typeof value === "boolean" ? (value ? "1" : "0") : String(value);
      try {
        await ipc.setSetting(key, encoded);
        setSavedKey(key);
        window.setTimeout(() => setSavedKey(null), 1200);
        await refresh();
      } catch (e) {
        setError(asAppError(e).message);
        await refresh();
      }
    },
    [refresh],
  );

  async function chooseBackupFolder() {
    const picked = await open({ directory: true, multiple: false });
    if (typeof picked !== "string") return;
    setBusy(true);
    try {
      await ipc.setBackupDir(picked);
      await refresh();
    } catch (e) {
      setError(asAppError(e).message);
    } finally {
      setBusy(false);
    }
  }

  async function backupNow() {
    setBusy(true);
    setError(null);
    try {
      await ipc.backupNow();
      await refresh();
    } catch (e) {
      setError(asAppError(e).message);
    } finally {
      setBusy(false);
    }
  }

  if (!settings) {
    return (
      <div className="flex items-center justify-center h-full text-text-faint">
        <Loader2 size={18} className="animate-spin" />
      </div>
    );
  }

  const s = settings;

  return (
    <div className="h-full overflow-y-auto">
      <div className="max-w-2xl mx-auto px-8 py-8">
        <header className="flex items-center justify-between mb-8">
          <h1 className="text-2xl font-medium text-text font-ui">Settings</h1>
          <Button variant="ghost" onClick={onClose}>
            Done
          </Button>
        </header>

        {error && <ErrorNote>{error}</ErrorNote>}
        {savedKey && (
          <p className="mb-4 text-sm text-accent font-ui flex items-center gap-1.5">
            <Check size={14} strokeWidth={2} /> Saved
          </p>
        )}

        {/* ---------------------------------------------------- Security */}
        <Section
          title="Security"
          description="These are the settings that decide how long a secret is reachable. Shorter is safer and more annoying; that trade is yours to make."
        >
          <Row
            label="Lock after idle"
            hint="Between 1 and 120 minutes."
          >
            <NumberField
              value={Math.round(s.idleLockSecs / 60)}
              min={1}
              max={120}
              suffix="minutes"
              onCommit={(v) => put("idle_lock_secs", Math.round(v * 60))}
            />
          </Row>

          <Row label="Lock when the computer sleeps">
            <Toggle
              label="Lock on sleep"
              checked={s.lockOnSleep}
              onChange={(v) => put("lock_on_sleep", v)}
            />
          </Row>

          <Row label="Lock on Win+L">
            <Toggle
              label="Lock on workstation lock"
              checked={s.lockOnWorkstationLock}
              onChange={(v) => put("lock_on_workstation_lock", v)}
            />
          </Row>

          <Row
            label="Clear the clipboard after"
            hint="Only cleared if the clipboard still holds what Keyring put there."
          >
            <NumberField
              value={s.clipboardClearSecs}
              min={5}
              max={600}
              suffix="seconds"
              onCommit={(v) => put("clipboard_clear_secs", v)}
            />
          </Row>

          <Row
            label="Delete extracted files after"
            hint="Keys and attachments written to disk are zeroed and unlinked. That removes easy recovery, not forensic recovery."
          >
            <NumberField
              value={s.tempfileTtlSecs}
              min={15}
              max={3600}
              suffix="seconds"
              onCommit={(v) => put("tempfile_ttl_secs", v)}
            />
          </Row>

          <Row label="Keep field history versions">
            <NumberField
              value={s.historyLimit}
              min={0}
              max={100}
              suffix="versions"
              onCommit={(v) => put("history_limit", v)}
            />
          </Row>

          <Row label="Keep trashed records for">
            <NumberField
              value={s.trashRetentionDays}
              min={1}
              max={365}
              suffix="days"
              onCommit={(v) => put("trash_retention_days", v)}
            />
          </Row>

          <Row
            label="Record activity in this vault"
            hint="What happened and when. Never field values."
          >
            <Toggle
              label="Activity log"
              checked={s.activityLogEnabled}
              onChange={(v) => put("activity_log_enabled", v)}
            />
          </Row>

          <div className="pt-2 text-sm text-text-faint font-ui">
            Unlocking uses Argon2id at {s.kdfMemoryKib / 1024} MiB,{" "}
            {s.kdfIterations} iterations, {s.kdfParallelism} lanes. Changing
            these re-derives the key and rewrites the vault, so it is offered
            from the vault menu rather than as a slider here.
          </div>
        </Section>

        {/* ------------------------------------------------------ Backup */}
        <Section
          title="Backup"
          description="A backup is the whole vault folder — the container and its attachment blobs. Restoring is a folder copy, with nothing to merge and nothing to get wrong."
        >
          {!backup?.backupDir && (
            <div className="rounded-panel border border-danger/60 bg-danger/[0.07] p-4">
              <p className="flex items-start gap-2 text-sm text-text leading-relaxed">
                <AlertTriangle
                  size={16}
                  className="text-danger shrink-0 mt-0.5"
                />
                <span>
                  <strong>No backup folder is set.</strong> If this disk fails
                  right now, every credential in this vault is gone. Point this
                  at a folder your cloud sync already watches.
                </span>
              </p>
              <Button className="mt-3" onClick={chooseBackupFolder} disabled={busy}>
                Choose a folder
              </Button>
            </div>
          )}

          {backup?.backupDir && (
            <>
              <Row label="Backup folder">
                <Button variant="ghost" onClick={chooseBackupFolder}>
                  <FolderOpen size={14} className="inline mr-1.5" />
                  Change
                </Button>
              </Row>
              <p className="-mt-2 text-sm text-text-faint font-data break-all">
                {backup.backupDir}
              </p>

              <Row
                label="Back up automatically"
                hint="After a change, debounced by a minute."
              >
                <Toggle
                  label="Automatic backup"
                  checked={backup.automatic}
                  onChange={async (v) => {
                    await ipc.setBackupAutomatic(v);
                    await refresh();
                  }}
                />
              </Row>

              <Row label="Versions to keep">
                <NumberField
                  value={backup.retention}
                  min={1}
                  max={100}
                  suffix="versions"
                  onCommit={async (v) => {
                    try {
                      await ipc.setBackupRetention(v);
                      await refresh();
                    } catch (e) {
                      setError(asAppError(e).message);
                    }
                  }}
                />
              </Row>

              <Row
                label="Last backup"
                hint={
                  backup.lastError
                    ? `Last attempt failed: ${backup.lastError}`
                    : `${snapshots.length} version${
                        snapshots.length === 1 ? "" : "s"
                      } stored`
                }
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`text-sm font-ui ${
                      backup.lastError ? "text-danger" : "text-text-dim"
                    }`}
                  >
                    {relativeTime(backup.lastBackupAt)}
                  </span>
                  <Button onClick={backupNow} disabled={busy}>
                    {busy ? (
                      <Loader2 size={14} className="animate-spin" />
                    ) : (
                      "Back up now"
                    )}
                  </Button>
                </div>
              </Row>

              {snapshots.length > 0 && (
                <div className="mt-2 rounded-panel border border-edge divide-y divide-edge">
                  {snapshots.slice(0, 5).map((snap) => (
                    <div
                      key={snap.path}
                      className="flex items-center justify-between px-3 py-2 text-sm"
                    >
                      <span className="font-data text-text-dim truncate">
                        {snap.name}
                      </span>
                      <span className="text-text-faint font-ui shrink-0 ml-4">
                        {bytes(snap.sizeBytes)} · {relativeTime(snap.createdAt)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </Section>

        {/* ----------------------------------------------------- Connect */}
        <Section
          title="Connect"
          description="One-click sessions open a terminal that is already authenticated. Credentials go into the child process environment, never onto a command line."
        >
          <Row label="Terminal">
            <Select
              value={s.terminalPreference}
              onChange={(v) => put("terminal_preference", v)}
              options={[
                ["auto", "Windows Terminal, then PowerShell"],
                ["windows_terminal", "Windows Terminal"],
                ["powershell", "PowerShell"],
                ["cmd", "Command Prompt"],
              ]}
            />
          </Row>

          <Row
            label="Hand SSH passwords to ssh automatically"
            hint="Uses a single-use pipe and the SSH_ASKPASS helper. Turn this off and ssh will prompt you instead."
          >
            <Toggle
              label="SSH password handoff"
              checked={s.sshAskpassEnabled}
              onChange={(v) => put("ssh_askpass_enabled", v)}
            />
          </Row>

          <Row
            label="Cloud shell credentials expire after"
            hint="Temporary config files are destroyed at this deadline, on lock, and on exit."
          >
            <NumberField
              value={Math.round(s.cloudShellTtlSecs / 60)}
              min={1}
              max={720}
              suffix="minutes"
              onCommit={(v) => put("cloud_shell_ttl_secs", Math.round(v * 60))}
            />
          </Row>

          {caps && caps.notes.length > 0 && (
            <div className="rounded-panel border border-edge bg-panel/50 p-3 space-y-1.5">
              {caps.notes.map((note, i) => (
                <p
                  key={i}
                  className="flex items-start gap-2 text-sm text-text-dim font-ui"
                >
                  <Terminal size={14} className="shrink-0 mt-0.5 text-text-faint" />
                  {note}
                </p>
              ))}
            </div>
          )}
        </Section>

        {/* --------------------------------------------------- Shortcuts */}
        <Section title="Shortcuts">
          <Row label="Global hotkey" hint="Opens the overlay from anywhere.">
            <HotkeyCapture
              current={s.hotkey}
              onCapture={async (accel) => {
                try {
                  await ipc.applyHotkey(accel);
                  await refresh();
                } catch (e) {
                  setError(asAppError(e).message);
                }
              }}
            />
          </Row>

          <div className="pt-2 space-y-1.5 text-sm text-text-faint font-ui">
            <p>
              <Kbd>Ctrl</Kbd> <Kbd>L</Kbd> lock now
            </p>
            <p>
              <Kbd>Ctrl</Kbd> <Kbd>F</Kbd> search
            </p>
            <p>
              <Kbd>Ctrl</Kbd> <Kbd>N</Kbd> new record
            </p>
            <p>
              <Kbd>Esc</Kbd> dismiss the overlay
            </p>
          </div>
        </Section>

        {/* -------------------------------------------------- Appearance */}
        <Section title="Appearance">
          <Row label="Theme">
            <Select
              value={s.theme}
              onChange={(v) => {
                document.documentElement.dataset.theme =
                  v === "system"
                    ? window.matchMedia("(prefers-color-scheme: light)").matches
                      ? "light"
                      : "dark"
                    : v;
                void put("theme", v);
              }}
              options={[
                ["dark", "Dark"],
                ["light", "Light"],
                ["system", "Follow system"],
              ]}
            />
          </Row>

          <Row label="Font size">
            <Select
              value={s.fontScale}
              onChange={(v) => {
                document.documentElement.dataset.fontScale = v;
                void put("font_scale", v);
              }}
              options={[
                ["small", "Small"],
                ["medium", "Medium"],
                ["large", "Large"],
              ]}
            />
          </Row>

          <Row
            label="Start minimised to the tray"
            hint="Keyring still starts locked. Minimised is not unlocked."
          >
            <Toggle
              label="Start minimised"
              checked={s.startMinimized}
              onChange={(v) => put("start_minimized", v)}
            />
          </Row>

          <Row label="Closing the window keeps Keyring in the tray">
            <Toggle
              label="Close to tray"
              checked={s.closeToTray}
              onChange={(v) => put("close_to_tray", v)}
            />
          </Row>
        </Section>

        {/* ------------------------------------------------------- Vault */}
        <Section title="Vault">
          <Row label="Records">
            <span className="text-sm text-text-dim font-data">
              {s.recordCount}
            </span>
          </Row>
          <Row label="Format version">
            <span className="text-sm text-text-dim font-data">
              {s.formatVersion}
            </span>
          </Row>
          <Row label="Warn before certificates expire">
            <NumberField
              value={s.certExpiryWarnDays}
              min={1}
              max={365}
              suffix="days"
              onCommit={(v) => put("cert_expiry_warn_days", v)}
            />
          </Row>
          {s.vaultPath && (
            <p className="text-sm text-text-faint font-data break-all">
              {s.vaultPath}
            </p>
          )}

          <ImportExport onChanged={refresh} />
        </Section>

        {/* ---------------------------------------------------- Activity */}
        <Section
          title="Activity"
          description="Stored inside the encrypted vault. Records what happened, never what the value was."
        >
          <ActivityLog />
        </Section>

        {/* ------------------------------------------------------- About */}
        <Section title="About">
          <p className="text-sm text-text-dim font-ui leading-relaxed">
            Keyring stores credentials in a single encrypted file on this
            computer. It has no networking code in its dependency tree.
          </p>
          <div className="rounded-panel border border-edge bg-panel/50 p-4">
            <p className="flex items-center gap-2 text-base text-text font-ui mb-2">
              <ShieldCheck size={16} className="text-accent" />
              Verify that for yourself
            </p>
            <ol className="text-sm text-text-dim font-ui space-y-1 list-decimal ml-5 leading-relaxed">
              <li>Open Resource Monitor and go to the Network tab.</li>
              <li>
                Find <span className="font-data">keyring-app.exe</span> in the
                process list.
              </li>
              <li>
                Use Keyring normally. The TCP Connections list should stay empty
                for it.
              </li>
            </ol>
            <p className="mt-3 text-sm text-text-faint font-ui leading-relaxed">
              Do not take our word for it, and do not take a checkbox in this
              window for it either. This one you can check yourself in a minute.
            </p>
          </div>
        </Section>
      </div>
    </div>
  );
}

/**
 * Captures a real key combination rather than asking the user to type
 * "CmdOrCtrl+Shift+Space" correctly.
 */
function HotkeyCapture({
  current,
  onCapture,
}: {
  current: string;
  onCapture: (accelerator: string) => void;
}) {
  const [capturing, setCapturing] = useState(false);

  useEffect(() => {
    if (!capturing) return;

    function onKey(e: KeyboardEvent) {
      e.preventDefault();
      // Modifiers alone are not a shortcut.
      if (["Control", "Shift", "Alt", "Meta"].includes(e.key)) return;

      const parts: string[] = [];
      if (e.ctrlKey) parts.push("CmdOrCtrl");
      if (e.shiftKey) parts.push("Shift");
      if (e.altKey) parts.push("Alt");

      if (parts.length === 0) {
        // A bare key would swallow that key everywhere in Windows.
        return;
      }

      const key = e.key === " " ? "Space" : e.key.toUpperCase();
      parts.push(key.length === 1 ? key : e.code.replace(/^Key|^Digit/, ""));

      setCapturing(false);
      onCapture(parts.join("+"));
    }

    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [capturing, onCapture]);

  return (
    <Button
      variant={capturing ? "primary" : "ghost"}
      onClick={() => setCapturing((c) => !c)}
      className="font-data"
    >
      {capturing ? (
        <>
          <RotateCw size={13} className="inline mr-1.5 animate-spin" />
          Press keys…
        </>
      ) : (
        current
      )}
    </Button>
  );
}
