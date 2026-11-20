import { useEffect, useRef, useState } from "react";
import { open as openFolder } from "@tauri-apps/plugin-dialog";
import { KeyRound } from "lucide-react";

import { Button, ErrorNote, Input } from "../components/ui";
import { ipc } from "../lib/ipc";
import type { AppError } from "../lib/types";

/**
 * The coldest screen in the product. Centred, nothing else on it.
 *
 * The failure message is always "Could not unlock this vault." It never says
 * whether the password was wrong or the file was damaged, because telling the
 * difference is a decryption oracle. The backend enforces this too - this is
 * belt and braces.
 */
export function Unlock({
  vaultPath,
  busy,
  error,
  onUnlock,
  onUnlockReadOnly,
  onChooseVault,
  onCreateNew,
}: {
  vaultPath: string | null;
  busy: boolean;
  error: AppError | null;
  onUnlock: (path: string, password: string) => Promise<boolean>;
  onUnlockReadOnly: (path: string, password: string) => Promise<boolean>;
  onChooseVault: (path: string) => void;
  onCreateNew: () => void;
}) {
  const [password, setPassword] = useState("");
  const [shake, setShake] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [cooldown, setCooldown] = useState(0);
  const [lastKnown, setLastKnown] = useState<string | null>(null);
  const field = useRef<HTMLInputElement>(null);

  useEffect(() => {
    field.current?.focus();
  }, []);

  // Without this the screen came up blank after a lock, and browsing to the
  // wrong folder reported "Could not unlock this vault" - which is not what had
  // happened. The path is remembered on disk; the password never is.
  useEffect(() => {
    if (vaultPath) return;
    ipc.lastVault().then(setLastKnown).catch(() => setLastKnown(null));
  }, [vaultPath]);

  const effectivePath = vaultPath ?? lastKnown;

  // Five failures introduces a visible pause. Argon2id already makes guessing
  // expensive; this stops a cat on a keyboard and signals seriousness.
  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const t = window.setInterval(() => setCooldown((c) => c - 1), 1000);
    return () => window.clearInterval(t);
  }, [cooldown]);

  useEffect(() => {
    if (!error) return;
    setShake(true);
    const t = window.setTimeout(() => setShake(false), 160);
    return () => window.clearTimeout(t);
  }, [error]);

  async function submit() {
    if (!effectivePath || busy || cooldown > 0 || password.length === 0) return;
    const ok = await onUnlock(effectivePath, password);
    if (ok) {
      setPassword("");
      setAttempts(0);
      return;
    }
    const next = attempts + 1;
    setAttempts(next);
    setPassword("");
    if (next >= 5) {
      setCooldown(30);
      setAttempts(0);
    }
  }

  async function pickVault() {
    const chosen = await openFolder({
      directory: true,
      multiple: false,
      title: "Choose a vault folder",
    });
    if (typeof chosen === "string") onChooseVault(chosen);
  }

  return (
    <main className="flex-1 grid place-items-center px-6">
      <div className="w-[340px] text-center">
        <KeyRound
          size={40}
          strokeWidth={1.5}
          className="mx-auto text-text-faint"
          aria-hidden
        />

        <h1 className="mt-6 text-2xl font-light uppercase text-text-dim tracking-[0.18em]">
          Keyring
        </h1>

        <form
          className={`mt-8 ${shake ? "kr-shake" : ""}`}
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <Input
            ref={field}
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={password}
            invalid={Boolean(error)}
            disabled={busy || cooldown > 0 || !effectivePath}
            placeholder="Master password"
            onChange={(e) => setPassword(e.target.value)}
            aria-label="Master password"
          />

          <p
            className="mt-3 text-xs text-text-faint font-data truncate"
            title={effectivePath ?? ""}
          >
            {effectivePath ?? "No vault selected"}
          </p>

          <Button
            type="submit"
            className={`mt-6 w-full ${busy ? "kr-deriving" : ""}`}
            disabled={busy || cooldown > 0 || !effectivePath || password.length === 0}
          >
            {busy ? "Unlocking…" : cooldown > 0 ? `Wait ${cooldown}s` : "Unlock"}
          </Button>
        </form>

        {error && <ErrorNote>{error.message}</ErrorNote>}

        {error?.kind === "already_open" && effectivePath && (
          <Button
            variant="ghost"
            className="mt-3 w-full"
            disabled={busy || password.length === 0}
            onClick={() => void onUnlockReadOnly(effectivePath, password)}
          >
            Open read-only instead
          </Button>
        )}

        {cooldown > 0 && (
          <p className="mt-3 text-xs text-text-faint">
            Five attempts failed. Take a breath.
          </p>
        )}

        <div className="mt-8 flex items-center justify-center gap-4 text-sm">
          <button
            onClick={() => void pickVault()}
            className="text-text-dim hover:text-accent transition-colors duration-100"
          >
            Open a different vault
          </button>
          <span className="text-text-faint" aria-hidden>·</span>
          <button
            onClick={onCreateNew}
            className="text-text-dim hover:text-accent transition-colors duration-100"
          >
            Create a vault
          </button>
        </div>
      </div>
    </main>
  );
}
