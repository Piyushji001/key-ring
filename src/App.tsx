import { useCallback, useEffect, useState } from "react";

import { TitleBar } from "./components/TitleBar";
import { useVault } from "./hooks/useVault";
import { Setup } from "./routes/Setup";
import { Unlock } from "./routes/Unlock";
import { VaultWindow } from "./routes/VaultWindow";

/**
 * Shell and lock-state gate.
 *
 * There is no router. The application has exactly three states in Phase 3 -
 * setting up, locked, unlocked - and lock state is not navigation. Treating it
 * as a URL would let the back button pretend to unlock a vault.
 */
export default function App() {
  const { status, busy, error, clearError, unlock, unlockReadOnly, create, lock } =
    useVault();
  const [mode, setMode] = useState<"unlock" | "setup">("unlock");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [copilotOpen, setCopilotOpen] = useState(false);

  // Ctrl+L locks from anywhere. The one shortcut that must never fail.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.ctrlKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        setCopilotOpen(false);
        void lock();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lock]);

  const chooseVault = useCallback(
    (path: string) => {
      clearError();
      setSelectedPath(path);
      setMode("unlock");
    },
    [clearError],
  );

  const vaultPath = selectedPath ?? status.vaultPath;

  return (
    <div className="h-full flex flex-col bg-void">
      <TitleBar
        locked={status.locked}
        readOnly={status.readOnly}
        copilotOpen={copilotOpen}
        onToggleCopilot={() => setCopilotOpen((v) => !v)}
        onLock={() => {
          setCopilotOpen(false);
          void lock();
        }}
      />

      {!status.locked ? (
        <VaultWindow
          status={status}
          copilotOpen={copilotOpen}
          setCopilotOpen={setCopilotOpen}
        />
      ) : mode === "setup" ? (
        <Setup
          busy={busy}
          error={error}
          onCreate={create}
          onCancel={() => {
            clearError();
            setMode("unlock");
          }}
        />
      ) : (
        <Unlock
          vaultPath={vaultPath}
          busy={busy}
          error={error}
          onUnlock={unlock}
          onUnlockReadOnly={unlockReadOnly}
          onChooseVault={chooseVault}
          onCreateNew={() => {
            clearError();
            setMode("setup");
          }}
        />
      )}
    </div>
  );
}
