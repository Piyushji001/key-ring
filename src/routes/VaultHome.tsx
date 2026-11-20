import { Database, KeyRound, Plus, Server } from "lucide-react";

import { Kbd } from "../components/ui";
import type { VaultStatus } from "../lib/types";

/**
 * Placeholder for the three-pane main window, which is Phase 4.
 *
 * It exists so that Phase 3 has somewhere to land after a successful unlock and
 * so the warming transition can be seen. Everything here is replaced by
 * Sidebar / RecordList / DetailPane.
 */
export function VaultHome({ status }: { status: VaultStatus }) {
  const empty = status.recordCount === 0;

  return (
    <main className="flex-1 grid place-items-center px-6">
      <div className="text-center max-w-[420px]">
        <div className="flex items-center justify-center gap-6 text-accent" aria-hidden>
          <Server size={22} strokeWidth={1.5} />
          <Database size={22} strokeWidth={1.5} />
          <KeyRound size={22} strokeWidth={1.5} />
        </div>

        <h1 className="mt-6 text-lg font-medium text-text">Vault unlocked</h1>

        {empty ? (
          <p className="mt-3 text-base text-text-dim">
            Nothing stored yet. Press <Kbd>Ctrl N</Kbd> to add your first
            credential.
          </p>
        ) : (
          <p className="mt-3 text-base text-text-dim">
            <span className="font-data text-text">{status.recordCount}</span>{" "}
            {status.recordCount === 1 ? "record" : "records"} available.
          </p>
        )}

        <dl className="mt-8 text-left rounded-panel border border-edge bg-panel p-4 text-sm">
          <Row label="Location" value={status.vaultPath ?? "—"} mono />
          <Row label="Format" value={`version ${status.formatVersion ?? "?"}`} />
          {status.kdf && (
            <Row
              label="Key derivation"
              value={`Argon2id · ${status.kdf.memoryMib} MiB · ${status.kdf.iterations} iterations`}
              mono
            />
          )}
          <Row label="Network access" value="None. No sockets exist in this build." />
        </dl>

        <p className="mt-8 text-xs text-text-faint">
          <Plus size={11} strokeWidth={1.5} className="inline mr-1" aria-hidden />
          Records, search and the three-pane window arrive in Phase 4.
        </p>
      </div>
    </main>
  );
}

function Row({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-4 py-1.5 first:pt-0 last:pb-0">
      <dt className="w-32 shrink-0 text-text-dim">{label}</dt>
      <dd
        className={`min-w-0 break-words text-text ${mono ? "font-data text-xs leading-5" : ""}`}
        data-selectable
      >
        {value}
      </dd>
    </div>
  );
}
