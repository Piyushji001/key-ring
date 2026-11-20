/**
 * One-click connect (Phase 7.5).
 *
 * The rule this component exists to enforce: **ask what is possible before
 * offering it.** `connectCapabilities` is called once and the button is
 * disabled with the real reason when something is missing. A Connect button
 * that opens a terminal which then asks for a password Keyring promised to
 * supply is worse than a greyed-out one, because the user has already stopped
 * paying attention by then.
 *
 * The `caveat` on a result is shown, never swallowed. It is how the backend
 * says "this worked, but not the way you assumed".
 */

import { useEffect, useState } from "react";
import { Cloud, Loader2, Terminal } from "lucide-react";

import { ipc, asAppError } from "../lib/ipc";
import type {
  AttachmentView,
  ConnectCapabilities,
  ConnectResult,
  RecordDetail,
} from "../lib/types";
import { Button } from "./ui";

const CLOUD_PROVIDERS: [string, string][] = [
  ["aws", "AWS"],
  ["gcp", "Google Cloud"],
  ["azure", "Azure"],
  ["kubernetes", "Kubernetes"],
];

export function ConnectBar({
  detail,
  readOnly,
  onResult,
}: {
  detail: RecordDetail;
  readOnly: boolean;
  onResult: (message: string, tone: "ok" | "warn") => void;
}) {
  const [caps, setCaps] = useState<ConnectCapabilities | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ConnectResult | null>(null);

  useEffect(() => {
    ipc
      .connectCapabilities()
      .then(setCaps)
      .catch(() => setCaps(null));
  }, []);

  const type = detail.summary.recordType;
  const isSsh = type === "ssh_server";
  const isCloud = type === "cloud_service_account";

  if (!isSsh && !isCloud) return null;

  const keyAttachment: AttachmentView | undefined = detail.attachments.find((a) =>
    /\.(pem|key|ppk)$|^id_/i.test(a.filename),
  );

  async function run(fn: () => Promise<ConnectResult>) {
    setBusy(true);
    try {
      const r = await fn();
      setResult(r);
      onResult(r.detail, r.caveat ? "warn" : "ok");
    } catch (e) {
      onResult(asAppError(e).message, "warn");
    } finally {
      setBusy(false);
    }
  }

  // Why the button might not work, in the user's language.
  const sshBlocker =
    caps && !caps.sshClient
      ? "The Windows OpenSSH client is not installed."
      : caps && !caps.windowsTerminal && !caps.powershell
        ? "No terminal was found."
        : null;

  const terminalBlocker =
    caps && !caps.windowsTerminal && !caps.powershell
      ? "No terminal was found."
      : null;

  return (
    <div className="mt-4">
      <div className="flex flex-wrap gap-2">
        {isSsh && (
          <Button
            onClick={() =>
              run(() => ipc.sshConnect(detail.summary.id, keyAttachment?.id))
            }
            disabled={readOnly || busy || sshBlocker !== null}
            title={sshBlocker ?? "Open a terminal connected to this host"}
          >
            {busy ? (
              <Loader2 size={14} className="inline animate-spin mr-1.5" />
            ) : (
              <Terminal size={14} className="inline mr-1.5" strokeWidth={1.5} />
            )}
            Connect
          </Button>
        )}

        {isCloud &&
          CLOUD_PROVIDERS.map(([value, label]) => (
            <Button
              key={value}
              variant="ghost"
              onClick={() => run(() => ipc.cloudConnect(detail.summary.id, value))}
              disabled={readOnly || busy || terminalBlocker !== null}
              title={terminalBlocker ?? `Open a shell authenticated to ${label}`}
            >
              <Cloud size={14} className="inline mr-1.5" strokeWidth={1.5} />
              {label}
            </Button>
          ))}
      </div>

      {sshBlocker && (
        <p className="mt-2 text-sm text-text-faint font-ui">{sshBlocker}</p>
      )}

      {result && (
        <div className="mt-3 rounded-panel border border-edge bg-panel/50 p-3 space-y-1.5">
          <p className="text-sm text-text-dim font-ui">
            {result.terminal}
            {result.auth === "key" && " · authenticated with a stored key"}
            {result.auth === "password" && " · password handed to ssh directly"}
            {result.auth === "interactive" && " · ssh will ask for credentials"}
          </p>

          {result.cleanupInSecs !== null && (
            <p className="text-sm text-text-faint font-ui">
              Extracted material is destroyed in{" "}
              {Math.round(result.cleanupInSecs / 60)} minute
              {result.cleanupInSecs >= 120 ? "s" : ""}, or when you lock.
            </p>
          )}

          {/* The honest bit. Do not hide this. */}
          {result.caveat && (
            <p className="text-sm text-warn font-ui leading-relaxed">
              {result.caveat}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
