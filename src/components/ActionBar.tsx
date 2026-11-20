import { useState } from "react";
import { Cloud, ExternalLink, KeyRound, Monitor, Terminal } from "lucide-react";

import { asAppError, ipc } from "../lib/ipc";
import type { RecordDetail } from "../lib/types";
import { Button } from "./ui";

/**
 * Type-specific primary actions (UI Spec section 4).
 *
 * The point of the whole product is here: not "here is your password", but
 * "you are connected". An RDP host gets a Connect button; an SSH server gets a
 * command on the clipboard; a web login gets a browser.
 *
 * Every one of these executes in Rust. Nothing on this bar receives a secret.
 */
export function ActionBar({
  detail,
  disabled,
  onResult,
}: {
  detail: RecordDetail;
  disabled: boolean;
  onResult: (message: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const { summary } = detail;

  const has = (name: string) =>
    detail.fields.some((f) => f.name === name && f.hasValue);
  const keyAttachment = detail.attachments.find((a) =>
    /(^id_|\.pem$|\.key$|\.ppk$)/i.test(a.filename),
  );

  async function run(fn: () => Promise<string>) {
    setBusy(true);
    try {
      onResult(await fn());
    } catch (e) {
      onResult(asAppError(e).message);
    } finally {
      setBusy(false);
    }
  }

  const actions: React.ReactNode[] = [];

  if (summary.recordType === "rdp_host" && has("host") && has("password")) {
    actions.push(
      <Button
        key="rdp"
        disabled={disabled || busy}
        onClick={() =>
          void run(async () => (await ipc.launchRdp(summary.id)).detail)
        }
      >
        <Monitor size={14} strokeWidth={1.5} className="inline mr-1.5" />
        Connect
      </Button>,
    );
  }

  if (summary.recordType === "ssh_server" && has("host")) {
    actions.push(
      <Button
        key="ssh-connect"
        disabled={disabled || busy}
        onClick={() =>
          void run(async () => {
            const result = await ipc.sshConnect(summary.id, keyAttachment?.id);
            return result.caveat ? `${result.detail} (${result.caveat})` : result.detail;
          })
        }
      >
        <Terminal size={14} strokeWidth={1.5} className="inline mr-1.5" />
        Connect
      </Button>,
    );

    actions.push(
      <Button
        key="ssh"
        variant="ghost"
        disabled={disabled || busy}
        onClick={() =>
          void run(async () => {
            const result = await ipc.sshCommand(summary.id);
            return `Copied: ${result.command}`;
          })
        }
      >
        Copy SSH command
      </Button>,
    );

    if (keyAttachment) {
      actions.push(
        <Button
          key="sshkey"
          variant="ghost"
          disabled={disabled || busy}
          onClick={() =>
            void run(async () => {
              const result = await ipc.sshCommandWithKey(
                summary.id,
                keyAttachment.id,
              );
              return `Key extracted and command copied: ${result.command}`;
            })
          }
        >
          <KeyRound size={14} strokeWidth={1.5} className="inline mr-1.5" />
          With key
        </Button>,
      );
    }
  }

  if (summary.recordType === "cloud_service_account") {
    const rawProvider =
      detail.fields.find((f) => f.name === "provider")?.value?.toLowerCase().trim() || "aws";
    const providerMap: Record<string, { key: string; label: string }> = {
      aws: { key: "aws", label: "AWS" },
      amazon: { key: "aws", label: "AWS" },
      gcp: { key: "gcp", label: "Google Cloud" },
      google: { key: "gcp", label: "Google Cloud" },
      azure: { key: "azure", label: "Azure" },
      kubernetes: { key: "kubernetes", label: "Kubernetes" },
      k8s: { key: "kubernetes", label: "Kubernetes" },
    };
    const info = providerMap[rawProvider] ?? { key: rawProvider, label: "Cloud" };

    actions.push(
      <Button
        key="cloud-launch"
        disabled={disabled || busy}
        onClick={() =>
          void run(async () => {
            const result = await ipc.cloudConnect(summary.id, info.key);
            return result.caveat ? `${result.detail} (${result.caveat})` : result.detail;
          })
        }
      >
        <Cloud size={14} strokeWidth={1.5} className="inline mr-1.5" />
        Launch {info.label} Shell
      </Button>,
    );
  }

  const url = detail.fields.find(
    (f) => (f.name === "url" || f.name === "console_url") && f.value,
  )?.value;

  if (url) {
    actions.push(
      <Button
        key="url"
        variant="ghost"
        disabled={disabled || busy}
        onClick={() =>
          void run(async () => {
            await ipc.openUrl(url);
            return `Opened ${url}`;
          })
        }
      >
        <ExternalLink size={14} strokeWidth={1.5} className="inline mr-1.5" />
        Open
      </Button>,
    );
  }

  if (actions.length === 0) return null;

  return (
    <div className="px-6 py-3 border-b border-edge flex flex-wrap gap-2">
      {actions}
    </div>
  );
}
