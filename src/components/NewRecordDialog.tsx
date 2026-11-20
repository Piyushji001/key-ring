import { useEffect, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Cloud,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Sparkles,
} from "lucide-react";
import clsx from "clsx";

import { iconFor } from "../lib/recordTypes";
import type { RecordTypeInfo } from "../lib/types";
import { Button, Input, Label } from "./ui";

/**
 * Clean, fast record creation dialog with smart connection string parser.
 */
export function NewRecordDialog({
  types,
  defaultFolder,
  folders,
  onCancel,
  onCreate,
}: {
  types: RecordTypeInfo[];
  defaultFolder: string;
  folders: string[];
  onCancel: () => void;
  onCreate: (
    recordType: string,
    title: string,
    folder: string,
    tags: string[],
    values: [string, string][],
  ) => void;
}) {
  const [typeKey, setTypeKey] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [folder, setFolder] = useState(defaultFolder);
  const [tags, setTags] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [visibleSecrets, setVisibleSecrets] = useState<Record<string, boolean>>({});
  const [showAdvanced, setShowAdvanced] = useState(false);

  // SSH specific helpers
  const [quickInput, setQuickInput] = useState("");
  const [quickParsedMsg, setQuickParsedMsg] = useState<string | null>(null);
  const [authMethod, setAuthMethod] = useState<"password" | "key">("password");

  // Cloud specific helpers
  const [cloudProvider, setCloudProvider] = useState<
    "aws" | "gcp" | "azure" | "kubernetes"
  >("aws");

  const selected = types.find((t) => t.key === typeKey) ?? null;

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onCancel();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  // Reset states when changing type
  useEffect(() => {
    setValues({});
    setQuickInput("");
    setQuickParsedMsg(null);
    setAuthMethod("password");
    setCloudProvider("aws");
    setShowAdvanced(false);
  }, [typeKey]);

  function toggleSecretVisibility(name: string) {
    setVisibleSecrets((prev) => ({ ...prev, [name]: !prev[name] }));
  }

  // Smart parser for SSH strings like:
  // "ssh root@94.136.186.9 -p 22" or "admin@10.0.0.1" or "94.136.186.9"
  function handleQuickParse(raw: string) {
    setQuickInput(raw);
    const text = raw.trim();
    if (!text) {
      setQuickParsedMsg(null);
      return;
    }

    let cleaned = text;
    if (cleaned.toLowerCase().startsWith("ssh ")) {
      cleaned = cleaned.slice(4).trim();
    }

    let parsedPort = "";
    // check -p <port>
    const portMatch = cleaned.match(/-p\s+(\d+)/i);
    if (portMatch && portMatch[1]) {
      parsedPort = portMatch[1];
      cleaned = cleaned.replace(/-p\s+\d+/i, "").trim();
    }

    // check user@host
    let parsedUser = "";
    let parsedHost = cleaned;

    if (cleaned.includes("@")) {
      const parts = cleaned.split("@");
      parsedUser = parts[0]?.trim() ?? "";
      parsedHost = parts.slice(1).join("@").trim();
    }

    // check host:port
    if (parsedHost.includes(":") && !parsedPort) {
      const colonParts = parsedHost.split(":");
      parsedHost = colonParts[0]?.trim() ?? "";
      parsedPort = colonParts[1]?.trim() ?? "";
    }

    // strip trailing flags like -i or -o
    parsedHost = parsedHost.split(" ")[0]?.trim() ?? "";

    if (parsedHost) {
      setValues((v) => ({
        ...v,
        host: parsedHost,
        ...(parsedUser ? { username: parsedUser } : {}),
        ...(parsedPort ? { port: parsedPort } : {}),
      }));

      if (!title.trim()) {
        setTitle(parsedHost);
      }

      setQuickParsedMsg(
        `Auto-detected: ${parsedUser ? `user '${parsedUser}', ` : ""}host '${parsedHost}'${
          parsedPort ? `, port ${parsedPort}` : ""
        }`,
      );
    }
  }

  // Smart Host change handler: automatically auto-splits if user pastes user@host into Host field
  function handleHostChange(text: string) {
    if (text.includes("@")) {
      const parts = text.split("@");
      const user = parts[0]?.trim() ?? "";
      const host = parts.slice(1).join("@").trim();
      setValues((v) => ({
        ...v,
        username: user,
        host: host,
      }));
      setQuickParsedMsg(`Auto-split username '${user}' and host '${host}'`);
    } else {
      setValues((v) => ({ ...v, host: text }));
    }
  }

  function save() {
    if (!selected || !title.trim()) return;

    const merged = { ...values };
    if (selected.key === "ssh_server") {
      merged.auth_method = authMethod;
    } else if (selected.key === "cloud_service_account") {
      merged.provider = cloudProvider;
    }

    const filled = Object.entries(merged).filter(([, v]) => v.trim() !== "");
    onCreate(
      selected.key,
      title.trim(),
      folder.trim(),
      tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
      filled as [string, string][],
    );
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm px-6">
      <div className="w-full max-w-[560px] max-h-[85vh] flex flex-col rounded-panel border border-edge bg-panel shadow-2xl overflow-hidden">
        <header className="px-5 py-4 border-b border-edge shrink-0 flex items-center justify-between">
          <div className="flex items-center gap-2">
            {selected && (
              <button
                onClick={() => setTypeKey(null)}
                className="text-text-dim hover:text-text text-sm mr-1"
                title="Change type"
              >
                ←
              </button>
            )}
            <h2 className="text-lg text-text font-medium">
              {selected ? `New ${selected.label}` : "What are you storing?"}
            </h2>
          </div>
          {selected && (
            <span className="text-xs text-text-faint font-ui">
              Fill essentials and save
            </span>
          )}
        </header>

        <div className="p-5 overflow-y-auto flex-1">
          {!selected ? (
            <div className="grid grid-cols-3 gap-2">
              {types.map((t) => {
                const Icon = iconFor(t.key);
                return (
                  <button
                    key={t.key}
                    onClick={() => setTypeKey(t.key)}
                    className="h-24 flex flex-col items-center justify-center gap-2 rounded-control border border-edge text-text-dim hover:border-accent hover:text-text hover:bg-panel-hi transition-all duration-100"
                  >
                    <Icon size={20} strokeWidth={1.5} className="text-accent" />
                    <span className="text-sm text-center px-2 font-ui">{t.label}</span>
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="space-y-4">
              {/* ⚡ Quick Connect Bar for SSH */}
              {selected.key === "ssh_server" && (
                <div className="rounded-control border border-accent/30 bg-accent/[0.04] p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-accent flex items-center gap-1.5 font-ui">
                      <Sparkles size={13} />
                      Quick Paste / Connection String
                    </span>
                    {quickParsedMsg && (
                      <span className="text-xs text-emerald-400 font-ui truncate max-w-[240px]">
                        {quickParsedMsg}
                      </span>
                    )}
                  </div>
                  <Input
                    mono
                    value={quickInput}
                    onChange={(e) => handleQuickParse(e.target.value)}
                    placeholder="e.g. ssh root@94.136.186.9 or root@host:22"
                    className="mt-2 h-9 text-xs bg-void border-edge"
                  />
                </div>
              )}

              {/* Title (Always required) */}
              <div>
                <Label>Title</Label>
                <Input
                  autoFocus
                  mono={false}
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder={selected.key === "ssh_server" ? "prod-web-01" : "My Credential"}
                />
              </div>

              {/* SSH SPECIFIC CLEAN LAYOUT */}
              {selected.key === "ssh_server" ? (
                <>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="col-span-2">
                      <Label>Host / IP Address</Label>
                      <Input
                        mono
                        value={values.host ?? ""}
                        onChange={(e) => handleHostChange(e.target.value)}
                        placeholder="94.136.186.9 or myhost.com"
                      />
                    </div>
                    <div>
                      <Label>Port</Label>
                      <Input
                        mono
                        type="number"
                        value={values.port ?? ""}
                        onChange={(e) =>
                          setValues((v) => ({ ...v, port: e.target.value }))
                        }
                        placeholder="22"
                      />
                    </div>
                  </div>

                  <div>
                    <Label>Username</Label>
                    <Input
                      mono
                      value={values.username ?? ""}
                      onChange={(e) =>
                        setValues((v) => ({ ...v, username: e.target.value }))
                      }
                      placeholder="root or ubuntu"
                    />
                  </div>

                  {/* Auth Method Selector */}
                  <div>
                    <Label>Authentication Type</Label>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        type="button"
                        onClick={() => setAuthMethod("password")}
                        className={clsx(
                          "py-2 px-3 text-sm rounded-control border transition-all flex items-center justify-center gap-2 font-ui",
                          authMethod === "password"
                            ? "border-accent bg-accent/15 text-accent font-medium shadow-sm"
                            : "border-edge text-text-dim hover:text-text hover:bg-panel-hi",
                        )}
                      >
                        <Lock size={14} />
                        Password
                      </button>
                      <button
                        type="button"
                        onClick={() => setAuthMethod("key")}
                        className={clsx(
                          "py-2 px-3 text-sm rounded-control border transition-all flex items-center justify-center gap-2 font-ui",
                          authMethod === "key"
                            ? "border-accent bg-accent/15 text-accent font-medium shadow-sm"
                            : "border-edge text-text-dim hover:text-text hover:bg-panel-hi",
                        )}
                      >
                        <KeyRound size={14} />
                        SSH Key (.pem / id_rsa)
                      </button>
                    </div>
                  </div>

                  {authMethod === "password" ? (
                    <div>
                      <Label>
                        Password
                        <span className="ml-2 text-xs text-accent">encrypted</span>
                      </Label>
                      <div className="relative">
                        <Input
                          type={visibleSecrets.password ? "text" : "password"}
                          autoComplete="off"
                          value={values.password ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, password: e.target.value }))
                          }
                          placeholder="Remote server password"
                          className="pr-10"
                        />
                        <button
                          type="button"
                          onClick={() => toggleSecretVisibility("password")}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text"
                          aria-label="Toggle password visibility"
                        >
                          {visibleSecrets.password ? <EyeOff size={15} /> : <Eye size={15} />}
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-control border border-edge bg-void/50 p-3 text-xs text-text-dim space-y-2">
                      <p className="text-text font-medium flex items-center gap-1.5">
                        <KeyRound size={14} className="text-accent" />
                        SSH Key Attachment
                      </p>
                      <p>
                        Attach your OpenSSH private key (<code className="text-accent font-data">.pem</code>, <code className="text-accent font-data">id_rsa</code>) in the <strong>Attachments</strong> panel right after saving.
                      </p>
                      <div>
                        <Label>Key Passphrase (Optional)</Label>
                        <Input
                          type={visibleSecrets.key_passphrase ? "text" : "password"}
                          value={values.key_passphrase ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, key_passphrase: e.target.value }))
                          }
                          placeholder="Passphrase for encrypted key (if any)"
                        />
                      </div>
                    </div>
                  )}
                </>
              ) : selected.key === "cloud_service_account" ? (
                <>
                  {/* Cloud Provider Tabs */}
                  <div>
                    <Label>Cloud Provider</Label>
                    <div className="grid grid-cols-4 gap-2">
                      {(
                        [
                          ["aws", "AWS"],
                          ["gcp", "Google Cloud"],
                          ["azure", "Azure"],
                          ["kubernetes", "Kubernetes"],
                        ] as const
                      ).map(([key, label]) => (
                        <button
                          key={key}
                          type="button"
                          onClick={() => {
                            setCloudProvider(key);
                            setValues((v) => ({ ...v, provider: key }));
                          }}
                          className={clsx(
                            "py-2 px-2 text-xs rounded-control border transition-all text-center font-ui truncate",
                            cloudProvider === key
                              ? "border-accent bg-accent/15 text-accent font-medium shadow-sm"
                              : "border-edge text-text-dim hover:text-text hover:bg-panel-hi",
                          )}
                        >
                          {label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {cloudProvider === "aws" && (
                    <div className="space-y-3">
                      <div>
                        <Label>AWS Access Key ID</Label>
                        <Input
                          mono
                          value={values.access_key_id ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, access_key_id: e.target.value }))
                          }
                          placeholder="AKIAIOSFODNN7EXAMPLE"
                        />
                      </div>

                      <div>
                        <Label>
                          AWS Secret Access Key
                          <span className="ml-2 text-xs text-accent">encrypted</span>
                        </Label>
                        <div className="relative">
                          <Input
                            type={visibleSecrets.secret_access_key ? "text" : "password"}
                            value={values.secret_access_key ?? ""}
                            onChange={(e) =>
                              setValues((v) => ({
                                ...v,
                                secret_access_key: e.target.value,
                              }))
                            }
                            placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                            className="pr-10"
                          />
                          <button
                            type="button"
                            onClick={() => toggleSecretVisibility("secret_access_key")}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text"
                          >
                            {visibleSecrets.secret_access_key ? (
                              <EyeOff size={15} />
                            ) : (
                              <Eye size={15} />
                            )}
                          </button>
                        </div>
                      </div>

                      <div>
                        <Label>Default Region</Label>
                        <Input
                          mono
                          value={values.region ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, region: e.target.value }))
                          }
                          placeholder="us-east-1 or ap-south-1"
                        />
                      </div>
                    </div>
                  )}

                  {cloudProvider === "gcp" && (
                    <div className="space-y-3">
                      <div>
                        <Label>Google Cloud Project ID</Label>
                        <Input
                          mono
                          value={values.project_id ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, project_id: e.target.value }))
                          }
                          placeholder="my-gcp-project-123456"
                        />
                      </div>

                      <div>
                        <Label>Service Account Email (Optional)</Label>
                        <Input
                          mono
                          value={values.account_email ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, account_email: e.target.value }))
                          }
                          placeholder="deployer@project.iam.gserviceaccount.com"
                        />
                      </div>

                      <div className="rounded-control border border-edge bg-void/50 p-3 text-xs text-text-dim space-y-1">
                        <p className="text-text font-medium flex items-center gap-1.5">
                          <Cloud size={14} className="text-accent" />
                          GCP Service Account Key
                        </p>
                        <p>
                          Attach your Service Account key file (<code className="text-accent font-data">.json</code>) in the <strong>Attachments</strong> panel after saving. Keyring will activate it automatically when launching the shell.
                        </p>
                      </div>
                    </div>
                  )}

                  {cloudProvider === "azure" && (
                    <div className="space-y-3">
                      <div>
                        <Label>Application (Client) ID</Label>
                        <Input
                          mono
                          value={values.client_id ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, client_id: e.target.value }))
                          }
                          placeholder="00000000-0000-0000-0000-000000000000"
                        />
                      </div>

                      <div>
                        <Label>
                          Client Secret
                          <span className="ml-2 text-xs text-accent">encrypted</span>
                        </Label>
                        <div className="relative">
                          <Input
                            type={visibleSecrets.client_secret ? "text" : "password"}
                            value={values.client_secret ?? ""}
                            onChange={(e) =>
                              setValues((v) => ({ ...v, client_secret: e.target.value }))
                            }
                            placeholder="Client Secret Value"
                            className="pr-10"
                          />
                          <button
                            type="button"
                            onClick={() => toggleSecretVisibility("client_secret")}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text"
                          >
                            {visibleSecrets.client_secret ? (
                              <EyeOff size={15} />
                            ) : (
                              <Eye size={15} />
                            )}
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <Label>Directory (Tenant) ID</Label>
                          <Input
                            mono
                            value={values.tenant_id ?? ""}
                            onChange={(e) =>
                              setValues((v) => ({ ...v, tenant_id: e.target.value }))
                            }
                            placeholder="Tenant GUID"
                          />
                        </div>
                        <div>
                          <Label>Subscription ID (Optional)</Label>
                          <Input
                            mono
                            value={values.subscription_id ?? ""}
                            onChange={(e) =>
                              setValues((v) => ({
                                ...v,
                                subscription_id: e.target.value,
                              }))
                            }
                            placeholder="Subscription GUID"
                          />
                        </div>
                      </div>
                    </div>
                  )}

                  {cloudProvider === "kubernetes" && (
                    <div className="space-y-3">
                      <div>
                        <Label>Cluster Name</Label>
                        <Input
                          mono
                          value={values.cluster ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, cluster: e.target.value }))
                          }
                          placeholder="production-eks-cluster"
                        />
                      </div>

                      <div>
                        <Label>Namespace (Optional)</Label>
                        <Input
                          mono
                          value={values.namespace ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, namespace: e.target.value }))
                          }
                          placeholder="default, production, etc."
                        />
                      </div>

                      <div className="rounded-control border border-edge bg-void/50 p-3 text-xs text-text-dim space-y-1">
                        <p className="text-text font-medium flex items-center gap-1.5">
                          <Cloud size={14} className="text-accent" />
                          Kubeconfig Attachment
                        </p>
                        <p>
                          Attach your cluster config file (<code className="text-accent font-data">.yaml</code>, <code className="text-accent font-data">.kubeconfig</code>) in the <strong>Attachments</strong> panel after saving.
                        </p>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                /* STANDARD CLEAN LAYOUT FOR OTHER TYPES */
                <div className="space-y-3">
                  {selected.fields.map((f) => (
                    <div key={f.name}>
                      <Label>
                        {f.label}
                        {f.secret && (
                          <span className="ml-2 text-xs text-accent">encrypted</span>
                        )}
                      </Label>
                      {f.kind === "multiline" ? (
                        <textarea
                          rows={3}
                          value={values[f.name] ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, [f.name]: e.target.value }))
                          }
                          className="w-full px-3 py-2 rounded-control bg-void text-text border border-edge font-data text-sm focus:outline-none focus:border-accent"
                        />
                      ) : (
                        <div className="relative">
                          <Input
                            type={
                              f.secret
                                ? visibleSecrets[f.name]
                                  ? "text"
                                  : "password"
                                : "text"
                            }
                            autoComplete="off"
                            value={values[f.name] ?? ""}
                            onChange={(e) =>
                              setValues((v) => ({ ...v, [f.name]: e.target.value }))
                            }
                            className={f.secret ? "pr-10" : ""}
                          />
                          {f.secret && (
                            <button
                              type="button"
                              onClick={() => toggleSecretVisibility(f.name)}
                              className="absolute right-3 top-1/2 -translate-y-1/2 text-text-dim hover:text-text"
                            >
                              {visibleSecrets[f.name] ? (
                                <EyeOff size={15} />
                              ) : (
                                <Eye size={15} />
                              )}
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* COLLAPSIBLE ADVANCED SECTION */}
              <div className="pt-2 border-t border-edge">
                <button
                  type="button"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex items-center gap-1.5 text-xs text-text-dim hover:text-text font-ui"
                >
                  {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  Advanced Options (Folder, Tags, Notes
                  {selected.key === "ssh_server" ? ", Jump host" : ""})
                </button>

                {showAdvanced && (
                  <div className="mt-3 space-y-3 pl-4 border-l border-edge/60">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <Label>Folder</Label>
                        <Input
                          mono={false}
                          list="kr-folder-suggestions"
                          value={folder}
                          onChange={(e) => setFolder(e.target.value)}
                          placeholder="clients/acme"
                        />
                        <datalist id="kr-folder-suggestions">
                          {folders.map((f) => (
                            <option key={f} value={f} />
                          ))}
                        </datalist>
                      </div>
                      <div>
                        <Label>Tags</Label>
                        <Input
                          mono={false}
                          value={tags}
                          onChange={(e) => setTags(e.target.value)}
                          placeholder="production, dr"
                        />
                      </div>
                    </div>

                    {selected.key === "ssh_server" && (
                      <div>
                        <Label>Jump Host (Optional)</Label>
                        <Input
                          mono
                          value={values.jump_host ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, jump_host: e.target.value }))
                          }
                          placeholder="jump.internal.corp"
                        />
                      </div>
                    )}

                    {selected.key === "cloud_service_account" && cloudProvider === "aws" && (
                      <div>
                        <Label>
                          AWS Session Token (Optional / STS)
                          <span className="ml-2 text-xs text-accent">encrypted</span>
                        </Label>
                        <Input
                          type={visibleSecrets.session_token ? "text" : "password"}
                          value={values.session_token ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, session_token: e.target.value }))
                          }
                          placeholder="Temporary session token from STS"
                        />
                      </div>
                    )}

                    {selected.key === "cloud_service_account" && (
                      <div>
                        <Label>Web Console URL (Optional)</Label>
                        <Input
                          mono
                          value={values.console_url ?? ""}
                          onChange={(e) =>
                            setValues((v) => ({ ...v, console_url: e.target.value }))
                          }
                          placeholder="https://console.aws.amazon.com or https://console.cloud.google.com"
                        />
                      </div>
                    )}

                    <div>
                      <Label>Notes</Label>
                      <textarea
                        rows={2}
                        value={values.notes ?? ""}
                        onChange={(e) =>
                          setValues((v) => ({ ...v, notes: e.target.value }))
                        }
                        placeholder="Internal documentation or instructions"
                        className="w-full px-3 py-2 rounded-control bg-void text-text border border-edge font-data text-xs focus:outline-none focus:border-accent"
                      />
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <footer className="px-5 py-4 border-t border-edge flex items-center justify-between shrink-0 bg-panel">
          <Button
            variant="ghost"
            onClick={selected ? () => setTypeKey(null) : onCancel}
          >
            {selected ? "Back" : "Cancel"}
          </Button>
          {selected && (
            <Button onClick={save} disabled={!title.trim()}>
              Save Record
            </Button>
          )}
        </footer>
      </div>
    </div>
  );
}
