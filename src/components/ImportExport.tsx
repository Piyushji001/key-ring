/**
 * Import and export.
 *
 * The plaintext export path deserves the friction it has. It writes every
 * credential you own to an unencrypted file. The confirmation is *not*
 * implemented here — the backend issues a single-use token that expires in
 * 120 seconds (D-37), and this component simply cannot produce a plaintext
 * export without one. That is deliberate: a React bug, a stray automation, or
 * a future refactor of this dialog cannot dump your vault.
 *
 * If you are simplifying this file: the two-step flow is the security control.
 * Do not collapse it into one button.
 */

import { useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { AlertTriangle, Download, Loader2, Upload } from "lucide-react";

import { ipc, asAppError } from "../lib/ipc";
import type {
  ExportFormatName,
  ImportPreview,
  ImportReport,
  ImportSourceName,
} from "../lib/types";
import { Button, DangerBlock, ErrorNote, Input, Label } from "./ui";

const SOURCES: [ImportSourceName, string, string[]][] = [
  ["keepass_csv", "KeePass CSV", ["csv"]],
  ["bitwarden_json", "Bitwarden JSON", ["json"]],
  ["keyring_json", "Keyring export", ["json", "krexport"]],
];

export function ImportExport({ onChanged }: { onChanged: () => void }) {
  const [mode, setMode] = useState<"none" | "import" | "export">("none");

  return (
    <div className="mt-4">
      <div className="flex gap-2">
        <Button variant="ghost" onClick={() => setMode(mode === "import" ? "none" : "import")}>
          <Upload size={14} className="inline mr-1.5" />
          Import
        </Button>
        <Button variant="ghost" onClick={() => setMode(mode === "export" ? "none" : "export")}>
          <Download size={14} className="inline mr-1.5" />
          Export
        </Button>
      </div>

      {mode === "import" && (
        <ImportPanel
          onDone={() => {
            setMode("none");
            onChanged();
          }}
        />
      )}
      {mode === "export" && <ExportPanel onDone={() => setMode("none")} />}
    </div>
  );
}

// ------------------------------------------------------------------- import

function ImportPanel({ onDone }: { onDone: () => void }) {
  const [source, setSource] = useState<ImportSourceName>("keepass_csv");
  const [path, setPath] = useState<string | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [folder, setFolder] = useState("Imported");
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const extensions = SOURCES.find(([s]) => s === source)?.[2] ?? ["csv"];

  async function pick() {
    const picked = await open({
      multiple: false,
      filters: [{ name: "Credential export", extensions }],
    });
    if (typeof picked !== "string") return;
    setPath(picked);
    setPreview(null);
    setReport(null);
    setError(null);

    if (source === "keyring_json") return; // needs a passphrase first

    setBusy(true);
    try {
      setPreview(await ipc.previewImport(source, picked));
    } catch (e) {
      setError(asAppError(e).message);
    } finally {
      setBusy(false);
    }
  }

  async function commit() {
    if (!path) return;
    setBusy(true);
    setError(null);
    try {
      const result =
        source === "keyring_json"
          ? await ipc.importKeyringExport(path, passphrase)
          : await ipc.runImport(source, path, folder || undefined);
      setReport(result);
      setPassphrase("");
    } catch (e) {
      setError(asAppError(e).message);
    } finally {
      setBusy(false);
    }
  }

  if (report) {
    return (
      <div className="mt-4 rounded-panel border border-edge p-4 space-y-2">
        <p className="text-base text-text font-ui">
          Imported {report.imported} record
          {report.imported === 1 ? "" : "s"} into “{report.folder}”.
        </p>
        {report.duplicatesFlagged > 0 && (
          <p className="text-sm text-text-dim font-ui">
            {report.duplicatesFlagged} looked like records you already have.
            They were added as new records and tagged{" "}
            <span className="font-data">duplicate</span> rather than
            overwriting anything.
          </p>
        )}
        {report.skipped > 0 && (
          <p className="text-sm text-text-dim font-ui">
            {report.skipped} row{report.skipped === 1 ? " was" : "s were"}{" "}
            skipped.
          </p>
        )}
        {report.warnings.map((w, i) => (
          <p key={i} className="text-sm text-warn font-ui">
            {w}
          </p>
        ))}
        <Button className="mt-2" onClick={onDone}>
          Done
        </Button>
      </div>
    );
  }

  return (
    <div className="mt-4 rounded-panel border border-edge p-4">
      <Label>Import from</Label>
      <div className="flex gap-2 mb-4">
        {SOURCES.map(([value, label]) => (
          <Button
            key={value}
            variant={source === value ? "primary" : "ghost"}
            onClick={() => {
              setSource(value);
              setPath(null);
              setPreview(null);
            }}
          >
            {label}
          </Button>
        ))}
      </div>

      <Button variant="ghost" onClick={pick} disabled={busy}>
        {path ? "Choose a different file" : "Choose a file"}
      </Button>
      {path && (
        <p className="mt-2 text-sm text-text-faint font-data break-all">{path}</p>
      )}

      {busy && (
        <p className="mt-3 text-sm text-text-faint">
          <Loader2 size={14} className="inline animate-spin mr-1.5" />
          Reading…
        </p>
      )}

      {source === "keyring_json" && path && (
        <div className="mt-4">
          <Label>Passphrase for this export</Label>
          <Input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="The passphrase used when it was exported"
          />
        </div>
      )}

      {preview && (
        <div className="mt-4 space-y-3">
          <p className="text-base text-text font-ui">
            {preview.total} record{preview.total === 1 ? "" : "s"} found.
          </p>

          <div className="text-sm text-text-dim font-ui space-y-1">
            {Object.entries(preview.byType).map(([type, count]) => (
              <p key={type}>
                {count} → <span className="font-data">{type}</span>
              </p>
            ))}
          </div>

          {preview.sampleTitles.length > 0 && (
            <p className="text-sm text-text-faint font-ui">
              For example: {preview.sampleTitles.slice(0, 3).join(", ")}
            </p>
          )}

          {preview.skipped.map((s, i) => (
            <p key={i} className="text-sm text-warn font-ui">
              {s.count} skipped — {s.reason}
            </p>
          ))}

          {preview.warnings.map((w, i) => (
            <p key={i} className="text-sm text-warn font-ui">
              {w}
            </p>
          ))}

          <div>
            <Label>Put them in this folder</Label>
            <Input value={folder} onChange={(e) => setFolder(e.target.value)} />
          </div>
        </div>
      )}

      {error && <ErrorNote>{error}</ErrorNote>}

      {(preview || (source === "keyring_json" && path)) && (
        <div className="mt-4 flex gap-2">
          <Button onClick={commit} disabled={busy}>
            Import
          </Button>
          <Button variant="ghost" onClick={onDone}>
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------------- export

function ExportPanel({ onDone }: { onDone: () => void }) {
  const [format, setFormat] = useState<ExportFormatName>("encrypted_json");
  const [passphrase, setPassphrase] = useState("");
  const [folder, setFolder] = useState("");
  const [includeAttachments, setIncludeAttachments] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  /** Plaintext only. Step one of two. */
  const [acknowledged, setAcknowledged] = useState(false);
  const [typed, setTyped] = useState("");

  async function run() {
    setBusy(true);
    setError(null);
    try {
      let token: string | undefined;
      if (format === "plaintext_json") {
        // Step two: ask Rust for a single-use token. If this call is removed,
        // the export fails — which is the point.
        token = await ipc.beginPlaintextExport();
      }

      const path = await save({
        defaultPath:
          format === "plaintext_json"
            ? "keyring-PLAINTEXT-export.json"
            : "keyring-export.json",
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!path) {
        setBusy(false);
        return;
      }

      const summary = await ipc.runExport({
        format,
        path,
        folder: format === "folder_subset" ? folder : undefined,
        passphrase: format === "encrypted_json" ? passphrase : undefined,
        confirmationToken: token,
        includeAttachments,
      });

      setDone(
        `${summary.recordCount} records and ${summary.attachmentCount} attachments written to ${summary.path}.`,
      );
      setPassphrase("");
    } catch (e) {
      setError(asAppError(e).message);
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="mt-4 rounded-panel border border-edge p-4">
        <p className="text-base text-text font-ui">{done}</p>
        {format === "plaintext_json" && (
          <p className="mt-2 text-sm text-danger font-ui leading-relaxed">
            That file is not encrypted. Anyone who reads it has every credential
            in this vault. Move it somewhere you control and delete it as soon
            as you are finished with it.
          </p>
        )}
        <Button className="mt-3" onClick={onDone}>
          Done
        </Button>
      </div>
    );
  }

  const plaintextReady = acknowledged && typed.trim() === "I understand";
  const canRun =
    busy === false &&
    (format === "encrypted_json"
      ? passphrase.length >= 12
      : format === "folder_subset"
        ? folder.trim().length > 0
        : plaintextReady);

  return (
    <div className="mt-4 rounded-panel border border-edge p-4">
      <Label>Export as</Label>
      <div className="flex flex-wrap gap-2 mb-4">
        <Button
          variant={format === "encrypted_json" ? "primary" : "ghost"}
          onClick={() => setFormat("encrypted_json")}
        >
          Encrypted
        </Button>
        <Button
          variant={format === "folder_subset" ? "primary" : "ghost"}
          onClick={() => setFormat("folder_subset")}
        >
          One folder
        </Button>
        <Button
          variant={format === "plaintext_json" ? "primary" : "ghost"}
          onClick={() => setFormat("plaintext_json")}
        >
          Plaintext
        </Button>
      </div>

      {format === "encrypted_json" && (
        <div>
          <Label>Passphrase for the export file</Label>
          <Input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="At least 12 characters"
          />
          <p className="mt-2 text-sm text-text-faint font-ui">
            This is separate from your master password, and Keyring does not
            store it either. If you lose it, the export is unreadable.
          </p>
        </div>
      )}

      {format === "folder_subset" && (
        <div>
          <Label>Folder to export</Label>
          <Input
            value={folder}
            onChange={(e) => setFolder(e.target.value)}
            placeholder="clientA"
          />
          <p className="mt-2 text-sm text-text-faint font-ui">
            For handing one client their own credentials without handing over
            everything else.
          </p>
        </div>
      )}

      {format === "plaintext_json" && (
        <div className="space-y-4">
          <DangerBlock>
            <p className="flex items-start gap-2">
              <AlertTriangle size={16} className="text-danger shrink-0 mt-0.5" />
              <span>
                <strong>
                  This writes every password, key and token in this vault to an
                  unencrypted file.
                </strong>{" "}
                Anyone who opens it — or any backup tool, sync client or
                indexing service that touches it — gets all of it. There is no
                way to un-export something.
              </span>
            </p>
          </DangerBlock>

          <label className="flex items-start gap-2.5 text-sm text-text font-ui cursor-pointer">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              I understand this file is unencrypted and I am responsible for
              deleting it.
            </span>
          </label>

          {acknowledged && (
            <div>
              <Label>Type “I understand” to continue</Label>
              <Input
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                mono={false}
                autoComplete="off"
              />
            </div>
          )}

          <p className="text-sm text-text-faint font-ui leading-relaxed">
            This export is recorded in the activity log before the file is
            written.
          </p>
        </div>
      )}

      {format !== "plaintext_json" && (
        <label className="mt-4 flex items-center gap-2.5 text-sm text-text font-ui cursor-pointer">
          <input
            type="checkbox"
            checked={includeAttachments}
            onChange={(e) => setIncludeAttachments(e.target.checked)}
          />
          Include attachments
        </label>
      )}

      {error && <ErrorNote>{error}</ErrorNote>}

      <div className="mt-4 flex gap-2">
        <Button
          variant={format === "plaintext_json" ? "danger" : "primary"}
          onClick={run}
          disabled={!canRun}
        >
          {busy ? <Loader2 size={14} className="animate-spin" /> : "Export"}
        </Button>
        <Button variant="ghost" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
