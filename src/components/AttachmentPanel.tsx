/**
 * Attachments (FR-3.1 to FR-3.4).
 *
 * Until Phase 7 this could not exist: the vault crate could store attachments
 * and no IPC command exposed it, so files could be read and extracted but
 * never added from the interface.
 *
 * Preview reads text-like files into the webview without writing them to disk
 * (FR-3.4). Extract writes to a temp file with a deadline, which is the route
 * for anything binary or anything another program has to open.
 */

import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { Eye, FileUp, Loader2, Trash2 } from "lucide-react";

import { ipc, asAppError } from "../lib/ipc";
import type { AttachmentPreview, AttachmentView } from "../lib/types";
import { Button, ErrorNote } from "./ui";

function size(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function AttachmentPanel({
  recordId,
  attachments,
  readOnly,
  onChanged,
}: {
  recordId: string;
  attachments: AttachmentView[];
  readOnly: boolean;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<AttachmentPreview | null>(null);
  const [extracted, setExtracted] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  async function attach() {
    const picked = await open({ multiple: false });
    if (typeof picked !== "string") return;
    setBusy(true);
    setError(null);
    try {
      await ipc.addAttachment(recordId, picked);
      onChanged();
    } catch (e) {
      setError(asAppError(e).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-6">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm text-text-dim font-ui uppercase tracking-wide">
          Attachments
        </h3>
        {!readOnly && (
          <Button variant="ghost" onClick={attach} disabled={busy}>
            {busy ? (
              <Loader2 size={13} className="inline animate-spin mr-1.5" />
            ) : (
              <FileUp size={13} className="inline mr-1.5" strokeWidth={1.5} />
            )}
            Attach a file
          </Button>
        )}
      </div>

      {attachments.length === 0 && (
        <p className="text-sm text-text-faint font-ui">
          Nothing attached. PEM keys, service account JSON and certificates all
          live here, encrypted separately from the record.
        </p>
      )}

      <div className="space-y-1">
        {attachments.map((a) => (
          <div
            key={a.id}
            className="flex items-center justify-between gap-3 px-3 py-2
                       rounded-control border border-edge"
          >
            <div className="min-w-0">
              <p className="text-sm text-text font-data truncate">{a.filename}</p>
              <p className="text-xs text-text-faint font-ui">
                {size(a.sizeBytes)}
              </p>
            </div>

            <div className="flex gap-1 shrink-0">
              <Button
                variant="ghost"
                className="h-8 px-2"
                title="Read it here, without writing it to disk"
                onClick={async () => {
                  setError(null);
                  try {
                    setPreview(await ipc.previewAttachment(a.id));
                  } catch (e) {
                    setError(asAppError(e).message);
                  }
                }}
              >
                <Eye size={13} strokeWidth={1.5} />
              </Button>

              <Button
                variant="ghost"
                className="h-8 px-2 text-xs"
                onClick={async () => {
                  setError(null);
                  try {
                    const r = await ipc.extractAttachment(a.id);
                    setExtracted(r.path);
                  } catch (e) {
                    setError(asAppError(e).message);
                  }
                }}
              >
                Extract
              </Button>

              {!readOnly && (
                <Button
                  variant="ghost"
                  className="h-8 px-2"
                  onClick={() => setConfirmDelete(a.id)}
                >
                  <Trash2 size={13} strokeWidth={1.5} />
                </Button>
              )}
            </div>
          </div>
        ))}
      </div>

      {confirmDelete && (
        <div className="mt-3 rounded-panel border border-danger/60 bg-danger/[0.07] p-3">
          <p className="text-sm text-text font-ui">
            Delete this attachment permanently? It is not moved to the trash.
          </p>
          <div className="mt-2 flex gap-2">
            <Button
              variant="danger"
              onClick={async () => {
                try {
                  await ipc.removeAttachment(confirmDelete);
                  setConfirmDelete(null);
                  onChanged();
                } catch (e) {
                  setError(asAppError(e).message);
                }
              }}
            >
              Delete
            </Button>
            <Button variant="ghost" onClick={() => setConfirmDelete(null)}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {extracted && (
        <p className="mt-3 text-sm text-text-dim font-ui">
          Written to <span className="font-data break-all">{extracted}</span>.
          It is zeroed and deleted at its deadline, or when you lock.
        </p>
      )}

      {preview && (
        <div className="mt-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm text-text-dim font-data">
              {preview.filename}
            </span>
            <Button
              variant="ghost"
              className="h-7 px-2 text-xs"
              onClick={() => setPreview(null)}
            >
              Close
            </Button>
          </div>
          {preview.text !== null ? (
            <pre
              className="max-h-64 overflow-auto rounded-control bg-panel border border-edge
                         p-3 text-xs font-data text-text whitespace-pre-wrap break-all"
              data-selectable
            >
              {preview.text}
              {preview.truncated && "\n\n… truncated"}
            </pre>
          ) : (
            <p className="text-sm text-text-faint font-ui">
              {preview.reason ?? "This file is not text, so extract it instead."}
            </p>
          )}
        </div>
      )}

      {error && <ErrorNote>{error}</ErrorNote>}
    </div>
  );
}
