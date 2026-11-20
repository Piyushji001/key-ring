import { useState } from "react";
import {
  ArchiveRestore,
  Copy as CopyIcon,
  Star,
  Trash2,
} from "lucide-react";

import { iconFor, relativeTime } from "../lib/recordTypes";
import type { ClipboardStatus, RecordDetail } from "../lib/types";
import { ActionBar } from "./ActionBar";
import { AttachmentPanel } from "./AttachmentPanel";
import { ConnectBar } from "./ConnectBar";
import { FolderPicker } from "./FolderPicker";
import { FieldRow } from "./SecretField";
import { TotpField } from "./TotpField";
import { Button } from "./ui";

/** Right pane. Empty state is a hint, not an apology. */
export function DetailPane({
  detail,
  readOnly,
  onEditField,
  onToggleFavorite,
  onTrash,
  onRestore,
  onPurge,
  onDuplicate,
  onAddTag,
  onRemoveTag,
  onCopied,
  onMoveToFolder,
  onChanged,
  folders,
}: {
  detail: RecordDetail | null;
  readOnly: boolean;
  onEditField: (name: string, value: string) => void;
  onToggleFavorite: () => void;
  onTrash: () => void;
  onRestore: () => void;
  onPurge: () => void;
  onDuplicate: () => void;
  onAddTag: (tag: string) => void;
  onRemoveTag: (tag: string) => void;
  onCopied: (status: ClipboardStatus) => void;
  /** Reload the record after an attachment changed. */
  onChanged?: () => void;
  onMoveToFolder: (folder: string) => void;
  /** Every folder that currently exists, for the picker's suggestions. */
  folders: string[];
}) {
  const [newTag, setNewTag] = useState("");
  const [confirmPurge, setConfirmPurge] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);


  if (!detail) {
    return (
      <section className="flex-1 grid place-items-center text-sm text-text-faint">
        Select a record, or press Ctrl N to create one.
      </section>
    );
  }

  const { summary } = detail;
  const Icon = iconFor(summary.recordType);
  const populated = detail.fields.filter((f) => f.hasValue);
  const hasTotp = detail.fields.some((f) => f.name === "totp_secret" && f.hasValue);
  const empty = detail.fields.filter((f) => !f.hasValue);

  return (
    <section className="flex-1 h-full overflow-y-auto">
      <header className="px-6 pt-5 pb-4 border-b border-edge">
        <div className="flex items-start gap-3">
          <Icon size={20} strokeWidth={1.5} className="mt-1 text-accent shrink-0" />
          <div className="min-w-0 flex-1">
            <h1 className="text-xl text-text truncate" data-selectable>
              {summary.title}
            </h1>
            <p className="mt-0.5 flex items-center gap-1.5 text-sm text-text-dim">
              <span>{summary.typeLabel}</span>
              <span className="text-text-faint" aria-hidden>
                ·
              </span>
              <FolderPicker
                current={summary.folder}
                folders={folders}
                disabled={readOnly || summary.inTrash}
                onMove={onMoveToFolder}
              />
            </p>
          </div>
          <button
            onClick={onToggleFavorite}
            aria-label={summary.favorite ? "Remove from favorites" : "Add to favorites"}
            className="h-8 w-8 grid place-items-center rounded-control text-text-dim hover:bg-panel-hi transition-colors duration-100"
          >
            <Star
              size={16}
              strokeWidth={1.5}
              className={summary.favorite ? "text-accent fill-current" : ""}
            />
          </button>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          {summary.tags.map((tag) => (
            <button
              key={tag}
              onClick={() => onRemoveTag(tag)}
              title="Remove tag"
              className="px-2 py-0.5 rounded-tag bg-panel-hi border border-edge text-xs text-text-dim hover:border-danger hover:text-danger transition-colors duration-100"
            >
              {tag}
            </button>
          ))}
          {!readOnly && (
            <input
              value={newTag}
              onChange={(e) => setNewTag(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && newTag.trim()) {
                  onAddTag(newTag.trim());
                  setNewTag("");
                }
              }}
              placeholder="+ tag"
              className="w-20 px-2 py-0.5 rounded-tag bg-transparent border border-dashed border-edge text-xs text-text placeholder:text-text-faint focus:outline-none focus:border-accent"
            />
          )}
        </div>
      </header>

      <ActionBar
        detail={detail}
        disabled={readOnly || summary.inTrash}
        onResult={setActionMessage}
      />

      {actionMessage && (
        <p className="px-6 py-2 text-xs text-text-dim border-b border-edge" data-selectable>
          {actionMessage}
        </p>
      )}

      <div className="px-6 py-2">
        {hasTotp && <TotpField recordId={summary.id} onCopied={onCopied} />}
        {populated
          .filter((f) => f.name !== "totp_secret")
          .map((field) => (
            <FieldRow
              key={field.name}
              recordId={summary.id}
              field={field}
              readOnly={readOnly}
              onEdit={onEditField}
              onCopied={onCopied}
            />
          ))}
      </div>

      {empty.length > 0 && !readOnly && (
        <details className="px-6 py-2 border-t border-edge">
          <summary className="text-sm text-text-dim cursor-pointer hover:text-text">
            {empty.length} empty {empty.length === 1 ? "field" : "fields"}
          </summary>
          <div className="mt-2">
            {empty.map((field) => (
              <FieldRow
                key={field.name}
                recordId={summary.id}
                field={field}
                readOnly={readOnly}
                onEdit={onEditField}
                onCopied={onCopied}
              />
            ))}
          </div>
        </details>
      )}

      {/* Phase 7.5: one-click connect. Renders only for SSH and cloud
          records, and gates itself on what is actually installed. */}
      <div className="px-6">
        <ConnectBar
          detail={detail}
          readOnly={readOnly}
          onResult={(message) => setNotice(message)}
        />
      </div>

      {notice && (
        <p className="px-6 pt-2 text-sm text-text-dim font-ui">{notice}</p>
      )}

      {/* Phase 7: attachments can finally be added from the interface. */}
      <div className="px-6 py-4 border-t border-edge">
        <AttachmentPanel
          recordId={summary.id}
          attachments={detail.attachments}
          readOnly={readOnly}
          onChanged={() => onChanged?.()}
        />
      </div>

      <footer className="px-6 py-4 border-t border-edge flex flex-wrap items-center gap-2">
        {summary.inTrash ? (
          <>
            <Button variant="ghost" onClick={onRestore}>
              <ArchiveRestore size={14} strokeWidth={1.5} className="inline mr-1.5" />
              Restore
            </Button>
            {confirmPurge ? (
              <Button variant="danger" onClick={onPurge}>
                Delete permanently — no undo
              </Button>
            ) : (
              <Button variant="ghost" onClick={() => setConfirmPurge(true)}>
                Delete permanently
              </Button>
            )}
          </>
        ) : (
          !readOnly && (
            <>
              <Button variant="ghost" onClick={onDuplicate}>
                <CopyIcon size={14} strokeWidth={1.5} className="inline mr-1.5" />
                Duplicate
              </Button>
              <Button variant="ghost" onClick={onTrash}>
                <Trash2 size={14} strokeWidth={1.5} className="inline mr-1.5" />
                Move to trash
              </Button>
            </>
          )
        )}

        <span className="flex-1" />
        <span className="text-xs text-text-faint">
          used {relativeTime(summary.usedAt)} · {summary.useCount}×
        </span>
      </footer>
    </section>
  );
}
