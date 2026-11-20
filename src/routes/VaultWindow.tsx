import { useEffect, useState } from "react";

import { CopilotDrawer } from "../components/CopilotDrawer";
import { DetailPane } from "../components/DetailPane";
import { NewRecordDialog } from "../components/NewRecordDialog";
import { RecordList } from "../components/RecordList";
import { Sidebar } from "../components/Sidebar";
import { Settings } from "./Settings";
import { ClipboardToast, useClipboardToast } from "../components/Toast";
import { useRecords } from "../hooks/useRecords";
import { ipc } from "../lib/ipc";
import type { VaultStatus } from "../lib/types";

/** The three-pane main window (UI Spec section 4). */
export function VaultWindow({
  status,
  copilotOpen,
  setCopilotOpen,
}: {
  status: VaultStatus;
  copilotOpen?: boolean;
  setCopilotOpen?: (open: boolean | ((prev: boolean) => boolean)) => void;
}) {
  const r = useRecords(!status.locked);
  const [creating, setCreating] = useState(false);
  const [initialRecordData, setInitialRecordData] = useState<{
    type?: string | null;
    title?: string;
    values?: Record<string, string>;
  } | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [localCopilotOpen, setLocalCopilotOpen] = useState(false);
  const toast = useClipboardToast();

  const isCopilotOpen = copilotOpen !== undefined ? copilotOpen : localCopilotOpen;
  const toggleCopilot = setCopilotOpen
    ? () => setCopilotOpen((v: boolean) => !v)
    : () => setLocalCopilotOpen((v) => !v);
  const closeCopilot = setCopilotOpen
    ? () => setCopilotOpen(false)
    : () => setLocalCopilotOpen(false);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const typing =
        e.target instanceof HTMLElement &&
        ["INPUT", "TEXTAREA"].includes(e.target.tagName);

      if (e.ctrlKey && e.key.toLowerCase() === "n") {
        e.preventDefault();
        setCreating(true);
      }
      if (e.ctrlKey && e.key.toLowerCase() === "j") {
        e.preventDefault();
        toggleCopilot();
      }
      if (e.ctrlKey && e.key === ",") {
        e.preventDefault();
        setShowSettings(true);
      }
      if (e.key === "Escape" && !typing) {
        if (isCopilotOpen) {
          closeCopilot();
        } else {
          setShowSettings(false);
        }
      }
      if (e.key === "/" && !typing) {
        e.preventDefault();
        document
          .querySelector<HTMLInputElement>('input[aria-label="Search records"]')
          ?.focus();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isCopilotOpen, toggleCopilot, closeCopilot]);

  const currentFolder = r.selection.kind === "folder" ? r.selection.key : "";

  if (showSettings) {
    return (
      <div className="flex-1 min-h-0">
        <Settings onClose={() => setShowSettings(false)} />
      </div>
    );
  }

  return (
    <div className="flex-1 flex min-h-0 relative">
      <Sidebar
        data={r.sidebar}
        selection={r.selection}
        onSelect={(s) => {
          r.setQuery("");
          r.setSelection(s);
        }}
        onOpenCopilot={toggleCopilot}
      />

      <RecordList
        records={r.records}
        selectedId={r.selectedId}
        query={r.query}
        searching={r.searching}
        onQueryChange={r.setQuery}
        onSelect={r.setSelectedId}
        emptyHint={r.emptyHint}
      />

      <DetailPane
        detail={r.detail}
        readOnly={status.readOnly}
        onEditField={(name, value) =>
          void r.mutate(() => ipc.setField(r.selectedId ?? "", name, value))
        }
        onToggleFavorite={() =>
          void r.mutate(() =>
            ipc.setFavorite(r.selectedId ?? "", !(r.detail?.summary.favorite ?? false)),
          )
        }
        onTrash={() => void r.mutate(() => ipc.trashRecord(r.selectedId ?? ""))}
        onRestore={() => void r.mutate(() => ipc.restoreRecord(r.selectedId ?? ""))}
        onPurge={() => void r.mutate(() => ipc.purgeRecord(r.selectedId ?? ""))}
        onDuplicate={() =>
          void r.mutate(() =>
            ipc.duplicateRecord(
              r.selectedId ?? "",
              `${r.detail?.summary.title ?? "Record"} copy`,
            ),
          )
        }
        onAddTag={(tag) => void r.mutate(() => ipc.addTag(r.selectedId ?? "", tag))}
        onRemoveTag={(tag) => void r.mutate(() => ipc.removeTag(r.selectedId ?? "", tag))}
        onCopied={toast.setStatus}
        folders={r.sidebar?.folders.map((f) => f.key) ?? []}
        onMoveToFolder={(folder) =>
          void r.mutate(() => ipc.moveRecord(r.selectedId ?? "", folder))
        }
      />

      {creating && (
        <NewRecordDialog
          types={r.types}
          defaultFolder={currentFolder}
          folders={r.sidebar?.folders.map((f) => f.key) ?? []}
          initialType={initialRecordData?.type}
          initialTitle={initialRecordData?.title}
          initialValues={initialRecordData?.values}
          onCancel={() => {
            setCreating(false);
            setInitialRecordData(null);
          }}
          onCreate={(type, title, folder, tags, values) => {
            setCreating(false);
            setInitialRecordData(null);
            void r.mutate(async () => {
              const id = await ipc.createRecord(type, title, folder, tags, values);
              r.setSelectedId(id);
            });
          }}
        />
      )}

      <CopilotDrawer
        isOpen={isCopilotOpen}
        onClose={closeCopilot}
        types={r.types}
        onOpenNewRecord={(type, values, title) => {
          setInitialRecordData({ type, values, title });
          setCreating(true);
        }}
        onOpenSettings={() => setShowSettings(true)}
        onSearch={(query) => r.setQuery(query)}
        onRecordCreated={(id) => {
          void r.mutate(async () => {
            r.setSelectedId(id);
          });
        }}
      />

      <ClipboardToast status={toast.status} onDismiss={toast.clear} />

      {r.error && (
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 px-4 py-2 rounded-control bg-panel border border-danger text-sm text-danger shadow-lg">
          {r.error}
          <button
            onClick={r.clearError}
            className="ml-3 text-text-dim hover:text-text"
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}
    </div>
  );
}
