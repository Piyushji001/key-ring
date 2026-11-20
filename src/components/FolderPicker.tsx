import { useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, FolderOpen, FolderX } from "lucide-react";

/**
 * Move a record into a folder, or out of one.
 *
 * ## How folders work here, and why there is no "create folder" button
 *
 * A folder is not a stored object. It is just the `folder` string on a record,
 * and the sidebar derives the folder list by grouping records by that value.
 *
 * The consequence, which is worth understanding before it surprises you: a
 * folder exists the moment a record names it, and stops existing when the last
 * record leaves. There are no empty folders. That is deliberate - an empty
 * folder in a credential vault is a piece of filing you did once and will never
 * look at again.
 *
 * So "create a folder" is "type a name here", and "delete a folder" is "move
 * everything out of it". Nesting is a `/` in the name: `clients/acme/prod`.
 */
export function FolderPicker({
  current,
  folders,
  disabled,
  onMove,
}: {
  current: string;
  /** Every folder that currently exists, from the sidebar counts. */
  folders: string[];
  disabled: boolean;
  onMove: (folder: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(current);
  const container = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => setDraft(current), [current]);

  useEffect(() => {
    if (!open) return undefined;
    window.setTimeout(() => input.current?.select(), 10);

    function onClickAway(e: MouseEvent) {
      if (!container.current?.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickAway);
    return () => document.removeEventListener("mousedown", onClickAway);
  }, [open]);

  // Suggestions include every parent path, so typing "clients" offers
  // "clients/acme" and "clients/acme/prod" as well.
  const suggestions = useMemo(() => {
    const all = new Set<string>();
    for (const folder of folders) {
      const parts = folder.split("/");
      for (let i = 1; i <= parts.length; i++) {
        all.add(parts.slice(0, i).join("/"));
      }
    }
    const needle = draft.trim().toLowerCase();
    return [...all]
      .filter((f) => f && f.toLowerCase().includes(needle))
      .sort()
      .slice(0, 8);
  }, [folders, draft]);

  const normalised = draft.trim().replace(/^\/+|\/+$/g, "");
  const isNew = normalised !== "" && !suggestions.includes(normalised);

  function apply(folder: string) {
    setOpen(false);
    const cleaned = folder.trim().replace(/^\/+|\/+$/g, "");
    if (cleaned !== current) onMove(cleaned);
  }

  if (disabled) {
    return (
      <span className="text-sm text-text-dim">
        {current || "No folder"}
      </span>
    );
  }

  return (
    <div ref={container} className="relative inline-block">
      <button
        onClick={() => setOpen((o) => !o)}
        className="h-6 px-2 -ml-2 inline-flex items-center gap-1.5 rounded-control text-sm text-text-dim hover:text-text hover:bg-panel-hi transition-colors duration-100"
        title="Move to a folder"
      >
        {current ? (
          <FolderOpen size={13} strokeWidth={1.5} />
        ) : (
          <FolderX size={13} strokeWidth={1.5} className="text-text-faint" />
        )}
        <span className={current ? "" : "text-text-faint italic"}>
          {current || "No folder"}
        </span>
        <ChevronDown size={12} strokeWidth={1.5} className="opacity-60" />
      </button>

      {open && (
        <div className="absolute z-40 mt-1 w-[300px] rounded-panel border border-edge bg-panel shadow-2xl overflow-hidden">
          <div className="p-2 border-b border-edge">
            <input
              ref={input}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  apply(draft);
                }
                if (e.key === "Escape") {
                  e.preventDefault();
                  setOpen(false);
                }
              }}
              placeholder="clients/acme/prod"
              aria-label="Folder path"
              className="w-full h-8 px-2 rounded-control bg-void border border-edge font-data text-sm text-text focus:outline-none focus:border-accent"
            />
            <p className="mt-1.5 px-0.5 text-xs text-text-faint">
              Use <span className="font-data">/</span> to nest. Enter to apply.
            </p>
          </div>

          <div className="max-h-[220px] overflow-y-auto py-1">
            {current !== "" && (
              <Option
                onClick={() => apply("")}
                icon={<FolderX size={13} strokeWidth={1.5} />}
                label="Remove from folder"
                muted
              />
            )}

            {isNew && (
              <Option
                onClick={() => apply(normalised)}
                icon={<FolderOpen size={13} strokeWidth={1.5} className="text-accent" />}
                label={`Create "${normalised}"`}
              />
            )}

            {suggestions.map((folder) => (
              <Option
                key={folder}
                onClick={() => apply(folder)}
                icon={<FolderOpen size={13} strokeWidth={1.5} />}
                label={folder}
                selected={folder === current}
              />
            ))}

            {suggestions.length === 0 && !isNew && current === "" && (
              <p className="px-3 py-2 text-xs text-text-faint">
                No folders yet. Type a name to make one.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Option({
  onClick,
  icon,
  label,
  selected = false,
  muted = false,
}: {
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  selected?: boolean;
  muted?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full px-3 py-1.5 flex items-center gap-2 text-left text-sm transition-colors duration-100 hover:bg-panel-hi ${
        muted ? "text-text-faint" : "text-text-dim hover:text-text"
      }`}
    >
      <span className="shrink-0">{icon}</span>
      <span className="flex-1 truncate font-data text-xs">{label}</span>
      {selected && <Check size={13} strokeWidth={2} className="text-accent shrink-0" />}
    </button>
  );
}
