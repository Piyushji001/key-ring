import clsx from "clsx";
import { Folder, Hash, Star, Trash2, Layers, LucideIcon, Sparkles } from "lucide-react";

import { iconFor } from "../lib/recordTypes";
import type { Selection, SidebarData } from "../lib/types";

/**
 * Left pane: folders, tags and type filters (UI Spec section 4).
 *
 * Counts are shown because "SSH servers 68" answers a question the user did
 * not know they had, and because an empty section that shows 0 is a section
 * that should not be drawn at all.
 */
export function Sidebar({
  data,
  selection,
  onSelect,
  onOpenCopilot,
}: {
  data: SidebarData | null;
  selection: Selection;
  onSelect: (s: Selection) => void;
  onOpenCopilot?: () => void;
}) {
  const isActive = (s: Selection) =>
    s.kind === selection.kind &&
    ("key" in s && "key" in selection ? s.key === selection.key : true);

  return (
    <nav className="w-[240px] shrink-0 h-full flex flex-col justify-between bg-panel border-r border-edge py-3">
      <div className="flex-1 overflow-y-auto min-h-0">
        <Section>
          <Item
            icon={Layers}
            label="All records"
            count={data?.total}
            active={isActive({ kind: "all" })}
            onClick={() => onSelect({ kind: "all" })}
          />
          <Item
            icon={Star}
            label="Favorites"
            count={data?.favorites}
            active={isActive({ kind: "favorites" })}
            onClick={() => onSelect({ kind: "favorites" })}
          />
          <Item
            icon={Trash2}
            label="Trash"
            count={data?.trash}
            active={isActive({ kind: "trash" })}
            onClick={() => onSelect({ kind: "trash" })}
          />
        </Section>

        {data && data.types.length > 0 && (
          <Section title="Types">
            {data.types.map((t) => (
              <Item
                key={t.key}
                icon={iconFor(t.key)}
                label={t.label}
                count={t.count}
                active={isActive({ kind: "type", key: t.key })}
                onClick={() => onSelect({ kind: "type", key: t.key })}
              />
            ))}
          </Section>
        )}

        {data && data.folders.length > 0 && (
          <Section title="Folders">
            {data.folders.map((f) => (
              <Item
                key={f.key}
                icon={Folder}
                label={f.label}
                count={f.count}
                indent={f.key.split("/").length - 1}
                active={isActive({ kind: "folder", key: f.key })}
                onClick={() => onSelect({ kind: "folder", key: f.key })}
              />
            ))}
          </Section>
        )}

        {data && data.tags.length > 0 && (
          <Section title="Tags">
            {data.tags.map((t) => (
              <Item
                key={t.key}
                icon={Hash}
                label={t.label}
                count={t.count}
                active={isActive({ kind: "tag", key: t.key })}
                onClick={() => onSelect({ kind: "tag", key: t.key })}
              />
            ))}
          </Section>
        )}
      </div>

      {onOpenCopilot && (
        <div className="pt-2 px-3 border-t border-edge">
          <button
            onClick={onOpenCopilot}
            className="w-full h-8 px-2.5 flex items-center gap-2 rounded-control text-xs font-medium text-accent hover:bg-accent/15 border border-accent/25 hover:border-accent/40 transition-colors"
            title="Open Keyring Copilot (Ctrl+J)"
          >
            <Sparkles size={14} className="text-accent" />
            <span>Keyring Copilot</span>
            <span className="ml-auto text-[10px] text-text-faint font-data">Ctrl J</span>
          </button>
        </div>
      )}
    </nav>
  );
}

function Section({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      {title && (
        <h2 className="px-4 mb-1 text-xs uppercase tracking-wider text-text-faint">
          {title}
        </h2>
      )}
      {children}
    </div>
  );
}

function Item({
  icon: Icon,
  label,
  count,
  active,
  onClick,
  indent = 0,
}: {
  icon: LucideIcon;
  label: string;
  count?: number;
  active: boolean;
  onClick: () => void;
  indent?: number;
}) {
  return (
    <button
      onClick={onClick}
      style={{ paddingLeft: 16 + indent * 12 }}
      className={clsx(
        "w-full h-8 pr-3 flex items-center gap-2.5 text-sm transition-colors duration-100",
        active
          ? "bg-panel-hi text-text border-l-2 border-accent"
          : "text-text-dim hover:bg-panel-hi hover:text-text border-l-2 border-transparent",
      )}
    >
      <Icon size={15} strokeWidth={1.5} className={active ? "text-accent" : ""} />
      <span className="flex-1 text-left truncate" title={label}>
        {label}
      </span>
      {count !== undefined && count > 0 && (
        <span className="font-data text-xs text-text-faint">{count}</span>
      )}
    </button>
  );
}
