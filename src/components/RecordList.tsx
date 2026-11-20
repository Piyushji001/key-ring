import clsx from "clsx";
import { Paperclip, Search, Star } from "lucide-react";

import { iconFor, relativeTime } from "../lib/recordTypes";
import type { RecordSummary } from "../lib/types";
import { Input, Kbd } from "./ui";

/**
 * Middle pane. Two lines per row: title, then a non-secret identifying line.
 *
 * The subtitle is assembled in Rust from plaintext fields only - see
 * `subtitle_for` in record_cmds.rs. The frontend could not build it even if it
 * wanted to, because it never receives the secret fields.
 */
export function RecordList({
  records,
  selectedId,
  query,
  searching,
  onQueryChange,
  onSelect,
  emptyHint,
}: {
  records: RecordSummary[];
  selectedId: string | null;
  query: string;
  searching: boolean;
  onQueryChange: (q: string) => void;
  onSelect: (id: string) => void;
  emptyHint: string;
}) {
  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const index = records.findIndex((r) => r.id === selectedId);
    const next =
      e.key === "ArrowDown"
        ? Math.min(index + 1, records.length - 1)
        : Math.max(index - 1, 0);
    const record = records[next];
    if (record) onSelect(record.id);
  }

  return (
    <section
      className="w-[340px] shrink-0 h-full flex flex-col border-r border-edge bg-void"
      onKeyDown={onKeyDown}
    >
      <div className="p-3 border-b border-edge">
        <div className="relative">
          <Search
            size={14}
            strokeWidth={1.5}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-text-faint pointer-events-none"
            aria-hidden
          />
          <Input
            mono={false}
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            placeholder="Search  ·  type: folder: tag:"
            className="pl-9 h-9"
            aria-label="Search records"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto" role="listbox" aria-label="Records">
        {records.length === 0 ? (
          <p className="p-6 text-sm text-text-faint text-center">
            {searching ? "Searching…" : emptyHint}
          </p>
        ) : (
          records.map((record) => (
            <Row
              key={record.id}
              record={record}
              selected={record.id === selectedId}
              onSelect={() => onSelect(record.id)}
            />
          ))
        )}
      </div>

      <footer className="h-8 shrink-0 px-3 flex items-center gap-3 border-t border-edge text-xs text-text-faint">
        <span>{records.length} shown</span>
        <span className="flex-1" />
        <Kbd>Ctrl N</Kbd>
        <span>new</span>
      </footer>
    </section>
  );
}

function Row({
  record,
  selected,
  onSelect,
}: {
  record: RecordSummary;
  selected: boolean;
  onSelect: () => void;
}) {
  const Icon = iconFor(record.recordType);

  return (
    <button
      role="option"
      aria-selected={selected}
      onClick={onSelect}
      className={clsx(
        "w-full px-3 py-2.5 flex gap-3 text-left border-l-2 transition-colors duration-100",
        selected
          ? "bg-panel-hi border-accent"
          : "border-transparent hover:bg-panel",
      )}
    >
      <Icon
        size={16}
        strokeWidth={1.5}
        className={clsx("mt-0.5 shrink-0", selected ? "text-accent" : "text-text-faint")}
      />

      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="truncate text-base text-text">{record.title}</span>
          {record.favorite && (
            <Star size={11} className="shrink-0 text-accent fill-current" aria-label="Favorite" />
          )}
          {record.attachmentCount > 0 && (
            <Paperclip size={11} className="shrink-0 text-text-faint" aria-hidden />
          )}
        </span>
        <span className="block truncate font-data text-xs text-text-dim mt-0.5">
          {record.subtitle ?? record.typeLabel}
        </span>
      </span>

      <span className="shrink-0 text-xs text-text-faint self-center">
        {relativeTime(record.usedAt)}
      </span>
    </button>
  );
}
