import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { asAppError, ipc } from "../lib/ipc";
import type {
  RecordDetail,
  RecordSummary,
  RecordTypeInfo,
  Selection,
  SidebarData,
} from "../lib/types";

/**
 * Owns the record list, the current selection and the search query.
 *
 * Search and browse are the same list: when the query is empty the backend
 * filter runs, and when it is not, the in-memory index runs. Keeping them as
 * one list means the arrow keys, the detail pane and the shortcuts do not each
 * need two code paths.
 */
export function useRecords(unlocked: boolean) {
  const [selection, setSelection] = useState<Selection>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [records, setRecords] = useState<RecordSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<RecordDetail | null>(null);
  const [sidebar, setSidebar] = useState<SidebarData | null>(null);
  const [types, setTypes] = useState<RecordTypeInfo[]>([]);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Guards against an older search resolving after a newer one.
  const queryToken = useRef(0);

  const filterFor = useCallback((s: Selection) => {
    switch (s.kind) {
      case "favorites":
        return { favoritesOnly: true };
      case "trash":
        return { trash: true };
      case "type":
        return { recordType: s.key };
      case "folder":
        return { folder: s.key };
      case "tag":
        return { tag: s.key };
      default:
        return {};
    }
  }, []);

  const refresh = useCallback(async () => {
    if (!unlocked) return;
    try {
      const [list, side] = await Promise.all([
        ipc.listRecords(filterFor(selection)),
        ipc.sidebarData(),
      ]);
      setRecords(list);
      setSidebar(side);
      setError(null);

      // Folders are derived from record paths, so moving the last record out
      // of one makes it vanish. Without this the sidebar would keep a dead
      // folder selected and show an empty list with no explanation.
      if (selection.kind === "folder") {
        const stillExists = side.folders.some(
          (f) => f.key === selection.key || f.key.startsWith(`${selection.key}/`),
        );
        if (!stillExists) setSelection({ kind: "all" });
      }
      if (selection.kind === "tag" && !side.tags.some((t) => t.key === selection.key)) {
        setSelection({ kind: "all" });
      }
    } catch (e) {
      setError(asAppError(e).message);
    }
  }, [unlocked, selection, filterFor]);

  // Browsing.
  useEffect(() => {
    if (query.trim() === "") void refresh();
  }, [refresh, query]);

  // Searching. Debounced at 60 ms: the backend answers in well under 50 ms, so
  // anything longer is the UI being slow rather than the search.
  useEffect(() => {
    if (!unlocked || query.trim() === "") {
      setSearching(false);
      return undefined;
    }
    const token = ++queryToken.current;
    setSearching(true);

    const timer = window.setTimeout(async () => {
      try {
        const hits = await ipc.search(query, 200);
        if (token !== queryToken.current) return;

        // Search returns hits; the list wants summaries. Reuse what we have and
        // fetch the rest, preserving the ranked order.
        const known = new Map(records.map((r) => [r.id, r]));
        const resolved = await Promise.all(
          hits.map(async (hit) => {
            const cached = known.get(hit.recordId);
            if (cached) return cached;
            try {
              return (await ipc.getRecord(hit.recordId)).summary;
            } catch {
              return null;
            }
          }),
        );
        if (token !== queryToken.current) return;
        setRecords(resolved.filter((r): r is RecordSummary => r !== null));
      } catch (e) {
        setError(asAppError(e).message);
      } finally {
        if (token === queryToken.current) setSearching(false);
      }
    }, 60);

    return () => window.clearTimeout(timer);
    // `records` is deliberately excluded: including it would re-run the search
    // every time results arrive.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, unlocked]);

  // Keep the selection valid as the list changes.
  useEffect(() => {
    if (records.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !records.some((r) => r.id === selectedId)) {
      setSelectedId(records[0]?.id ?? null);
    }
  }, [records, selectedId]);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    ipc
      .getRecord(selectedId)
      .then(setDetail)
      .catch((e) => setError(asAppError(e).message));
  }, [selectedId]);

  useEffect(() => {
    if (!unlocked) {
      setRecords([]);
      setDetail(null);
      setSidebar(null);
      return;
    }
    ipc.recordTypes().then(setTypes).catch(() => setTypes([]));
  }, [unlocked]);

  /** Run a mutation, then reload the list and the open record. */
  const mutate = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        await refresh();
        if (selectedId) setDetail(await ipc.getRecord(selectedId).catch(() => null));
        setError(null);
      } catch (e) {
        setError(asAppError(e).message);
      }
    },
    [refresh, selectedId],
  );

  const emptyHint = useMemo(() => {
    if (query.trim() !== "") return "Nothing matches that.";
    if (selection.kind === "trash") return "Trash is empty.";
    if (selection.kind === "favorites") return "No favorites yet.";
    return "No records here yet. Press Ctrl N.";
  }, [query, selection]);

  return {
    selection,
    setSelection,
    query,
    setQuery,
    records,
    selectedId,
    setSelectedId,
    detail,
    sidebar,
    types,
    searching,
    error,
    clearError: () => setError(null),
    refresh,
    mutate,
    emptyHint,
  };
}
