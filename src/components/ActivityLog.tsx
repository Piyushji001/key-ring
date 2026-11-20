/**
 * Activity log viewer.
 *
 * The log lives inside the encrypted container, which protects it at rest —
 * but it is also the one table designed to be read back in bulk. That is
 * exactly why the backend never writes a field value into it. This component
 * renders `description` and `detail` verbatim on the assumption that the
 * backend held that line; if you ever find a credential rendered here, the bug
 * is in `db/activity.rs`, not in this file.
 */

import { useCallback, useEffect, useState } from "react";
import { AlertCircle, Loader2 } from "lucide-react";

import { ipc, asAppError } from "../lib/ipc";
import type { LogEntry } from "../lib/types";
import { Button, ErrorNote } from "./ui";

function when(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ActivityLog() {
  const [entries, setEntries] = useState<LogEntry[] | null>(null);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [confirmingClear, setConfirmingClear] = useState(false);
  const [limit, setLimit] = useState(50);

  const load = useCallback(async () => {
    try {
      const [rows, count] = await Promise.all([
        ipc.activityLog(limit),
        ipc.activityCount(),
      ]);
      setEntries(rows);
      setTotal(count);
      setError(null);
    } catch (e) {
      setError(asAppError(e).message);
    }
  }, [limit]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) return <ErrorNote>{error}</ErrorNote>;

  if (!entries) {
    return (
      <div className="py-6 text-text-faint">
        <Loader2 size={16} className="animate-spin" />
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <p className="py-4 text-sm text-text-faint font-ui">
        Nothing recorded yet.
      </p>
    );
  }

  return (
    <div>
      <div className="rounded-panel border border-edge divide-y divide-edge max-h-96 overflow-y-auto">
        {entries.map((entry) => (
          <div
            key={entry.id}
            className="flex items-start gap-3 px-3 py-2 text-sm"
          >
            {entry.notable && (
              <AlertCircle
                size={14}
                className="text-warn shrink-0 mt-0.5"
                aria-label="Notable event"
              />
            )}
            <div className="min-w-0 flex-1">
              <p
                className={`font-ui ${
                  entry.notable ? "text-text font-medium" : "text-text-dim"
                }`}
              >
                {entry.description}
                {entry.recordTitle && (
                  <span className="text-text-faint"> — {entry.recordTitle}</span>
                )}
              </p>
              {entry.detail && (
                <p className="text-xs text-text-faint font-data mt-0.5 break-all">
                  {entry.detail}
                </p>
              )}
            </div>
            <span className="text-xs text-text-faint font-ui shrink-0 tabular-nums">
              {when(entry.at)}
            </span>
          </div>
        ))}
      </div>

      <div className="mt-3 flex items-center justify-between">
        <span className="text-sm text-text-faint font-ui">
          Showing {entries.length} of {total}
        </span>
        <div className="flex gap-2">
          {entries.length < total && (
            <Button variant="ghost" onClick={() => setLimit((l) => l + 200)}>
              Show more
            </Button>
          )}
          {confirmingClear ? (
            <>
              <Button
                variant="danger"
                onClick={async () => {
                  try {
                    await ipc.clearActivityLog();
                    setConfirmingClear(false);
                    await load();
                  } catch (e) {
                    setError(asAppError(e).message);
                  }
                }}
              >
                Erase permanently
              </Button>
              <Button variant="ghost" onClick={() => setConfirmingClear(false)}>
                Cancel
              </Button>
            </>
          ) : (
            <Button variant="ghost" onClick={() => setConfirmingClear(true)}>
              Clear log
            </Button>
          )}
        </div>
      </div>

      {confirmingClear && (
        <p className="mt-2 text-sm text-text-faint font-ui">
          The erasure itself is recorded. A log that can be silently emptied is
          not a log.
        </p>
      )}
    </div>
  );
}
