import { useEffect, useState } from "react";

import { iconFor } from "../lib/recordTypes";
import type { RecordTypeInfo } from "../lib/types";
import { Button, Input, Label } from "./ui";

/**
 * UC-06 gives this fifteen seconds. So: pick a type, type a name, fill what you
 * have, save. Every field is optional except the title, because a credential
 * you half-recorded beats one you put in a text file.
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
  /** Existing folders, offered as suggestions. Typing a new one creates it. */
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

  const selected = types.find((t) => t.key === typeKey) ?? null;

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onCancel();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  function save() {
    if (!selected || !title.trim()) return;
    const filled = Object.entries(values).filter(([, v]) => v.trim() !== "");
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
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/50 px-6">
      <div className="w-full max-w-[560px] max-h-[80vh] overflow-y-auto rounded-panel border border-edge bg-panel shadow-2xl">
        <header className="px-5 py-4 border-b border-edge">
          <h2 className="text-lg text-text">
            {selected ? `New ${selected.label.toLowerCase()}` : "What are you storing?"}
          </h2>
        </header>

        {!selected ? (
          <div className="p-5 grid grid-cols-3 gap-2">
            {types.map((t) => {
              const Icon = iconFor(t.key);
              return (
                <button
                  key={t.key}
                  onClick={() => setTypeKey(t.key)}
                  className="h-24 flex flex-col items-center justify-center gap-2 rounded-control border border-edge text-text-dim hover:border-accent hover:text-text transition-colors duration-100"
                >
                  <Icon size={20} strokeWidth={1.5} />
                  <span className="text-sm text-center px-2">{t.label}</span>
                </button>
              );
            })}
          </div>
        ) : (
          <div className="p-5">
            <Label>Title</Label>
            <Input
              autoFocus
              mono={false}
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="prod-web-01"
            />

            <div className="mt-4 grid grid-cols-2 gap-3">
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

            <div className="mt-5 space-y-3">
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
                    <Input
                      type={f.secret ? "password" : "text"}
                      autoComplete="off"
                      value={values[f.name] ?? ""}
                      onChange={(e) =>
                        setValues((v) => ({ ...v, [f.name]: e.target.value }))
                      }
                    />
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        <footer className="px-5 py-4 border-t border-edge flex gap-2">
          {selected && (
            <Button onClick={save} disabled={!title.trim()}>
              Save
            </Button>
          )}
          <Button variant="ghost" onClick={selected ? () => setTypeKey(null) : onCancel}>
            {selected ? "Back" : "Cancel"}
          </Button>
        </footer>
      </div>
    </div>
  );
}
