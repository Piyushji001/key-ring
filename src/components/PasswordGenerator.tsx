/**
 * Password generator.
 *
 * The generated value is plaintext in JavaScript, which is a third crossing of
 * the trust boundary beyond `reveal_field` and TOTP codes. It is defensible
 * where those needed arguing: this value is microseconds old, stored nowhere,
 * and protects nothing until the user saves it. A generator whose output you
 * cannot see is not a generator.
 *
 * It is still handled carefully — cleared on unmount, never logged.
 */

import { useCallback, useEffect, useState } from "react";
import { Check, Copy, RefreshCw } from "lucide-react";

import { ipc, asAppError } from "../lib/ipc";
import type { GeneratedPassword } from "../lib/types";
import { Button, ErrorNote, Label } from "./ui";

export function PasswordGenerator({
  onUse,
}: {
  onUse?: (value: string) => void;
}) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(24);
  const [words, setWords] = useState(5);
  const [symbols, setSymbols] = useState(true);
  const [digits, setDigits] = useState(true);
  const [uppercase, setUppercase] = useState(true);
  const [result, setResult] = useState<GeneratedPassword | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const generate = useCallback(async () => {
    setError(null);
    try {
      setResult(
        mode === "password"
          ? await ipc.generatePassword({
              length,
              lowercase: true,
              uppercase,
              digits,
              symbols,
            })
          : await ipc.generatePassphrase({
              words,
              separator: "-",
              includeNumber: digits,
            }),
      );
    } catch (e) {
      setError(asAppError(e).message);
    }
  }, [mode, length, words, symbols, digits, uppercase]);

  useEffect(() => {
    void generate();
  }, [generate]);

  // Do not leave the value sitting in state after the panel closes.
  useEffect(() => () => setResult(null), []);

  return (
    <div className="rounded-panel border border-edge p-4">
      <div className="flex gap-2 mb-4">
        <Button
          variant={mode === "password" ? "primary" : "ghost"}
          onClick={() => setMode("password")}
        >
          Random
        </Button>
        <Button
          variant={mode === "passphrase" ? "primary" : "ghost"}
          onClick={() => setMode("passphrase")}
        >
          Passphrase
        </Button>
      </div>

      {result && (
        <div className="mb-4">
          <div
            className="px-3 py-3 rounded-control bg-panel border border-edge
                       font-data text-base text-text break-all select-all"
            data-selectable
          >
            {result.value}
          </div>
          <p className="mt-2 text-sm text-text-faint font-ui">
            {Math.round(result.entropyBits)} bits · {result.strengthNote}
          </p>
        </div>
      )}

      {mode === "password" ? (
        <div className="space-y-3">
          <div>
            <Label>Length: {length}</Label>
            <input
              type="range"
              min={12}
              max={64}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              className="w-full accent-accent"
            />
          </div>
          <div className="flex flex-wrap gap-4 text-sm text-text font-ui">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={uppercase}
                onChange={(e) => setUppercase(e.target.checked)}
              />
              A-Z
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={digits}
                onChange={(e) => setDigits(e.target.checked)}
              />
              0-9
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={symbols}
                onChange={(e) => setSymbols(e.target.checked)}
              />
              Symbols
            </label>
          </div>
        </div>
      ) : (
        <div>
          <Label>Words: {words}</Label>
          <input
            type="range"
            min={3}
            max={10}
            value={words}
            onChange={(e) => setWords(Number(e.target.value))}
            className="w-full accent-accent"
          />
          <p className="mt-1 text-sm text-text-faint font-ui">
            Easier to type on a phone or read down to someone. Length is doing
            the work, not the symbols.
          </p>
        </div>
      )}

      {error && <ErrorNote>{error}</ErrorNote>}

      <div className="mt-4 flex gap-2">
        <Button variant="ghost" onClick={generate}>
          <RefreshCw size={14} className="inline mr-1.5" strokeWidth={1.5} />
          Again
        </Button>
        {result && (
          <Button
            variant="ghost"
            onClick={async () => {
              await navigator.clipboard.writeText(result.value);
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? (
              <Check size={14} className="inline mr-1.5" />
            ) : (
              <Copy size={14} className="inline mr-1.5" strokeWidth={1.5} />
            )}
            Copy
          </Button>
        )}
        {result && onUse && (
          <Button onClick={() => onUse(result.value)}>Use this</Button>
        )}
      </div>

      <p className="mt-3 text-xs text-text-faint font-ui leading-relaxed">
        Copying here uses the ordinary clipboard, not Keyring's protected one —
        it will appear in Windows clipboard history. Save the value to a record
        and copy it from there if that matters.
      </p>
    </div>
  );
}
