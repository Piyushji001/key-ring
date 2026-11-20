import { useEffect, useState } from "react";
import { open as openFolder } from "@tauri-apps/plugin-dialog";

import {
  Button,
  DangerBlock,
  ErrorNote,
  Input,
  Label,
  StrengthMeter,
} from "../components/ui";
import { ipc } from "../lib/ipc";
import type { AppError, CalibrationResult, PasswordAssessment } from "../lib/types";

/**
 * Four-step first-run wizard. This is the only place the application is allowed
 * to be slow and wordy, because the decisions here are permanent.
 */
type Step = 1 | 2 | 3 | 4;

const STEP_LABELS: Record<Step, string> = {
  1: "Welcome",
  2: "Location",
  3: "Master password",
  4: "Unlock speed",
};

const STRENGTH_HINTS = [
  "Too short. Twelve characters minimum.",
  "Weak. Add length rather than symbols.",
  "Fair. A few more words would help.",
  "Good.",
  "Strong.",
];

export function Setup({
  busy,
  error,
  onCreate,
  onCancel,
}: {
  busy: boolean;
  error: AppError | null;
  onCreate: (path: string, password: string, targetMs: number) => Promise<boolean>;
  onCancel: () => void;
}) {
  const [step, setStep] = useState<Step>(1);
  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [acknowledged, setAcknowledged] = useState("");
  const [assessment, setAssessment] = useState<PasswordAssessment | null>(null);
  const [targetMs, setTargetMs] = useState(1000);
  const [calibration, setCalibration] = useState<CalibrationResult | null>(null);
  const [calibrating, setCalibrating] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Strength scoring happens in Rust, so the same logic serves any future CLI
  // or importer. Debounced: it is cheap, but not free.
  useEffect(() => {
    if (password.length === 0) {
      setAssessment(null);
      return undefined;
    }
    const t = window.setTimeout(() => {
      ipc.assessPassword(password).then(setAssessment).catch(() => setAssessment(null));
    }, 120);
    return () => window.clearTimeout(t);
  }, [password]);

  async function pickFolder() {
    const chosen = await openFolder({
      directory: true,
      multiple: false,
      title: "Where should the vault live?",
    });
    if (typeof chosen !== "string") return;

    if (await ipc.vaultExists(chosen)) {
      setLocalError("A vault already exists in that folder. Choose another, or open it instead.");
      return;
    }
    setLocalError(null);
    setPath(chosen);
  }

  async function runCalibration(ms: number) {
    setCalibrating(true);
    try {
      setCalibration(await ipc.calibrateKdf(ms));
    } catch {
      setCalibration(null);
    } finally {
      setCalibrating(false);
    }
  }

  useEffect(() => {
    if (step === 4) void runCalibration(targetMs);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  const passwordsMatch = password.length > 0 && password === confirm;
  const canLeaveStep3 =
    passwordsMatch &&
    (assessment?.meetsMinimum ?? false) &&
    acknowledged.trim().toLowerCase() === "i understand";

  return (
    <main className="flex-1 overflow-y-auto px-6 py-10">
      <div className="mx-auto w-full max-w-[520px]">
        <ol className="flex items-center gap-2 mb-8 text-xs font-ui" aria-label="Progress">
          {([1, 2, 3, 4] as Step[]).map((n) => (
            <li key={n} className="flex items-center gap-2">
              <span
                className={`grid place-items-center h-5 w-5 rounded-full border text-[10px] ${
                  n === step
                    ? "border-accent text-accent"
                    : n < step
                      ? "border-accent bg-accent text-void"
                      : "border-edge text-text-faint"
                }`}
              >
                {n}
              </span>
              <span className={n === step ? "text-text" : "text-text-faint"}>
                {STEP_LABELS[n]}
              </span>
              {n < 4 && <span className="w-4 h-px bg-edge" aria-hidden />}
            </li>
          ))}
        </ol>

        {step === 1 && (
          <section>
            <h1 className="text-xl font-medium text-text">Keyring</h1>
            <p className="mt-3 text-base text-text-dim leading-relaxed">
              Keyring stores your credentials in a single encrypted file on this
              computer. It has no network access.
            </p>
            <div className="mt-8 flex gap-3">
              <Button onClick={() => setStep(2)}>Create a vault</Button>
              <Button variant="ghost" onClick={onCancel}>
                Open an existing vault
              </Button>
            </div>
          </section>
        )}

        {step === 2 && (
          <section>
            <h1 className="text-xl font-medium text-text">Where should the vault live?</h1>
            <p className="mt-3 text-sm text-text-dim">
              Pick a folder your backup tool already watches, or configure backups
              later.
            </p>

            <div className="mt-6">
              <Label>Vault folder</Label>
              <div className="flex gap-2">
                <Input
                  value={path}
                  readOnly
                  placeholder="No folder chosen"
                  aria-label="Vault folder"
                />
                <Button variant="ghost" onClick={() => void pickFolder()}>
                  Browse
                </Button>
              </div>
              {path && (
                <p className="mt-2 text-xs text-text-faint font-data">
                  {path}\vault.kr
                </p>
              )}
              {localError && <ErrorNote>{localError}</ErrorNote>}
            </div>

            <div className="mt-8 flex gap-3">
              <Button onClick={() => setStep(3)} disabled={!path}>
                Continue
              </Button>
              <Button variant="ghost" onClick={() => setStep(1)}>
                Back
              </Button>
            </div>
          </section>
        )}

        {step === 3 && (
          <section>
            <h1 className="text-xl font-medium text-text">Choose a master password</h1>
            <p className="mt-3 text-sm text-text-dim">
              Twelve characters minimum. Length beats symbols — a passphrase of
              four unrelated words is stronger than eight scrambled characters.
            </p>

            <div className="mt-6">
              <Label>Master password</Label>
              <Input
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                aria-label="Master password"
              />
              {assessment && (
                <StrengthMeter
                  score={assessment.score}
                  hint={STRENGTH_HINTS[assessment.score] ?? ""}
                />
              )}
            </div>

            <div className="mt-5">
              <Label>Confirm</Label>
              <Input
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                value={confirm}
                invalid={confirm.length > 0 && !passwordsMatch}
                onChange={(e) => setConfirm(e.target.value)}
                aria-label="Confirm master password"
              />
              {confirm.length > 0 && !passwordsMatch && (
                <ErrorNote>These do not match.</ErrorNote>
              )}
            </div>

            <div className="mt-7">
              <DangerBlock>
                <strong className="block mb-2 font-medium">
                  There is no way to recover this password.
                </strong>
                Keyring does not store it, cannot reset it, and has no backdoor.
                If you forget it, every credential in this vault is permanently
                unreadable. Write it down and keep it somewhere physically safe.
              </DangerBlock>

              <div className="mt-4">
                <Label>
                  Type <span className="font-data text-text">I understand</span> to
                  continue
                </Label>
                <Input
                  value={acknowledged}
                  onChange={(e) => setAcknowledged(e.target.value)}
                  aria-label="Type I understand"
                />
              </div>
            </div>

            <div className="mt-8 flex gap-3">
              <Button onClick={() => setStep(4)} disabled={!canLeaveStep3}>
                Continue
              </Button>
              <Button variant="ghost" onClick={() => setStep(2)}>
                Back
              </Button>
            </div>
          </section>
        )}

        {step === 4 && (
          <section>
            <h1 className="text-xl font-medium text-text">How slow should unlocking be?</h1>
            <p className="mt-3 text-sm text-text-dim">
              Keyring deliberately makes unlocking expensive, so that guessing
              your password is expensive too. Slower is more secure.
            </p>

            <div className="mt-6 flex gap-2">
              {[500, 1000, 2000, 5000].map((ms) => (
                <button
                  key={ms}
                  onClick={() => {
                    setTargetMs(ms);
                    void runCalibration(ms);
                  }}
                  className={`h-9 px-4 rounded-control border text-sm transition-colors duration-100 ${
                    targetMs === ms
                      ? "border-accent text-accent bg-accent-dim/30"
                      : "border-edge text-text-dim hover:border-edge-strong"
                  }`}
                >
                  {ms / 1000} s
                </button>
              ))}
            </div>

            <div className="mt-6 rounded-panel border border-edge bg-panel p-4">
              {calibrating && (
                <p className="text-sm text-text-dim">Timing Argon2id on this machine…</p>
              )}
              {!calibrating && calibration && (
                <>
                  <p className="text-base text-text">
                    Unlocking will take about{" "}
                    <span className="font-data text-accent">
                      {(calibration.measuredMs / 1000).toFixed(1)} s
                    </span>{" "}
                    on this computer.
                  </p>
                  <p className="mt-2 text-xs text-text-faint font-data">
                    {calibration.memoryMib} MiB memory · {calibration.iterations}{" "}
                    iterations · {calibration.parallelism} lanes
                  </p>
                </>
              )}
              {!calibrating && !calibration && (
                <p className="text-sm text-text-dim">
                  Calibration did not complete. You can change this later in
                  Settings.
                </p>
              )}
            </div>

            {error && <ErrorNote>{error.message}</ErrorNote>}

            <div className="mt-8 flex gap-3">
              <Button
                className={busy ? "kr-deriving" : ""}
                disabled={busy || calibrating || !path}
                onClick={() => void onCreate(path, password, targetMs)}
              >
                {busy ? "Creating…" : "Create vault"}
              </Button>
              <Button variant="ghost" onClick={() => setStep(3)} disabled={busy}>
                Back
              </Button>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
