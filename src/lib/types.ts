/**
 * Mirrors src-tauri/src/model/dto.rs exactly. When you change one, change both.
 *
 * READ THE BANNER AT THE TOP OF dto.rs BEFORE ADDING A FIELD HERE.
 *
 * There is no type in this file for a decrypted secret, and there never will
 * be. The frontend learns *that* a secret exists (`hasSecret: boolean`) and
 * never *what* it is. Copying, revealing and launching all happen in Rust.
 */

export interface KdfSummary {
  memoryMib: number;
  iterations: number;
  parallelism: number;
}

export interface VaultStatus {
  locked: boolean;
  readOnly: boolean;
  vaultPath: string | null;
  vaultId: string | null;
  formatVersion: number | null;
  recordCount: number;
  createdAt: number | null;
  modifiedAt: number | null;
  kdf: KdfSummary | null;
}

export interface CalibrationResult {
  memoryMib: number;
  iterations: number;
  parallelism: number;
  measuredMs: number;
  targetMs: number;
}

export interface PasswordAssessment {
  score: 0 | 1 | 2 | 3 | 4;
  length: number;
  meetsMinimum: boolean;
}

export type ErrorKind =
  | "locked"
  | "unlock"
  | "already_open"
  | "read_only"
  | "already_exists"
  | "not_found"
  | "invalid"
  | "io"
  | "internal";

export interface AppError {
  kind: ErrorKind;
  message: string;
}

export const LOCKED_STATUS: VaultStatus = {
  locked: true,
  readOnly: false,
  vaultPath: null,
  vaultId: null,
  formatVersion: null,
  recordCount: 0,
  createdAt: null,
  modifiedAt: null,
  kdf: null,
};

// ---------------------------------------------------------------- Phase 4

export interface RecordSummary {
  id: string;
  title: string;
  recordType: string;
  typeLabel: string;
  folder: string;
  favorite: boolean;
  tags: string[];
  subtitle: string | null;
  usedAt: number | null;
  modifiedAt: number;
  useCount: number;
  attachmentCount: number;
  inTrash: boolean;
}

export interface FieldView {
  name: string;
  label: string;
  kind: string;
  isSecret: boolean;
  /** Always null for secret fields. This is the boundary, in one type. */
  value: string | null;
  hasValue: boolean;
  historyCount: number;
}

export interface AttachmentView {
  id: string;
  filename: string;
  sizeBytes: number;
  createdAt: number;
}

export interface RecordDetail {
  summary: RecordSummary;
  fields: FieldView[];
  attachments: AttachmentView[];
  createdAt: number;
  primaryField: string | null;
}

export interface SearchHit {
  recordId: string;
  title: string;
  recordType: string;
  typeLabel: string;
  folder: string;
  favorite: boolean;
  matchedField: string | null;
  matchedContext: string | null;
}

export interface CountedItem {
  key: string;
  label: string;
  count: number;
}

export interface SidebarData {
  total: number;
  favorites: number;
  trash: number;
  types: CountedItem[];
  folders: CountedItem[];
  tags: CountedItem[];
}

export interface FieldTemplateInfo {
  name: string;
  label: string;
  kind: string;
  secret: boolean;
}

export interface RecordTypeInfo {
  key: string;
  label: string;
  primaryField: string | null;
  fields: FieldTemplateInfo[];
}

/**
 * The only shape in this file carrying a decrypted secret.
 * Read the banner above `RevealedValue` in src-tauri/src/model/dto.rs.
 * Never put this in state that outlives the countdown.
 */
export interface RevealedValue {
  recordId: string;
  field: string;
  value: string;
  expiresInMs: number;
}

export type Selection =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "trash" }
  | { kind: "type"; key: string }
  | { kind: "folder"; key: string }
  | { kind: "tag"; key: string };

// ---------------------------------------------------------------- Phase 5

export interface ClipboardStatus {
  active: boolean;
  field: string | null;
  secondsRemaining: number;
  /** False when Windows refused an exclusion format. Say so; do not imply a
   *  guarantee we did not get. */
  excludedFromHistory: boolean;
}

export interface ExtractResult {
  path: string;
  filename: string;
  expiresInSeconds: number;
}

// ---------------------------------------------------------------- Phase 6

export interface LaunchResult {
  launched: boolean;
  detail: string;
}

export interface SshCommand {
  command: string;
  copied: boolean;
}

/**
 * A TOTP code. Unlike RevealedValue this needs no ceremony: it is derived,
 * six digits, and worthless in thirty seconds. The seed never leaves Rust.
 */
export interface TotpCode {
  code: string;
  secondsRemaining: number;
  digits: number;
}

// ===========================================================================
// Phase 7, 7.5 and 8
// ===========================================================================

export interface SnapshotView {
  name: string;
  path: string;
  createdAt: number;
  sizeBytes: number;
  recordCount: number | null;
}

export interface BackupStatus {
  /** Null means unconfigured, which is the state FR-8.4 warns about. */
  backupDir: string | null;
  automatic: boolean;
  retention: number;
  lastBackupAt: number | null;
  lastError: string | null;
  pending: boolean;
  snapshotCount: number;
}

export type ImportSourceName = "keepass_csv" | "bitwarden_json" | "keyring_json";

export interface ImportPreview {
  source: ImportSourceName;
  total: number;
  /** Type name -> count, so the user sees the mapping before committing. */
  byType: Record<string, number>;
  skipped: { reason: string; count: number }[];
  /** Titles only. Never a field value. */
  sampleTitles: string[];
  warnings: string[];
}

export interface ImportReport {
  imported: number;
  skipped: number;
  duplicatesFlagged: number;
  folder: string;
  warnings: string[];
}

export type ExportFormatName = "encrypted_json" | "plaintext_json" | "folder_subset";

export interface ExportArgs {
  format: ExportFormatName;
  path: string;
  /** Required for folder_subset. */
  folder?: string;
  /** Required for encrypted_json. Never stored. */
  passphrase?: string;
  /** Required for plaintext_json. From beginPlaintextExport, valid 120s. */
  confirmationToken?: string;
  includeAttachments?: boolean;
}

export interface ExportSummary {
  path: string;
  format: ExportFormatName;
  recordCount: number;
  attachmentCount: number;
  bytesWritten: number;
  /** True only for plaintext. The UI must keep saying so afterwards. */
  plaintext: boolean;
}

/** Result of a one-click connect. Never carries a credential. */
export interface ConnectResult {
  launched: boolean;
  /** "key", "password", "interactive", or null. */
  auth: string | null;
  terminal: string;
  detail: string;
  /** Set when Keyring had to degrade. Show it; do not swallow it. */
  caveat: string | null;
  cleanupInSecs: number | null;
}

export interface ConnectCapabilities {
  windowsTerminal: boolean;
  powershell: boolean;
  sshClient: boolean;
  askpassHelper: boolean;
  notes: string[];
}

export interface SettingsView {
  idleLockSecs: number;
  lockOnSleep: boolean;
  lockOnWorkstationLock: boolean;
  clipboardClearSecs: number;
  tempfileTtlSecs: number;
  historyLimit: number;
  trashRetentionDays: number;
  activityLogEnabled: boolean;

  backupDir: string | null;
  backupRetention: number;
  backupAutomatic: boolean;
  backupDebounceSecs: number;

  terminalPreference: string;
  sshAskpassEnabled: boolean;
  cloudShellTtlSecs: number;

  hotkey: string;
  theme: string;
  fontScale: string;

  startMinimized: boolean;
  closeToTray: boolean;

  certExpiryWarnDays: number;

  vaultPath: string | null;
  formatVersion: number;
  recordCount: number;
  kdfMemoryKib: number;
  kdfIterations: number;
  kdfParallelism: number;
}

export interface PasswordOptions {
  length: number;
  lowercase?: boolean;
  uppercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  requireEachClass?: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator?: string;
  capitalize?: boolean;
  includeNumber?: boolean;
}

/**
 * The generator is the one place a plaintext value legitimately arrives in
 * JavaScript that is not `reveal_field`. It is not a secret until it is saved.
 * Do not log it, do not put it in component state longer than needed.
 */
export interface GeneratedPassword {
  value: string;
  entropyBits: number;
  /** Human sentence, e.g. "Centuries to crack offline." */
  strengthNote: string;
}

export interface LogEntry {
  id: number;
  at: number;
  action: string;
  description: string;
  recordId: string | null;
  recordTitle: string | null;
  detail: string | null;
  /** Rendered with emphasis: exports, password changes, restores. */
  notable: boolean;
}

export interface AttachmentPreview {
  filename: string;
  /** Present only for text-like files. Binary previews are refused. */
  text: string | null;
  truncated: boolean;
  sizeBytes: number;
  reason: string | null;
}
