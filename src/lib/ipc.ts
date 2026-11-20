/**
 * Typed wrappers over Tauri's invoke. Every IPC call in the app goes through
 * this file, so there is exactly one place to audit what the frontend can ask
 * the backend to do.
 *
 * Note what is absent: there is no `getSecret`, no `revealField`, no
 * `decrypt`. Those commands do not exist in the backend either. Actions on
 * secrets are commands that *do* something (copy, launch, extract) and return
 * nothing.
 */

import { invoke } from "@tauri-apps/api/core";
import type {
  AppError,
  AttachmentPreview,
  BackupStatus,
  ConnectCapabilities,
  ConnectResult,
  ExportArgs,
  ExportSummary,
  GeneratedPassword,
  ImportPreview,
  ImportReport,
  ImportSourceName,
  LogEntry,
  PassphraseOptions,
  PasswordOptions,
  SettingsView,
  SnapshotView,
  CalibrationResult,
  ClipboardStatus,
  ExtractResult,
  LaunchResult,
  PasswordAssessment,
  RecordDetail,
  RecordSummary,
  RecordTypeInfo,
  RevealedValue,
  SearchHit,
  SidebarData,
  SshCommand,
  TotpCode,
  VaultStatus,
} from "./types";

/** Narrow an unknown thrown value into our AppError shape. */
export function asAppError(e: unknown): AppError {
  if (
    typeof e === "object" &&
    e !== null &&
    "kind" in e &&
    "message" in e &&
    typeof (e as AppError).message === "string"
  ) {
    return e as AppError;
  }
  return { kind: "internal", message: "Something went wrong inside Keyring." };
}

export const ipc = {
  vaultStatus: () => invoke<VaultStatus>("vault_status"),
  isLocked: () => invoke<boolean>("is_locked"),
  recentVaults: () => invoke<string[]>("recent_vaults"),
  vaultExists: (path: string) => invoke<boolean>("vault_exists", { path }),

  assessPassword: (password: string) =>
    invoke<PasswordAssessment>("assess_password", { password }),

  /** Slow on purpose - runs real Argon2 derivations. Show a spinner. */
  calibrateKdf: (targetMs: number) =>
    invoke<CalibrationResult>("calibrate_kdf", { targetMs }),

  createVault: (path: string, password: string, targetMs: number) =>
    invoke<VaultStatus>("create_vault", { path, password, targetMs }),

  openVault: (path: string, password: string) =>
    invoke<VaultStatus>("open_vault", { path, password }),

  openVaultReadOnly: (path: string, password: string) =>
    invoke<VaultStatus>("open_vault_read_only", { path, password }),

  lockVault: () => invoke<VaultStatus>("lock_vault"),

  changeMasterPassword: (current: string, newPassword: string) =>
    invoke<void>("change_master_password", { current, newPassword }),

  touchActivity: () => invoke<void>("touch_activity"),
  idleSeconds: () => invoke<number>("idle_seconds"),
  lastVault: () => invoke<string | null>("last_vault"),

  // -------------------------------------------------------------- records

  listRecords: (opts: {
    recordType?: string;
    folder?: string;
    tag?: string;
    favoritesOnly?: boolean;
    trash?: boolean;
  }) => invoke<RecordSummary[]>("list_records", opts),

  getRecord: (recordId: string) => invoke<RecordDetail>("get_record", { recordId }),

  createRecord: (
    recordType: string,
    title: string,
    folder: string,
    tags: string[],
    values: [string, string][],
  ) =>
    invoke<string>("create_record_with_fields", {
      recordType,
      title,
      folder,
      tags,
      values,
    }),

  setField: (recordId: string, name: string, value: string) =>
    invoke<void>("set_field", { recordId, name, value }),

  deleteField: (recordId: string, name: string) =>
    invoke<void>("delete_field", { recordId, name }),

  addCustomField: (recordId: string, name: string, value: string, secret: boolean) =>
    invoke<void>("add_custom_field", { recordId, name, value, secret }),

  renameRecord: (recordId: string, title: string) =>
    invoke<void>("rename_record", { recordId, title }),

  moveRecord: (recordId: string, folder: string) =>
    invoke<void>("move_record", { recordId, folder }),

  setFavorite: (recordId: string, favorite: boolean) =>
    invoke<void>("set_favorite", { recordId, favorite }),

  addTag: (recordId: string, tag: string) => invoke<void>("add_tag", { recordId, tag }),
  removeTag: (recordId: string, tag: string) =>
    invoke<void>("remove_tag", { recordId, tag }),

  duplicateRecord: (recordId: string, title: string) =>
    invoke<string>("duplicate_record", { recordId, title }),

  trashRecord: (recordId: string) => invoke<void>("trash_record", { recordId }),
  restoreRecord: (recordId: string) => invoke<void>("restore_record", { recordId }),
  purgeRecord: (recordId: string) => invoke<void>("purge_record", { recordId }),
  markUsed: (recordId: string) => invoke<void>("mark_used", { recordId }),

  recordTypes: () => invoke<RecordTypeInfo[]>("record_types"),
  sidebarData: () => invoke<SidebarData>("sidebar_data"),

  /**
   * THE EXCEPTION. Returns a decrypted value.
   * Only call this from an explicit user action, and drop the result when the
   * countdown ends. Copying does not go through here - that happens in Rust.
   */
  revealField: (recordId: string, field: string) =>
    invoke<RevealedValue>("reveal_field", { recordId, field }),

  // --------------------------------------------------------------- search

  search: (query: string, limit?: number) =>
    invoke<SearchHit[]>("search", { query, limit }),
  indexSize: () => invoke<number>("index_size"),

  // -------------------------------------------------------------- actions
  //
  // These are the commands that make the boundary real. Each one decrypts,
  // acts, and returns nothing but status. No plaintext crosses back.

  copyField: (recordId: string, field: string) =>
    invoke<ClipboardStatus>("copy_field", { recordId, field }),
  copyPrimary: (recordId: string) =>
    invoke<ClipboardStatus>("copy_primary", { recordId }),
  copyUsername: (recordId: string) =>
    invoke<ClipboardStatus>("copy_username", { recordId }),
  clearClipboard: () => invoke<void>("clear_clipboard"),
  clipboardStatus: () => invoke<ClipboardStatus>("clipboard_status"),

  extractAttachment: (attachmentId: string, ttlSeconds?: number) =>
    invoke<ExtractResult>("extract_attachment", { attachmentId, ttlSeconds }),
  extractedFiles: () => invoke<[string, number][]>("extracted_files"),
  purgeExtracted: () => invoke<number>("purge_extracted"),

  openUrl: (url: string) => invoke<void>("open_url", { url }),

  // --------------------------------------------------------- integrations

  launchRdp: (recordId: string) => invoke<LaunchResult>("launch_rdp", { recordId }),
  clearRdpCredential: (recordId: string) =>
    invoke<void>("clear_rdp_credential", { recordId }),

  sshCommand: (recordId: string) => invoke<SshCommand>("ssh_command", { recordId }),
  sshCommandWithKey: (recordId: string, attachmentId: string) =>
    invoke<SshCommand>("ssh_command_with_key", { recordId, attachmentId }),
  extractSshKey: (recordId: string, attachmentId: string, ttlSeconds?: number) =>
    invoke<ExtractResult>("extract_ssh_key", { recordId, attachmentId, ttlSeconds }),

  totpCode: (recordId: string) => invoke<TotpCode>("totp_code", { recordId }),
  copyTotp: (recordId: string) => invoke<TotpCode>("copy_totp", { recordId }),
  validateTotpSecret: (secret: string) =>
    invoke<TotpCode>("validate_totp_secret", { secret }),

  // ----------------------------------------------------------- attachments
  //
  // `addAttachment` closes a gap that existed until Phase 7: the vault could
  // store attachments and no command exposed it, so FR-3.1 was unreachable
  // from the interface.

  addAttachment: (recordId: string, path: string) =>
    invoke<string>("add_attachment", { recordId, path }),
  removeAttachment: (attachmentId: string) =>
    invoke<void>("remove_attachment", { attachmentId }),
  /** Reads text-like attachments without writing them to disk (FR-3.4). */
  previewAttachment: (attachmentId: string) =>
    invoke<AttachmentPreview>("preview_attachment", { attachmentId }),

  // ---------------------------------------------------------------- backup

  backupStatus: () => invoke<BackupStatus>("backup_status"),
  listBackups: () => invoke<SnapshotView[]>("list_backups"),
  backupNow: () => invoke<SnapshotView>("backup_now"),
  setBackupDir: (path: string | null) => invoke<void>("set_backup_dir", { path }),
  setBackupRetention: (keep: number) =>
    invoke<void>("set_backup_retention", { keep }),
  setBackupAutomatic: (enabled: boolean) =>
    invoke<void>("set_backup_automatic", { enabled }),
  restoreBackup: (snapshotPath: string, destination: string) =>
    invoke<void>("restore_backup", { snapshotPath, destination }),

  // ------------------------------------------------------- import / export

  previewImport: (source: ImportSourceName, path: string) =>
    invoke<ImportPreview>("preview_import", { source, path }),
  runImport: (source: ImportSourceName, path: string, folder?: string) =>
    invoke<ImportReport>("run_import", { source, path, folder }),
  importKeyringExport: (path: string, passphrase: string) =>
    invoke<ImportReport>("import_keyring_export", { path, passphrase }),

  /**
   * Step one of two for a plaintext export. Returns a single-use token that
   * expires in 120 seconds.
   *
   * The gate is in Rust on purpose (D-37). Do not add a frontend-only
   * shortcut around it, and do not cache the token.
   */
  beginPlaintextExport: () => invoke<string>("begin_plaintext_export"),
  runExport: (args: ExportArgs) => invoke<ExportSummary>("run_export", { args }),

  // --------------------------------------------------------------- connect

  sshConnect: (recordId: string, attachmentId?: string) =>
    invoke<ConnectResult>("ssh_connect", { recordId, attachmentId }),
  cloudConnect: (recordId: string, provider?: string) =>
    invoke<ConnectResult>("cloud_connect", { recordId, provider }),
  connectCapabilities: () => invoke<ConnectCapabilities>("connect_capabilities"),
  cancelAskpass: () => invoke<void>("cancel_askpass"),

  // -------------------------------------------------------------- settings

  getSettings: () => invoke<SettingsView>("get_settings"),
  setSetting: (key: string, value: string) =>
    invoke<void>("set_setting", { key, value }),
  applyHotkey: (accelerator: string) =>
    invoke<void>("apply_hotkey", { accelerator }),

  generatePassword: (options: PasswordOptions) =>
    invoke<GeneratedPassword>("generate_password", { options }),
  generatePassphrase: (options: PassphraseOptions) =>
    invoke<GeneratedPassword>("generate_passphrase", { options }),

  activityLog: (limit?: number, action?: string) =>
    invoke<LogEntry[]>("activity_log", { query: { limit, action } }),
  activityCount: () => invoke<number>("activity_count"),
  clearActivityLog: () => invoke<void>("clear_activity_log"),
};
