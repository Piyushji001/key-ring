//! Phase 8 — settings, the password generator, and the activity log.
//!
//! Settings live in the `settings` table *inside the encrypted container*, not
//! in the registry and not in an AppData JSON file. That is not tidiness: an
//! idle-lock timeout stored outside the vault is a value an attacker with file
//! access can edit before you next unlock. Inside the container it is covered
//! by the same AEAD as everything else.
//!
//! The one exception is the window's own geometry, which Tauri persists itself
//! and which reveals nothing.

use keyring_vault::db;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::actions::generator::{
    self, GeneratedPassword, PassphraseOptions, PasswordOptions,
};
use crate::error::{AppError, Result};
use crate::state::AppState;

// ------------------------------------------------------------------ Settings

/// Everything the Settings screen renders, in one round trip.
///
/// One command rather than twenty `get_setting` calls: the screen would
/// otherwise flash through twenty separate loading states, and a partially
/// applied settings page is a genuinely confusing thing to look at.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    // Security
    pub idle_lock_secs: i64,
    pub lock_on_sleep: bool,
    pub lock_on_workstation_lock: bool,
    pub clipboard_clear_secs: i64,
    pub tempfile_ttl_secs: i64,
    pub history_limit: i64,
    pub trash_retention_days: i64,
    pub activity_log_enabled: bool,

    // Backup
    pub backup_dir: Option<String>,
    pub backup_retention: i64,
    pub backup_automatic: bool,
    pub backup_debounce_secs: i64,

    // Connect
    pub terminal_preference: String,
    pub ssh_askpass_enabled: bool,
    pub cloud_shell_ttl_secs: i64,

    // Shortcuts and appearance
    pub hotkey: String,
    pub theme: String,
    pub font_scale: String,

    // Windows integration
    pub start_minimized: bool,
    pub close_to_tray: bool,

    // Warnings
    pub cert_expiry_warn_days: i64,

    // Read-only vault facts, for the Vault section
    pub vault_path: Option<String>,
    pub format_version: u16,
    pub record_count: i64,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
}

/// Default hotkey. Matches FR-5.1 and the constant in `lib.rs`.
const DEFAULT_HOTKEY: &str = "CmdOrCtrl+Shift+Space";

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<SettingsView> {
    state.with_session(|session| {
        let conn = session.conn()?;
        let g = |k: &str, d: i64| db::settings::get_i64(conn, k, d);
        let b = |k: &str, d: i64| db::settings::get_i64(conn, k, d) != 0;
        let s = |k: &str| db::settings::get(conn, k).ok().flatten();

        let record_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE deleted_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let kdf = &session.header().kdf;

        Ok(SettingsView {
            idle_lock_secs: g(db::settings::IDLE_LOCK_SECS, 600),
            lock_on_sleep: b(db::settings::LOCK_ON_SLEEP, 1),
            lock_on_workstation_lock: b(db::settings::LOCK_ON_WORKSTATION_LOCK, 1),
            clipboard_clear_secs: g(db::settings::CLIPBOARD_CLEAR_SECS, 30),
            tempfile_ttl_secs: g(db::settings::TEMPFILE_TTL_SECS, 300),
            history_limit: g(db::settings::HISTORY_LIMIT, 10),
            trash_retention_days: g(db::settings::TRASH_RETENTION_DAYS, 30),
            activity_log_enabled: b(db::settings::ACTIVITY_LOG_ENABLED, 1),

            backup_dir: s(db::settings::BACKUP_DIR),
            backup_retention: g(db::settings::BACKUP_RETENTION, 10),
            backup_automatic: b(db::settings::BACKUP_AUTOMATIC, 1),
            backup_debounce_secs: g(db::settings::BACKUP_DEBOUNCE_SECS, 60),

            terminal_preference: s(db::settings::TERMINAL_PREFERENCE)
                .unwrap_or_else(|| "auto".to_string()),
            ssh_askpass_enabled: b(db::settings::SSH_ASKPASS_ENABLED, 1),
            cloud_shell_ttl_secs: g(db::settings::CLOUD_SHELL_TTL_SECS, 3600),

            hotkey: s(db::settings::HOTKEY).unwrap_or_else(|| DEFAULT_HOTKEY.to_string()),
            theme: s(db::settings::THEME).unwrap_or_else(|| "system".to_string()),
            font_scale: s(db::settings::FONT_SCALE).unwrap_or_else(|| "medium".to_string()),

            start_minimized: b(db::settings::START_MINIMIZED, 0),
            close_to_tray: b(db::settings::CLOSE_TO_TRAY, 1),

            cert_expiry_warn_days: g(db::settings::CERT_EXPIRY_WARN_DAYS, 30),

            vault_path: session
                .paths()
                .container()
                .to_str()
                .map(|s| s.to_string()),
            format_version: session.format_version(),
            record_count,
            kdf_memory_kib: kdf.memory_kib,
            kdf_iterations: kdf.iterations,
            kdf_parallelism: kdf.parallelism,
        })
    })
}

/// Bounds for every numeric setting, enforced in Rust.
///
/// The UI also constrains these, but a slider is a suggestion and an IPC call
/// is an instruction. An idle timeout of zero would lock the vault
/// continuously; a clipboard clear of zero would wipe the value before the
/// user could paste it.
fn clamp_setting(key: &str, value: i64) -> Result<i64> {
    let (lo, hi) = match key {
        // FR-1.4: 1 to 120 minutes.
        db::settings::IDLE_LOCK_SECS => (60, 7_200),
        db::settings::CLIPBOARD_CLEAR_SECS => (5, 600),
        db::settings::TEMPFILE_TTL_SECS => (15, 3_600),
        db::settings::HISTORY_LIMIT => (0, 100),
        db::settings::TRASH_RETENTION_DAYS => (1, 365),
        db::settings::BACKUP_RETENTION => (1, 100),
        db::settings::BACKUP_DEBOUNCE_SECS => (10, 3_600),
        db::settings::CLOUD_SHELL_TTL_SECS => (60, 43_200),
        db::settings::CERT_EXPIRY_WARN_DAYS => (1, 365),
        _ => return Ok(value),
    };
    if value < lo || value > hi {
        return Err(AppError::invalid(format!(
            "That value is outside the allowed range ({lo} to {hi})."
        )));
    }
    Ok(value)
}

/// Keys the UI is allowed to write.
///
/// An allow-list rather than a free-form key/value setter. Without it, the
/// frontend could write arbitrary rows into the settings table, and a future
/// setting that changes security behaviour would be writable by any injected
/// script long before anyone noticed.
const WRITABLE: &[&str] = &[
    db::settings::IDLE_LOCK_SECS,
    db::settings::LOCK_ON_SLEEP,
    db::settings::LOCK_ON_WORKSTATION_LOCK,
    db::settings::CLIPBOARD_CLEAR_SECS,
    db::settings::TEMPFILE_TTL_SECS,
    db::settings::HISTORY_LIMIT,
    db::settings::TRASH_RETENTION_DAYS,
    db::settings::ACTIVITY_LOG_ENABLED,
    db::settings::BACKUP_RETENTION,
    db::settings::BACKUP_AUTOMATIC,
    db::settings::BACKUP_DEBOUNCE_SECS,
    db::settings::TERMINAL_PREFERENCE,
    db::settings::SSH_ASKPASS_ENABLED,
    db::settings::CLOUD_SHELL_TTL_SECS,
    db::settings::HOTKEY,
    db::settings::THEME,
    db::settings::FONT_SCALE,
    db::settings::START_MINIMIZED,
    db::settings::CLOSE_TO_TRAY,
    db::settings::CERT_EXPIRY_WARN_DAYS,
];

/// Write one setting.
///
/// `backup_dir` is deliberately absent from `WRITABLE` — it goes through
/// `set_backup_dir` in `backup_cmds`, which validates that the folder exists
/// and is writable before accepting it.
#[tauri::command]
pub fn set_setting(state: State<'_, AppState>, key: String, value: String) -> Result<()> {
    if !WRITABLE.contains(&key.as_str()) {
        return Err(AppError::invalid(format!(
            "'{key}' is not a setting this application writes."
        )));
    }

    // Numeric settings are range-checked; the rest are stored as given.
    let stored = match value.parse::<i64>() {
        Ok(n) => clamp_setting(&key, n)?.to_string(),
        Err(_) => value.clone(),
    };

    state.with_session_mut(|session| {
        Ok(session.mutate(|conn| {
            db::settings::set(conn, &key, &stored)?;
            Ok(())
        })?)
    })?;

    // The setting name is not a secret; the value might be a hotkey or a path,
    // so only the key is recorded.
    state.log_activity(
        keyring_vault::LogAction::SettingChanged,
        None,
        Some(key.as_str()),
    );
    Ok(())
}

/// Apply a newly chosen global hotkey immediately.
///
/// Separate from `set_setting` because it has to talk to the shortcut plugin,
/// and because a hotkey that another application already owns must be reported
/// as a failure rather than saved and silently dead.
#[tauri::command]
pub fn apply_hotkey(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    accelerator: String,
) -> Result<()> {
    use tauri_plugin_global_shortcut::GlobalShortcutExt;

    let previous = state
        .with_session(|s| {
            Ok(db::settings::get(s.conn()?, db::settings::HOTKEY)
                .ok()
                .flatten()
                .unwrap_or_else(|| DEFAULT_HOTKEY.to_string()))
        })
        .unwrap_or_else(|_| DEFAULT_HOTKEY.to_string());

    let shortcuts = app.global_shortcut();
    let _ = shortcuts.unregister(previous.as_str());

    if let Err(e) = shortcuts.register(accelerator.as_str()) {
        // Put the old one back rather than leaving the user with no hotkey.
        let _ = shortcuts.register(previous.as_str());
        return Err(AppError::invalid(format!(
            "Windows would not give Keyring that shortcut — another application \
             is probably using it. ({e})"
        )));
    }

    set_setting(state, db::settings::HOTKEY.to_string(), accelerator)
}

// ----------------------------------------------------------------- Generator

/// FR: password generator. Phase 8.
///
/// Both commands return plaintext, which is the third outbound crossing of the
/// trust boundary. The justification is written out in `generator.rs` and is
/// narrow: the value is not protecting anything until the user saves it.
#[tauri::command]
pub fn generate_password(options: PasswordOptions) -> Result<GeneratedPassword> {
    generator::generate_password(&options)
}

#[tauri::command]
pub fn generate_passphrase(options: PassphraseOptions) -> Result<GeneratedPassword> {
    generator::generate_passphrase(&options)
}

// -------------------------------------------------------------- Activity log

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityQuery {
    pub limit: Option<i64>,
    /// Restrict to one action name, e.g. `exported_plaintext`.
    pub action: Option<String>,
}

#[tauri::command]
pub fn activity_log(
    state: State<'_, AppState>,
    query: Option<ActivityQuery>,
) -> Result<Vec<db::activity::LogEntry>> {
    let query = query.unwrap_or(ActivityQuery {
        limit: None,
        action: None,
    });
    let limit = query.limit.unwrap_or(200).clamp(1, 5_000);

    state.with_session(|session| {
        Ok(db::activity::list(
            session.conn()?,
            limit,
            query.action.as_deref(),
        )?)
    })
}

#[tauri::command]
pub fn activity_count(state: State<'_, AppState>) -> Result<i64> {
    state.with_session(|session| Ok(db::activity::count(session.conn()?)?))
}

/// Erase the activity log.
///
/// Offered because the log is a record of when you touched which credential,
/// and a user handing a vault to a client should be able to hand over the
/// records without the history. The erasure itself is logged — an audit log
/// that can be silently emptied is not an audit log.
#[tauri::command]
pub fn clear_activity_log(state: State<'_, AppState>) -> Result<()> {
    state.with_session_mut(|session| {
        Ok(session.mutate(|conn| {
            conn.execute("DELETE FROM activity_log", [])?;
            let _ = db::activity::record(
                conn,
                keyring_vault::LogAction::SettingChanged,
                None,
                Some("activity log cleared"),
            );
            Ok(())
        })?)
    })
}
