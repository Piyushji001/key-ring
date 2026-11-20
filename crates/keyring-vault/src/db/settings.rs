//! Vault-scoped settings. Stored inside the encrypted container, so they
//! travel with the vault and never touch the registry.

use rusqlite::{params, Connection};

use crate::error::Result;

pub const IDLE_LOCK_SECS: &str = "idle_lock_secs";
pub const CLIPBOARD_CLEAR_SECS: &str = "clipboard_clear_secs";
pub const TEMPFILE_TTL_SECS: &str = "tempfile_ttl_secs";
pub const BACKUP_DIR: &str = "backup_dir";
pub const BACKUP_RETENTION: &str = "backup_retention";
pub const HISTORY_LIMIT: &str = "history_limit";
pub const TRASH_RETENTION_DAYS: &str = "trash_retention_days";

// Phase 7.
pub const BACKUP_AUTOMATIC: &str = "backup_automatic";
pub const BACKUP_DEBOUNCE_SECS: &str = "backup_debounce_secs";

// Phase 7.5 - one-click connect.
pub const TERMINAL_PREFERENCE: &str = "terminal_preference";
pub const SSH_ASKPASS_ENABLED: &str = "ssh_askpass_enabled";
pub const CLOUD_SHELL_TTL_SECS: &str = "cloud_shell_ttl_secs";

// Phase 8.
pub const HOTKEY: &str = "hotkey";
pub const THEME: &str = "theme";
pub const FONT_SCALE: &str = "font_scale";
pub const LOCK_ON_SLEEP: &str = "lock_on_sleep";
pub const LOCK_ON_WORKSTATION_LOCK: &str = "lock_on_workstation_lock";
pub const START_MINIMIZED: &str = "start_minimized";
pub const CLOSE_TO_TRAY: &str = "close_to_tray";
pub const ACTIVITY_LOG_ENABLED: &str = "activity_log_enabled";
pub const CERT_EXPIRY_WARN_DAYS: &str = "cert_expiry_warn_days";

pub fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let v = conn
        .query_row("SELECT value FROM settings WHERE key = ?1", params![key], |r| {
            r.get(0)
        })
        .ok();
    Ok(v)
}

pub fn get_i64(conn: &Connection, key: &str, default: i64) -> i64 {
    match get(conn, key) {
        Ok(Some(v)) => v.parse().unwrap_or(default),
        _ => default,
    }
}

pub fn get_bool(conn: &Connection, key: &str, default: bool) -> bool {
    match get(conn, key) {
        Ok(Some(v)) => matches!(v.as_str(), "true" | "1" | "yes"),
        _ => default,
    }
}

/// Every setting, for the Settings screen. Sorted, so the UI does not have to
/// care about insertion order.
pub fn all(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings ORDER BY key")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

pub fn set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// Written once at vault creation.
pub fn seed_defaults(conn: &Connection) -> Result<()> {
    for (k, v) in [
        (IDLE_LOCK_SECS, "600"),
        (CLIPBOARD_CLEAR_SECS, "30"),
        (TEMPFILE_TTL_SECS, "300"),
        (BACKUP_RETENTION, "10"),
        (HISTORY_LIMIT, "10"),
        (TRASH_RETENTION_DAYS, "30"),
        (BACKUP_AUTOMATIC, "true"),
        (BACKUP_DEBOUNCE_SECS, "60"),
        (TERMINAL_PREFERENCE, "auto"),
        (SSH_ASKPASS_ENABLED, "true"),
        (CLOUD_SHELL_TTL_SECS, "900"),
        (HOTKEY, "CmdOrCtrl+Shift+Space"),
        (THEME, "system"),
        (FONT_SCALE, "medium"),
        (LOCK_ON_SLEEP, "true"),
        (LOCK_ON_WORKSTATION_LOCK, "true"),
        (START_MINIMIZED, "false"),
        (CLOSE_TO_TRAY, "true"),
        (ACTIVITY_LOG_ENABLED, "true"),
        (CERT_EXPIRY_WARN_DAYS, "30"),
    ] {
        if get(conn, k)?.is_none() {
            set(conn, k, v)?;
        }
    }
    Ok(())
}
