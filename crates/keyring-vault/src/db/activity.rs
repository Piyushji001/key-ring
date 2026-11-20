//! The activity log (Phase 8, and FR-9.2's "logs the event").
//!
//! The `activity_log` table has existed since the Phase 2 schema and nothing
//! has ever written to it. This is that writer.
//!
//! ## What goes in
//!
//! What happened, when, and to which record. That is all.
//!
//! ## What must never go in
//!
//! Field values. Passwords. The contents of a note. The name of a file the
//! user extracted is borderline and is allowed, because a filename is already
//! visible in the record list; the *contents* never are.
//!
//! The reason this matters more than it looks: the log lives **inside the
//! encrypted container**, so it is protected at rest — but it is also the one
//! table designed to be read back and displayed in bulk. A log that quietly
//! accumulated copied values would be a plaintext credential dump with a nice
//! table view over it. The `detail` column is therefore documented as
//! "human-readable context, never a secret", and every call site in the
//! application is expected to honour that.
//!
//! ## Retention
//!
//! Capped by row count rather than age. An engineer who uses Keyring heavily
//! for a week generates thousands of entries, and an unbounded log inside a
//! file that is rewritten atomically on every save is a slow, silent
//! performance leak.

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::error::Result;

/// Keep this many entries. Roughly a fortnight of heavy use.
pub const DEFAULT_LOG_LIMIT: i64 = 2_000;

/// Every action worth recording. A closed set rather than free text, so that
/// the viewer can filter and so nobody can log a sentence containing a secret
/// by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    VaultCreated,
    VaultUnlocked,
    VaultLocked,
    MasterPasswordChanged,
    RecordCreated,
    RecordEdited,
    RecordTrashed,
    RecordRestored,
    RecordPurged,
    RecordDuplicated,
    AttachmentAdded,
    AttachmentRemoved,
    AttachmentExtracted,
    FieldRevealed,
    FieldCopied,
    RdpLaunched,
    SshLaunched,
    CloudShellOpened,
    BackupCreated,
    BackupFailed,
    BackupRestored,
    Imported,
    /// The dangerous one. Logged before the file is written, so the record
    /// survives even if the write fails.
    ExportedPlaintext,
    ExportedEncrypted,
    SettingChanged,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::VaultCreated => "vault_created",
            Action::VaultUnlocked => "vault_unlocked",
            Action::VaultLocked => "vault_locked",
            Action::MasterPasswordChanged => "master_password_changed",
            Action::RecordCreated => "record_created",
            Action::RecordEdited => "record_edited",
            Action::RecordTrashed => "record_trashed",
            Action::RecordRestored => "record_restored",
            Action::RecordPurged => "record_purged",
            Action::RecordDuplicated => "record_duplicated",
            Action::AttachmentAdded => "attachment_added",
            Action::AttachmentRemoved => "attachment_removed",
            Action::AttachmentExtracted => "attachment_extracted",
            Action::FieldRevealed => "field_revealed",
            Action::FieldCopied => "field_copied",
            Action::RdpLaunched => "rdp_launched",
            Action::SshLaunched => "ssh_launched",
            Action::CloudShellOpened => "cloud_shell_opened",
            Action::BackupCreated => "backup_created",
            Action::BackupFailed => "backup_failed",
            Action::BackupRestored => "backup_restored",
            Action::Imported => "imported",
            Action::ExportedPlaintext => "exported_plaintext",
            Action::ExportedEncrypted => "exported_encrypted",
            Action::SettingChanged => "setting_changed",
        }
    }

    /// Sentence shown in the viewer. Kept next to the variant so a new action
    /// cannot be added without deciding how it reads.
    pub fn describe(&self) -> &'static str {
        match self {
            Action::VaultCreated => "Vault created",
            Action::VaultUnlocked => "Vault unlocked",
            Action::VaultLocked => "Vault locked",
            Action::MasterPasswordChanged => "Master password changed",
            Action::RecordCreated => "Record created",
            Action::RecordEdited => "Record edited",
            Action::RecordTrashed => "Record moved to trash",
            Action::RecordRestored => "Record restored from trash",
            Action::RecordPurged => "Record permanently deleted",
            Action::RecordDuplicated => "Record duplicated",
            Action::AttachmentAdded => "Attachment added",
            Action::AttachmentRemoved => "Attachment removed",
            Action::AttachmentExtracted => "Attachment extracted to a temporary file",
            Action::FieldRevealed => "Field revealed on screen",
            Action::FieldCopied => "Field copied to the clipboard",
            Action::RdpLaunched => "RDP session launched",
            Action::SshLaunched => "SSH session launched",
            Action::CloudShellOpened => "Cloud shell opened",
            Action::BackupCreated => "Backup created",
            Action::BackupFailed => "Backup failed",
            Action::BackupRestored => "Backup restored",
            Action::Imported => "Records imported",
            Action::ExportedPlaintext => "PLAINTEXT EXPORT — every credential written unencrypted",
            Action::ExportedEncrypted => "Encrypted export written",
            Action::SettingChanged => "Setting changed",
        }
    }

    /// Entries the viewer highlights. Not a severity scale — just the handful
    /// of events that should be findable at a glance six months later.
    pub fn is_notable(&self) -> bool {
        matches!(
            self,
            Action::ExportedPlaintext
                | Action::MasterPasswordChanged
                | Action::RecordPurged
                | Action::BackupFailed
                | Action::BackupRestored
                | Action::Imported
        )
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: i64,
    pub at: i64,
    pub action: String,
    pub description: String,
    pub record_id: Option<String>,
    /// Resolved at read time. `None` when the record has since been purged,
    /// which is itself informative.
    pub record_title: Option<String>,
    pub detail: Option<String>,
    pub notable: bool,
}

/// Append an entry.
///
/// `detail` is human-readable context — a filename, a hostname, a count.
/// **Never a field value.** See the module banner.
pub fn record(
    conn: &Connection,
    action: Action,
    record_id: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO activity_log (at, action, record_id, detail) VALUES (?1, ?2, ?3, ?4)",
        params![
            crate::util::time::now_unix(),
            action.as_str(),
            record_id,
            detail
        ],
    )?;
    Ok(())
}

/// Append and immediately trim. Used on the paths that fire often.
pub fn record_and_trim(
    conn: &Connection,
    action: Action,
    record_id: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    record(conn, action, record_id, detail)?;
    // Trimming on every write would be wasteful; every 64th is plenty.
    if rand_ish() % 64 == 0 {
        trim(conn, DEFAULT_LOG_LIMIT)?;
    }
    Ok(())
}

/// Cheap jitter source. Not cryptographic and does not pretend to be — it
/// decides how often to run a `DELETE`, nothing more.
fn rand_ish() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
}

/// Newest first.
pub fn list(conn: &Connection, limit: i64, filter: Option<&str>) -> Result<Vec<LogEntry>> {
    let limit = limit.clamp(1, 5_000);

    let sql = "SELECT a.id, a.at, a.action, a.record_id, a.detail, r.title
               FROM activity_log a
               LEFT JOIN records r ON r.id = a.record_id
               WHERE (?1 IS NULL OR a.action = ?1)
               ORDER BY a.at DESC, a.id DESC
               LIMIT ?2";

    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![filter, limit], |r| {
        let action: String = r.get(2)?;
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            action,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, Option<String>>(5)?,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (id, at, action, record_id, detail, record_title) = row?;
        let parsed = parse_action(&action);
        out.push(LogEntry {
            id,
            at,
            description: parsed
                .map(|a| a.describe().to_string())
                .unwrap_or_else(|| action.clone()),
            notable: parsed.map(|a| a.is_notable()).unwrap_or(false),
            action,
            record_id,
            record_title,
            detail,
        });
    }
    Ok(out)
}

fn parse_action(s: &str) -> Option<Action> {
    const ALL: &[Action] = &[
        Action::VaultCreated,
        Action::VaultUnlocked,
        Action::VaultLocked,
        Action::MasterPasswordChanged,
        Action::RecordCreated,
        Action::RecordEdited,
        Action::RecordTrashed,
        Action::RecordRestored,
        Action::RecordPurged,
        Action::RecordDuplicated,
        Action::AttachmentAdded,
        Action::AttachmentRemoved,
        Action::AttachmentExtracted,
        Action::FieldRevealed,
        Action::FieldCopied,
        Action::RdpLaunched,
        Action::SshLaunched,
        Action::CloudShellOpened,
        Action::BackupCreated,
        Action::BackupFailed,
        Action::BackupRestored,
        Action::Imported,
        Action::ExportedPlaintext,
        Action::ExportedEncrypted,
        Action::SettingChanged,
    ];
    ALL.iter().copied().find(|a| a.as_str() == s)
}

/// Keep the newest `limit` entries.
pub fn trim(conn: &Connection, limit: i64) -> Result<usize> {
    let removed = conn.execute(
        "DELETE FROM activity_log WHERE id NOT IN (
             SELECT id FROM activity_log ORDER BY at DESC, id DESC LIMIT ?1
         )",
        params![limit.max(1)],
    )?;
    Ok(removed)
}

/// Erase the log entirely. Offered in Settings, because a log the user cannot
/// clear is surveillance rather than a feature.
pub fn clear(conn: &Connection) -> Result<usize> {
    let removed = conn.execute("DELETE FROM activity_log", [])?;
    Ok(removed)
}

pub fn count(conn: &Connection) -> Result<i64> {
    let n = conn.query_row("SELECT COUNT(*) FROM activity_log", [], |r| r.get(0))?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::schema::initialize(&conn).unwrap();
        conn
    }

    #[test]
    fn entries_come_back_newest_first_with_descriptions() {
        let conn = db();
        record(&conn, Action::VaultUnlocked, None, None).unwrap();
        record(&conn, Action::RecordCreated, Some("r1"), Some("ssh_server")).unwrap();

        let entries = list(&conn, 10, None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "record_created");
        assert_eq!(entries[0].description, "Record created");
        assert_eq!(entries[0].detail.as_deref(), Some("ssh_server"));
    }

    #[test]
    fn plaintext_export_is_flagged_notable() {
        let conn = db();
        record(&conn, Action::ExportedPlaintext, None, Some("412 records")).unwrap();
        let entries = list(&conn, 10, None).unwrap();
        assert!(entries[0].notable);
        assert!(entries[0].description.contains("PLAINTEXT"));
    }

    #[test]
    fn filtering_by_action_works() {
        let conn = db();
        record(&conn, Action::VaultUnlocked, None, None).unwrap();
        record(&conn, Action::VaultLocked, None, None).unwrap();
        record(&conn, Action::VaultLocked, None, None).unwrap();

        let locked = list(&conn, 10, Some("vault_locked")).unwrap();
        assert_eq!(locked.len(), 2);
    }

    #[test]
    fn trim_keeps_the_newest_and_drops_the_rest() {
        let conn = db();
        for _ in 0..50 {
            record(&conn, Action::FieldCopied, None, None).unwrap();
        }
        assert_eq!(count(&conn).unwrap(), 50);
        trim(&conn, 10).unwrap();
        assert_eq!(count(&conn).unwrap(), 10);
    }

    #[test]
    fn a_purged_record_leaves_a_readable_entry() {
        let conn = db();
        record(&conn, Action::RecordPurged, Some("gone-id"), Some("Old server")).unwrap();
        let entries = list(&conn, 10, None).unwrap();
        // The join finds no title, which is expected and must not error.
        assert!(entries[0].record_title.is_none());
        assert_eq!(entries[0].detail.as_deref(), Some("Old server"));
    }

    #[test]
    fn clearing_empties_the_log() {
        let conn = db();
        record(&conn, Action::VaultUnlocked, None, None).unwrap();
        clear(&conn).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
    }
}
