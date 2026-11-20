//! Backup, import and export commands (Phase 7).
//!
//! The plaintext export path is the one worth reading twice. Its two-step
//! confirmation is enforced here, in Rust, by a token the frontend cannot
//! forge (D-37). A React bug cannot produce a plaintext dump of every
//! credential the user owns.

use std::path::PathBuf;
use std::time::Duration;

use tauri::State;
use zeroize::Zeroizing;

use keyring_vault::backup::{self, Trigger};
use keyring_vault::db;
use keyring_vault::portable::{bridge, export, import};

use crate::error::{AppError, Result};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupStatus {
    /// `None` means unconfigured, which the UI must warn about (FR-8.4).
    pub backup_dir: Option<String>,
    pub configured: bool,
    pub automatic: bool,
    pub retention: usize,
    /// Unix seconds of the newest snapshot (FR-8.5).
    pub last_backup_at: Option<i64>,
    pub snapshot_count: usize,
    pub total_bytes: u64,
    /// Seconds until the debounced backup fires. `None` when nothing is owed.
    pub pending_in_secs: Option<u64>,
    /// Set when the last attempt failed, so a silently broken backup folder
    /// cannot look identical to a working one.
    pub last_error: Option<String>,
}

#[tauri::command]
pub fn backup_status(state: State<AppState>) -> Result<BackupStatus> {
    let (dir, automatic, retention) = state.with_session(|session| {
        let conn = session.conn()?;
        Ok((
            db::settings::get(conn, db::settings::BACKUP_DIR)?,
            db::settings::get_bool(conn, db::settings::BACKUP_AUTOMATIC, true),
            db::settings::get_i64(conn, db::settings::BACKUP_RETENTION, 10) as usize,
        ))
    })?;

    let dir_path = dir.as_ref().map(PathBuf::from);
    let snapshots = dir_path
        .as_ref()
        .map(|p| backup::list_snapshots(p).unwrap_or_default())
        .unwrap_or_default();

    Ok(BackupStatus {
        configured: dir_path.is_some(),
        last_backup_at: snapshots.first().map(|s| s.created_at),
        snapshot_count: snapshots.len(),
        total_bytes: snapshots.iter().map(|s| s.total_bytes).sum(),
        backup_dir: dir,
        automatic,
        retention,
        pending_in_secs: state.backup_scheduler().seconds_until_due(),
        last_error: state.last_backup_error(),
    })
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotView {
    pub path: String,
    pub stamp: String,
    pub created_at: i64,
    pub total_bytes: u64,
    pub record_count: Option<i64>,
    pub attachment_count: Option<usize>,
    pub trigger: Option<String>,
}

#[tauri::command]
pub fn list_backups(state: State<AppState>) -> Result<Vec<SnapshotView>> {
    let dir = state.with_session(|session| {
        let conn = session.conn()?;
        Ok(db::settings::get(conn, db::settings::BACKUP_DIR)?)
    })?;

    let Some(dir) = dir else {
        return Ok(Vec::new());
    };

    let snapshots = backup::list_snapshots(std::path::Path::new(&dir))?;
    Ok(snapshots
        .into_iter()
        .map(|s| SnapshotView {
            path: s.path.to_string_lossy().into_owned(),
            stamp: s.stamp,
            created_at: s.created_at,
            total_bytes: s.total_bytes,
            record_count: s.manifest.as_ref().map(|m| m.record_count),
            attachment_count: s.manifest.as_ref().map(|m| m.attachment_count),
            trigger: s.manifest.as_ref().map(|m| m.trigger.as_str().to_string()),
        })
        .collect())
}

/// FR-8.3. Also the path the scheduler calls.
#[tauri::command]
pub fn backup_now(state: State<AppState>) -> Result<SnapshotView> {
    let snapshot = state.run_backup(Trigger::Manual)?;
    Ok(SnapshotView {
        path: snapshot.path.to_string_lossy().into_owned(),
        stamp: snapshot.stamp,
        created_at: snapshot.created_at,
        total_bytes: snapshot.total_bytes,
        record_count: snapshot.manifest.as_ref().map(|m| m.record_count),
        attachment_count: snapshot.manifest.as_ref().map(|m| m.attachment_count),
        trigger: Some("manual".to_string()),
    })
}

#[tauri::command]
pub fn set_backup_dir(state: State<AppState>, path: Option<String>) -> Result<()> {
    // Validate before storing: a backup folder that does not exist is a
    // backup configuration that silently does nothing.
    if let Some(p) = &path {
        let dir = std::path::Path::new(p);
        std::fs::create_dir_all(dir).map_err(|_| {
            AppError::invalid("Keyring could not create or reach that folder.")
        })?;

        // Refuse to back a vault up into itself. The snapshot would be
        // inside the thing being snapshotted, and each backup would contain
        // every previous one.
        let vault_root = state.with_session(|s| Ok(s.paths().root.clone()))?;
        if dir.starts_with(&vault_root) {
            return Err(AppError::invalid(
                "That folder is inside the vault. Choose somewhere else — ideally a folder your cloud sync already watches.",
            ));
        }
    }

    state.with_session_mut(|session| {
        let conn = session.conn()?;
        match &path {
            Some(p) => db::settings::set(conn, db::settings::BACKUP_DIR, p)?,
            None => db::settings::set(conn, db::settings::BACKUP_DIR, "")?,
        }
        db::activity::record(
            conn,
            db::activity::Action::SettingChanged,
            None,
            Some("backup folder"),
        )?;
        session.touch();
        Ok(session.save()?)
    })?;

    Ok(())
}

#[tauri::command]
pub fn set_backup_retention(state: State<AppState>, keep: u32) -> Result<()> {
    let keep = keep.clamp(1, 200);
    state.with_session_mut(|session| {
        let conn = session.conn()?;
        db::settings::set(conn, db::settings::BACKUP_RETENTION, &keep.to_string())?;
        session.touch();
        Ok(session.save()?)
    })
}

#[tauri::command]
pub fn set_backup_automatic(state: State<AppState>, enabled: bool) -> Result<()> {
    state.with_session_mut(|session| {
        let conn = session.conn()?;
        db::settings::set(
            conn,
            db::settings::BACKUP_AUTOMATIC,
            if enabled { "true" } else { "false" },
        )?;
        session.touch();
        Ok(session.save()?)
    })?;
    state.backup_scheduler().set_enabled(enabled);
    Ok(())
}

/// Restore a snapshot into a folder.
///
/// Deliberately does **not** restore over the open vault. The user picks a
/// destination, Keyring writes there, and then they open it like any other
/// vault. Overwriting a live vault during a recovery is how the good copy
/// gets destroyed while rescuing the bad one.
#[tauri::command]
pub fn restore_backup(
    state: State<AppState>,
    snapshot_path: String,
    destination: String,
) -> Result<String> {
    let source = PathBuf::from(&snapshot_path);
    let dest = PathBuf::from(&destination);

    backup::restore_snapshot(&source, &dest)?;

    // Best-effort: if a vault is open, note it. If not, the restore still
    // happened and that is what matters.
    let _ = state.with_session_mut(|session| {
        let conn = session.conn()?;
        Ok(db::activity::record(
            conn,
            db::activity::Action::BackupRestored,
            None,
            Some(&snapshot_path),
        )?)
    });

    tracing::info!(from = %snapshot_path, to = %destination, "backup restored");
    Ok(dest.to_string_lossy().into_owned())
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub source: String,
    pub total: usize,
    /// Titles and types only. **Never any field value** — a preview that
    /// showed passwords would put every imported credential into the webview
    /// heap for no reason.
    pub sample: Vec<PreviewRow>,
    pub type_counts: Vec<(String, usize)>,
    pub attachments_dropped: usize,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewRow {
    pub row: usize,
    pub title: String,
    pub record_type: String,
    pub folder: String,
    pub field_count: usize,
}

/// Parse an import file and report what *would* happen, without writing.
///
/// A dry run first, always. An import that silently mangles four hundred
/// records is not recoverable by undo.
#[tauri::command]
pub fn preview_import(source: String, path: String) -> Result<ImportPreview> {
    let source = import::ImportSource::parse(&source)
        .ok_or_else(|| AppError::invalid("Unknown import format."))?;

    let text = import::read_source_file(std::path::Path::new(&path))?;
    let (parsed, attachments_dropped) = import::parse(source, &text)?;

    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, record) in &parsed {
        *counts.entry(record.record_type.clone()).or_insert(0) += 1;
    }
    let mut type_counts: Vec<(String, usize)> = counts.into_iter().collect();
    type_counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let sample = parsed
        .iter()
        .take(20)
        .map(|(row, r)| PreviewRow {
            row: *row,
            title: r.title.clone(),
            record_type: r.record_type.clone(),
            folder: r.folder.clone(),
            field_count: r.fields.len(),
        })
        .collect();

    Ok(ImportPreview {
        source: source.as_str().to_string(),
        total: parsed.len(),
        sample,
        type_counts,
        attachments_dropped,
    })
}

#[tauri::command]
pub fn run_import(
    state: State<AppState>,
    source: String,
    path: String,
    into_folder: Option<String>,
    skip_duplicates: bool,
) -> Result<import::ImportReport> {
    let source = import::ImportSource::parse(&source)
        .ok_or_else(|| AppError::invalid("Unknown import format."))?;

    let text = import::read_source_file(std::path::Path::new(&path))?;
    let (parsed, attachments_dropped) = import::parse(source, &text)?;

    if parsed.is_empty() {
        return Err(AppError::invalid("That file contains no records."));
    }

    // Safety snapshot before a bulk write. Best-effort: a missing backup
    // folder must not block an import, but a configured one should be used.
    let _ = state.run_backup(Trigger::Safety);

    let report = state.with_session_mut(|session| {
        Ok(bridge::apply(
            session,
            parsed,
            source,
            into_folder.as_deref(),
            skip_duplicates,
            attachments_dropped,
        )?)
    })?;

    state.rebuild_index();
    Ok(report)
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Step one of the plaintext export. Returns a token that expires in two
/// minutes and can be spent exactly once.
#[tauri::command]
pub fn begin_plaintext_export(state: State<AppState>) -> Result<String> {
    // Only from an unlocked vault, and only once the user has already seen the
    // first warning. The frontend shows the second one.
    state.with_session(|_| Ok(()))?;
    Ok(state.plaintext_gate().issue()?)
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportArgs {
    /// "encrypted_json" or "plaintext_json".
    pub format: String,
    pub path: String,
    pub folder: Option<String>,
    /// Required for the encrypted format.
    pub passphrase: Option<String>,
    /// Required for the plaintext format. Issued by `begin_plaintext_export`.
    pub confirmation_token: Option<String>,
}

#[tauri::command]
pub fn run_export(state: State<AppState>, args: ExportArgs) -> Result<export::ExportSummary> {
    let folder = args.folder.filter(|f| !f.trim().is_empty());
    let path = PathBuf::from(&args.path);

    match args.format.as_str() {
        "encrypted_json" => {
            let passphrase = Zeroizing::new(
                args.passphrase
                    .ok_or_else(|| AppError::invalid("An encrypted export needs a passphrase."))?,
            );

            let (records, attachments) = state.with_session(|session| {
                Ok((
                    bridge::collect(session, folder.as_deref())?,
                    bridge::count_attachments(session, folder.as_deref())?,
                ))
            })?;

            if records.is_empty() {
                return Err(AppError::invalid("There is nothing to export."));
            }

            let count = records.len();
            let field_count: usize = records.iter().map(|r| r.fields.len()).sum();
            let bytes = export::build_encrypted(records, folder.clone(), &passphrase)?;
            std::fs::write(&path, &bytes)
                .map_err(|_| AppError::invalid("Keyring could not write to that location."))?;

            state.with_session_mut(|session| {
                let conn = session.conn()?;
                db::activity::record(
                    conn,
                    db::activity::Action::ExportedEncrypted,
                    None,
                    Some(&format!("{count} records")),
                )?;
                session.touch();
                Ok(session.save()?)
            })?;

            Ok(export::ExportSummary {
                format: "encrypted_json".to_string(),
                record_count: count,
                field_count,
                folder,
                bytes_written: bytes.len() as u64,
                attachments_excluded: attachments,
            })
        }

        "plaintext_json" => {
            // The gate. Everything about this ordering is deliberate.
            let token = args.confirmation_token.ok_or_else(|| {
                AppError::invalid("That confirmation has expired. Start the plaintext export again.")
            })?;
            state.plaintext_gate().redeem(&token)?;

            let (records, attachments) = state.with_session(|session| {
                Ok((
                    bridge::collect(session, folder.as_deref())?,
                    bridge::count_attachments(session, folder.as_deref())?,
                ))
            })?;

            if records.is_empty() {
                return Err(AppError::invalid("There is nothing to export."));
            }

            let count = records.len();
            let field_count: usize = records.iter().map(|r| r.fields.len()).sum();

            // Logged BEFORE the file is written, so the record survives a
            // failed write. This is the one event that must never be missing.
            state.with_session_mut(|session| {
                let conn = session.conn()?;
                db::activity::record(
                    conn,
                    db::activity::Action::ExportedPlaintext,
                    None,
                    Some(&format!("{count} records to {}", args.path)),
                )?;
                session.touch();
                Ok(session.save()?)
            })?;

            let bytes = export::build_plaintext(records, folder.clone())?;
            std::fs::write(&path, &bytes)
                .map_err(|_| AppError::invalid("Keyring could not write to that location."))?;

            tracing::warn!(
                records = count,
                path = %args.path,
                "PLAINTEXT EXPORT written"
            );

            Ok(export::ExportSummary {
                format: "plaintext_json".to_string(),
                record_count: count,
                field_count,
                folder,
                bytes_written: bytes.len() as u64,
                attachments_excluded: attachments,
            })
        }

        _ => Err(AppError::invalid("Unknown export format.")),
    }
}

/// Read a Keyring encrypted export back in.
#[tauri::command]
pub fn import_keyring_export(
    state: State<AppState>,
    path: String,
    passphrase: String,
    into_folder: Option<String>,
) -> Result<import::ImportReport> {
    let passphrase = Zeroizing::new(passphrase);
    let bytes = std::fs::read(&path)
        .map_err(|_| AppError::invalid("Keyring could not read that file."))?;

    let _ = state.run_backup(Trigger::Safety);

    let report = state.with_session_mut(|session| {
        Ok(bridge::apply_encrypted_export(
            session,
            &bytes,
            &passphrase,
            into_folder.as_deref(),
        )?)
    })?;

    state.rebuild_index();
    Ok(report)
}

/// Background sweeper: fires the debounced backup when it comes due.
///
/// Separate from the temp-file sweeper because the cadences differ and because
/// a slow backup of a large vault must not delay the deletion of an extracted
/// private key.
pub fn spawn_backup_worker(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));

        use tauri::Manager;
        let Some(state) = app.try_state::<AppState>() else {
            continue;
        };
        if state.is_locked() {
            continue;
        }
        if !state.backup_scheduler().is_due() {
            continue;
        }
        if !state.backup_scheduler().claim() {
            continue;
        }

        match state.run_backup(Trigger::Automatic) {
            Ok(snapshot) => {
                tracing::info!(stamp = %snapshot.stamp, "automatic backup complete");
                use tauri::Emitter;
                let _ = app.emit("backup-complete", snapshot.created_at);
            }
            Err(e) => {
                tracing::warn!(error = %e, "automatic backup failed");
                // Put the job back: a failed backup is still an owed backup.
                state.backup_scheduler().requeue();
                use tauri::Emitter;
                let _ = app.emit("backup-failed", e.message.clone());
            }
        }
    });
}
