//! Commands that act on secrets without returning them.
//!
//! Read `actions/mod.rs` for why this module exists. In short: `copy_field`
//! takes a record id and a field name and returns whether it worked. The
//! plaintext is decrypted, written to the clipboard and dropped, entirely
//! inside Rust.

use std::time::Duration;

use keyring_vault::db;
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

use crate::actions::{clipboard, tempfile::TempRegistry};
use crate::error::{AppError, Result};
use crate::model::dto::{ClipboardStatus, ExtractResult};
use crate::state::AppState;

/// FR-6.2 default. Configurable per vault in Settings.
const DEFAULT_CLEAR_SECS: u64 = 30;
/// FR-3.3 / UC-07 default.
const DEFAULT_TEMPFILE_SECS: u64 = 300;

fn clear_after(state: &AppState) -> u64 {
    state
        .with_session(|s| {
            Ok(db::settings::get_i64(
                s.conn()?,
                db::settings::CLIPBOARD_CLEAR_SECS,
                DEFAULT_CLEAR_SECS as i64,
            ) as u64)
        })
        .unwrap_or(DEFAULT_CLEAR_SECS)
}

/// Copy a field to the clipboard and schedule the clear.
///
/// `field` may name a secret or a plaintext field; both are handled here so the
/// UI does not have to know which is which before asking.
#[tauri::command]
pub fn copy_field(
    state: State<'_, AppState>,
    app: AppHandle,
    record_id: String,
    field: String,
) -> Result<ClipboardStatus> {
    let value: Zeroizing<String> = state.with_session(|session| {
        let conn = session.conn()?;
        let row = db::fields::get(conn, &record_id, &field)?
            .ok_or_else(|| AppError::invalid("That field is not on this record."))?;

        if row.has_secret {
            let bytes = session.open_secret(&record_id, &field)?;
            Ok(Zeroizing::new(
                String::from_utf8(bytes.to_vec())
                    .map_err(|_| AppError::invalid("That value is not text."))?,
            ))
        } else {
            Ok(Zeroizing::new(row.plain_value.unwrap_or_default()))
        }
    })?;

    if value.is_empty() {
        return Err(AppError::invalid("There is nothing stored in that field."));
    }

    let outcome = clipboard::write(&value)?;
    let fingerprint = clipboard::fingerprint(&value);
    // `value` drops here and wipes itself. Nothing below touches plaintext.

    let seconds = clear_after(&state);
    let generation = state.begin_clipboard_hold(fingerprint, seconds);
    schedule_clear(app.clone(), generation, fingerprint, seconds);

    let _ = state.with_session_mut(|s| Ok(s.mark_used(&record_id)?));
    state.rebuild_index();

    tracing::info!(record = %record_id, field = %field, "copied to clipboard");

    Ok(ClipboardStatus {
        active: true,
        field: Some(field),
        seconds_remaining: seconds as u32,
        excluded_from_history: outcome.excluded_from_history,
    })
}

/// Copy whatever a record's primary action would copy. Used by the overlay's
/// Enter key, so the UI does not have to know each type's primary field.
#[tauri::command]
pub fn copy_primary(
    state: State<'_, AppState>,
    app: AppHandle,
    record_id: String,
) -> Result<ClipboardStatus> {
    let field = state.with_session(|session| {
        let conn = session.conn()?;
        let row = db::records::require(conn, &record_id)?;
        row.record_type
            .primary_field()
            .map(|s| s.to_string())
            .ok_or_else(|| AppError::invalid("This record has no primary field."))
    })?;

    copy_field(state, app, record_id, field)
}

/// `Ctrl+Enter` in the overlay. Falls back sensibly for types with no username.
#[tauri::command]
pub fn copy_username(
    state: State<'_, AppState>,
    app: AppHandle,
    record_id: String,
) -> Result<ClipboardStatus> {
    let field = state.with_session(|session| {
        let conn = session.conn()?;
        for candidate in ["username", "account_email", "key_id", "common_name"] {
            if let Some(row) = db::fields::get(conn, &record_id, candidate)? {
                if row.plain_value.as_deref().unwrap_or("").len() > 0 {
                    return Ok(candidate.to_string());
                }
            }
        }
        Err(AppError::invalid("This record has no username."))
    })?;

    copy_field(state, app, record_id, field)
}

/// Clear now, from the toast's "Clear now" button.
#[tauri::command]
pub fn clear_clipboard(state: State<'_, AppState>, app: AppHandle) -> Result<()> {
    state.end_clipboard_hold();
    clipboard::clear_now()?;
    let _ = app.emit("clipboard-cleared", ());
    Ok(())
}

#[tauri::command]
pub fn clipboard_status(state: State<'_, AppState>) -> ClipboardStatus {
    state.clipboard_status()
}

/// Spawn the timed clear.
///
/// The generation counter is what makes overlapping copies safe: copying a
/// second value supersedes the first, and the first timer finds a stale
/// generation and does nothing.
fn schedule_clear(app: AppHandle, generation: u64, fingerprint: [u8; 32], seconds: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(seconds));

        use tauri::Manager;
        let Some(state) = app.try_state::<AppState>() else {
            return;
        };
        if !state.clipboard_generation_is(generation) {
            return; // Superseded by a newer copy.
        }

        match clipboard::clear_if_ours(&fingerprint) {
            Ok(true) => {
                state.end_clipboard_hold();
                let _ = app.emit("clipboard-cleared", ());
                tracing::info!("clipboard cleared on schedule");
            }
            Ok(false) => {
                // Someone else copied something. Leave it; stop tracking.
                state.end_clipboard_hold();
                let _ = app.emit("clipboard-cleared", ());
            }
            Err(e) => tracing::warn!(error = %e, "scheduled clipboard clear failed"),
        }
    });
}

// ------------------------------------------------------------- attachments

/// UC-07. Decrypt an attachment to a temp file and return only the path.
#[tauri::command]
pub fn extract_attachment(
    state: State<'_, AppState>,
    app: AppHandle,
    attachment_id: String,
    ttl_seconds: Option<u64>,
) -> Result<ExtractResult> {
    let (filename, data) = state.with_session(|session| {
        let conn = session.conn()?;
        let filename: String = conn.query_row(
            "SELECT filename FROM attachments WHERE id = ?1",
            [&attachment_id],
            |r| r.get(0),
        ).map_err(|e| AppError::from(keyring_vault::VaultError::Db(e)))?;
        let data = session.open_attachment(&attachment_id)?;
        Ok((filename, data))
    })?;

    let ttl = Duration::from_secs(ttl_seconds.unwrap_or(DEFAULT_TEMPFILE_SECS));
    let path = state.temp_files().extract(&filename, &data, ttl)?;
    drop(data);

    // The path is not a secret; the file it points at is, which is why it has
    // a deadline. Putting the path on the clipboard is the whole point - the
    // user pastes it into gcloud or ssh.
    let path_string = path.to_string_lossy().into_owned();
    let _ = clipboard::write(&path_string);

    let _ = app.emit("tempfile-extracted", &path_string);

    Ok(ExtractResult {
        path: path_string,
        filename,
        expires_in_seconds: ttl.as_secs() as u32,
    })
}

/// Everything currently on disk, so Settings can show it and the user can
/// delete it early.
#[tauri::command]
pub fn extracted_files(state: State<'_, AppState>) -> Vec<(String, u64)> {
    state.temp_files().active()
}

#[tauri::command]
pub fn purge_extracted(state: State<'_, AppState>) -> usize {
    state.temp_files().purge_all()
}

// -------------------------------------------------------------------- misc

/// FR-7.4. Opens a record's URL in the default browser.
///
/// Note what this is not: it is not Keyring making a network request. It hands
/// a URL to the shell and forgets about it. The scheme allowlist exists because
/// `file:` and custom protocol handlers are an attack surface.
#[tauri::command]
pub fn open_url(app: AppHandle, url: String) -> Result<()> {
    let lowered = url.trim().to_ascii_lowercase();
    if !(lowered.starts_with("https://") || lowered.starts_with("http://")) {
        return Err(AppError::invalid(
            "Only http and https links can be opened.",
        ));
    }

    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| AppError::internal("could not open the browser"))?;
    Ok(())
}

/// Registry sweeper. Started once at setup.
pub fn spawn_sweeper(app: AppHandle) {
    std::thread::spawn(move || {
        use tauri::Manager;
        loop {
            std::thread::sleep(Duration::from_secs(15));
            let Some(state) = app.try_state::<AppState>() else {
                return;
            };
            let removed = state.temp_files().sweep();
            if removed > 0 {
                let _ = app.emit("tempfiles-expired", removed);
            }
        }
    });
}

#[allow(dead_code)]
fn _registry_type_is_used(_: &TempRegistry) {}
