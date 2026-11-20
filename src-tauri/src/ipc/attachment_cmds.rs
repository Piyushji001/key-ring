//! Attachment commands (FR-3).
//!
//! ## Why this file did not exist until now
//!
//! `keyring-vault` has had working attachment storage since Phase 2, and
//! Phase 5 shipped extraction with a cleanup registry. But nothing ever
//! exposed *adding* one across IPC, so the only way to get a file into a vault
//! was the developer CLI. FR-3.1 was implemented and unreachable.
//!
//! It matters more than a missing button: Phase 7's definition of done
//! requires restoring a backup "including attachments", and there was no way
//! to create the test fixture through the product.
//!
//! ## The size limit
//!
//! FR-3.1 says 50 MB per file. That number is not arbitrary — the whole vault
//! is loaded into memory on unlock and rewritten atomically on save, so an
//! attachment is paid for three times over: once in the blob, once in the
//! read buffer, and once in the write buffer. A 500 MB ISO would work and
//! would also make every subsequent save unbearable.
//!
//! ## Preview (FR-3.4)
//!
//! Text-based attachments can be shown in the app without writing to disk.
//! This is the *safer* path and should be preferred over extraction wherever
//! it works: no file, no ACL, no cleanup deadline, nothing left behind if the
//! process dies.
//!
//! It does mean the content crosses IPC as a string, which is a plaintext
//! crossing and is treated as one — capped in size, only on explicit request,
//! and never for anything that does not look like text.

use tauri::State;

use keyring_vault::db;

use crate::error::{AppError, Result};
use crate::state::AppState;

/// FR-3.1.
pub const MAX_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;

/// Largest preview returned across IPC. Two megabytes of PEM or JSON is
/// already far more than anyone reads on screen.
const MAX_PREVIEW_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentAdded {
    pub id: String,
    pub filename: String,
    pub size_bytes: u64,
    /// Hex SHA-256, so the user can verify the file arrived intact without
    /// extracting it again.
    pub sha256: String,
}

#[tauri::command]
pub fn add_attachment(
    state: State<AppState>,
    record_id: String,
    path: String,
) -> Result<AttachmentAdded> {
    let source = std::path::Path::new(&path);

    let metadata = std::fs::metadata(source)
        .map_err(|_| AppError::invalid("Keyring could not read that file."))?;
    if !metadata.is_file() {
        return Err(AppError::invalid("That is a folder, not a file."));
    }
    if metadata.len() > MAX_ATTACHMENT_BYTES {
        return Err(AppError::invalid(format!(
            "That file is {:.1} MB. The limit is 50 MB per attachment.",
            metadata.len() as f64 / (1024.0 * 1024.0)
        )));
    }
    if metadata.len() == 0 {
        return Err(AppError::invalid("That file is empty."));
    }

    let filename = source
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment")
        .to_string();

    let id = state.with_session_mut(|session| {
        let id = session.add_attachment(&record_id, source)?;
        let conn = session.conn()?;
        db::activity::record(
            conn,
            db::activity::Action::AttachmentAdded,
            Some(&record_id),
            Some(&filename),
        )?;
        session.save()?;
        Ok(id)
    })?;

    // The index carries attachment filenames (FR-4.1).
    state.rebuild_index();
    state.mark_dirty_for_backup();

    let sha256 = state.with_session(|session| {
        let conn = session.conn()?;
        let rows = db::attachments::list_for_record(conn, &record_id)?;
        Ok(rows
            .into_iter()
            .find(|a| a.id == id)
            .map(|a| hex(&a.sha256))
            .unwrap_or_default())
    })?;

    tracing::info!(record = %record_id, file = %filename, bytes = metadata.len(), "attachment added");

    Ok(AttachmentAdded {
        id,
        filename,
        size_bytes: metadata.len(),
        sha256,
    })
}

#[tauri::command]
pub fn remove_attachment(
    state: State<AppState>,
    record_id: String,
    attachment_id: String,
) -> Result<()> {
    state.with_session_mut(|session| {
        let paths = session.paths().clone();
        let conn = session.conn()?;
        let filename = db::attachments::list_for_record(conn, &record_id)?
            .into_iter()
            .find(|a| a.id == attachment_id)
            .map(|a| a.filename)
            .unwrap_or_default();

        db::attachments::remove(conn, &paths, &attachment_id)?;
        db::activity::record(
            conn,
            db::activity::Action::AttachmentRemoved,
            Some(&record_id),
            Some(&filename),
        )?;
        session.touch();
        Ok(session.save()?)
    })?;

    state.rebuild_index();
    state.mark_dirty_for_backup();
    Ok(())
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentPreview {
    pub filename: String,
    /// Decoded text. Absent when the file is not text.
    pub text: Option<String>,
    pub is_text: bool,
    pub truncated: bool,
    pub size_bytes: u64,
    /// A guess at the syntax, for highlighting: "json", "pem", "yaml", "text".
    pub kind: String,
}

/// FR-3.4. Show a text attachment without writing it to disk.
#[tauri::command]
pub fn preview_attachment(
    state: State<AppState>,
    record_id: String,
    attachment_id: String,
) -> Result<AttachmentPreview> {
    let (filename, data) = state.with_session(|session| {
        let conn = session.conn()?;
        let row = db::attachments::list_for_record(conn, &record_id)?
            .into_iter()
            .find(|a| a.id == attachment_id)
            .ok_or_else(|| AppError::new(crate::error::ErrorKind::NotFound, "No such attachment."))?;
        let data = session.open_attachment(&attachment_id)?;
        Ok((row.filename, data))
    })?;

    let size_bytes = data.len() as u64;

    // A file is text if it decodes as UTF-8 and holds no NUL bytes. Both
    // checks: valid UTF-8 alone lets a lot of binary through.
    let looks_binary = data.iter().take(8192).any(|b| *b == 0);
    let decoded = if looks_binary {
        None
    } else {
        std::str::from_utf8(&data).ok()
    };

    let Some(text) = decoded else {
        return Ok(AttachmentPreview {
            filename,
            text: None,
            is_text: false,
            truncated: false,
            size_bytes,
            kind: "binary".to_string(),
        });
    };

    let truncated = text.len() > MAX_PREVIEW_BYTES;
    let shown = if truncated {
        // Cut on a character boundary, not a byte one.
        let mut end = MAX_PREVIEW_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    } else {
        text.to_string()
    };

    let kind = classify(&filename, &shown);

    tracing::info!(record = %record_id, file = %filename, "attachment previewed in app");

    Ok(AttachmentPreview {
        filename,
        text: Some(shown),
        is_text: true,
        truncated,
        size_bytes,
        kind,
    })
}

fn classify(filename: &str, content: &str) -> String {
    let lower = filename.to_lowercase();
    if lower.ends_with(".json") {
        return "json".to_string();
    }
    if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        return "yaml".to_string();
    }
    if lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".crt")
        || lower.ends_with(".cer")
    {
        return "pem".to_string();
    }
    // Fall back to the content, because DevOps files are frequently named
    // things like `id_rsa` with no extension at all.
    let head = content.trim_start();
    if head.starts_with("-----BEGIN") {
        return "pem".to_string();
    }
    if head.starts_with('{') || head.starts_with('[') {
        return "json".to_string();
    }
    "text".to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_prefers_the_extension_then_the_content() {
        assert_eq!(classify("key.json", "{}"), "json");
        assert_eq!(classify("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----"), "pem");
        assert_eq!(classify("config", "{\"a\":1}"), "json");
        assert_eq!(classify("notes", "hello"), "text");
        assert_eq!(classify("stack.yml", "a: 1"), "yaml");
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
    }
}
