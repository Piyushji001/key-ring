//! Record CRUD and the sidebar. Phase 4.
//!
//! Every function returns types from `model::dto`. Read the banner in that file
//! before adding anything here.

use keyring_vault::{db, model::FieldKind, NewRecord, RecordFilter, RecordType};
use rusqlite;
use tauri::State;

use crate::error::{AppError, Result};
use crate::model::dto::{
    AttachmentView, CountedItem, FieldTemplateInfo, FieldView, RecordDetail, RecordSummary,
    RecordTypeInfo, RevealedValue,
};
use crate::state::AppState;

/// How long a revealed secret may stay on screen. UI Spec section 4.
const REVEAL_MS: u32 = 15_000;

fn parse_type(s: &str) -> Result<RecordType> {
    RecordType::parse(s).ok_or_else(|| AppError::invalid(format!("Unknown record type '{s}'.")))
}

/// Build the non-secret identifying line for a list row.
///
/// Only ever reads `plain_value`, so it cannot leak. The field order per type
/// is what a DevOps engineer would recognise the record by at a glance.
fn subtitle_for(
    conn: &rusqlite::Connection,
    record_id: &str,
    record_type: RecordType,
) -> Option<String> {
    let fields = db::fields::list_for_record(conn, record_id).ok()?;
    let get = |name: &str| -> Option<String> {
        fields
            .iter()
            .find(|f| f.name == name && !f.has_secret)
            .and_then(|f| f.plain_value.clone())
            .filter(|v| !v.is_empty())
    };

    match record_type {
        RecordType::SshServer | RecordType::RdpHost => {
            let host = get("host")?;
            Some(match get("username") {
                Some(user) => format!("{user}@{host}"),
                None => host,
            })
        }
        RecordType::ApiKey => get("provider").or_else(|| get("key_id")),
        RecordType::CloudServiceAccount => get("project_id")
            .or_else(|| get("access_key_id"))
            .or_else(|| get("cluster"))
            .or_else(|| get("client_id"))
            .or_else(|| get("provider")),
        RecordType::WebLogin => {
            let url = get("url");
            match (get("username"), url) {
                (Some(u), Some(url)) => Some(format!("{u} · {url}")),
                (Some(u), None) => Some(u),
                (None, url) => url,
            }
        }
        RecordType::Database => {
            let host = get("host")?;
            Some(match get("database") {
                Some(db_name) => format!("{db_name} @ {host}"),
                None => host,
            })
        }
        RecordType::Certificate => get("common_name").or_else(|| get("expires_at")),
        RecordType::CommandSnippet => get("description"),
        RecordType::SecureNote => None,
    }
}

fn summary_from(
    conn: &rusqlite::Connection,
    row: &keyring_vault::RecordRow,
) -> Result<RecordSummary> {
    Ok(RecordSummary {
        id: row.id.clone(),
        title: row.title.clone(),
        record_type: row.record_type.as_str().to_string(),
        type_label: row.record_type.label().to_string(),
        folder: row.folder.clone(),
        favorite: row.favorite,
        tags: db::tags::for_record(conn, &row.id)?,
        subtitle: subtitle_for(conn, &row.id, row.record_type),
        used_at: row.used_at,
        modified_at: row.modified_at,
        use_count: row.use_count,
        attachment_count: db::attachments::list_for_record(conn, &row.id)?.len() as u32,
        in_trash: row.deleted_at.is_some(),
    })
}

#[tauri::command]
pub fn list_records(
    state: State<'_, AppState>,
    record_type: Option<String>,
    folder: Option<String>,
    tag: Option<String>,
    favorites_only: Option<bool>,
    trash: Option<bool>,
) -> Result<Vec<RecordSummary>> {
    let filter = RecordFilter {
        record_type: match record_type.as_deref() {
            Some(t) => Some(parse_type(t)?),
            None => None,
        },
        folder,
        tag,
        favorites_only: favorites_only.unwrap_or(false),
        only_deleted: trash.unwrap_or(false),
        include_deleted: false,
        limit: None,
    };

    state.with_session(|session| {
        let conn = session.conn()?;
        let rows = db::records::list(conn, &filter)?;
        rows.iter().map(|r| summary_from(conn, r)).collect()
    })
}

#[tauri::command]
pub fn get_record(state: State<'_, AppState>, record_id: String) -> Result<RecordDetail> {
    state.with_session(|session| {
        let conn = session.conn()?;
        let row = db::records::require(conn, &record_id)?;
        let summary = summary_from(conn, &row)?;

        // A record shows its stored fields first, then any template field that
        // has not been filled in - so the form is complete without inventing
        // rows the user never created.
        let stored = db::fields::list_for_record(conn, &record_id)?;
        let mut fields: Vec<FieldView> = Vec::new();

        for f in &stored {
            let history_count = if f.has_secret {
                db::fields::list_history(conn, &f.id)?.len() as u32
            } else {
                0
            };
            fields.push(FieldView {
                name: f.name.clone(),
                label: f.label.clone(),
                kind: f.kind.as_str().to_string(),
                is_secret: f.has_secret,
                // The single line that enforces the whole boundary.
                value: if f.has_secret { None } else { f.plain_value.clone() },
                has_value: f.has_secret || f.plain_value.as_deref().unwrap_or("").len() > 0,
                history_count,
            });
        }

        for t in row.record_type.template() {
            if !stored.iter().any(|f| f.name == t.name) {
                fields.push(FieldView {
                    name: t.name.to_string(),
                    label: t.label.to_string(),
                    kind: t.kind.as_str().to_string(),
                    is_secret: t.secret,
                    value: None,
                    has_value: false,
                    history_count: 0,
                });
            }
        }

        let attachments = db::attachments::list_for_record(conn, &record_id)?
            .into_iter()
            .map(|a| AttachmentView {
                id: a.id,
                filename: a.filename,
                size_bytes: a.size_bytes,
                created_at: a.created_at,
            })
            .collect();

        Ok(RecordDetail {
            created_at: row.created_at,
            primary_field: row.record_type.primary_field().map(|s| s.to_string()),
            summary,
            fields,
            attachments,
        })
    })
}

#[tauri::command]
pub fn create_record(
    state: State<'_, AppState>,
    record_type: String,
    title: String,
    folder: String,
    values: Vec<(String, String)>,
) -> Result<String> {
    let record_type = parse_type(&record_type)?;
    if title.trim().is_empty() {
        return Err(AppError::invalid("A record needs a title."));
    }
    let id = state.with_session_mut(|session| {
        let id = session.create_record(record_type, title.trim(), folder.trim(), &values)?;
        session.save()?;
        Ok(id)
    })?;
    state.rebuild_index();
    Ok(id)
}

#[tauri::command]
pub fn set_field(
    state: State<'_, AppState>,
    record_id: String,
    name: String,
    value: String,
) -> Result<()> {
    state.with_session_mut(|session| {
        session.set_field(&record_id, &name, &value)?;
        session.save()?;
        Ok(())
    })?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn delete_field(state: State<'_, AppState>, record_id: String, name: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.delete_field(&record_id, &name)?))?;
    state.rebuild_index();
    Ok(())
}

/// Add a user-defined field. `secret` decides whether it is encrypted, and the
/// choice is the user's rather than a guess from the name.
#[tauri::command]
pub fn add_custom_field(
    state: State<'_, AppState>,
    record_id: String,
    name: String,
    value: String,
    secret: bool,
) -> Result<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::invalid("A field needs a name."));
    }
    let key = if secret { format!("secret:{name}") } else { name };
    state.with_session_mut(|session| {
        session.set_field(&record_id, &key, &value)?;
        session.save()?;
        Ok(())
    })?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn rename_record(state: State<'_, AppState>, record_id: String, title: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.rename_record(&record_id, &title)?))?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn move_record(state: State<'_, AppState>, record_id: String, folder: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.move_record(&record_id, &folder)?))?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn set_favorite(
    state: State<'_, AppState>,
    record_id: String,
    favorite: bool,
) -> Result<()> {
    state.with_session_mut(|s| Ok(s.set_favorite(&record_id, favorite)?))?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn add_tag(state: State<'_, AppState>, record_id: String, tag: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.add_tag(&record_id, &tag)?))?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn remove_tag(state: State<'_, AppState>, record_id: String, tag: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.remove_tag(&record_id, &tag)?))?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn duplicate_record(
    state: State<'_, AppState>,
    record_id: String,
    title: String,
) -> Result<String> {
    let id = state.with_session_mut(|s| Ok(s.duplicate_record(&record_id, &title)?))?;
    state.rebuild_index();
    Ok(id)
}

/// Move to trash. Recoverable for the retention window (default 30 days).
#[tauri::command]
pub fn trash_record(state: State<'_, AppState>, record_id: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.trash_record(&record_id)?))?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn restore_record(state: State<'_, AppState>, record_id: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.restore_record(&record_id)?))?;
    state.rebuild_index();
    Ok(())
}

/// Permanent. The UI must confirm before calling this.
#[tauri::command]
pub fn purge_record(state: State<'_, AppState>, record_id: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.purge_record(&record_id)?))?;
    state.rebuild_index();
    Ok(())
}

#[tauri::command]
pub fn mark_used(state: State<'_, AppState>, record_id: String) -> Result<()> {
    state.with_session_mut(|s| Ok(s.mark_used(&record_id)?))?;
    state.rebuild_index();
    Ok(())
}

/// The record type catalogue, so the form is data-driven and TypeScript never
/// duplicates the field templates.
#[tauri::command]
pub fn record_types() -> Vec<RecordTypeInfo> {
    RecordType::ALL
        .into_iter()
        .map(|t| RecordTypeInfo {
            key: t.as_str().to_string(),
            label: t.label().to_string(),
            primary_field: t.primary_field().map(|s| s.to_string()),
            fields: t
                .template()
                .iter()
                .map(|f| FieldTemplateInfo {
                    name: f.name.to_string(),
                    label: f.label.to_string(),
                    kind: f.kind.as_str().to_string(),
                    secret: f.secret,
                })
                .collect(),
        })
        .collect()
}

#[tauri::command]
pub fn sidebar_data(state: State<'_, AppState>) -> Result<crate::model::dto::SidebarData> {
    state.with_session(|session| {
        let conn = session.conn()?;

        let mut types = Vec::new();
        for t in RecordType::ALL {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM records WHERE type = ?1 AND deleted_at IS NULL",
                [t.as_str()],
                |r| r.get(0),
            ).map_err(|e| AppError::from(keyring_vault::VaultError::Db(e)))?;
            if count > 0 {
                types.push(CountedItem {
                    key: t.as_str().to_string(),
                    label: t.label().to_string(),
                    count,
                });
            }
        }

        let folders = db::tags::folders(conn)?
            .into_iter()
            .filter(|(name, _)| !name.is_empty())
            .map(|(name, count)| CountedItem {
                key: name.clone(),
                label: name,
                count,
            })
            .collect();

        let tags = db::tags::counts(conn)?
            .into_iter()
            .map(|(name, count)| CountedItem {
                key: name.clone(),
                label: name,
                count,
            })
            .collect();

        let favorites: i64 = conn.query_row(
            "SELECT COUNT(*) FROM records WHERE favorite = 1 AND deleted_at IS NULL",
            [],
            |r| r.get(0),
        ).map_err(|e| AppError::from(keyring_vault::VaultError::Db(e)))?;
        let trash: i64 = conn.query_row(
            "SELECT COUNT(*) FROM records WHERE deleted_at IS NOT NULL",
            [],
            |r| r.get(0),
        ).map_err(|e| AppError::from(keyring_vault::VaultError::Db(e)))?;

        Ok(crate::model::dto::SidebarData {
            total: db::records::count(conn)?,
            favorites,
            trash,
            types,
            folders,
            tags,
        })
    })
}

// ---------------------------------------------------------------- reveal
//
// See the banner above `RevealedValue` in model/dto.rs. This is the only
// command in the application that returns a decrypted value.

#[tauri::command]
pub fn reveal_field(
    state: State<'_, AppState>,
    record_id: String,
    field: String,
) -> Result<RevealedValue> {
    let value = state.with_session(|session| {
        let bytes = session.open_secret(&record_id, &field)?;
        // The buffer wipes itself on drop; the String we build here is what
        // crosses the boundary, and the frontend is required to drop it when
        // the countdown ends.
        String::from_utf8(bytes.to_vec())
            .map_err(|_| AppError::invalid("That value is not text and cannot be displayed."))
    })?;

    tracing::info!(record = %record_id, field = %field, "secret revealed");

    Ok(RevealedValue {
        record_id,
        field,
        value,
        expires_in_ms: REVEAL_MS,
    })
}

/// Field kinds, for the custom-field editor.
#[tauri::command]
pub fn field_kinds() -> Vec<String> {
    [
        FieldKind::Text,
        FieldKind::Secret,
        FieldKind::Url,
        FieldKind::Multiline,
        FieldKind::Totp,
        FieldKind::Number,
        FieldKind::Date,
    ]
    .into_iter()
    .map(|k| k.as_str().to_string())
    .collect()
}

/// Used by the record form to create a record and populate it in one call.
#[tauri::command]
pub fn create_record_with_fields(
    state: State<'_, AppState>,
    record_type: String,
    title: String,
    folder: String,
    tags: Vec<String>,
    values: Vec<(String, String)>,
) -> Result<String> {
    let rt = parse_type(&record_type)?;
    if title.trim().is_empty() {
        return Err(AppError::invalid("A record needs a title."));
    }

    let id = state.with_session_mut(|session| {
        let id = session.create_record(rt, title.trim(), folder.trim(), &values)?;
        for tag in &tags {
            session.add_tag(&id, tag)?;
        }
        session.save()?;
        Ok(id)
    })?;

    state.rebuild_index();
    Ok(id)
}

/// Unused import guard: keeps `NewRecord` referenced so the type stays visible
/// to readers of this module as the shape `create_record` builds internally.
#[allow(dead_code)]
fn _new_record_shape(t: RecordType, title: &str) -> NewRecord {
    NewRecord::new(t, title)
}
