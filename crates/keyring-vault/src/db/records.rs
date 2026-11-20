//! Record CRUD. No encryption happens here - records carry only metadata.

use rusqlite::{params, Connection, Row};
use uuid::Uuid;

use crate::error::{Result, VaultError};
use crate::model::{NewRecord, RecordFilter, RecordRow, RecordType};
use crate::util::time::now_unix;

fn row_to_record(row: &Row<'_>) -> rusqlite::Result<RecordRow> {
    let type_str: String = row.get("type")?;
    Ok(RecordRow {
        id: row.get("id")?,
        record_type: RecordType::parse(&type_str).unwrap_or(RecordType::SecureNote),
        title: row.get("title")?,
        folder: row.get("folder")?,
        favorite: row.get::<_, i64>("favorite")? != 0,
        created_at: row.get("created_at")?,
        modified_at: row.get("modified_at")?,
        used_at: row.get("used_at")?,
        use_count: row.get("use_count")?,
        deleted_at: row.get("deleted_at")?,
    })
}

const SELECT: &str = "SELECT id, type, title, folder, favorite, created_at, modified_at, \
                      used_at, use_count, deleted_at FROM records";

pub fn insert(conn: &Connection, new: &NewRecord) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let now = now_unix();
    conn.execute(
        "INSERT INTO records (id, type, title, folder, favorite, created_at, modified_at, use_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 0)",
        params![
            id,
            new.record_type.as_str(),
            new.title,
            new.folder,
            new.favorite as i64,
            now
        ],
    )?;
    Ok(id)
}

pub fn get(conn: &Connection, id: &str) -> Result<Option<RecordRow>> {
    let sql = format!("{SELECT} WHERE id = ?1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query_map(params![id], row_to_record)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

pub fn require(conn: &Connection, id: &str) -> Result<RecordRow> {
    get(conn, id)?.ok_or_else(|| VaultError::NoSuchRecord(id.to_string()))
}

/// Case-insensitive exact title lookup, used by the CLI so you can say
/// `get "prod db"` instead of pasting a UUID.
pub fn find_by_title(conn: &Connection, title: &str) -> Result<Vec<RecordRow>> {
    let sql = format!("{SELECT} WHERE deleted_at IS NULL AND lower(title) = lower(?1)");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![title], row_to_record)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn list(conn: &Connection, filter: &RecordFilter) -> Result<Vec<RecordRow>> {
    let mut sql = String::from(SELECT);
    let mut clauses: Vec<String> = Vec::new();
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if filter.only_deleted {
        clauses.push("deleted_at IS NOT NULL".into());
    } else if !filter.include_deleted {
        clauses.push("deleted_at IS NULL".into());
    }
    if let Some(t) = filter.record_type {
        clauses.push(format!("type = ?{}", args.len() + 1));
        args.push(Box::new(t.as_str().to_string()));
    }
    if let Some(f) = &filter.folder {
        clauses.push(format!("folder = ?{}", args.len() + 1));
        args.push(Box::new(f.clone()));
    }
    if let Some(tag) = &filter.tag {
        clauses.push(format!(
            "id IN (SELECT record_id FROM tags WHERE tag = ?{})",
            args.len() + 1
        ));
        args.push(Box::new(tag.clone()));
    }
    if filter.favorites_only {
        clauses.push("favorite = 1".into());
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY used_at DESC NULLS LAST, modified_at DESC");
    if let Some(limit) = filter.limit {
        sql.push_str(&format!(" LIMIT {limit}"));
    }

    let mut stmt = conn.prepare(&sql)?;
    let arg_refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(arg_refs.as_slice(), row_to_record)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn rename(conn: &Connection, id: &str, title: &str) -> Result<()> {
    conn.execute(
        "UPDATE records SET title = ?2, modified_at = ?3 WHERE id = ?1",
        params![id, title, now_unix()],
    )?;
    Ok(())
}

pub fn set_folder(conn: &Connection, id: &str, folder: &str) -> Result<()> {
    conn.execute(
        "UPDATE records SET folder = ?2, modified_at = ?3 WHERE id = ?1",
        params![id, folder, now_unix()],
    )?;
    Ok(())
}

pub fn set_favorite(conn: &Connection, id: &str, favorite: bool) -> Result<()> {
    conn.execute(
        "UPDATE records SET favorite = ?2, modified_at = ?3 WHERE id = ?1",
        params![id, favorite as i64, now_unix()],
    )?;
    Ok(())
}

pub fn touch_modified(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE records SET modified_at = ?2 WHERE id = ?1",
        params![id, now_unix()],
    )?;
    Ok(())
}

/// Record a use. Drives search ranking.
pub fn touch_used(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE records SET used_at = ?2, use_count = use_count + 1 WHERE id = ?1",
        params![id, now_unix()],
    )?;
    Ok(())
}

/// Move to trash. Retention is enforced by `purge_expired`.
pub fn soft_delete(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE records SET deleted_at = ?2 WHERE id = ?1",
        params![id, now_unix()],
    )?;
    Ok(())
}

pub fn restore(conn: &Connection, id: &str) -> Result<()> {
    conn.execute(
        "UPDATE records SET deleted_at = NULL, modified_at = ?2 WHERE id = ?1",
        params![id, now_unix()],
    )?;
    Ok(())
}

/// Permanent deletion. Cascades to fields, history, tags and attachment rows.
/// Blob files on disk are removed by the caller, which knows the paths.
pub fn purge(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM records WHERE id = ?1", params![id])?;
    Ok(())
}

/// Empty trash items older than `retention_days` (FR-2.4: 30 days).
pub fn purge_expired(conn: &Connection, retention_days: i64) -> Result<Vec<String>> {
    let cutoff = now_unix() - retention_days * 86_400;
    let mut stmt =
        conn.prepare("SELECT id FROM records WHERE deleted_at IS NOT NULL AND deleted_at < ?1")?;
    let ids: Vec<String> = stmt
        .query_map(params![cutoff], |r| r.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for id in &ids {
        purge(conn, id)?;
    }
    Ok(ids)
}

pub fn count(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM records WHERE deleted_at IS NULL",
        [],
        |r| r.get(0),
    )?)
}
