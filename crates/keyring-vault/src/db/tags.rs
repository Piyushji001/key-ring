use rusqlite::{params, Connection};

use crate::error::Result;

pub fn add(conn: &Connection, record_id: &str, tag: &str) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO tags (record_id, tag) VALUES (?1, ?2)",
        params![record_id, tag.trim().to_lowercase()],
    )?;
    Ok(())
}

pub fn remove(conn: &Connection, record_id: &str, tag: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM tags WHERE record_id = ?1 AND tag = ?2",
        params![record_id, tag.trim().to_lowercase()],
    )?;
    Ok(())
}

pub fn for_record(conn: &Connection, record_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT tag FROM tags WHERE record_id = ?1 ORDER BY tag")?;
    let rows = stmt.query_map(params![record_id], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Every tag with its live-record count, for the sidebar.
pub fn counts(conn: &Connection) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT t.tag, COUNT(*) FROM tags t
         JOIN records r ON r.id = t.record_id
         WHERE r.deleted_at IS NULL
         GROUP BY t.tag ORDER BY t.tag",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Distinct folder paths, for the sidebar tree.
pub fn folders(conn: &Connection) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT folder, COUNT(*) FROM records WHERE deleted_at IS NULL
         GROUP BY folder ORDER BY folder",
    )?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
