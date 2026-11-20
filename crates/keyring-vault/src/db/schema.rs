//! Table definitions (Architecture 5) and version management.

use rusqlite::Connection;

use crate::error::{Result, VaultError};

/// Bump this whenever the schema changes, and add a migration below.
pub const SCHEMA_VERSION: i64 = 1;

pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    title       TEXT NOT NULL,
    folder      TEXT NOT NULL DEFAULT '',
    favorite    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    modified_at INTEGER NOT NULL,
    used_at     INTEGER,
    use_count   INTEGER NOT NULL DEFAULT 0,
    deleted_at  INTEGER
);

CREATE TABLE IF NOT EXISTS fields (
    id          TEXT PRIMARY KEY,
    record_id   TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    label       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    position    INTEGER NOT NULL,
    plain_value TEXT,
    nonce       BLOB,
    ciphertext  BLOB,
    UNIQUE(record_id, name)
);

CREATE TABLE IF NOT EXISTS field_history (
    id          TEXT PRIMARY KEY,
    field_id    TEXT NOT NULL REFERENCES fields(id) ON DELETE CASCADE,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    replaced_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id          TEXT PRIMARY KEY,
    record_id   TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,
    mime_type   TEXT,
    size_bytes  INTEGER NOT NULL,
    blob_path   TEXT NOT NULL,
    nonce       BLOB NOT NULL,
    sha256      BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
    record_id   TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    tag         TEXT NOT NULL,
    PRIMARY KEY (record_id, tag)
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    action      TEXT NOT NULL,
    record_id   TEXT,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_records_type   ON records(type)   WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_records_folder ON records(folder) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_records_used   ON records(used_at DESC);
CREATE INDEX IF NOT EXISTS idx_fields_record  ON fields(record_id);
CREATE INDEX IF NOT EXISTS idx_tags_tag       ON tags(tag);
"#;

/// Create every table in a fresh database and stamp the schema version.
pub fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_SQL)?;
    conn.execute("DELETE FROM schema_version", [])?;
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        [SCHEMA_VERSION],
    )?;
    Ok(())
}

pub fn current_version(conn: &Connection) -> Result<i64> {
    let v: Option<i64> = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
            r.get(0)
        })
        .ok();
    Ok(v.unwrap_or(0))
}

/// Apply migrations in order. Every future schema change gets a step here.
pub fn migrate(conn: &Connection) -> Result<()> {
    let from = current_version(conn)?;

    if from == 0 {
        initialize(conn)?;
        return Ok(());
    }
    if from == SCHEMA_VERSION {
        // Still run the CREATE IF NOT EXISTS batch: cheap, and it repairs a
        // database that lost an index.
        conn.execute_batch(SCHEMA_SQL)?;
        return Ok(());
    }
    if from > SCHEMA_VERSION {
        return Err(VaultError::UnsupportedFormat(from as u16));
    }

    // Future migrations:
    //   if from < 2 { conn.execute_batch("ALTER TABLE ...")?; }
    //   stamp(conn, 2)?;

    Err(VaultError::Invalid(format!(
        "no migration path from schema version {from} to {SCHEMA_VERSION}"
    )))
}

#[allow(dead_code)]
fn stamp(conn: &Connection, version: i64) -> Result<()> {
    conn.execute("DELETE FROM schema_version", [])?;
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        [version],
    )?;
    Ok(())
}
