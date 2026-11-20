pub mod activity;
pub mod attachments;
pub mod fields;
pub mod records;
pub mod schema;
pub mod settings;
pub mod tags;

use std::time::Duration;

use rusqlite::backup::Backup;
use rusqlite::Connection;

use crate::error::Result;
use crate::vault::file::VaultPaths;

/// Open an in-memory database from a SQLite image, or create an empty one.
///
/// DECISION D-3: the vault database is never a live file on disk. It is a
/// byte image inside `vault.kr`, restored into an in-memory connection on
/// unlock and written back as a whole on save. That is what makes the atomic
/// write protocol meaningful - there is no journal, no WAL sidecar and no
/// half-flushed page cache to reconcile. It also matches Architecture 4.1's
/// "load the entire vault into memory on unlock".
///
/// The transfer uses SQLite's own online backup API through a short-lived
/// scratch file next to the vault, which is deleted immediately afterwards.
pub fn load_in_memory(paths: &VaultPaths, db_bytes: &[u8]) -> Result<Connection> {
    let mut mem = Connection::open_in_memory()?;
    configure(&mem)?;

    if db_bytes.is_empty() {
        schema::initialize(&mem)?;
        return Ok(mem);
    }

    let work = paths.work_db();
    std::fs::write(&work, db_bytes)?;
    let transfer = (|| -> Result<()> {
        let src = Connection::open(&work)?;
        let backup = Backup::new(&src, &mut mem)?;
        backup.run_to_completion(1024, Duration::from_millis(0), None)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&work);
    transfer?;

    schema::migrate(&mem)?;
    Ok(mem)
}

/// Serialize the in-memory database back to a SQLite image.
pub fn dump_image(paths: &VaultPaths, conn: &Connection) -> Result<Vec<u8>> {
    let work = paths.work_db();
    let _ = std::fs::remove_file(&work);

    let bytes = (|| -> Result<Vec<u8>> {
        let mut dst = Connection::open(&work)?;
        {
            let backup = Backup::new(conn, &mut dst)?;
            backup.run_to_completion(1024, Duration::from_millis(0), None)?;
        }
        drop(dst);
        Ok(std::fs::read(&work)?)
    })();

    let _ = std::fs::remove_file(&work);
    bytes
}

/// Remove a scratch file left behind by a crash.
pub fn purge_work_file(paths: &VaultPaths) {
    let _ = std::fs::remove_file(paths.work_db());
}

fn configure(conn: &Connection) -> Result<()> {
    // No `journal_mode = WAL` here: an in-memory database cannot use WAL,
    // and durability is provided by the atomic container write instead.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(())
}
