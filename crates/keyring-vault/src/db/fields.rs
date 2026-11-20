//! Field storage. THIS IS THE ENCRYPTION BOUNDARY.
//!
//! Plaintext exists above this module only inside `Zeroizing` buffers, and
//! it never travels further up than the caller that asked for it.
//!
//! Secret fields are sealed with the DEK using
//! `AAD = "keyring/field" | format_version | record_id | field_name`,
//! which binds every ciphertext to its exact location. An attacker who
//! swaps two blobs in the database gets an authentication failure, not the
//! other record's password.

use keyring_crypto::{DerivedKey, SealedBlob};
use rusqlite::{params, Connection, Row};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::model::{FieldKind, FieldRow};
use crate::util::time::now_unix;

/// Build the AAD for a field value. Length-prefixed so that
/// (record "ab", field "c") can never collide with (record "a", field "bc").
pub fn field_aad(record_id: &str, field_name: &str, format_version: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + record_id.len() + field_name.len());
    aad.extend_from_slice(b"keyring/field");
    aad.extend_from_slice(&format_version.to_le_bytes());
    aad.extend_from_slice(&(record_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(record_id.as_bytes());
    aad.extend_from_slice(&(field_name.len() as u32).to_le_bytes());
    aad.extend_from_slice(field_name.as_bytes());
    aad
}

fn row_to_field(row: &Row<'_>) -> rusqlite::Result<FieldRow> {
    let kind_str: String = row.get("kind")?;
    let nonce: Option<Vec<u8>> = row.get("nonce")?;
    let ciphertext: Option<Vec<u8>> = row.get("ciphertext")?;
    Ok(FieldRow {
        id: row.get("id")?,
        record_id: row.get("record_id")?,
        name: row.get("name")?,
        label: row.get("label")?,
        kind: FieldKind::parse(&kind_str).unwrap_or(FieldKind::Text),
        position: row.get("position")?,
        plain_value: row.get("plain_value")?,
        has_secret: nonce.is_some() && ciphertext.is_some(),
    })
}

const SELECT: &str = "SELECT id, record_id, name, label, kind, position, plain_value, \
                      nonce, ciphertext FROM fields";

pub fn list_for_record(conn: &Connection, record_id: &str) -> Result<Vec<FieldRow>> {
    let sql = format!("{SELECT} WHERE record_id = ?1 ORDER BY position ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![record_id], row_to_field)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn get(conn: &Connection, record_id: &str, name: &str) -> Result<Option<FieldRow>> {
    let sql = format!("{SELECT} WHERE record_id = ?1 AND name = ?2");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query_map(params![record_id, name], row_to_field)?;
    match rows.next() {
        Some(r) => Ok(Some(r?)),
        None => Ok(None),
    }
}

fn next_position(conn: &Connection, record_id: &str) -> Result<i64> {
    let max: Option<i64> = conn.query_row(
        "SELECT MAX(position) FROM fields WHERE record_id = ?1",
        params![record_id],
        |r| r.get(0),
    )?;
    Ok(max.map(|m| m + 1).unwrap_or(0))
}

/// Store a non-secret field value in `plain_value`. These are searchable.
pub fn set_plain(
    conn: &Connection,
    record_id: &str,
    name: &str,
    label: &str,
    kind: FieldKind,
    value: &str,
) -> Result<String> {
    if kind == FieldKind::Secret {
        return Err(VaultError::Invalid(
            "a secret-kind field cannot be stored as plaintext".into(),
        ));
    }
    match get(conn, record_id, name)? {
        Some(existing) => {
            conn.execute(
                "UPDATE fields SET label = ?2, kind = ?3, plain_value = ?4, \
                 nonce = NULL, ciphertext = NULL WHERE id = ?1",
                params![existing.id, label, kind.as_str(), value],
            )?;
            Ok(existing.id)
        }
        None => {
            let id = Uuid::new_v4().to_string();
            let position = next_position(conn, record_id)?;
            conn.execute(
                "INSERT INTO fields (id, record_id, name, label, kind, position, plain_value)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![id, record_id, name, label, kind.as_str(), position, value],
            )?;
            Ok(id)
        }
    }
}

/// Encrypt and store a secret field value.
///
/// The previous ciphertext, if any, is pushed onto `field_history` first, so
/// rotation never loses the old credential (UC-12).
pub fn set_secret(
    conn: &Connection,
    dek: &DerivedKey,
    format_version: u16,
    record_id: &str,
    name: &str,
    label: &str,
    kind: FieldKind,
    value: &[u8],
    history_limit: usize,
) -> Result<String> {
    let aad = field_aad(record_id, name, format_version);
    let sealed = keyring_crypto::seal(dek, value, &aad)?;

    match get(conn, record_id, name)? {
        Some(existing) => {
            if existing.has_secret {
                push_history(conn, &existing.id)?;
                trim_history(conn, &existing.id, history_limit)?;
            }
            conn.execute(
                "UPDATE fields SET label = ?2, kind = ?3, plain_value = NULL, \
                 nonce = ?4, ciphertext = ?5 WHERE id = ?1",
                params![
                    existing.id,
                    label,
                    kind.as_str(),
                    sealed.nonce.to_vec(),
                    sealed.ciphertext
                ],
            )?;
            Ok(existing.id)
        }
        None => {
            let id = Uuid::new_v4().to_string();
            let position = next_position(conn, record_id)?;
            conn.execute(
                "INSERT INTO fields (id, record_id, name, label, kind, position, nonce, ciphertext)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id,
                    record_id,
                    name,
                    label,
                    kind.as_str(),
                    position,
                    sealed.nonce.to_vec(),
                    sealed.ciphertext
                ],
            )?;
            Ok(id)
        }
    }
}

/// Decrypt a secret field into a buffer that wipes itself on drop.
///
/// Callers must not clone the contents into a `String` that outlives the
/// operation, and must never send it across an IPC boundary.
pub fn open_secret(
    conn: &Connection,
    dek: &DerivedKey,
    format_version: u16,
    record_id: &str,
    name: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let sql = format!("{SELECT} WHERE record_id = ?1 AND name = ?2");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params![record_id, name])?;
    let row = rows
        .next()?
        .ok_or_else(|| VaultError::NoSuchField(record_id.to_string(), name.to_string()))?;

    let nonce: Option<Vec<u8>> = row.get("nonce")?;
    let ciphertext: Option<Vec<u8>> = row.get("ciphertext")?;
    let (nonce, ciphertext) = match (nonce, ciphertext) {
        (Some(n), Some(c)) => (n, c),
        _ => return Err(VaultError::NotSecret),
    };

    let sealed = SealedBlob::from_parts(&nonce, &ciphertext)?;
    let aad = field_aad(record_id, name, format_version);
    Ok(keyring_crypto::open(dek, &sealed, &aad)?)
}

pub fn delete(conn: &Connection, record_id: &str, name: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM fields WHERE record_id = ?1 AND name = ?2",
        params![record_id, name],
    )?;
    Ok(())
}

// ---------------------------------------------------------------- history

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: String,
    pub replaced_at: i64,
}

/// Copy the current ciphertext into `field_history` before it is replaced.
///
/// Note that history entries keep the ORIGINAL AAD, which is derived from
/// the record id and field name - both unchanged by an edit - so old values
/// stay decryptable.
fn push_history(conn: &Connection, field_id: &str) -> Result<()> {
    let row: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT nonce, ciphertext FROM fields WHERE id = ?1",
            params![field_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();

    if let Some((Some(nonce), Some(ciphertext))) = row {
        conn.execute(
            "INSERT INTO field_history (id, field_id, nonce, ciphertext, replaced_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Uuid::new_v4().to_string(),
                field_id,
                nonce,
                ciphertext,
                now_unix()
            ],
        )?;
    }
    Ok(())
}

/// Keep only the most recent `limit` versions (FR-2.3 default: 10).
fn trim_history(conn: &Connection, field_id: &str, limit: usize) -> Result<()> {
    conn.execute(
        "DELETE FROM field_history WHERE field_id = ?1 AND id NOT IN (
             SELECT id FROM field_history WHERE field_id = ?1
             ORDER BY replaced_at DESC LIMIT ?2
         )",
        params![field_id, limit as i64],
    )?;
    Ok(())
}

pub fn list_history(conn: &Connection, field_id: &str) -> Result<Vec<HistoryEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, replaced_at FROM field_history WHERE field_id = ?1 ORDER BY replaced_at DESC",
    )?;
    let rows = stmt.query_map(params![field_id], |r| {
        Ok(HistoryEntry {
            id: r.get(0)?,
            replaced_at: r.get(1)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Decrypt one historical value.
pub fn open_history(
    conn: &Connection,
    dek: &DerivedKey,
    format_version: u16,
    history_id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let (record_id, name, nonce, ciphertext): (String, String, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT f.record_id, f.name, h.nonce, h.ciphertext
         FROM field_history h JOIN fields f ON f.id = h.field_id
         WHERE h.id = ?1",
        params![history_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;

    let sealed = SealedBlob::from_parts(&nonce, &ciphertext)?;
    let aad = field_aad(&record_id, &name, format_version);
    Ok(keyring_crypto::open(dek, &sealed, &aad)?)
}

pub fn delete_history_entry(conn: &Connection, history_id: &str) -> Result<()> {
    conn.execute("DELETE FROM field_history WHERE id = ?1", params![history_id])?;
    Ok(())
}
