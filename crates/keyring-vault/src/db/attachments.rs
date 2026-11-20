//! Attachment metadata plus encrypted blob files.
//!
//! Blobs live outside the database (Architecture 4.1) so the container stays
//! small and fast to load. Each blob is sealed independently with
//! `AAD = "keyring/attachment" | format_version | attachment_id`.
//!
//! The SHA-256 of the *plaintext* is stored so extraction can be verified.

use std::path::Path;

use keyring_crypto::{DerivedKey, SealedBlob};
use rusqlite::{params, Connection};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::util::atomic_write::atomic_write;
use crate::util::time::now_unix;
use crate::vault::file::VaultPaths;

/// FR-3.1: 50 MB per file.
pub const MAX_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AttachmentRow {
    pub id: String,
    pub record_id: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub blob_path: String,
    pub sha256: Vec<u8>,
    pub created_at: i64,
}

pub fn attachment_aad(attachment_id: &str, format_version: u16) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + attachment_id.len());
    aad.extend_from_slice(b"keyring/attachment");
    aad.extend_from_slice(&format_version.to_le_bytes());
    aad.extend_from_slice(&(attachment_id.len() as u32).to_le_bytes());
    aad.extend_from_slice(attachment_id.as_bytes());
    aad
}

/// SHA-256 of attachment plaintext, used only as an integrity check on
/// extraction. Uses the `sha2` crate: no hash is hand-rolled in this
/// codebase, per the project rules.
pub mod sha256 {
    use sha2::{Digest, Sha256};

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[cfg(test)]
    mod tests {
        use super::digest;

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        #[test]
        fn matches_the_standard_vectors() {
            assert_eq!(
                hex(&digest(b"")),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            assert_eq!(
                hex(&digest(b"abc")),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            assert_eq!(
                hex(&digest(
                    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
                )),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            );
        }
    }
}

/// Encrypt `data` and write it as a blob, recording the metadata row.
pub fn add(
    conn: &Connection,
    paths: &VaultPaths,
    dek: &DerivedKey,
    format_version: u16,
    record_id: &str,
    filename: &str,
    mime_type: Option<&str>,
    data: &[u8],
) -> Result<String> {
    if data.len() as u64 > MAX_ATTACHMENT_BYTES {
        return Err(VaultError::Invalid(format!(
            "attachment exceeds the {} MB limit",
            MAX_ATTACHMENT_BYTES / 1024 / 1024
        )));
    }

    let id = Uuid::new_v4().to_string();
    let aad = attachment_aad(&id, format_version);
    let sealed = keyring_crypto::seal(dek, data, &aad)?;
    let digest = sha256::digest(data);

    let mut blob = Vec::with_capacity(sealed.nonce.len() + sealed.ciphertext.len());
    blob.extend_from_slice(&sealed.nonce);
    blob.extend_from_slice(&sealed.ciphertext);

    std::fs::create_dir_all(paths.blobs_dir())?;
    atomic_write(&paths.blob_path(&id), &blob)?;

    conn.execute(
        "INSERT INTO attachments
           (id, record_id, filename, mime_type, size_bytes, blob_path, nonce, sha256, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            record_id,
            filename,
            mime_type,
            data.len() as i64,
            format!("blobs/{id}.blob"),
            sealed.nonce.to_vec(),
            digest.to_vec(),
            now_unix()
        ],
    )?;

    Ok(id)
}

pub fn list_for_record(conn: &Connection, record_id: &str) -> Result<Vec<AttachmentRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, record_id, filename, mime_type, size_bytes, blob_path, sha256, created_at
         FROM attachments WHERE record_id = ?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map(params![record_id], |r| {
        Ok(AttachmentRow {
            id: r.get(0)?,
            record_id: r.get(1)?,
            filename: r.get(2)?,
            mime_type: r.get(3)?,
            size_bytes: r.get(4)?,
            blob_path: r.get(5)?,
            sha256: r.get(6)?,
            created_at: r.get(7)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Decrypt a blob into a self-wiping buffer and verify its SHA-256.
///
/// A missing blob file is an error, but callers are expected to keep going
/// (Architecture 11: the record still opens, the attachment shows as
/// unavailable).
pub fn open_blob(
    conn: &Connection,
    paths: &VaultPaths,
    dek: &DerivedKey,
    format_version: u16,
    attachment_id: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let expected: Vec<u8> = conn.query_row(
        "SELECT sha256 FROM attachments WHERE id = ?1",
        params![attachment_id],
        |r| r.get(0),
    )?;

    let path = paths.blob_path(attachment_id);
    let blob = std::fs::read(&path)?;
    if blob.len() < keyring_crypto::NONCE_LEN {
        return Err(VaultError::Corrupt("blob"));
    }
    let (nonce, ciphertext) = blob.split_at(keyring_crypto::NONCE_LEN);
    let sealed = SealedBlob::from_parts(nonce, ciphertext)?;
    let aad = attachment_aad(attachment_id, format_version);
    let plaintext = keyring_crypto::open(dek, &sealed, &aad)?;

    if sha256::digest(&plaintext).as_slice() != expected.as_slice() {
        return Err(VaultError::Corrupt("attachment digest"));
    }
    Ok(plaintext)
}

pub fn remove(conn: &Connection, paths: &VaultPaths, attachment_id: &str) -> Result<()> {
    conn.execute("DELETE FROM attachments WHERE id = ?1", params![attachment_id])?;
    let _ = std::fs::remove_file(paths.blob_path(attachment_id));
    Ok(())
}

/// Blob files with no metadata row, left by an interrupted delete.
pub fn orphan_blobs(conn: &Connection, paths: &VaultPaths) -> Result<Vec<std::path::PathBuf>> {
    let dir = paths.blobs_dir();
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut known = std::collections::HashSet::new();
    let mut stmt = conn.prepare("SELECT id FROM attachments")?;
    for id in stmt.query_map([], |r| r.get::<_, String>(0))? {
        known.insert(id?);
    }

    let mut orphans = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path: std::path::PathBuf = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("blob") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        if !known.contains(&stem) {
            orphans.push(path);
        }
    }
    Ok(orphans)
}

/// Copy every blob into a destination directory. Used by backup.
pub fn copy_blobs_to(paths: &VaultPaths, dest_dir: &Path) -> Result<usize> {
    let src = paths.blobs_dir();
    if !src.is_dir() {
        return Ok(0);
    }
    std::fs::create_dir_all(dest_dir)?;
    let mut n = 0;
    for entry in std::fs::read_dir(&src)? {
        let path = entry?.path();
        if path.is_file() {
            if let Some(name) = path.file_name() {
                std::fs::copy(&path, dest_dir.join(name))?;
                n += 1;
            }
        }
    }
    Ok(n)
}
