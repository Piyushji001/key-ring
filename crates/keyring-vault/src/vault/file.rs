//! The `vault.kr` container: header followed by a SQLite database image.
//!
//! ```text
//! offset  size  field
//! 0       8     magic "KEYRING\0"
//! 8       2     format version, u16 LE
//! 10      2     header length, u16 LE
//! 12      N     header, CBOR, plaintext but authenticated
//! 12+N    ..    SQLite database image
//! ```

use std::path::{Path, PathBuf};

use crate::error::{Result, VaultError};
use crate::util::atomic_write::atomic_write;

use super::header::{VaultHeader, FORMAT_VERSION, HEADER_OFFSET, MAGIC};

/// Every path that belongs to one vault.
#[derive(Debug, Clone)]
pub struct VaultPaths {
    pub root: PathBuf,
}

impl VaultPaths {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        VaultPaths { root: root.into() }
    }

    pub fn container(&self) -> PathBuf {
        self.root.join("vault.kr")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.root.join("vault.lock")
    }

    /// Scratch file used to move the SQLite image between disk and the
    /// in-memory connection. Never left behind; purged on open.
    pub fn work_db(&self) -> PathBuf {
        self.root.join("vault.kr.work")
    }

    pub fn blob_path(&self, attachment_id: &str) -> PathBuf {
        self.blobs_dir().join(format!("{attachment_id}.blob"))
    }

    pub fn exists(&self) -> bool {
        self.container().is_file()
    }
}

/// Read and validate the container. Returns the header and the raw SQLite
/// image. Does no cryptography: the caller still has to unwrap the DEK.
pub fn read_container(path: &Path) -> Result<(VaultHeader, Vec<u8>)> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < HEADER_OFFSET {
        return Err(VaultError::Corrupt("truncated"));
    }
    if &bytes[0..8] != MAGIC {
        return Err(VaultError::Corrupt("magic"));
    }

    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version > FORMAT_VERSION {
        return Err(VaultError::UnsupportedFormat(version));
    }

    let header_len = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
    let header_end = HEADER_OFFSET
        .checked_add(header_len)
        .ok_or(VaultError::Corrupt("header length"))?;
    if header_end > bytes.len() {
        return Err(VaultError::Corrupt("header length"));
    }

    let header = VaultHeader::from_cbor(&bytes[HEADER_OFFSET..header_end])?;
    if header.format_version != version {
        return Err(VaultError::Corrupt("version mismatch"));
    }

    let db_bytes = bytes[header_end..].to_vec();
    Ok((header, db_bytes))
}

/// Serialize header + database image and replace the container atomically.
pub fn write_container(path: &Path, header: &VaultHeader, db_bytes: &[u8]) -> Result<()> {
    let header_cbor = header.to_cbor()?;
    let header_len: u16 = header_cbor
        .len()
        .try_into()
        .map_err(|_| VaultError::Invalid("vault header exceeds 65535 bytes".into()))?;

    let mut buf = Vec::with_capacity(HEADER_OFFSET + header_cbor.len() + db_bytes.len());
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&header.format_version.to_le_bytes());
    buf.extend_from_slice(&header_len.to_le_bytes());
    buf.extend_from_slice(&header_cbor);
    buf.extend_from_slice(db_bytes);

    atomic_write(path, &buf)?;
    Ok(())
}
