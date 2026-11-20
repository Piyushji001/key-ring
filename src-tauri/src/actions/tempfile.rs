//! Temp files for tools that need a path, and the registry that guarantees
//! they disappear.
//!
//! UC-07: `gcloud` wants a service-account JSON on disk, `ssh` wants a key
//! file. Both mean writing a decrypted secret to the filesystem, which is the
//! single most dangerous thing this application does.
//!
//! Three guarantees, in order of importance:
//!
//!   1. Deleted when the vault locks. Non-negotiable - a locked vault must not
//!      leave plaintext lying around.
//!   2. Deleted on exit, including the window being closed.
//!   3. Deleted at a deadline (default five minutes), whichever comes first.
//!
//! Files live under `%LOCALAPPDATA%\Keyring\extracted`, not the shared system
//! temp directory, because that folder is per-user and not world-readable.
//! Explicit ACL hardening - the `icacls`-equivalent that Windows OpenSSH
//! insists on for private keys - lands in Phase 6.
//!
//! Deletion overwrites the file with zeros before unlinking. On an SSD with
//! wear levelling that is not a guarantee, and this comment exists so nobody
//! later mistakes it for one. It removes the easy recovery, not the hard one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{AppError, Result};

#[derive(Debug)]
struct Extracted {
    deadline: Instant,
    size: u64,
}

#[derive(Debug, Default)]
pub struct TempRegistry {
    files: Mutex<HashMap<PathBuf, Extracted>>,
}

impl TempRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Directory for extractions. Created on demand, per user.
    pub fn dir() -> Result<PathBuf> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("Keyring").join("extracted");
        std::fs::create_dir_all(&dir)
            .map_err(|_| AppError::internal("could not create the extraction directory"))?;
        Ok(dir)
    }

    /// Write `data` to a file and register it for deletion.
    pub fn extract(&self, filename: &str, data: &[u8], ttl: Duration) -> Result<PathBuf> {
        let safe = sanitize(filename);
        let dir = Self::dir()?;
        // A short random-ish prefix avoids collisions when the same key is
        // extracted twice without the first having expired yet.
        let unique = format!("{}-{}", std::process::id(), now_millis());
        let path = dir.join(format!("{unique}-{safe}"));

        std::fs::write(&path, data)
            .map_err(|_| AppError::internal("could not write the extracted file"))?;

        if let Ok(mut files) = self.files.lock() {
            files.insert(
                path.clone(),
                Extracted {
                    deadline: Instant::now() + ttl,
                    size: data.len() as u64,
                },
            );
        }

        tracing::info!(file = %safe, ttl_secs = ttl.as_secs(), "extracted to temp file");
        Ok(path)
    }

    /// Register a file that already exists on disk.
    ///
    /// Used by the cloud shell path (Phase 7.5), where the provider's own
    /// tooling writes config into a scratch directory that Keyring created.
    /// Those files were not produced by `extract`, but they carry credential
    /// material and must be destroyed on exactly the same terms.
    pub fn adopt(&self, path: &Path, ttl: Duration) {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if let Ok(mut files) = self.files.lock() {
            files.insert(
                path.to_path_buf(),
                Extracted {
                    deadline: Instant::now() + ttl,
                    size,
                },
            );
        }
    }

    /// Delete anything past its deadline. Called by the sweeper thread.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let expired: Vec<(PathBuf, u64)> = match self.files.lock() {
            Ok(files) => files
                .iter()
                .filter(|(_, e)| e.deadline <= now)
                .map(|(p, e)| (p.clone(), e.size))
                .collect(),
            Err(_) => return 0,
        };

        for (path, size) in &expired {
            shred(path, *size);
        }
        if let Ok(mut files) = self.files.lock() {
            for (path, _) in &expired {
                files.remove(path);
            }
        }
        expired.len()
    }

    /// Delete everything, now. Called on lock and on exit.
    pub fn purge_all(&self) -> usize {
        let all: Vec<(PathBuf, u64)> = match self.files.lock() {
            Ok(files) => files.iter().map(|(p, e)| (p.clone(), e.size)).collect(),
            Err(_) => Vec::new(),
        };
        for (path, size) in &all {
            shred(path, *size);
        }
        if let Ok(mut files) = self.files.lock() {
            files.clear();
        }

        // Also sweep the directory itself, in case a previous run died before
        // it could clean up after itself.
        if let Ok(dir) = Self::dir() {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    if path.is_file() {
                        shred(&path, size);
                    }
                }
            }
        }

        if !all.is_empty() {
            tracing::info!(count = all.len(), "purged extracted files");
        }
        all.len()
    }

    pub fn active(&self) -> Vec<(String, u64)> {
        match self.files.lock() {
            Ok(files) => files
                .iter()
                .map(|(p, e)| {
                    let remaining = e.deadline.saturating_duration_since(Instant::now());
                    (p.to_string_lossy().into_owned(), remaining.as_secs())
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// Overwrite with zeros, then unlink. See the module comment for what this
/// does and does not promise.
fn shred(path: &Path, size: u64) {
    use std::io::Write;
    if size > 0 && size < 64 * 1024 * 1024 {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; size as usize];
            let _ = f.write_all(&zeros);
            let _ = f.flush();
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

/// Strip anything that could escape the extraction directory. An attachment
/// filename comes from the vault, but the vault contents came from somewhere.
fn sanitize(filename: &str) -> String {
    let cleaned: String = filename
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
            _ => '_',
        })
        .collect();
    let trimmed = cleaned.trim_matches('.').to_string();
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed.chars().take(64).collect()
    }
}

fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_traversal() {
        assert_eq!(sanitize("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(sanitize("id_ed25519"), "id_ed25519");
        assert_eq!(sanitize(""), "attachment");
        assert!(!sanitize("a/b\\c").contains('/'));
        assert!(!sanitize("a/b\\c").contains('\\'));
    }
}
