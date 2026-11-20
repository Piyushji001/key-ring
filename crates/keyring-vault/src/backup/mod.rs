//! Backup (FR-8): copy the vault somewhere the user's own sync client watches.
//!
//! ## What a backup is
//!
//! A timestamped folder containing a complete, self-contained vault:
//!
//! ```text
//! <backup_dir>/
//!   keyring-20260804-171003/
//!     vault.kr
//!     blobs/
//!       <uuid>.blob
//!       ...
//!     MANIFEST.json
//! ```
//!
//! **The blobs are not optional.** A `vault.kr` without its `blobs/` directory
//! is a vault whose attachments are all missing, and that is the kind of
//! failure you only discover on the day you need it. Every snapshot copies
//! them, which costs disk (ten retained snapshots of a vault with a 40 MB PEM
//! bundle is 400 MB) and buys the only property that matters: **restore is a
//! folder copy.** No merge step, no partial state, nothing to get wrong at
//! 3 a.m. See D-34.
//!
//! ## What a backup is not
//!
//! It is not an export. The container is still encrypted with the same master
//! password; a snapshot in a Dropbox folder is exactly as safe as the original,
//! which is the whole reason this design is acceptable at all. Nothing here
//! ever decrypts anything — `create_snapshot` does not need a key and does not
//! take one.

pub mod rotate;
pub mod scheduler;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::vault::file::VaultPaths;

pub use rotate::{prune, RetentionOutcome};
pub use scheduler::{BackupScheduler, SchedulerConfig};

/// Written alongside every snapshot. Purely informational — restore works by
/// copying the folder, and never reads this. It exists so that a user staring
/// at nine identically-named folders can tell which one they want.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Seconds since the Unix epoch.
    pub created_at: i64,
    /// Human-sortable stamp, matching the folder name.
    pub stamp: String,
    /// Vault format version, so a future Keyring can refuse politely.
    pub format_version: u16,
    /// Vault id from the header. Distinguishes snapshots of *different* vaults
    /// that happen to share a backup folder.
    pub vault_id: String,
    /// Records not in the trash, at the moment of the snapshot.
    pub record_count: i64,
    /// Number of `.blob` files copied.
    pub attachment_count: usize,
    /// Total bytes written.
    pub total_bytes: u64,
    /// What triggered it.
    pub trigger: Trigger,
    /// The version of Keyring that wrote it.
    pub app_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// The debounced automatic backup after a change (FR-8.1).
    Automatic,
    /// The user pressed "Back up now" (FR-8.3).
    Manual,
    /// Taken automatically before a risky operation — an import, a master
    /// password change, a format migration. Cheap insurance.
    Safety,
}

impl Trigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            Trigger::Automatic => "automatic",
            Trigger::Manual => "manual",
            Trigger::Safety => "safety",
        }
    }
}

/// A snapshot on disk, as discovered by [`list_snapshots`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub path: PathBuf,
    pub stamp: String,
    pub created_at: i64,
    pub total_bytes: u64,
    /// `None` when the manifest is missing or unreadable. The snapshot is
    /// still listed: a folder that looks like a backup and contains a
    /// `vault.kr` probably *is* one, and hiding it would be worse than
    /// showing it with blanks.
    pub manifest: Option<Manifest>,
}

const PREFIX: &str = "keyring-";

/// Format a Unix timestamp as `YYYYMMDD-HHMMSS` in UTC.
///
/// UTC rather than local time, deliberately: snapshot folders sort
/// lexicographically in a file browser, and local time stops sorting correctly
/// twice a year.
pub fn stamp_for(unix_secs: i64) -> String {
    match chrono::DateTime::from_timestamp(unix_secs, 0) {
        Some(dt) => dt.format("%Y%m%d-%H%M%S").to_string(),
        // Only reachable for a timestamp outside chrono's range, which means
        // the system clock is broken. A snapshot still has to land somewhere.
        None => format!("invalid-{unix_secs}"),
    }
}

/// Create one snapshot of `paths` inside `backup_dir`.
///
/// Writes into a `.partial` folder and renames it at the end, so an
/// interrupted backup can never be mistaken for a complete one — the same
/// reasoning as the atomic container write, applied one level up.
pub fn create_snapshot(
    paths: &VaultPaths,
    backup_dir: &Path,
    record_count: i64,
    format_version: u16,
    vault_id: &str,
    trigger: Trigger,
) -> Result<Snapshot> {
    if !paths.container().is_file() {
        return Err(VaultError::NoVaultHere);
    }

    std::fs::create_dir_all(backup_dir)?;

    let created_at = crate::util::time::now_unix();
    let stamp = stamp_for(created_at);

    // A second snapshot within the same second (a manual click landing on top
    // of a debounced automatic one) must not collide.
    let mut final_dir = backup_dir.join(format!("{PREFIX}{stamp}"));
    let mut suffix = 1;
    while final_dir.exists() {
        final_dir = backup_dir.join(format!("{PREFIX}{stamp}-{suffix}"));
        suffix += 1;
        if suffix > 50 {
            return Err(VaultError::Invalid(
                "too many backups with the same timestamp".into(),
            ));
        }
    }

    let partial = final_dir.with_extension("partial");
    if partial.exists() {
        // Left by a previous interrupted run. It is by definition incomplete.
        let _ = std::fs::remove_dir_all(&partial);
    }
    std::fs::create_dir_all(&partial)?;

    // Copy the container first. If this fails there is no point continuing.
    let container_bytes = std::fs::copy(paths.container(), partial.join("vault.kr"))?;

    let blob_dest = partial.join("blobs");
    let attachment_count = if paths.blobs_dir().is_dir() {
        crate::db::attachments::copy_blobs_to(paths, &blob_dest)?
    } else {
        std::fs::create_dir_all(&blob_dest)?;
        0
    };

    let total_bytes = container_bytes + dir_size(&blob_dest);

    let manifest = Manifest {
        created_at,
        stamp: stamp.clone(),
        format_version,
        vault_id: vault_id.to_string(),
        record_count,
        attachment_count,
        total_bytes,
        trigger,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| VaultError::Invalid("could not serialize the backup manifest".into()))?;
    std::fs::write(partial.join("MANIFEST.json"), &manifest_json)?;

    // Only now does it become a backup.
    std::fs::rename(&partial, &final_dir)?;

    tracing::info!(
        snapshot = %final_dir.display(),
        attachments = attachment_count,
        bytes = total_bytes,
        trigger = trigger.as_str(),
        "backup snapshot written"
    );

    Ok(Snapshot {
        path: final_dir,
        stamp,
        created_at,
        total_bytes,
        manifest: Some(manifest),
    })
}

/// Every snapshot in `backup_dir`, newest first.
pub fn list_snapshots(backup_dir: &Path) -> Result<Vec<Snapshot>> {
    if !backup_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in std::fs::read_dir(backup_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with(PREFIX) || name.ends_with(".partial") {
            continue;
        }
        // A folder without a container is not a restorable backup, whatever
        // it is named.
        if !path.join("vault.kr").is_file() {
            continue;
        }

        let manifest = std::fs::read(path.join("MANIFEST.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Manifest>(&b).ok());

        let stamp = name.trim_start_matches(PREFIX).to_string();
        let created_at = manifest
            .as_ref()
            .map(|m| m.created_at)
            .unwrap_or_else(|| modified_unix(&path));
        let total_bytes = manifest
            .as_ref()
            .map(|m| m.total_bytes)
            .unwrap_or_else(|| dir_size(&path));

        out.push(Snapshot {
            path,
            stamp,
            created_at,
            total_bytes,
            manifest,
        });
    }

    out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.stamp.cmp(&a.stamp)));
    Ok(out)
}

/// The most recent snapshot's timestamp, for FR-8.5.
pub fn last_backup_at(backup_dir: &Path) -> Option<i64> {
    list_snapshots(backup_dir).ok()?.first().map(|s| s.created_at)
}

/// Restore a snapshot into `dest`.
///
/// Refuses to write into a folder that already holds a vault. Restoring on top
/// of a live vault is how people lose the good copy while trying to recover the
/// bad one; the caller must move the existing one aside deliberately.
pub fn restore_snapshot(snapshot_dir: &Path, dest: &Path) -> Result<()> {
    let source_container = snapshot_dir.join("vault.kr");
    if !source_container.is_file() {
        return Err(VaultError::NoVaultHere);
    }

    let dest_paths = VaultPaths::new(dest.to_path_buf());
    if dest_paths.container().exists() {
        return Err(VaultError::AlreadyExists);
    }

    std::fs::create_dir_all(dest)?;
    std::fs::copy(&source_container, dest_paths.container())?;

    let source_blobs = snapshot_dir.join("blobs");
    let dest_blobs = dest_paths.blobs_dir();
    std::fs::create_dir_all(&dest_blobs)?;
    if source_blobs.is_dir() {
        for entry in std::fs::read_dir(&source_blobs)? {
            let entry = entry?;
            if entry.path().is_file() {
                std::fs::copy(entry.path(), dest_blobs.join(entry.file_name()))?;
            }
        }
    }

    Ok(())
}

/// Sum of file sizes directly beneath `dir`, recursing one level.
///
/// One level is enough: a snapshot is `vault.kr`, `MANIFEST.json` and `blobs/`.
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        match entry.metadata() {
            Ok(meta) if meta.is_file() => total += meta.len(),
            Ok(meta) if meta.is_dir() => {
                if let Ok(inner) = std::fs::read_dir(entry.path()) {
                    for f in inner.flatten() {
                        if let Ok(m) = f.metadata() {
                            if m.is_file() {
                                total += m.len();
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    total
}

fn modified_unix(path: &Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_is_sortable_and_correct() {
        // 2026-08-04T17:10:03Z
        assert_eq!(stamp_for(1_785_863_403), "20260804-171003");
        // Lexicographic order must match chronological order.
        assert!(stamp_for(1_000_000) < stamp_for(2_000_000));
    }

    #[test]
    fn listing_an_absent_directory_is_empty_not_an_error() {
        let missing = std::path::Path::new("./definitely-not-here-9f3a");
        assert!(list_snapshots(missing).map(|v| v.len()).unwrap_or(99) == 0);
    }
}
