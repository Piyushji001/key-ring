//! Retention (FR-8.2): keep the last N snapshots, delete the rest.
//!
//! The whole file is about one risk: a bug here deletes backups. So the rules
//! are deliberately blunt.
//!
//!   - `keep` is clamped to at least 1. A retention of zero would mean
//!     "back up, then immediately delete the backup", which is never what
//!     anyone meant.
//!   - Only folders that [`super::list_snapshots`] already accepted as
//!     snapshots are candidates. Anything else in the backup folder — the
//!     user's own files, another tool's output, a half-finished download — is
//!     invisible to this code and stays that way.
//!   - Deletion is newest-first ordered and takes from the tail, so an error
//!     partway through leaves the *newest* snapshots intact rather than a
//!     random subset.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::Result;

use super::{list_snapshots, Snapshot};

/// What a prune actually did. Returned rather than logged-and-forgotten so the
/// settings screen can show it and a test can assert on it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionOutcome {
    pub kept: usize,
    pub removed: Vec<PathBuf>,
    /// Snapshots that matched the retention rule but could not be deleted —
    /// almost always a sync client holding a file open. Reported, not retried:
    /// the next prune will pick them up.
    pub failed: Vec<PathBuf>,
    pub bytes_freed: u64,
}

/// Delete every snapshot beyond the newest `keep`.
pub fn prune(backup_dir: &Path, keep: usize) -> Result<RetentionOutcome> {
    let keep = keep.max(1);
    let snapshots = list_snapshots(backup_dir)?;

    let mut outcome = RetentionOutcome {
        kept: snapshots.len().min(keep),
        removed: Vec::new(),
        failed: Vec::new(),
        bytes_freed: 0,
    };

    if snapshots.len() <= keep {
        return Ok(outcome);
    }

    for snapshot in snapshots.into_iter().skip(keep) {
        let Snapshot {
            path, total_bytes, ..
        } = snapshot;
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {
                outcome.bytes_freed += total_bytes;
                tracing::info!(snapshot = %path.display(), "pruned old backup");
                outcome.removed.push(path);
            }
            Err(e) => {
                tracing::warn!(snapshot = %path.display(), error = %e, "could not prune backup");
                outcome.failed.push(path);
            }
        }
    }

    Ok(outcome)
}

/// Remove `.partial` folders left by an interrupted backup.
///
/// Called before taking a new snapshot. These are never restorable and their
/// presence in a sync folder is alarming for no reason.
pub fn clear_partials(backup_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(backup_dir) else {
        return 0;
    };
    let mut cleared = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_partial = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.starts_with("keyring-") && n.ends_with(".partial"))
            .unwrap_or(false);
        if is_partial && path.is_dir() && std::fs::remove_dir_all(&path).is_ok() {
            cleared += 1;
        }
    }
    cleared
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_snapshot(dir: &Path, stamp: &str) {
        let d = dir.join(format!("keyring-{stamp}"));
        std::fs::create_dir_all(d.join("blobs")).unwrap();
        std::fs::write(d.join("vault.kr"), b"not a real vault").unwrap();
    }

    #[test]
    fn keeps_exactly_n_and_removes_the_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        for stamp in [
            "20260101-000000",
            "20260102-000000",
            "20260103-000000",
            "20260104-000000",
            "20260105-000000",
        ] {
            fake_snapshot(tmp.path(), stamp);
        }

        let outcome = prune(tmp.path(), 3).unwrap();
        assert_eq!(outcome.kept, 3);
        assert_eq!(outcome.removed.len(), 2);

        let left = list_snapshots(tmp.path()).unwrap();
        assert_eq!(left.len(), 3);
        // The survivors are the three newest.
        assert_eq!(left[0].stamp, "20260105-000000");
        assert_eq!(left[2].stamp, "20260103-000000");
    }

    #[test]
    fn retention_of_zero_still_keeps_one() {
        let tmp = tempfile::tempdir().unwrap();
        fake_snapshot(tmp.path(), "20260101-000000");
        fake_snapshot(tmp.path(), "20260102-000000");

        let outcome = prune(tmp.path(), 0).unwrap();
        assert_eq!(outcome.kept, 1);
        assert_eq!(list_snapshots(tmp.path()).unwrap().len(), 1);
    }

    #[test]
    fn fewer_snapshots_than_retention_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        fake_snapshot(tmp.path(), "20260101-000000");
        let outcome = prune(tmp.path(), 10).unwrap();
        assert!(outcome.removed.is_empty());
        assert_eq!(outcome.kept, 1);
    }

    #[test]
    fn unrelated_folders_are_never_touched() {
        let tmp = tempfile::tempdir().unwrap();
        fake_snapshot(tmp.path(), "20260101-000000");
        fake_snapshot(tmp.path(), "20260102-000000");
        let precious = tmp.path().join("my-tax-returns");
        std::fs::create_dir_all(&precious).unwrap();
        std::fs::write(precious.join("2025.pdf"), b"x").unwrap();

        prune(tmp.path(), 1).unwrap();

        assert!(precious.join("2025.pdf").is_file());
    }

    #[test]
    fn partials_are_cleared_and_never_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join("keyring-20260101-000000.partial");
        std::fs::create_dir_all(&partial).unwrap();
        std::fs::write(partial.join("vault.kr"), b"half written").unwrap();

        assert_eq!(list_snapshots(tmp.path()).unwrap().len(), 0);
        assert_eq!(clear_partials(tmp.path()), 1);
        assert!(!partial.exists());
    }
}
