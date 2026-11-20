//! The debounce (FR-8.1): back up 60 seconds after the last change, not
//! 60 seconds after the first.
//!
//! ## Why a debounce rather than a timer
//!
//! Editing a record touches the vault several times in a row — set a field,
//! set another, add a tag. Each one is a full container rewrite. Backing up
//! after every write would copy the whole vault (plus every blob) five times
//! in ten seconds, and on a folder that OneDrive is watching that turns into a
//! sync storm.
//!
//! So: every write calls [`BackupScheduler::mark_dirty`], which pushes the due
//! time out to `now + debounce`. The vault is only copied once the user has
//! stopped touching it. A burst of fifty edits produces one backup.
//!
//! ## Why this holds no session
//!
//! The scheduler decides *when*, never *what*. It owns a clock and a flag.
//! The caller — `src-tauri`, which has the `AppState` mutex — decides whether
//! the vault is still unlocked and does the copying. That split is why this
//! file has no lock ordering to get wrong: taking a backup must never be able
//! to deadlock against a save.
//!
//! ## The guarantee it does not make
//!
//! If the process dies during the debounce window, that change is not backed
//! up. It is still *saved* — the atomic container write already happened —
//! so nothing is lost, but the newest snapshot is up to a minute stale. That
//! is the deliberate trade for not thrashing the disk, and it is why locking
//! and exiting both force a flush.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

/// Default from FR-8.1.
pub const DEFAULT_DEBOUNCE_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Where snapshots go. `None` means backups are not configured, which is
    /// the state FR-8.4 wants shouted about in the UI.
    pub backup_dir: Option<std::path::PathBuf>,
    pub retention: usize,
    pub debounce: Duration,
    /// Automatic backups can be switched off without clearing the folder, so
    /// that turning them back on does not mean finding the path again.
    pub automatic: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            backup_dir: None,
            retention: 10,
            debounce: Duration::from_secs(DEFAULT_DEBOUNCE_SECS),
            automatic: true,
        }
    }
}

/// Tracks whether a backup is owed and when it comes due.
///
/// Deliberately lock-free: `mark_dirty` is called from inside the save path,
/// which already holds the session mutex, and adding a second lock there is
/// how deadlocks get written.
#[derive(Debug)]
pub struct BackupScheduler {
    dirty: AtomicBool,
    /// Monotonic milliseconds since the scheduler was created. Monotonic
    /// rather than wall-clock so that an NTP correction or a daylight-saving
    /// jump cannot make a backup either overdue by an hour or never due.
    due_at_ms: AtomicI64,
    started: std::time::Instant,
    debounce_ms: AtomicI64,
    enabled: AtomicBool,
}

impl BackupScheduler {
    pub fn new(debounce: Duration) -> Self {
        BackupScheduler {
            dirty: AtomicBool::new(false),
            due_at_ms: AtomicI64::new(0),
            started: std::time::Instant::now(),
            debounce_ms: AtomicI64::new(debounce.as_millis() as i64),
            enabled: AtomicBool::new(true),
        }
    }

    fn now_ms(&self) -> i64 {
        self.started.elapsed().as_millis() as i64
    }

    pub fn set_debounce(&self, debounce: Duration) {
        self.debounce_ms
            .store(debounce.as_millis() as i64, Ordering::SeqCst);
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
        if !enabled {
            self.dirty.store(false, Ordering::SeqCst);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// The vault changed. Push the due time out.
    pub fn mark_dirty(&self) {
        if !self.is_enabled() {
            return;
        }
        let due = self.now_ms() + self.debounce_ms.load(Ordering::SeqCst);
        self.due_at_ms.store(due, Ordering::SeqCst);
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// Is a backup owed *and* has the quiet period elapsed?
    pub fn is_due(&self) -> bool {
        self.is_enabled()
            && self.dirty.load(Ordering::SeqCst)
            && self.now_ms() >= self.due_at_ms.load(Ordering::SeqCst)
    }

    /// Is a backup owed, regardless of the debounce?
    ///
    /// Used on lock and on exit: the user is walking away, so the reason for
    /// waiting has gone.
    pub fn is_pending(&self) -> bool {
        self.dirty.load(Ordering::SeqCst)
    }

    /// Seconds until the backup comes due, for the settings screen. `None`
    /// when nothing is owed.
    pub fn seconds_until_due(&self) -> Option<u64> {
        if !self.is_pending() {
            return None;
        }
        let remaining = self.due_at_ms.load(Ordering::SeqCst) - self.now_ms();
        Some(remaining.max(0) as u64 / 1000)
    }

    /// Claim the pending backup.
    ///
    /// Returns `true` exactly once per dirty period, so two sweeper ticks
    /// racing each other cannot both take a snapshot. The caller that gets
    /// `true` owns the job; if it fails it should call [`Self::mark_dirty`]
    /// again rather than leaving the change unbacked.
    pub fn claim(&self) -> bool {
        self.dirty
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Give the job back after a failure.
    pub fn requeue(&self) {
        self.mark_dirty();
    }
}

impl Default for BackupScheduler {
    fn default() -> Self {
        Self::new(Duration::from_secs(DEFAULT_DEBOUNCE_SECS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_due_before_a_change() {
        let s = BackupScheduler::new(Duration::from_millis(0));
        assert!(!s.is_due());
        assert!(!s.is_pending());
    }

    #[test]
    fn a_change_becomes_due_after_the_debounce() {
        let s = BackupScheduler::new(Duration::from_millis(40));
        s.mark_dirty();
        assert!(s.is_pending());
        assert!(!s.is_due(), "should still be inside the quiet period");
        std::thread::sleep(Duration::from_millis(60));
        assert!(s.is_due());
    }

    #[test]
    fn a_burst_of_changes_produces_one_backup() {
        let s = BackupScheduler::new(Duration::from_millis(50));
        for _ in 0..20 {
            s.mark_dirty();
            std::thread::sleep(Duration::from_millis(5));
        }
        // 100 ms of edits, but the last one reset the clock, so nothing is due.
        assert!(!s.is_due());
        std::thread::sleep(Duration::from_millis(70));
        assert!(s.is_due());

        assert!(s.claim());
        // The second claimant gets nothing: one backup, not two.
        assert!(!s.claim());
        assert!(!s.is_due());
    }

    #[test]
    fn requeue_after_a_failure_keeps_the_change_owed() {
        let s = BackupScheduler::new(Duration::from_millis(0));
        s.mark_dirty();
        assert!(s.claim());
        s.requeue();
        assert!(s.is_pending());
    }

    #[test]
    fn disabling_clears_the_pending_job() {
        let s = BackupScheduler::new(Duration::from_millis(0));
        s.mark_dirty();
        s.set_enabled(false);
        assert!(!s.is_pending());
        s.mark_dirty();
        assert!(!s.is_pending(), "marking while disabled must do nothing");
    }
}
