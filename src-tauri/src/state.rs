//! Application state: exactly one optional unlocked session, behind a Mutex.
//!
//! The `Mutex` is not for performance, it is for correctness: Tauri dispatches
//! commands on a thread pool, so two IPC calls can arrive concurrently and both
//! could otherwise mutate the vault.
//!
//! The session is `Option` because the locked state is a real state, not an
//! absence. When it is `None`, no key material exists anywhere in the process.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use keyring_vault::backup::{BackupScheduler, Snapshot, Trigger};
use keyring_vault::db;
use keyring_vault::portable::export::PlaintextGate;
use keyring_vault::{LockReason, SearchIndex, VaultSession};

use crate::actions::tempfile::TempRegistry;
use crate::error::{AppError, Result};
use crate::model::dto::ClipboardStatus;

pub struct AppState {
    session: Mutex<Option<VaultSession>>,
    /// Rebuilt on unlock and after every mutation. Dropped on lock, which is
    /// what wipes the decrypted note bodies it holds.
    index: Mutex<Option<SearchIndex>>,
    /// Last time the user did anything. Drives the idle lock in Phase 6.
    last_activity: Mutex<Instant>,
    /// Vault paths the user has opened. Paths only - never passwords.
    recent_vaults: Mutex<Vec<PathBuf>>,
    /// Files extracted to disk, and their deadlines.
    temp_files: TempRegistry,
    /// Tracks what we last put on the clipboard. Holds a SHA-256 of the value,
    /// never the value: enough to verify ownership before clearing, useless to
    /// anyone who reads it out of memory.
    clipboard: Mutex<Option<ClipboardHold>>,
    /// Incremented on every copy. A scheduled clear whose generation no longer
    /// matches has been superseded and does nothing.
    clipboard_generation: AtomicU64,

    // ----------------------------------------------------------- Phase 7
    /// Decides *when* a backup is owed. Never holds the session, so it cannot
    /// deadlock against a save.
    backup: BackupScheduler,
    /// Message from the last failed backup. Surfaced in Settings, because a
    /// backup folder that silently stopped working must not look identical to
    /// one that is fine.
    backup_error: Mutex<Option<String>>,
    /// Enforces the two-step plaintext export confirmation in Rust (D-37).
    plaintext_gate: PlaintextGate,

    // --------------------------------------------------------- Phase 7.5
    /// A one-shot pipe holding an SSH password until the askpass helper reads
    /// it. Parked here because `ssh` may take a second or two to get round to
    /// asking, and a channel dropped at the end of the IPC call would close
    /// the pipe first.
    ///
    /// At most one is ever held: a second connection supersedes the first,
    /// which closes it. That is deliberate — two simultaneous pending
    /// passwords would mean the helper could read the wrong one.
    askpass: Mutex<Option<crate::actions::askpass::AskpassChannel>>,
}

#[derive(Debug)]
struct ClipboardHold {
    fingerprint: [u8; 32],
    expires_at: Instant,
    generation: u64,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            session: Mutex::new(None),
            index: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            recent_vaults: Mutex::new(Vec::new()),
            temp_files: TempRegistry::new(),
            clipboard: Mutex::new(None),
            clipboard_generation: AtomicU64::new(0),
            backup: BackupScheduler::default(),
            backup_error: Mutex::new(None),
            plaintext_gate: PlaintextGate::new(),
            askpass: Mutex::new(None),
        }
    }

    // --------------------------------------------------------- Phase 7.5

    /// Hold a pending askpass channel, replacing and closing any previous one.
    pub fn park_askpass(&self, channel: crate::actions::askpass::AskpassChannel) {
        if let Ok(mut slot) = self.askpass.lock() {
            // The old channel drops here, which closes its pipe.
            *slot = Some(channel);
        }
    }

    /// Close any pending askpass channel now.
    pub fn clear_askpass(&self) {
        if let Ok(mut slot) = self.askpass.lock() {
            slot.take();
        }
    }

    /// Append to the in-vault activity log, honouring the user's setting.
    ///
    /// Deliberately infallible from the caller's point of view. A log write
    /// that fails must never abort the action the user actually asked for —
    /// refusing to launch a session because an audit row would not insert
    /// would be a worse outcome than the missing row.
    ///
    /// `detail` must never carry a field value. See the banner in
    /// `db/activity.rs`.
    pub fn log_activity(
        &self,
        action: keyring_vault::LogAction,
        record_id: Option<&str>,
        detail: Option<&str>,
    ) {
        let _ = self.with_session_mut(|session| {
            let enabled = {
                let conn = session.conn()?;
                db::settings::get_i64(conn, db::settings::ACTIVITY_LOG_ENABLED, 1) != 0
            };
            if !enabled {
                return Ok(());
            }
            let conn = session.conn()?;
            let _ = db::activity::record(conn, action, record_id, detail);
            Ok(())
        });
    }

    // ----------------------------------------------------------- Phase 7

    pub fn backup_scheduler(&self) -> &BackupScheduler {
        &self.backup
    }

    pub fn plaintext_gate(&self) -> &PlaintextGate {
        &self.plaintext_gate
    }

    pub fn last_backup_error(&self) -> Option<String> {
        self.backup_error.lock().ok().and_then(|e| e.clone())
    }

    fn set_backup_error(&self, message: Option<String>) {
        if let Ok(mut slot) = self.backup_error.lock() {
            *slot = message;
        }
    }

    /// The vault changed. Called from every mutating command.
    ///
    /// Cheap and lock-free, so putting it on the write path costs nothing.
    pub fn mark_dirty_for_backup(&self) {
        self.backup.mark_dirty();
    }

    /// Take a snapshot now.
    ///
    /// Reads the destination from the vault's own settings, so backup
    /// configuration travels with the vault rather than living in the
    /// registry. Returns `Err` when no folder is configured - the caller
    /// decides whether that is a failure (a manual "Back up now") or simply
    /// nothing to do (the automatic sweeper).
    pub fn run_backup(&self, trigger: Trigger) -> Result<Snapshot> {
        let (dir, retention, record_count, format_version, vault_id, root) =
            self.with_session(|session| {
                let conn = session.conn()?;
                Ok((
                    db::settings::get(conn, db::settings::BACKUP_DIR)?
                        .filter(|d| !d.trim().is_empty()),
                    db::settings::get_i64(conn, db::settings::BACKUP_RETENTION, 10) as usize,
                    db::records::count(conn)?,
                    session.format_version(),
                    session.header().vault_id.clone(),
                    session.paths().clone(),
                ))
            })?;

        let Some(dir) = dir else {
            self.set_backup_error(None);
            return Err(AppError::invalid(
                "No backup folder is configured. Set one in Settings.",
            ));
        };

        let dir = std::path::PathBuf::from(dir);
        keyring_vault::backup::rotate::clear_partials(&dir);

        let snapshot = match keyring_vault::backup::create_snapshot(
            &root,
            &dir,
            record_count,
            format_version,
            &vault_id,
            trigger,
        ) {
            Ok(s) => s,
            Err(e) => {
                let message = AppError::from(e).message;
                self.set_backup_error(Some(message.clone()));
                let _ = self.with_session_mut(|session| {
                    let conn = session.conn()?;
                    Ok(db::activity::record(
                        conn,
                        db::activity::Action::BackupFailed,
                        None,
                        Some(&message),
                    )?)
                });
                return Err(AppError::invalid(message));
            }
        };

        // Retention is applied after the new snapshot exists, never before.
        // Pruning first would mean a failed backup left the user with one
        // fewer copy than they had a moment ago.
        match keyring_vault::backup::prune(&dir, retention) {
            Ok(outcome) if !outcome.failed.is_empty() => {
                tracing::warn!(
                    failed = outcome.failed.len(),
                    "some old backups could not be pruned"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "backup retention failed"),
        }

        self.set_backup_error(None);

        let _ = self.with_session_mut(|session| {
            let conn = session.conn()?;
            Ok(db::activity::record(
                conn,
                db::activity::Action::BackupCreated,
                None,
                Some(&snapshot.stamp),
            )?)
        });

        Ok(snapshot)
    }

    /// Flush an owed backup because the user is walking away.
    ///
    /// Called on lock and on exit. The debounce exists to avoid thrashing the
    /// disk during editing; once the session is ending there is nothing left
    /// to wait for.
    pub fn flush_pending_backup(&self) {
        if !self.backup.is_pending() {
            return;
        }
        if !self.backup.claim() {
            return;
        }
        match self.run_backup(Trigger::Automatic) {
            Ok(s) => tracing::info!(stamp = %s.stamp, "flushed pending backup before locking"),
            Err(e) => tracing::info!(reason = %e.message, "no backup taken on lock"),
        }
    }

    pub fn is_locked(&self) -> bool {
        match self.session.lock() {
            Ok(guard) => guard.as_ref().map(|s| s.is_locked()).unwrap_or(true),
            // A poisoned mutex means a command panicked mid-mutation. Report
            // locked, which is the safe answer.
            Err(_) => true,
        }
    }

    /// Read from the unlocked session. Errors if the vault is locked.
    pub fn with_session<T>(&self, f: impl FnOnce(&VaultSession) -> Result<T>) -> Result<T> {
        let guard = self
            .session
            .lock()
            .map_err(|_| AppError::internal("session mutex poisoned"))?;
        let session = guard.as_ref().ok_or_else(AppError::locked)?;
        if session.is_locked() {
            return Err(AppError::locked());
        }
        f(session)
    }

    /// Mutate the unlocked session.
    pub fn with_session_mut<T>(
        &self,
        f: impl FnOnce(&mut VaultSession) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| AppError::internal("session mutex poisoned"))?;
        let session = guard.as_mut().ok_or_else(AppError::locked)?;
        if session.is_locked() {
            return Err(AppError::locked());
        }
        f(session)
    }

    /// Install a freshly unlocked session, replacing and locking any previous
    /// one so two vaults can never be open at once.
    pub fn set_session(&self, session: VaultSession) -> Result<()> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| AppError::internal("session mutex poisoned"))?;
        if let Some(mut old) = guard.take() {
            old.lock(LockReason::Manual);
        }
        self.remember_vault(session.paths().root.clone());
        *guard = Some(session);
        drop(guard);
        self.touch();
        self.rebuild_index();
        Ok(())
    }

    /// Rebuild the search index from the current session. Silent on failure:
    /// a missing index degrades search, it does not break the application.
    pub fn rebuild_index(&self) {
        let built = self
            .session
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|s| SearchIndex::build(s).ok()));

        if let Ok(mut slot) = self.index.lock() {
            *slot = built;
        }
    }

    pub fn with_index<T>(&self, f: impl FnOnce(&SearchIndex) -> Result<T>) -> Result<T> {
        let guard = self
            .index
            .lock()
            .map_err(|_| AppError::internal("index mutex poisoned"))?;
        match guard.as_ref() {
            Some(index) => f(index),
            None => Err(AppError::locked()),
        }
    }

    /// Wipe key material. Idempotent: locking an already-locked vault is fine.
    pub fn lock_vault(&self, reason: LockReason) -> Result<()> {
        // Before the keys go: an owed backup is taken now rather than lost.
        // Must happen before the session mutex is taken, since `run_backup`
        // takes it too.
        self.flush_pending_backup();

        let mut guard = self
            .session
            .lock()
            .map_err(|_| AppError::internal("session mutex poisoned"))?;
        if let Some(session) = guard.as_mut() {
            session.lock(reason);
        }
        // Drop the session entirely, releasing the advisory file lock.
        *guard = None;
        drop(guard);

        // The index holds decrypted note bodies. Locking must destroy it.
        if let Ok(mut slot) = self.index.lock() {
            *slot = None;
        }

        // A pending askpass pipe still holds a password. It expires on its own,
        // but a lock is an explicit instruction to stop holding secrets now.
        self.clear_askpass();

        // A locked vault must not leave plaintext on disk or on the clipboard.
        self.temp_files.purge_all();
        if let Some(fingerprint) = self.clipboard_fingerprint() {
            let _ = crate::actions::clipboard::clear_if_ours(&fingerprint);
        }
        self.end_clipboard_hold();

        Ok(())
    }

    pub fn temp_files(&self) -> &TempRegistry {
        &self.temp_files
    }

    /// Record that we own the clipboard, returning the generation that a timer
    /// must still match when it fires.
    pub fn begin_clipboard_hold(&self, fingerprint: [u8; 32], seconds: u64) -> u64 {
        let generation = self.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut slot) = self.clipboard.lock() {
            *slot = Some(ClipboardHold {
                fingerprint,
                expires_at: Instant::now() + Duration::from_secs(seconds),
                generation,
            });
        }
        generation
    }

    pub fn clipboard_generation_is(&self, generation: u64) -> bool {
        match self.clipboard.lock() {
            Ok(slot) => slot.as_ref().map(|h| h.generation) == Some(generation),
            Err(_) => false,
        }
    }

    pub fn end_clipboard_hold(&self) {
        if let Ok(mut slot) = self.clipboard.lock() {
            *slot = None;
        }
    }

    pub fn clipboard_fingerprint(&self) -> Option<[u8; 32]> {
        self.clipboard.lock().ok()?.as_ref().map(|h| h.fingerprint)
    }

    pub fn clipboard_status(&self) -> ClipboardStatus {
        match self.clipboard.lock() {
            Ok(slot) => match slot.as_ref() {
                Some(hold) => {
                    let remaining = hold.expires_at.saturating_duration_since(Instant::now());
                    ClipboardStatus {
                        active: remaining.as_secs() > 0,
                        field: None,
                        seconds_remaining: remaining.as_secs() as u32,
                        excluded_from_history: true,
                    }
                }
                None => ClipboardStatus::idle(),
            },
            Err(_) => ClipboardStatus::idle(),
        }
    }

    pub fn touch(&self) {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Instant::now();
        }
    }

    pub fn idle_secs(&self) -> u64 {
        match self.last_activity.lock() {
            Ok(t) => t.elapsed().as_secs(),
            Err(_) => 0,
        }
    }

    fn remember_vault(&self, path: PathBuf) {
        if let Ok(mut list) = self.recent_vaults.lock() {
            list.retain(|p| p != &path);
            list.insert(0, path);
            list.truncate(8);
        }
    }

    /// Where the remembered vault list is kept. Paths only - never a password,
    /// never a key. Losing this file costs the user one Browse click.
    fn recents_file(app: &tauri::AppHandle) -> Option<PathBuf> {
        use tauri::Manager;
        let dir = app.path().app_config_dir().ok()?;
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join("recent-vaults.json"))
    }

    /// Load remembered paths at startup, so closing and reopening the app does
    /// not leave the unlock screen with nothing to unlock.
    pub fn load_recents(&self, app: &tauri::AppHandle) {
        let Some(file) = Self::recents_file(app) else { return };
        let Ok(text) = std::fs::read_to_string(file) else { return };
        let Ok(paths) = serde_json::from_str::<Vec<String>>(&text) else { return };

        if let Ok(mut list) = self.recent_vaults.lock() {
            *list = paths
                .into_iter()
                .map(PathBuf::from)
                // Drop anything that has since been deleted or moved.
                .filter(|p| p.join("vault.kr").is_file())
                .collect();
        }
    }

    pub fn save_recents(&self, app: &tauri::AppHandle) {
        let Some(file) = Self::recents_file(app) else { return };
        let paths = self.recent_vaults();
        if let Ok(json) = serde_json::to_string(&paths) {
            let _ = std::fs::write(file, json);
        }
    }

    /// The vault to offer on the unlock screen.
    pub fn last_vault(&self) -> Option<String> {
        self.recent_vaults().into_iter().next()
    }

    pub fn recent_vaults(&self) -> Vec<String> {
        match self.recent_vaults.lock() {
            Ok(list) => list
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}
