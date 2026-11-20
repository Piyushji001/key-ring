//! Advisory single-writer lock.
//!
//! This matters because cloud sync clients will happily produce conflicted
//! copies if two machines write the same vault at once, and because a second
//! window opening the same vault would fight the first over every save.
//!
//! ## Liveness
//!
//! The lock records a PID. On Windows we ask the OS whether that process is
//! still running; if it is not, the lock is stale and gets cleared silently.
//! This replaces the original twelve-hour age heuristic (decision D-9), which
//! was a real problem in practice: `cargo tauri dev` orphans processes on
//! Ctrl+C, and an orphan used to hold your vault hostage for half a day.
//!
//! Age is still used as a backstop on platforms where liveness is unknown.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::util::time::now_unix;

/// Backstop for platforms where process liveness cannot be determined.
pub const STALE_AFTER_SECS: i64 = 12 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub pid: u32,
    pub acquired_at: i64,
}

#[derive(Debug)]
pub enum LockOutcome {
    /// The lock is ours.
    Acquired(LockGuard),
    /// A live process holds it. The caller may offer read-only.
    Held(LockInfo),
}

/// Deletes the lock file on drop.
#[derive(Debug)]
pub struct LockGuard {
    path: PathBuf,
    /// Set when ownership has been handed to a replacement guard, so dropping
    /// this one does not delete a lock somebody else now holds.
    released: bool,
}

impl LockGuard {
    /// Give up ownership without deleting the file. Used when one session
    /// hands a vault directly to another.
    pub fn release(&mut self) {
        self.released = true;
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        if !self.released {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Is a process with this id currently running?
///
/// `None` means we could not tell, in which case the caller falls back to the
/// age heuristic rather than guessing.
#[cfg(windows)]
#[allow(unsafe_code)] // The only unsafe in this crate. Three Win32 calls, each
                      // with its handle closed on every path. No pointers are
                      // dereferenced and no buffers are shared.
pub fn process_is_alive(pid: u32) -> Option<bool> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// STATUS_PENDING. GetExitCodeProcess reports this while a process runs.
    const STILL_RUNNING: u32 = 259;
    /// E_ACCESSDENIED: the process exists, it just is not ours to inspect.
    const ACCESS_DENIED: i32 = -2147024891; // 0x80070005

    if pid == 0 {
        return Some(false);
    }

    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            // Access denied means the process exists but belongs to someone
            // else; anything else means it is gone.
            Err(e) => {
                return Some(e.code().0 == ACCESS_DENIED);
            }
        };

        let mut code: u32 = 0;
        let alive = match GetExitCodeProcess(handle, &mut code) {
            Ok(()) => code == STILL_RUNNING,
            Err(_) => false,
        };
        let _ = CloseHandle(handle);
        Some(alive)
    }
}

#[cfg(not(windows))]
pub fn process_is_alive(_pid: u32) -> Option<bool> {
    // Implemented per-platform as macOS and Linux builds arrive.
    None
}

/// Try to take the lock.
pub fn acquire(path: &Path) -> Result<LockOutcome> {
    if let Ok(text) = std::fs::read_to_string(path) {
        if let Ok(info) = serde_json::from_str::<LockInfo>(&text) {
            if info.pid == std::process::id() {
                tracing::debug!("re-taking our own lock");
            } else {
                let stale = match process_is_alive(info.pid) {
                    Some(true) => false,
                    Some(false) => {
                        tracing::warn!(pid = info.pid, "lock owner is gone, clearing stale lock");
                        true
                    }
                    None => {
                        let age = now_unix() - info.acquired_at;
                        age < 0 || age >= STALE_AFTER_SECS
                    }
                };
                if !stale {
                    return Ok(LockOutcome::Held(info));
                }
            }
        }
    }

    let info = LockInfo {
        pid: std::process::id(),
        acquired_at: now_unix(),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, serde_json::to_string(&info).unwrap_or_default())?;

    Ok(LockOutcome::Acquired(LockGuard {
        path: path.to_path_buf(),
        released: false,
    }))
}
