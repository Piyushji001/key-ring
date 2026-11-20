//! The server side of the `SSH_ASKPASS` handoff.
//!
//! Creates a single-use named pipe, hands the name to `ssh.exe` through the
//! environment, and serves exactly one password to the helper described in
//! `crates/keyring-askpass`.
//!
//! ## Decision D-39 — the fifth `unsafe` site
//!
//! The handoff document says a fifth `unsafe` block should have to justify
//! itself. Here is the justification.
//!
//! The *client* side needs no bindings: on Windows a named pipe is opened with
//! an ordinary file open, which is why the helper binary is `forbid(unsafe)`.
//! The *server* side is different — `CreateNamedPipeW` and `ConnectNamedPipe`
//! have no safe equivalent in the standard library, and the alternatives are:
//!
//!   - A crate (`interprocess`, `named_pipe`). Adds a dependency with its own
//!     unsafe blocks to the tree of a security product, to save writing forty
//!     lines. It also would not reduce the total amount of unsafe code in the
//!     process, only move it somewhere less visible.
//!   - A file in a temp directory instead of a pipe. Worse in every way: the
//!     password would be written to disk, and the whole point of this module
//!     is that it never is.
//!   - A TCP socket on loopback. Absolutely not. Rule 1 of this project is
//!     that no networking crate is in the dependency tree, and a socket is a
//!     socket whatever address it binds.
//!
//! So: forty lines of `unsafe`, contained in this file, in three calls whose
//! failure modes are all "the connection falls back to an interactive
//! password prompt".
//!
//! ## What the security descriptor does
//!
//! The pipe is created with `PIPE_REJECT_REMOTE_CLIENTS` and a maximum
//! instance count of one. Combined with a 128-bit random name and a hard
//! deadline, that means a process racing for the name gets one attempt at
//! guessing a value it cannot see, inside a window measured in seconds.
//!
//! Windows named pipes default to a descriptor granting access to the creating
//! user and to administrators. Administrators can read any process's memory
//! anyway, so that is not a boundary this code can create or lose.

use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{AppError, Result};

/// How long the pipe waits for the helper before giving up.
///
/// `ssh` runs the askpass program almost immediately after starting, so this
/// is generous. If it expires, `ssh` falls back to prompting and the user
/// types the password — degraded, not broken.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// A pipe that is waiting to hand one password to one helper process.
pub struct AskpassChannel {
    pipe_name: String,
    /// Signals the serving thread to stop early — on lock, or when the launch
    /// failed and no helper is ever going to connect.
    cancel: mpsc::Sender<()>,
}

impl AskpassChannel {
    /// The value for `KEYRING_ASKPASS_PIPE`.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Stop serving. Idempotent.
    pub fn cancel(&self) {
        let _ = self.cancel.send(());
    }
}

impl Drop for AskpassChannel {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Path to the helper binary.
///
/// It sits next to the main executable, because that is where the installer
/// puts it and where a portable unzip leaves it.
pub fn helper_path() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()
        .map_err(|_| AppError::internal("could not locate the Keyring executable"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| AppError::internal("Keyring executable has no parent directory"))?;

    let candidate = dir.join("keyring-askpass.exe");
    if candidate.is_file() {
        return Ok(candidate);
    }

    // `cargo tauri dev` puts the helper in the workspace target directory
    // or parent build directory rather than beside the app binary.
    let sibling = dir.join("..").join("keyring-askpass.exe");
    if sibling.is_file() {
        return Ok(sibling);
    }

    // Check cargo build output root directory directly (target/debug/keyring-askpass.exe)
    if let Ok(ancestor) = dir.canonicalize() {
        let root_candidate = ancestor.join("keyring-askpass.exe");
        if root_candidate.is_file() {
            return Ok(root_candidate);
        }
        if let Some(parent) = ancestor.parent() {
            let parent_candidate = parent.join("keyring-askpass.exe");
            if parent_candidate.is_file() {
                return Ok(parent_candidate);
            }
        }
    }

    Err(AppError::invalid(
        "The SSH password helper (keyring-askpass.exe) is missing. Reinstall Keyring, or connect with a key instead.",
    ))
}

/// Is password-based one-click SSH available on this machine?
///
/// Two conditions: the helper exists, and the installed OpenSSH understands
/// `SSH_ASKPASS_REQUIRE`. The second cannot be probed reliably without
/// attempting a connection, so this reports on the helper and the presence of
/// `ssh.exe`, and the UI is written to describe it as "should work" rather
/// than "will work".
pub fn is_available() -> bool {
    helper_path().is_ok() && which_ssh().is_some()
}

/// Locate `ssh.exe`. Windows has shipped OpenSSH since 1803, but it is an
/// optional feature and can be absent.
pub fn which_ssh() -> Option<std::path::PathBuf> {
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        let path = std::path::Path::new(&system_root)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        if path.is_file() {
            return Some(path);
        }
    }
    // Fall back to PATH — Git for Windows and Scoop both provide one.
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|p| p.join("ssh.exe"))
            .find(|p| p.is_file())
    })
}

#[cfg(windows)]
#[allow(unsafe_code)] // D-39: CreateNamedPipeW/ConnectNamedPipe have no safe equivalent.
mod imp {
    use super::*;
    use std::os::windows::io::FromRawHandle;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::Storage::FileSystem::PIPE_ACCESS_OUTBOUND;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Create the pipe and spawn a thread that serves `secret` exactly once.
    pub fn serve(secret: Zeroizing<String>) -> Result<AskpassChannel> {
        let mut suffix = [0u8; 16];
        keyring_crypto::fill_random(&mut suffix)
            .map_err(|_| AppError::internal("could not generate a pipe name"))?;
        let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let pipe_name = format!(r"\\.\pipe\keyring-askpass-{hex}");

        let name_w = wide(&pipe_name);

        // SAFETY (D-39): `CreateNamedPipeW` is given a null-terminated UTF-16
        // buffer that outlives the call, a fixed set of documented flags, and
        // a null security attributes pointer (meaning "default descriptor for
        // this user"). The returned handle is either INVALID_HANDLE_VALUE,
        // which is checked immediately, or a handle this function owns and
        // hands to exactly one thread.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name_w.as_ptr()),
                PIPE_ACCESS_OUTBOUND,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                // Exactly one instance. A second creator of the same name
                // fails rather than silently sharing.
                1,
                4096,
                4096,
                0,
                None,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(AppError::internal("could not create the askpass pipe"));
        }

        let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
        let name_for_thread = pipe_name.clone();

        std::thread::spawn(move || {
            let handle = handle;
            let served = serve_once(handle, secret, cancel_rx);
            // SAFETY: the handle was created above, has not been closed, and
            // this thread is its sole owner at this point.
            unsafe {
                let _ = DisconnectNamedPipe(handle);
                let _ = CloseHandle(handle);
            }
            match served {
                Ok(true) => tracing::info!("askpass: password delivered to the helper"),
                Ok(false) => tracing::info!("askpass: pipe closed without being used"),
                Err(e) => tracing::warn!(error = %e, "askpass: could not serve the password"),
            }
            let _ = name_for_thread;
        });

        Ok(AskpassChannel {
            pipe_name,
            cancel: cancel_tx,
        })
    }

    /// Wait for the helper, write the secret, return whether it was consumed.
    fn serve_once(
        handle: HANDLE,
        secret: Zeroizing<String>,
        cancel: mpsc::Receiver<()>,
    ) -> std::result::Result<bool, String> {
        let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;

        // `ConnectNamedPipe` on a blocking pipe waits indefinitely, which
        // would leak a thread whenever a launch fails. So the wait is done in
        // a nested thread and this one polls for cancellation.
        let (done_tx, done_rx) = mpsc::channel::<bool>();
        let raw = handle.0 as isize;
        std::thread::spawn(move || {
            let handle = HANDLE(raw as _);
            // SAFETY: the handle is valid for the lifetime of the outer
            // thread, which does not close it until this one has reported.
            let connected = unsafe { ConnectNamedPipe(handle, None) }.is_ok();
            let _ = done_tx.send(connected);
        });

        loop {
            if cancel.try_recv().is_ok() {
                return Ok(false);
            }
            match done_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(true) => break,
                Ok(false) => return Err("the helper never connected".to_string()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if std::time::Instant::now() > deadline {
                        return Ok(false);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(false),
            }
        }

        // SAFETY: converting a connected pipe handle into a `File` so the
        // write itself is safe code. `File` takes ownership, so it is
        // deliberately leaked with `into_raw_handle` semantics via `forget`
        // below — the outer thread closes the handle exactly once.
        let mut file = unsafe { std::fs::File::from_raw_handle(handle.0 as *mut _) };
        let mut payload = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
        payload.extend_from_slice(secret.as_bytes());
        payload.push(b'\n');

        let result = file
            .write_all(&payload)
            .and_then(|_| file.flush())
            .map(|_| true)
            .map_err(|e| e.to_string());

        // Do not let `File`'s Drop close the handle: the outer thread does it.
        std::mem::forget(file);
        result
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    /// Non-Windows builds compile but cannot serve. The whole feature is
    /// Windows-only for v1; this exists so `cargo check` works on a Linux CI
    /// runner without `cfg` noise at every call site.
    pub fn serve(_secret: Zeroizing<String>) -> Result<AskpassChannel> {
        Err(AppError::invalid(
            "One-click SSH with a password is only available on Windows.",
        ))
    }
}

/// Start serving `secret` on a fresh single-use pipe.
pub fn serve(secret: Zeroizing<String>) -> Result<AskpassChannel> {
    imp::serve(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_helper_produces_an_actionable_message() {
        // Cannot assert on the presence of the binary in a test run, but the
        // error text must always tell the user what to do about it.
        if let Err(e) = helper_path() {
            assert!(e.message.contains("key instead") || e.message.contains("Reinstall"));
        }
    }

    #[test]
    fn availability_is_a_conjunction_not_a_guess() {
        // is_available must never be true when the helper is absent.
        if helper_path().is_err() {
            assert!(!is_available());
        }
    }
}
