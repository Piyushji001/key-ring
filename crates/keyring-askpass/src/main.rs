//! `keyring-askpass.exe` — the helper OpenSSH calls when it needs a password.
//!
//! ## Why this program exists
//!
//! OpenSSH will not read a password from its command line or from stdin. That
//! is deliberate, and working around it is the wrong instinct: a password on a
//! command line is visible to Task Manager, Process Explorer and every EDR
//! agent on the machine. Keyring already rejected that route once, for RDP
//! (decision D-33), and the same reasoning applies here.
//!
//! What OpenSSH *does* support is `SSH_ASKPASS`: the path to a program it runs
//! when it wants a passphrase, reading the answer from that program's standard
//! output. So Keyring ships one.
//!
//! ## How the password gets here
//!
//! Not through the command line, and not through an environment variable —
//! both are readable by any process running as the same user, and an
//! environment block is inherited by every child.
//!
//! Instead, Keyring creates a **named pipe** with a 128-bit random name, then
//! launches `ssh.exe` with two variables set:
//!
//! ```text
//! SSH_ASKPASS         = <path to this program>
//! SSH_ASKPASS_REQUIRE = force
//! KEYRING_ASKPASS_PIPE = \\.\pipe\keyring-askpass-<32 hex chars>
//! ```
//!
//! `ssh.exe` inherits those and passes them on when it spawns this helper.
//! This program connects to the pipe, reads exactly one line, prints it to
//! stdout, and exits. Keyring closes the pipe after that single read.
//!
//! The pipe **name** is not a secret and does not need to be — the pipe is
//! created with a security descriptor allowing only the current user, and it
//! accepts exactly one connection before Keyring tears it down. What the name
//! being random buys is that a process which is already running as this user
//! cannot sit and wait for a predictable name to appear.
//!
//! ## Threat model, stated plainly
//!
//! This protects the password from: the process list, command-line logging,
//! shell history, EDR command-line capture, and other users on the machine.
//!
//! It does **not** protect against malware already running as this user. That
//! attacker can read Keyring's own memory and does not need to bother with the
//! pipe. No password-manager integration on Windows defends against that, and
//! any that claims to is lying.
//!
//! ## Why a separate binary
//!
//! `SSH_ASKPASS` must point at something executable. Pointing it at the main
//! Keyring binary with a magic flag would mean the GUI application has a code
//! path that prints a password to stdout — a single argument-parsing mistake
//! away from disaster. A forty-line program that does nothing else is much
//! easier to reason about, and it is trivially auditable in full.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io::{BufRead, BufReader, Write};

/// Environment variable naming the pipe to read from.
const PIPE_VAR: &str = "KEYRING_ASKPASS_PIPE";

fn main() {
    // Exit code 1 with nothing on stdout makes `ssh` fall back to its normal
    // interactive prompt, which is the correct degraded behaviour: the user
    // types the password themselves and the connection still works.
    match read_secret() {
        Ok(secret) => {
            let mut stdout = std::io::stdout();
            // OpenSSH reads one line. The newline is required.
            let _ = stdout.write_all(secret.as_bytes());
            let _ = stdout.write_all(b"\n");
            let _ = stdout.flush();
            // The buffer wipes itself on drop; do not let anything else run
            // between here and process exit.
            drop(secret);
        }
        Err(message) => {
            // stderr, never stdout: anything on stdout is treated as the
            // password.
            eprintln!("keyring-askpass: {message}");
            std::process::exit(1);
        }
    }
}

fn read_secret() -> Result<zeroize::Zeroizing<String>, String> {
    let pipe_name = std::env::var(PIPE_VAR)
        .map_err(|_| format!("{PIPE_VAR} is not set; nothing to read"))?;

    if !pipe_name.starts_with(r"\\.\pipe\keyring-askpass-") {
        // Refuses to be pointed at an arbitrary pipe by something that has
        // tampered with the environment.
        return Err("pipe name is not a Keyring askpass pipe".to_string());
    }

    // On Windows a named pipe client is just a file open. No `unsafe`, no
    // bindings — `\\.\pipe\name` is a real path to the OS.
    let file = open_with_retry(&pipe_name)?;

    let mut reader = BufReader::new(file);
    let mut line = zeroize::Zeroizing::new(String::new());
    reader
        .read_line(&mut line)
        .map_err(|e| format!("could not read from the pipe: {e}"))?;

    // Strip exactly the line terminator, never trailing whitespace: a password
    // is allowed to end in a space and it is not this program's business to
    // decide otherwise.
    let mut value = line.to_string();
    while value.ends_with('\n') || value.ends_with('\r') {
        value.pop();
    }
    let out = zeroize::Zeroizing::new(value);

    if out.is_empty() {
        return Err("the pipe delivered an empty value".to_string());
    }
    Ok(out)
}

/// Open the pipe, retrying briefly.
///
/// `ssh.exe` may invoke this helper a fraction before Keyring's server side
/// finishes waiting for a connection. A short retry loop turns a race into a
/// non-event. Two seconds total: if Keyring is not there by then, it is not
/// coming, and falling back to the interactive prompt is better than hanging.
fn open_with_retry(pipe_name: &str) -> Result<std::fs::File, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut last_error = String::from("unknown");
    while std::time::Instant::now() < deadline {
        match std::fs::OpenOptions::new().read(true).open(pipe_name) {
            Ok(file) => return Ok(file),
            Err(e) => {
                last_error = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
    Err(format!("could not open the pipe: {last_error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_foreign_pipe_name_is_refused() {
        std::env::set_var(PIPE_VAR, r"\\.\pipe\something-else");
        let err = read_secret().unwrap_err();
        assert!(err.contains("not a Keyring askpass pipe"));
        std::env::remove_var(PIPE_VAR);
    }

    #[test]
    fn a_missing_variable_is_refused_rather_than_panicking() {
        std::env::remove_var(PIPE_VAR);
        assert!(read_secret().is_err());
    }
}
