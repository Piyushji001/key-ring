//! One-click connect: the layer that turns a record into a live session.
//!
//! Everything here follows the same shape. Read the record's fields inside
//! Rust, decrypt what is needed into `Zeroizing` buffers, hand them to the OS
//! through a channel that is not a command line, and return nothing but
//! status. No plaintext crosses IPC in either direction.
//!
//! ## The four routes
//!
//! | Record type | Mechanism | Secret travels via |
//! |---|---|---|
//! | SSH with a key | extract key, `ssh -i` | file with a restrictive ACL |
//! | SSH with a password | `SSH_ASKPASS` helper | single-use named pipe |
//! | RDP | `CredWriteW` staging (Phase 6) | Windows credential store |
//! | Cloud / Kubernetes | terminal launch | child environment block |
//!
//! None of them is a command line. That is the whole design.
//!
//! ## Why SSH prefers the key
//!
//! When a record has both a private key and a password, the key wins. It is
//! the stronger credential, it needs no helper process, and it is what the
//! record's owner almost certainly intended. The password stays available as
//! an explicit fallback for the cases where the key has a passphrase the user
//! would rather type.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::{AppError, Result};

use super::askpass;
use super::cloud::{self, CloudCredentials, CloudProvider};
use super::terminal::{self, Launch, TerminalKind};

/// How the SSH session authenticated. Reported to the UI so the toast can be
/// specific rather than saying "connected" and leaving the user guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAuth {
    /// A private key was extracted to a temp file.
    Key,
    /// The askpass helper is standing by with the password.
    AskpassPassword,
    /// Neither was available; the user will be prompted by `ssh` itself.
    Interactive,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResult {
    pub launched: bool,
    pub auth: Option<SshAuth>,
    pub terminal: String,
    /// Human-readable, never contains a secret.
    pub detail: String,
    /// Set when Keyring had to degrade — no helper, no key, a CLI that will
    /// prompt anyway. The UI shows this rather than claiming success.
    pub caveat: Option<String>,
    /// Seconds until any extracted material is destroyed.
    pub cleanup_in_secs: Option<u64>,
}

/// Everything needed to open an SSH session, gathered by the caller from the
/// record before any of it reaches this module.
pub struct SshTarget {
    pub host: String,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub jump_host: Option<String>,
    /// Decrypted private key, if the record has one.
    pub private_key: Option<Zeroizing<Vec<u8>>>,
    pub key_filename: Option<String>,
    /// Decrypted password, if the record has one.
    pub password: Option<Zeroizing<String>>,
}

/// Open an SSH session in a terminal.
///
/// Returns the channel that must stay alive until the helper has read the
/// password — the caller holds it for the duration and drops it afterwards.
pub fn ssh(
    target: SshTarget,
    preference: TerminalKind,
    registry: &super::tempfile::TempRegistry,
    key_ttl: Duration,
    askpass_enabled: bool,
) -> Result<(ConnectResult, Option<askpass::AskpassChannel>)> {
    if target.host.trim().is_empty() {
        return Err(AppError::invalid("This record has no host."));
    }

    let resolved = terminal::resolve(preference)?;
    let mut caveat = None;
    let mut channel = None;
    let mut cleanup_in_secs = None;

    // Route 1: a key. Preferred whenever one exists.
    let (auth, key_path) = if let Some(key) = target.private_key {
        let filename = target
            .key_filename
            .clone()
            .unwrap_or_else(|| "id_keyring".to_string());
        let path = registry.extract(&filename, &key, key_ttl)?;
        // OpenSSH refuses a key whose permissions are "too open".
        super::ssh::restrict_to_current_user(&path)?;
        cleanup_in_secs = Some(key_ttl.as_secs());
        (SshAuth::Key, Some(path))
    } else if let Some(password) = target.password {
        // Route 2: the askpass helper.
        if !askpass_enabled {
            caveat = Some(
                "Password handoff is switched off in Settings, so ssh will ask for it.".to_string(),
            );
            (SshAuth::Interactive, None)
        } else {
            match askpass::serve(password) {
                Ok(ch) => {
                    channel = Some(ch);
                    (SshAuth::AskpassPassword, None)
                }
                Err(e) => {
                    // Degrade, never fail. An interactive prompt is a working
                    // connection; an error dialog is not.
                    tracing::warn!(error = %e, "askpass unavailable, falling back to a prompt");
                    caveat = Some(format!("{} ssh will ask for the password.", e.message));
                    (SshAuth::Interactive, None)
                }
            }
        }
    } else {
        (SshAuth::Interactive, None)
    };

    let command = super::ssh::build_command(
        &target.host,
        target.port,
        target.username.as_deref(),
        target.jump_host.as_deref(),
        key_path.as_deref(),
    )?;

    // `build_command` returns a shell-ready string; split it back into argv so
    // the no-secret-in-argv check has something to inspect. Everything in it
    // is non-secret by contract.
    let mut argv = shell_split(&command);
    if argv.is_empty() {
        return Err(AppError::internal("empty ssh command"));
    }

    let mut launch = Launch {
        keep_open: false,
        title: Some(format!("SSH — {}", target.host)),
        ..Default::default()
    };

    if auth == SshAuth::AskpassPassword {
        if let Some(ch) = &channel {
            let helper = askpass::helper_path()?;
            launch.env.insert(
                "SSH_ASKPASS".into(),
                Zeroizing::new(helper.to_string_lossy().into_owned()),
            );
            // Without `force`, OpenSSH uses the helper only when there is no
            // console attached — which there always is, here.
            launch
                .env
                .insert("SSH_ASKPASS_REQUIRE".into(), Zeroizing::new("force".into()));
            launch.env.insert(
                "KEYRING_ASKPASS_PIPE".into(),
                Zeroizing::new(ch.pipe_name().to_string()),
            );
            // The helper cannot answer a host-key prompt, so a first
            // connection to an unknown host would hang waiting for one.
            argv.push("-o".into());
            argv.push("StrictHostKeyChecking=accept-new".into());
        }
    }

    launch.argv = argv;
    let pid = terminal::spawn(&resolved, launch)?;

    let detail = match auth {
        SshAuth::Key => format!("Connected to {} with a key", target.host),
        SshAuth::AskpassPassword => format!("Connecting to {}", target.host),
        SshAuth::Interactive => format!("Opened a session to {}", target.host),
    };

    tracing::info!(host = %target.host, pid, auth = ?auth, "ssh session launched");

    Ok((
        ConnectResult {
            launched: true,
            auth: Some(auth),
            terminal: resolved.label.to_string(),
            detail,
            caveat,
            cleanup_in_secs,
        },
        channel,
    ))
}

/// Open a cloud shell.
pub fn cloud_shell(
    provider: CloudProvider,
    creds: CloudCredentials,
    preference: TerminalKind,
    registry: &super::tempfile::TempRegistry,
    ttl: Duration,
) -> Result<ConnectResult> {
    let resolved = terminal::resolve(preference)?;

    let session_id = format!("{}-{}", provider.as_str(), std::process::id());
    let scratch = cloud::scratch_root(&session_id)?;

    let session = cloud::build_launch(provider, &creds, &scratch, true)?;

    // Register every file written into the scratch tree so the existing
    // registry destroys them on lock, on exit, or at the TTL.
    if let Some(dir) = &session.config_dir {
        register_tree(registry, dir, ttl);
    }

    let pid = terminal::spawn(&resolved, session.launch)?;

    let caveat = if session.cli_may_prompt {
        Some(format!(
            "SDKs and Terraform are authenticated. The {} CLI itself may still ask you to sign in — Keyring will not put a client secret on a command line.",
            provider.label()
        ))
    } else {
        None
    };

    tracing::info!(
        provider = provider.as_str(),
        pid,
        "cloud shell launched"
    );

    Ok(ConnectResult {
        launched: true,
        auth: None,
        terminal: resolved.label.to_string(),
        detail: format!("{} — try `{}`", session.summary, provider.verify_command()),
        caveat,
        cleanup_in_secs: Some(ttl.as_secs()),
    })
}

/// Walk a scratch directory and register every file for deletion.
///
/// The registry tracks files, not directories, and the cloud tools write
/// their own state into these folders after we are done with them. Registering
/// what exists now covers the credential material; the periodic sweep of the
/// extraction root catches the rest.
fn register_tree(registry: &super::tempfile::TempRegistry, dir: &std::path::Path, ttl: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            register_tree(registry, &path, ttl);
        } else {
            registry.adopt(&path, ttl);
        }
    }
}

/// Split a command string back into arguments, honouring the quoting that
/// `ssh::build_command` produces.
///
/// Deliberately simple and deliberately paired with that one function. It is
/// not a general shell parser and should not become one.
fn shell_split(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for c in command.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_reverses_build_command_quoting() {
        let command = super::super::ssh::build_command(
            "host with space",
            Some(2222),
            Some("deploy"),
            None,
            None,
        )
        .unwrap();
        let argv = shell_split(&command);
        assert_eq!(argv[0], "ssh");
        assert!(argv.contains(&"-p".to_string()));
        assert!(argv.contains(&"2222".to_string()));
        assert!(argv.iter().any(|a| a.contains("deploy@host with space")));
    }

    #[test]
    fn shell_split_handles_plain_commands() {
        assert_eq!(
            shell_split("ssh -p 22 deploy@10.0.0.7"),
            vec!["ssh", "-p", "22", "deploy@10.0.0.7"]
        );
    }

    #[test]
    fn shell_split_keeps_escaped_quotes_inside_a_quoted_argument() {
        assert_eq!(shell_split(r#"ssh "a\"b""#), vec!["ssh", "a\"b"]);
    }
}
