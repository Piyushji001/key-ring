//! UC-03. SSH: build the command, or put the key somewhere the client can read.
//!
//! Two levels of help, because SSH workflows vary more than RDP ones:
//!
//!   - Build `ssh user@host -p port` and copy it. Works with every client,
//!     every terminal, every multiplexer. No files, no cleanup.
//!   - Extract the private key to a temp file with an ACL that Windows OpenSSH
//!     will accept, for the tools that insist on a path.
//!
//! Direct injection into the Windows OpenSSH agent over its named pipe is
//! deliberately out of scope for v1.0 - roadmap Phase 6 defers it to v1.1, and
//! extract-to-file is acceptable while cleanup is reliable, which Phase 5's
//! registry makes it.

use std::path::Path;

use crate::error::{AppError, Result};

/// Build an `ssh` command line from a record's non-secret fields.
///
/// Nothing secret goes in here. A password would be visible in shell history
/// and in the process list, which is exactly the mistake this product exists
/// to stop people making.
pub fn build_command(
    host: &str,
    port: Option<u16>,
    username: Option<&str>,
    jump_host: Option<&str>,
    key_path: Option<&Path>,
) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(AppError::invalid("This record has no host."));
    }

    let mut parts = vec!["ssh".to_string()];

    if let Some(jump) = jump_host.map(str::trim).filter(|j| !j.is_empty()) {
        parts.push("-J".into());
        parts.push(quote_if_needed(jump));
    }
    if let Some(key) = key_path {
        parts.push("-i".into());
        parts.push(quote_if_needed(&key.to_string_lossy()));
    }
    if let Some(port) = port.filter(|p| *p != 22) {
        parts.push("-p".into());
        parts.push(port.to_string());
    }

    let destination = match username.map(str::trim).filter(|u| !u.is_empty()) {
        Some(user) => format!("{user}@{host}"),
        None => host.to_string(),
    };
    parts.push(quote_if_needed(&destination));

    Ok(parts.join(" "))
}

fn quote_if_needed(value: &str) -> String {
    if value.contains(' ') || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

/// Lock a file down to the current user only.
///
/// Windows OpenSSH refuses a private key whose permissions are "too open", and
/// a file created in a user directory still inherits ACEs from its parent that
/// OpenSSH will object to. So inheritance is removed and a single grant is
/// added for the current user.
///
/// ## Why this shells out to `icacls`
///
/// The API version is `SetNamedSecurityInfoW` plus building a DACL by hand:
/// open the process token, read the user SID, initialise an ACL, add one ACE,
/// apply it. That is a lot of unsafe pointer work for something Windows ships
/// a supported tool to do, and unlike the RDP case there is no secret on the
/// command line here - only a path and a username. So the shell-out is safe in
/// the way the `cmdkey` one was not.
///
/// Replacing this with `SetNamedSecurityInfoW` is a reasonable later exercise.
/// Decision D-31.
#[cfg(windows)]
pub fn restrict_to_current_user(path: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;

    // CREATE_NO_WINDOW: do not flash a console at the user.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let user = std::env::var("USERNAME").unwrap_or_default();
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    if user.is_empty() {
        return Err(AppError::internal("USERNAME is not set"));
    }
    let principal = if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    };

    let output = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{principal}:F"))
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|_| AppError::internal("could not run icacls"))?;

    if !output.status.success() {
        tracing::warn!(
            status = ?output.status.code(),
            "icacls did not report success; OpenSSH may reject this key"
        );
        return Err(AppError::new(
            crate::error::ErrorKind::Io,
            "Keyring could not restrict permissions on the key file. \
             SSH may refuse to use it.",
        ));
    }

    tracing::info!("extracted key locked to the current user");
    Ok(())
}

#[cfg(not(windows))]
pub fn restrict_to_current_user(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| AppError::internal("could not chmod the key file"))?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_host_needs_no_flags() {
        assert_eq!(
            build_command("10.0.0.7", None, Some("deploy"), None, None).unwrap(),
            "ssh deploy@10.0.0.7"
        );
    }

    #[test]
    fn the_default_port_is_omitted() {
        assert_eq!(
            build_command("h", Some(22), Some("u"), None, None).unwrap(),
            "ssh u@h"
        );
        assert_eq!(
            build_command("h", Some(2222), Some("u"), None, None).unwrap(),
            "ssh -p 2222 u@h"
        );
    }

    #[test]
    fn a_jump_host_and_key_are_included() {
        let cmd = build_command(
            "10.0.0.7",
            Some(2222),
            Some("deploy"),
            Some("bastion.example.com"),
            Some(Path::new("C:\\keys\\id_ed25519")),
        )
        .unwrap();
        assert!(cmd.contains("-J bastion.example.com"));
        assert!(cmd.contains("-i C:\\keys\\id_ed25519"));
        assert!(cmd.contains("-p 2222"));
        assert!(cmd.ends_with("deploy@10.0.0.7"));
    }

    #[test]
    fn paths_with_spaces_are_quoted() {
        let cmd = build_command(
            "h",
            None,
            Some("u"),
            None,
            Some(Path::new("C:\\my keys\\id_rsa")),
        )
        .unwrap();
        assert!(cmd.contains("\"C:\\my keys\\id_rsa\""));
    }

    #[test]
    fn a_missing_host_is_an_error() {
        assert!(build_command("  ", None, Some("u"), None, None).is_err());
    }

    #[test]
    fn no_secret_can_reach_the_command_line() {
        // The signature has no password parameter. This test exists so that
        // adding one is a visible, deliberate act rather than a quiet edit.
        let cmd = build_command("h", None, Some("u"), None, None).unwrap();
        assert!(!cmd.contains("password"));
        assert!(!cmd.to_lowercase().contains("pass"));
    }
}
