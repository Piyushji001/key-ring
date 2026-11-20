//! UC-04. Launch an RDP session without the user typing a password.
//!
//! ## Why not `cmdkey`
//!
//! The obvious implementation is `cmdkey /generic:TERMSRV/host /user:u /pass:p`
//! followed by `mstsc`. It is also indefensible: the password appears in the
//! command line of a child process, which any user on the machine can read
//! from the process list. Task Manager will show it. Process Explorer will show
//! it. It ends up in Sysmon logs and in EDR telemetry.
//!
//! So the credential is staged with `CredWriteW` directly. The password moves
//! from our memory into the Credential Manager through an API call, and never
//! becomes a string in any command line.
//!
//! ## Lifetime of the staged credential
//!
//! `CRED_PERSIST_SESSION` means it dies with the logon session even if we
//! crash. On top of that, a timer deletes it a few seconds after `mstsc` has
//! had a chance to read it. Both matter: the timer is the normal path, the
//! persistence flag is what saves you when the normal path does not run.
//!
//! Verify with `rundll32.exe keymgr.dll,KRShowKeyMgr` or Credential Manager in
//! Control Panel - after a launch, `TERMSRV/<host>` must not be listed.

use std::time::Duration;

use crate::error::{AppError, Result};

/// How long `mstsc` gets to read the credential before we delete it. Long
/// enough for a slow machine, short enough that the window is small.
const CREDENTIAL_LIFETIME: Duration = Duration::from_secs(12);

#[cfg(windows)]
mod win {
    #![allow(unsafe_code)] // CredWriteW takes a struct of raw pointers. Every
                           // buffer here outlives the call it is passed to.

    use windows::core::PWSTR;
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::Security::Credentials::{
        CredDeleteW, CredWriteW, CREDENTIALW, CRED_PERSIST_SESSION, CRED_TYPE_DOMAIN_PASSWORD,
    };

    use crate::error::{AppError, Result};

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Stage a credential for `TERMSRV/<host>`, which is the target name the
    /// Remote Desktop client looks up.
    pub fn stage(target: &str, username: &str, password: &str) -> Result<()> {
        let mut target_w = wide(target);
        let mut user_w = wide(username);
        // The blob is the UTF-16 password WITHOUT its NUL terminator.
        let password_utf16: Vec<u16> = password.encode_utf16().collect();
        let mut blob: Vec<u8> = password_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();

        let credential = CREDENTIALW {
            Flags: Default::default(),
            Type: CRED_TYPE_DOMAIN_PASSWORD,
            TargetName: PWSTR(target_w.as_mut_ptr()),
            Comment: PWSTR::null(),
            LastWritten: FILETIME::default(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_SESSION,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(user_w.as_mut_ptr()),
        };

        let result = unsafe { CredWriteW(&credential, 0) };

        // Wipe our copy of the password bytes regardless of the outcome.
        use zeroize::Zeroize;
        blob.zeroize();

        result.map_err(|_| AppError::internal("CredWriteW failed"))
    }

    pub fn unstage(target: &str) -> Result<()> {
        let target_w = wide(target);
        unsafe {
            CredDeleteW(
                windows::core::PCWSTR(target_w.as_ptr()),
                CRED_TYPE_DOMAIN_PASSWORD,
                0,
            )
        }
        .map_err(|_| AppError::internal("CredDeleteW failed"))
    }
}

#[cfg(not(windows))]
mod win {
    use crate::error::{AppError, Result};

    pub fn stage(_t: &str, _u: &str, _p: &str) -> Result<()> {
        Err(AppError::internal("RDP is Windows-only"))
    }
    pub fn unstage(_t: &str) -> Result<()> {
        Ok(())
    }
}

/// Where the credential is filed. `mstsc` looks up exactly this name.
pub fn target_name(host: &str) -> String {
    format!("TERMSRV/{}", host.trim())
}

/// Stage the credential, start `mstsc`, and schedule the credential's removal.
///
/// Returns the target name so the caller can report what was staged. The
/// password is consumed here and never returned.
pub fn launch(host: &str, port: Option<u16>, username: &str, password: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(AppError::invalid("This record has no host to connect to."));
    }
    // A host containing a quote or a switch would be interpreted by mstsc.
    if host.contains(['"', '\'', ' ', '\n', '\r']) || host.starts_with('/') {
        return Err(AppError::invalid("That hostname contains illegal characters."));
    }

    let target = target_name(host);
    win::stage(&target, username, password)?;

    let address = match port {
        Some(p) if p != 3389 => format!("{host}:{p}"),
        _ => host.to_string(),
    };

    // Only the address is ever on the command line.
    let spawned = std::process::Command::new("mstsc.exe")
        .arg(format!("/v:{address}"))
        .spawn();

    if let Err(e) = spawned {
        // Do not leave a credential behind for a session that never started.
        let _ = win::unstage(&target);
        tracing::error!(error = %e, "mstsc.exe did not start");
        return Err(AppError::internal("Remote Desktop did not start"));
    }

    tracing::info!(host, "RDP session launched");

    let target_for_cleanup = target.clone();
    std::thread::spawn(move || {
        std::thread::sleep(CREDENTIAL_LIFETIME);
        match win::unstage(&target_for_cleanup) {
            Ok(()) => tracing::info!(target = %target_for_cleanup, "staged credential removed"),
            Err(_) => tracing::warn!(
                target = %target_for_cleanup,
                "staged credential could not be removed; it expires with this logon session"
            ),
        }
    });

    Ok(target)
}

/// Remove a staged credential immediately, for the "clean up now" action.
pub fn clear_staged(host: &str) -> Result<()> {
    win::unstage(&target_name(host))
}
