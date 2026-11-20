//! Phase 6 commands: connect to things, rather than copy strings about them.
//!
//! Same discipline as `action_cmds`: every secret used here is decrypted,
//! consumed and dropped inside Rust. The RDP password goes from the vault into
//! the Credential Manager without ever being a JavaScript value or a command
//! line argument.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keyring_vault::db;
use rusqlite;
use tauri::State;
use zeroize::Zeroizing;

use crate::actions::{rdp, ssh, totp};
use crate::error::{AppError, Result};
use crate::model::dto::{ExtractResult, LaunchResult, SshCommand, TotpCode};
use crate::state::AppState;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read a non-secret field, or an empty string.
fn plain(
    conn: &rusqlite::Connection,
    record_id: &str,
    name: &str,
) -> Result<String> {
    Ok(db::fields::get(conn, record_id, name)?
        .and_then(|f| f.plain_value)
        .unwrap_or_default())
}

// ---------------------------------------------------------------------- RDP

/// UC-04. Stage the credential, launch `mstsc`, schedule cleanup.
#[tauri::command]
pub fn launch_rdp(state: State<'_, AppState>, record_id: String) -> Result<LaunchResult> {
    let target = state.with_session(|session| {
        let conn = session.conn()?;
        let host = plain(conn, &record_id, "host")?;
        let port = plain(conn, &record_id, "port")?.parse::<u16>().ok();
        let user = plain(conn, &record_id, "username")?;
        let domain = plain(conn, &record_id, "domain")?;

        if host.is_empty() {
            return Err(AppError::invalid("This record has no host."));
        }

        let principal = if domain.is_empty() {
            user
        } else {
            format!("{domain}\\{user}")
        };

        let password = Zeroizing::new(
            String::from_utf8(session.open_secret(&record_id, "password")?.to_vec())
                .map_err(|_| AppError::invalid("The stored password is not text."))?,
        );

        rdp::launch(&host, port, &principal, &password)
        // `password` drops here and wipes.
    })?;

    let _ = state.with_session_mut(|s| Ok(s.mark_used(&record_id)?));
    state.rebuild_index();

    Ok(LaunchResult {
        launched: true,
        detail: format!(
            "Remote Desktop is starting. The staged credential ({target}) is removed \
             automatically a few seconds after launch."
        ),
    })
}

/// Remove a staged credential immediately.
#[tauri::command]
pub fn clear_rdp_credential(state: State<'_, AppState>, record_id: String) -> Result<()> {
    let host = state.with_session(|s| plain(s.conn()?, &record_id, "host"))?;
    rdp::clear_staged(&host)
}

// ---------------------------------------------------------------------- SSH

/// UC-03. Build the command and put it on the clipboard.
///
/// No password is included, ever - it would land in shell history and in the
/// process list of every command the user then runs.
#[tauri::command]
pub fn ssh_command(state: State<'_, AppState>, record_id: String) -> Result<SshCommand> {
    let command = state.with_session(|session| {
        let conn = session.conn()?;
        let host = plain(conn, &record_id, "host")?;
        let port = plain(conn, &record_id, "port")?.parse::<u16>().ok();
        let user = plain(conn, &record_id, "username")?;
        let jump = plain(conn, &record_id, "jump_host")?;

        ssh::build_command(
            &host,
            port,
            Some(&user).filter(|u| !u.is_empty()).map(|u| u.as_str()),
            Some(&jump).filter(|j| !j.is_empty()).map(|j| j.as_str()),
            None,
        )
    })?;

    crate::actions::clipboard::write(&command)?;
    let _ = state.with_session_mut(|s| Ok(s.mark_used(&record_id)?));

    Ok(SshCommand {
        command: command.clone(),
        copied: true,
    })
}

/// Extract a private key attachment to a temp file with an ACL that Windows
/// OpenSSH will accept, and return the path.
#[tauri::command]
pub fn extract_ssh_key(
    state: State<'_, AppState>,
    record_id: String,
    attachment_id: String,
    ttl_seconds: Option<u64>,
) -> Result<ExtractResult> {
    let (filename, data) = state.with_session(|session| {
        let conn = session.conn()?;
        let filename: String = conn.query_row(
            "SELECT filename FROM attachments WHERE id = ?1",
            [&attachment_id],
            |r| r.get(0),
        ).map_err(|e| AppError::from(keyring_vault::VaultError::Db(e)))?;
        Ok((filename, session.open_attachment(&attachment_id)?))
    })?;

    let ttl = Duration::from_secs(ttl_seconds.unwrap_or(300));
    let path = state.temp_files().extract(&filename, &data, ttl)?;
    drop(data);

    // Without this, OpenSSH rejects the key as "too open" and the whole
    // feature is useless.
    ssh::restrict_to_current_user(&path)?;

    let path_string = path.to_string_lossy().into_owned();
    let _ = state.with_session_mut(|s| Ok(s.mark_used(&record_id)?));

    Ok(ExtractResult {
        path: path_string,
        filename,
        expires_in_seconds: ttl.as_secs() as u32,
    })
}

/// The full command including `-i <extracted key>`, for the common case of a
/// key-authenticated host.
#[tauri::command]
pub fn ssh_command_with_key(
    state: State<'_, AppState>,
    record_id: String,
    attachment_id: String,
) -> Result<SshCommand> {
    let extracted = extract_ssh_key(state.clone(), record_id.clone(), attachment_id, None)?;

    let command = state.with_session(|session| {
        let conn = session.conn()?;
        let host = plain(conn, &record_id, "host")?;
        let port = plain(conn, &record_id, "port")?.parse::<u16>().ok();
        let user = plain(conn, &record_id, "username")?;
        let jump = plain(conn, &record_id, "jump_host")?;

        ssh::build_command(
            &host,
            port,
            Some(&user).filter(|u| !u.is_empty()).map(|u| u.as_str()),
            Some(&jump).filter(|j| !j.is_empty()).map(|j| j.as_str()),
            Some(std::path::Path::new(&extracted.path)),
        )
    })?;

    crate::actions::clipboard::write(&command)?;

    Ok(SshCommand {
        command,
        copied: true,
    })
}

// --------------------------------------------------------------------- TOTP

/// FR-7.5. Generate the current code and say how long it lives.
///
/// The code is returned to the frontend, which is unavoidable - a TOTP code
/// exists to be read and typed. It is not a stored secret: it is derived, it is
/// six digits, and it is worthless in thirty seconds. The *seed* never leaves
/// Rust, which is the part that matters.
#[tauri::command]
pub fn totp_code(state: State<'_, AppState>, record_id: String) -> Result<TotpCode> {
    let (code, remaining, digits) = state.with_session(|session| {
        let seed = session.open_secret(&record_id, "totp_secret")?;
        let text = std::str::from_utf8(&seed)
            .map_err(|_| AppError::invalid("The stored TOTP secret is not text."))?;

        let config = totp::parse_secret(text)?;
        let now = now_unix();
        Ok((
            totp::generate_at_time(&config, now)?,
            totp::seconds_remaining(&config, now),
            config.digits,
        ))
    })?;

    Ok(TotpCode {
        code,
        seconds_remaining: remaining,
        digits,
    })
}

/// Generate and copy in one step, so the overlay can do it with one keystroke.
#[tauri::command]
pub fn copy_totp(state: State<'_, AppState>, record_id: String) -> Result<TotpCode> {
    let result = totp_code(state.clone(), record_id.clone())?;
    crate::actions::clipboard::write(&result.code)?;
    let _ = state.with_session_mut(|s| Ok(s.mark_used(&record_id)?));
    Ok(result)
}

/// Validate a secret at the point the user pastes it, rather than letting them
/// discover next month that it was never going to work.
#[tauri::command]
pub fn validate_totp_secret(secret: String) -> Result<TotpCode> {
    let config = totp::parse_secret(&secret)?;
    let now = now_unix();
    Ok(TotpCode {
        code: totp::generate_at_time(&config, now)?,
        seconds_remaining: totp::seconds_remaining(&config, now),
        digits: config.digits,
    })
}
