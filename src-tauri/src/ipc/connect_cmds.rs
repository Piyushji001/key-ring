//! Phase 7.5 — one-click connect.
//!
//! The rule from `actions/mod.rs` still holds and is the reason this module
//! looks the way it does: a secret is gathered inside `with_session`, handed
//! to an action, and dropped. Nothing here returns a credential, and nothing
//! here puts one on a command line.
//!
//! Two things are worth understanding before editing this file.
//!
//! **The askpass channel must outlive the command.** `connect::ssh` returns a
//! channel that the helper process reads the password from exactly once. If we
//! dropped it when this function returned, the pipe would close before `ssh`
//! got round to asking. It is therefore parked in `AppState` until it is either
//! consumed or times out. That is not a leak — it is a one-shot pipe with a
//! deadline, and it is a great deal safer than the alternatives.
//!
//! **Cloud credentials never touch a command line, only a child environment
//! block.** A process environment is readable by the same user, which is the
//! same trust boundary as the unlocked vault itself. A command line is readable
//! by every EDR agent and every Task Manager column. That distinction is the
//! whole design (decision D-33, applied again here as D-38).

use std::time::Duration;

use keyring_vault::db;
use rusqlite;
use tauri::State;
use zeroize::Zeroizing;

use crate::actions::{
    askpass,
    cloud::{CloudCredentials, CloudProvider},
    connect::{self, ConnectResult, SshTarget},
    terminal::TerminalKind,
};
use crate::error::{AppError, Result};
use crate::state::AppState;

/// Fallback lifetime for an extracted private key when the vault has no
/// setting. Short, because the key exists on disk for this whole window.
const DEFAULT_KEY_TTL_SECS: u64 = 120;

/// Read a non-secret field, or an empty string.
fn plain(conn: &rusqlite::Connection, record_id: &str, name: &str) -> Result<String> {
    Ok(db::fields::get(conn, record_id, name)?
        .and_then(|f| f.plain_value)
        .unwrap_or_default())
}

/// Read a secret field as text, or `None` when it is absent or empty.
///
/// A missing secret is not an error here. An SSH record may legitimately have
/// a key and no password, or a password and no key.
fn secret_text(
    session: &keyring_vault::VaultSession,
    record_id: &str,
    name: &str,
) -> Option<Zeroizing<String>> {
    let bytes = session.open_secret(record_id, name).ok()?;
    let text = String::from_utf8(bytes.to_vec()).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(Zeroizing::new(text))
    }
}

fn terminal_preference(conn: &rusqlite::Connection) -> TerminalKind {
    match db::settings::get(conn, db::settings::TERMINAL_PREFERENCE) {
        Ok(Some(v)) => TerminalKind::parse(&v),
        _ => TerminalKind::Auto,
    }
}

fn askpass_enabled(conn: &rusqlite::Connection) -> bool {
    db::settings::get_i64(conn, db::settings::SSH_ASKPASS_ENABLED, 1) != 0
}

fn key_ttl(conn: &rusqlite::Connection) -> Duration {
    let secs = db::settings::get_i64(
        conn,
        db::settings::TEMPFILE_TTL_SECS,
        DEFAULT_KEY_TTL_SECS as i64,
    );
    Duration::from_secs(secs.clamp(15, 3600) as u64)
}

fn cloud_ttl(conn: &rusqlite::Connection) -> Duration {
    let secs = db::settings::get_i64(conn, db::settings::CLOUD_SHELL_TTL_SECS, 3600);
    Duration::from_secs(secs.clamp(60, 43_200) as u64)
}

// ---------------------------------------------------------------------- SSH

/// UC-03 extended: open a terminal already connected to the host.
///
/// `attachment_id` selects which stored key to use. When it is `None` and the
/// record has exactly one attachment, that one is used — a record with a single
/// PEM file attached is overwhelmingly the common case, and making the user
/// pick from a list of one is friction for its own sake. With several
/// attachments and no choice made, we do not guess.
#[tauri::command]
pub fn ssh_connect(
    state: State<'_, AppState>,
    record_id: String,
    attachment_id: Option<String>,
) -> Result<ConnectResult> {
    let (target, preference, ttl, askpass_on) = state.with_session(|session| {
        let conn = session.conn()?;

        let host = plain(conn, &record_id, "host")?;
        if host.trim().is_empty() {
            return Err(AppError::invalid("This record has no host."));
        }

        let port = plain(conn, &record_id, "port")?.parse::<u16>().ok();
        let username = {
            let u = plain(conn, &record_id, "username")?;
            if u.is_empty() {
                None
            } else {
                Some(u)
            }
        };
        let jump_host = {
            let j = plain(conn, &record_id, "jump_host")?;
            if j.is_empty() {
                None
            } else {
                Some(j)
            }
        };

        // Resolve the key attachment.
        let attachments = db::attachments::list_for_record(conn, &record_id)?;
        let chosen = match &attachment_id {
            Some(id) => attachments.iter().find(|a| &a.id == id),
            None if attachments.len() == 1 => attachments.first(),
            None => None,
        };

        let (private_key, key_filename) = match chosen {
            Some(a) => (
                Some(session.open_attachment(&a.id)?),
                Some(a.filename.clone()),
            ),
            None => (None, None),
        };

        // Only reach for the password when there is no key. Asking the vault
        // to decrypt a secret we are not going to use is pointless work and a
        // pointless plaintext buffer.
        let password = if private_key.is_none() {
            secret_text(session, &record_id, "password")
        } else {
            None
        };

        Ok((
            SshTarget {
                host,
                port,
                username,
                jump_host,
                private_key,
                key_filename,
                password,
            },
            terminal_preference(conn),
            key_ttl(conn),
            askpass_enabled(conn),
        ))
    })?;

    let (result, channel) = connect::ssh(target, preference, state.temp_files(), ttl, askpass_on)?;

    // Park the channel so the helper can still read from it. It closes itself
    // after one read or at its own deadline, whichever comes first.
    if let Some(channel) = channel {
        state.park_askpass(channel);
    }

    let _ = state.with_session_mut(|s| Ok(s.mark_used(&record_id)?));
    state.log_activity(keyring_vault::LogAction::SshLaunched, Some(&record_id), None);
    state.rebuild_index();

    Ok(result)
}

// -------------------------------------------------------------------- Cloud

/// Gather the credential set for a provider from whatever the record holds.
///
/// Absent optional values are simply not inserted; `cloud::build_launch` is
/// the single place that decides what is mandatory, so the error messages stay
/// in one file rather than being duplicated here.
fn gather_cloud_credentials(
    session: &keyring_vault::VaultSession,
    record_id: &str,
    provider: CloudProvider,
) -> Result<CloudCredentials> {
    let conn = session.conn()?;
    let mut creds = CloudCredentials::default();

    let put_plain = |creds: &mut CloudCredentials, field: &str, key: &str| -> Result<()> {
        let v = plain(conn, record_id, field)?;
        if !v.is_empty() {
            creds.insert(key, v);
        }
        Ok(())
    };

    let put_secret = |creds: &mut CloudCredentials, field: &str, key: &str| {
        if let Some(v) = secret_text(session, record_id, field) {
            creds.insert(key, v.to_string());
        }
    };

    match provider {
        CloudProvider::Aws => {
            put_plain(&mut creds, "access_key_id", "access_key_id")?;
            put_plain(&mut creds, "region", "region")?;
            put_secret(&mut creds, "secret_access_key", "secret_access_key");
            put_secret(&mut creds, "session_token", "session_token");
        }
        CloudProvider::Gcp => {
            put_plain(&mut creds, "project_id", "project_id")?;
            // The service account key is an attachment on this type.
            if let Some(json) = first_attachment_text(session, record_id, &["json"])? {
                creds.insert("service_account_json", json.to_string());
            }
        }
        CloudProvider::Azure => {
            put_plain(&mut creds, "client_id", "client_id")?;
            put_plain(&mut creds, "tenant_id", "tenant_id")?;
            put_plain(&mut creds, "subscription_id", "subscription_id")?;
            put_secret(&mut creds, "client_secret", "client_secret");
        }
        CloudProvider::Kubernetes => {
            put_plain(&mut creds, "namespace", "namespace")?;
            put_plain(&mut creds, "cluster", "cluster")?;
            if let Some(cfg) =
                first_attachment_text(session, record_id, &["yaml", "yml", "conf", "kubeconfig"])?
            {
                creds.insert("kubeconfig", cfg.to_string());
            }
        }
    }

    Ok(creds)
}

/// Pull the first attachment whose extension matches, as UTF-8 text.
///
/// Falls back to the only attachment when there is exactly one, for the same
/// reason `ssh_connect` does.
fn first_attachment_text(
    session: &keyring_vault::VaultSession,
    record_id: &str,
    extensions: &[&str],
) -> Result<Option<Zeroizing<String>>> {
    let conn = session.conn()?;
    let attachments = db::attachments::list_for_record(conn, record_id)?;

    let matched = attachments
        .iter()
        .find(|a| {
            let lower = a.filename.to_ascii_lowercase();
            extensions.iter().any(|e| lower.ends_with(&format!(".{e}")))
        })
        .or(if attachments.len() == 1 {
            attachments.first()
        } else {
            None
        });

    let Some(a) = matched else {
        return Ok(None);
    };

    let bytes = session.open_attachment(&a.id)?;
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| AppError::invalid("That attachment is not a text credential file."))?;
    Ok(Some(Zeroizing::new(text)))
}

/// Open a terminal with cloud credentials in its environment.
///
/// `provider` overrides the record's own `provider` field, which lets a record
/// that stores, say, both an AWS key and a kubeconfig be launched either way.
#[tauri::command]
pub fn cloud_connect(
    state: State<'_, AppState>,
    record_id: String,
    provider: Option<String>,
) -> Result<ConnectResult> {
    let (provider, creds, preference, ttl) = state.with_session(|session| {
        let conn = session.conn()?;

        let name = match &provider {
            Some(p) => p.clone(),
            None => plain(conn, &record_id, "provider")?,
        };
        let provider = CloudProvider::parse(&name).ok_or_else(|| {
            AppError::invalid(
                "Set this record's Provider field to aws, gcp, azure or kubernetes first.",
            )
        })?;

        let creds = gather_cloud_credentials(session, &record_id, provider)?;

        Ok((provider, creds, terminal_preference(conn), cloud_ttl(conn)))
    })?;

    let result = connect::cloud_shell(provider, creds, preference, state.temp_files(), ttl)?;

    let _ = state.with_session_mut(|s| Ok(s.mark_used(&record_id)?));
    state.log_activity(
        keyring_vault::LogAction::CloudShellOpened,
        Some(&record_id),
        Some(provider.as_str()),
    );
    state.rebuild_index();

    Ok(result)
}

// ------------------------------------------------------------- Capabilities

/// What the UI needs to know before it draws a Connect button.
///
/// The point is to fail *visibly* and early. A greyed-out button with a reason
/// is honest; a button that launches a terminal which then asks for a password
/// Keyring was supposed to supply is not.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectCapabilities {
    pub windows_terminal: bool,
    pub powershell: bool,
    pub ssh_client: bool,
    pub askpass_helper: bool,
    /// Populated when something is missing, in the user's language.
    pub notes: Vec<String>,
}

#[tauri::command]
pub fn connect_capabilities() -> ConnectCapabilities {
    let windows_terminal = crate::actions::terminal::find_windows_terminal().is_some();
    let powershell = crate::actions::terminal::find_powershell().is_some();
    let ssh_client = askpass::which_ssh().is_some();
    let askpass_helper = askpass::is_available();

    let mut notes = Vec::new();
    if !windows_terminal && powershell {
        notes.push(
            "Windows Terminal was not found, so sessions will open in PowerShell.".to_string(),
        );
    }
    if !windows_terminal && !powershell {
        notes.push("No terminal was found. One-click connect is unavailable.".to_string());
    }
    if !ssh_client {
        notes.push(
            "The Windows OpenSSH client is not installed. Add it from \
             Settings → Apps → Optional features."
                .to_string(),
        );
    }
    if ssh_client && !askpass_helper {
        notes.push(
            "The password helper is unavailable, so ssh will prompt for passwords. \
             Key-based connections are unaffected."
                .to_string(),
        );
    }

    ConnectCapabilities {
        windows_terminal,
        powershell,
        ssh_client,
        askpass_helper,
        notes,
    }
}

/// Drop any parked askpass channel immediately.
///
/// Called when the user cancels, and on lock. The channel expires on its own,
/// but "on its own" is not a thing to rely on when the user has just told us
/// they are done.
#[tauri::command]
pub fn cancel_askpass(state: State<'_, AppState>) {
    state.clear_askpass();
}
