//! Vault lifecycle commands: the entire IPC surface for Phase 3.
//!
//! Every command here either returns metadata (see `model::dto`) or nothing.
//! None of them return a decrypted value, and none of them accept one.
//!
//! On passwords: they arrive as `String` because the user types them into a
//! webview text field, which is unavoidable. Each command wraps the incoming
//! password in `Zeroizing` on its first line so the buffer is wiped when the
//! command returns, and never logs it, stores it, or returns it.

use std::path::PathBuf;
use std::time::Duration;

use keyring_vault::{db, LockReason, OpenMode, VaultSession, MIN_PASSWORD_LEN};
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

use crate::error::{AppError, ErrorKind, Result};
use crate::model::dto::{
    CalibrationResult, KdfSummary, LockedEvent, PasswordAssessment, VaultStatus,
};
use crate::state::AppState;

/// Build a status snapshot from whatever the session currently is.
fn status_of(state: &AppState) -> VaultStatus {
    let result = state.with_session(|session| {
        let header = session.header();
        let record_count = session
            .conn()
            .ok()
            .and_then(|conn| db::records::count(conn).ok())
            .unwrap_or(0);

        Ok(VaultStatus {
            locked: false,
            read_only: session.mode() == OpenMode::ReadOnly,
            vault_path: Some(session.paths().root.to_string_lossy().into_owned()),
            vault_id: Some(header.vault_id.clone()),
            format_version: Some(header.format_version),
            record_count: record_count.max(0) as u32,
            created_at: Some(header.created_at),
            modified_at: Some(header.modified_at),
            kdf: Some(KdfSummary {
                memory_mib: header.kdf.memory_kib / 1024,
                iterations: header.kdf.iterations,
                parallelism: header.kdf.parallelism,
            }),
        })
    });

    result.unwrap_or_else(|_| VaultStatus::locked())
}

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> VaultStatus {
    status_of(&state)
}

#[tauri::command]
pub fn is_locked(state: State<'_, AppState>) -> bool {
    state.is_locked()
}

#[tauri::command]
pub fn recent_vaults(state: State<'_, AppState>) -> Vec<String> {
    state.recent_vaults()
}

/// The vault the unlock screen should offer. Without this the screen came up
/// blank after a lock, and browsing to the wrong folder then reported "Could
/// not unlock this vault" - which is the bug that started all this.
#[tauri::command]
pub fn last_vault(state: State<'_, AppState>) -> Option<String> {
    state.last_vault()
}

/// Does a vault already exist in this folder? Lets the wizard branch between
/// "create" and "open" without the user having to know.
#[tauri::command]
pub fn vault_exists(path: String) -> bool {
    PathBuf::from(path).join("vault.kr").is_file()
}

/// Strength meter input for the setup wizard. Returns a score, never a reason.
#[tauri::command]
pub fn assess_password(password: String) -> PasswordAssessment {
    let password = Zeroizing::new(password);
    let length = password.chars().count() as u32;
    PasswordAssessment {
        score: keyring_vault::password_strength(&password),
        length,
        meets_minimum: length as usize >= MIN_PASSWORD_LEN,
    }
}

/// Time Argon2id on this machine and pick parameters near `target_ms`.
///
/// This is genuinely slow - it runs several real derivations - so the UI must
/// show a spinner. Do not call it on every keystroke.
#[tauri::command]
pub fn calibrate_kdf(target_ms: u32) -> Result<CalibrationResult> {
    let target = Duration::from_millis(target_ms.clamp(200, 10_000) as u64);
    let params = keyring_vault::calibrate_kdf(target)?;
    let measured = keyring_crypto::kdf::measure(&params)?;

    Ok(CalibrationResult {
        memory_mib: params.memory_kib / 1024,
        iterations: params.iterations,
        parallelism: params.parallelism,
        measured_ms: measured.as_millis().min(u32::MAX as u128) as u32,
        target_ms,
    })
}

/// Create a vault. Irreversible in the sense that matters: if the user forgets
/// this password, the data is gone. The wizard is responsible for having said
/// so before calling this.
#[tauri::command]
pub fn create_vault(
    state: State<'_, AppState>,
    app: AppHandle,
    path: String,
    password: String,
    target_ms: u32,
) -> Result<VaultStatus> {
    let password = Zeroizing::new(password.into_bytes());

    if password.len() < MIN_PASSWORD_LEN {
        return Err(AppError::invalid(format!(
            "The master password must be at least {MIN_PASSWORD_LEN} characters."
        )));
    }

    let root = PathBuf::from(&path);
    if root.join("vault.kr").is_file() {
        return Err(AppError::new(
            ErrorKind::AlreadyExists,
            "A vault already exists in that folder.",
        ));
    }

    let target = Duration::from_millis(target_ms.clamp(200, 10_000) as u64);
    let params = keyring_vault::calibrate_kdf(target)?;

    tracing::info!(
        memory_kib = params.memory_kib,
        iterations = params.iterations,
        "creating vault"
    );

    state.lock_vault(LockReason::Manual)?;
    let session = VaultSession::create(&root, &password, &params, target_ms)?;
    state.set_session(session)?;
    state.save_recents(&app);

    let status = status_of(&state);
    let _ = app.emit("vault-unlocked", &status);
    Ok(status)
}

/// Open an existing vault.
///
/// If another process holds the write lock, this fails with `AlreadyOpen`
/// rather than silently opening read-only - the frontend then offers
/// `open_vault_read_only` as an explicit choice.
#[tauri::command]
pub fn open_vault(
    state: State<'_, AppState>,
    app: AppHandle,
    path: String,
    password: String,
) -> Result<VaultStatus> {
    let password = Zeroizing::new(password.into_bytes());
    let root = PathBuf::from(&path);

    // Release any vault we already hold BEFORE opening the next one. The old
    // session's LockGuard deletes vault.lock when it drops, so opening first
    // and replacing second would delete the lock the new session had just
    // written - leaving the vault apparently unlocked to every other process.
    state.lock_vault(LockReason::Manual)?;

    let session = VaultSession::open(&root, &password, OpenMode::ReadWrite)?;
    state.set_session(session)?;
    state.save_recents(&app);

    let status = status_of(&state);
    tracing::info!(records = status.record_count, "vault unlocked");
    let _ = app.emit("vault-unlocked", &status);
    Ok(status)
}

#[tauri::command]
pub fn open_vault_read_only(
    state: State<'_, AppState>,
    app: AppHandle,
    path: String,
    password: String,
) -> Result<VaultStatus> {
    let password = Zeroizing::new(password.into_bytes());
    let root = PathBuf::from(&path);

    state.lock_vault(LockReason::Manual)?;
    let session = VaultSession::open(&root, &password, OpenMode::ReadOnly)?;
    state.set_session(session)?;
    state.save_recents(&app);

    let status = status_of(&state);
    let _ = app.emit("vault-unlocked", &status);
    Ok(status)
}

/// Wipe key material now. The UI calls this on Ctrl+L and on the lock button.
#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>, app: AppHandle) -> Result<VaultStatus> {
    state.lock_vault(LockReason::Manual)?;
    let _ = app.emit("vault-locked", LockedEvent::Manual);
    Ok(VaultStatus::locked())
}

/// UC-11. Verifies the current password, re-derives over a fresh salt, re-wraps
/// the DEK. Records are untouched, so this costs about one derivation.
#[tauri::command]
pub fn change_master_password(
    state: State<'_, AppState>,
    current: String,
    new_password: String,
) -> Result<()> {
    let current = Zeroizing::new(current.into_bytes());
    let new_password = Zeroizing::new(new_password.into_bytes());

    if new_password.len() < MIN_PASSWORD_LEN {
        return Err(AppError::invalid(format!(
            "The new master password must be at least {MIN_PASSWORD_LEN} characters."
        )));
    }

    state.with_session_mut(|session| {
        session.change_master_password(&current, &new_password, None)?;
        Ok(())
    })
}

/// Records a user interaction, so the Phase 6 idle timer knows the user is
/// still there. Cheap enough to call on keypress.
#[tauri::command]
pub fn touch_activity(state: State<'_, AppState>) {
    state.touch();
}

#[tauri::command]
pub fn idle_seconds(state: State<'_, AppState>) -> u64 {
    state.idle_secs()
}
