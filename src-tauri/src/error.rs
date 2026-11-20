//! IPC-safe errors.
//!
//! Two rules, both inherited from the crypto core:
//!
//! 1. Nothing that reaches the frontend distinguishes a wrong password from a
//!    corrupted vault. Both are `ErrorKind::Unlock` with the same message.
//! 2. No error ever carries key material, a plaintext value, or a crypto
//!    library's internal detail.
//!
//! `AppError` is `Serialize` because Tauri commands return it directly to
//! JavaScript. It is deliberately NOT built from `Display` on the underlying
//! error - every message here is written by hand.

use keyring_vault::VaultError;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The vault is locked and the requested operation needs it open.
    Locked,
    /// Unlocking failed. Wrong password, tampered header, corrupt file - the
    /// frontend cannot tell which, and neither can the user.
    Unlock,
    /// Another process holds the write lock.
    AlreadyOpen,
    /// The session is read-only.
    ReadOnly,
    /// A vault already exists where one was going to be created.
    AlreadyExists,
    /// Requested record or field does not exist.
    NotFound,
    /// The caller passed something invalid. Message is safe to display.
    Invalid,
    /// Filesystem problem.
    Io,
    /// Bug on our side. Logged locally, generic to the user.
    Internal,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub kind: ErrorKind,
    pub message: String,
}

impl AppError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        AppError {
            kind,
            message: message.into(),
        }
    }

    pub fn locked() -> Self {
        Self::new(ErrorKind::Locked, "The vault is locked.")
    }

    /// The only message shown for any failure to unlock.
    pub fn unlock() -> Self {
        Self::new(ErrorKind::Unlock, "Could not unlock this vault.")
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Invalid, message)
    }

    pub fn internal(context: &str) -> Self {
        // The context goes to the local log, never to the user.
        tracing::error!(context, "internal error");
        Self::new(ErrorKind::Internal, "Something went wrong inside Keyring.")
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

impl From<VaultError> for AppError {
    fn from(e: VaultError) -> Self {
        match e {
            // Everything that could be a wrong password collapses to one
            // indistinguishable case. Do not "improve" this.
            VaultError::Crypto(_) | VaultError::Corrupt(_) => AppError::unlock(),

            // NOT collapsed into the unlock message. Whether a file exists
            // reveals nothing about the password, and hiding it turned "wrong
            // folder" into an unfalsifiable password failure.
            VaultError::NoVaultHere => AppError::new(
                ErrorKind::NotFound,
                "There is no vault in that folder. Check the path, or create one.",
            ),

            VaultError::Locked => AppError::locked(),
            VaultError::ReadOnly => AppError::new(
                ErrorKind::ReadOnly,
                "This vault is open read-only, so it cannot be changed.",
            ),
            VaultError::AlreadyOpen { pid } => AppError::new(
                ErrorKind::AlreadyOpen,
                format!("This vault is already open in another Keyring window (process {pid})."),
            ),
            VaultError::AlreadyExists => AppError::new(
                ErrorKind::AlreadyExists,
                "A vault already exists in that folder.",
            ),
            VaultError::UnsupportedFormat(v) => AppError::new(
                ErrorKind::Invalid,
                format!("This vault was written by a newer version of Keyring (format {v})."),
            ),
            VaultError::NoSuchRecord(_) => {
                AppError::new(ErrorKind::NotFound, "That record no longer exists.")
            }
            VaultError::NoSuchField(_, _) => {
                AppError::new(ErrorKind::NotFound, "That field no longer exists.")
            }
            VaultError::NotSecret => {
                AppError::invalid("That field does not hold an encrypted value.")
            }
            VaultError::PasswordTooShort(n) => AppError::invalid(format!(
                "The master password must be at least {n} characters."
            )),
            VaultError::Invalid(m) => AppError::invalid(m),

            // Storage and filesystem detail stays in the log.
            VaultError::Db(e) => {
                tracing::error!(error = %e, "database error");
                AppError::new(ErrorKind::Io, "Keyring could not read or write the vault.")
            }
            VaultError::Io(e) => {
                tracing::error!(error = %e, "io error");
                AppError::new(ErrorKind::Io, "Keyring could not read or write that file.")
            }
            VaultError::Cbor => AppError::unlock(),
        }
    }
}

impl From<keyring_crypto::CryptoError> for AppError {
    fn from(_: keyring_crypto::CryptoError) -> Self {
        AppError::unlock()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
