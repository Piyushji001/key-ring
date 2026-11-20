//! Error type for the crypto core.
//!
//! SECURITY: every variant renders the *same* user-facing message. A message
//! that distinguishes "wrong password" from "corrupted data" is a decryption
//! oracle. The variant names exist only for local debugging via `Debug`.

use thiserror::Error;

/// The single error type of this crate.
///
/// `Display` is deliberately uniform and uninformative.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Key derivation failed (bad parameters, allocation failure).
    #[error("cryptographic operation failed")]
    Kdf,
    /// Encryption failed.
    #[error("cryptographic operation failed")]
    Seal,
    /// Decryption or authentication failed. Covers wrong key, wrong AAD,
    /// tampering and truncation. Deliberately indistinguishable.
    #[error("cryptographic operation failed")]
    Open,
    /// An input had the wrong length (nonce, salt, key, wrapped key).
    #[error("cryptographic operation failed")]
    Length,
    /// The operating system random number generator failed.
    #[error("cryptographic operation failed")]
    Rng,
    /// KDF parameters are below the minimum strength policy.
    #[error("cryptographic operation failed")]
    WeakParams,
}

impl CryptoError {
    /// The only string that may ever be shown to a user or written to a log
    /// in response to a crypto failure.
    pub const fn user_message(&self) -> &'static str {
        "Could not unlock this vault."
    }
}
