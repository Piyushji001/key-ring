//! # keyring-crypto
//!
//! The cryptographic core of Keyring. It knows nothing about records,
//! SQLite, Tauri or the application. It takes bytes and returns bytes.
//!
//! ## Key hierarchy
//!
//! ```text
//! master password
//!   -> Argon2id(salt, m, t, p)        -> KEK   (RAM only, zeroized on lock)
//!   -> XChaCha20-Poly1305 unwrap      -> DEK   (RAM only, zeroized on lock)
//!        -> field values      AAD = record_id | field_name | version
//!        -> attachment blobs  AAD = attachment_id | version
//! ```
//!
//! ## Rules for anyone editing this crate
//!
//! 1. No new dependencies without a written reason.
//! 2. No `unwrap()` or `expect()` outside `#[cfg(test)]`.
//! 3. Every error path returns the same user-facing message. Do not add a
//!    variant whose `Display` distinguishes wrong-password from corruption.
//! 4. Nonces are always random, never counters.
//! 5. Key material never implements a `Debug` that prints bytes and never
//!    leaves this crate except as a `DerivedKey`.

#![forbid(unsafe_code)]
// `unwrap()` and `expect()` are forbidden in library code (Architecture 11).
// Test builds are exempt, which is why this is `cfg_attr(not(test), ...)`.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_debug_implementations)]

pub mod aead;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod random;

pub use aead::{open, seal, SealedBlob, NONCE_LEN, TAG_LEN};
pub use envelope::{unwrap_dek, wrap_dek, WrappedKey, WRAPPED_LEN};
pub use error::CryptoError;
pub use kdf::{
    calibrate_kdf, derive_kek, KdfParams, ALGORITHM_ARGON2ID, DEFAULT_ITERATIONS,
    DEFAULT_MEMORY_KIB, DEFAULT_PARALLELISM, MIN_MEMORY_KIB, SALT_LEN,
};
pub use keys::{DerivedKey, KEY_LEN};
pub use random::{fill_random, generate_dek, random_nonce, random_salt};

/// Cheap KDF parameters for tests and benchmarks ONLY.
///
/// These are far too weak for a real vault. They are safe to ship because
/// `KdfParams::validate_strength()` is enforced by the vault layer at
/// creation time, so a vault can never be created with them.
#[doc(hidden)]
pub fn insecure_test_params() -> KdfParams {
    KdfParams {
        algorithm: ALGORITHM_ARGON2ID.to_string(),
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
        salt: [7u8; SALT_LEN],
    }
}
