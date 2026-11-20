//! All randomness in Keyring comes from the operating system CSPRNG.
//! There is no seeded generator anywhere in this crate.

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

use crate::aead::NONCE_LEN;
use crate::error::CryptoError;
use crate::keys::{DerivedKey, KEY_LEN};

/// Fill a buffer with cryptographically secure random bytes.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    OsRng.try_fill_bytes(buf).map_err(|_| CryptoError::Rng)
}

/// A fresh 24-byte XChaCha20 nonce.
pub fn random_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// A fresh 16-byte KDF salt.
pub fn random_salt() -> Result<[u8; 16], CryptoError> {
    let mut salt = [0u8; 16];
    fill_random(&mut salt)?;
    Ok(salt)
}

/// Generate a new Data Encryption Key. Called exactly once per vault, at
/// creation. The DEK never changes for the life of the vault.
pub fn generate_dek() -> Result<DerivedKey, CryptoError> {
    let mut buf = [0u8; KEY_LEN];
    let result = fill_random(&mut buf);
    match result {
        Ok(()) => Ok(DerivedKey::from_bytes(buf)),
        Err(e) => {
            buf.zeroize();
            Err(e)
        }
    }
}
