//! Envelope encryption: the KEK wraps the DEK.
//!
//! Why: changing the master password re-wraps 32 bytes instead of
//! re-encrypting every record and attachment in the vault.

use crate::aead::{self, SealedBlob, NONCE_LEN, TAG_LEN};
use crate::error::CryptoError;
use crate::keys::{DerivedKey, KEY_LEN};

/// Size of the wrapped DEK: 32-byte key plus 16-byte tag.
pub const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN;

/// The DEK, encrypted under the KEK, as stored in the vault header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: [u8; WRAPPED_LEN],
}

impl WrappedKey {
    /// Reconstruct from bytes read out of the header. Length errors here are
    /// how a corrupted or truncated header is caught before decryption.
    pub fn from_parts(nonce: &[u8], ciphertext: &[u8]) -> Result<Self, CryptoError> {
        if nonce.len() != NONCE_LEN || ciphertext.len() != WRAPPED_LEN {
            return Err(CryptoError::Length);
        }
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(nonce);
        let mut c = [0u8; WRAPPED_LEN];
        c.copy_from_slice(ciphertext);
        Ok(WrappedKey {
            nonce: n,
            ciphertext: c,
        })
    }
}

/// Encrypt the DEK under the KEK, binding the header bytes as AAD.
///
/// `header_aad` MUST be produced by the same function used at unwrap time.
/// A mismatch is silent and catastrophic: the vault becomes unopenable.
pub fn wrap_dek(
    kek: &DerivedKey,
    dek: &DerivedKey,
    header_aad: &[u8],
) -> Result<WrappedKey, CryptoError> {
    let sealed = aead::seal(kek, dek.expose(), header_aad)?;
    if sealed.ciphertext.len() != WRAPPED_LEN {
        return Err(CryptoError::Length);
    }
    let mut c = [0u8; WRAPPED_LEN];
    c.copy_from_slice(&sealed.ciphertext);
    Ok(WrappedKey {
        nonce: sealed.nonce,
        ciphertext: c,
    })
}

/// Recover the DEK. Fails if the password was wrong, if the header was
/// modified in any way (including downgraded KDF parameters), or if the
/// wrapped key was tampered with.
pub fn unwrap_dek(
    kek: &DerivedKey,
    wrapped: &WrappedKey,
    header_aad: &[u8],
) -> Result<DerivedKey, CryptoError> {
    let sealed = SealedBlob {
        nonce: wrapped.nonce,
        ciphertext: wrapped.ciphertext.to_vec(),
    };
    let plaintext = aead::open(kek, &sealed, header_aad)?;
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::Length);
    }
    DerivedKey::from_slice(&plaintext)
}
