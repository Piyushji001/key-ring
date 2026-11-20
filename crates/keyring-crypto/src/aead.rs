//! Authenticated encryption with XChaCha20-Poly1305.
//!
//! Chosen over AES-GCM because the 24-byte nonce can be generated randomly
//! with negligible collision probability, which removes counter management
//! (a common source of catastrophic bugs) from the design entirely.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::DerivedKey;
use crate::random;

/// XChaCha20 nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;

/// A nonce plus the ciphertext (which has the 16-byte tag appended).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

impl SealedBlob {
    /// Reconstruct from parts read out of storage.
    pub fn from_parts(nonce: &[u8], ciphertext: &[u8]) -> Result<Self, CryptoError> {
        if nonce.len() != NONCE_LEN || ciphertext.len() < TAG_LEN {
            return Err(CryptoError::Length);
        }
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(nonce);
        Ok(SealedBlob {
            nonce: n,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// Encrypt `plaintext` under `key`, binding `aad` to the result.
///
/// A fresh random nonce is generated for every call. Sealing the same
/// plaintext twice therefore produces different ciphertext.
pub fn seal(key: &DerivedKey, plaintext: &[u8], aad: &[u8]) -> Result<SealedBlob, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    let nonce_bytes = random::random_nonce()?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Seal)?;

    Ok(SealedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt and authenticate. Any modification to the ciphertext, the tag,
/// the nonce or the AAD causes this to fail rather than return garbage.
///
/// The plaintext is returned in a buffer that wipes itself on drop.
pub fn open(
    key: &DerivedKey,
    sealed: &SealedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Explicit length guard so a truncated blob is an error, never a panic.
    if sealed.ciphertext.len() < TAG_LEN {
        return Err(CryptoError::Open);
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    let nonce = XNonce::from_slice(&sealed.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Open)?;

    Ok(Zeroizing::new(plaintext))
}
