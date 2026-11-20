//! The vault header: plaintext, but authenticated.
//!
//! ## Why it is authenticated
//!
//! The header must be readable before you have a key, so it cannot be
//! encrypted. An attacker could otherwise edit `memory_kib` down to 8 KiB
//! and brute-force the password cheaply.
//!
//! Mitigation: when the DEK is wrapped, every byte of the header EXCEPT the
//! wrapped DEK itself is passed as AAD. Any edit to the version, the salt,
//! or the cost parameters makes unwrapping fail.
//!
//! `header_aad_bytes` is the single function used on both wrap and unwrap.
//! Never inline it, never write a second version of it: a mismatch between
//! the two sides is silent and makes vaults permanently unopenable.

use ciborium::{de::from_reader, ser::into_writer};
use keyring_crypto::{KdfParams, WrappedKey, SALT_LEN};
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

/// File magic. Eight bytes, NUL-terminated.
pub const MAGIC: &[u8; 8] = b"KEYRING\0";
/// Current on-disk format version.
pub const FORMAT_VERSION: u16 = 1;
/// Byte offset at which the CBOR header starts.
pub const HEADER_OFFSET: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParamsRepr {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    #[serde(with = "serde_bytes_compat")]
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedKeyRepr {
    #[serde(with = "serde_bytes_compat")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes_compat")]
    pub ciphertext: Vec<u8>,
}

/// Minimal byte-vector codec so CBOR encodes these as byte strings rather
/// than arrays of integers. Keeps the header compact and, more importantly,
/// deterministic in length.
mod serde_bytes_compat {
    use serde::{Deserializer, Serializer};

    #[allow(clippy::ptr_arg)] // signature is dictated by serde(with = ...)
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::new();
                while let Some(b) = seq.next_element::<u8>()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        d.deserialize_bytes(V)
    }
}

/// The vault header as stored (Architecture 4.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultHeader {
    pub format_version: u16,
    pub vault_id: String,
    pub created_at: i64,
    pub modified_at: i64,
    pub kdf: KdfParamsRepr,
    /// Excluded from its own AAD.
    pub wrapped_dek: WrappedKeyRepr,
    pub kdf_calibrated_ms: u32,
}

/// Exactly the header minus `wrapped_dek`. Serializing a dedicated struct
/// (rather than blanking a field) makes the exclusion impossible to get
/// wrong by accident.
#[derive(Serialize)]
struct HeaderAad<'a> {
    format_version: u16,
    vault_id: &'a str,
    created_at: i64,
    modified_at: i64,
    kdf: &'a KdfParamsRepr,
    kdf_calibrated_ms: u32,
}

impl VaultHeader {
    pub fn new(
        vault_id: String,
        created_at: i64,
        kdf: &KdfParams,
        wrapped: &WrappedKey,
        kdf_calibrated_ms: u32,
    ) -> Self {
        VaultHeader {
            format_version: FORMAT_VERSION,
            vault_id,
            created_at,
            modified_at: created_at,
            kdf: KdfParamsRepr {
                algorithm: kdf.algorithm.clone(),
                memory_kib: kdf.memory_kib,
                iterations: kdf.iterations,
                parallelism: kdf.parallelism,
                salt: kdf.salt.to_vec(),
            },
            wrapped_dek: WrappedKeyRepr {
                nonce: wrapped.nonce.to_vec(),
                ciphertext: wrapped.ciphertext.to_vec(),
            },
            kdf_calibrated_ms,
        }
    }

    /// Rebuild the crypto-layer KDF parameters from the header.
    pub fn kdf_params(&self) -> Result<KdfParams> {
        if self.kdf.salt.len() != SALT_LEN {
            return Err(VaultError::Corrupt("salt length"));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&self.kdf.salt);
        Ok(KdfParams {
            algorithm: self.kdf.algorithm.clone(),
            memory_kib: self.kdf.memory_kib,
            iterations: self.kdf.iterations,
            parallelism: self.kdf.parallelism,
            salt,
        })
    }

    pub fn wrapped_key(&self) -> Result<WrappedKey> {
        WrappedKey::from_parts(&self.wrapped_dek.nonce, &self.wrapped_dek.ciphertext)
            .map_err(VaultError::from)
    }

    pub fn set_kdf(&mut self, kdf: &KdfParams) {
        self.kdf = KdfParamsRepr {
            algorithm: kdf.algorithm.clone(),
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
            salt: kdf.salt.to_vec(),
        };
    }

    pub fn set_wrapped(&mut self, wrapped: &WrappedKey) {
        self.wrapped_dek = WrappedKeyRepr {
            nonce: wrapped.nonce.to_vec(),
            ciphertext: wrapped.ciphertext.to_vec(),
        };
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(256);
        into_writer(self, &mut out).map_err(|_| VaultError::Cbor)?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        from_reader(bytes).map_err(|_| VaultError::Corrupt("header"))
    }
}

/// THE function. Used identically when wrapping and when unwrapping.
///
/// Layout: magic || format_version (LE) || CBOR(header minus wrapped_dek)
pub fn header_aad_bytes(h: &VaultHeader) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&h.format_version.to_le_bytes());
    let view = HeaderAad {
        format_version: h.format_version,
        vault_id: &h.vault_id,
        created_at: h.created_at,
        modified_at: h.modified_at,
        kdf: &h.kdf,
        kdf_calibrated_ms: h.kdf_calibrated_ms,
    };
    into_writer(&view, &mut out).map_err(|_| VaultError::Cbor)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultHeader {
        VaultHeader {
            format_version: 1,
            vault_id: "1f2e3d4c".into(),
            created_at: 1_700_000_000,
            modified_at: 1_700_000_000,
            kdf: KdfParamsRepr {
                algorithm: "argon2id".into(),
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 4,
                salt: vec![9u8; SALT_LEN],
            },
            wrapped_dek: WrappedKeyRepr {
                nonce: vec![1u8; 24],
                ciphertext: vec![2u8; 48],
            },
            kdf_calibrated_ms: 900,
        }
    }

    #[test]
    fn cbor_roundtrips() {
        let h = sample();
        let bytes = h.to_cbor().unwrap();
        assert_eq!(VaultHeader::from_cbor(&bytes).unwrap(), h);
    }

    #[test]
    fn cbor_is_deterministic() {
        let h = sample();
        assert_eq!(h.to_cbor().unwrap(), h.to_cbor().unwrap());
        assert_eq!(header_aad_bytes(&h).unwrap(), header_aad_bytes(&h).unwrap());
    }

    #[test]
    fn aad_excludes_the_wrapped_dek() {
        let a = sample();
        let mut b = sample();
        b.wrapped_dek.ciphertext = vec![0xFF; 48];
        assert_eq!(header_aad_bytes(&a).unwrap(), header_aad_bytes(&b).unwrap());
    }

    #[test]
    fn aad_covers_every_other_field() {
        let base = header_aad_bytes(&sample()).unwrap();

        let mut m = sample();
        m.kdf.memory_kib = 8;
        assert_ne!(header_aad_bytes(&m).unwrap(), base);

        let mut m = sample();
        m.kdf.iterations = 1;
        assert_ne!(header_aad_bytes(&m).unwrap(), base);

        let mut m = sample();
        m.kdf.salt = vec![0u8; SALT_LEN];
        assert_ne!(header_aad_bytes(&m).unwrap(), base);

        let mut m = sample();
        m.kdf.algorithm = "argon2i".into();
        assert_ne!(header_aad_bytes(&m).unwrap(), base);

        let mut m = sample();
        m.format_version = 2;
        assert_ne!(header_aad_bytes(&m).unwrap(), base);

        let mut m = sample();
        m.vault_id = "other".into();
        assert_ne!(header_aad_bytes(&m).unwrap(), base);

        let mut m = sample();
        m.modified_at += 1;
        assert_ne!(header_aad_bytes(&m).unwrap(), base);
    }
}
