//! Key material wrappers. Nothing in here ever implements `Debug` in a way
//! that prints bytes, and every buffer is zeroized on drop.

use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Length of every symmetric key in this system.
pub const KEY_LEN: usize = 32;

/// A 32-byte symmetric key held in memory that is wiped on drop.
///
/// Used for both the KEK (derived from the master password) and the DEK
/// (random, wrapped by the KEK). The type does not distinguish between them;
/// the caller does.
#[derive(Clone)]
pub struct DerivedKey(Zeroizing<[u8; KEY_LEN]>);

impl DerivedKey {
    /// Take ownership of raw key bytes. The caller's copy is wiped.
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let key = DerivedKey(Zeroizing::new(bytes));
        // `bytes` was copied into the Zeroizing buffer; wipe the original.
        zeroize::Zeroize::zeroize(&mut bytes);
        key
    }

    /// Build from a slice. Errors if the slice is not exactly `KEY_LEN`.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != KEY_LEN {
            return Err(CryptoError::Length);
        }
        let mut buf = [0u8; KEY_LEN];
        buf.copy_from_slice(slice);
        Ok(Self::from_bytes(buf))
    }

    /// Crate-internal access to the raw bytes. Deliberately not `pub`:
    /// no key material leaves this crate.
    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Explicitly overwrite this key with zeros, now, without waiting for
    /// drop. Called by `VaultSession::lock()` so that wiping is observable
    /// in a test rather than merely promised by the drop impl.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }

    /// Constant-time equality. Used by tests and by password verification
    /// paths so that comparison time does not leak information.
    pub fn ct_eq(&self, other: &DerivedKey) -> bool {
        let a = self.expose();
        let b = other.expose();
        let mut diff: u8 = 0;
        for i in 0..KEY_LEN {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DerivedKey(<redacted>)")
    }
}

impl PartialEq for DerivedKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}
impl Eq for DerivedKey {}
