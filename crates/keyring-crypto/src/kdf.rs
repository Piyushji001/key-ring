//! Argon2id key derivation and calibration.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::{DerivedKey, KEY_LEN};
use crate::random;

/// KDF salt length in bytes.
pub const SALT_LEN: usize = 16;
/// Default memory cost: 256 MiB.
pub const DEFAULT_MEMORY_KIB: u32 = 256 * 1024;
/// Policy floor for memory cost: 64 MiB. Enforced at vault creation.
pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
/// Ceiling used by the calibrator so a slow machine cannot pick 4 GiB.
pub const MAX_MEMORY_KIB: u32 = 1024 * 1024;
/// Default time cost.
pub const DEFAULT_ITERATIONS: u32 = 3;
/// Default lane count.
pub const DEFAULT_PARALLELISM: u32 = 4;
/// The only algorithm identifier accepted in a v1 header.
pub const ALGORITHM_ARGON2ID: &str = "argon2id";

/// Parameters for deriving the KEK from the master password.
///
/// DEVIATION from Architecture 3.5: the salt lives inside `KdfParams` rather
/// than being a separate argument to `derive_kek`. Architecture 4.3 already
/// places the salt inside the header's `kdf` object, so this keeps a single
/// source of truth and makes it impossible to pair a salt with the wrong
/// parameter set. Recorded in the decision log as D-1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Default parameters with a freshly generated random salt.
    pub fn new_default() -> Result<Self, CryptoError> {
        Ok(KdfParams {
            algorithm: ALGORITHM_ARGON2ID.to_string(),
            memory_kib: DEFAULT_MEMORY_KIB,
            iterations: DEFAULT_ITERATIONS,
            parallelism: DEFAULT_PARALLELISM,
            salt: random::random_salt()?,
        })
    }

    /// Same parameters, brand new salt. Used when changing the master
    /// password so the new KEK is derived over fresh salt.
    pub fn with_new_salt(&self) -> Result<Self, CryptoError> {
        Ok(KdfParams {
            salt: random::random_salt()?,
            ..self.clone()
        })
    }

    /// Policy check applied when creating a vault or accepting calibrated
    /// parameters. Not applied inside `derive_kek`, so that tests may use
    /// cheap parameters.
    pub fn validate_strength(&self) -> Result<(), CryptoError> {
        if self.algorithm != ALGORITHM_ARGON2ID
            || self.memory_kib < MIN_MEMORY_KIB
            || self.iterations < 2
            || self.parallelism < 1
        {
            return Err(CryptoError::WeakParams);
        }
        Ok(())
    }

    fn to_argon2(&self) -> Result<Argon2<'static>, CryptoError> {
        if self.algorithm != ALGORITHM_ARGON2ID {
            return Err(CryptoError::Kdf);
        }
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| CryptoError::Kdf)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Derive the Key Encryption Key from the master password.
///
/// Deterministic: the same password and the same parameters always produce
/// the same key. That is what makes unlocking possible.
pub fn derive_kek(password: &[u8], params: &KdfParams) -> Result<DerivedKey, CryptoError> {
    let argon = params.to_argon2()?;
    let mut out = [0u8; KEY_LEN];
    match argon.hash_password_into(password, &params.salt, &mut out) {
        Ok(()) => Ok(DerivedKey::from_bytes(out)),
        Err(_) => {
            out.zeroize();
            Err(CryptoError::Kdf)
        }
    }
}

/// Measure how long one derivation takes with the given parameters.
pub fn measure(params: &KdfParams) -> Result<Duration, CryptoError> {
    let start = Instant::now();
    let key = derive_kek(b"calibration-probe-password", params)?;
    let elapsed = start.elapsed();
    drop(key);
    Ok(elapsed)
}

/// Pick memory cost so that unlocking takes roughly `target` on this machine.
///
/// Iterations and parallelism stay at their defaults; only memory is scaled,
/// because memory hardness is what makes GPU attacks expensive.
///
/// DEVIATION from Architecture 3.5: returns `Result` rather than a bare
/// `KdfParams`, because salt generation can fail. Recorded as D-2.
pub fn calibrate_kdf(target: Duration) -> Result<KdfParams, CryptoError> {
    let mut params = KdfParams {
        algorithm: ALGORITHM_ARGON2ID.to_string(),
        memory_kib: MIN_MEMORY_KIB,
        iterations: DEFAULT_ITERATIONS,
        parallelism: DEFAULT_PARALLELISM,
        salt: random::random_salt()?,
    };

    // Two scaling passes. Argon2's cost is close to linear in memory, so the
    // first pass lands near the target and the second corrects for noise.
    for _ in 0..2 {
        let elapsed = measure(&params)?;
        let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
        if elapsed_ms <= 0.5 {
            params.memory_kib = MAX_MEMORY_KIB;
            break;
        }
        let ratio = (target.as_secs_f64() * 1000.0) / elapsed_ms;
        let scaled = (params.memory_kib as f64 * ratio).round();
        let scaled = scaled.clamp(MIN_MEMORY_KIB as f64, MAX_MEMORY_KIB as f64) as u32;
        // Round down to a multiple of 8 MiB for tidy values in the header.
        params.memory_kib = (scaled / 8192).max(MIN_MEMORY_KIB / 8192) * 8192;
    }

    params.validate_strength()?;
    Ok(params)
}
