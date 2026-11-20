//! RFC 6238 time-based one-time passwords.
//!
//! ## What is and is not hand-written here
//!
//! HMAC comes from the `hmac` crate, and SHA-1/256/512 from `sha1` and `sha2`.
//! Those are the cryptographic primitives and they are not reimplemented.
//! What this module contains is RFC 6238's counter construction and RFC 4226's
//! dynamic truncation - arithmetic on a MAC that already exists. Base32
//! decoding is an encoding, not a cipher.
//!
//! Structure §3 lists `totp-rs`. This is a direct implementation instead
//! because the whole algorithm is forty lines on top of audited HMAC, and
//! because it is verified against the RFC's own vectors below. Decision D-30.
//!
//! ## The vectors, and the errata that catches people
//!
//! RFC 6238 Appendix B says the shared secret is the ASCII string
//! `12345678901234567890`. Verified erratum EID 2866 corrects that: only the
//! SHA-1 vectors use those 20 bytes. SHA-256 uses a 32-byte seed and SHA-512 a
//! 64-byte seed, both formed by repeating the same digits. An implementation
//! that uses the 20-byte seed for all three will fail the SHA-256 and SHA-512
//! vectors and conclude, wrongly, that its HMAC is broken.

use hmac::Hmac;
use zeroize::Zeroizing;


use crate::error::{AppError, Result};

/// RFC 6238 §5.2 recommends 30 seconds.
pub const DEFAULT_STEP_SECS: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Algorithm {
        match s.trim().to_ascii_uppercase().as_str() {
            "SHA256" | "SHA-256" => Algorithm::Sha256,
            "SHA512" | "SHA-512" => Algorithm::Sha512,
            _ => Algorithm::Sha1,
        }
    }
}

/// Everything needed to produce a code, parsed from a stored secret.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub step_secs: u64,
}

impl Default for TotpConfig {
    fn default() -> Self {
        TotpConfig {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: DEFAULT_DIGITS,
            step_secs: DEFAULT_STEP_SECS,
        }
    }
}

/// Decode RFC 4648 base32, ignoring padding, spaces and case.
///
/// Authenticator apps hand out secrets with spaces every four characters and
/// inconsistent padding, so being liberal here is not sloppiness - it is the
/// difference between a secret pasting cleanly and the user giving up.
pub fn base32_decode(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut out = Zeroizing::new(Vec::with_capacity(input.len() * 5 / 8));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.chars() {
        if ch == '=' || ch.is_whitespace() || ch == '-' {
            continue;
        }
        let upper = ch.to_ascii_uppercase() as u8;
        let Some(value) = ALPHABET.iter().position(|&c| c == upper) else {
            return Err(AppError::invalid(
                "That does not look like a base32 TOTP secret.",
            ));
        };

        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }

    if out.is_empty() {
        return Err(AppError::invalid("The TOTP secret is empty."));
    }
    Ok(out)
}

/// Accepts a raw base32 secret or a full `otpauth://` URI, because users paste
/// whichever their provider gave them.
pub fn parse_secret(input: &str) -> Result<TotpConfig> {
    let trimmed = input.trim();

    if !trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        return Ok(TotpConfig {
            secret: base32_decode(trimmed)?,
            ..Default::default()
        });
    }

    // Minimal query parsing. No URL crate: the format is fixed and this avoids
    // a dependency that exists to parse things we do not accept anyway.
    let query = trimmed.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut config = TotpConfig::default();
    let mut secret_param: Option<&str> = None;

    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret_param = Some(value),
            "algorithm" => config.algorithm = Algorithm::parse(value),
            "digits" => {
                if let Ok(d) = value.parse::<u32>() {
                    config.digits = d.clamp(6, 8);
                }
            }
            "period" => {
                if let Ok(p) = value.parse::<u64>() {
                    config.step_secs = p.clamp(10, 300);
                }
            }
            _ => {}
        }
    }

    let secret = secret_param
        .ok_or_else(|| AppError::invalid("That otpauth link has no secret in it."))?;
    config.secret = base32_decode(secret)?;
    Ok(config)
}

fn hmac_digest(algorithm: Algorithm, key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    use hmac::Mac as _;
    match algorithm {
        Algorithm::Sha1 => {
            let mut mac = <Hmac<sha1::Sha1>>::new_from_slice(key)
                .map_err(|_| AppError::internal("HMAC rejected the key length"))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Algorithm::Sha256 => {
            let mut mac = <Hmac<sha2::Sha256>>::new_from_slice(key)
                .map_err(|_| AppError::internal("HMAC rejected the key length"))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Algorithm::Sha512 => {
            let mut mac = <Hmac<sha2::Sha512>>::new_from_slice(key)
                .map_err(|_| AppError::internal("HMAC rejected the key length"))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Generate the code for an explicit counter. Separated from wall-clock time
/// so that the RFC vectors can be tested at all.
pub fn generate_at_counter(config: &TotpConfig, counter: u64) -> Result<String> {
    let digest = hmac_digest(config.algorithm, &config.secret, &counter.to_be_bytes())?;

    // RFC 4226 §5.4 dynamic truncation: the low nibble of the last byte picks
    // a 4-byte window, and the top bit of that window is masked off so the
    // result is always positive.
    let offset = (*digest.last().unwrap_or(&0) & 0x0f) as usize;
    if digest.len() < offset + 4 {
        return Err(AppError::internal("HMAC output was unexpectedly short"));
    }
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);

    let modulus = 10u32.pow(config.digits);
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = config.digits as usize
    ))
}

/// Generate the code for a Unix timestamp.
pub fn generate_at_time(config: &TotpConfig, unix_seconds: u64) -> Result<String> {
    let counter = unix_seconds / config.step_secs.max(1);
    generate_at_counter(config, counter)
}

/// Seconds until the current code expires. Drives the countdown ring.
pub fn seconds_remaining(config: &TotpConfig, unix_seconds: u64) -> u32 {
    let step = config.step_secs.max(1);
    (step - (unix_seconds % step)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B, with verified erratum EID 2866 applied: the three
    /// algorithms use different seed lengths, all formed by repeating
    /// "1234567890".
    fn seed(bytes: usize) -> Zeroizing<Vec<u8>> {
        let pattern = b"1234567890";
        Zeroizing::new(pattern.iter().cycle().take(bytes).copied().collect())
    }

    fn config(algorithm: Algorithm, secret_len: usize) -> TotpConfig {
        TotpConfig {
            secret: seed(secret_len),
            algorithm,
            digits: 8,
            step_secs: 30,
        }
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let c = config(Algorithm::Sha1, 20);
        for (time, expected) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(generate_at_time(&c, time).unwrap(), expected, "T={time}");
        }
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        // 32-byte seed, per erratum EID 2866.
        let c = config(Algorithm::Sha256, 32);
        for (time, expected) in [
            (59u64, "46119246"),
            (1_111_111_109, "68084774"),
            (1_111_111_111, "67062674"),
            (1_234_567_890, "91819424"),
            (2_000_000_000, "90698825"),
            (20_000_000_000, "77737706"),
        ] {
            assert_eq!(generate_at_time(&c, time).unwrap(), expected, "T={time}");
        }
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        // 64-byte seed, per erratum EID 2866.
        let c = config(Algorithm::Sha512, 64);
        for (time, expected) in [
            (59u64, "90693936"),
            (1_111_111_109, "25091201"),
            (1_111_111_111, "99943326"),
            (1_234_567_890, "93441116"),
            (2_000_000_000, "38618901"),
            (20_000_000_000, "47863826"),
        ] {
            assert_eq!(generate_at_time(&c, time).unwrap(), expected, "T={time}");
        }
    }

    #[test]
    fn base32_is_liberal_about_formatting() {
        let plain = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        let spaced = base32_decode("jbsw y3dp ehpk 3pxp").unwrap();
        let padded = base32_decode("JBSWY3DPEHPK3PXP====").unwrap();
        assert_eq!(&plain[..], &spaced[..]);
        assert_eq!(&plain[..], &padded[..]);
    }

    #[test]
    fn base32_rejects_nonsense() {
        assert!(base32_decode("not base32!").is_err());
        assert!(base32_decode("").is_err());
    }

    #[test]
    fn otpauth_uris_are_parsed() {
        let c = parse_secret(
            "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(c.algorithm, Algorithm::Sha256);
        assert_eq!(c.digits, 8);
        assert_eq!(c.step_secs, 60);
        assert_eq!(&c.secret[..], &base32_decode("JBSWY3DPEHPK3PXP").unwrap()[..]);
    }

    #[test]
    fn codes_are_zero_padded_to_the_requested_width() {
        let mut c = config(Algorithm::Sha1, 20);
        c.digits = 6;
        let code = generate_at_time(&c, 1_111_111_109).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn the_countdown_reaches_zero_at_a_step_boundary() {
        let c = config(Algorithm::Sha1, 20);
        assert_eq!(seconds_remaining(&c, 0), 30);
        assert_eq!(seconds_remaining(&c, 29), 1);
        assert_eq!(seconds_remaining(&c, 30), 30);
    }
}
