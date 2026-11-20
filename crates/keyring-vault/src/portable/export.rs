//! Export (FR-9.2, FR-9.3). Three destinations, one of them dangerous.
//!
//! ## The three
//!
//! - **Encrypted JSON** — the whole vault, sealed with a passphrase the user
//!   supplies at export time. Safe to email, safe to leave on a share. Uses
//!   the same Argon2id + XChaCha20-Poly1305 envelope as the vault itself, with
//!   its own salt, because reusing the vault's KEK would mean the export file
//!   is only as portable as the vault's master password.
//!
//! - **Folder subset** — one folder, encrypted, for handing a client their own
//!   credentials without handing them everyone else's. This is the feature that
//!   makes the product usable by a consultancy, and it is deliberately
//!   encrypted-only: a "quick plaintext subset" is how a client's credentials
//!   end up in a Slack thread.
//!
//! - **Plaintext JSON** — every credential the user owns, in the clear.
//!
//! ## About that third one
//!
//! It exists because refusing to export is how password managers hold people
//! hostage, and a vault you cannot leave is a vault you should not enter. But
//! it is the single most dangerous button in the product, and the design
//! reflects that:
//!
//!   1. The caller must present a **confirmation token** issued by
//!      [`issue_plaintext_token`] moments earlier. The two-step confirmation is
//!      therefore enforced in Rust, not in React. A frontend bug, a stray
//!      automation, or a future refactor that "simplifies" the dialog cannot
//!      produce a plaintext export on its own. (D-37)
//!   2. The token expires in 120 seconds and is single-use.
//!   3. The event is written to the activity log before the file is created,
//!      so the record survives even if the write fails.
//!   4. The file carries a header warning as its first key, because the person
//!      who finds it six months later in a Downloads folder is not necessarily
//!      the person who made it.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

use super::PortableRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// Encrypted with a passphrase given at export time.
    EncryptedJson,
    /// Plaintext. Requires a confirmation token.
    PlaintextJson,
}

#[derive(Debug, Clone)]
pub struct ExportRequest {
    pub format: ExportFormat,
    /// `None` exports everything; `Some(folder)` exports one folder and its
    /// descendants (FR-9.3).
    pub folder: Option<String>,
    /// Required for [`ExportFormat::EncryptedJson`].
    pub passphrase: Option<Zeroizing<String>>,
    /// Required for [`ExportFormat::PlaintextJson`].
    pub confirmation_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportSummary {
    pub format: String,
    pub record_count: usize,
    pub field_count: usize,
    pub folder: Option<String>,
    pub bytes_written: u64,
    /// Always reported, so the UI can say "attachments were not included"
    /// rather than leaving the user to discover it.
    pub attachments_excluded: usize,
}

/// The envelope written for an encrypted export.
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedExport {
    pub format: String,
    pub version: u16,
    /// Argon2id parameters, so a future Keyring can open this file.
    pub kdf: KdfDescriptor,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfDescriptor {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

/// The plaintext payload — also what sits inside the encrypted envelope.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportPayload {
    /// First key in the file, on purpose.
    #[serde(rename = "_warning")]
    pub warning: String,
    pub format: String,
    pub version: u16,
    pub exported_at: i64,
    pub folder: Option<String>,
    pub records: Vec<PortableRecord>,
}

pub const EXPORT_FORMAT_NAME: &str = "keyring-export";
pub const EXPORT_VERSION: u16 = 1;

const PLAINTEXT_WARNING: &str = "This file contains unencrypted credentials in plain text. \
Anyone who can read this file can read every password in it. Delete it as soon as you have \
finished with it, and do not place it in cloud storage, email, or a chat message.";

const ENCRYPTED_NOTE: &str = "This file is encrypted with a passphrase chosen at export time. \
Without that passphrase there is no way to recover its contents.";

// ---------------------------------------------------------------------------
// Plaintext confirmation tokens (D-37)
// ---------------------------------------------------------------------------

const TOKEN_TTL_SECS: i64 = 120;

/// A one-shot permission slip for a plaintext export.
#[derive(Debug)]
pub struct PlaintextToken {
    token: String,
    issued_at: i64,
    used: bool,
}

/// Holds the outstanding token. One at a time: issuing a second invalidates
/// the first, so a stale dialog left open in another window cannot be used.
#[derive(Debug, Default)]
pub struct PlaintextGate {
    current: std::sync::Mutex<Option<PlaintextToken>>,
}

impl PlaintextGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a token. The caller shows the second confirmation dialog and
    /// passes the token back with the export request.
    pub fn issue(&self) -> Result<String> {
        let token = hex_random_32()?;
        let mut slot = self
            .current
            .lock()
            .map_err(|_| VaultError::Invalid("export gate poisoned".into()))?;
        *slot = Some(PlaintextToken {
            token: token.clone(),
            issued_at: crate::util::time::now_unix(),
            used: false,
        });
        Ok(token)
    }

    /// Spend the token. Fails if it is wrong, expired, or already used.
    ///
    /// The error message is deliberately the same for all three: an attacker
    /// probing this has nothing to learn, and the legitimate user's fix is the
    /// same either way — start the export again.
    pub fn redeem(&self, presented: &str) -> Result<()> {
        let mut slot = self
            .current
            .lock()
            .map_err(|_| VaultError::Invalid("export gate poisoned".into()))?;

        let refused = || {
            VaultError::Invalid(
                "That confirmation has expired. Start the plaintext export again.".into(),
            )
        };

        let Some(entry) = slot.as_mut() else {
            return Err(refused());
        };
        if entry.used {
            return Err(refused());
        }
        if crate::util::time::now_unix() - entry.issued_at > TOKEN_TTL_SECS {
            *slot = None;
            return Err(refused());
        }
        // Constant-time-ish comparison. The token is not a secret in the
        // cryptographic sense, but there is no reason to leak its prefix.
        if !constant_time_eq(entry.token.as_bytes(), presented.as_bytes()) {
            return Err(refused());
        }

        entry.used = true;
        *slot = None;
        Ok(())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_random_32() -> Result<String> {
    let mut bytes = [0u8; 32];
    keyring_crypto::fill_random(&mut bytes)?;
    let mut out = String::with_capacity(64);
    for b in bytes.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Serialise records to plaintext JSON bytes.
///
/// Returns a `Zeroizing` buffer: the caller writes it to disk and the copy in
/// memory wipes itself. The copy on disk is the user's problem, which is what
/// all the warnings are about.
pub fn build_plaintext(
    records: Vec<PortableRecord>,
    folder: Option<String>,
) -> Result<Zeroizing<Vec<u8>>> {
    let payload = ExportPayload {
        warning: PLAINTEXT_WARNING.to_string(),
        format: EXPORT_FORMAT_NAME.to_string(),
        version: EXPORT_VERSION,
        exported_at: crate::util::time::now_unix(),
        folder,
        records,
    };
    let bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|_| VaultError::Invalid("could not serialize the export".into()))?;
    Ok(Zeroizing::new(bytes))
}

/// Serialise records, then seal them under a passphrase.
///
/// The KDF parameters are the policy floor rather than the vault's calibrated
/// ones, because an export may be opened on a different machine years later
/// and there is no reason to inherit today's hardware.
pub fn build_encrypted(
    records: Vec<PortableRecord>,
    folder: Option<String>,
    passphrase: &str,
) -> Result<Vec<u8>> {
    if passphrase.chars().count() < crate::vault::session::MIN_PASSWORD_LEN {
        return Err(VaultError::PasswordTooShort(
            crate::vault::session::MIN_PASSWORD_LEN,
        ));
    }

    let plain = {
        let payload = ExportPayload {
            warning: ENCRYPTED_NOTE.to_string(),
            format: EXPORT_FORMAT_NAME.to_string(),
            version: EXPORT_VERSION,
            exported_at: crate::util::time::now_unix(),
            folder: folder.clone(),
            records,
        };
        Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|_| VaultError::Invalid("could not serialize the export".into()))?,
        )
    };

    let params = export_kdf_params()?;
    let key = keyring_crypto::derive_kek(passphrase.as_bytes(), &params)?;

    // The AAD binds the ciphertext to the envelope metadata, so an attacker
    // cannot swap this payload under a different set of KDF parameters and
    // have it still authenticate.
    let aad = export_aad(&params);
    let sealed = keyring_crypto::seal(&key, &plain, &aad)?;

    let envelope = EncryptedExport {
        format: EXPORT_FORMAT_NAME.to_string(),
        version: EXPORT_VERSION,
        kdf: KdfDescriptor {
            algorithm: "argon2id".to_string(),
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
            salt: params.salt.to_vec(),
        },
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext,
    };

    serde_json::to_vec_pretty(&envelope)
        .map_err(|_| VaultError::Invalid("could not serialize the export envelope".into()))
}

/// Open an encrypted export produced by [`build_encrypted`].
///
/// Provided so that an export is not a one-way door — a file nobody can read
/// back is not a backup, it is a rumour.
pub fn open_encrypted(bytes: &[u8], passphrase: &str) -> Result<Vec<PortableRecord>> {
    let envelope: EncryptedExport = serde_json::from_slice(bytes)
        .map_err(|_| VaultError::Invalid("That is not a Keyring export file.".into()))?;

    if envelope.format != EXPORT_FORMAT_NAME {
        return Err(VaultError::Invalid(
            "That is not a Keyring export file.".into(),
        ));
    }
    if envelope.version > EXPORT_VERSION {
        return Err(VaultError::UnsupportedFormat(envelope.version));
    }

    if envelope.kdf.algorithm != keyring_crypto::ALGORITHM_ARGON2ID {
        return Err(VaultError::Invalid(
            "That export uses an unsupported key derivation algorithm.".into(),
        ));
    }
    if envelope.kdf.salt.len() != keyring_crypto::SALT_LEN {
        return Err(VaultError::Corrupt("export salt length"));
    }
    let mut salt = [0u8; keyring_crypto::SALT_LEN];
    salt.copy_from_slice(&envelope.kdf.salt);

    let params = keyring_crypto::KdfParams {
        algorithm: envelope.kdf.algorithm.clone(),
        memory_kib: envelope.kdf.memory_kib,
        iterations: envelope.kdf.iterations,
        parallelism: envelope.kdf.parallelism,
        salt,
    };
    let key = keyring_crypto::derive_kek(passphrase.as_bytes(), &params)?;
    let aad = export_aad(&params);

    let sealed = keyring_crypto::SealedBlob::from_parts(&envelope.nonce, &envelope.ciphertext)?;
    let plain = keyring_crypto::open(&key, &sealed, &aad)?;

    let payload: ExportPayload = serde_json::from_slice(&plain)
        .map_err(|_| VaultError::Corrupt("export payload"))?;
    Ok(payload.records)
}

/// KDF parameters for an export envelope.
///
/// The policy defaults, not the vault's calibrated ones: an export may be
/// opened on different hardware years later, and there is no reason for it to
/// inherit the speed of the machine that happened to write it.
fn export_kdf_params() -> Result<keyring_crypto::KdfParams> {
    let params = keyring_crypto::KdfParams {
        algorithm: keyring_crypto::ALGORITHM_ARGON2ID.to_string(),
        memory_kib: keyring_crypto::DEFAULT_MEMORY_KIB,
        iterations: keyring_crypto::DEFAULT_ITERATIONS,
        parallelism: keyring_crypto::DEFAULT_PARALLELISM,
        salt: keyring_crypto::random_salt()?,
    };
    params.validate_strength()?;
    Ok(params)
}

/// Authenticated data for an export envelope: format name, version and every
/// KDF parameter. Length-prefixed for the same reason D-7 length-prefixes the
/// field AAD — concatenation without lengths admits collisions.
fn export_aad(params: &keyring_crypto::KdfParams) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    let mut push = |bytes: &[u8]| {
        aad.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        aad.extend_from_slice(bytes);
    };
    push(EXPORT_FORMAT_NAME.as_bytes());
    push(&EXPORT_VERSION.to_le_bytes());
    push(&params.memory_kib.to_le_bytes());
    push(&params.iterations.to_le_bytes());
    push(&params.parallelism.to_le_bytes());
    push(&params.salt);
    aad
}

/// Does `record_folder` sit inside `wanted`?
///
/// Folder matching is prefix-based on path segments, so exporting
/// `Clients/Acme` includes `Clients/Acme/Prod` but never `Clients/Acme Corp`.
/// Getting that wrong means handing a client the wrong customer's passwords.
pub fn folder_matches(record_folder: &str, wanted: &str) -> bool {
    if wanted.is_empty() {
        return true;
    }
    if record_folder == wanted {
        return true;
    }
    record_folder.starts_with(wanted) && record_folder.as_bytes().get(wanted.len()) == Some(&b'/')
}

/// A "b64" serde helper. Base64 is written here rather than pulled in as a
/// dependency: it is thirty lines, it has no error cases worth outsourcing,
/// and this crate's dependency list is a security surface.
mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut out = Vec::with_capacity(s.len() / 4 * 3);
        for c in s.bytes() {
            if c == b'=' || c == b'\n' || c == b'\r' {
                continue;
            }
            let v = ALPHABET.iter().position(|&a| a == c)? as u32;
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        Some(out)
    }

    pub fn serialize<S: Serializer>(data: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        decode(&s).ok_or_else(|| serde::de::Error::custom("invalid base64"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portable::PortableField;

    fn sample() -> Vec<PortableRecord> {
        let mut r = PortableRecord {
            title: "Acme prod".into(),
            record_type: "web_login".into(),
            folder: "Clients/Acme".into(),
            ..Default::default()
        };
        r.push(PortableField::new("username", "Username", "admin", false));
        r.push(PortableField::new("password", "Password", "hunter2", true));
        vec![r]
    }

    #[test]
    fn base64_round_trips_including_padding_cases() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let encoded = b64::encode(&data);
            assert_eq!(b64::decode(&encoded).unwrap(), data, "length {len}");
        }
    }

    #[test]
    fn plaintext_export_leads_with_the_warning() {
        let bytes = build_plaintext(sample(), None).unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let warning_at = text.find("_warning").unwrap();
        let records_at = text.find("\"records\"").unwrap();
        assert!(warning_at < records_at, "the warning must come first");
        assert!(text.contains("plain text"));
        // And it really is plaintext - this is the point of the two-step gate.
        assert!(text.contains("hunter2"));
    }

    #[test]
    fn folder_prefix_matching_does_not_leak_a_sibling() {
        assert!(folder_matches("Clients/Acme", "Clients/Acme"));
        assert!(folder_matches("Clients/Acme/Prod", "Clients/Acme"));
        assert!(!folder_matches("Clients/Acme Corp", "Clients/Acme"));
        assert!(!folder_matches("Clients", "Clients/Acme"));
        assert!(folder_matches("anything", ""));
    }

    #[test]
    fn a_token_is_single_use() {
        let gate = PlaintextGate::new();
        let token = gate.issue().unwrap();
        assert!(gate.redeem(&token).is_ok());
        assert!(gate.redeem(&token).is_err(), "a token must not be reusable");
    }

    #[test]
    fn a_wrong_or_absent_token_is_refused() {
        let gate = PlaintextGate::new();
        assert!(gate.redeem("nope").is_err());
        let _token = gate.issue().unwrap();
        assert!(gate.redeem("still nope").is_err());
    }

    #[test]
    fn issuing_a_second_token_invalidates_the_first() {
        let gate = PlaintextGate::new();
        let first = gate.issue().unwrap();
        let second = gate.issue().unwrap();
        assert_ne!(first, second);
        assert!(gate.redeem(&first).is_err());
        assert!(gate.redeem(&second).is_ok());
    }
}
