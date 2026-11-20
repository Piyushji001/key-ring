//! Vault-layer errors.
//!
//! Rule inherited from the crypto core: nothing that reaches a user or a log
//! may distinguish "wrong password" from "corrupted vault".

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Could not unlock this vault.")]
    Crypto(#[from] keyring_crypto::CryptoError),

    #[error("Could not unlock this vault.")]
    /// Bad magic, bad length, unparseable header. Same message as a wrong
    /// password on purpose.
    Corrupt(&'static str),

    /// There is no vault file at that path.
    ///
    /// This is deliberately NOT collapsed into the generic unlock message.
    /// Whether a file exists reveals nothing about the master password, and
    /// hiding it turns "you picked the wrong folder" into an unfalsifiable
    /// password failure - which is exactly the bug this variant was added to
    /// fix. Wrong password and damaged file stay indistinguishable; missing
    /// file does not.
    #[error("There is no vault in that folder.")]
    NoVaultHere,

    #[error("This vault was written by a newer version of Keyring (format {0}).")]
    UnsupportedFormat(u16),

    #[error("The vault is locked. Unlock it first.")]
    Locked,

    #[error("This vault is open in another process.")]
    AlreadyOpen { pid: u32 },

    #[error("The vault is open read-only.")]
    ReadOnly,

    #[error("No record with id {0}.")]
    NoSuchRecord(String),

    #[error("No field named {1} on record {0}.")]
    NoSuchField(String, String),

    #[error("That field is not a secret field.")]
    NotSecret,

    #[error("A vault already exists at that location.")]
    AlreadyExists,

    #[error("Master password must be at least {0} characters.")]
    PasswordTooShort(usize),

    #[error("{0}")]
    Invalid(String),

    #[error("Storage error.")]
    Db(#[from] rusqlite::Error),

    #[error("File error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Could not unlock this vault.")]
    Cbor,
}

pub type Result<T> = std::result::Result<T, VaultError>;
