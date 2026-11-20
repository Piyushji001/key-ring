//! Import and export (FR-9). Getting credentials in from another manager, and
//! out again.
//!
//! ## The shared shape
//!
//! Both directions go through [`PortableRecord`] — a flat, format-agnostic
//! record. KeePass CSV and Bitwarden JSON both parse *into* it; every export
//! serialises *from* it. That keeps the mapping logic in one place instead of
//! growing a matrix of format-to-format converters.
//!
//! ## The rule that matters
//!
//! A `PortableRecord` holds plaintext. It is the only structure in this crate
//! that does, by design — an import has just read a plaintext CSV, and an
//! export is about to write one. Every field that could be a secret is a
//! `Zeroizing<String>`, and no `PortableRecord` is ever held longer than the
//! operation that needed it.
//!
//! Import never touches the header, never re-derives a key, and never creates
//! a vault. It writes records into an already-unlocked session through the same
//! `set_field` path the UI uses, so imported secrets are encrypted by exactly
//! the same code as typed ones.

pub mod bridge;
pub mod export;
pub mod import;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::model::RecordType;

pub use export::{ExportFormat, ExportRequest, ExportSummary};
pub use import::{ImportReport, ImportSource, SkipReason};

/// One credential, in transit between Keyring and the outside world.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortableRecord {
    pub title: String,
    /// Keyring record type as a string. On import this is a guess; the user
    /// can change it afterwards.
    #[serde(default)]
    pub record_type: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Field name to value. Names match the templates in
    /// `model/record_type.rs` wherever a sensible mapping exists.
    #[serde(default)]
    pub fields: Vec<PortableField>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableField {
    pub name: String,
    pub label: String,
    /// Wrapped so that a dropped import buffer does not leave a password
    /// sitting in freed heap. `Zeroizing<String>` serialises as a plain
    /// string, which is what both formats need.
    pub value: Zeroizing<String>,
    /// Whether Keyring will encrypt this field. Set from the destination
    /// template on import; written to the manifest on export so a round trip
    /// does not silently downgrade a secret to a searchable value.
    pub secret: bool,
}

impl PortableField {
    pub fn new(name: &str, label: &str, value: impl Into<String>, secret: bool) -> Self {
        PortableField {
            name: name.to_string(),
            label: label.to_string(),
            value: Zeroizing::new(value.into()),
            secret,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.value.trim().is_empty()
    }
}

impl PortableRecord {
    pub fn resolved_type(&self) -> RecordType {
        RecordType::parse(&self.record_type).unwrap_or(RecordType::SecureNote)
    }

    pub fn field(&self, name: &str) -> Option<&PortableField> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn push(&mut self, field: PortableField) {
        if field.is_empty() {
            return;
        }
        self.fields.push(field);
    }

    /// Does this record carry anything worth importing?
    ///
    /// A row with a title and nothing else is almost always a section header
    /// or an artefact of a bad export, not a credential.
    pub fn is_substantive(&self) -> bool {
        !self.title.trim().is_empty()
            && (!self.fields.is_empty() || !self.notes.trim().is_empty())
    }
}

/// Guess a Keyring record type from whatever the source gave us.
///
/// This is heuristic and says so. It exists because dropping 400 imported
/// logins into `secure_note` would be technically correct and practically
/// useless — the type drives the field template, the action bar, and half the
/// product's value. Getting it right 80% of the time and letting the user fix
/// the rest beats getting it right 0% of the time.
pub fn guess_type(title: &str, url: &str, username: &str, extra: &str) -> RecordType {
    let hay = format!(
        "{} {} {} {}",
        title.to_lowercase(),
        url.to_lowercase(),
        username.to_lowercase(),
        extra.to_lowercase()
    );

    // Order matters: the more specific signals are checked first.
    let has = |needles: &[&str]| needles.iter().any(|n| hay.contains(n));

    if has(&["ssh://", "sftp://"]) || has(&["ssh ", " ssh", "bastion", "jump host"]) {
        return RecordType::SshServer;
    }
    if has(&["rdp://", "ms-rd:"]) || has(&["rdp", "remote desktop", "terminal server"]) {
        return RecordType::RdpHost;
    }
    if has(&[
        "aws",
        "amazon web services",
        "gcp",
        "google cloud",
        "azure",
        "service account",
        "service principal",
        "iam",
    ]) {
        return RecordType::CloudServiceAccount;
    }
    if has(&["api key", "api-key", "apikey", "access token", "bearer"]) {
        return RecordType::ApiKey;
    }
    if has(&[
        "postgres",
        "postgresql",
        "mysql",
        "mariadb",
        "mongodb",
        "redis",
        "mssql",
        "sql server",
        "oracle db",
        "jdbc:",
    ]) {
        return RecordType::Database;
    }
    if has(&[".pem", ".pfx", ".p12", "certificate", "x509", "tls cert"]) {
        return RecordType::Certificate;
    }
    if !url.trim().is_empty() || has(&["http://", "https://"]) {
        return RecordType::WebLogin;
    }
    if !username.trim().is_empty() {
        return RecordType::WebLogin;
    }
    RecordType::SecureNote
}

/// Split a slash- or backslash-separated group path into a Keyring folder.
///
/// KeePass uses `Group/Subgroup`, Bitwarden uses `Folder/Subfolder`. Keyring's
/// folder is a plain string with `/` separators (D-29), so this mostly just
/// normalises separators and trims noise.
pub fn normalize_folder(raw: &str) -> String {
    let cleaned: Vec<&str> = raw
        .split(['/', '\\'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        // KeePass exports frequently carry a top-level group named after the
        // database itself. It carries no information and doubles everyone's
        // folder depth.
        .filter(|s| !s.eq_ignore_ascii_case("root") && !s.eq_ignore_ascii_case("database"))
        .collect();
    cleaned.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_paths_normalise() {
        assert_eq!(normalize_folder("Root/Clients/Acme"), "Clients/Acme");
        assert_eq!(normalize_folder("\\Clients\\Acme\\"), "Clients/Acme");
        assert_eq!(normalize_folder("  "), "");
        assert_eq!(normalize_folder("Acme"), "Acme");
    }

    #[test]
    fn type_guessing_picks_the_specific_signal_over_the_generic_one() {
        // Has a URL, but the AWS signal is stronger.
        assert_eq!(
            guess_type("AWS prod", "https://console.aws.amazon.com", "root", ""),
            RecordType::CloudServiceAccount
        );
        assert_eq!(
            guess_type("db-prod-01", "", "app", "postgresql://"),
            RecordType::Database
        );
        assert_eq!(
            guess_type("GitHub", "https://github.com", "me", ""),
            RecordType::WebLogin
        );
        assert_eq!(guess_type("Wifi codes", "", "", ""), RecordType::SecureNote);
        assert_eq!(
            guess_type("bastion.example.com", "", "ubuntu", "ssh"),
            RecordType::SshServer
        );
    }

    #[test]
    fn a_title_alone_is_not_substantive() {
        let mut r = PortableRecord {
            title: "Section".into(),
            ..Default::default()
        };
        assert!(!r.is_substantive());
        r.push(PortableField::new("username", "Username", "me", false));
        assert!(r.is_substantive());
    }

    #[test]
    fn empty_fields_are_dropped_on_push() {
        let mut r = PortableRecord::default();
        r.push(PortableField::new("password", "Password", "   ", true));
        assert!(r.fields.is_empty());
    }
}
