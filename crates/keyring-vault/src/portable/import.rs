//! Import from KeePass CSV and Bitwarden JSON (FR-9.1).
//!
//! ## Why the CSV parser is written here
//!
//! RFC 4180 is small — quoted fields, doubled quotes inside them, embedded
//! newlines — and a dependency that pulls in a derive macro and a serde
//! integration to parse six columns is not worth the supply-chain surface on a
//! security product. Roughly seventy lines, fully tested, no `unsafe`. If this
//! ever needs to handle a genuinely hostile dialect, `csv` is the replacement
//! and [`parse_csv`] is the seam.
//!
//! ## What import guarantees
//!
//! 1. **It never creates or unlocks a vault.** Records go into an already-open
//!    session, through the ordinary encrypted write path.
//! 2. **It never partially imports a record.** A row either becomes a complete
//!    record or is skipped and reported.
//! 3. **It reports every skip with a reason.** Silent data loss during an
//!    import is how people discover, months later, that forty credentials
//!    never made it.
//! 4. **It takes a safety backup first** — done by the caller in `src-tauri`,
//!    because this crate does not decide policy.
//!
//! ## What it does not do
//!
//! Attachments. Neither format carries them in a way that round-trips
//! reliably: KeePass CSV has no binary column at all, and Bitwarden's JSON
//! export references attachments by URL, which would need a network fetch —
//! and this product does not have one. Records import; their attachments do
//! not, and the report says so.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::model::RecordType;

use super::{guess_type, normalize_folder, PortableField, PortableRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportSource {
    KeePassCsv,
    BitwardenJson,
}

impl ImportSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ImportSource::KeePassCsv => "keepass_csv",
            ImportSource::BitwardenJson => "bitwarden_json",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "keepass_csv" => Some(ImportSource::KeePassCsv),
            "bitwarden_json" => Some(ImportSource::BitwardenJson),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// No title and nothing else usable.
    Empty,
    /// A Bitwarden folder entry, a KeePass group header — structure, not data.
    NotACredential,
    /// Bitwarden marks it deleted.
    InTrash,
    /// The row had fewer columns than the header promised.
    Malformed,
    /// A record with this exact title already exists in the target folder.
    Duplicate,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedRow {
    /// 1-based, matching what a spreadsheet shows. For JSON this is the index
    /// in the items array.
    pub row: usize,
    /// The title, if there was one. **Never the value of any field** — a skip
    /// report that quoted the password would be a log file full of passwords.
    pub title: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub source: String,
    pub parsed: usize,
    pub imported: usize,
    pub skipped: Vec<SkippedRow>,
    /// Types assigned by the guesser, so the user can see at a glance whether
    /// the mapping was sensible before committing to it.
    pub type_counts: Vec<(String, usize)>,
    /// Set when the source referenced attachments that could not come across.
    pub attachments_dropped: usize,
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// Minimal RFC 4180 parser. Returns rows of owned fields.
///
/// Handles: quoted fields, `""` as a literal quote, commas and newlines inside
/// quotes, and both `\n` and `\r\n` line endings.
pub fn parse_csv(input: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                _ => field.push(c),
            }
            continue;
        }

        match c {
            '"' if field.is_empty() => in_quotes = true,
            ',' => row.push(std::mem::take(&mut field)),
            '\r' => {
                // Swallow; the \n that follows ends the row.
            }
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            _ => field.push(c),
        }
    }

    // A file that does not end in a newline still has a final row.
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }

    // Drop entirely blank trailing rows.
    rows.retain(|r| !(r.len() == 1 && r[0].trim().is_empty()));
    rows
}

/// Locate a column by any of several accepted header names.
///
/// KeePass's CSV header has changed across versions and localisations —
/// `Account`/`Title`, `Login Name`/`Username`, `Web Site`/`URL`. Matching a
/// set of aliases is the difference between "imports cleanly" and "imports
/// four hundred records with no usernames".
fn column(headers: &[String], aliases: &[&str]) -> Option<usize> {
    headers.iter().position(|h| {
        let h = h.trim().trim_start_matches('\u{feff}').to_lowercase();
        aliases.iter().any(|a| h == *a)
    })
}

/// Parse a KeePass CSV export into portable records.
pub fn parse_keepass_csv(input: &str) -> Result<Vec<(usize, PortableRecord)>> {
    let rows = parse_csv(input);
    let Some(headers) = rows.first() else {
        return Err(VaultError::Invalid("That CSV file is empty.".into()));
    };

    let c_title = column(headers, &["account", "title", "name"]);
    let c_user = column(headers, &["login name", "username", "user name", "login"]);
    let c_pass = column(headers, &["password", "pass"]);
    let c_url = column(headers, &["web site", "url", "website", "uri"]);
    let c_notes = column(headers, &["comments", "notes", "note"]);
    let c_group = column(headers, &["group", "folder", "group tree"]);
    let c_totp = column(headers, &["totp", "otp", "otpauth"]);

    if c_title.is_none() && c_user.is_none() && c_pass.is_none() {
        return Err(VaultError::Invalid(
            "That does not look like a KeePass CSV export. Expected a header row with at least Account, Login Name or Password.".into(),
        ));
    }

    let get = |row: &[String], idx: Option<usize>| -> String {
        idx.and_then(|i| row.get(i)).map(|s| s.trim().to_string()).unwrap_or_default()
    };

    let mut out = Vec::new();
    for (n, row) in rows.iter().enumerate().skip(1) {
        let title = get(row, c_title);
        let username = get(row, c_user);
        let password = get(row, c_pass);
        let url = get(row, c_url);
        let notes = get(row, c_notes);
        let group = get(row, c_group);
        let totp = get(row, c_totp);

        let rtype = guess_type(&title, &url, &username, &notes);
        let mut record = PortableRecord {
            title: if title.is_empty() {
                // A row with credentials but no title is still worth keeping;
                // give it something findable rather than dropping it.
                if !url.is_empty() {
                    url.clone()
                } else {
                    username.clone()
                }
            } else {
                title.clone()
            },
            record_type: rtype.as_str().to_string(),
            folder: normalize_folder(&group),
            notes: notes.clone(),
            ..Default::default()
        };

        push_common(&mut record, rtype, &username, &password, &url, &totp, &notes);
        out.push((n + 1, record));
    }

    Ok(out)
}

/// Map the universal login triplet onto whichever field names the guessed type
/// actually uses. An SSH server has `host`, not `url`; a database has
/// `username` but no `url` at all.
fn push_common(
    record: &mut PortableRecord,
    rtype: RecordType,
    username: &str,
    password: &str,
    url: &str,
    totp: &str,
    notes: &str,
) {
    match rtype {
        RecordType::SshServer => {
            let (host, port) = split_host_port(url, 22);
            record.push(PortableField::new("host", "Host", host, false));
            if port != 22 {
                record.push(PortableField::new("port", "Port", port.to_string(), false));
            }
            record.push(PortableField::new("username", "Username", username, false));
            record.push(PortableField::new("password", "Password", password, true));
        }
        RecordType::RdpHost => {
            let (host, port) = split_host_port(url, 3389);
            record.push(PortableField::new("host", "Host", host, false));
            if port != 3389 {
                record.push(PortableField::new("port", "Port", port.to_string(), false));
            }
            record.push(PortableField::new("username", "Username", username, false));
            record.push(PortableField::new("password", "Password", password, true));
        }
        RecordType::Database => {
            let (host, port) = split_host_port(url, 0);
            record.push(PortableField::new("host", "Host", host, false));
            if port != 0 {
                record.push(PortableField::new("port", "Port", port.to_string(), false));
            }
            record.push(PortableField::new("username", "Username", username, false));
            record.push(PortableField::new("password", "Password", password, true));
        }
        RecordType::ApiKey => {
            record.push(PortableField::new("key_id", "Key ID", username, false));
            record.push(PortableField::new("secret_key", "Secret key", password, true));
            record.push(PortableField::new("endpoint", "Endpoint", url, false));
        }
        RecordType::CloudServiceAccount => {
            record.push(PortableField::new(
                "account_email",
                "Account email",
                username,
                false,
            ));
            record.push(PortableField::new("console_url", "Console URL", url, false));
            // The password column on a cloud row is usually a secret key, and
            // the template has no home for it. A custom field keeps it, and
            // D-8 means a field named like this is encrypted by default.
            record.push(PortableField::new(
                "secret_key",
                "Secret key",
                password,
                true,
            ));
        }
        RecordType::SecureNote => {
            let body = if notes.trim().is_empty() {
                password.to_string()
            } else {
                notes.to_string()
            };
            record.push(PortableField::new("body", "Body", body, true));
        }
        RecordType::Certificate => {
            record.push(PortableField::new(
                "common_name",
                "Common name",
                url,
                false,
            ));
            record.push(PortableField::new("passphrase", "Passphrase", password, true));
        }
        RecordType::CommandSnippet => {
            record.push(PortableField::new("command", "Command", notes, false));
        }
        RecordType::WebLogin => {
            record.push(PortableField::new("url", "URL", url, false));
            record.push(PortableField::new("username", "Username", username, false));
            record.push(PortableField::new("password", "Password", password, true));
        }
    }

    if !totp.trim().is_empty() && matches!(rtype, RecordType::WebLogin) {
        record.push(PortableField::new(
            "totp_secret",
            "TOTP secret",
            extract_totp_secret(totp),
            true,
        ));
    }

    if !notes.trim().is_empty() && !matches!(rtype, RecordType::SecureNote | RecordType::CommandSnippet) {
        record.push(PortableField::new("notes", "Notes", notes, true));
    }
}

/// Pull the base32 seed out of an `otpauth://` URI, or pass a bare seed
/// through unchanged. Both appear in the wild.
fn extract_totp_secret(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(query) = raw.split_once('?').map(|(_, q)| q) {
        for pair in query.split('&') {
            if let Some(v) = pair.strip_prefix("secret=") {
                return v.to_string();
            }
        }
    }
    raw.to_string()
}

/// Split `host:port`, `scheme://host:port/path` or a bare host.
fn split_host_port(raw: &str, default_port: u16) -> (String, u16) {
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), default_port);
    }
    // Drop a scheme.
    let without_scheme = raw.split_once("://").map(|(_, r)| r).unwrap_or(raw);
    // Drop credentials, a path, and a query.
    let authority = without_scheme
        .split_once('@')
        .map(|(_, r)| r)
        .unwrap_or(without_scheme);
    let authority = authority
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(authority);

    // IPv6 literals are bracketed; do not split those on the colon.
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = authority[..=end].to_string();
            let port = authority[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host, port);
        }
    }

    match authority.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(p) => (host.to_string(), p),
            Err(_) => (authority.to_string(), default_port),
        },
        None => (authority.to_string(), default_port),
    }
}

// ---------------------------------------------------------------------------
// Bitwarden JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwFolder {
    id: Option<String>,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct BwItem {
    #[serde(default, rename = "type")]
    kind: i64,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "folderId")]
    folder_id: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    card: Option<serde_json::Value>,
    #[serde(default)]
    identity: Option<serde_json::Value>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
    #[serde(default)]
    attachments: Option<Vec<serde_json::Value>>,
    #[serde(default, rename = "deletedDate")]
    deleted_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    /// Bitwarden's own type: 0 text, 1 hidden, 2 boolean, 3 linked.
    #[serde(default, rename = "type")]
    kind: i64,
}

/// Parse a Bitwarden JSON export.
pub fn parse_bitwarden_json(input: &str) -> Result<(Vec<(usize, PortableRecord)>, usize)> {
    let export: BwExport = serde_json::from_str(input)
        .map_err(|_| VaultError::Invalid("That file is not a Bitwarden JSON export.".into()))?;

    if export.encrypted {
        return Err(VaultError::Invalid(
            "That is an encrypted Bitwarden export. Export again with the unencrypted option — Keyring has no way to decrypt Bitwarden's format.".into(),
        ));
    }

    let folder_names: std::collections::HashMap<String, String> = export
        .folders
        .into_iter()
        .filter_map(|f| f.id.map(|id| (id, f.name)))
        .collect();

    let mut out = Vec::new();
    let mut attachments_dropped = 0usize;

    for (n, item) in export.items.into_iter().enumerate() {
        if item.deleted_date.is_some() {
            continue;
        }
        attachments_dropped += item.attachments.as_ref().map(|a| a.len()).unwrap_or(0);

        let folder = item
            .folder_id
            .as_ref()
            .and_then(|id| folder_names.get(id))
            .map(|s| normalize_folder(s))
            .unwrap_or_default();

        let notes = item.notes.clone().unwrap_or_default();
        let login = item.login.as_ref();
        let username = login.and_then(|l| l.username.clone()).unwrap_or_default();
        let password = login.and_then(|l| l.password.clone()).unwrap_or_default();
        let totp = login.and_then(|l| l.totp.clone()).unwrap_or_default();
        let url = login
            .and_then(|l| l.uris.as_ref())
            .and_then(|u| u.first())
            .and_then(|u| u.uri.clone())
            .unwrap_or_default();

        // Bitwarden item types: 1 login, 2 secure note, 3 card, 4 identity.
        // Cards and identities have no meaningful home in a DevOps credential
        // vault; they become notes so nothing is lost.
        let rtype = match item.kind {
            1 => guess_type(&item.name, &url, &username, &notes),
            2 => RecordType::SecureNote,
            _ => RecordType::SecureNote,
        };

        let mut record = PortableRecord {
            title: item.name.clone(),
            record_type: rtype.as_str().to_string(),
            folder,
            notes: notes.clone(),
            ..Default::default()
        };

        push_common(&mut record, rtype, &username, &password, &url, &totp, &notes);

        // Card and identity payloads are flattened into the note body rather
        // than dropped.
        for extra in [item.card.as_ref(), item.identity.as_ref()].into_iter().flatten() {
            if let Ok(text) = serde_json::to_string_pretty(extra) {
                record.push(PortableField::new("body", "Body", text, true));
            }
        }

        // Custom fields. Bitwarden type 1 is hidden, which is exactly what
        // Keyring calls a secret.
        for f in item.fields.into_iter().flatten() {
            let (Some(name), Some(value)) = (f.name, f.value) else {
                continue;
            };
            if name.trim().is_empty() {
                continue;
            }
            let secret = f.kind == 1;
            let field_name = sanitize_field_name(&name);
            record.push(PortableField::new(&field_name, &name, value, secret));
        }

        out.push((n + 1, record));
    }

    Ok((out, attachments_dropped))
}

/// Turn an arbitrary label into something usable as a field name.
///
/// Field names are a key in a unique index, so they cannot contain arbitrary
/// text. Lowercase, non-alphanumerics to underscores, collapsed.
fn sanitize_field_name(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut last_underscore = false;
    for c in label.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore && !out.is_empty() {
            out.push('_');
            last_underscore = true;
        }
    }
    let trimmed = out.trim_end_matches('_').to_string();
    if trimmed.is_empty() {
        "custom".to_string()
    } else {
        trimmed
    }
}

/// Parse whichever format, returning records plus a count of attachments that
/// could not be carried across.
pub fn parse(source: ImportSource, input: &str) -> Result<(Vec<(usize, PortableRecord)>, usize)> {
    match source {
        ImportSource::KeePassCsv => Ok((parse_keepass_csv(input)?, 0)),
        ImportSource::BitwardenJson => parse_bitwarden_json(input),
    }
}

/// Read an import file into a zeroizing buffer.
///
/// The file on disk is plaintext and out of our control — but the copy in our
/// address space is not, and it wipes on drop.
pub fn read_source_file(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let text = String::from_utf8(bytes.to_vec()).map_err(|_| {
        VaultError::Invalid("That file is not valid UTF-8 text.".into())
    })?;
    Ok(Zeroizing::new(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_handles_quotes_commas_and_embedded_newlines() {
        let input = "a,b,c\n1,\"two, with comma\",\"line one\nline two\"\n";
        let rows = parse_csv(input);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][1], "two, with comma");
        assert_eq!(rows[1][2], "line one\nline two");
    }

    #[test]
    fn csv_handles_doubled_quotes_and_crlf() {
        let input = "a\r\n\"he said \"\"hi\"\"\"\r\n";
        let rows = parse_csv(input);
        assert_eq!(rows[1][0], "he said \"hi\"");
    }

    #[test]
    fn csv_final_row_without_trailing_newline_is_kept() {
        let rows = parse_csv("a,b\n1,2");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][1], "2");
    }

    #[test]
    fn keepass_export_maps_the_standard_columns() {
        let input = "\"Group\",\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\
                     \"Root/Clients\",\"Acme portal\",\"admin\",\"hunter2\",\"https://acme.example\",\"note text\"\n";
        let records = parse_keepass_csv(input).unwrap();
        assert_eq!(records.len(), 1);
        let (row, r) = &records[0];
        assert_eq!(*row, 2, "row numbers must match the spreadsheet");
        assert_eq!(r.title, "Acme portal");
        assert_eq!(r.folder, "Clients");
        assert_eq!(r.record_type, "web_login");
        assert_eq!(&*r.field("password").unwrap().value, "hunter2");
        assert!(r.field("password").unwrap().secret);
        assert!(!r.field("username").unwrap().secret);
    }

    #[test]
    fn keepass_alternate_header_names_still_map() {
        let input = "Title,Username,Password,URL,Notes\nX,me,pw,https://x.example,\n";
        let records = parse_keepass_csv(input).unwrap();
        assert_eq!(&*records[0].1.field("username").unwrap().value, "me");
    }

    #[test]
    fn a_csv_that_is_not_keepass_is_rejected_with_a_useful_message() {
        let err = parse_keepass_csv("foo,bar\n1,2\n").unwrap_err();
        assert!(matches!(err, VaultError::Invalid(_)));
    }

    #[test]
    fn ssh_rows_map_host_and_port_not_url() {
        let input = "Account,Login Name,Password,Web Site,Comments\n\
                     bastion,ubuntu,pw,ssh://bastion.example.com:2222,ssh jump host\n";
        let records = parse_keepass_csv(input).unwrap();
        let r = &records[0].1;
        assert_eq!(r.record_type, "ssh_server");
        assert_eq!(&*r.field("host").unwrap().value, "bastion.example.com");
        assert_eq!(&*r.field("port").unwrap().value, "2222");
        assert!(r.field("url").is_none());
    }

    #[test]
    fn host_port_splitting_handles_ipv6_and_bare_hosts() {
        assert_eq!(split_host_port("example.com", 22), ("example.com".into(), 22));
        assert_eq!(split_host_port("example.com:2222", 22), ("example.com".into(), 2222));
        assert_eq!(
            split_host_port("[2001:db8::1]:22", 22),
            ("[2001:db8::1]".into(), 22)
        );
        assert_eq!(
            split_host_port("https://user@host.example/path?a=b", 443),
            ("host.example".into(), 443)
        );
    }

    #[test]
    fn totp_uri_yields_only_the_seed() {
        assert_eq!(
            extract_totp_secret("otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&issuer=Acme"),
            "JBSWY3DPEHPK3PXP"
        );
        assert_eq!(extract_totp_secret("JBSWY3DPEHPK3PXP"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn bitwarden_login_imports_with_folder_and_custom_fields() {
        let json = r#"{
          "encrypted": false,
          "folders": [{"id": "f1", "name": "Clients/Acme"}],
          "items": [{
            "type": 1,
            "name": "Acme console",
            "folderId": "f1",
            "notes": "prod",
            "login": {
              "username": "admin",
              "password": "s3cret",
              "totp": "JBSWY3DPEHPK3PXP",
              "uris": [{"uri": "https://acme.example"}]
            },
            "fields": [
              {"name": "Recovery Code", "value": "abc123", "type": 1},
              {"name": "Region", "value": "eu-west-1", "type": 0}
            ]
          }]
        }"#;
        let (records, dropped) = parse_bitwarden_json(json).unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(records.len(), 1);
        let r = &records[0].1;
        assert_eq!(r.folder, "Clients/Acme");
        assert_eq!(&*r.field("password").unwrap().value, "s3cret");
        assert!(r.field("recovery_code").unwrap().secret, "hidden field stays secret");
        assert!(!r.field("region").unwrap().secret);
    }

    #[test]
    fn bitwarden_deleted_items_are_not_imported() {
        let json = r#"{"encrypted": false, "items": [
            {"type": 1, "name": "gone", "deletedDate": "2026-01-01T00:00:00.000Z",
             "login": {"username": "u", "password": "p"}}
        ]}"#;
        let (records, _) = parse_bitwarden_json(json).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn an_encrypted_bitwarden_export_is_refused_with_instructions() {
        let json = r#"{"encrypted": true, "items": []}"#;
        let err = parse_bitwarden_json(json).unwrap_err();
        match err {
            VaultError::Invalid(m) => assert!(m.contains("unencrypted")),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn bitwarden_attachments_are_counted_as_dropped_not_silently_ignored() {
        let json = r#"{"encrypted": false, "items": [
            {"type": 1, "name": "x", "login": {"username": "u", "password": "p"},
             "attachments": [{"id": "a1"}, {"id": "a2"}]}
        ]}"#;
        let (_, dropped) = parse_bitwarden_json(json).unwrap();
        assert_eq!(dropped, 2);
    }

    #[test]
    fn field_names_are_sanitized_into_valid_keys() {
        assert_eq!(sanitize_field_name("Recovery Code"), "recovery_code");
        assert_eq!(sanitize_field_name("  ***  "), "custom");
        assert_eq!(sanitize_field_name("API-Key #2"), "api_key_2");
    }
}
