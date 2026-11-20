//! The nine record types and their field templates (Architecture 6).
//!
//! A template is the *starting* set of fields. Every type also accepts
//! user-defined custom fields, stored in the same `fields` table.

use serde::{Deserialize, Serialize};

use super::field::{FieldKind, FieldTemplate};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordType {
    SshServer,
    RdpHost,
    ApiKey,
    CloudServiceAccount,
    WebLogin,
    Database,
    Certificate,
    CommandSnippet,
    SecureNote,
}

const fn t(name: &'static str, label: &'static str, kind: FieldKind, secret: bool) -> FieldTemplate {
    FieldTemplate {
        name,
        label,
        kind,
        secret,
    }
}

use FieldKind::*;

const SSH_SERVER: &[FieldTemplate] = &[
    t("host", "Host", Text, false),
    t("port", "Port", Number, false),
    t("username", "Username", Text, false),
    t("auth_method", "Auth method", Text, false),
    t("password", "Password", Secret, true),
    t("private_key", "Private key", Attachment, true),
    t("key_passphrase", "Key passphrase", Secret, true),
    t("jump_host", "Jump host", Text, false),
    t("notes", "Notes", Multiline, true),
];

const RDP_HOST: &[FieldTemplate] = &[
    t("host", "Host", Text, false),
    t("port", "Port", Number, false),
    t("username", "Username", Text, false),
    t("domain", "Domain", Text, false),
    t("password", "Password", Secret, true),
    t("gateway", "Gateway", Text, false),
    t("notes", "Notes", Multiline, true),
];

const API_KEY: &[FieldTemplate] = &[
    t("provider", "Provider", Text, false),
    t("key_id", "Key ID", Text, false),
    t("secret_key", "Secret key", Secret, true),
    t("endpoint", "Endpoint", Url, false),
    t("scopes", "Scopes", Text, false),
    t("expires_at", "Expires", Date, false),
    t("notes", "Notes", Multiline, true),
];

const CLOUD_SERVICE_ACCOUNT: &[FieldTemplate] = &[
    t("provider", "Provider", Text, false),
    t("project_id", "Project ID", Text, false),
    t("account_email", "Account email", Text, false),
    t("key_file", "Key file", Attachment, true),
    t("console_url", "Console URL", Url, false),
    t("notes", "Notes", Multiline, true),
];

const WEB_LOGIN: &[FieldTemplate] = &[
    t("url", "URL", Url, false),
    t("username", "Username", Text, false),
    t("password", "Password", Secret, true),
    t("totp_secret", "TOTP secret", Totp, true),
    t("client_name", "Client", Text, false),
    t("notes", "Notes", Multiline, true),
];

const DATABASE: &[FieldTemplate] = &[
    t("engine", "Engine", Text, false),
    t("host", "Host", Text, false),
    t("port", "Port", Number, false),
    t("database", "Database", Text, false),
    t("username", "Username", Text, false),
    t("password", "Password", Secret, true),
    t("ssl_mode", "SSL mode", Text, false),
    t("notes", "Notes", Multiline, true),
];

const CERTIFICATE: &[FieldTemplate] = &[
    t("common_name", "Common name", Text, false),
    t("issuer", "Issuer", Text, false),
    t("issued_at", "Issued", Date, false),
    t("expires_at", "Expires", Date, false),
    t("certificate", "Certificate", Attachment, true),
    t("private_key", "Private key", Attachment, true),
    t("passphrase", "Passphrase", Secret, true),
];

const COMMAND_SNIPPET: &[FieldTemplate] = &[
    t("command", "Command", Multiline, false),
    t("description", "Description", Multiline, false),
    t("working_dir", "Working directory", Text, false),
    t("shell", "Shell", Text, false),
];

const SECURE_NOTE: &[FieldTemplate] = &[t("body", "Body", Multiline, true)];

impl RecordType {
    pub const ALL: [RecordType; 9] = [
        RecordType::SshServer,
        RecordType::RdpHost,
        RecordType::ApiKey,
        RecordType::CloudServiceAccount,
        RecordType::WebLogin,
        RecordType::Database,
        RecordType::Certificate,
        RecordType::CommandSnippet,
        RecordType::SecureNote,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::SshServer => "ssh_server",
            RecordType::RdpHost => "rdp_host",
            RecordType::ApiKey => "api_key",
            RecordType::CloudServiceAccount => "cloud_service_account",
            RecordType::WebLogin => "web_login",
            RecordType::Database => "database",
            RecordType::Certificate => "certificate",
            RecordType::CommandSnippet => "command_snippet",
            RecordType::SecureNote => "secure_note",
        }
    }

    pub fn parse(s: &str) -> Option<RecordType> {
        RecordType::ALL.into_iter().find(|t| t.as_str() == s)
    }

    pub fn label(&self) -> &'static str {
        match self {
            RecordType::SshServer => "SSH server",
            RecordType::RdpHost => "RDP host",
            RecordType::ApiKey => "API key",
            RecordType::CloudServiceAccount => "Cloud service account",
            RecordType::WebLogin => "Web login",
            RecordType::Database => "Database",
            RecordType::Certificate => "Certificate",
            RecordType::CommandSnippet => "Command snippet",
            RecordType::SecureNote => "Secure note",
        }
    }

    pub fn template(&self) -> &'static [FieldTemplate] {
        match self {
            RecordType::SshServer => SSH_SERVER,
            RecordType::RdpHost => RDP_HOST,
            RecordType::ApiKey => API_KEY,
            RecordType::CloudServiceAccount => CLOUD_SERVICE_ACCOUNT,
            RecordType::WebLogin => WEB_LOGIN,
            RecordType::Database => DATABASE,
            RecordType::Certificate => CERTIFICATE,
            RecordType::CommandSnippet => COMMAND_SNIPPET,
            RecordType::SecureNote => SECURE_NOTE,
        }
    }

    /// The field copied when the user presses Enter on a search result.
    pub fn primary_field(&self) -> Option<&'static str> {
        Some(match self {
            RecordType::SshServer => "password",
            RecordType::RdpHost => "password",
            RecordType::ApiKey => "secret_key",
            RecordType::CloudServiceAccount => "project_id",
            RecordType::WebLogin => "password",
            RecordType::Database => "password",
            RecordType::Certificate => "passphrase",
            RecordType::CommandSnippet => "command",
            RecordType::SecureNote => "body",
        })
    }

    pub fn find_template(&self, field_name: &str) -> Option<&'static FieldTemplate> {
        self.template().iter().find(|f| f.name == field_name)
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
