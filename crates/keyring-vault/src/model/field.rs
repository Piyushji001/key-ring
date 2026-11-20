use serde::{Deserialize, Serialize};

/// How a field is presented and whether its value is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Secret,
    Url,
    Multiline,
    Totp,
    Number,
    Date,
    Attachment,
}

impl FieldKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FieldKind::Text => "text",
            FieldKind::Secret => "secret",
            FieldKind::Url => "url",
            FieldKind::Multiline => "multiline",
            FieldKind::Totp => "totp",
            FieldKind::Number => "number",
            FieldKind::Date => "date",
            FieldKind::Attachment => "attachment",
        }
    }

    pub fn parse(s: &str) -> Option<FieldKind> {
        Some(match s {
            "text" => FieldKind::Text,
            "secret" => FieldKind::Secret,
            "url" => FieldKind::Url,
            "multiline" => FieldKind::Multiline,
            "totp" => FieldKind::Totp,
            "number" => FieldKind::Number,
            "date" => FieldKind::Date,
            "attachment" => FieldKind::Attachment,
            _ => return None,
        })
    }
}

/// A field definition from a record type template.
#[derive(Debug, Clone, Copy)]
pub struct FieldTemplate {
    pub name: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
    pub secret: bool,
}

/// A field as stored. `plain_value` is `Some` for non-secret fields;
/// `has_secret` is true when nonce+ciphertext are present.
///
/// NOTE: this struct never carries a decrypted secret. Decryption happens
/// only inside `db::fields::open_secret`, into a self-wiping buffer.
#[derive(Debug, Clone)]
pub struct FieldRow {
    pub id: String,
    pub record_id: String,
    pub name: String,
    pub label: String,
    pub kind: FieldKind,
    pub position: i64,
    pub plain_value: Option<String>,
    pub has_secret: bool,
}
