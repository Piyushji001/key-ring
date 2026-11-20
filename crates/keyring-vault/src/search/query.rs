//! Query parsing for the `type:` / `folder:` / `tag:` prefixes (FR-4.4).
//!
//! Everything that is not a recognised prefix is free text. `type:ssh billing`
//! means "SSH records matching billing", and a stray colon is just a colon.

use crate::model::RecordType;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub record_type: Option<RecordType>,
    pub folder: Option<String>,
    pub tag: Option<String>,
    pub favorites_only: bool,
}

impl Scope {
    pub fn is_empty(&self) -> bool {
        self.record_type.is_none()
            && self.folder.is_none()
            && self.tag.is_none()
            && !self.favorites_only
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedQuery {
    /// Lowercased free text, prefixes removed.
    pub text: String,
    pub scope: Scope,
}

/// Accepts partial type names so `type:ssh` finds `ssh_server` without the user
/// having to remember the exact identifier.
fn match_type(value: &str) -> Option<RecordType> {
    let v = value.to_ascii_lowercase();
    RecordType::ALL
        .into_iter()
        .find(|t| t.as_str() == v)
        .or_else(|| RecordType::ALL.into_iter().find(|t| t.as_str().starts_with(&v)))
        .or_else(|| {
            RecordType::ALL
                .into_iter()
                .find(|t| t.as_str().replace('_', "").starts_with(&v.replace('_', "")))
        })
}

pub fn parse(input: &str) -> ParsedQuery {
    let mut parsed = ParsedQuery::default();
    let mut words: Vec<String> = Vec::new();

    for token in input.split_whitespace() {
        match token.split_once(':') {
            Some(("type" | "t", value)) if !value.is_empty() => {
                parsed.scope.record_type = match_type(value);
            }
            Some(("folder" | "f", value)) if !value.is_empty() => {
                parsed.scope.folder = Some(value.trim_matches('"').to_string());
            }
            Some(("tag" | "#", value)) if !value.is_empty() => {
                parsed.scope.tag = Some(value.trim_matches('"').to_ascii_lowercase());
            }
            Some(("is", value)) if value.eq_ignore_ascii_case("favorite") => {
                parsed.scope.favorites_only = true;
            }
            _ => {
                if let Some(tag) = token.strip_prefix('#') {
                    if !tag.is_empty() {
                        parsed.scope.tag = Some(tag.to_ascii_lowercase());
                        continue;
                    }
                }
                words.push(token.to_ascii_lowercase());
            }
        }
    }

    parsed.text = words.join(" ");
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_has_no_scope() {
        let q = parse("prod web");
        assert_eq!(q.text, "prod web");
        assert!(q.scope.is_empty());
    }

    #[test]
    fn prefixes_are_extracted_and_removed() {
        let q = parse("type:ssh folder:clients/acme tag:production billing");
        assert_eq!(q.text, "billing");
        assert_eq!(q.scope.record_type, Some(RecordType::SshServer));
        assert_eq!(q.scope.folder.as_deref(), Some("clients/acme"));
        assert_eq!(q.scope.tag.as_deref(), Some("production"));
    }

    #[test]
    fn partial_type_names_resolve() {
        assert_eq!(parse("type:ssh").scope.record_type, Some(RecordType::SshServer));
        assert_eq!(parse("type:api").scope.record_type, Some(RecordType::ApiKey));
        assert_eq!(parse("type:rdp").scope.record_type, Some(RecordType::RdpHost));
    }

    #[test]
    fn hash_is_shorthand_for_tag() {
        assert_eq!(parse("#production").scope.tag.as_deref(), Some("production"));
    }

    #[test]
    fn a_stray_colon_is_just_text() {
        let q = parse("note:to self");
        assert!(q.text.contains("note:to"));
        assert!(q.scope.is_empty());
    }
}
