//! The in-memory index, built once on unlock.
//!
//! ## Encrypted fields and the note-body problem
//!
//! FR-4.1 says search must cover note bodies. Note bodies are encrypted, so
//! they can only be searched by decrypting them - and decrypting every note on
//! every keystroke is not viable.
//!
//! The resolution: notes are decrypted **once**, at index build time, and only
//! a lowercased copy is retained in the index, in a `Zeroizing` buffer that is
//! wiped when the vault locks. The index therefore holds note text in memory
//! while unlocked, which is the same exposure the vault already has (the DEK is
//! in memory too), and none at all once locked.
//!
//! `SearchIndex` deliberately implements no `Debug` that prints entries.
//! Decision D-20.


use zeroize::Zeroizing;

use crate::db;
use crate::error::Result;
use crate::model::{FieldKind, RecordType};
use crate::vault::session::VaultSession;

use super::query::{self, ParsedQuery};
use super::rank::{self, SearchHit};

/// One record, flattened into the strings a user might type.
pub struct IndexEntry {
    pub record_id: String,
    pub title: String,
    pub record_type: RecordType,
    pub folder: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub used_at: Option<i64>,
    pub use_count: i64,
    /// (field name, lowercased searchable value). Never a secret value, except
    /// note bodies, per the module comment.
    pub fields: Vec<(String, Zeroizing<String>)>,
    pub attachments: Vec<String>,
}

#[derive(Default)]
pub struct SearchIndex {
    entries: Vec<IndexEntry>,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SearchIndex({} entries, contents redacted)", self.entries.len())
    }
}

/// Field names whose encrypted contents are worth decrypting into the index.
/// Deliberately short: a password is not searchable by its value, ever.
const SEARCHABLE_SECRET_FIELDS: [&str; 3] = ["notes", "body", "description"];

impl SearchIndex {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Build from an unlocked session. Called on unlock and after any mutation.
    ///
    /// Cost is dominated by decrypting note bodies, so it is linear in the
    /// number of records that have one.
    pub fn build(session: &VaultSession) -> Result<Self> {
        let conn = session.conn()?;
        let records = db::records::list(conn, &crate::model::RecordFilter::default())?;
        let mut entries = Vec::with_capacity(records.len());

        for record in records {
            let mut fields = Vec::new();

            for field in db::fields::list_for_record(conn, &record.id)? {
                if let Some(plain) = &field.plain_value {
                    if !plain.is_empty() {
                        fields.push((field.name.clone(), Zeroizing::new(plain.to_lowercase())));
                    }
                } else if field.has_secret
                    && SEARCHABLE_SECRET_FIELDS.contains(&field.name.as_str())
                    && matches!(field.kind, FieldKind::Multiline)
                {
                    // The only decryption that happens here. See module comment.
                    if let Ok(bytes) = session.open_secret(&record.id, &field.name) {
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            fields.push((field.name.clone(), Zeroizing::new(text.to_lowercase())));
                        }
                    }
                }
            }

            let attachments = db::attachments::list_for_record(conn, &record.id)?
                .into_iter()
                .map(|a| a.filename.to_lowercase())
                .collect();

            entries.push(IndexEntry {
                tags: db::tags::for_record(conn, &record.id)?,
                record_id: record.id,
                title: record.title,
                record_type: record.record_type,
                folder: record.folder,
                favorite: record.favorite,
                used_at: record.used_at,
                use_count: record.use_count,
                fields,
                attachments,
            });
        }

        Ok(SearchIndex { entries })
    }

    /// Run a query. `limit` caps the result set; the overlay asks for 8, the
    /// main window for a few hundred.
    pub fn search(&self, raw: &str, limit: usize, now: i64) -> Vec<SearchHit> {
        let parsed = query::parse(raw);
        let mut hits: Vec<SearchHit> = Vec::new();

        for entry in &self.entries {
            if !self.in_scope(entry, &parsed) {
                continue;
            }

            let scored = if parsed.text.is_empty() {
                // Empty query with a scope: everything in scope, ordered by use.
                Some((0i64, None, None))
            } else {
                self.best_match(entry, &parsed.text)
            };

            let Some((match_score, matched_field, matched_context)) = scored else {
                continue;
            };

            let score = match_score
                + rank::recency_bonus(entry.used_at, now)
                + rank::frequency_bonus(entry.use_count)
                + if entry.favorite { 60 } else { 0 };

            hits.push(SearchHit {
                record_id: entry.record_id.clone(),
                title: entry.title.clone(),
                record_type: entry.record_type,
                folder: entry.folder.clone(),
                favorite: entry.favorite,
                score,
                matched_field,
                matched_context,
            });
        }

        hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.title.cmp(&b.title)));
        hits.truncate(limit);
        hits
    }

    fn in_scope(&self, entry: &IndexEntry, parsed: &ParsedQuery) -> bool {
        let s = &parsed.scope;
        if let Some(t) = s.record_type {
            if entry.record_type != t {
                return false;
            }
        }
        if let Some(folder) = &s.folder {
            let f = folder.to_ascii_lowercase();
            let entry_folder = entry.folder.to_ascii_lowercase();
            if !(entry_folder == f || entry_folder.starts_with(&format!("{f}/"))) {
                return false;
            }
        }
        if let Some(tag) = &s.tag {
            if !entry.tags.iter().any(|t| t == tag) {
                return false;
            }
        }
        if s.favorites_only && !entry.favorite {
            return false;
        }
        true
    }

    /// The best-scoring field for this entry, and what to show as evidence.
    ///
    /// Title matches are weighted above field matches, because a user typing
    /// "prod" almost always means a record called prod, not one whose username
    /// happens to contain it.
    fn best_match(
        &self,
        entry: &IndexEntry,
        text: &str,
    ) -> Option<(i64, Option<String>, Option<String>)> {
        let mut best: Option<(i64, Option<String>, Option<String>)> = None;

        let mut consider = |score: i64, field: Option<&str>, context: Option<&str>| {
            if best.as_ref().map(|(s, _, _)| score > *s).unwrap_or(true) {
                best = Some((
                    score,
                    field.map(|f| f.to_string()),
                    context.map(|c| c.to_string()),
                ));
            }
        };

        if let Some(score) = rank::fuzzy_score(text, &entry.title) {
            consider(score + 150, None, None);
        }
        if let Some(score) = rank::fuzzy_score(text, &entry.folder) {
            consider(score / 2, Some("folder"), Some(&entry.folder));
        }
        for tag in &entry.tags {
            if let Some(score) = rank::fuzzy_score(text, tag) {
                consider(score / 2 + 40, Some("tag"), Some(tag));
            }
        }
        for (name, value) in &entry.fields {
            if let Some(score) = rank::fuzzy_score(text, value) {
                // Only non-secret values may be shown as context. Note bodies
                // are in the index but must never be echoed into a result row.
                let context = if SEARCHABLE_SECRET_FIELDS.contains(&name.as_str()) {
                    None
                } else {
                    Some(value.as_str())
                };
                consider(score / 2, Some(name), context);
            }
        }
        for filename in &entry.attachments {
            if let Some(score) = rank::fuzzy_score(text, filename) {
                consider(score / 2, Some("attachment"), Some(filename));
            }
        }

        best
    }
}
