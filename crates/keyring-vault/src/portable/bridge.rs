//! The join between [`PortableRecord`] and a live [`VaultSession`].
//!
//! Kept out of `session.rs` on purpose. Import and export are the two
//! operations that move plaintext in bulk, and having them in their own file
//! means an auditor can read every line that does so without reading the
//! nine-hundred-line session module around it.
//!
//! Both directions go through the ordinary encrypted accessors —
//! `set_field` and `open_secret`. Nothing here touches the DEK, constructs an
//! AAD, or calls the crypto crate. If a future change makes it need to, that
//! is the signal that something has gone wrong.

use zeroize::Zeroizing;

use crate::db;
use crate::error::{Result, VaultError};
use crate::model::{NewRecord, RecordFilter};
use crate::vault::session::VaultSession;

use super::export::{folder_matches, ExportSummary};
use super::import::{ImportReport, ImportSource, SkipReason, SkippedRow};
use super::{PortableField, PortableRecord};

/// Read records out of the vault into portable form.
///
/// **This decrypts every secret in the selection.** It is called by exactly
/// two paths — encrypted export and, behind the confirmation gate, plaintext
/// export — and the result must not outlive the write that consumes it.
pub fn collect(session: &VaultSession, folder: Option<&str>) -> Result<Vec<PortableRecord>> {
    let conn = session.conn()?;
    let rows = db::records::list(conn, &RecordFilter::default())?;

    let mut out = Vec::new();
    for row in rows {
        // The trash is not exported. A record the user deleted should not
        // reappear in a client handover.
        if row.deleted_at.is_some() {
            continue;
        }
        if let Some(wanted) = folder {
            if !folder_matches(&row.folder, wanted) {
                continue;
            }
        }

        let mut record = PortableRecord {
            title: row.title.clone(),
            record_type: row.record_type.as_str().to_string(),
            folder: row.folder.clone(),
            tags: db::tags::for_record(conn, &row.id)?,
            ..Default::default()
        };

        for field in db::fields::list_for_record(conn, &row.id)? {
            let is_secret = field.has_secret;
            let value: Zeroizing<String> = if is_secret {
                let bytes = session.open_secret(&row.id, &field.name)?;
                Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                Zeroizing::new(field.plain_value.clone().unwrap_or_default())
            };

            if value.trim().is_empty() {
                continue;
            }
            record.fields.push(PortableField {
                name: field.name.clone(),
                label: field.label.clone(),
                value,
                secret: is_secret,
            });
        }

        // Attachments are not exported. Documented rather than silent: see
        // `ExportSummary::attachments_excluded`.
        out.push(record);
    }

    Ok(out)
}

/// How many attachments the selection holds, so the export summary can say so.
pub fn count_attachments(session: &VaultSession, folder: Option<&str>) -> Result<usize> {
    let conn = session.conn()?;
    let rows = db::records::list(conn, &RecordFilter::default())?;
    let mut total = 0;
    for row in rows {
        if row.deleted_at.is_some() {
            continue;
        }
        if let Some(wanted) = folder {
            if !folder_matches(&row.folder, wanted) {
                continue;
            }
        }
        total += db::attachments::list_for_record(conn, &row.id)?.len();
    }
    Ok(total)
}

pub fn summarize(
    records: &[PortableRecord],
    format: &str,
    folder: Option<String>,
    bytes_written: u64,
    attachments_excluded: usize,
) -> ExportSummary {
    ExportSummary {
        format: format.to_string(),
        record_count: records.len(),
        field_count: records.iter().map(|r| r.fields.len()).sum(),
        folder,
        bytes_written,
        attachments_excluded,
    }
}

/// Write portable records into the vault.
///
/// One save at the end rather than one per record: an import of four hundred
/// records would otherwise rewrite and fsync the whole container four hundred
/// times. Everything up to that point happens against the in-memory database,
/// so a failure partway leaves the vault on disk exactly as it was.
pub fn apply(
    session: &mut VaultSession,
    parsed: Vec<(usize, PortableRecord)>,
    source: ImportSource,
    into_folder: Option<&str>,
    skip_duplicates: bool,
    attachments_dropped: usize,
) -> Result<ImportReport> {
    let mut report = ImportReport {
        source: source.as_str().to_string(),
        parsed: parsed.len(),
        imported: 0,
        skipped: Vec::new(),
        type_counts: Vec::new(),
        attachments_dropped,
    };

    // Existing (folder, title) pairs, for duplicate detection. Built once:
    // querying per row turns an import into an O(n²) table scan.
    let existing: std::collections::HashSet<(String, String)> = {
        let conn = session.conn()?;
        db::records::list(conn, &RecordFilter::default())?
            .into_iter()
            .map(|r| (r.folder, r.title))
            .collect()
    };

    let mut seen_in_this_import: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    let mut type_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (row_number, record) in parsed {
        if !record.is_substantive() {
            report.skipped.push(SkippedRow {
                row: row_number,
                title: record.title.clone(),
                reason: SkipReason::Empty,
            });
            continue;
        }

        let folder = match into_folder {
            Some(prefix) if !prefix.is_empty() => {
                if record.folder.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{prefix}/{}", record.folder)
                }
            }
            _ => record.folder.clone(),
        };

        let key = (folder.clone(), record.title.clone());
        if (skip_duplicates && existing.contains(&key)) || seen_in_this_import.contains(&key) {
            report.skipped.push(SkippedRow {
                row: row_number,
                title: record.title.clone(),
                reason: SkipReason::Duplicate,
            });
            continue;
        }

        let rtype = record.resolved_type();
        let new = NewRecord {
            record_type: rtype,
            title: record.title.clone(),
            folder: folder.clone(),
            favorite: false,
        };

        let record_id = {
            let conn = session.conn()?;
            db::records::insert(conn, &new)?
        };

        // Fields go through `set_field`, which consults the type template and
        // D-8's name heuristic to decide encryption. An imported password is
        // therefore encrypted by exactly the code that encrypts a typed one.
        for field in &record.fields {
            session.set_field(&record_id, &field.name, &field.value)?;
        }

        for tag in &record.tags {
            let conn = session.conn()?;
            db::tags::add(conn, &record_id, tag)?;
        }

        seen_in_this_import.insert(key);
        *type_counts.entry(rtype.as_str().to_string()).or_insert(0) += 1;
        report.imported += 1;
    }

    let mut counts: Vec<(String, usize)> = type_counts.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    report.type_counts = counts;

    if report.imported > 0 {
        let conn = session.conn()?;
        db::activity::record(
            conn,
            db::activity::Action::Imported,
            None,
            Some(&format!(
                "{} records from {}",
                report.imported,
                source.as_str()
            )),
        )?;
        // The single save for the whole import.
        session.touch();
        session.save()?;
    }

    Ok(report)
}

/// Import an encrypted Keyring export back into a vault.
pub fn apply_encrypted_export(
    session: &mut VaultSession,
    bytes: &[u8],
    passphrase: &str,
    into_folder: Option<&str>,
) -> Result<ImportReport> {
    let records = super::export::open_encrypted(bytes, passphrase)?;
    if records.is_empty() {
        return Err(VaultError::Invalid(
            "That export contains no records.".into(),
        ));
    }
    let numbered = records.into_iter().enumerate().map(|(i, r)| (i + 1, r)).collect();
    apply(
        session,
        numbered,
        ImportSource::BitwardenJson,
        into_folder,
        true,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portable::PortableField;

    fn open_test_vault(dir: &std::path::Path) -> VaultSession {
        // Same approach as the Phase 2 suite: the weakest parameters the
        // strength policy still accepts, so tests are fast without the policy
        // being switched off.
        let mut params = keyring_crypto::KdfParams::new_default().unwrap();
        params.memory_kib = keyring_crypto::MIN_MEMORY_KIB;
        params.iterations = 2;
        VaultSession::create(dir, b"correct horse battery staple", &params, 0).unwrap()
    }

    fn portable(title: &str, folder: &str, password: &str) -> PortableRecord {
        let mut r = PortableRecord {
            title: title.into(),
            record_type: "web_login".into(),
            folder: folder.into(),
            ..Default::default()
        };
        r.push(PortableField::new("username", "Username", "admin", false));
        r.push(PortableField::new("password", "Password", password, true));
        r
    }

    #[test]
    fn imported_secrets_are_encrypted_not_stored_in_plain_value() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = open_test_vault(tmp.path());

        let report = apply(
            &mut session,
            vec![(1, portable("Acme", "Clients", "hunter2"))],
            ImportSource::KeePassCsv,
            None,
            true,
            0,
        )
        .unwrap();
        assert_eq!(report.imported, 1);

        let conn = session.conn().unwrap();
        let rows = db::records::list(conn, &RecordFilter::default()).unwrap();
        let id = rows[0].id.clone();
        let fields = db::fields::list_for_record(conn, &id).unwrap();

        let password = fields.iter().find(|f| f.name == "password").unwrap();
        assert!(password.has_secret, "must be encrypted");
        assert!(
            password.plain_value.is_none(),
            "an imported password must never land in the searchable column"
        );

        let opened = session.open_secret(&id, "password").unwrap();
        assert_eq!(&*opened, b"hunter2");
    }

    #[test]
    fn duplicates_are_skipped_and_reported_not_merged() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = open_test_vault(tmp.path());

        apply(
            &mut session,
            vec![(1, portable("Acme", "Clients", "one"))],
            ImportSource::KeePassCsv,
            None,
            true,
            0,
        )
        .unwrap();

        let report = apply(
            &mut session,
            vec![(1, portable("Acme", "Clients", "two"))],
            ImportSource::KeePassCsv,
            None,
            true,
            0,
        )
        .unwrap();

        assert_eq!(report.imported, 0);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].reason, SkipReason::Duplicate);
    }

    #[test]
    fn skip_reports_never_contain_field_values() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = open_test_vault(tmp.path());
        let empty = PortableRecord {
            title: "Header row".into(),
            ..Default::default()
        };

        let report = apply(
            &mut session,
            vec![(2, empty)],
            ImportSource::KeePassCsv,
            None,
            true,
            0,
        )
        .unwrap();

        let json = serde_json::to_string(&report.skipped).unwrap();
        assert!(json.contains("Header row"));
        assert!(!json.contains("value"));
    }

    #[test]
    fn a_target_folder_prefixes_the_source_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = open_test_vault(tmp.path());

        apply(
            &mut session,
            vec![(1, portable("Acme", "Clients", "pw"))],
            ImportSource::KeePassCsv,
            Some("Imported"),
            true,
            0,
        )
        .unwrap();

        let conn = session.conn().unwrap();
        let rows = db::records::list(conn, &RecordFilter::default()).unwrap();
        assert_eq!(rows[0].folder, "Imported/Clients");
    }

    #[test]
    fn collect_round_trips_a_secret_and_respects_the_folder_filter() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = open_test_vault(tmp.path());

        apply(
            &mut session,
            vec![
                (1, portable("Acme", "Clients/Acme", "acme-pw")),
                (2, portable("Other", "Clients/Other", "other-pw")),
            ],
            ImportSource::KeePassCsv,
            None,
            true,
            0,
        )
        .unwrap();

        let all = collect(&session, None).unwrap();
        assert_eq!(all.len(), 2);

        let subset = collect(&session, Some("Clients/Acme")).unwrap();
        assert_eq!(subset.len(), 1);
        assert_eq!(subset[0].title, "Acme");
        assert_eq!(&*subset[0].field("password").unwrap().value, "acme-pw");
        assert!(subset[0].field("password").unwrap().secret);
    }

    #[test]
    fn trashed_records_are_never_exported() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = open_test_vault(tmp.path());
        apply(
            &mut session,
            vec![(1, portable("Acme", "Clients", "pw"))],
            ImportSource::KeePassCsv,
            None,
            true,
            0,
        )
        .unwrap();

        let id = {
            let conn = session.conn().unwrap();
            db::records::list(conn, &RecordFilter::default()).unwrap()[0]
                .id
                .clone()
        };
        session.trash_record(&id).unwrap();

        assert!(collect(&session, None).unwrap().is_empty());
    }
}
