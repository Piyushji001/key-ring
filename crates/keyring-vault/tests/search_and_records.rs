//! Phase 4 acceptance tests.

use keyring_vault::search::SearchIndex;
use keyring_vault::{db, OpenMode, RecordType, VaultSession};

const PW: &[u8] = b"correct horse battery staple";

fn vault(dir: &std::path::Path) -> VaultSession {
    let mut params = keyring_vault::KdfParams::new_default().unwrap();
    params.memory_kib = keyring_crypto::MIN_MEMORY_KIB;
    params.iterations = 2;
    VaultSession::create(dir, PW, &params, 0).unwrap()
}

fn now() -> i64 {
    keyring_vault::util::time::now_unix()
}

#[test]
fn search_finds_records_by_title_field_tag_and_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());

    let ssh = v
        .create_record(
            RecordType::SshServer,
            "prod-web-01",
            "clients/acme/prod",
            &[
                ("host".into(), "10.20.1.14".into()),
                ("username".into(), "deploy".into()),
                ("password".into(), "never-searchable".into()),
            ],
        )
        .unwrap();
    v.add_tag(&ssh, "production").unwrap();

    v.create_record(
        RecordType::ApiKey,
        "Stripe live",
        "clients/acme",
        &[("provider".into(), "Stripe".into())],
    )
    .unwrap();
    v.save().unwrap();

    let index = SearchIndex::build(&v).unwrap();

    assert_eq!(index.search("prod-web", 10, now())[0].record_id, ssh);
    assert_eq!(index.search("deploy", 10, now())[0].record_id, ssh);
    assert_eq!(index.search("10.20", 10, now())[0].record_id, ssh);
    assert_eq!(index.search("#production", 10, now())[0].record_id, ssh);
    assert_eq!(index.search("stripe", 10, now())[0].title, "Stripe live");
    assert_eq!(index.search("folder:clients/acme", 10, now()).len(), 2);
    assert_eq!(index.search("type:ssh", 10, now()).len(), 1);
}

#[test]
fn secret_values_are_never_searchable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());
    v.create_record(
        RecordType::WebLogin,
        "client portal",
        "",
        &[("password".into(), "zebrastripe".into())],
    )
    .unwrap();
    v.save().unwrap();

    let index = SearchIndex::build(&v).unwrap();
    assert!(
        index.search("zebrastripe", 10, now()).is_empty(),
        "a password was findable by its own value"
    );
}

#[test]
fn note_bodies_are_searchable_but_never_echoed() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());
    v.create_record(
        RecordType::SecureNote,
        "datacentre access",
        "",
        &[("body".into(), "gate code is by the loading bay".into())],
    )
    .unwrap();
    v.save().unwrap();

    let index = SearchIndex::build(&v).unwrap();
    let hits = index.search("loading bay", 10, now());
    assert_eq!(hits.len(), 1, "FR-4.1 requires note bodies to be searchable");
    assert!(
        hits[0].matched_context.is_none(),
        "note body content leaked into a result row"
    );
}

#[test]
fn recently_used_records_rank_first() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());

    let old = v
        .create_record(RecordType::SshServer, "web-alpha", "", &[])
        .unwrap();
    let recent = v
        .create_record(RecordType::SshServer, "web-beta", "", &[])
        .unwrap();
    v.mark_used(&recent).unwrap();
    v.save().unwrap();

    let index = SearchIndex::build(&v).unwrap();
    let hits = index.search("web", 10, now());
    assert_eq!(hits[0].record_id, recent);
    assert_eq!(hits[1].record_id, old);
}

#[test]
fn search_of_ten_thousand_records_is_under_fifty_milliseconds() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());

    for i in 0..10_000 {
        v.create_record(
            RecordType::SshServer,
            &format!("host-{i:05}"),
            "bulk",
            &[
                ("host".into(), format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)),
                ("username".into(), "root".into()),
            ],
        )
        .unwrap();
    }
    v.save().unwrap();

    let index = SearchIndex::build(&v).unwrap();
    assert_eq!(index.len(), 10_000);

    // Warm, then measure. FR-4.3.
    let _ = index.search("host", 200, now());
    let start = std::time::Instant::now();
    let hits = index.search("host-042", 200, now());
    let elapsed = start.elapsed();

    assert!(!hits.is_empty());
    assert!(
        elapsed.as_millis() < 50,
        "search took {elapsed:?}, budget is 50ms"
    );
}

#[test]
fn trash_restore_and_purge_behave() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());
    let id = v
        .create_record(RecordType::SecureNote, "disposable", "", &[])
        .unwrap();

    v.trash_record(&id).unwrap();
    assert_eq!(db::records::count(v.conn().unwrap()).unwrap(), 0);
    assert!(SearchIndex::build(&v).unwrap().search("disposable", 5, now()).is_empty());

    v.restore_record(&id).unwrap();
    assert_eq!(db::records::count(v.conn().unwrap()).unwrap(), 1);

    v.purge_record(&id).unwrap();
    assert!(db::records::get(v.conn().unwrap(), &id).unwrap().is_none());
}

#[test]
fn duplicating_a_record_re_encrypts_rather_than_copying_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());
    let original = v
        .create_record(
            RecordType::Database,
            "billing-db",
            "clients/acme",
            &[
                ("host".into(), "db-01".into()),
                ("password".into(), "shared-value".into()),
            ],
        )
        .unwrap();

    let copy = v.duplicate_record(&original, "billing-db (staging)").unwrap();
    assert_eq!(&v.open_secret(&copy, "password").unwrap()[..], b"shared-value");

    // Different record ids mean different AAD, so the ciphertext must differ
    // even though the plaintext is identical.
    let conn = v.conn().unwrap();
    let ct = |id: &str| -> Vec<u8> {
        conn.query_row(
            "SELECT ciphertext FROM fields WHERE record_id = ?1 AND name = 'password'",
            [id],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_ne!(ct(&original), ct(&copy));
}

#[test]
fn a_locked_vault_cannot_be_indexed() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = vault(tmp.path());
    v.create_record(RecordType::SecureNote, "secret plans", "", &[])
        .unwrap();
    v.save().unwrap();

    v.lock(keyring_vault::LockReason::Manual);
    assert!(SearchIndex::build(&v).is_err());
}

#[test]
fn reopening_preserves_records_and_the_index_rebuilds() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut v = vault(tmp.path());
        for i in 0..25 {
            v.create_record(
                RecordType::ApiKey,
                &format!("key-{i:02}"),
                "providers",
                &[("provider".into(), format!("provider-{i}"))],
            )
            .unwrap();
        }
        v.save().unwrap();
    }

    let v = VaultSession::open(tmp.path(), PW, OpenMode::ReadWrite).unwrap();
    let index = SearchIndex::build(&v).unwrap();
    assert_eq!(index.len(), 25);
    assert_eq!(index.search("key-07", 5, now())[0].title, "key-07");
}
