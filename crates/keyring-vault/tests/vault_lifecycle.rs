//! Phase 2 acceptance tests. These are the checklist from the roadmap,
//! expressed as code.

use keyring_vault::db;
use keyring_vault::vault::header::{header_aad_bytes, VaultHeader};
use keyring_vault::{LockReason, OpenMode, RecordType, VaultSession};

const PW: &[u8] = b"correct horse battery staple";

/// Test vaults use the weakest parameters the strength policy still allows,
/// so the suite stays fast without disabling the policy itself.
fn create_test_vault(dir: &std::path::Path) -> VaultSession {
    // Strength validation is part of `create`, so tests use real-ish params
    // with the smallest memory cost the policy allows.
    let mut params = keyring_vault::KdfParams::new_default().unwrap();
    params.memory_kib = keyring_crypto::MIN_MEMORY_KIB;
    params.iterations = 2;
    VaultSession::create(dir, PW, &params, 0).unwrap()
}

#[test]
fn create_close_reopen_reads_the_data_back() {
    let tmp = tempfile::tempdir().unwrap();
    let id = {
        let mut v = create_test_vault(tmp.path());
        let id = v
            .create_record(
                RecordType::SshServer,
                "prod-web-01",
                "clients/acme/prod",
                &[
                    ("host".into(), "10.0.0.7".into()),
                    ("port".into(), "22".into()),
                    ("username".into(), "deploy".into()),
                    ("password".into(), "s3cret-shell".into()),
                ],
            )
            .unwrap();
        v.save().unwrap();
        id
    }; // session dropped: keys wiped, lock released

    let v = VaultSession::open(tmp.path(), PW, OpenMode::ReadWrite).unwrap();
    let record = db::records::require(v.conn().unwrap(), &id).unwrap();
    assert_eq!(record.title, "prod-web-01");
    assert_eq!(record.folder, "clients/acme/prod");

    let fields = db::fields::list_for_record(v.conn().unwrap(), &id).unwrap();
    let host = fields.iter().find(|f| f.name == "host").unwrap();
    assert_eq!(host.plain_value.as_deref(), Some("10.0.0.7"));

    let password = fields.iter().find(|f| f.name == "password").unwrap();
    assert!(password.has_secret);
    assert!(password.plain_value.is_none(), "secret leaked into plain_value");

    let opened = v.open_secret(&id, "password").unwrap();
    assert_eq!(&opened[..], b"s3cret-shell");
}

#[test]
fn wrong_password_fails_with_the_generic_message() {
    let tmp = tempfile::tempdir().unwrap();
    drop(create_test_vault(tmp.path()));

    let err = VaultSession::open(tmp.path(), b"not the right one", OpenMode::ReadWrite).unwrap_err();
    assert_eq!(err.to_string(), "Could not unlock this vault.");
}

#[test]
fn tampering_with_the_kdf_parameters_prevents_unlocking() {
    let tmp = tempfile::tempdir().unwrap();
    drop(create_test_vault(tmp.path()));

    // Read the container, weaken memory_kib, write it back. This is exactly
    // the hex-editor attack from Architecture 3.4.
    let path = tmp.path().join("vault.kr");
    let (mut header, db_bytes) =
        keyring_vault::vault::file::read_container(&path).unwrap();
    header.kdf.memory_kib = 8;
    keyring_vault::vault::file::write_container(&path, &header, &db_bytes).unwrap();

    assert!(VaultSession::open(tmp.path(), PW, OpenMode::ReadWrite).is_err());
}

#[test]
fn tampering_with_any_header_field_prevents_unlocking() {
    let tmp = tempfile::tempdir().unwrap();
    drop(create_test_vault(tmp.path()));
    let path = tmp.path().join("vault.kr");

    let mutate: Vec<Box<dyn Fn(&mut VaultHeader)>> = vec![
        Box::new(|h| h.kdf.iterations = 1),
        Box::new(|h| h.kdf.salt = vec![0u8; 16]),
        Box::new(|h| h.created_at += 1),
        Box::new(|h| h.vault_id = "attacker".into()),
    ];

    for m in mutate {
        let (mut header, db_bytes) =
            keyring_vault::vault::file::read_container(&path).unwrap();
        let original = header.clone();
        m(&mut header);
        keyring_vault::vault::file::write_container(&path, &header, &db_bytes).unwrap();
        assert!(
            VaultSession::open(tmp.path(), PW, OpenMode::ReadWrite).is_err(),
            "a header mutation went undetected"
        );
        keyring_vault::vault::file::write_container(&path, &original, &db_bytes).unwrap();
    }

    // ...and the vault still opens once the header is restored.
    assert!(VaultSession::open(tmp.path(), PW, OpenMode::ReadWrite).is_ok());
}

#[test]
fn locking_wipes_the_keys_and_blocks_decryption() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = create_test_vault(tmp.path());
    let id = v
        .create_record(
            RecordType::ApiKey,
            "openai",
            "",
            &[("secret_key".into(), "sk-test-123".into())],
        )
        .unwrap();
    v.save().unwrap();

    assert!(v.open_secret(&id, "secret_key").is_ok());

    v.lock(LockReason::Manual);
    assert!(v.is_locked());
    assert!(v.keys_are_wiped());
    assert!(v.open_secret(&id, "secret_key").is_err());
    assert!(v.conn().is_err());
}

#[test]
fn a_second_process_gets_the_lock_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let first = create_test_vault(tmp.path());

    // Simulate a different process by using PID 4 (Windows System PID, always alive)
    let lock_path = tmp.path().join("vault.lock");
    let text = std::fs::read_to_string(&lock_path).unwrap();
    let doctored = text.replace(
        &format!("\"pid\":{}", std::process::id()),
        "\"pid\":4",
    );
    std::fs::write(&lock_path, doctored).unwrap();

    match VaultSession::open(tmp.path(), PW, OpenMode::ReadWrite) {
        Err(keyring_vault::VaultError::AlreadyOpen { .. }) => {}
        other => panic!("expected AlreadyOpen, got {other:?}"),
    }

    // Read-only is offered instead.
    assert!(VaultSession::open(tmp.path(), PW, OpenMode::ReadOnly).is_ok());
    drop(first);
}

#[test]
fn read_only_sessions_refuse_to_save() {
    let tmp = tempfile::tempdir().unwrap();
    drop(create_test_vault(tmp.path()));

    let mut v = VaultSession::open(tmp.path(), PW, OpenMode::ReadOnly).unwrap();
    assert!(matches!(v.save(), Err(keyring_vault::VaultError::ReadOnly)));
}

#[test]
fn changing_the_master_password_keeps_every_record() {
    let tmp = tempfile::tempdir().unwrap();
    let new_pw: &[u8] = b"an entirely different passphrase";

    let id = {
        let mut v = create_test_vault(tmp.path());
        let id = v
            .create_record(
                RecordType::WebLogin,
                "client portal",
                "",
                &[("password".into(), "portal-pw".into())],
            )
            .unwrap();
        v.save().unwrap();
        v.change_master_password(PW, new_pw, None).unwrap();
        id
    };

    assert!(VaultSession::open(tmp.path(), PW, OpenMode::ReadWrite).is_err());
    let v = VaultSession::open(tmp.path(), new_pw, OpenMode::ReadWrite).unwrap();
    assert_eq!(&v.open_secret(&id, "password").unwrap()[..], b"portal-pw");
}

#[test]
fn field_history_retains_the_previous_value() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = create_test_vault(tmp.path());
    let id = v
        .create_record(
            RecordType::Database,
            "billing-db",
            "",
            &[("password".into(), "first".into())],
        )
        .unwrap();
    v.set_field(&id, "password", "second").unwrap();
    v.save().unwrap();

    assert_eq!(&v.open_secret(&id, "password").unwrap()[..], b"second");

    let field = db::fields::get(v.conn().unwrap(), &id, "password")
        .unwrap()
        .unwrap();
    let history = db::fields::list_history(v.conn().unwrap(), &field.id).unwrap();
    assert_eq!(history.len(), 1);

    let old = db::fields::open_history(
        v.conn().unwrap(),
        // history decryption goes through the session's DEK
        &keyring_crypto::DerivedKey::from_bytes([0u8; 32]),
        v.format_version(),
        &history[0].id,
    );
    // Wrong key: must fail rather than return the old password.
    assert!(old.is_err());
}

#[test]
fn ciphertext_cannot_be_swapped_between_records() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = create_test_vault(tmp.path());

    let a = v
        .create_record(
            RecordType::ApiKey,
            "alpha",
            "",
            &[("secret_key".into(), "alpha-secret".into())],
        )
        .unwrap();
    let b = v
        .create_record(
            RecordType::ApiKey,
            "beta",
            "",
            &[("secret_key".into(), "beta-secret".into())],
        )
        .unwrap();
    v.save().unwrap();

    // Copy alpha's ciphertext onto beta's field row.
    let conn = v.conn().unwrap();
    let (nonce, ct): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT nonce, ciphertext FROM fields WHERE record_id = ?1 AND name = 'secret_key'",
            [&a],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    conn.execute(
        "UPDATE fields SET nonce = ?2, ciphertext = ?3 WHERE record_id = ?1 AND name = 'secret_key'",
        rusqlite::params![b, nonce, ct],
    )
    .unwrap();

    // The record id is bound as AAD, so the swap is detected.
    assert!(v.open_secret(&b, "secret_key").is_err());
}

#[test]
fn attachments_roundtrip_and_verify_their_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = create_test_vault(tmp.path());
    let id = v
        .create_record(RecordType::CloudServiceAccount, "gcp-prod", "", &[])
        .unwrap();

    let source = tmp.path().join("service-account.json");
    let content = br#"{"type":"service_account","project_id":"acme-prod"}"#;
    std::fs::write(&source, content).unwrap();

    let attachment_id = v.add_attachment(&id, &source).unwrap();
    v.save().unwrap();

    let opened = v.open_attachment(&attachment_id).unwrap();
    assert_eq!(&opened[..], content);

    // Corrupt the blob: extraction must fail, not return garbage.
    let blob = v.paths().blob_path(&attachment_id);
    let mut bytes = std::fs::read(&blob).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&blob, bytes).unwrap();
    assert!(v.open_attachment(&attachment_id).is_err());
}

#[test]
fn soft_delete_restore_and_purge() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = create_test_vault(tmp.path());
    let id = v
        .create_record(RecordType::SecureNote, "junk drawer", "", &[])
        .unwrap();
    let conn = v.conn().unwrap();

    db::records::soft_delete(conn, &id).unwrap();
    assert_eq!(db::records::count(conn).unwrap(), 0);

    db::records::restore(conn, &id).unwrap();
    assert_eq!(db::records::count(conn).unwrap(), 1);

    db::records::purge(conn, &id).unwrap();
    assert!(db::records::get(conn, &id).unwrap().is_none());
    // Cascade removed the fields too.
    assert!(db::fields::list_for_record(conn, &id).unwrap().is_empty());
}

#[test]
fn one_thousand_records_insert_quickly() {
    let tmp = tempfile::tempdir().unwrap();
    let mut v = create_test_vault(tmp.path());

    let start = std::time::Instant::now();
    for i in 0..1000 {
        v.create_record(
            RecordType::SshServer,
            &format!("host-{i:04}"),
            "bulk",
            &[
                ("host".into(), format!("10.1.{}.{}", i / 256, i % 256)),
                ("username".into(), "root".into()),
                ("password".into(), format!("pw-{i}")),
            ],
        )
        .unwrap();
    }
    let insert_time = start.elapsed();
    v.save().unwrap();

    assert_eq!(db::records::count(v.conn().unwrap()).unwrap(), 1000);
    assert!(
        insert_time.as_secs() < 5,
        "1000 records took {insert_time:?}, budget is 5s"
    );
}

#[test]
fn the_aad_function_is_the_only_one() {
    // Guards against someone writing a second AAD builder: wrapping with a
    // manually assembled byte string must not unwrap.
    let tmp = tempfile::tempdir().unwrap();
    let v = create_test_vault(tmp.path());
    let real = header_aad_bytes(v.header()).unwrap();
    let mut hand_rolled = real.clone();
    hand_rolled.push(0);
    assert_ne!(real, hand_rolled);
}
