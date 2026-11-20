//! Phase 5 tests that do not need a window.
//!
//! The clipboard cannot be tested here: it is a Windows-wide singleton, so a
//! test would fight whatever the developer had copied at the time. Clipboard
//! behaviour is verified by hand against the Phase 5 checklist, including the
//! `Win+V` check that proves FR-6.4 is actually in effect.

use std::time::Duration;

use keyring_app_lib::actions::clipboard::fingerprint;
use keyring_app_lib::actions::tempfile::TempRegistry;

#[test]
fn extracted_files_are_registered_and_purged() {
    let registry = TempRegistry::new();
    let path = registry
        .extract(
            "service-account.json",
            b"{\"type\":\"service_account\"}",
            Duration::from_secs(300),
        )
        .unwrap();

    assert!(path.exists(), "extraction did not write the file");
    assert_eq!(registry.active().len(), 1);

    registry.purge_all();
    assert!(!path.exists(), "purge left the file on disk");
    assert!(registry.active().is_empty());
}

#[test]
fn expired_files_are_swept() {
    let registry = TempRegistry::new();
    let path = registry
        .extract("expiring.pem", b"-----BEGIN-----", Duration::from_millis(1))
        .unwrap();
    assert!(path.exists());

    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(registry.sweep(), 1);
    assert!(!path.exists(), "sweep did not delete an expired file");
}

#[test]
fn a_live_file_survives_a_sweep() {
    let registry = TempRegistry::new();
    let path = registry
        .extract("long-lived.pem", b"data", Duration::from_secs(600))
        .unwrap();

    assert_eq!(registry.sweep(), 0);
    assert!(path.exists());
    registry.purge_all();
}

#[test]
fn filenames_cannot_escape_the_extraction_directory() {
    let registry = TempRegistry::new();
    let dir = TempRegistry::dir().unwrap();

    for hostile in ["../../evil.txt", "..\\..\\evil.txt", "C:\\Windows\\evil"] {
        let path = registry
            .extract(hostile, b"x", Duration::from_secs(60))
            .unwrap();
        assert!(
            path.starts_with(&dir),
            "a hostile filename escaped the directory: {}",
            path.display()
        );
    }
    registry.purge_all();
}

#[test]
fn the_clipboard_fingerprint_is_not_the_value() {
    let a = fingerprint("hunter2");
    let b = fingerprint("hunter2");
    let c = fingerprint("hunter3");

    assert_eq!(a, b, "fingerprinting must be deterministic");
    assert_ne!(a, c);
    assert_eq!(a.len(), 32);
}
