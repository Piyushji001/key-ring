//! Correctness of seal/open and wrap/unwrap.

use keyring_crypto::{
    aead, envelope, generate_dek, insecure_test_params, kdf, keys::DerivedKey, CryptoError,
};

fn key(byte: u8) -> DerivedKey {
    DerivedKey::from_bytes([byte; 32])
}

#[test]
fn seal_then_open_roundtrips() {
    let k = key(1);
    let msg = b"ssh://root@10.0.0.1 hunter2";
    let sealed = aead::seal(&k, msg, b"aad").unwrap();
    let opened = aead::open(&k, &sealed, b"aad").unwrap();
    assert_eq!(&opened[..], msg);
}

#[test]
fn empty_plaintext_roundtrips() {
    let k = key(2);
    let sealed = aead::seal(&k, b"", b"aad").unwrap();
    assert_eq!(sealed.ciphertext.len(), aead::TAG_LEN);
    let opened = aead::open(&k, &sealed, b"aad").unwrap();
    assert!(opened.is_empty());
}

#[test]
fn empty_aad_roundtrips() {
    let k = key(3);
    let sealed = aead::seal(&k, b"payload", b"").unwrap();
    let opened = aead::open(&k, &sealed, b"").unwrap();
    assert_eq!(&opened[..], b"payload");
}

#[test]
#[ignore = "allocates 50 MB; run with --ignored"]
fn fifty_megabyte_plaintext_roundtrips() {
    let k = key(4);
    let msg = vec![0xABu8; 50 * 1024 * 1024];
    let sealed = aead::seal(&k, &msg, b"blob-aad").unwrap();
    let opened = aead::open(&k, &sealed, b"blob-aad").unwrap();
    assert_eq!(opened.len(), msg.len());
    assert_eq!(&opened[..], &msg[..]);
}

#[test]
fn wrong_key_fails() {
    let sealed = aead::seal(&key(1), b"secret", b"aad").unwrap();
    let err = aead::open(&key(2), &sealed, b"aad").unwrap_err();
    assert_eq!(err, CryptoError::Open);
}

#[test]
fn wrong_aad_fails() {
    let k = key(1);
    let sealed = aead::seal(&k, b"secret", b"record-a").unwrap();
    assert!(aead::open(&k, &sealed, b"record-b").is_err());
}

#[test]
fn same_plaintext_sealed_twice_differs() {
    let k = key(5);
    let a = aead::seal(&k, b"identical", b"aad").unwrap();
    let b = aead::seal(&k, b"identical", b"aad").unwrap();
    assert_ne!(a.nonce, b.nonce, "nonce must be fresh per operation");
    assert_ne!(a.ciphertext, b.ciphertext);
}

#[test]
fn one_hundred_thousand_nonces_have_no_collisions() {
    use std::collections::HashSet;
    let mut seen = HashSet::with_capacity(100_000);
    for _ in 0..100_000 {
        let n = keyring_crypto::random_nonce().unwrap();
        assert!(seen.insert(n), "nonce collision");
    }
}

#[test]
fn wrap_then_unwrap_recovers_the_same_dek() {
    let kek = key(9);
    let dek = generate_dek().unwrap();
    let aad = b"serialized header bytes";
    let wrapped = envelope::wrap_dek(&kek, &dek, aad).unwrap();
    let recovered = envelope::unwrap_dek(&kek, &wrapped, aad).unwrap();
    assert!(recovered.ct_eq(&dek));
}

#[test]
fn wrapped_key_has_the_expected_size() {
    let wrapped = envelope::wrap_dek(&key(1), &generate_dek().unwrap(), b"h").unwrap();
    assert_eq!(wrapped.ciphertext.len(), envelope::WRAPPED_LEN);
    assert_eq!(wrapped.nonce.len(), aead::NONCE_LEN);
}

#[test]
fn header_aad_modification_breaks_unwrapping() {
    let kek = key(3);
    let dek = generate_dek().unwrap();
    let header = b"format_version=1;memory_kib=262144;iterations=3";
    let tampered = b"format_version=1;memory_kib=000008;iterations=3";
    let wrapped = envelope::wrap_dek(&kek, &dek, header).unwrap();
    assert!(envelope::unwrap_dek(&kek, &wrapped, tampered).is_err());
}

#[test]
fn wrong_password_produces_a_wrong_kek_and_fails_to_unwrap() {
    let params = insecure_test_params();
    let kek_good = kdf::derive_kek(b"correct horse battery", &params).unwrap();
    let kek_bad = kdf::derive_kek(b"correct horse batterY", &params).unwrap();
    assert!(!kek_good.ct_eq(&kek_bad));

    let dek = generate_dek().unwrap();
    let wrapped = envelope::wrap_dek(&kek_good, &dek, b"hdr").unwrap();
    assert!(envelope::unwrap_dek(&kek_bad, &wrapped, b"hdr").is_err());
}
