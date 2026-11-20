//! Known-answer tests.
//!
//! ## READ THIS BEFORE TICKING THE PHASE 1 CHECKBOX
//!
//! The tests below verify *determinism and sensitivity*: that Argon2id is
//! reproducible, and that changing any input changes the output. They do NOT
//! yet verify our output against an independent reference implementation.
//!
//! Roadmap Phase 1 requires "known-answer vectors match the RFC 8439
//! reference". That step is deliberately left for you to do by hand, because
//! a fabricated test vector is worse than no test vector at all: it looks
//! green and proves nothing.
//!
//! To complete it:
//!
//! 1. Take the XChaCha20-Poly1305 vector from
//!    draft-irtf-cfrg-xchacha-03, Appendix A.3 (key, 24-byte nonce, AAD,
//!    plaintext, expected ciphertext + tag).
//! 2. Paste the hex into `xchacha20poly1305_official_vector` below and
//!    remove the `#[ignore]`.
//! 3. Do the same for one Argon2id vector from RFC 9106 in
//!    `argon2id_official_vector`.
//!
//! Verifying a *deterministic* ciphertext requires pinning the nonce, which
//! `seal()` deliberately does not allow. Use the `chacha20poly1305` crate's
//! low-level API directly inside the test - it is the same code path our
//! `seal()` calls, minus the random nonce.

use keyring_crypto::{kdf, insecure_test_params, KdfParams, SALT_LEN};

#[test]
fn argon2id_is_deterministic() {
    let params = insecure_test_params();
    let a = kdf::derive_kek(b"master password", &params).unwrap();
    let b = kdf::derive_kek(b"master password", &params).unwrap();
    assert!(a.ct_eq(&b));
}

#[test]
fn changing_the_salt_changes_the_key() {
    let mut p1 = insecure_test_params();
    p1.salt = [1u8; SALT_LEN];
    let mut p2 = insecure_test_params();
    p2.salt = [2u8; SALT_LEN];
    let a = kdf::derive_kek(b"same password", &p1).unwrap();
    let b = kdf::derive_kek(b"same password", &p2).unwrap();
    assert!(!a.ct_eq(&b));
}

#[test]
fn changing_any_cost_parameter_changes_the_key() {
    let base = insecure_test_params();

    let mut more_memory = base.clone();
    more_memory.memory_kib = base.memory_kib * 2;
    let mut more_time = base.clone();
    more_time.iterations = base.iterations + 1;
    let mut more_lanes = base.clone();
    more_lanes.parallelism = base.parallelism + 1;

    let k0 = kdf::derive_kek(b"pw", &base).unwrap();
    for variant in [more_memory, more_time, more_lanes] {
        let k = kdf::derive_kek(b"pw", &variant).unwrap();
        assert!(!k.ct_eq(&k0), "parameter change did not affect the key");
    }
}

#[test]
fn a_one_character_password_difference_changes_the_key() {
    let p = insecure_test_params();
    let a = kdf::derive_kek(b"correct horse battery staple", &p).unwrap();
    let b = kdf::derive_kek(b"correct horse battery stapl3", &p).unwrap();
    assert!(!a.ct_eq(&b));
}

#[test]
fn unknown_algorithm_is_rejected() {
    let mut p = insecure_test_params();
    p.algorithm = "scrypt".to_string();
    assert!(kdf::derive_kek(b"pw", &p).is_err());
}

#[test]
fn weak_parameters_fail_the_strength_policy() {
    assert!(insecure_test_params().validate_strength().is_err());

    let strong = KdfParams::new_default().unwrap();
    assert!(strong.validate_strength().is_ok());

    let mut below_floor = strong.clone();
    below_floor.memory_kib = keyring_crypto::MIN_MEMORY_KIB - 1;
    assert!(below_floor.validate_strength().is_err());
}

#[test]
#[ignore = "paste the official vector from draft-irtf-cfrg-xchacha-03 A.3 first"]
fn xchacha20poly1305_official_vector() {
    unimplemented!("see the module comment at the top of this file");
}

#[test]
#[ignore = "paste the official vector from RFC 9106 first"]
fn argon2id_official_vector() {
    unimplemented!("see the module comment at the top of this file");
}
