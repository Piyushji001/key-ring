//! Property tests. seal -> open must be the identity for every input.

use keyring_crypto::{aead, envelope, generate_dek, keys::DerivedKey};
use proptest::prelude::*;

fn key_from(bytes: [u8; 32]) -> DerivedKey {
    DerivedKey::from_bytes(bytes)
}

proptest! {
    // 10,000 cycles as required by the Phase 1 checklist.
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn seal_open_is_identity(
        key_bytes in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        aad in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let k = key_from(key_bytes);
        let sealed = aead::seal(&k, &plaintext, &aad).unwrap();
        let opened = aead::open(&k, &sealed, &aad).unwrap();
        prop_assert_eq!(&opened[..], &plaintext[..]);
    }

    #[test]
    fn open_with_a_different_key_never_succeeds(
        key_a in any::<[u8; 32]>(),
        key_b in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(key_a != key_b);
        let sealed = aead::seal(&key_from(key_a), &plaintext, b"aad").unwrap();
        prop_assert!(aead::open(&key_from(key_b), &sealed, b"aad").is_err());
    }

    #[test]
    fn open_with_a_different_aad_never_succeeds(
        key_bytes in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        aad_a in proptest::collection::vec(any::<u8>(), 0..64),
        aad_b in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        prop_assume!(aad_a != aad_b);
        let k = key_from(key_bytes);
        let sealed = aead::seal(&k, &plaintext, &aad_a).unwrap();
        prop_assert!(aead::open(&k, &sealed, &aad_b).is_err());
    }

    #[test]
    fn any_single_byte_mutation_is_detected(
        key_bytes in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 1..256),
        index in 0usize..64,
        xor in 1u8..=255,
    ) {
        let k = key_from(key_bytes);
        let mut sealed = aead::seal(&k, &plaintext, b"aad").unwrap();
        let i = index % sealed.ciphertext.len();
        sealed.ciphertext[i] ^= xor;
        prop_assert!(aead::open(&k, &sealed, b"aad").is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn wrap_unwrap_is_identity(
        kek_bytes in any::<[u8; 32]>(),
        header in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let kek = key_from(kek_bytes);
        let dek = generate_dek().unwrap();
        let wrapped = envelope::wrap_dek(&kek, &dek, &header).unwrap();
        let recovered = envelope::unwrap_dek(&kek, &wrapped, &header).unwrap();
        prop_assert!(recovered.ct_eq(&dek));
    }

    #[test]
    fn any_header_mutation_breaks_unwrapping(
        kek_bytes in any::<[u8; 32]>(),
        header in proptest::collection::vec(any::<u8>(), 1..256),
        index in 0usize..256,
        xor in 1u8..=255,
    ) {
        let kek = key_from(kek_bytes);
        let dek = generate_dek().unwrap();
        let wrapped = envelope::wrap_dek(&kek, &dek, &header).unwrap();

        let mut tampered = header.clone();
        let i = index % tampered.len();
        tampered[i] ^= xor;

        prop_assert!(envelope::unwrap_dek(&kek, &wrapped, &tampered).is_err());
    }
}
