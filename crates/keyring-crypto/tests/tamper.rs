//! Every tampering case must fail loudly. None may panic.

use keyring_crypto::{aead, envelope, generate_dek, keys::DerivedKey, SealedBlob};

fn key(byte: u8) -> DerivedKey {
    DerivedKey::from_bytes([byte; 32])
}

const MSG: &[u8] = b"AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI";
const AAD: &[u8] = b"record:1234|field:secret_key|v1";

fn sealed() -> SealedBlob {
    aead::seal(&key(1), MSG, AAD).unwrap()
}

#[test]
fn flipping_any_bit_of_the_ciphertext_body_fails() {
    let base = sealed();
    let body_len = base.ciphertext.len() - aead::TAG_LEN;
    for byte_idx in 0..body_len {
        for bit in 0..8 {
            let mut s = base.clone();
            s.ciphertext[byte_idx] ^= 1 << bit;
            assert!(
                aead::open(&key(1), &s, AAD).is_err(),
                "bit {bit} of ciphertext byte {byte_idx} was not detected"
            );
        }
    }
}

#[test]
fn flipping_any_bit_of_the_auth_tag_fails() {
    let base = sealed();
    let start = base.ciphertext.len() - aead::TAG_LEN;
    for byte_idx in start..base.ciphertext.len() {
        for bit in 0..8 {
            let mut s = base.clone();
            s.ciphertext[byte_idx] ^= 1 << bit;
            assert!(aead::open(&key(1), &s, AAD).is_err());
        }
    }
}

#[test]
fn flipping_any_bit_of_the_nonce_fails() {
    let base = sealed();
    for byte_idx in 0..aead::NONCE_LEN {
        for bit in 0..8 {
            let mut s = base.clone();
            s.nonce[byte_idx] ^= 1 << bit;
            assert!(aead::open(&key(1), &s, AAD).is_err());
        }
    }
}

#[test]
fn truncated_ciphertext_errors_without_panicking() {
    let base = sealed();
    for cut in 0..base.ciphertext.len() {
        let mut s = base.clone();
        s.ciphertext.truncate(cut);
        assert!(aead::open(&key(1), &s, AAD).is_err());
    }
}

#[test]
fn extended_ciphertext_errors() {
    let mut s = sealed();
    s.ciphertext.push(0x00);
    assert!(aead::open(&key(1), &s, AAD).is_err());
}

#[test]
fn from_parts_rejects_bad_lengths() {
    assert!(SealedBlob::from_parts(&[0u8; 23], &[0u8; 32]).is_err());
    assert!(SealedBlob::from_parts(&[0u8; 24], &[0u8; 15]).is_err());
    assert!(SealedBlob::from_parts(&[0u8; 24], &[0u8; 16]).is_ok());
}

#[test]
fn flipping_any_bit_of_the_wrapped_dek_fails() {
    let kek = key(2);
    let dek = generate_dek().unwrap();
    let base = envelope::wrap_dek(&kek, &dek, b"hdr").unwrap();

    for byte_idx in 0..base.ciphertext.len() {
        for bit in 0..8 {
            let mut w = base.clone();
            w.ciphertext[byte_idx] ^= 1 << bit;
            assert!(envelope::unwrap_dek(&kek, &w, b"hdr").is_err());
        }
    }
    for byte_idx in 0..base.nonce.len() {
        let mut w = base.clone();
        w.nonce[byte_idx] ^= 0x01;
        assert!(envelope::unwrap_dek(&kek, &w, b"hdr").is_err());
    }
}

#[test]
fn wrapped_key_from_parts_rejects_bad_lengths() {
    assert!(envelope::WrappedKey::from_parts(&[0u8; 24], &[0u8; 47]).is_err());
    assert!(envelope::WrappedKey::from_parts(&[0u8; 23], &[0u8; 48]).is_err());
    assert!(envelope::WrappedKey::from_parts(&[0u8; 24], &[0u8; 48]).is_ok());
}

#[test]
fn error_messages_never_distinguish_failure_causes() {
    let wrong_key = aead::open(&key(9), &sealed(), AAD).unwrap_err();
    let mut corrupt = sealed();
    corrupt.ciphertext[0] ^= 0xFF;
    let corrupted = aead::open(&key(1), &corrupt, AAD).unwrap_err();

    // Same rendered message: no decryption oracle.
    assert_eq!(wrong_key.to_string(), corrupted.to_string());
    assert_eq!(wrong_key.user_message(), corrupted.user_message());
}
