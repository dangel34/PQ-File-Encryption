//! Property-based tests for core cryptographic invariants.
//!
//! These tests use `proptest` to verify invariants that must hold for every
//! possible input, not just the specific cases covered by unit tests.
//!
//! Run with: `cargo test --test property`

use proptest::prelude::*;

use pqfile::decrypt::decrypt_stream;
use pqfile::encrypt::encrypt_stream;
use pqfile::format::CHUNK_SIZE;
use pqfile::keygen::keygen_bytes;
use pqfile::shamir::{reconstruct_key, split_key};

// ---------------------------------------------------------------------------
// Encrypt / decrypt roundtrip
// ---------------------------------------------------------------------------

// For any plaintext length, encrypt→decrypt recovers the original bytes.
proptest! {
    #[test]
    fn prop_encrypt_decrypt_roundtrip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..=(3 * CHUNK_SIZE + 512))
    ) {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        ).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        prop_assert_eq!(out, plaintext);
    }
}

// Roundtrip with small custom chunk sizes.
proptest! {
    #[test]
    fn prop_encrypt_decrypt_small_chunks(
        plaintext in proptest::collection::vec(any::<u8>(), 0..=2048),
        chunk_size in 16usize..=256,
    ) {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            chunk_size,
            &mut plaintext.as_slice(),
            &mut ct,
        ).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        prop_assert_eq!(out, plaintext);
    }
}

// ---------------------------------------------------------------------------
// Ciphertext integrity: any flip always fails authentication
// ---------------------------------------------------------------------------

// Any single-byte flip in the ciphertext payload must fail authentication.
proptest! {
    // Keep test short: 64-byte plaintext → 1 chunk.
    #[test]
    fn prop_single_byte_flip_fails(
        plaintext in proptest::collection::vec(any::<u8>(), 1..=64),
        flip_offset in 0usize..64,
    ) {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        ).unwrap();

        // The header for ML-KEM-768 v3 is 1139 bytes. Flip within the ciphertext
        // payload (after the header).
        let header_len = ct.len().saturating_sub(plaintext.len() + 16);
        let payload_len = ct.len() - header_len;
        if payload_len == 0 {
            return Ok(());
        }
        let flip_pos = header_len + (flip_offset % payload_len);
        ct[flip_pos] ^= 0xFF;

        let result = decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut Vec::new(), None);
        prop_assert!(result.is_err(), "tampered ciphertext must not decrypt successfully");
    }
}

// ---------------------------------------------------------------------------
// Shamir split / reconstruct
// ---------------------------------------------------------------------------

// Splitting then reconstructing always recovers the original key.
proptest! {
    #[test]
    fn prop_shamir_split_reconstruct(
        threshold in 2u8..=5,
        extra in 0u8..=3,   // total = threshold + extra
    ) {
        let total = threshold + extra;
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();

        let result = split_key(&priv_pem, threshold, total, None).unwrap();
        prop_assert_eq!(result.share_pems.len(), total as usize);

        // Reconstruct using exactly `threshold` shares (always pick the first ones).
        let subset: Vec<&str> = result.share_pems[..threshold as usize]
            .iter().map(|s| s.as_str()).collect();
        let (_, reconstructed_priv) = reconstruct_key(&subset).unwrap();
        prop_assert_eq!(reconstructed_priv, priv_pem);
    }
}

// Fewer shares than threshold must not recover the original key.
proptest! {
    #[test]
    fn prop_shamir_insufficient_shares_gives_wrong_key(
        threshold in 3u8..=5,
    ) {
        let total = threshold;
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        let result = split_key(&priv_pem, threshold, total, None).unwrap();

        // Use threshold - 1 shares.
        let subset: Vec<&str> = result.share_pems[..threshold as usize - 1]
            .iter().map(|s| s.as_str()).collect();
        match reconstruct_key(&subset) {
            Err(_) => {}  // explicit error is fine
            Ok((_, recovered_priv)) => prop_assert_ne!(recovered_priv, priv_pem,
                "reconstructing with too few shares must not recover the key"),
        }
    }
}
