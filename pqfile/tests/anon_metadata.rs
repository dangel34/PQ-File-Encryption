//! Regression coverage for the v8/v9 anonymised-recipient metadata leak: real
//! recipient slots must be padded with random bytes, not zeros, or the
//! deterministic zero suffix left by a shorter KEM ciphertext (each variant
//! has a distinct length) identifies the variant and - against v9's random
//! dummy slots - which slots are real at all, defeating the format's
//! documented metadata-privacy guarantee (docs/FORMAT.md, docs/SECURITY.md).

use pqfile::encrypt::{encrypt_stream_multi_anon, encrypt_stream_multi_anon_padded};
use pqfile::format::{KEM_CT_LEN_768, PADDED_CT_LEN, WRAPPED_KEY_LEN};
use pqfile::keygen::keygen_bytes;

#[test]
fn v8_real_slot_padding_is_not_all_zero() {
    let (public_key, _) = keygen_bytes(768, None).unwrap();

    let mut v8 = Vec::new();
    let mut empty = &b""[..];
    encrypt_stream_multi_anon(&[public_key.as_str()], 0, &mut empty, &mut v8).unwrap();

    assert_eq!(v8[4] & 0x7f, 8);
    let v8_slot = &v8[7..7 + PADDED_CT_LEN];
    // Before the fix this suffix was always zero, deterministically revealing
    // ML-KEM-768's ciphertext length (and, by elimination, its variant).
    assert!(
        v8_slot[KEM_CT_LEN_768..].iter().any(|&b| b != 0),
        "real slot's padding suffix must not be all-zero"
    );
}

#[test]
fn v9_real_slots_are_not_distinguishable_from_dummies_by_zero_padding() {
    let (public_key, _) = keygen_bytes(768, None).unwrap();

    // Three real ML-KEM-768 recipients pad to four slots (next power of two).
    let recipients = [
        public_key.as_str(),
        public_key.as_str(),
        public_key.as_str(),
    ];
    let mut v9 = Vec::new();
    let mut empty = &b""[..];
    encrypt_stream_multi_anon_padded(&recipients, 0, &mut empty, &mut v9).unwrap();

    assert_eq!(v9[4] & 0x7f, 9);
    let count = u16::from_le_bytes([v9[5], v9[6]]) as usize;
    assert_eq!(count, 4);

    let slot_len = PADDED_CT_LEN + WRAPPED_KEY_LEN;
    let zero_padded_count = (0..count)
        .filter(|&i| {
            let start = 7 + i * slot_len;
            let padded_ct = &v9[start..start + PADDED_CT_LEN];
            padded_ct[KEM_CT_LEN_768..].iter().all(|&b| b == 0)
        })
        .count();

    // Before the fix, exactly the 3 real slots had an all-zero suffix
    // (probability of a random dummy matching by chance is 2^-3840), exactly
    // revealing the real recipient count. Now every slot - real or dummy -
    // is fully random, so none should classify as zero-padded.
    assert_eq!(
        zero_padded_count, 0,
        "no slot (real or dummy) should have an all-zero padding suffix"
    );
}
