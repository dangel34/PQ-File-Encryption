//! Stealth-mode tests: `encrypt_stream_stealth`/`decrypt_stream_stealth` omit
//! the `.pqf` magic, version byte, and KEM variant field entirely, so the
//! output should not begin with `PQFL`, should round-trip correctly for every
//! KEM variant (including hybrid), should reject a wrong-variant key, and
//! should compose with Padmé padding.

use pqfile::decrypt::decrypt_stream_stealth;
use pqfile::encrypt::encrypt_stream_stealth;
use pqfile::format::{BASE_NONCE_LEN, KEM_CT_LEN_768};
use pqfile::keygen::{keygen_bytes, keygen_bytes_hybrid_768};
use pqfile::padding::{padme_length, PadmeReader, TruncatingWriter};

const MAGIC: &[u8; 4] = b"PQFL";
const PLAINTEXT: &[u8] = b"stealth mode test payload, long enough to span more than one byte";

#[test]
fn stealth_roundtrip_768() {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(
        &pub_pem,
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();

    assert_ne!(&ct[..4], MAGIC, "stealth output must not start with PQFL");

    let mut out = Vec::new();
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
    assert_eq!(out, PLAINTEXT);
}

#[test]
fn stealth_roundtrip_all_kem_variants() {
    for level in [512, 768, 1024] {
        let (pub_pem, priv_pem) = keygen_bytes(level, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream_stealth(
            &pub_pem,
            PLAINTEXT.len() as u64,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, PLAINTEXT, "level={level}");
    }
}

#[test]
fn stealth_roundtrip_hybrid() {
    let (pub_pem, priv_pem) = keygen_bytes_hybrid_768(None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(
        &pub_pem,
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();
    let mut out = Vec::new();
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
    assert_eq!(out, PLAINTEXT);
}

#[test]
fn stealth_wrong_key_type_fails() {
    let (pub_pem, _) = keygen_bytes(768, None).unwrap();
    let (_, priv_512) = keygen_bytes(512, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(
        &pub_pem,
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();

    let mut out = Vec::new();
    let result = decrypt_stream_stealth(&priv_512, &mut ct.as_slice(), &mut out, None);
    assert!(
        result.is_err(),
        "decrypting with a wrong-variant key must fail"
    );
}

#[test]
fn stealth_wrong_key_same_variant_fails() {
    let (pub1, _) = keygen_bytes(768, None).unwrap();
    let (_, priv2) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(&pub1, PLAINTEXT.len() as u64, &mut { PLAINTEXT }, &mut ct).unwrap();

    let mut out = Vec::new();
    let result = decrypt_stream_stealth(&priv2, &mut ct.as_slice(), &mut out, None);
    assert!(
        result.is_err(),
        "decrypting with an unrelated key must fail"
    );
}

#[test]
fn stealth_tamper_is_rejected() {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(
        &pub_pem,
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();

    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    let mut out = Vec::new();
    let result = decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None);
    assert!(
        result.is_err(),
        "tampered stealth ciphertext must fail decryption"
    );
}

#[test]
fn stealth_wire_length_matches_expected_layout() {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(
        &pub_pem,
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();

    // KEM_CT + BASE_NONCE(8) + ORIGINAL_SIZE(8) + single chunk (plaintext + 16-byte tag).
    let expected = KEM_CT_LEN_768 + BASE_NONCE_LEN + 8 + PLAINTEXT.len() + 16;
    assert_eq!(ct.len(), expected);

    let mut out = Vec::new();
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
    assert_eq!(out, PLAINTEXT);
}

#[test]
fn stealth_composes_with_padme_padding() {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let real_len = PLAINTEXT.len() as u64;
    let padded_len = padme_length(real_len);
    assert!(padded_len >= real_len);

    let mut ct = Vec::new();
    {
        let mut padded_reader = PadmeReader::new(PLAINTEXT, real_len);
        // The header keeps recording the *real* length; the physical stream is padded.
        encrypt_stream_stealth(&pub_pem, real_len, &mut padded_reader, &mut ct).unwrap();
    }

    let expected = KEM_CT_LEN_768 + BASE_NONCE_LEN + 8 + padded_len as usize + 16;
    assert_eq!(
        ct.len(),
        expected,
        "ciphertext should reflect the padded length"
    );

    // decrypt_stream_stealth truncates to the header's original_size
    // automatically, so the padding tail never reaches the caller.
    let mut out = Vec::new();
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
    assert_eq!(out, PLAINTEXT);
}

#[test]
fn stealth_truncating_writer_wrap_is_a_noop_on_top() {
    // decrypt_stream_stealth already truncates internally; wrapping the
    // caller's writer with a TruncatingWriter at the same (or a looser)
    // limit must not change the result.
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(
        &pub_pem,
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();

    let mut writer = TruncatingWriter::new(Vec::new(), PLAINTEXT.len() as u64);
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut writer, None).unwrap();
    assert_eq!(writer.into_inner(), PLAINTEXT);
}

#[test]
fn stealth_empty_plaintext_roundtrip() {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream_stealth(&pub_pem, 0, &mut [].as_ref(), &mut ct).unwrap();
    let mut out = Vec::new();
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
    assert!(out.is_empty());
}

#[test]
fn stealth_multi_chunk_roundtrip() {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let plaintext: Vec<u8> = (0u8..=255)
        .cycle()
        .take(pqfile::CHUNK_SIZE * 2 + 137)
        .collect();
    let mut ct = Vec::new();
    encrypt_stream_stealth(
        &pub_pem,
        plaintext.len() as u64,
        &mut plaintext.as_slice(),
        &mut ct,
    )
    .unwrap();
    let mut out = Vec::new();
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
    assert_eq!(out, plaintext);
}
