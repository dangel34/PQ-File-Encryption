//! Authenticated-header tests: files written with `VERSION_AUTH_BIT` bind the
//! non-self-healing header fields (chunk_size, compression_algo, v10 KDF fields)
//! into the chunk-0 key commitment, so tampering with any of them — or with the
//! bit itself — must fail authentication. Legacy files (bit clear) keep
//! decrypting via the v2 commitment; the cross-version fixtures in
//! `tests/compat.rs` cover that half.

use pqfile::decrypt::{decrypt_stream, decrypt_stream_passphrase};
use pqfile::encrypt::{encrypt_stream, encrypt_stream_passphrase};
use pqfile::format::{
    is_header_authenticated, version_layout, CHUNK_SIZE, COMPRESSION_NONE, KEM_CT_LEN_768,
    NONCE_LEN, VERSION_AUTH_BIT, VERSION_V3, VERSION_V4,
};
use pqfile::keygen::keygen_bytes;

const PLAINTEXT: &[u8] = b"authenticated header test payload";

/// Byte offset of the version byte in every `.pqf` header.
const VERSION_OFF: usize = 4;

/// Header length of a single-recipient v3/v5/v6 file up to (not including) the
/// v5/v6 extension fields: MAGIC(4) + VERSION(1) + KEM_VARIANT(2) + CT + NONCE(12) + SIZE(8).
fn single_header_base(ct_len: usize) -> usize {
    4 + 1 + 2 + ct_len + NONCE_LEN + 8
}

fn encrypt_768(chunk_size: usize) -> (Vec<u8>, String) {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream(
        &pub_pem,
        PLAINTEXT.len() as u64,
        chunk_size,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();
    (ct, priv_pem)
}

#[test]
fn new_files_carry_the_auth_bit() {
    let (ct, priv_pem) = encrypt_768(CHUNK_SIZE);
    assert!(is_header_authenticated(ct[VERSION_OFF]));
    assert_eq!(version_layout(ct[VERSION_OFF]), VERSION_V3);

    let mut out = Vec::new();
    decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
    assert_eq!(out, PLAINTEXT);
}

#[test]
fn auth_bit_strip_is_rejected() {
    let (mut ct, priv_pem) = encrypt_768(CHUNK_SIZE);
    // An attacker downgrading the file to the legacy commitment must not succeed:
    // the two commitment definitions use different domain-separation contexts.
    ct[VERSION_OFF] &= !VERSION_AUTH_BIT;
    let mut out = Vec::new();
    let result = decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None);
    assert!(result.is_err(), "stripped auth bit must fail decryption");
}

#[test]
fn auth_bit_added_to_legacy_file_is_rejected() {
    // v3_512.pqf is a stored pre-auth-bit fixture (version byte 0x03).
    let mut ct = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/compat/v3_512.pqf"
    ))
    .unwrap();
    let priv_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/compat/v3_512.priv.pem"
    ))
    .unwrap();
    assert!(!is_header_authenticated(ct[VERSION_OFF]));
    ct[VERSION_OFF] |= VERSION_AUTH_BIT;
    let mut out = Vec::new();
    let result = decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None);
    assert!(
        result.is_err(),
        "adding the auth bit to a legacy file must fail decryption"
    );
}

#[test]
fn v5_chunk_size_tamper_is_rejected() {
    let (mut ct, priv_pem) = encrypt_768(4096);
    let chunk_size_off = single_header_base(KEM_CT_LEN_768);
    assert_eq!(
        u32::from_le_bytes(ct[chunk_size_off..chunk_size_off + 4].try_into().unwrap()),
        4096
    );
    ct[chunk_size_off..chunk_size_off + 4].copy_from_slice(&8192u32.to_le_bytes());
    let mut out = Vec::new();
    let result = decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None);
    assert!(result.is_err(), "tampered chunk_size must fail decryption");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn v6_compression_flag_flip_is_rejected() {
    use pqfile::encrypt::encrypt_stream_compressed;
    // The headline attack this feature closes: flipping zstd -> none on a v6 file
    // previously delivered the compressed bytes as "plaintext" with every AEAD
    // tag still verifying.
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    // Compressible plaintext spanning multiple chunks.
    let plaintext: Vec<u8> = (0u8..=63).cycle().take(CHUNK_SIZE + 100).collect();
    let mut ct = Vec::new();
    encrypt_stream_compressed(
        &pub_pem,
        plaintext.len() as u64,
        CHUNK_SIZE,
        3,
        &mut plaintext.as_slice(),
        &mut ct,
    )
    .unwrap();

    let algo_off = single_header_base(KEM_CT_LEN_768) + 4;
    assert_ne!(ct[algo_off], COMPRESSION_NONE, "fixture must be compressed");
    ct[algo_off] = COMPRESSION_NONE;

    let mut out = Vec::new();
    let result = decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None);
    assert!(
        result.is_err(),
        "flipped compression flag must fail decryption, not emit compressed bytes"
    );
    assert_ne!(out, plaintext);
}

#[test]
fn v10_kdf_param_tamper_is_rejected() {
    let mut ct = Vec::new();
    encrypt_stream_passphrase(
        "hunter2",
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();
    assert!(is_header_authenticated(ct[VERSION_OFF]));

    // v10 header: MAGIC(4) VERSION(1) SALT(16) M(4) T(4) P(4) FLAGS(1) NONCE(12) SIZE(8).
    let t_off = 4 + 1 + 16 + 4;
    let t = u32::from_le_bytes(ct[t_off..t_off + 4].try_into().unwrap());
    ct[t_off..t_off + 4].copy_from_slice(&(t - 1).to_le_bytes());

    let mut out = Vec::new();
    let result = decrypt_stream_passphrase("hunter2", &mut ct.as_slice(), &mut out);
    assert!(
        result.is_err(),
        "tampered Argon2 t_cost must fail decryption"
    );
}

#[test]
fn rekey_preserves_auth_bit_and_decrypts() {
    let (pub_old, priv_old) = keygen_bytes(768, None).unwrap();
    let (pub_new, priv_new) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    encrypt_stream(
        &pub_old,
        PLAINTEXT.len() as u64,
        CHUNK_SIZE,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();
    assert!(is_header_authenticated(ct[VERSION_OFF]));

    let mut rekeyed = Vec::new();
    pqfile::rekey::rekey_stream(&priv_old, &pub_new, &mut ct.as_slice(), &mut rekeyed, None)
        .unwrap();
    assert!(is_header_authenticated(rekeyed[VERSION_OFF]));
    assert_eq!(version_layout(rekeyed[VERSION_OFF]), VERSION_V4);

    let mut out = Vec::new();
    decrypt_stream(&priv_new, &mut rekeyed.as_slice(), &mut out, None).unwrap();
    assert_eq!(out, PLAINTEXT);
}

#[test]
fn add_recipient_preserves_auth_bit_and_decrypts() {
    let (pub1, priv1) = keygen_bytes(768, None).unwrap();
    let (pub2, priv2) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    pqfile::encrypt::encrypt_stream_multi(
        &[pub1.as_str()],
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut ct,
    )
    .unwrap();
    assert!(is_header_authenticated(ct[VERSION_OFF]));

    let mut with_new = Vec::new();
    pqfile::add_recipient::add_recipient_stream(
        &priv1,
        &pub2,
        &mut ct.as_slice(),
        &mut with_new,
        None,
    )
    .unwrap();
    assert!(is_header_authenticated(with_new[VERSION_OFF]));

    for priv_pem in [&priv1, &priv2] {
        let mut out = Vec::new();
        decrypt_stream(priv_pem, &mut with_new.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, PLAINTEXT);
    }
}

#[test]
fn legacy_fixture_with_bit_variants_reports_clean_errors() {
    // A hypothetical authenticated v2 (0x82) does not exist and must be rejected
    // with UnsupportedVersion rather than misparsed.
    let mut ct = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/compat/v2_768.pqf"
    ))
    .unwrap();
    let priv_pem = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/compat/v2_768.priv.pem"
    ))
    .unwrap();
    ct[VERSION_OFF] |= VERSION_AUTH_BIT;
    let mut out = Vec::new();
    let result = decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None);
    assert!(matches!(
        result,
        Err(pqfile::error::PqfileError::UnsupportedVersion(0x82))
    ));
}
