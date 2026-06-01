//! Format specification compliance tests -- docs/FORMAT.md section 5.
//!
//! Each test encrypts a known plaintext, parses the output byte-by-byte to
//! verify the field layout matches FORMAT.md, then decrypts and verifies the
//! result. Together these tests act as executable documentation: an alternative
//! implementation can verify byte-level conformance using the assertions below.
//!
//! Run with `cargo test --test vectors -- --nocapture` to print hex output
//! for each format version, usable as reference vectors.

use pqfile::decrypt::decrypt_stream;
use pqfile::encrypt::{
    encrypt_bytes, encrypt_stream, encrypt_stream_multi, encrypt_stream_multi_anon,
};
use pqfile::format::{
    BASE_NONCE_LEN, CHUNK_SIZE, HYBRID_CT_LEN_768, KEM_CT_LEN_1024, KEM_CT_LEN_512, KEM_CT_LEN_768,
    KEM_VARIANT_1024, KEM_VARIANT_512, KEM_VARIANT_768, KEM_VARIANT_HYBRID_768, NONCE_LEN,
    PADDED_CT_LEN, VERSION, VERSION_V3, VERSION_V4, VERSION_V5, VERSION_V7, WRAPPED_KEY_LEN,
};
use pqfile::keygen::{keygen_bytes, keygen_bytes_hybrid_768};

const MAGIC: &[u8; 4] = b"PQFL";
const PLAINTEXT: &[u8] = b"pqfile format test vector";

// ---- byte helpers ----------------------------------------------------------

fn u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

fn u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

fn hex(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---- single-recipient header check -----------------------------------------
//
// Format (v2 / v3 / v5):
//   0     4   MAGIC
//   4     1   VERSION
//   5     2   KEM_VARIANT (u16 LE)
//   7     ?   KEM_CT
//   7+ct  12  NONCE (first 8 bytes random; bytes 8-11 are 0x00 for v3)
//   7+ct+12 8  ORIGINAL_SIZE (u64 LE)

fn check_single_recipient_header(out: &[u8], version: u8, ct_len: usize, kem_variant: u16) {
    assert_eq!(&out[0..4], MAGIC, "magic bytes");
    assert_eq!(out[4], version, "version byte");
    assert_eq!(u16_le(out, 5), kem_variant, "KEM_VARIANT field");

    let nonce_off = 7 + ct_len;
    let size_off = nonce_off + NONCE_LEN;

    assert_eq!(
        u64_le(out, size_off),
        PLAINTEXT.len() as u64,
        "ORIGINAL_SIZE"
    );

    if version == VERSION_V3 || version == VERSION_V5 {
        // BASE_NONCE bytes 8-11 must be zero (counter starts at 0).
        assert_eq!(
            &out[nonce_off + BASE_NONCE_LEN..nonce_off + NONCE_LEN],
            &[0u8; 4],
            "BASE_NONCE counter bytes must be zero"
        );
    }
}

// ---- v2 (whole-file AEAD) --------------------------------------------------

#[test]
fn v2_ml_kem_768() {
    // FORMAT.md §5.1
    // Header: MAGIC(4) | VERSION(1) | KEM_VARIANT(2) | KEM_CT(1088) | NONCE(12) | ORIGINAL_SIZE(8)
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let out = encrypt_bytes(&pub_pem, PLAINTEXT).unwrap();

    check_single_recipient_header(&out, VERSION, KEM_CT_LEN_768, KEM_VARIANT_768);

    // v2 CIPHERTEXT = PLAINTEXT_LEN + 16-byte Poly1305 tag, no chunking
    let header_len = 7 + KEM_CT_LEN_768 + NONCE_LEN + 8;
    assert_eq!(
        out.len(),
        header_len + PLAINTEXT.len() + 16,
        "v2 total size"
    );

    let mut dec = Vec::new();
    decrypt_stream(&priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
    assert_eq!(dec, PLAINTEXT);

    eprintln!(
        "v2/768  {} bytes  header={} payload={}",
        out.len(),
        header_len,
        out.len() - header_len
    );
    eprintln!("  first 16 bytes: {}", hex(&out[..16]));
}

// ---- v3 (64 KiB chunked STREAM) --------------------------------------------

#[test]
fn v3_ml_kem_512() {
    // FORMAT.md §5.2 with KEM_VARIANT=512
    let (pub_pem, priv_pem) = keygen_bytes(512, None).unwrap();
    let mut out = Vec::new();
    encrypt_stream(
        &pub_pem,
        PLAINTEXT.len() as u64,
        CHUNK_SIZE,
        &mut { PLAINTEXT },
        &mut out,
    )
    .unwrap();

    check_single_recipient_header(&out, VERSION_V3, KEM_CT_LEN_512, KEM_VARIANT_512);

    let mut dec = Vec::new();
    decrypt_stream(&priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
    assert_eq!(dec, PLAINTEXT);

    eprintln!("v3/512  {} bytes", out.len());
}

#[test]
fn v3_ml_kem_768() {
    // FORMAT.md §5.2 -- most common format
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut out = Vec::new();
    encrypt_stream(
        &pub_pem,
        PLAINTEXT.len() as u64,
        CHUNK_SIZE,
        &mut { PLAINTEXT },
        &mut out,
    )
    .unwrap();

    check_single_recipient_header(&out, VERSION_V3, KEM_CT_LEN_768, KEM_VARIANT_768);

    // Single chunk: PLAINTEXT + 16-byte tag
    let header_len = 7 + KEM_CT_LEN_768 + NONCE_LEN + 8;
    assert_eq!(
        out.len(),
        header_len + PLAINTEXT.len() + 16,
        "v3 single-chunk size"
    );

    let mut dec = Vec::new();
    decrypt_stream(&priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
    assert_eq!(dec, PLAINTEXT);

    eprintln!("v3/768  {} bytes  header={}", out.len(), header_len);
    eprintln!("  first 16 bytes: {}", hex(&out[..16]));
}

#[test]
fn v3_ml_kem_1024() {
    let (pub_pem, priv_pem) = keygen_bytes(1024, None).unwrap();
    let mut out = Vec::new();
    encrypt_stream(
        &pub_pem,
        PLAINTEXT.len() as u64,
        CHUNK_SIZE,
        &mut { PLAINTEXT },
        &mut out,
    )
    .unwrap();

    check_single_recipient_header(&out, VERSION_V3, KEM_CT_LEN_1024, KEM_VARIANT_1024);

    let mut dec = Vec::new();
    decrypt_stream(&priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
    assert_eq!(dec, PLAINTEXT);

    eprintln!("v3/1024 {} bytes", out.len());
}

#[test]
fn v3_hybrid_x25519_ml_kem_768() {
    // FORMAT.md §2: Hybrid KEM CT = X25519 ephemeral pubkey (32) + ML-KEM-768 CT (1088) = 1120 bytes
    let (pub_pem, priv_pem) = keygen_bytes_hybrid_768(None).unwrap();
    let mut out = Vec::new();
    encrypt_stream(
        &pub_pem,
        PLAINTEXT.len() as u64,
        CHUNK_SIZE,
        &mut { PLAINTEXT },
        &mut out,
    )
    .unwrap();

    check_single_recipient_header(&out, VERSION_V3, HYBRID_CT_LEN_768, KEM_VARIANT_HYBRID_768);

    // KEM_VARIANT for hybrid is 0x0301
    let variant_bytes = out[5..7].to_vec();
    assert_eq!(
        variant_bytes,
        &KEM_VARIANT_HYBRID_768.to_le_bytes(),
        "hybrid variant bytes"
    );

    let mut dec = Vec::new();
    decrypt_stream(&priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
    assert_eq!(dec, PLAINTEXT);

    eprintln!(
        "v3/hybrid {} bytes  KEM_VARIANT={:#06x}",
        out.len(),
        KEM_VARIANT_HYBRID_768
    );
}

// ---- v5 (configurable chunk size) ------------------------------------------

#[test]
fn v5_ml_kem_768_custom_chunk() {
    // FORMAT.md §5.3
    // Header adds CHUNK_SIZE(4) field after ORIGINAL_SIZE.
    // v5 is emitted only when chunk_size != 65536.
    const CUSTOM_CHUNK: usize = 4096;
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    let mut out = Vec::new();
    encrypt_stream(
        &pub_pem,
        PLAINTEXT.len() as u64,
        CUSTOM_CHUNK,
        &mut { PLAINTEXT },
        &mut out,
    )
    .unwrap();

    assert_eq!(&out[0..4], MAGIC);
    assert_eq!(out[4], VERSION_V5, "v5 version byte");
    assert_eq!(u16_le(&out, 5), KEM_VARIANT_768, "KEM_VARIANT");

    let nonce_off = 7 + KEM_CT_LEN_768;
    let size_off = nonce_off + NONCE_LEN;
    let chunk_off = size_off + 8;

    assert_eq!(
        u64_le(&out, size_off),
        PLAINTEXT.len() as u64,
        "ORIGINAL_SIZE"
    );
    assert_eq!(
        u32_le(&out, chunk_off),
        CUSTOM_CHUNK as u32,
        "CHUNK_SIZE field"
    );

    let mut dec = Vec::new();
    decrypt_stream(&priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
    assert_eq!(dec, PLAINTEXT);

    eprintln!("v5/768  {} bytes  CHUNK_SIZE={}", out.len(), CUSTOM_CHUNK);
}

// ---- v6 (compress-then-encrypt) --------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn v6_ml_kem_768_zstd() {
    use pqfile::encrypt::encrypt_stream_compressed;
    use pqfile::format::{
        COMPRESSION_ZSTD, V5_CHUNK_SIZE_FIELD_LEN, V6_COMPRESSION_FIELD_LEN, VERSION_V6,
    };

    // FORMAT.md §5.4
    // Header: ... | CHUNK_SIZE(4) | COMPRESSION_ALGO(1)
    let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
    // Use a compressible plaintext so v6 is always smaller than v3.
    let compressible: Vec<u8> = b"aaaa".iter().cycle().take(4096).cloned().collect();

    let mut out = Vec::new();
    encrypt_stream_compressed(
        &pub_pem,
        compressible.len() as u64,
        CHUNK_SIZE,
        3,
        &mut compressible.as_slice(),
        &mut out,
    )
    .unwrap();

    assert_eq!(&out[0..4], MAGIC);
    assert_eq!(out[4], VERSION_V6, "v6 version byte");
    assert_eq!(u16_le(&out, 5), KEM_VARIANT_768, "KEM_VARIANT");

    let nonce_off = 7 + KEM_CT_LEN_768;
    let size_off = nonce_off + NONCE_LEN;
    let chunk_off = size_off + 8;
    let algo_off = chunk_off + V5_CHUNK_SIZE_FIELD_LEN;

    assert_eq!(
        u64_le(&out, size_off),
        compressible.len() as u64,
        "ORIGINAL_SIZE is uncompressed size"
    );
    assert_eq!(
        u32_le(&out, chunk_off),
        CHUNK_SIZE as u32,
        "CHUNK_SIZE field"
    );
    assert_eq!(
        out[algo_off], COMPRESSION_ZSTD,
        "COMPRESSION_ALGO = 0x01 (zstd)"
    );

    let header_len = nonce_off + NONCE_LEN + 8 + V5_CHUNK_SIZE_FIELD_LEN + V6_COMPRESSION_FIELD_LEN;

    let mut dec = Vec::new();
    decrypt_stream(&priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
    assert_eq!(dec, compressible.as_slice());

    eprintln!(
        "v6/768  {} bytes  header={}  algo=0x{:02x}",
        out.len(),
        header_len,
        COMPRESSION_ZSTD
    );
}

// ---- v4 (multi-recipient) --------------------------------------------------

#[test]
fn v4_ml_kem_768_two_recipients() {
    // FORMAT.md §5.5
    // Header: MAGIC(4) | VERSION(1) | COUNT(2) | [VARIANT(2)|KEM_CT(?)|WRAPPED_KEY(48)]... | NONCE(12) | ORIGINAL_SIZE(8)
    let (pub1, priv1) = keygen_bytes(768, None).unwrap();
    let (pub2, priv2) = keygen_bytes(768, None).unwrap();
    let mut out = Vec::new();
    encrypt_stream_multi(
        &[pub1.as_str(), pub2.as_str()],
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut out,
    )
    .unwrap();

    assert_eq!(&out[0..4], MAGIC);
    assert_eq!(out[4], VERSION_V4, "v4 version byte");

    let count = u16_le(&out, 5) as usize;
    assert_eq!(count, 2, "COUNT = 2 recipients");

    // Each recipient entry for ML-KEM-768: VARIANT(2) + CT(1088) + WRAPPED_KEY(48) = 1138 bytes
    let entry_size = 2 + KEM_CT_LEN_768 + WRAPPED_KEY_LEN;
    assert_eq!(entry_size, 1138, "ML-KEM-768 v4 entry size");

    // Verify both entry variant fields.
    let entry0_off = 7;
    let entry1_off = entry0_off + entry_size;
    assert_eq!(u16_le(&out, entry0_off), KEM_VARIANT_768, "entry 0 variant");
    assert_eq!(u16_le(&out, entry1_off), KEM_VARIANT_768, "entry 1 variant");

    let nonce_off = 7 + count * entry_size;
    let size_off = nonce_off + NONCE_LEN;
    assert_eq!(
        u64_le(&out, size_off),
        PLAINTEXT.len() as u64,
        "ORIGINAL_SIZE"
    );

    // Both recipients can decrypt.
    for priv_pem in [&priv1, &priv2] {
        let mut dec = Vec::new();
        decrypt_stream(priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
        assert_eq!(dec, PLAINTEXT);
    }

    eprintln!(
        "v4/768x2 {} bytes  header={}  entry_size={}",
        out.len(),
        size_off + 8,
        entry_size
    );
}

// ---- v7 (anonymous multi-recipient) ----------------------------------------

#[test]
fn v7_ml_kem_768_two_recipients() {
    // FORMAT.md §5.6
    // All slots are PADDED_CT_LEN (1568) wide; entries are shuffled.
    // Fixed slot: VARIANT(2) + PADDED_CT(1568) + WRAPPED_KEY(48) = 1618 bytes.
    let (pub1, priv1) = keygen_bytes(768, None).unwrap();
    let (pub2, priv2) = keygen_bytes(768, None).unwrap();
    let mut out = Vec::new();
    encrypt_stream_multi_anon(
        &[pub1.as_str(), pub2.as_str()],
        PLAINTEXT.len() as u64,
        &mut { PLAINTEXT },
        &mut out,
    )
    .unwrap();

    assert_eq!(&out[0..4], MAGIC);
    assert_eq!(out[4], VERSION_V7, "v7 version byte");

    let count = u16_le(&out, 5) as usize;
    assert_eq!(count, 2, "COUNT = 2 recipients");

    // Each fixed-width v7 entry: VARIANT(2) + PADDED_CT(1568) + WRAPPED_KEY(48) = 1618 bytes.
    let slot_size = 2 + PADDED_CT_LEN + WRAPPED_KEY_LEN;
    assert_eq!(slot_size, 1618, "v7 fixed slot size");

    // Both variant fields must be KEM_VARIANT_768 (no mixing in this test).
    let entry0_off = 7;
    let entry1_off = entry0_off + slot_size;
    assert_eq!(u16_le(&out, entry0_off), KEM_VARIANT_768, "slot 0 variant");
    assert_eq!(u16_le(&out, entry1_off), KEM_VARIANT_768, "slot 1 variant");

    let nonce_off = 7 + count * slot_size;
    let size_off = nonce_off + NONCE_LEN;
    assert_eq!(
        u64_le(&out, size_off),
        PLAINTEXT.len() as u64,
        "ORIGINAL_SIZE"
    );

    // Both recipients can decrypt regardless of slot order.
    for priv_pem in [&priv1, &priv2] {
        let mut dec = Vec::new();
        decrypt_stream(priv_pem, &mut out.as_slice(), &mut dec, None).unwrap();
        assert_eq!(dec, PLAINTEXT);
    }

    eprintln!(
        "v7/768x2 {} bytes  header={}  slot_size={}",
        out.len(),
        size_off + 8,
        slot_size
    );
}

// ---- cross-version size assertions -----------------------------------------
//
// Sanity-check that the computed header sizes from FORMAT.md match reality.

#[test]
fn header_sizes_match_format_spec() {
    // FORMAT.md §5.1 table:
    //   ML-KEM-512  768 + 7 + 12 + 8 = 795
    //   ML-KEM-768  1088 + 7 + 12 + 8 = 1115
    //   ML-KEM-1024 1568 + 7 + 12 + 8 = 1595
    //   Hybrid 768  1120 + 7 + 12 + 8 = 1147
    let base = |ct: usize| 7 + ct + NONCE_LEN + 8;
    assert_eq!(base(KEM_CT_LEN_512), 795);
    assert_eq!(base(KEM_CT_LEN_768), 1115);
    assert_eq!(base(KEM_CT_LEN_1024), 1595);
    assert_eq!(base(HYBRID_CT_LEN_768), 1147);

    // FORMAT.md §5.5 table for v4 entry sizes:
    //   ML-KEM-512  768 + 2 + 48 = 818
    //   ML-KEM-768  1088 + 2 + 48 = 1138
    //   ML-KEM-1024 1568 + 2 + 48 = 1618
    //   Hybrid 768  1120 + 2 + 48 = 1170
    let entry = |ct: usize| 2 + ct + WRAPPED_KEY_LEN;
    assert_eq!(entry(KEM_CT_LEN_512), 818);
    assert_eq!(entry(KEM_CT_LEN_768), 1138);
    assert_eq!(entry(KEM_CT_LEN_1024), 1618);
    assert_eq!(entry(HYBRID_CT_LEN_768), 1170);

    // v7 fixed slot size = 2 + PADDED_CT_LEN + WRAPPED_KEY_LEN = 1618
    assert_eq!(2 + PADDED_CT_LEN + WRAPPED_KEY_LEN, 1618);
}
