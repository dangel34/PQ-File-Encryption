//! Cross-version backward-compatibility tests.
//!
//! Each test decrypts a golden ciphertext file from `pqfile/tests/compat/` that
//! was produced by a specific format version and verifies the output matches
//! `plaintext.bin`. These files are committed to the repository; if a decryptor
//! change breaks any of them, this suite catches the regression immediately.
//!
//! To regenerate the golden files after a deliberate wire-format change:
//!   cargo run --example gen_compat_vectors -p pqfile
//! Commit the updated files alongside any format code changes.

use std::path::Path;

use pqfile::decrypt::{
    decrypt_stream, decrypt_stream_passphrase, decrypt_stream_passphrase_keyfile,
    decrypt_stream_stealth,
};

const COMPAT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/compat");

/// Must match the passphrase baked into `examples/gen_compat_vectors.rs`.
const PASSPHRASE: &str = "pqfile compat vector passphrase";

fn plaintext() -> Vec<u8> {
    std::fs::read(Path::new(COMPAT_DIR).join("plaintext.bin")).expect("plaintext.bin missing")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(COMPAT_DIR).join(name))
        .unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

fn decrypt_one(ct_name: &str, key_name: &str) -> Vec<u8> {
    let ct = read(ct_name);
    let priv_pem = String::from_utf8(read(key_name)).unwrap();
    let mut out = Vec::new();
    decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None)
        .unwrap_or_else(|e| panic!("decrypt {ct_name} with {key_name}: {e}"));
    out
}

#[test]
fn compat_v2_768() {
    assert_eq!(decrypt_one("v2_768.pqf", "v2_768.priv.pem"), plaintext());
}

#[test]
fn compat_v3_512() {
    assert_eq!(decrypt_one("v3_512.pqf", "v3_512.priv.pem"), plaintext());
}

#[test]
fn compat_v3_1024() {
    assert_eq!(decrypt_one("v3_1024.pqf", "v3_1024.priv.pem"), plaintext());
}

#[test]
fn compat_v3_hybrid() {
    assert_eq!(
        decrypt_one("v3_hybrid.pqf", "v3_hybrid.priv.pem"),
        plaintext()
    );
}

#[test]
fn compat_v4_multi_recipient1() {
    assert_eq!(
        decrypt_one("v4_multi.pqf", "v4_multi.priv1.pem"),
        plaintext()
    );
}

#[test]
fn compat_v4_multi_recipient2() {
    assert_eq!(
        decrypt_one("v4_multi.pqf", "v4_multi.priv2.pem"),
        plaintext()
    );
}

#[test]
fn compat_v5_custom_chunk() {
    assert_eq!(decrypt_one("v5_8k.pqf", "v5_8k.priv.pem"), plaintext());
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn compat_v6_zstd() {
    assert_eq!(decrypt_one("v6_zstd.pqf", "v6_zstd.priv.pem"), plaintext());
}

#[test]
fn compat_v8_anon_recipient1() {
    assert_eq!(decrypt_one("v8_anon.pqf", "v8_anon.priv1.pem"), plaintext());
}

#[test]
fn compat_v8_anon_recipient2() {
    assert_eq!(decrypt_one("v8_anon.pqf", "v8_anon.priv2.pem"), plaintext());
}

#[test]
fn compat_v8_anon_recipient3() {
    assert_eq!(decrypt_one("v8_anon.pqf", "v8_anon.priv3.pem"), plaintext());
}

#[test]
fn compat_v9_padded_recipient1() {
    assert_eq!(
        decrypt_one("v9_padded.pqf", "v9_padded.priv1.pem"),
        plaintext()
    );
}

#[test]
fn compat_v9_padded_recipient2() {
    assert_eq!(
        decrypt_one("v9_padded.pqf", "v9_padded.priv2.pem"),
        plaintext()
    );
}

#[test]
fn compat_v9_padded_recipient3() {
    assert_eq!(
        decrypt_one("v9_padded.pqf", "v9_padded.priv3.pem"),
        plaintext()
    );
}

#[test]
fn compat_v10_passphrase() {
    let ct = read("v10_passphrase.pqf");
    let mut out = Vec::new();
    decrypt_stream_passphrase(PASSPHRASE, &mut ct.as_slice(), &mut out)
        .expect("decrypt v10_passphrase.pqf");
    assert_eq!(out, plaintext());
}

#[test]
fn compat_v10_keyfile() {
    let ct = read("v10_keyfile.pqf");
    let keyfile = read("v10_keyfile.bin");
    let mut out = Vec::new();
    decrypt_stream_passphrase_keyfile(PASSPHRASE, &keyfile, &mut ct.as_slice(), &mut out)
        .expect("decrypt v10_keyfile.pqf");
    assert_eq!(out, plaintext());
}

#[test]
fn compat_v10_keyfile_required() {
    // The flags byte (bit 0) must make a keyfile-less decrypt fail fast.
    let ct = read("v10_keyfile.pqf");
    let mut out = Vec::new();
    decrypt_stream_passphrase(PASSPHRASE, &mut ct.as_slice(), &mut out)
        .expect_err("v10_keyfile.pqf must not decrypt without its keyfile");
    assert!(out.is_empty(), "no plaintext may be emitted");
}

#[test]
fn compat_stealth_768() {
    // No magic/version/variant on the wire: the committed private key is the
    // decryptor's only source of parameters, as in real stealth-mode use.
    let ct = read("stealth_768.pqf");
    let priv_pem = String::from_utf8(read("stealth_768.priv.pem")).unwrap();
    let mut out = Vec::new();
    decrypt_stream_stealth(&priv_pem, &mut ct.as_slice(), &mut out, None)
        .expect("decrypt stealth_768.pqf");
    assert_eq!(out, plaintext());
}

#[test]
fn compat_padme_768() {
    // The padded vector's plaintext differs from plaintext.bin: its length was
    // chosen so padme_length(len) > len, otherwise this test would lock in
    // nothing. Locks in both halves of the padding contract: the header's
    // original_size is the true length, and capping decrypt output at that
    // field (as the CLI does via TruncatingWriter) recovers the exact input.
    let padme_plain = read("padme_plaintext.bin");
    let ct = read("padme_768.pqf");
    let priv_pem = String::from_utf8(read("padme_768.priv.pem")).unwrap();

    let original_size =
        match pqfile::inspect::inspect_stream(&mut ct.as_slice()).expect("inspect padme_768.pqf") {
            pqfile::inspect::PqfHeaderInfo::Single { original_size, .. } => original_size,
            other => panic!("padme_768.pqf should be a single-recipient header, got {other:?}"),
        };
    assert_eq!(
        original_size,
        padme_plain.len() as u64,
        "header original_size must be the true (unpadded) length"
    );

    let mut writer = pqfile::padding::TruncatingWriter::new(Vec::new(), original_size);
    decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut writer, None)
        .expect("decrypt padme_768.pqf");
    assert_eq!(writer.into_inner(), padme_plain);
}
