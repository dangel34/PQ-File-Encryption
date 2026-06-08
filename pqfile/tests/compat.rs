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

use pqfile::decrypt::decrypt_stream;

const COMPAT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/compat");

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
