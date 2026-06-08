//! WASM smoke tests - compiled and executed only on wasm32 targets via `wasm-pack test --node`.
//!
//! Run locally with:
//!   wasm-pack test --node pqfile --test wasm_smoke
#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test;

// No browser API needed; globalThis.crypto is available in Node.js >= 19 and all browsers.

#[wasm_bindgen_test]
fn encrypt_bytes_decrypt_bytes_roundtrip() {
    let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(768, None).unwrap();
    let plaintext = b"hello, post-quantum WASM";
    let ct = pqfile::encrypt::encrypt_bytes(&pub_pem, plaintext).unwrap();
    let recovered = pqfile::decrypt::decrypt_bytes(&priv_pem, &ct, None).unwrap();
    assert_eq!(recovered, plaintext);
}

#[wasm_bindgen_test]
fn keygen_512_roundtrip() {
    let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(512, None).unwrap();
    let plaintext = b"ml-kem-512 wasm roundtrip";
    let ct = pqfile::encrypt::encrypt_bytes(&pub_pem, plaintext).unwrap();
    let out = pqfile::decrypt::decrypt_bytes(&priv_pem, &ct, None).unwrap();
    assert_eq!(out, plaintext);
}

#[wasm_bindgen_test]
fn keygen_1024_roundtrip() {
    let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(1024, None).unwrap();
    let plaintext = b"ml-kem-1024 wasm roundtrip";
    let ct = pqfile::encrypt::encrypt_bytes(&pub_pem, plaintext).unwrap();
    let out = pqfile::decrypt::decrypt_bytes(&priv_pem, &ct, None).unwrap();
    assert_eq!(out, plaintext);
}

#[wasm_bindgen_test]
fn wrong_key_fails() {
    let (pub1, _priv1) = pqfile::keygen::keygen_bytes(768, None).unwrap();
    let (_pub2, priv2) = pqfile::keygen::keygen_bytes(768, None).unwrap();
    let ct = pqfile::encrypt::encrypt_bytes(&pub1, b"secret").unwrap();
    let result = pqfile::decrypt::decrypt_bytes(&priv2, &ct, None);
    assert!(result.is_err());
}
