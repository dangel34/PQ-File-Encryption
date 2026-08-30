//! Regression coverage: multi-recipient encryption with zero recipient public
//! keys must be rejected up front, not silently produce a `.pqf` file whose
//! session key is wrapped for nobody and can never be decrypted by any key.

use pqfile::encrypt::{
    encrypt_stream_multi, encrypt_stream_multi_anon, encrypt_stream_multi_anon_padded,
    encrypt_stream_multi_anon_padded_with_progress, encrypt_stream_multi_anon_with_progress,
    MultiEncryptBuilder,
};
use pqfile::PqfileError;

#[test]
fn v4_rejects_zero_recipients() {
    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err = encrypt_stream_multi(&[], 9, &mut input, &mut ct).unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));
    assert!(ct.is_empty(), "no bytes should be written on rejection");
}

#[test]
fn v8_rejects_zero_recipients() {
    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err = encrypt_stream_multi_anon(&[], 9, &mut input, &mut ct).unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));
    assert!(ct.is_empty());
}

#[test]
fn v9_rejects_zero_recipients() {
    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err = encrypt_stream_multi_anon_padded(&[], 9, &mut input, &mut ct).unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));
    assert!(ct.is_empty());
}

#[test]
fn progress_wrappers_reject_zero_recipients() {
    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err = encrypt_stream_multi_anon_with_progress(&[], 9, &mut input, &mut ct, &|_, _| {})
        .unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));

    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err =
        encrypt_stream_multi_anon_padded_with_progress(&[], 9, &mut input, &mut ct, &|_, _| {})
            .unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));
}

#[test]
fn multi_encrypt_builder_rejects_zero_recipients() {
    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err = MultiEncryptBuilder::new(&[])
        .encrypt(9, &mut input, &mut ct)
        .unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));

    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err = MultiEncryptBuilder::new(&[])
        .anonymous()
        .encrypt(9, &mut input, &mut ct)
        .unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));

    let mut input = &b"important"[..];
    let mut ct = Vec::new();
    let err = MultiEncryptBuilder::new(&[])
        .padded()
        .encrypt(9, &mut input, &mut ct)
        .unwrap_err();
    assert!(matches!(err, PqfileError::NoRecipients));
}
