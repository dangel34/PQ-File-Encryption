//! Regression coverage: a v10 header's Argon2id `p_cost` must be checked
//! against a ceiling before the KDF runs, same as `m_kib`/`t_cost`. Before
//! this fix, an attacker-controlled (and, at this point in decryption,
//! unauthenticated) `p_cost` flowed straight into Argon2id with no bound.

use pqfile::decrypt::decrypt_stream_passphrase;
use pqfile::encrypt::encrypt_stream_passphrase_with_params;
use pqfile::PqfileError;

#[test]
fn decrypt_rejects_p_cost_above_the_compiled_ceiling_before_running_argon2() {
    // m=64 KiB (Argon2's own minimum for p=5 is 8*p=40 KiB), t=1: kept
    // minimal so if the ceiling check *didn't* fire and Argon2 actually ran,
    // the test would still finish quickly rather than hang - the assertion
    // below is what actually proves it didn't run.
    let mut ct = Vec::new();
    let mut empty = &b""[..];
    encrypt_stream_passphrase_with_params(
        "correct horse",
        64,
        1,
        5, // one above the compiled-in default of 4
        0,
        &mut empty,
        &mut ct,
    )
    .unwrap();

    let mut out = Vec::new();
    let err = decrypt_stream_passphrase("correct horse", &mut ct.as_slice(), &mut out).unwrap_err();
    assert!(
        matches!(
            err,
            PqfileError::KdfParallelismLimitExceeded { p: 5, max_p: 4 }
        ),
        "expected KdfParallelismLimitExceeded{{p: 5, max_p: 4}}, got {err:?}"
    );
    assert!(
        out.is_empty(),
        "no plaintext should be written on rejection"
    );
}

#[test]
fn decrypt_accepts_p_cost_at_the_compiled_ceiling() {
    let mut ct = Vec::new();
    let mut empty = &b""[..];
    encrypt_stream_passphrase_with_params("correct horse", 64, 1, 4, 0, &mut empty, &mut ct)
        .unwrap();

    let mut out = Vec::new();
    decrypt_stream_passphrase("correct horse", &mut ct.as_slice(), &mut out).unwrap();
}
