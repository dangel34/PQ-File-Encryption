//! Regression coverage: single-recipient encoders must reject an
//! out-of-range `original_size` or `chunk_size` themselves, mirroring the
//! exact bounds the header reader enforces, instead of returning `Ok` and
//! producing a `.pqf` file pqfile's own reader then rejects.

use pqfile::encrypt::{encrypt_stream, encrypt_stream_compressed};
use pqfile::format::MAX_CHUNK_SIZE;
use pqfile::keygen::keygen_bytes;
use pqfile::writer::PqfWriter;

#[test]
fn encrypt_stream_rejects_oversized_original_size() {
    let (public_key, _) = keygen_bytes(768, None).unwrap();
    let mut input = &b""[..];
    let mut ct = Vec::new();
    let result = encrypt_stream(
        &public_key,
        (1u64 << 40) + 1, // MAX_ORIGINAL_SIZE + 1
        pqfile::CHUNK_SIZE,
        &mut input,
        &mut ct,
    );
    assert!(result.is_err(), "oversized original_size must be rejected");
    assert!(ct.is_empty(), "no bytes should be written on rejection");
}

#[test]
fn encrypt_stream_rejects_oversized_chunk_size() {
    let (public_key, _) = keygen_bytes(768, None).unwrap();
    let mut input = &b""[..];
    let mut ct = Vec::new();
    let result = encrypt_stream(
        &public_key,
        0,
        MAX_CHUNK_SIZE as usize + 1,
        &mut input,
        &mut ct,
    );
    assert!(result.is_err(), "oversized chunk_size must be rejected");
    assert!(ct.is_empty());
}

#[cfg(target_pointer_width = "64")]
#[test]
fn encrypt_stream_rejects_chunk_size_above_u32_max_without_truncating() {
    let (public_key, _) = keygen_bytes(768, None).unwrap();
    let mut input = &b""[..];
    let mut ct = Vec::new();
    // Before the fix, `chunk_size as u32` silently truncated this to 0 and
    // the subsequent `chunk_size == 0` check never re-ran on the cast value.
    let oversized = u32::MAX as usize + 1;
    let result = encrypt_stream(&public_key, 0, oversized, &mut input, &mut ct);
    assert!(result.is_err());
    assert!(ct.is_empty());
}

#[test]
fn encrypt_stream_compressed_rejects_oversized_original_size() {
    let (public_key, _) = keygen_bytes(768, None).unwrap();
    let mut input = &b""[..];
    let mut ct = Vec::new();
    let result = encrypt_stream_compressed(
        &public_key,
        (1u64 << 40) + 1,
        pqfile::CHUNK_SIZE,
        3,
        &mut input,
        &mut ct,
    );
    assert!(result.is_err());
    assert!(ct.is_empty());
}

#[test]
fn pqf_writer_new_rejects_oversized_chunk_size() {
    let (public_key, _) = keygen_bytes(768, None).unwrap();
    let mut ct = Vec::new();
    let is_err = PqfWriter::new(&mut ct, &public_key, 0, MAX_CHUNK_SIZE as usize + 1).is_err();
    assert!(is_err);
    assert!(ct.is_empty());
}
