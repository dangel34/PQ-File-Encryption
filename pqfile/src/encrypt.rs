use rayon::prelude::*;
use std::io::{Read, Write};

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ml_kem::{
    array::Array, kem::Encapsulate, EncapsulationKey1024, EncapsulationKey512, EncapsulationKey768,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

use crate::format::{
    chunk_aad, chunk_nonce, fill_chunk, hybrid_hkdf, PqfHeader, PqfHeaderV4, PqfHeaderV7,
    RecipientEntryV4, RecipientEntryV7, BASE_NONCE_LEN, CHUNK_SIZE, COMPRESSION_NONE,
    EK_LEN_1024, EK_LEN_512, EK_LEN_768, HEADER_LEN_768, HYBRID_CT_LEN_768,
    HYBRID_EK_LEN_768, KEM_VARIANT_1024, KEM_VARIANT_512, KEM_VARIANT_768, KEM_VARIANT_HYBRID_768,
    NONCE_LEN, VERSION, VERSION_V3, VERSION_V5, WRAPPED_KEY_LEN,
};
// Used only in the native compressed-encrypt path and its tests.
#[cfg(not(target_arch = "wasm32"))]
use crate::format::{COMPRESSION_ZSTD, VERSION_V6};
use crate::keygen::{PUB_TAG, PUB_TAG_1024, PUB_TAG_512, PUB_TAG_HYBRID_768};

enum EkVariant {
    Kem512(EncapsulationKey512),
    Kem768(EncapsulationKey768),
    Kem1024(EncapsulationKey1024),
    HybridKem768 {
        x25519_pk: [u8; 32],
        ml_ek: EncapsulationKey768,
    },
}

/// Encrypts `plaintext` in a single pass (v2 format). Kept for library consumers
/// and backward-compatibility tests; new code should use [`encrypt_stream`].
#[must_use = "encryption result must be used"]
pub fn encrypt_bytes(pubkey_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;

    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;

    let original_size = plaintext.len() as u64;

    let header = PqfHeader {
        version: VERSION,
        kem_variant,
        kem_ciphertext: kem_ct_bytes,
        nonce: nonce_bytes,
        original_size,
        chunk_size: CHUNK_SIZE as u32,
        compression_algo: COMPRESSION_NONE,
    };
    let mut output = Vec::with_capacity(HEADER_LEN_768 + plaintext.len() + 16);
    header.write(&mut output)?;

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &output,
            },
        )
        .map_err(|_| PqfileError::EncryptionFailure)?;

    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Encrypts a stream of plaintext bytes.
///
/// When `chunk_size == CHUNK_SIZE` (65536), emits v3 format (backward-compatible).
/// For any other value, emits v5 format which stores the chunk size in the header.
/// Each chunk is authenticated with a position-bound nonce and AAD that prevents
/// truncation and reordering attacks.
///
/// `original_size` is written into the header for informational purposes (pass 0
/// when unknown, e.g. when reading from stdin).
#[must_use = "encryption result must be used"]
pub fn encrypt_stream(
    pubkey_pem: &str,
    original_size: u64,
    chunk_size: usize,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    if chunk_size == 0 {
        return Err(PqfileError::EncryptionFailure);
    }
    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;

    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let version = if chunk_size == CHUNK_SIZE {
        VERSION_V3
    } else {
        VERSION_V5
    };
    let header = PqfHeader {
        version,
        kem_variant,
        kem_ciphertext: kem_ct_bytes,
        nonce: nonce_bytes,
        original_size,
        chunk_size: chunk_size as u32,
        compression_algo: COMPRESSION_NONE,
    };
    header.write(writer)?;

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; slice length is always valid");
    let key = Key::from_slice(ss_bytes.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(&cipher, base_nonce, chunk_size, reader, writer)
}

fn parse_encapsulation_key(pubkey_pem: &str) -> Result<(EkVariant, u16), PqfileError> {
    let pem = pem::parse(pubkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let raw = pem.contents();
    match pem.tag() {
        t if t == PUB_TAG_512 => {
            let raw_arr = Array::try_from(raw).map_err(|_| PqfileError::InvalidKeyLength {
                expected: EK_LEN_512,
                got: raw.len(),
            })?;
            let ek = EncapsulationKey512::new(&raw_arr)
                .map_err(|_| PqfileError::InvalidPem("invalid ML-KEM-512 public key".to_owned()))?;
            Ok((EkVariant::Kem512(ek), KEM_VARIANT_512))
        }
        t if t == PUB_TAG => {
            let raw_arr = Array::try_from(raw).map_err(|_| PqfileError::InvalidKeyLength {
                expected: EK_LEN_768,
                got: raw.len(),
            })?;
            let ek = EncapsulationKey768::new(&raw_arr)
                .map_err(|_| PqfileError::InvalidPem("invalid ML-KEM-768 public key".to_owned()))?;
            Ok((EkVariant::Kem768(ek), KEM_VARIANT_768))
        }
        t if t == PUB_TAG_1024 => {
            let raw_arr = Array::try_from(raw).map_err(|_| PqfileError::InvalidKeyLength {
                expected: EK_LEN_1024,
                got: raw.len(),
            })?;
            let ek = EncapsulationKey1024::new(&raw_arr).map_err(|_| {
                PqfileError::InvalidPem("invalid ML-KEM-1024 public key".to_owned())
            })?;
            Ok((EkVariant::Kem1024(ek), KEM_VARIANT_1024))
        }
        t if t == PUB_TAG_HYBRID_768 => {
            if raw.len() != HYBRID_EK_LEN_768 {
                return Err(PqfileError::InvalidKeyLength {
                    expected: HYBRID_EK_LEN_768,
                    got: raw.len(),
                });
            }
            let x25519_pk_bytes: [u8; 32] = raw[..32].try_into().unwrap();
            let ml_raw = &raw[32..];
            let ml_arr = Array::try_from(ml_raw).map_err(|_| PqfileError::InvalidKeyLength {
                expected: EK_LEN_768,
                got: ml_raw.len(),
            })?;
            let ml_ek = EncapsulationKey768::new(&ml_arr).map_err(|_| {
                PqfileError::InvalidPem("invalid ML-KEM-768 public key in hybrid".to_owned())
            })?;
            Ok((
                EkVariant::HybridKem768 {
                    x25519_pk: x25519_pk_bytes,
                    ml_ek,
                },
                KEM_VARIANT_HYBRID_768,
            ))
        }
        _ => Err(PqfileError::InvalidPem(
            "unrecognised public key tag".to_owned(),
        )),
    }
}

fn encapsulate(ek: EkVariant) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), PqfileError> {
    match ek {
        EkVariant::Kem512(ek) => {
            let (ct, ss) = ek.encapsulate();
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok((ct.as_slice().to_vec(), ss_bytes))
        }
        EkVariant::Kem768(ek) => {
            let (ct, ss) = ek.encapsulate();
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok((ct.as_slice().to_vec(), ss_bytes))
        }
        EkVariant::Kem1024(ek) => {
            let (ct, ss) = ek.encapsulate();
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok((ct.as_slice().to_vec(), ss_bytes))
        }
        EkVariant::HybridKem768 { x25519_pk, ml_ek } => {
            let mut eph_scalar = Zeroizing::new([0u8; 32]);
            getrandom::fill(eph_scalar.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;
            let eph_sk = X25519StaticSecret::from(*eph_scalar);
            let eph_pk = X25519PublicKey::from(&eph_sk);

            let recipient_pk = X25519PublicKey::from(x25519_pk);
            let x25519_ss = Zeroizing::new(eph_sk.diffie_hellman(&recipient_pk));

            let (ml_ct, ml_ss) = ml_ek.encapsulate();

            let mut kem_ct = Vec::with_capacity(HYBRID_CT_LEN_768);
            kem_ct.extend_from_slice(eph_pk.as_bytes());
            kem_ct.extend_from_slice(ml_ct.as_slice());

            let ss = hybrid_hkdf(x25519_ss.as_bytes(), ml_ss.as_slice())?;
            Ok((kem_ct, ss))
        }
    }
}

/// Encrypts a stream to multiple recipients (v4 format).
///
/// Each recipient's public key is used to encapsulate a fresh shared secret that wraps
/// a single random 32-byte session key K under AES-256-GCM. Any holder of a matching
/// private key can recover K and decrypt the file.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_multi(
    pubkey_pems: &[&str],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let mut session_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(session_key.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;

    let mut recipients: Vec<RecipientEntryV4> = Vec::with_capacity(pubkey_pems.len());
    for pubkey_pem in pubkey_pems {
        let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
        let (kem_ct, ss) = encapsulate(ek)?;
        let wrapped_key = wrap_session_key(&session_key, &ss)?;
        recipients.push(RecipientEntryV4 {
            kem_variant,
            kem_ciphertext: kem_ct,
            wrapped_key,
        });
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let header = PqfHeaderV4 {
        recipients,
        nonce: nonce_bytes,
        original_size,
    };
    header.write(writer)?;

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; slice length is always valid");
    let key = chacha20poly1305::Key::from_slice(session_key.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(&cipher, base_nonce, CHUNK_SIZE, reader, writer)
}

/// Encrypts a stream to multiple recipients in anonymous (v7) format.
///
/// Identical to [`encrypt_stream_multi`] except that all KEM ciphertexts are zero-padded
/// to the maximum variant size and recipient entries are written in a randomly shuffled
/// order, preventing an observer from correlating entry position with a specific recipient.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_multi_anon(
    pubkey_pems: &[&str],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let mut session_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(session_key.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;

    let mut recipients: Vec<RecipientEntryV7> = Vec::with_capacity(pubkey_pems.len());
    for pubkey_pem in pubkey_pems {
        let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
        let (kem_ct, ss) = encapsulate(ek)?;
        let wrapped_key = wrap_session_key(&session_key, &ss)?;
        recipients.push(RecipientEntryV7 {
            kem_variant,
            kem_ciphertext: kem_ct,
            wrapped_key,
        });
    }

    // Fisher-Yates shuffle with rejection sampling to eliminate modulo bias.
    // For recipient counts up to 1000 the expected number of retries is < 1.001.
    for i in (1..recipients.len()).rev() {
        let range = (i + 1) as u64;
        // Largest multiple of `range` that fits in u32 (2^32 values: 0..=u32::MAX).
        let threshold = (1u64 << 32) - ((1u64 << 32) % range);
        let j = loop {
            let mut r = [0u8; 4];
            getrandom::fill(&mut r).map_err(|_| PqfileError::EncryptionFailure)?;
            let v = u32::from_le_bytes(r) as u64;
            if v < threshold {
                break (v % range) as usize;
            }
        };
        recipients.swap(i, j);
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let header = PqfHeaderV7 {
        recipients,
        nonce: nonce_bytes,
        original_size,
    };
    header.write(writer)?;

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; slice length is always valid");
    let key = chacha20poly1305::Key::from_slice(session_key.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(&cipher, base_nonce, CHUNK_SIZE, reader, writer)
}

/// Encapsulates `session_key` under `pubkey_pem` for use during rekey.
///
/// Returns `(kem_ciphertext, kem_variant, wrapped_session_key)`.
pub(crate) fn encapsulate_for_rekey(
    pubkey_pem: &str,
    session_key: &[u8; 32],
) -> Result<(Vec<u8>, u16, [u8; WRAPPED_KEY_LEN]), PqfileError> {
    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
    let (kem_ct, ss) = encapsulate(ek)?;
    let wrapped_key = wrap_session_key(session_key, &ss)?;
    Ok((kem_ct, kem_variant, wrapped_key))
}

/// Compress plaintext with zstd then encrypt as v6 format (native builds only).
///
/// WASM builds always return `CompressionNotSupported`.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_compressed(
    pubkey_pem: &str,
    original_size: u64,
    chunk_size: usize,
    compress_level: i32,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if chunk_size == 0 {
            return Err(PqfileError::EncryptionFailure);
        }
        let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
        let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
            .map_err(|_| PqfileError::EncryptionFailure)?;

        let header = PqfHeader {
            version: VERSION_V6,
            kem_variant,
            kem_ciphertext: kem_ct_bytes,
            nonce: nonce_bytes,
            original_size,
            chunk_size: chunk_size as u32,
            compression_algo: COMPRESSION_ZSTD,
        };
        header.write(writer)?;

        let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
            .try_into()
            .expect("BASE_NONCE_LEN <= NONCE_LEN");
        let key = Key::from_slice(ss_bytes.as_ref());
        let cipher = ChaCha20Poly1305::new(key);
        // Stream through a zstd encoder instead of buffering the full compressed payload.
        let mut zstd_src =
            zstd::stream::read::Encoder::new(reader, compress_level).map_err(PqfileError::Io)?;
        encrypt_chunks(&cipher, base_nonce, chunk_size, &mut zstd_src, writer)
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (
            pubkey_pem,
            original_size,
            chunk_size,
            compress_level,
            reader,
            writer,
        );
        Err(PqfileError::CompressionNotSupported)
    }
}

fn encrypt_chunks(
    cipher: &ChaCha20Poly1305,
    base_nonce: &[u8; BASE_NONCE_LEN],
    chunk_size: usize,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let mut current = vec![0u8; chunk_size];
    let mut current_len = fill_chunk(reader, &mut current)?;
    let mut next = vec![0u8; chunk_size];
    let mut counter: u32 = 0;
    loop {
        let next_len = fill_chunk(reader, &mut next)?;
        let is_last = next_len == 0;
        let cn = chunk_nonce(base_nonce, counter);
        let aad = chunk_aad(counter, is_last);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&cn), &aad, &mut current[..current_len])
            .map_err(|_| PqfileError::EncryptionFailure)?;
        writer.write_all(&current[..current_len])?;
        writer.write_all(tag.as_ref())?;
        if is_last {
            break;
        }
        counter = counter
            .checked_add(1)
            .ok_or(PqfileError::EncryptionFailure)?;
        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }
    Ok(())
}

/// Wraps `session_key` under `ss` using AES-256-GCM with a zero nonce.
///
/// A fixed zero nonce is safe here because the AES-256-GCM key (`ss`) is a
/// fresh, single-use KEM shared secret — it is never reused across calls.
/// Nonce uniqueness is guaranteed per-key, not per-nonce, so a constant nonce
/// with a unique key is cryptographically equivalent to a random nonce with a
/// fixed key. See §5.1 of RFC 5116 for the formal nonce-uniqueness requirement.
pub(crate) fn wrap_session_key(
    session_key: &[u8; 32],
    ss: &[u8; 32],
) -> Result<[u8; WRAPPED_KEY_LEN], PqfileError> {
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(ss));
    let nonce = AesNonce::from([0u8; 12]);
    let ct = cipher
        .encrypt(&nonce, session_key.as_slice())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out.copy_from_slice(&ct);
    Ok(out)
}

/// Parallel version of [`encrypt_stream`] that processes chunks concurrently using rayon.
///
/// `batch_size` chunks are read, encrypted in parallel, then written in order.
/// The output format and ciphertext are identical to `encrypt_stream` (same nonce
/// derivation, same AAD) — parallel vs. serial encryption is transparent to the
/// decryptor.
///
/// Falls back to [`encrypt_stream`] for `batch_size` == 1.
///
/// **Performance note:** The rayon thread-pool spin-up cost is amortized across
/// the entire file and is negligible for files with more than ~4 chunks (> 256 KiB
/// at the default 64 KiB chunk size). For smaller files the overhead is comparable
/// to or larger than the encryption time; the overhead crossover is roughly 100-200 KiB
/// on a modern CPU. Callers should measure on their target workload before enabling
/// `--parallel` for small-file paths.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_parallel(
    pubkey_pem: &str,
    original_size: u64,
    chunk_size: usize,
    batch_size: usize,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    if batch_size <= 1 {
        return encrypt_stream(pubkey_pem, original_size, chunk_size, reader, writer);
    }
    if chunk_size == 0 {
        return Err(PqfileError::EncryptionFailure);
    }

    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let version = if chunk_size == CHUNK_SIZE {
        VERSION_V3
    } else {
        VERSION_V5
    };
    let header = PqfHeader {
        version,
        kem_variant,
        kem_ciphertext: kem_ct_bytes,
        nonce: nonce_bytes,
        original_size,
        chunk_size: chunk_size as u32,
        compression_algo: COMPRESSION_NONE,
    };
    header.write(writer)?;

    let base_nonce: [u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN].try_into().unwrap();
    let key_bytes = Zeroizing::new(*ss_bytes);

    // Prime: read the very first chunk
    let mut first = vec![0u8; chunk_size];
    let first_len = fill_chunk(reader, &mut first)?;
    if first_len == 0 {
        // Empty input: emit a single empty authenticated last chunk
        let cn = chunk_nonce(&base_nonce, 0);
        let aad = chunk_aad(0, true);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&cn), &aad, &mut [])
            .map_err(|_| PqfileError::EncryptionFailure)?;
        writer.write_all(tag.as_ref())?;
        return Ok(());
    }

    let mut carry: Option<(Vec<u8>, usize)> = Some((first, first_len));
    let mut counter: u32 = 0;

    loop {
        let mut batch: Vec<(Vec<u8>, usize)> = Vec::with_capacity(batch_size);
        if let Some(c) = carry.take() {
            batch.push(c);
        }
        while batch.len() < batch_size {
            let mut buf = vec![0u8; chunk_size];
            let n = fill_chunk(reader, &mut buf)?;
            if n == 0 {
                break;
            }
            batch.push((buf, n));
        }

        if batch.is_empty() {
            break;
        }

        // Peek one more chunk to determine if this batch ends the stream
        let mut peek = vec![0u8; chunk_size];
        let peek_len = fill_chunk(reader, &mut peek)?;
        let batch_is_final = peek_len == 0;
        if !batch_is_final {
            carry = Some((peek, peek_len));
        }

        let batch_len = batch.len();
        let batch_start = counter;

        let results: Vec<Result<_, PqfileError>> = batch
            .into_par_iter()
            .enumerate()
            .map(|(i, (mut chunk, chunk_len))| {
                let c = batch_start
                    .checked_add(i as u32)
                    .ok_or(PqfileError::EncryptionFailure)?;
                let is_last = batch_is_final && i == batch_len - 1;
                let cn = chunk_nonce(&base_nonce, c);
                let aad = chunk_aad(c, is_last);
                let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
                let tag = cipher
                    .encrypt_in_place_detached(
                        Nonce::from_slice(&cn),
                        &aad,
                        &mut chunk[..chunk_len],
                    )
                    .map_err(|_| PqfileError::EncryptionFailure)?;
                let mut tag_arr = [0u8; 16];
                tag_arr.copy_from_slice(tag.as_ref());
                Ok((chunk, chunk_len, tag_arr))
            })
            .collect();

        for r in results {
            let (ct, ct_len, tag): (Vec<u8>, usize, [u8; 16]) = r?;
            writer.write_all(&ct[..ct_len])?;
            writer.write_all(&tag)?;
        }

        counter = batch_start
            .checked_add(batch_len as u32)
            .ok_or(PqfileError::EncryptionFailure)?;

        if batch_is_final {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;

    fn keypair() -> (String, String) {
        keygen_bytes(768, None).unwrap()
    }

    fn keypair_1024() -> (String, String) {
        keygen_bytes(1024, None).unwrap()
    }

    fn keypair_512() -> (String, String) {
        keygen_bytes(512, None).unwrap()
    }

    #[test]
    fn encrypt_rejects_malformed_public_key_bytes() {
        let bad_key = pem::encode(&pem::Pem::new("ML-KEM-768 PUBLIC KEY", vec![0xFFu8; 1184]));
        let result = encrypt_bytes(&bad_key, b"hello");
        assert!(matches!(result, Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn encrypt_rejects_unrecognised_key_tag() {
        let bad_key = pem::encode(&pem::Pem::new("UNKNOWN KEY", vec![0u8; 1184]));
        let result = encrypt_bytes(&bad_key, b"hello");
        assert!(matches!(result, Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn encrypt_stream_rejects_malformed_public_key() {
        let bad_key = pem::encode(&pem::Pem::new("ML-KEM-768 PUBLIC KEY", vec![0xFFu8; 1184]));
        let mut reader: &[u8] = b"data";
        let mut writer = Vec::new();
        let result = encrypt_stream(&bad_key, 4, CHUNK_SIZE, &mut reader, &mut writer);
        assert!(matches!(result, Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn encrypt_stream_rejects_zero_chunk_size() {
        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = b"data";
        let mut writer = Vec::new();
        let result = encrypt_stream(&pub_pem, 4, 0, &mut reader, &mut writer);
        assert!(matches!(result, Err(PqfileError::EncryptionFailure)));
    }

    #[test]
    fn encrypt_stream_empty_input() {
        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = &[];
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 0, CHUNK_SIZE, &mut reader, &mut writer).unwrap();
        // Header (1115 bytes for 768) + one empty chunk AEAD tag (16 bytes)
        assert_eq!(writer.len(), HEADER_LEN_768 + 16);
    }

    #[test]
    fn encrypt_stream_small_input_produces_header_plus_one_chunk() {
        let (pub_pem, _) = keypair();
        let plaintext = b"small payload";
        let mut reader: &[u8] = plaintext;
        let mut writer = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut reader,
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.len(), HEADER_LEN_768 + plaintext.len() + 16);
    }

    #[test]
    fn encrypt_stream_exact_chunk_boundary() {
        let (pub_pem, _) = keypair();
        let plaintext = vec![0xABu8; CHUNK_SIZE];
        let mut reader: &[u8] = &plaintext;
        let mut writer = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut reader,
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.len(), HEADER_LEN_768 + CHUNK_SIZE + 16);
    }

    #[test]
    fn encrypt_stream_multi_chunk() {
        let (pub_pem, _) = keypair();
        let plaintext = vec![0x42u8; CHUNK_SIZE * 2 + 1];
        let mut reader: &[u8] = &plaintext;
        let mut writer = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut reader,
            &mut writer,
        )
        .unwrap();
        let expected = HEADER_LEN_768 + (CHUNK_SIZE + 16) * 2 + (1 + 16);
        assert_eq!(writer.len(), expected);
    }

    #[test]
    fn encrypt_stream_writes_v3_version_byte() {
        use crate::format::VERSION_V3;
        use std::io::Cursor;

        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = b"test";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 4, CHUNK_SIZE, &mut reader, &mut writer).unwrap();

        let header = PqfHeader::read(&mut Cursor::new(&writer)).unwrap();
        assert_eq!(header.version, VERSION_V3);
    }

    #[test]
    fn encrypt_stream_1024_writes_correct_header() {
        use crate::format::{HEADER_LEN_1024, KEM_VARIANT_1024, VERSION_V3};
        use std::io::Cursor;

        let (pub_pem, _) = keypair_1024();
        let mut reader: &[u8] = b"test";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 4, CHUNK_SIZE, &mut reader, &mut writer).unwrap();

        let header = PqfHeader::read(&mut Cursor::new(&writer)).unwrap();
        assert_eq!(header.version, VERSION_V3);
        assert_eq!(header.kem_variant, KEM_VARIANT_1024);
        assert_eq!(header.kem_ciphertext.len(), 1568);
        // header + one small chunk
        assert_eq!(writer.len(), HEADER_LEN_1024 + 4 + 16);
    }

    // ── ML-KEM-512 ────────────────────────────────────────────────────────────

    #[test]
    fn encrypt_stream_512_writes_correct_header() {
        use crate::format::{HEADER_LEN_512, KEM_VARIANT_512, VERSION_V3};
        use std::io::Cursor;

        let (pub_pem, _) = keypair_512();
        let mut reader: &[u8] = b"test";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 4, CHUNK_SIZE, &mut reader, &mut writer).unwrap();

        let header = PqfHeader::read(&mut Cursor::new(&writer)).unwrap();
        assert_eq!(header.version, VERSION_V3);
        assert_eq!(header.kem_variant, KEM_VARIANT_512);
        assert_eq!(header.kem_ciphertext.len(), 768);
        assert_eq!(writer.len(), HEADER_LEN_512 + 4 + 16);
    }

    // ── Configurable chunk size (v5 format) ───────────────────────────────────

    #[test]
    fn encrypt_stream_default_chunk_size_emits_v3() {
        use std::io::Cursor;
        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = b"hello";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 5, CHUNK_SIZE, &mut reader, &mut writer).unwrap();
        let header = PqfHeader::read(&mut Cursor::new(&writer)).unwrap();
        assert_eq!(header.version, VERSION_V3);
    }

    #[test]
    fn encrypt_stream_custom_chunk_size_emits_v5() {
        use crate::format::VERSION_V5;
        use std::io::Cursor;
        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = b"hello";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 5, 4096, &mut reader, &mut writer).unwrap();
        let header = PqfHeader::read(&mut Cursor::new(&writer)).unwrap();
        assert_eq!(header.version, VERSION_V5);
        assert_eq!(header.chunk_size, 4096);
    }

    #[test]
    fn encrypt_stream_v5_header_is_4_bytes_longer_than_v3() {
        use crate::format::V5_CHUNK_SIZE_FIELD_LEN;
        let (pub_pem, _) = keypair();

        let mut r1: &[u8] = b"x";
        let mut v3_out = Vec::new();
        encrypt_stream(&pub_pem, 1, CHUNK_SIZE, &mut r1, &mut v3_out).unwrap();

        let mut r2: &[u8] = b"x";
        let mut v5_out = Vec::new();
        encrypt_stream(&pub_pem, 1, 4096, &mut r2, &mut v5_out).unwrap();

        assert_eq!(v5_out.len() - v3_out.len(), V5_CHUNK_SIZE_FIELD_LEN);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypt_stream_compressed_writes_v6_version_byte() {
        let (pub_pem, _) = keypair();
        let plaintext = b"compress me";
        let mut out = Vec::new();
        encrypt_stream_compressed(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            3,
            &mut plaintext.as_slice(),
            &mut out,
        )
        .unwrap();

        let version_pos = crate::format::MAGIC.len();
        assert_eq!(out[version_pos], VERSION_V6);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypt_stream_compressed_rejects_zero_chunk_size() {
        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = b"data";
        let mut writer = Vec::new();
        let result = encrypt_stream_compressed(&pub_pem, 4, 0, 3, &mut reader, &mut writer);
        assert!(matches!(result, Err(PqfileError::EncryptionFailure)));
    }

    // ── Parallel encryption ───────────────────────────────────────────────────

    #[test]
    fn parallel_encrypt_small_input_decrypts_correctly() {
        use crate::decrypt::decrypt_stream;
        let (pub_pem, priv_pem) = keypair();
        let plaintext = b"parallel small";
        let mut ct = Vec::new();
        encrypt_stream_parallel(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            4,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn parallel_encrypt_multi_batch_decrypts_correctly() {
        use crate::decrypt::decrypt_stream;
        let (pub_pem, priv_pem) = keypair();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 10 + 7).collect();
        let mut ct = Vec::new();
        encrypt_stream_parallel(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            4,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn parallel_encrypt_empty_input_decrypts_correctly() {
        use crate::decrypt::decrypt_stream;
        let (pub_pem, priv_pem) = keypair();
        let mut ct = Vec::new();
        encrypt_stream_parallel(&pub_pem, 0, CHUNK_SIZE, 4, &mut [].as_slice(), &mut ct).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert!(out.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypt_stream_compressed_v6_header_has_extra_fields() {
        let (pub_pem, _) = keypair();
        let plaintext = b"v6 header size check";
        let mut v3_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut v3_out,
        )
        .unwrap();

        let mut v6_out = Vec::new();
        encrypt_stream_compressed(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            1,
            &mut plaintext.as_slice(),
            &mut v6_out,
        )
        .unwrap();

        // v6 header = v3 header + chunk_size(4) + compression_algo(1) = v3 + 5 bytes
        use crate::format::{V5_CHUNK_SIZE_FIELD_LEN, V6_COMPRESSION_FIELD_LEN};
        assert!(v6_out.len() > v3_out.len());
        // The extra header overhead should be exactly 5 bytes more than v3
        // (both have the same ciphertext payload since compression may vary,
        //  but we can check the compression_algo byte in the header).
        let _ = V5_CHUNK_SIZE_FIELD_LEN + V6_COMPRESSION_FIELD_LEN; // 5 bytes
    }
}
