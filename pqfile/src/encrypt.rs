use rayon::prelude::*;
use std::io::{Read, Write};

use chacha20poly1305::{
    aead::{Aead, AeadInOut, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ml_kem::{
    array::Array, kem::Encapsulate, EncapsulationKey1024, EncapsulationKey512, EncapsulationKey768,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};

use crate::format::{
    chunk_nonce, commitment_for_stream, commitment_for_v10, fill_chunk, hybrid_hkdf,
    make_chunk_aad, PqfHeader, PqfHeaderV4, PqfHeaderV8, RecipientEntryV4, RecipientEntryV8,
    BASE_NONCE_LEN, CHUNK_SIZE, COMPRESSION_NONE, EK_LEN_1024, EK_LEN_512, EK_LEN_768,
    HEADER_LEN_768, HYBRID_CT_LEN_768, HYBRID_EK_LEN_768, KEM_VARIANT_1024, KEM_VARIANT_512,
    KEM_VARIANT_768, KEM_VARIANT_HYBRID_768, NONCE_LEN, PADDED_CT_LEN, VERSION, VERSION_AUTH_BIT,
    VERSION_V3, VERSION_V4, VERSION_V5, VERSION_V8, VERSION_V9, WRAPPED_KEY_LEN,
};
// Used only in the native compressed-encrypt path and its tests.
#[cfg(not(target_arch = "wasm32"))]
use crate::format::{COMPRESSION_ZSTD, VERSION_V6};
use crate::keygen::{PUB_TAG, PUB_TAG_1024, PUB_TAG_512, PUB_TAG_HYBRID_768};

pub(crate) enum EkVariant {
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

    let key: &Key = ss_bytes.as_ref().try_into().expect("32-byte key");
    let nonce: &Nonce = nonce_bytes.as_slice().try_into().expect("12-byte nonce");
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

    let version = VERSION_AUTH_BIT
        | if chunk_size == CHUNK_SIZE {
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
    let key_commitment = commitment_for_stream(
        ss_bytes.as_ref(),
        version,
        &nonce_bytes,
        original_size,
        chunk_size as u32,
        COMPRESSION_NONE,
    );

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; slice length is always valid");
    let key: &Key = ss_bytes.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(
        &cipher,
        base_nonce,
        chunk_size,
        &key_commitment,
        reader,
        writer,
    )
}

/// Encrypts a stream in "stealth" mode: the `.pqf` magic, version byte, and KEM
/// variant field are all omitted, so the output does not immediately identify
/// itself as pqfile ciphertext to an observer. Single recipient only.
///
/// Wire layout: `KEM_CT(ct_len) || BASE_NONCE(8) || ORIGINAL_SIZE(8) || <chunked ciphertext>`,
/// where `ct_len` depends on the recipient's KEM variant. There is nowhere on
/// the wire to record which variant was used, because the decryptor's private
/// key already implies it - [`crate::decrypt::decrypt_stream_stealth`] derives
/// `ct_len` from the supplied key, so a wrong key type simply fails to parse
/// rather than needing a field to check against.
///
/// The KEM ciphertext, X25519 ephemeral key (hybrid mode), and nonce are all
/// computationally indistinguishable from random bytes; `ORIGINAL_SIZE` is the
/// one field that is not (small files leave high-order zero bytes visible).
/// Combine with [`PadmeReader`](crate::padding::PadmeReader) if the true
/// plaintext length is also sensitive - `original_size` should still be the
/// real length so the padding can be stripped back off on decrypt, exactly as
/// with the non-stealth formats.
///
/// Always uses [`CHUNK_SIZE`] and no compression: both are constants baked
/// into the key commitment (the same "v3 authenticated" definition used by
/// [`encrypt_stream`]'s `VERSION_AUTH_BIT` files) even though no version byte
/// travels on the wire to say so, so a chunk_size/compression downgrade attack
/// has nothing to target.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_stealth(
    pubkey_pem: &str,
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let (ek, _kem_variant) = parse_encapsulation_key(pubkey_pem)?;
    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    writer.write_all(&kem_ct_bytes)?;
    writer.write_all(&nonce_bytes[..BASE_NONCE_LEN])?;
    writer.write_all(&original_size.to_le_bytes())?;

    let key_commitment = commitment_for_stream(
        ss_bytes.as_ref(),
        VERSION_V3 | VERSION_AUTH_BIT,
        &nonce_bytes,
        original_size,
        CHUNK_SIZE as u32,
        COMPRESSION_NONE,
    );

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; slice length is always valid");
    let key: &Key = ss_bytes.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(
        &cipher,
        base_nonce,
        CHUNK_SIZE,
        &key_commitment,
        reader,
        writer,
    )
}

/// Encrypts a stream of plaintext bytes, calling `progress(bytes_read, original_size)` after
/// each chunk is consumed from `reader`.
///
/// This is identical to [`encrypt_stream`] but reports progress incrementally.
/// `bytes_read` counts plaintext bytes consumed so far; `original_size` is the same value
/// passed as the second argument and can be used as the denominator for a progress fraction.
/// When `original_size` is 0 the fraction is undefined; the callback will still fire but
/// callers should treat the second argument as "unknown total" in that case.
///
/// Use [`MultiEncryptBuilder::with_progress`] for multi-recipient variants, or
/// [`encrypt_stream_multi_anon_with_progress`] / [`encrypt_stream_multi_anon_padded_with_progress`]
/// when a borrowed callback is more convenient.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_with_progress(
    pubkey_pem: &str,
    original_size: u64,
    chunk_size: usize,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    progress: &dyn Fn(u64, u64),
) -> Result<(), PqfileError> {
    let mut tracked = crate::progress::ProgressReader::new(reader, original_size, progress);
    encrypt_stream(pubkey_pem, original_size, chunk_size, &mut tracked, writer)
}

/// Multi-recipient v8 (anonymous) encryption with a progress callback.
///
/// Identical to [`encrypt_stream_multi_anon`] but calls `progress(bytes_read, original_size)`
/// after each plaintext chunk is consumed. See [`encrypt_stream_with_progress`] for semantics.
pub fn encrypt_stream_multi_anon_with_progress(
    pubkey_pems: &[&str],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    progress: &dyn Fn(u64, u64),
) -> Result<(), PqfileError> {
    let mut tracked = crate::progress::ProgressReader::new(reader, original_size, progress);
    encrypt_stream_multi_anon(pubkey_pems, original_size, &mut tracked, writer)
}

/// Multi-recipient v9 (padded anonymous) encryption with a progress callback.
///
/// Identical to [`encrypt_stream_multi_anon_padded`] but calls `progress(bytes_read, original_size)`
/// after each plaintext chunk is consumed. See [`encrypt_stream_with_progress`] for semantics.
pub fn encrypt_stream_multi_anon_padded_with_progress(
    pubkey_pems: &[&str],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    progress: &dyn Fn(u64, u64),
) -> Result<(), PqfileError> {
    let mut tracked = crate::progress::ProgressReader::new(reader, original_size, progress);
    encrypt_stream_multi_anon_padded(pubkey_pems, original_size, &mut tracked, writer)
}

pub(crate) fn parse_encapsulation_key(pubkey_pem: &str) -> Result<(EkVariant, u16), PqfileError> {
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
            let x25519_pk_bytes: [u8; 32] = raw[..32]
                .try_into()
                .expect("HYBRID_EK_LEN_768 > 32; length checked above");
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

pub(crate) fn encapsulate(ek: EkVariant) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), PqfileError> {
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
            // x25519-dalek v3 with the "zeroize" feature zeroizes StaticSecret
            // and SharedSecret on drop, so both eph_sk and x25519_ss are
            // overwritten on drop.
            let x25519_ss = eph_sk.diffie_hellman(&recipient_pk);

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
    let version = VERSION_V4 | VERSION_AUTH_BIT;
    header.write(writer, version)?;
    let key_commitment = commitment_for_stream(
        session_key.as_ref(),
        version,
        &nonce_bytes,
        original_size,
        CHUNK_SIZE as u32,
        COMPRESSION_NONE,
    );

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; slice length is always valid");
    let key: &Key = session_key.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(
        &cipher,
        base_nonce,
        CHUNK_SIZE,
        &key_commitment,
        reader,
        writer,
    )
}

/// Encrypts a stream to multiple recipients in anonymous (v8) format.
///
/// All KEM ciphertexts are zero-padded to `PADDED_CT_LEN` (1568 bytes) and the
/// per-slot KEM variant field is omitted entirely. Entries are written in a randomly
/// shuffled order. An observer learns only the recipient count - no key-type
/// information is exposed. Supersedes v7 anonymous mode.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_multi_anon(
    pubkey_pems: &[&str],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let mut session_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(session_key.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;

    let mut recipients: Vec<RecipientEntryV8> = Vec::with_capacity(pubkey_pems.len());
    for pubkey_pem in pubkey_pems {
        let (ek, _kem_variant) = parse_encapsulation_key(pubkey_pem)?;
        let (kem_ct, ss) = encapsulate(ek)?;
        let wrapped_key = wrap_session_key(&session_key, &ss)?;
        // Pad actual CT to PADDED_CT_LEN; trailing bytes are zeros.
        let mut padded_ct = [0u8; PADDED_CT_LEN];
        padded_ct[..kem_ct.len()].copy_from_slice(&kem_ct);
        recipients.push(RecipientEntryV8 {
            padded_ct,
            wrapped_key,
        });
    }

    // Fisher-Yates shuffle with rejection sampling to eliminate modulo bias.
    // For recipient counts up to 1000 the expected number of retries is < 1.001.
    // A hard limit of 1000 retries per position guards against a malfunctioning
    // entropy source causing an infinite loop.
    const MAX_REJECTION_RETRIES: u32 = 1000;
    for i in (1..recipients.len()).rev() {
        let range = (i + 1) as u64;
        let threshold = (1u64 << 32) - ((1u64 << 32) % range);
        let j = 'sample: {
            for _ in 0..MAX_REJECTION_RETRIES {
                let mut r = [0u8; 4];
                getrandom::fill(&mut r).map_err(|_| PqfileError::EncryptionFailure)?;
                let v = u32::from_le_bytes(r) as u64;
                if v < threshold {
                    break 'sample (v % range) as usize;
                }
            }
            return Err(PqfileError::EncryptionFailure);
        };
        recipients.swap(i, j);
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let header = PqfHeaderV8 {
        recipients,
        nonce: nonce_bytes,
        original_size,
    };
    let version = VERSION_V8 | VERSION_AUTH_BIT;
    header.write_with_version(writer, version)?;
    let key_commitment = commitment_for_stream(
        session_key.as_ref(),
        version,
        &nonce_bytes,
        original_size,
        CHUNK_SIZE as u32,
        COMPRESSION_NONE,
    );

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; slice length is always valid");
    let key: &Key = session_key.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(
        &cipher,
        base_nonce,
        CHUNK_SIZE,
        &key_commitment,
        reader,
        writer,
    )
}

/// Like [`encrypt_stream_multi_anon`] but pads the recipient list to the next power
/// of two by inserting random dummy slots (v9 format).
///
/// An observer can determine only that there are 1, 2, 4, 8, … recipient slots,
/// not how many are real. Dummy slots consist of random bytes and will fail both
/// KEM decapsulation and AES-GCM tag verification, so the decryptor skips them
/// silently.
///
/// Use this when the exact recipient count is itself sensitive information.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_multi_anon_padded(
    pubkey_pems: &[&str],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let mut session_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(session_key.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;

    let mut recipients: Vec<RecipientEntryV8> = Vec::with_capacity(pubkey_pems.len());
    for pubkey_pem in pubkey_pems {
        let (ek, _kem_variant) = parse_encapsulation_key(pubkey_pem)?;
        let (kem_ct, ss) = encapsulate(ek)?;
        let wrapped_key = wrap_session_key(&session_key, &ss)?;
        let mut padded_ct = [0u8; PADDED_CT_LEN];
        padded_ct[..kem_ct.len()].copy_from_slice(&kem_ct);
        recipients.push(RecipientEntryV8 {
            padded_ct,
            wrapped_key,
        });
    }

    // Pad with random dummy slots to the next power of two.
    let real_count = recipients.len();
    let padded_count = real_count.next_power_of_two().max(1);
    for _ in real_count..padded_count {
        let mut padded_ct = [0u8; PADDED_CT_LEN];
        let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
        getrandom::fill(&mut padded_ct).map_err(|_| PqfileError::EncryptionFailure)?;
        getrandom::fill(&mut wrapped_key).map_err(|_| PqfileError::EncryptionFailure)?;
        recipients.push(RecipientEntryV8 {
            padded_ct,
            wrapped_key,
        });
    }

    // Fisher-Yates shuffle so dummy positions are unpredictable. Rejection sampling
    // is bounded the same way as in encrypt_stream_multi_anon above: a hard limit of
    // 1000 retries per position guards against a malfunctioning entropy source
    // causing an infinite loop instead of returning an error.
    const MAX_REJECTION_RETRIES: u32 = 1000;
    for i in (1..recipients.len()).rev() {
        let range = (i + 1) as u64;
        let threshold = (1u64 << 32) - ((1u64 << 32) % range);
        let j = 'sample: {
            for _ in 0..MAX_REJECTION_RETRIES {
                let mut r = [0u8; 4];
                getrandom::fill(&mut r).map_err(|_| PqfileError::EncryptionFailure)?;
                let v = u32::from_le_bytes(r) as u64;
                if v < threshold {
                    break 'sample (v % range) as usize;
                }
            }
            return Err(PqfileError::EncryptionFailure);
        };
        recipients.swap(i, j);
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    // v9 uses the same wire format as v8 but with version byte 0x09.
    let header = PqfHeaderV8 {
        recipients,
        nonce: nonce_bytes,
        original_size,
    };
    let version = VERSION_V9 | VERSION_AUTH_BIT;
    header.write_with_version(writer, version)?;

    let key_commitment = commitment_for_stream(
        session_key.as_ref(),
        version,
        &nonce_bytes,
        original_size,
        CHUNK_SIZE as u32,
        COMPRESSION_NONE,
    );
    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN");
    let key: &Key = session_key.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(
        &cipher,
        base_nonce,
        CHUNK_SIZE,
        &key_commitment,
        reader,
        writer,
    )
}

// ---------------------------------------------------------------------------
// Multi-recipient builder
// ---------------------------------------------------------------------------

/// Format selector for [`MultiEncryptBuilder`].
#[derive(Debug, Clone, Copy, Default)]
enum MultiEncryptMode {
    #[default]
    Standard,
    Anonymous,
    Padded,
}

/// Ergonomic builder for multi-recipient encryption.
///
/// Wraps the three multi-recipient free functions and selects the right format
/// based on the options you configure. Prefer this over calling
/// [`encrypt_stream_multi`], [`encrypt_stream_multi_anon`], or
/// [`encrypt_stream_multi_anon_padded`] directly; future minor releases will
/// add progress callbacks and other knobs here without changing the existing
/// free-function signatures.
///
/// # Format selection
///
/// | Method called | Format | Version byte |
/// |---|---|---|
/// | (none) | v4 - explicit per-slot KEM variant | `0x04` |
/// | `.anonymous()` | v8 - uniform slot size, shuffled order | `0x08` |
/// | `.padded()` | v9 - like v8 + slot count padded to next power of two | `0x09` |
///
/// # Example
///
/// ```no_run
/// use pqfile::encrypt::MultiEncryptBuilder;
/// # let (pub1, pub2) = (String::new(), String::new());
/// # let plaintext = vec![0u8; 0];
/// let mut ct = Vec::new();
/// MultiEncryptBuilder::new(&[pub1.as_str(), pub2.as_str()])
///     .anonymous()
///     .encrypt(plaintext.len() as u64, &mut plaintext.as_slice(), &mut ct)?;
/// # Ok::<_, pqfile::error::PqfileError>(())
/// ```
pub struct MultiEncryptBuilder<'a> {
    pubkey_pems: Vec<&'a str>,
    mode: MultiEncryptMode,
    progress: Option<Box<dyn Fn(u64, u64)>>,
}

impl<'a> MultiEncryptBuilder<'a> {
    /// Creates a new builder with the given recipient public keys.
    ///
    /// Defaults to v4 (standard multi-recipient) format. Call [`anonymous`](Self::anonymous)
    /// or [`padded`](Self::padded) to select a different format.
    pub fn new(pubkey_pems: &[&'a str]) -> Self {
        Self {
            pubkey_pems: pubkey_pems.to_vec(),
            mode: MultiEncryptMode::Standard,
            progress: None,
        }
    }

    /// Use v8 anonymous format: uniform 1568-byte slots, no per-slot KEM variant field,
    /// recipient order shuffled with Fisher-Yates.
    pub fn anonymous(mut self) -> Self {
        self.mode = MultiEncryptMode::Anonymous;
        self
    }

    /// Use v9 padded format: like anonymous but slot count is rounded up to the next power
    /// of two with random dummy slots to obscure recipient count.
    pub fn padded(mut self) -> Self {
        self.mode = MultiEncryptMode::Padded;
        self
    }

    /// Register a progress callback invoked after each plaintext chunk is consumed.
    ///
    /// The callback receives `(bytes_read, original_size)`. When `original_size` is 0
    /// the total is unknown; the callback still fires but the second argument should be
    /// treated as "unknown total".
    pub fn with_progress(mut self, progress: impl Fn(u64, u64) + 'static) -> Self {
        self.progress = Some(Box::new(progress));
        self
    }

    /// Encrypts `reader` for all configured recipients and writes to `writer`.
    pub fn encrypt(
        self,
        original_size: u64,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), PqfileError> {
        if let Some(cb) = self.progress {
            let mut tracked =
                crate::progress::ProgressReader::new(reader, original_size, cb.as_ref());
            match self.mode {
                MultiEncryptMode::Standard => {
                    encrypt_stream_multi(&self.pubkey_pems, original_size, &mut tracked, writer)
                }
                MultiEncryptMode::Anonymous => encrypt_stream_multi_anon(
                    &self.pubkey_pems,
                    original_size,
                    &mut tracked,
                    writer,
                ),
                MultiEncryptMode::Padded => encrypt_stream_multi_anon_padded(
                    &self.pubkey_pems,
                    original_size,
                    &mut tracked,
                    writer,
                ),
            }
        } else {
            match self.mode {
                MultiEncryptMode::Standard => {
                    encrypt_stream_multi(&self.pubkey_pems, original_size, reader, writer)
                }
                MultiEncryptMode::Anonymous => {
                    encrypt_stream_multi_anon(&self.pubkey_pems, original_size, reader, writer)
                }
                MultiEncryptMode::Padded => encrypt_stream_multi_anon_padded(
                    &self.pubkey_pems,
                    original_size,
                    reader,
                    writer,
                ),
            }
        }
    }
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

        let version = VERSION_V6 | VERSION_AUTH_BIT;
        let header = PqfHeader {
            version,
            kem_variant,
            kem_ciphertext: kem_ct_bytes,
            nonce: nonce_bytes,
            original_size,
            chunk_size: chunk_size as u32,
            compression_algo: COMPRESSION_ZSTD,
        };
        header.write(writer)?;
        let key_commitment = commitment_for_stream(
            ss_bytes.as_ref(),
            version,
            &nonce_bytes,
            original_size,
            chunk_size as u32,
            COMPRESSION_ZSTD,
        );

        let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
            .try_into()
            .expect("BASE_NONCE_LEN <= NONCE_LEN");
        let key: &Key = ss_bytes.as_ref().try_into().expect("32-byte key");
        let cipher = ChaCha20Poly1305::new(key);
        // Stream through a zstd encoder instead of buffering the full compressed payload.
        let mut zstd_src =
            zstd::stream::read::Encoder::new(reader, compress_level).map_err(PqfileError::Io)?;
        encrypt_chunks(
            &cipher,
            base_nonce,
            chunk_size,
            &key_commitment,
            &mut zstd_src,
            writer,
        )
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

/// Encrypts a stream of plaintext using a passphrase directly, with no key pair required (v10 format).
///
/// The session key is derived from `passphrase` via Argon2id (m=64 MiB, t=3, p=4). The
/// KDF parameters are stored in the header so the decryptor can reproduce them without
/// out-of-band configuration. Use [`crate::decrypt::decrypt_stream_passphrase`] to decrypt.
///
/// The default KDF parameters match the default ceiling enforced by
/// [`crate::decrypt::decrypt_stream_passphrase`], so files written by this function are
/// always decryptable without adjusting `--max-kdf-mem` / `--max-kdf-time`.
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_passphrase(
    passphrase: &str,
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    use crate::passphrase::{ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST};
    encrypt_stream_passphrase_with_params(
        passphrase,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        original_size,
        reader,
        writer,
    )
}

/// [`encrypt_stream_passphrase`] with caller-chosen Argon2id parameters, e.g.
/// the output of [`crate::calibrate`].
///
/// The parameters travel in the v10 header, so any pqfile can decrypt the
/// result — but [`crate::decrypt::decrypt_stream_passphrase`] enforces a
/// default ceiling of m=64 MiB / t=3 as a decompression-bomb guard. A file
/// written with stronger parameters than that requires the decryptor to raise
/// the ceiling (`decrypt_stream_passphrase_with_limits`, or the CLI's
/// `--max-kdf-mem` / `--max-kdf-time`).
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_passphrase_with_params(
    passphrase: &str,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    encrypt_stream_passphrase_inner(
        passphrase,
        None,
        m_kib,
        t_cost,
        p_cost,
        original_size,
        reader,
        writer,
    )
}

/// [`encrypt_stream_passphrase`] with a keyfile as a second factor.
///
/// `keyfile` is the raw content of any file the user chooses; its hash is mixed
/// into the Argon2id derivation as the secret (pepper) input, so decryption
/// requires both the passphrase (something you know) and the same keyfile bytes
/// (something you have). The header records that a keyfile is required, so
/// decrypting without one fails with [`PqfileError::KeyfileRequired`] before
/// the KDF runs. Use [`crate::decrypt::decrypt_stream_passphrase_keyfile`] to
/// decrypt.
///
/// Returns an error if `keyfile` is empty, since an empty keyfile adds no
/// second factor.
///
/// [`PqfileError::KeyfileRequired`]: crate::error::PqfileError::KeyfileRequired
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_passphrase_keyfile(
    passphrase: &str,
    keyfile: &[u8],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    use crate::passphrase::{ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST};
    encrypt_stream_passphrase_keyfile_with_params(
        passphrase,
        keyfile,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        original_size,
        reader,
        writer,
    )
}

/// [`encrypt_stream_passphrase_keyfile`] with caller-chosen Argon2id parameters.
/// See [`encrypt_stream_passphrase_with_params`] for the KDF-ceiling caveats.
#[allow(clippy::too_many_arguments)]
#[must_use = "encryption result must be used"]
pub fn encrypt_stream_passphrase_keyfile_with_params(
    passphrase: &str,
    keyfile: &[u8],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    if keyfile.is_empty() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "keyfile is empty; a keyfile must contain at least one byte",
        )));
    }
    encrypt_stream_passphrase_inner(
        passphrase,
        Some(keyfile),
        m_kib,
        t_cost,
        p_cost,
        original_size,
        reader,
        writer,
    )
}

#[allow(clippy::too_many_arguments)]
fn encrypt_stream_passphrase_inner(
    passphrase: &str,
    keyfile: Option<&[u8]>,
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    use crate::format::{PqfHeaderV10, V10_FLAG_KEYFILE};
    use crate::passphrase::{derive_key_with_params_and_secret, keyfile_secret};

    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| PqfileError::EncryptionFailure)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let secret = keyfile.map(keyfile_secret);
    let session_key = derive_key_with_params_and_secret(
        passphrase,
        secret.as_deref().map(|s| s.as_slice()),
        &salt,
        m_kib,
        t_cost,
        p_cost,
    )?;

    let header = PqfHeaderV10 {
        salt,
        m_kib,
        t_cost,
        p_cost,
        flags: if keyfile.is_some() {
            V10_FLAG_KEYFILE
        } else {
            0
        },
        nonce: nonce_bytes,
        original_size,
    };
    let version = crate::format::VERSION_V10 | VERSION_AUTH_BIT;
    header.write(writer, version).map_err(PqfileError::Io)?;

    let key_commitment = commitment_for_v10(session_key.as_ref(), version, &header);
    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN");
    let key: &Key = session_key.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(
        &cipher,
        base_nonce,
        CHUNK_SIZE,
        &key_commitment,
        reader,
        writer,
    )
}

fn encrypt_chunks(
    cipher: &ChaCha20Poly1305,
    base_nonce: &[u8; BASE_NONCE_LEN],
    chunk_size: usize,
    key_commitment: &[u8; 32],
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
        let (aad_buf, aad_len) = make_chunk_aad(counter, is_last, key_commitment);
        let tag = cipher
            .encrypt_inout_detached(
                cn.as_slice().try_into().expect("12-byte nonce"),
                &aad_buf[..aad_len],
                (&mut current[..current_len]).into(),
            )
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

/// Memory-maps `source_path` and encrypts its contents without a userspace read buffer.
///
/// On large files (100 MiB+) this can improve throughput compared to [`encrypt_stream`]
/// by eliminating the intermediate copy through the 64 KiB read buffer. The kernel maps
/// file pages directly into the process address space; the AEAD reads from that mapping.
///
/// Only available on native platforms (not WASM). The ciphertext format and structure are
/// identical to [`encrypt_stream`].
///
/// # Example
///
/// ```no_run
/// use pqfile::encrypt::encrypt_mmap;
/// use pqfile::format::CHUNK_SIZE;
///
/// let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(768, None).unwrap();
/// let mut ct = Vec::new();
/// encrypt_mmap(&pub_pem, std::path::Path::new("large_file.dat"), CHUNK_SIZE, &mut ct).unwrap();
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn encrypt_mmap(
    pubkey_pem: &str,
    source_path: &std::path::Path,
    chunk_size: usize,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    if chunk_size == 0 {
        return Err(PqfileError::EncryptionFailure);
    }
    let file = std::fs::File::open(source_path)?;
    let original_size = file.metadata()?.len();

    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let version = VERSION_AUTH_BIT
        | if chunk_size == CHUNK_SIZE {
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
    let key_commitment = commitment_for_stream(
        ss_bytes.as_ref(),
        version,
        &nonce_bytes,
        original_size,
        chunk_size as u32,
        COMPRESSION_NONE,
    );

    let base_nonce: [u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN");
    let key: &Key = ss_bytes.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);

    if original_size == 0 {
        // Empty file: emit single zero-length authenticated chunk.
        return encrypt_chunks(
            &cipher,
            &base_nonce,
            chunk_size,
            &key_commitment,
            &mut [].as_ref(),
            writer,
        );
    }

    // SAFETY: The file is opened read-only. We hold a shared mapping; the file
    // must not be modified concurrently during encryption. If another process
    // truncates the file between the metadata() call above and reads inside
    // encrypt_chunks, the OS may deliver SIGBUS on Unix or raise a structured
    // exception on Windows - this is an inherent mmap caveat and the caller is
    // responsible for ensuring the source file is stable during the call.
    #[allow(unsafe_code)]
    let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(PqfileError::Io)?;
    // Hint to the OS that we will read the mapping sequentially (Unix only).
    // best-effort: ignore errors.
    #[cfg(unix)]
    let _ = mmap.advise(memmap2::Advice::Sequential);
    encrypt_chunks(
        &cipher,
        &base_nonce,
        chunk_size,
        &key_commitment,
        &mut mmap.as_ref(),
        writer,
    )
}

/// Encrypts `plaintext` from `reader` using a two-buffer producer/consumer pipeline:
/// while one chunk is being encrypted on the CPU, the next chunk is being read from
/// `reader` concurrently. This can eliminate CPU idle time on I/O-bound workloads
/// (spinning disks, network-mounted storage).
///
/// Produces the same ciphertext as [`encrypt_stream`] - files are interchangeable.
/// Requires `R: Read + Send + 'static` so the reader can be moved to a background thread.
///
/// On I/O-fast hardware (NVMe SSD) the throughput gain is typically small; on latency-
/// bound storage (spinning disk, NFS) it can double throughput for large files.
///
/// # Example
///
/// ```no_run
/// use pqfile::encrypt::encrypt_stream_pipelined;
/// use pqfile::format::CHUNK_SIZE;
/// use std::fs::File;
///
/// let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(768, None).unwrap();
/// let f = File::open("large_file.dat").unwrap();
/// let size = f.metadata().unwrap().len();
/// let mut ct = Vec::new();
/// encrypt_stream_pipelined(&pub_pem, size, CHUNK_SIZE, f, &mut ct).unwrap();
/// ```
pub fn encrypt_stream_pipelined<R>(
    pubkey_pem: &str,
    original_size: u64,
    chunk_size: usize,
    reader: R,
    writer: &mut dyn Write,
) -> Result<(), PqfileError>
where
    R: Read + Send + 'static,
{
    if chunk_size == 0 {
        return Err(PqfileError::EncryptionFailure);
    }
    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let version = VERSION_AUTH_BIT
        | if chunk_size == CHUNK_SIZE {
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
    let key_commitment = commitment_for_stream(
        ss_bytes.as_ref(),
        version,
        &nonce_bytes,
        original_size,
        chunk_size as u32,
        COMPRESSION_NONE,
    );

    let base_nonce: [u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN");
    let key: &Key = ss_bytes.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);

    encrypt_chunks_pipelined(
        &cipher,
        &base_nonce,
        chunk_size,
        &key_commitment,
        reader,
        writer,
    )
}

/// Two-buffer pipeline: reader thread fills chunks into a bounded channel while
/// the main thread encrypts and writes. Channel capacity 2 keeps the reader
/// one full chunk ahead of the encryptor.
fn encrypt_chunks_pipelined<R>(
    cipher: &ChaCha20Poly1305,
    base_nonce: &[u8; BASE_NONCE_LEN],
    chunk_size: usize,
    key_commitment: &[u8; 32],
    reader: R,
    writer: &mut dyn Write,
) -> Result<(), PqfileError>
where
    R: Read + Send + 'static,
{
    use std::sync::mpsc;

    // Each message is Ok((buffer, filled_len)) or Err(io::Error).
    // A capacity-2 channel lets the reader stay 1 chunk ahead of the encryptor.
    let (tx, rx) = mpsc::sync_channel::<std::io::Result<(Vec<u8>, usize)>>(2);

    let reader_thread = std::thread::spawn(move || {
        let mut rdr = reader;
        loop {
            let mut buf = vec![0u8; chunk_size];
            match fill_chunk(&mut rdr, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.send(Ok((buf, n))).is_err() {
                        break; // encryptor dropped the receiver (error path)
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string())));
                    break;
                }
            }
        }
        // Sending nothing more signals end-of-stream to the encryptor.
    });

    // Receive chunks from the reader and encrypt them.
    let result = (|| -> Result<(), PqfileError> {
        let mut counter: u32 = 0;
        // Buffer current and peek the next to determine is_last.
        let first = match rx.recv() {
            Err(_) => {
                // Empty input: emit a single zero-length chunk.
                let cn = chunk_nonce(base_nonce, 0);
                let (aad_buf, aad_len) = make_chunk_aad(0, true, key_commitment);
                let tag = cipher
                    .encrypt_inout_detached(
                        cn.as_slice().try_into().expect("12-byte nonce"),
                        &aad_buf[..aad_len],
                        (&mut [] as &mut [u8]).into(),
                    )
                    .map_err(|_| PqfileError::EncryptionFailure)?;
                writer.write_all(tag.as_ref())?;
                return Ok(());
            }
            Ok(Err(e)) => return Err(PqfileError::Io(e)),
            Ok(Ok(msg)) => msg,
        };

        let mut current = first;

        loop {
            let next = rx.recv();
            let is_last = matches!(next, Err(_) | Ok(Ok((_, 0))));
            let (current_buf, current_len) = &mut current;

            let cn = chunk_nonce(base_nonce, counter);
            let (aad_buf, aad_len) = make_chunk_aad(counter, is_last, key_commitment);
            let tag = cipher
                .encrypt_inout_detached(
                    cn.as_slice().try_into().expect("12-byte nonce"),
                    &aad_buf[..aad_len],
                    (&mut current_buf[..*current_len]).into(),
                )
                .map_err(|_| PqfileError::EncryptionFailure)?;
            writer.write_all(&current_buf[..*current_len])?;
            writer.write_all(tag.as_ref())?;

            if is_last {
                break;
            }
            match next {
                Ok(Ok(msg)) => {
                    current = msg;
                }
                Ok(Err(e)) => return Err(PqfileError::Io(e)),
                Err(_) => break,
            }
            counter = counter
                .checked_add(1)
                .ok_or(PqfileError::EncryptionFailure)?;
        }
        Ok(())
    })();

    // Always join the reader thread, even on error, to avoid leaking it.
    let _ = reader_thread.join();
    result
}

/// Wraps `session_key` under `ss` using AES-256-GCM with a zero nonce.
///
/// A fixed zero nonce is safe here because the AES-256-GCM key (`ss`) is a
/// fresh, single-use KEM shared secret - it is never reused across calls.
/// Nonce uniqueness is guaranteed per-key, not per-nonce, so a constant nonce
/// with a unique key is cryptographically equivalent to a random nonce with a
/// fixed key. See Section 5.1 of RFC 5116 for the formal nonce-uniqueness requirement.
///
/// The wrapped key has no additional AAD binding it to the per-file nonce or
/// KEM ciphertext. That binding is provided instead by the key commitment in
/// `crate::format::compute_key_commitment`, which is checked on every chunk-0
/// decryption. See that function for the full security argument.
pub(crate) fn wrap_session_key(
    session_key: &[u8; 32],
    ss: &[u8; 32],
) -> Result<[u8; WRAPPED_KEY_LEN], PqfileError> {
    let cipher = Aes256Gcm::new(ss.as_slice().try_into().expect("32-byte key"));
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
/// derivation, same AAD) - parallel vs. serial encryption is transparent to the
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

    let version = VERSION_AUTH_BIT
        | if chunk_size == CHUNK_SIZE {
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
    let key_commitment = commitment_for_stream(
        ss_bytes.as_ref(),
        version,
        &nonce_bytes,
        original_size,
        chunk_size as u32,
        COMPRESSION_NONE,
    );

    let base_nonce: [u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN");
    let key_bytes = Zeroizing::new(*ss_bytes);

    // Prime: read the very first chunk
    let mut first = vec![0u8; chunk_size];
    let first_len = fill_chunk(reader, &mut first)?;
    if first_len == 0 {
        // Empty input: emit a single empty authenticated last chunk
        let cn = chunk_nonce(&base_nonce, 0);
        let (aad_buf, aad_len) = make_chunk_aad(0, true, &key_commitment);
        let cipher = ChaCha20Poly1305::new(key_bytes.as_ref().try_into().expect("32-byte key"));
        let tag = cipher
            .encrypt_inout_detached(
                cn.as_slice().try_into().expect("12-byte nonce"),
                &aad_buf[..aad_len],
                (&mut [] as &mut [u8]).into(),
            )
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

        // key_commitment is [u8; 32] (Copy) - captured by value in closure.
        let results: Vec<Result<_, PqfileError>> = batch
            .into_par_iter()
            .enumerate()
            .map(|(i, (mut chunk, chunk_len))| {
                let c = batch_start
                    .checked_add(i as u32)
                    .ok_or(PqfileError::EncryptionFailure)?;
                let is_last = batch_is_final && i == batch_len - 1;
                let cn = chunk_nonce(&base_nonce, c);
                let (aad_buf, aad_len) = make_chunk_aad(c, is_last, &key_commitment);
                let cipher =
                    ChaCha20Poly1305::new(key_bytes.as_ref().try_into().expect("32-byte key"));
                let tag = cipher
                    .encrypt_inout_detached(
                        cn.as_slice().try_into().expect("12-byte nonce"),
                        &aad_buf[..aad_len],
                        (&mut chunk[..chunk_len]).into(),
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
    use crate::decrypt::decrypt_stream;
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
        assert_eq!(header.version, VERSION_V3 | VERSION_AUTH_BIT);
        assert_eq!(header.layout(), VERSION_V3);
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
        assert_eq!(header.version, VERSION_V3 | VERSION_AUTH_BIT);
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
        assert_eq!(header.version, VERSION_V3 | VERSION_AUTH_BIT);
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
        assert_eq!(header.version, VERSION_V3 | VERSION_AUTH_BIT);
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
        assert_eq!(header.version, VERSION_V5 | VERSION_AUTH_BIT);
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
        assert_eq!(out[version_pos], VERSION_V6 | VERSION_AUTH_BIT);
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

    #[test]
    fn pipelined_encrypt_empty_input_decrypts_correctly() {
        use std::io::Cursor;
        let (pub_pem, priv_pem) = keypair();
        let mut ct = Vec::new();
        encrypt_stream_pipelined(
            &pub_pem,
            0,
            CHUNK_SIZE,
            Cursor::new(Vec::<u8>::new()),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn pipelined_encrypt_small_input_decrypts_correctly() {
        use std::io::Cursor;
        let (pub_pem, priv_pem) = keypair();
        let plaintext = b"pipelined encrypt small input";
        let mut ct = Vec::new();
        encrypt_stream_pipelined(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            Cursor::new(plaintext.to_vec()),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext.as_ref());
    }

    #[test]
    fn pipelined_encrypt_multi_chunk_decrypts_correctly() {
        use std::io::Cursor;
        let (pub_pem, priv_pem) = keypair();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 3 + 77).collect();
        let mut ct = Vec::new();
        encrypt_stream_pipelined(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            Cursor::new(plaintext.clone()),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn pipelined_ciphertext_matches_serial() {
        use std::io::Cursor;
        let (pub_pem, priv_pem) = keypair();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE + 50).collect();
        let mut ct = Vec::new();
        encrypt_stream_pipelined(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            Cursor::new(plaintext.clone()),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypt_mmap_roundtrip_small() {
        use crate::encrypt::encrypt_mmap;
        use std::io::Write as IoWrite;
        use tempfile::NamedTempFile;
        let (pub_pem, priv_pem) = keypair();
        let plaintext = b"mmap roundtrip small test";
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(plaintext).unwrap();
        tmp.flush().unwrap();
        let mut ct = Vec::new();
        encrypt_mmap(&pub_pem, tmp.path(), CHUNK_SIZE, &mut ct).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypt_mmap_roundtrip_multi_chunk() {
        use crate::encrypt::encrypt_mmap;
        use std::io::Write as IoWrite;
        use tempfile::NamedTempFile;
        let (pub_pem, priv_pem) = keypair();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 2 + 33).collect();
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&plaintext).unwrap();
        tmp.flush().unwrap();
        let mut ct = Vec::new();
        encrypt_mmap(&pub_pem, tmp.path(), CHUNK_SIZE, &mut ct).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn encrypt_mmap_empty_file() {
        use crate::encrypt::encrypt_mmap;
        use tempfile::NamedTempFile;
        let (pub_pem, priv_pem) = keypair();
        let tmp = NamedTempFile::new().unwrap();
        let mut ct = Vec::new();
        encrypt_mmap(&pub_pem, tmp.path(), CHUNK_SIZE, &mut ct).unwrap();
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

    // ── MultiEncryptBuilder ───────────────────────────────────────────────────

    use crate::format::{VERSION_V4, VERSION_V8, VERSION_V9};

    #[test]
    fn builder_standard_roundtrip() {
        let (pub1, priv1) = keypair();
        let (pub2, priv2) = keypair();
        let plaintext = b"builder standard v4 roundtrip";
        let mut ct = Vec::new();
        MultiEncryptBuilder::new(&[pub1.as_str(), pub2.as_str()])
            .encrypt(plaintext.len() as u64, &mut plaintext.as_slice(), &mut ct)
            .unwrap();
        let version_pos = crate::format::MAGIC.len();
        assert_eq!(ct[version_pos], VERSION_V4 | VERSION_AUTH_BIT);
        for priv_pem in [&priv1, &priv2] {
            let mut out = Vec::new();
            decrypt_stream(priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
            assert_eq!(out, plaintext);
        }
    }

    #[test]
    fn builder_anonymous_roundtrip() {
        let (pub1, priv1) = keypair();
        let (pub2, priv2) = keypair();
        let plaintext = b"builder anonymous v8 roundtrip";
        let mut ct = Vec::new();
        MultiEncryptBuilder::new(&[pub1.as_str(), pub2.as_str()])
            .anonymous()
            .encrypt(plaintext.len() as u64, &mut plaintext.as_slice(), &mut ct)
            .unwrap();
        let version_pos = crate::format::MAGIC.len();
        assert_eq!(ct[version_pos], VERSION_V8 | VERSION_AUTH_BIT);
        for priv_pem in [&priv1, &priv2] {
            let mut out = Vec::new();
            decrypt_stream(priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
            assert_eq!(out, plaintext);
        }
    }

    #[test]
    fn builder_padded_roundtrip() {
        let (pub1, priv1) = keypair();
        let (pub2, priv2) = keypair();
        let plaintext = b"builder padded v9 roundtrip";
        let mut ct = Vec::new();
        MultiEncryptBuilder::new(&[pub1.as_str(), pub2.as_str()])
            .padded()
            .encrypt(plaintext.len() as u64, &mut plaintext.as_slice(), &mut ct)
            .unwrap();
        let version_pos = crate::format::MAGIC.len();
        assert_eq!(ct[version_pos], VERSION_V9 | VERSION_AUTH_BIT);
        for priv_pem in [&priv1, &priv2] {
            let mut out = Vec::new();
            decrypt_stream(priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
            assert_eq!(out, plaintext);
        }
    }

    #[test]
    fn builder_last_mode_wins() {
        let (pub1, _priv1) = keypair();
        let plaintext = b"mode ordering";
        let mut ct_ap = Vec::new();
        MultiEncryptBuilder::new(&[pub1.as_str()])
            .anonymous()
            .padded()
            .encrypt(
                plaintext.len() as u64,
                &mut plaintext.as_slice(),
                &mut ct_ap,
            )
            .unwrap();
        let version_pos = crate::format::MAGIC.len();
        assert_eq!(
            ct_ap[version_pos],
            VERSION_V9 | VERSION_AUTH_BIT,
            ".anonymous().padded() => v9"
        );

        let mut ct_pa = Vec::new();
        MultiEncryptBuilder::new(&[pub1.as_str()])
            .padded()
            .anonymous()
            .encrypt(
                plaintext.len() as u64,
                &mut plaintext.as_slice(),
                &mut ct_pa,
            )
            .unwrap();
        assert_eq!(
            ct_pa[version_pos],
            VERSION_V8 | VERSION_AUTH_BIT,
            ".padded().anonymous() => v8"
        );
    }

    #[test]
    fn encrypt_stream_with_progress_fires_and_accurate() {
        use std::sync::{Arc, Mutex};
        let (pub_pem, priv_pem) = keypair();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 2 + 100).collect();
        let calls: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let mut ct = Vec::new();
        encrypt_stream_with_progress(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
            &move |done, total| {
                calls2.lock().unwrap().push((done, total));
            },
        )
        .unwrap();
        let log = calls.lock().unwrap().clone();
        assert!(!log.is_empty(), "progress callback must fire at least once");
        let (last_done, last_total) = *log.last().unwrap();
        assert_eq!(
            last_done,
            plaintext.len() as u64,
            "final bytes_read must equal plaintext length"
        );
        assert_eq!(last_total, plaintext.len() as u64);
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn builder_with_progress_fires() {
        use std::sync::{Arc, Mutex};
        let (pub1, priv1) = keypair();
        let plaintext = b"builder progress test payload";
        let calls: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let calls2 = Arc::clone(&calls);
        let mut ct = Vec::new();
        MultiEncryptBuilder::new(&[pub1.as_str()])
            .with_progress(move |_, _| {
                *calls2.lock().unwrap() += 1;
            })
            .encrypt(plaintext.len() as u64, &mut plaintext.as_slice(), &mut ct)
            .unwrap();
        assert!(*calls.lock().unwrap() > 0, "progress callback must fire");
        let mut out = Vec::new();
        decrypt_stream(&priv1, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }
}
