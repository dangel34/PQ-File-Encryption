use rayon::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
use std::io;
use std::io::{Cursor, Read, Write};

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, Payload, Tag},
    ChaCha20Poly1305, Key, Nonce,
};
use ml_kem::{
    kem::Decapsulate, Ciphertext, DecapsulationKey1024, DecapsulationKey512, DecapsulationKey768,
    MlKem1024, MlKem512, MlKem768, Seed,
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{
    chunk_nonce, compute_key_commitment, ct_len_for_variant, fill_chunk, hybrid_hkdf,
    make_chunk_aad, PqfHeader, PqfHeaderV4, PqfHeaderV7, PqfHeaderV8, RecipientEntryV8,
    BASE_NONCE_LEN, CHUNK_SIZE, COMPRESSION_NONE, COMPRESSION_ZSTD, HYBRID_CT_LEN_768,
    HYBRID_SEED_LEN_768, KEM_CT_LEN_1024, KEM_CT_LEN_512, KEM_CT_LEN_768, KEM_VARIANT_1024,
    KEM_VARIANT_512, KEM_VARIANT_768, KEM_VARIANT_HYBRID_768, NONCE_LEN, VERSION, VERSION_V3,
    VERSION_V4, VERSION_V5, VERSION_V6, VERSION_V7, VERSION_V8, VERSION_V9, WRAPPED_KEY_LEN,
};
use crate::hardware;
use crate::keygen::{
    PRIV_ENC_TAG, PRIV_ENC_TAG_1024, PRIV_ENC_TAG_512, PRIV_ENC_TAG_HYBRID_768, PRIV_TAG,
    PRIV_TAG_1024, PRIV_TAG_512, PRIV_TAG_HYBRID_768,
};
use crate::passphrase;

enum DkVariant {
    Kem512(DecapsulationKey512),
    Kem768(DecapsulationKey768),
    Kem1024(DecapsulationKey1024),
    HybridKem768 {
        x25519_sk: X25519StaticSecret,
        ml_dk: DecapsulationKey768,
    },
}

impl DkVariant {
    fn kem_variant(&self) -> u16 {
        match self {
            DkVariant::Kem512(_) => KEM_VARIANT_512,
            DkVariant::Kem768(_) => KEM_VARIANT_768,
            DkVariant::Kem1024(_) => KEM_VARIANT_1024,
            DkVariant::HybridKem768 { .. } => KEM_VARIANT_HYBRID_768,
        }
    }
}

/// A `Write` adapter that returns an error once more than `limit` bytes have been written.
///
/// Used to cap decompressed output for v6 (compressed) files so that an authenticated
/// but adversarially crafted compression bomb cannot cause unbounded memory allocation.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct LimitedWriter<'a> {
    inner: &'a mut dyn Write,
    remaining: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl<'a> LimitedWriter<'a> {
    fn new(inner: &'a mut dyn Write, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<'a> Write for LimitedWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if (buf.len() as u64) > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed data exceeds declared original_size limit",
            ));
        }
        let n = self.inner.write(buf)?;
        self.remaining -= n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Return value of [`decapsulate_stream_init`], used by [`PqfReader`].
pub(crate) struct StreamDecryptState {
    pub version: u8,
    pub kem_variant: u16,
    pub original_size: u64,
    pub chunk_size: usize,
    pub cipher: ChaCha20Poly1305,
    pub nonce: [u8; NONCE_LEN],
    pub v2_plaintext: Option<Zeroizing<Vec<u8>>>,
    /// SHA3-256 key commitment bound into the first chunk AAD (see `compute_key_commitment`).
    pub key_commitment: [u8; 32],
}

/// Decrypts a v2 (whole-file) `.pqf` payload. Kept for library consumers and
/// backward-compatibility tests; new code should use [`decrypt_stream`].
///
/// Returns `UnsupportedVersion` if passed a v3 streaming file so callers get a
/// clear diagnostic rather than a confusing authentication failure.
#[must_use = "decryption result must be used"]
pub fn decrypt_bytes(
    privkey_pem: &str,
    pqf_data: &[u8],
    passphrase: Option<&str>,
) -> Result<Vec<u8>, PqfileError> {
    let dk = derive_dk(privkey_pem, passphrase)?;

    let mut cursor = Cursor::new(pqf_data);
    let header = PqfHeader::read(&mut cursor)?;

    if header.version == VERSION_V3 || header.version == VERSION_V5 {
        return Err(PqfileError::UnsupportedVersion(header.version));
    }

    check_kem_variant_match(dk.kem_variant(), header.kem_variant)?;

    let ss_bytes = decapsulate_shared_secret(&dk, &header.kem_ciphertext)?;

    let header_len = header.header_len();
    let header_bytes = &pqf_data[..header_len];
    let payload = &pqf_data[header_len..];
    if payload.len() < 16 {
        return Err(PqfileError::DecryptionFailure);
    }

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&header.nonce);
    let cipher = ChaCha20Poly1305::new(key);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: payload,
                aad: header_bytes,
            },
        )
        .map_err(|_| PqfileError::DecryptionFailure)
}

/// Decrypts a `.pqf` stream, supporting v2 (whole-file), v3/v5 (chunked), and v4
/// (multi-recipient) formats, and all key variants (ML-KEM-512/768/1024, hybrid).
#[must_use = "decryption result must be used"]
pub fn decrypt_stream(
    privkey_pem: &str,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    passphrase: Option<&str>,
) -> Result<(), PqfileError> {
    let dk = derive_dk(privkey_pem, passphrase)?;

    let version = PqfHeader::read_magic_version(reader)?;

    match version {
        VERSION | VERSION_V3 | VERSION_V5 => {
            let header = PqfHeader::read_body(reader, version)?;
            check_kem_variant_match(dk.kem_variant(), header.kem_variant)?;
            let ss_bytes = decapsulate_shared_secret(&dk, &header.kem_ciphertext)?;
            let key = Key::from_slice(ss_bytes.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            match version {
                VERSION => {
                    let mut header_bytes = Vec::with_capacity(header.header_len());
                    header
                        .write(&mut header_bytes)
                        .expect("write to Vec<u8> is infallible");
                    decrypt_v2_payload(&cipher, &header.nonce, &header_bytes, reader, writer)
                }
                _ => {
                    let key_commitment = compute_key_commitment(
                        ss_bytes.as_ref(),
                        &header.nonce,
                        header.original_size,
                    );
                    decrypt_v3_chunks(
                        &cipher,
                        &header.nonce,
                        header.chunk_size as usize,
                        &key_commitment,
                        reader,
                        writer,
                    )
                }
            }
        }
        VERSION_V4 => {
            let header = PqfHeaderV4::read_body(reader)?;
            let entries: Vec<(u16, &[u8], &[u8; WRAPPED_KEY_LEN])> = header
                .recipients
                .iter()
                .map(|e| (e.kem_variant, e.kem_ciphertext.as_slice(), &e.wrapped_key))
                .collect();
            let session_key = find_session_key(&dk, &entries)?;
            let key_commitment =
                compute_key_commitment(session_key.as_ref(), &header.nonce, header.original_size);
            let key = Key::from_slice(session_key.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            decrypt_v3_chunks(
                &cipher,
                &header.nonce,
                CHUNK_SIZE,
                &key_commitment,
                reader,
                writer,
            )
        }
        VERSION_V7 => {
            let header = PqfHeaderV7::read_body(reader)?;
            let entries: Vec<(u16, &[u8], &[u8; WRAPPED_KEY_LEN])> = header
                .recipients
                .iter()
                .map(|e| (e.kem_variant, e.kem_ciphertext.as_slice(), &e.wrapped_key))
                .collect();
            let session_key = find_session_key(&dk, &entries)?;
            let key_commitment =
                compute_key_commitment(session_key.as_ref(), &header.nonce, header.original_size);
            let key = Key::from_slice(session_key.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            decrypt_v3_chunks(
                &cipher,
                &header.nonce,
                CHUNK_SIZE,
                &key_commitment,
                reader,
                writer,
            )
        }
        // v9 uses the same wire format as v8; the decryptor path is identical.
        VERSION_V8 | VERSION_V9 => {
            let header = PqfHeaderV8::read_body(reader)?;
            let session_key = find_session_key_v8(&dk, &header.recipients)?;
            let key_commitment =
                compute_key_commitment(session_key.as_ref(), &header.nonce, header.original_size);
            let key = Key::from_slice(session_key.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            decrypt_v3_chunks(
                &cipher,
                &header.nonce,
                CHUNK_SIZE,
                &key_commitment,
                reader,
                writer,
            )
        }
        VERSION_V6 => {
            let header = PqfHeader::read_body(reader, VERSION_V6)?;
            check_kem_variant_match(dk.kem_variant(), header.kem_variant)?;
            let ss_bytes = decapsulate_shared_secret(&dk, &header.kem_ciphertext)?;
            let key = Key::from_slice(ss_bytes.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            let key_commitment =
                compute_key_commitment(ss_bytes.as_ref(), &header.nonce, header.original_size);
            match header.compression_algo {
                COMPRESSION_NONE => {
                    // No compression: pipe authenticated chunks directly to writer.
                    decrypt_v3_chunks(
                        &cipher,
                        &header.nonce,
                        header.chunk_size as usize,
                        &key_commitment,
                        reader,
                        writer,
                    )
                }
                COMPRESSION_ZSTD => {
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        // Stream authenticated chunks directly into the zstd decoder so that
                        // we never hold the entire compressed payload in memory.  The
                        // LimitedWriter cap prevents authenticated compression-bomb expansion
                        // beyond the declared original_size.
                        let limit = if header.original_size > 0 {
                            header.original_size
                        } else {
                            crate::format::MAX_ORIGINAL_SIZE
                        };
                        let mut limited = LimitedWriter::new(writer, limit);
                        let mut decoder = zstd::stream::write::Decoder::new(&mut limited)
                            .map_err(PqfileError::Io)?;
                        decrypt_v3_chunks(
                            &cipher,
                            &header.nonce,
                            header.chunk_size as usize,
                            &key_commitment,
                            reader,
                            &mut decoder,
                        )?;
                        decoder.flush().map_err(PqfileError::Io)
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        let _ = (reader, writer);
                        Err(PqfileError::CompressionNotSupported)
                    }
                }
                _ => Err(PqfileError::CompressionNotSupported),
            }
        }
        v => Err(PqfileError::UnsupportedVersion(v)),
    }
}

/// Decrypts a stream, calling `progress(bytes_written, total_hint)` after each plaintext
/// chunk is written to `writer`.
///
/// `total_hint` is the expected plaintext size in bytes. Pass the `original_size` from a
/// prior [`inspect_stream`](crate::inspect::inspect_stream) call if known, or 0 to signal
/// "unknown total". The callback still fires with `(bytes_written, 0)` when total is 0;
/// callers should treat the second argument as "unknown" in that case.
///
/// In all other respects this function is identical to [`decrypt_stream`].
pub fn decrypt_stream_with_progress(
    privkey_pem: &str,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    passphrase: Option<&str>,
    total_hint: u64,
    progress: &dyn Fn(u64, u64),
) -> Result<(), PqfileError> {
    let mut tracked = crate::progress::ProgressWriter::new(writer, total_hint, progress);
    decrypt_stream(privkey_pem, reader, &mut tracked, passphrase)
}

fn find_session_key(
    dk: &DkVariant,
    entries: &[(u16, &[u8], &[u8; WRAPPED_KEY_LEN])],
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let dk_variant = dk.kem_variant();
    let mut found: Option<Zeroizing<[u8; 32]>> = None;
    let mut slots_tried: usize = 0;
    // For v4 files, each slot carries an explicit kem_variant field in the header.
    // Skipping mismatched-variant slots does not leak information beyond what the
    // header already exposes in plaintext. Slots that match the key's variant are
    // always decapsulated regardless of position, so the matched slot index is not
    // revealed by timing.
    for (kem_variant, kem_ciphertext, wrapped_key) in entries {
        if *kem_variant != dk_variant {
            continue;
        }
        slots_tried += 1;
        let ss = decapsulate_shared_secret(dk, kem_ciphertext)?;
        if let Ok(k) = unwrap_session_key(wrapped_key, &ss) {
            if found.is_none() {
                found = Some(k);
            }
        }
    }
    found.ok_or(PqfileError::NoMatchingRecipient { slots_tried })
}

/// Searches v8 entries for one whose wrapped session key is recoverable with `dk`.
///
/// Since v8 entries carry no `kem_variant` field, every slot is tried: the
/// decryptor takes the first `ct_len_for_variant(dk.kem_variant())` bytes of
/// each padded CT, attempts ML-KEM decapsulation (which always produces a value  -
/// implicit rejection returns a pseudorandom key), then verifies the AES-GCM tag.
/// A matching tag identifies the correct slot with probability ≈ 1 − 2^{−128}.
/// Always tries every slot so timing does not reveal which slot matched.
/// ML-KEM decapsulation uses implicit rejection (always produces a value), and
/// AES-GCM tag verification is constant-time; iterating all entries before
/// returning prevents a timing side-channel that would reveal the matching
/// slot index in the anonymised v8 format.
fn find_session_key_v8(
    dk: &DkVariant,
    entries: &[RecipientEntryV8],
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let ct_len = ct_len_for_variant(dk.kem_variant())?;
    let mut found: Option<Zeroizing<[u8; 32]>> = None;
    for entry in entries {
        let kem_ct = &entry.padded_ct[..ct_len];
        let ss = decapsulate_shared_secret(dk, kem_ct)?;
        if let Ok(k) = unwrap_session_key(&entry.wrapped_key, &ss) {
            if found.is_none() {
                found = Some(k);
            }
        }
    }
    found.ok_or(PqfileError::NoMatchingRecipient {
        slots_tried: entries.len(),
    })
}

fn unwrap_session_key(
    wrapped: &[u8; WRAPPED_KEY_LEN],
    ss: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(ss));
    let nonce = AesNonce::from([0u8; 12]);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(&nonce, wrapped.as_slice())
            .map_err(|_| PqfileError::DecryptionFailure)?,
    );
    if plaintext.len() != 32 {
        return Err(PqfileError::DecryptionFailure);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Initialises decryption state from a `.pqf` stream for use by [`PqfReader`].
///
/// For v2 files, `v2_plaintext` in the returned state contains the fully-decrypted
/// payload. For streaming formats it is `None`; the caller consumes chunks via the reader.
///
/// **v6 (compressed) files are not supported** - returns
/// `PqfileError::CompressionNotSupported`. Use [`decrypt_stream`] instead.
pub(crate) fn decapsulate_stream_init(
    reader: &mut dyn Read,
    privkey_pem: &str,
    passphrase: Option<&str>,
) -> Result<StreamDecryptState, PqfileError> {
    let dk = derive_dk(privkey_pem, passphrase)?;
    let version = PqfHeader::read_magic_version(reader)?;

    match version {
        VERSION | VERSION_V3 | VERSION_V5 => {
            let header = PqfHeader::read_body(reader, version)?;
            check_kem_variant_match(dk.kem_variant(), header.kem_variant)?;
            let ss_bytes = decapsulate_shared_secret(&dk, &header.kem_ciphertext)?;
            let key = Key::from_slice(ss_bytes.as_ref());
            let cipher = ChaCha20Poly1305::new(key);

            if version == VERSION {
                // v2: whole-file AEAD - header bytes needed as AAD.
                let mut header_bytes = Vec::with_capacity(header.header_len());
                header
                    .write(&mut header_bytes)
                    .expect("write to Vec<u8> is infallible");
                // Cap the read to MAX_ORIGINAL_SIZE + AEAD tag to prevent DoS via a
                // crafted header whose original_size field understates the true payload.
                let mut payload = Vec::new();
                reader
                    .take(crate::format::MAX_ORIGINAL_SIZE + 16)
                    .read_to_end(&mut payload)?;
                if payload.len() < 16 {
                    return Err(PqfileError::DecryptionFailure);
                }
                let nonce = Nonce::from_slice(&header.nonce);
                let plaintext = Zeroizing::new(
                    cipher
                        .decrypt(
                            nonce,
                            Payload {
                                msg: &payload,
                                aad: &header_bytes,
                            },
                        )
                        .map_err(|_| PqfileError::DecryptionFailure)?,
                );
                Ok(StreamDecryptState {
                    version,
                    kem_variant: header.kem_variant,
                    original_size: header.original_size,
                    chunk_size: header.chunk_size as usize,
                    cipher,
                    nonce: header.nonce,
                    v2_plaintext: Some(plaintext),
                    key_commitment: [0u8; 32],
                })
            } else {
                let key_commitment =
                    compute_key_commitment(ss_bytes.as_ref(), &header.nonce, header.original_size);
                Ok(StreamDecryptState {
                    version,
                    kem_variant: header.kem_variant,
                    original_size: header.original_size,
                    chunk_size: header.chunk_size as usize,
                    cipher,
                    nonce: header.nonce,
                    v2_plaintext: None,
                    key_commitment,
                })
            }
        }
        VERSION_V4 => {
            let header = PqfHeaderV4::read_body(reader)?;
            let entries: Vec<(u16, &[u8], &[u8; WRAPPED_KEY_LEN])> = header
                .recipients
                .iter()
                .map(|e| (e.kem_variant, e.kem_ciphertext.as_slice(), &e.wrapped_key))
                .collect();
            let session_key = find_session_key(&dk, &entries)?;
            let key_commitment =
                compute_key_commitment(session_key.as_ref(), &header.nonce, header.original_size);
            let key = Key::from_slice(session_key.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            Ok(StreamDecryptState {
                version: VERSION_V4,
                kem_variant: dk.kem_variant(),
                original_size: header.original_size,
                chunk_size: CHUNK_SIZE,
                cipher,
                nonce: header.nonce,
                v2_plaintext: None,
                key_commitment,
            })
        }
        VERSION_V7 => {
            let header = PqfHeaderV7::read_body(reader)?;
            let entries: Vec<(u16, &[u8], &[u8; WRAPPED_KEY_LEN])> = header
                .recipients
                .iter()
                .map(|e| (e.kem_variant, e.kem_ciphertext.as_slice(), &e.wrapped_key))
                .collect();
            let session_key = find_session_key(&dk, &entries)?;
            let key_commitment =
                compute_key_commitment(session_key.as_ref(), &header.nonce, header.original_size);
            let key = Key::from_slice(session_key.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            Ok(StreamDecryptState {
                version: VERSION_V7,
                kem_variant: dk.kem_variant(),
                original_size: header.original_size,
                chunk_size: CHUNK_SIZE,
                cipher,
                nonce: header.nonce,
                v2_plaintext: None,
                key_commitment,
            })
        }
        // v9 uses the same wire format as v8; only the version byte differs.
        VERSION_V8 | VERSION_V9 => {
            let header = PqfHeaderV8::read_body(reader)?;
            let session_key = find_session_key_v8(&dk, &header.recipients)?;
            let key_commitment =
                compute_key_commitment(session_key.as_ref(), &header.nonce, header.original_size);
            let key = Key::from_slice(session_key.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            Ok(StreamDecryptState {
                version,
                kem_variant: dk.kem_variant(),
                original_size: header.original_size,
                chunk_size: CHUNK_SIZE,
                cipher,
                nonce: header.nonce,
                v2_plaintext: None,
                key_commitment,
            })
        }
        VERSION_V6 => Err(PqfileError::CompressionNotSupported),
        v => Err(PqfileError::UnsupportedVersion(v)),
    }
}

/// Recovers the shared secret from a v3/v5 header for use during rekey.
pub(crate) fn decapsulate_for_rekey(
    privkey_pem: &str,
    passphrase: Option<&str>,
    header: &PqfHeader,
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let dk = derive_dk(privkey_pem, passphrase)?;
    check_kem_variant_match(dk.kem_variant(), header.kem_variant)?;
    decapsulate_shared_secret(&dk, &header.kem_ciphertext)
}

/// Recover the 32-byte session key from a multi-recipient header entry list.
///
/// Tries each entry whose KEM variant matches the private key; returns the
/// unwrapped session key on the first match, or `NoMatchingRecipient`.
pub(crate) fn recover_session_key_multi(
    privkey_pem: &str,
    passphrase: Option<&str>,
    entries: &[(u16, &[u8], &[u8; WRAPPED_KEY_LEN])],
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let dk = derive_dk(privkey_pem, passphrase)?;
    find_session_key(&dk, entries)
}

/// Recover the 32-byte session key from a v8 (variant-blind) recipient entry list.
pub(crate) fn recover_session_key_v8(
    privkey_pem: &str,
    passphrase: Option<&str>,
    entries: &[RecipientEntryV8],
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let dk = derive_dk(privkey_pem, passphrase)?;
    find_session_key_v8(&dk, entries)
}

fn check_kem_variant_match(key_variant: u16, file_variant: u16) -> Result<(), PqfileError> {
    if key_variant != file_variant {
        return Err(PqfileError::KemVariantMismatch {
            key: key_variant,
            file: file_variant,
        });
    }
    Ok(())
}

fn decrypt_v2_payload(
    cipher: &ChaCha20Poly1305,
    nonce_bytes: &[u8; NONCE_LEN],
    header_bytes: &[u8],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let mut payload = Vec::new();
    reader.read_to_end(&mut payload)?;
    if payload.len() < 16 {
        return Err(PqfileError::DecryptionFailure);
    }
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &payload,
                    aad: header_bytes,
                },
            )
            .map_err(|_| PqfileError::DecryptionFailure)?,
    );
    writer.write_all(&plaintext)?;
    Ok(())
}

fn decrypt_v3_chunks(
    cipher: &ChaCha20Poly1305,
    header_nonce: &[u8; NONCE_LEN],
    chunk_size: usize,
    key_commitment: &[u8; 32],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let base_nonce: &[u8; BASE_NONCE_LEN] = header_nonce[..BASE_NONCE_LEN].try_into().unwrap();

    let max_chunk = chunk_size + 16;
    let mut current = vec![0u8; max_chunk];
    let mut current_len = fill_chunk(reader, &mut current)?;

    if current_len == 0 {
        return Err(PqfileError::DecryptionFailure);
    }

    let mut next = vec![0u8; max_chunk];
    let mut counter: u32 = 0;

    loop {
        let next_len = fill_chunk(reader, &mut next)?;
        let is_last = next_len == 0;

        let cn = chunk_nonce(base_nonce, counter);
        let (aad_buf, aad_len) = make_chunk_aad(counter, is_last, key_commitment);

        if current_len < 16 {
            return Err(PqfileError::DecryptionFailure);
        }
        let ct_len = current_len - 16;
        let tag = Tag::<ChaCha20Poly1305>::clone_from_slice(&current[ct_len..current_len]);
        match cipher.decrypt_in_place_detached(
            Nonce::from_slice(&cn),
            &aad_buf[..aad_len],
            &mut current[..ct_len],
            &tag,
        ) {
            Ok(_) => {}
            Err(_) => {
                // is_last is true when next_len == 0 (nothing more in stream).
                // If we've successfully decrypted at least one prior chunk (counter > 0)
                // this pattern is characteristic of a stream truncated at a chunk boundary.
                return Err(if is_last && counter > 0 {
                    PqfileError::Truncated
                } else {
                    PqfileError::DecryptionFailure
                });
            }
        }

        writer.write_all(&current[..ct_len])?;

        if is_last {
            break;
        }

        counter = counter
            .checked_add(1)
            .ok_or(PqfileError::DecryptionFailure)?;
        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }

    Ok(())
}

fn derive_dk(privkey_pem: &str, passphrase: Option<&str>) -> Result<DkVariant, PqfileError> {
    let pem = pem::parse(privkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let raw = pem.contents();

    match pem.tag() {
        // ── Hardware key stubs: load seed from OS credential store ────────────
        t if t == hardware::HW_TAG_512 => {
            let seed = hardware::load_seed(raw)?;
            let arr =
                Seed::try_from(seed.as_slice()).map_err(|_| PqfileError::InvalidKeyLength {
                    expected: 64,
                    got: seed.len(),
                })?;
            Ok(DkVariant::Kem512(DecapsulationKey512::from_seed(arr)))
        }
        t if t == hardware::HW_TAG_768 => {
            let seed = hardware::load_seed(raw)?;
            let arr =
                Seed::try_from(seed.as_slice()).map_err(|_| PqfileError::InvalidKeyLength {
                    expected: 64,
                    got: seed.len(),
                })?;
            Ok(DkVariant::Kem768(DecapsulationKey768::from_seed(arr)))
        }
        t if t == hardware::HW_TAG_1024 => {
            let seed = hardware::load_seed(raw)?;
            let arr =
                Seed::try_from(seed.as_slice()).map_err(|_| PqfileError::InvalidKeyLength {
                    expected: 64,
                    got: seed.len(),
                })?;
            Ok(DkVariant::Kem1024(DecapsulationKey1024::from_seed(arr)))
        }
        t if t == hardware::HW_TAG_HYBRID_768 => {
            let seed = hardware::load_seed(raw)?;
            if seed.len() != HYBRID_SEED_LEN_768 {
                return Err(PqfileError::InvalidKeyLength {
                    expected: HYBRID_SEED_LEN_768,
                    got: seed.len(),
                });
            }
            let mut seed_arr = Zeroizing::new([0u8; HYBRID_SEED_LEN_768]);
            seed_arr.copy_from_slice(&seed);
            derive_hybrid_dk_from_seed(&seed_arr)
        }
        // ── Passphrase-encrypted keys ─────────────────────────────────────────
        t if t == PRIV_ENC_TAG_512 => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            let seed = passphrase::decrypt_seed(raw, pp)?;
            let seed_arr =
                Seed::try_from(seed.as_slice()).map_err(|_| PqfileError::InvalidKeyLength {
                    expected: 64,
                    got: seed.len(),
                })?;
            Ok(DkVariant::Kem512(DecapsulationKey512::from_seed(seed_arr)))
        }
        t if t == PRIV_ENC_TAG => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            let seed = passphrase::decrypt_seed(raw, pp)?;
            let seed_arr =
                Seed::try_from(seed.as_slice()).map_err(|_| PqfileError::InvalidKeyLength {
                    expected: 64,
                    got: seed.len(),
                })?;
            Ok(DkVariant::Kem768(DecapsulationKey768::from_seed(seed_arr)))
        }
        t if t == PRIV_ENC_TAG_1024 => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            let seed = passphrase::decrypt_seed(raw, pp)?;
            let seed_arr =
                Seed::try_from(seed.as_slice()).map_err(|_| PqfileError::InvalidKeyLength {
                    expected: 64,
                    got: seed.len(),
                })?;
            Ok(DkVariant::Kem1024(DecapsulationKey1024::from_seed(
                seed_arr,
            )))
        }
        t if t == PRIV_TAG_512 => {
            let seed = Seed::try_from(raw).map_err(|_| PqfileError::InvalidKeyLength {
                expected: 64,
                got: raw.len(),
            })?;
            Ok(DkVariant::Kem512(DecapsulationKey512::from_seed(seed)))
        }
        t if t == PRIV_TAG => {
            let seed = Seed::try_from(raw).map_err(|_| PqfileError::InvalidKeyLength {
                expected: 64,
                got: raw.len(),
            })?;
            Ok(DkVariant::Kem768(DecapsulationKey768::from_seed(seed)))
        }
        t if t == PRIV_TAG_1024 => {
            let seed = Seed::try_from(raw).map_err(|_| PqfileError::InvalidKeyLength {
                expected: 64,
                got: raw.len(),
            })?;
            Ok(DkVariant::Kem1024(DecapsulationKey1024::from_seed(seed)))
        }
        t if t == PRIV_ENC_TAG_HYBRID_768 => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            let seed = passphrase::decrypt_hybrid_seed(raw, pp)?;
            derive_hybrid_dk_from_seed(&seed)
        }
        t if t == PRIV_TAG_HYBRID_768 => {
            if raw.len() != HYBRID_SEED_LEN_768 {
                return Err(PqfileError::InvalidKeyLength {
                    expected: HYBRID_SEED_LEN_768,
                    got: raw.len(),
                });
            }
            let mut seed = Zeroizing::new([0u8; HYBRID_SEED_LEN_768]);
            seed.copy_from_slice(raw);
            derive_hybrid_dk_from_seed(&seed)
        }
        _ => Err(PqfileError::InvalidPem(
            "unrecognised private key tag".to_owned(),
        )),
    }
}

fn derive_hybrid_dk_from_seed(seed: &[u8; HYBRID_SEED_LEN_768]) -> Result<DkVariant, PqfileError> {
    let x25519_scalar: [u8; 32] = seed[..32].try_into().unwrap();
    let ml_seed_bytes = &seed[32..];

    let x25519_sk = X25519StaticSecret::from(x25519_scalar);
    let ml_seed = Seed::try_from(ml_seed_bytes).map_err(|_| PqfileError::InvalidKeyLength {
        expected: 64,
        got: ml_seed_bytes.len(),
    })?;
    let ml_dk = DecapsulationKey768::from_seed(ml_seed);

    Ok(DkVariant::HybridKem768 { x25519_sk, ml_dk })
}

fn decapsulate_shared_secret(
    dk: &DkVariant,
    kem_ct_bytes: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    match dk {
        DkVariant::Kem512(dk) => {
            let ct = Ciphertext::<MlKem512>::try_from(kem_ct_bytes).map_err(|_| {
                PqfileError::InvalidKeyLength {
                    expected: KEM_CT_LEN_512,
                    got: kem_ct_bytes.len(),
                }
            })?;
            let ss = dk.decapsulate(&ct);
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok(ss_bytes)
        }
        DkVariant::Kem768(dk) => {
            let ct = Ciphertext::<MlKem768>::try_from(kem_ct_bytes).map_err(|_| {
                PqfileError::InvalidKeyLength {
                    expected: KEM_CT_LEN_768,
                    got: kem_ct_bytes.len(),
                }
            })?;
            let ss = dk.decapsulate(&ct);
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok(ss_bytes)
        }
        DkVariant::Kem1024(dk) => {
            let ct = Ciphertext::<MlKem1024>::try_from(kem_ct_bytes).map_err(|_| {
                PqfileError::InvalidKeyLength {
                    expected: KEM_CT_LEN_1024,
                    got: kem_ct_bytes.len(),
                }
            })?;
            let ss = dk.decapsulate(&ct);
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok(ss_bytes)
        }
        DkVariant::HybridKem768 { x25519_sk, ml_dk } => {
            if kem_ct_bytes.len() != HYBRID_CT_LEN_768 {
                return Err(PqfileError::InvalidKeyLength {
                    expected: HYBRID_CT_LEN_768,
                    got: kem_ct_bytes.len(),
                });
            }
            let eph_pk_bytes: [u8; 32] = kem_ct_bytes[..32].try_into().unwrap();
            let eph_pk = X25519PublicKey::from(eph_pk_bytes);
            let x25519_ss = Zeroizing::new(x25519_sk.diffie_hellman(&eph_pk));

            let ml_ct_bytes = &kem_ct_bytes[32..];
            let ml_ct = Ciphertext::<MlKem768>::try_from(ml_ct_bytes).map_err(|_| {
                PqfileError::InvalidKeyLength {
                    expected: KEM_CT_LEN_768,
                    got: ml_ct_bytes.len(),
                }
            })?;
            let ml_ss = ml_dk.decapsulate(&ml_ct);

            hybrid_hkdf(x25519_ss.as_bytes(), ml_ss.as_slice())
        }
    }
}

/// Parallel version of [`decrypt_stream`] for v3/v5 (chunked) files.
///
/// Non-parallel formats (v2, v4, v6) are forwarded to [`decrypt_stream`]
/// transparently. `batch_size` controls how many chunks are decrypted
/// concurrently per rayon batch.
#[must_use = "decryption result must be used"]
pub fn decrypt_stream_parallel(
    privkey_pem: &str,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    passphrase: Option<&str>,
    batch_size: usize,
) -> Result<(), PqfileError> {
    if batch_size <= 1 {
        return decrypt_stream(privkey_pem, reader, writer, passphrase);
    }

    // Peek at the 5-byte preamble (MAGIC + VERSION) to decide the code path.
    let mut preamble = [0u8; 5];
    reader.read_exact(&mut preamble).map_err(PqfileError::Io)?;
    if &preamble[..4] != crate::format::MAGIC.as_ref() {
        return Err(PqfileError::InvalidMagic);
    }
    let version = preamble[4];

    if version != VERSION_V3 && version != VERSION_V5 {
        // Stitch the consumed bytes back and delegate to single-threaded path.
        let prefix = Cursor::new(preamble.to_vec());
        let mut chained = prefix.chain(&mut *reader);
        return decrypt_stream(privkey_pem, &mut chained, writer, passphrase);
    }

    // v3 / v5: parallel chunk decryption
    let dk = derive_dk(privkey_pem, passphrase)?;
    let header = PqfHeader::read_body(reader, version)?;
    check_kem_variant_match(dk.kem_variant(), header.kem_variant)?;
    let ss_bytes = decapsulate_shared_secret(&dk, &header.kem_ciphertext)?;
    let key_bytes = Zeroizing::new(*ss_bytes);
    let chunk_size = header.chunk_size as usize;
    let max_chunk = chunk_size + 16;
    let base_nonce: [u8; BASE_NONCE_LEN] = header.nonce[..BASE_NONCE_LEN].try_into().unwrap();

    let key_commitment =
        compute_key_commitment(key_bytes.as_ref(), &header.nonce, header.original_size);

    let mut first = vec![0u8; max_chunk];
    let first_len = fill_chunk(reader, &mut first)?;
    if first_len == 0 {
        return Err(PqfileError::DecryptionFailure);
    }

    let mut carry: Option<(Vec<u8>, usize)> = Some((first, first_len));
    let mut counter: u32 = 0;

    loop {
        let mut batch: Vec<(Vec<u8>, usize)> = Vec::with_capacity(batch_size);
        if let Some(c) = carry.take() {
            batch.push(c);
        }
        while batch.len() < batch_size {
            let mut buf = vec![0u8; max_chunk];
            let n = fill_chunk(reader, &mut buf)?;
            if n == 0 {
                break;
            }
            batch.push((buf, n));
        }
        if batch.is_empty() {
            break;
        }

        let mut peek = vec![0u8; max_chunk];
        let peek_len = fill_chunk(reader, &mut peek)?;
        let batch_is_final = peek_len == 0;
        if !batch_is_final {
            carry = Some((peek, peek_len));
        }

        let batch_len = batch.len();
        let batch_start = counter;

        // key_commitment is [u8; 32] (Copy) - captured by value.
        let results: Vec<Result<Zeroizing<Vec<u8>>, PqfileError>> = batch
            .into_par_iter()
            .enumerate()
            .map(|(i, (mut ct_buf, ct_len))| {
                let c = batch_start
                    .checked_add(i as u32)
                    .ok_or(PqfileError::DecryptionFailure)?;
                let is_last = batch_is_final && i == batch_len - 1;
                let cn = chunk_nonce(&base_nonce, c);
                let (aad_buf, aad_len) = make_chunk_aad(c, is_last, &key_commitment);
                if ct_len < 16 {
                    return Err(PqfileError::DecryptionFailure);
                }
                let pt_len = ct_len - 16;
                let tag = Tag::<ChaCha20Poly1305>::clone_from_slice(&ct_buf[pt_len..ct_len]);
                let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_ref()));
                cipher
                    .decrypt_in_place_detached(
                        Nonce::from_slice(&cn),
                        &aad_buf[..aad_len],
                        &mut ct_buf[..pt_len],
                        &tag,
                    )
                    .map_err(|_| {
                        // Mirror decrypt_v3_chunks: a final-chunk AEAD failure after at
                        // least one prior chunk indicates truncation, not bit corruption.
                        if is_last && c > 0 {
                            PqfileError::Truncated
                        } else {
                            PqfileError::DecryptionFailure
                        }
                    })?;
                ct_buf.truncate(pt_len);
                // Wrap in Zeroizing so plaintext bytes are overwritten when the Vec is dropped.
                Ok(Zeroizing::new(ct_buf))
            })
            .collect();

        for r in results {
            writer.write_all(&r?)?;
        }

        counter = batch_start
            .checked_add(batch_len as u32)
            .ok_or(PqfileError::DecryptionFailure)?;
        if batch_is_final {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_arch = "wasm32"))]
    use crate::encrypt::encrypt_stream_compressed;
    use crate::encrypt::{encrypt_bytes, encrypt_stream};
    use crate::format::{KEM_CT_LEN_768, KEM_VARIANT_768, MAGIC, NONCE_LEN, VERSION};
    use crate::keygen::keygen_bytes;

    #[test]
    fn decrypt_rejects_truncated_payload() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(VERSION);
        data.extend_from_slice(&KEM_VARIANT_768.to_le_bytes());
        data.extend_from_slice(&[0u8; KEM_CT_LEN_768]);
        data.extend_from_slice(&[0u8; NONCE_LEN]);
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);

        let result = decrypt_bytes(&priv_pem, &data, None);
        assert!(matches!(result, Err(PqfileError::DecryptionFailure)));
    }

    #[test]
    fn decrypt_rejects_oversized_original_size_field() {
        use crate::format::{KEM_CT_LEN_768, MAGIC, VERSION_V3};
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(VERSION_V3);
        data.extend_from_slice(&KEM_VARIANT_768.to_le_bytes());
        data.extend_from_slice(&[0u8; KEM_CT_LEN_768]);
        data.extend_from_slice(&[0u8; NONCE_LEN]);
        // original_size = MAX_ORIGINAL_SIZE + 1 (1 TiB + 1 byte) - must be rejected.
        let oversized: u64 = (1u64 << 40) + 1;
        data.extend_from_slice(&oversized.to_le_bytes());

        let result = decrypt_stream(&priv_pem, &mut data.as_slice(), &mut Vec::new(), None);
        assert!(
            matches!(result, Err(PqfileError::Io(_))),
            "expected Io error for oversized original_size, got {result:?}"
        );
    }

    #[test]
    fn decrypt_bytes_with_encrypted_key_and_correct_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("correct horse")).unwrap();
        let plaintext = b"passphrase-protected roundtrip";
        let pqf = encrypt_bytes(&pub_pem, plaintext).unwrap();
        let result = decrypt_bytes(&priv_pem, &pqf, Some("correct horse")).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn decrypt_bytes_with_encrypted_key_wrong_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("correct")).unwrap();
        let plaintext = b"passphrase-protected roundtrip";
        let pqf = encrypt_bytes(&pub_pem, plaintext).unwrap();
        let result = decrypt_bytes(&priv_pem, &pqf, Some("wrong"));
        assert!(matches!(result, Err(PqfileError::WrongPassphrase)));
    }

    #[test]
    fn decrypt_bytes_encrypted_key_without_passphrase_returns_error() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("secret")).unwrap();
        let pqf = encrypt_bytes(&pub_pem, b"data").unwrap();
        let result = decrypt_bytes(&priv_pem, &pqf, None);
        assert!(matches!(result, Err(PqfileError::PassphraseRequired)));
    }

    #[test]
    fn decrypt_bytes_rejects_v3_file() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut reader: &[u8] = b"payload";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 7, CHUNK_SIZE, &mut reader, &mut writer).unwrap();
        let result = decrypt_bytes(&priv_pem, &writer, None);
        assert!(matches!(result, Err(PqfileError::UnsupportedVersion(0x03))));
    }

    #[test]
    fn decrypt_bytes_rejects_v5_file() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut reader: &[u8] = b"payload";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 7, 4096, &mut reader, &mut writer).unwrap();
        let result = decrypt_bytes(&priv_pem, &writer, None);
        assert!(matches!(result, Err(PqfileError::UnsupportedVersion(0x05))));
    }

    #[test]
    fn decrypt_rejects_kem_variant_mismatch() {
        let (pub_768, _) = keygen_bytes(768, None).unwrap();
        let (_, priv_1024) = keygen_bytes(1024, None).unwrap();
        let mut enc = Vec::new();
        encrypt_stream(&pub_768, 5, CHUNK_SIZE, &mut b"hello".as_slice(), &mut enc).unwrap();
        let mut dec = Vec::new();
        let result = decrypt_stream(&priv_1024, &mut enc.as_slice(), &mut dec, None);
        assert!(matches!(
            result,
            Err(PqfileError::KemVariantMismatch { .. })
        ));
    }

    // ── decrypt_stream v2 backward-compatibility ───────────────────────────

    #[test]
    fn decrypt_stream_handles_v2_file() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"v2 backward compat check";
        let pqf = encrypt_bytes(&pub_pem, plaintext).unwrap();
        let mut reader: &[u8] = &pqf;
        let mut output = Vec::new();
        decrypt_stream(&priv_pem, &mut reader, &mut output, None).unwrap();
        assert_eq!(output, plaintext);
    }

    // ── decrypt_stream v3 streaming roundtrips ────────────────────────────

    #[test]
    fn stream_roundtrip_empty() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: &[u8] = &[];
        let mut enc_out = Vec::new();
        encrypt_stream(&pub_pem, 0, CHUNK_SIZE, &mut { plaintext }, &mut enc_out).unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[test]
    fn stream_roundtrip_small() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"small streaming payload";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[test]
    fn stream_roundtrip_exact_chunk_boundary() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = vec![0xDDu8; CHUNK_SIZE];
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[test]
    fn stream_roundtrip_multi_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0..u8::MAX).cycle().take(CHUNK_SIZE * 3 + 7).collect();
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[test]
    fn stream_roundtrip_with_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("stream-pass")).unwrap();
        let plaintext = b"passphrase streaming roundtrip";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(
            &priv_pem,
            &mut enc_out.as_slice(),
            &mut dec_out,
            Some("stream-pass"),
        )
        .unwrap();
        assert_eq!(dec_out, plaintext.as_slice());
    }

    #[test]
    fn stream_decrypt_rejects_truncated_ciphertext() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = vec![0u8; CHUNK_SIZE + 100];
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        // Keep only the first (non-last) chunk; counter==0 so we get DecryptionFailure.
        use crate::format::HEADER_LEN_768;
        let truncated = &enc_out[..HEADER_LEN_768 + CHUNK_SIZE + 16];
        let mut src: &[u8] = truncated;
        let mut dec_out = Vec::new();
        let result = decrypt_stream(&priv_pem, &mut src, &mut dec_out, None);
        assert!(matches!(result, Err(PqfileError::DecryptionFailure)));
    }

    #[test]
    fn stream_decrypt_truncated_mid_stream_returns_truncated_error() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        // Three chunks: keep the first two complete ciphertext chunks; drop the third.
        let plaintext = vec![0u8; 2 * CHUNK_SIZE + 100];
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        use crate::format::HEADER_LEN_768;
        let keep = HEADER_LEN_768 + 2 * (CHUNK_SIZE + 16);
        let truncated = &enc_out[..keep];
        let mut src: &[u8] = truncated;
        let mut dec_out = Vec::new();
        let result = decrypt_stream(&priv_pem, &mut src, &mut dec_out, None);
        assert!(matches!(result, Err(PqfileError::Truncated)));
    }

    #[test]
    fn stream_decrypt_rejects_tampered_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"tamper test payload";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        use crate::format::HEADER_LEN_768;
        let flip_pos = HEADER_LEN_768 + 4;
        enc_out[flip_pos] ^= 0xFF;

        let mut dec_out = Vec::new();
        let result = decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None);
        assert!(matches!(result, Err(PqfileError::DecryptionFailure)));
    }

    // ── ML-KEM-1024 roundtrips ─────────────────────────────────────────────

    #[test]
    fn stream_roundtrip_1024() {
        let (pub_pem, priv_pem) = keygen_bytes(1024, None).unwrap();
        let plaintext = b"ML-KEM-1024 streaming roundtrip";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[test]
    fn stream_roundtrip_1024_with_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(1024, Some("1024-pass")).unwrap();
        let plaintext = b"ML-KEM-1024 passphrase roundtrip";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(
            &priv_pem,
            &mut enc_out.as_slice(),
            &mut dec_out,
            Some("1024-pass"),
        )
        .unwrap();
        assert_eq!(dec_out, plaintext.as_slice());
    }

    #[test]
    fn decrypt_stream_rejects_unknown_version() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut fake: Vec<u8> = b"PQFL".to_vec();
        fake.push(0xFF);
        let mut out = Vec::new();
        let result = decrypt_stream(&priv_pem, &mut fake.as_slice(), &mut out, None);
        assert!(matches!(result, Err(PqfileError::UnsupportedVersion(0xFF))));
    }

    // ── ML-KEM-512 roundtrips ─────────────────────────────────────────────

    #[test]
    fn stream_roundtrip_512() {
        let (pub_pem, priv_pem) = keygen_bytes(512, None).unwrap();
        let plaintext = b"ML-KEM-512 streaming roundtrip";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[test]
    fn stream_roundtrip_512_with_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(512, Some("512-pass")).unwrap();
        let plaintext = b"ML-KEM-512 passphrase roundtrip";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(
            &priv_pem,
            &mut enc_out.as_slice(),
            &mut dec_out,
            Some("512-pass"),
        )
        .unwrap();
        assert_eq!(dec_out, plaintext.as_slice());
    }

    #[test]
    fn decrypt_rejects_512_key_on_768_file() {
        let (pub_768, _) = keygen_bytes(768, None).unwrap();
        let (_, priv_512) = keygen_bytes(512, None).unwrap();
        let mut enc = Vec::new();
        encrypt_stream(&pub_768, 5, CHUNK_SIZE, &mut b"hello".as_slice(), &mut enc).unwrap();
        let mut dec = Vec::new();
        let result = decrypt_stream(&priv_512, &mut enc.as_slice(), &mut dec, None);
        assert!(matches!(
            result,
            Err(PqfileError::KemVariantMismatch { .. })
        ));
    }

    // ── Configurable chunk size / v5 format ───────────────────────────────

    #[test]
    fn stream_roundtrip_custom_chunk_size_small() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"custom chunk size roundtrip";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            512,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[test]
    fn stream_roundtrip_custom_chunk_size_multi_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(1024 * 3 + 17).collect();
        let chunk_size = 1024;
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            chunk_size,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn v6_roundtrip_small() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"compress-then-encrypt roundtrip";
        let mut enc_out = Vec::new();
        encrypt_stream_compressed(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            3,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        // Header version byte should be v6.
        let version_pos = crate::format::MAGIC.len();
        assert_eq!(enc_out[version_pos], crate::format::VERSION_V6);

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn v6_roundtrip_multi_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        // Repeated pattern compresses well.
        let plaintext: Vec<u8> = (0u8..=63).cycle().take(CHUNK_SIZE * 2 + 17).collect();
        let mut enc_out = Vec::new();
        encrypt_stream_compressed(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            3,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn v6_compressed_ciphertext_smaller_than_v3_for_compressible_input() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        // Highly compressible: 256 KiB of zeros.
        let plaintext = vec![0u8; 256 * 1024];

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
            3,
            &mut plaintext.as_slice(),
            &mut v6_out,
        )
        .unwrap();

        // Compressed ciphertext must be strictly smaller.
        assert!(
            v6_out.len() < v3_out.len(),
            "v6 len {} should be < v3 len {}",
            v6_out.len(),
            v3_out.len()
        );

        // And must still decrypt correctly.
        let mut dec_out = Vec::new();
        decrypt_stream(&priv_pem, &mut v6_out.as_slice(), &mut dec_out, None).unwrap();
        assert_eq!(dec_out, plaintext);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn v6_roundtrip_rejects_tampered_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"v6 tamper test";
        let mut enc_out = Vec::new();
        encrypt_stream_compressed(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            1,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        // Flip a byte after the header.
        let header_len = {
            use crate::format::{
                HEADER_LEN_768, V5_CHUNK_SIZE_FIELD_LEN, V6_COMPRESSION_FIELD_LEN,
            };
            HEADER_LEN_768 + V5_CHUNK_SIZE_FIELD_LEN + V6_COMPRESSION_FIELD_LEN
        };
        enc_out[header_len + 2] ^= 0xFF;

        let mut dec_out = Vec::new();
        let result = decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None);
        assert!(matches!(result, Err(PqfileError::DecryptionFailure)));
    }

    #[test]
    fn v5_roundtrip_rejects_tampered_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"v5 tamper test";
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            4096,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();

        // Flip a byte in the ciphertext region (after the v5 header)
        let header_len = {
            use crate::format::{HEADER_LEN_768, V5_CHUNK_SIZE_FIELD_LEN};
            HEADER_LEN_768 + V5_CHUNK_SIZE_FIELD_LEN
        };
        enc_out[header_len + 2] ^= 0xFF;

        let mut dec_out = Vec::new();
        let result = decrypt_stream(&priv_pem, &mut enc_out.as_slice(), &mut dec_out, None);
        assert!(matches!(result, Err(PqfileError::DecryptionFailure)));
    }

    // ── Parallel decryption ───────────────────────────────────────────────────

    #[test]
    fn parallel_decrypt_roundtrip_small() {
        use crate::encrypt::encrypt_stream_parallel;
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"parallel decrypt small";
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
        decrypt_stream_parallel(&priv_pem, &mut ct.as_slice(), &mut out, None, 4).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn parallel_decrypt_roundtrip_multi_batch() {
        use crate::encrypt::encrypt_stream_parallel;
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 12 + 3).collect();
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
        decrypt_stream_parallel(&priv_pem, &mut ct.as_slice(), &mut out, None, 4).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn parallel_decrypt_falls_back_for_non_v3_v5() {
        // Encrypt with standard (v3) then parallel-decrypt should still work.
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"fallback test";
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream_parallel(&priv_pem, &mut ct.as_slice(), &mut out, None, 4).unwrap();
        assert_eq!(out, plaintext);
    }

    // ── Fix #4: parallel decrypt distinguishes Truncated from DecryptionFailure ─

    #[test]
    fn parallel_decrypt_truncated_mid_stream_returns_truncated_error() {
        use crate::format::HEADER_LEN_768;
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        // Three chunks so truncation drops the third; counter > 0 when failure occurs.
        let plaintext = vec![0u8; 2 * CHUNK_SIZE + 100];
        let mut enc_out = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc_out,
        )
        .unwrap();
        // Keep header + first two complete ciphertext chunks; drop the third.
        let keep = HEADER_LEN_768 + 2 * (CHUNK_SIZE + 16);
        let mut truncated: &[u8] = &enc_out[..keep];
        let mut out = Vec::new();
        let result = decrypt_stream_parallel(&priv_pem, &mut truncated, &mut out, None, 4);
        assert!(
            matches!(result, Err(PqfileError::Truncated)),
            "expected Truncated, got {result:?}"
        );
    }

    // ── Fix #3: find_session_key completes all slots even when match is first ──

    #[test]
    fn v4_multi_recipient_last_slot_matches() {
        use crate::encrypt::encrypt_stream_multi;
        // Two recipients; key to be used (priv2) is in the SECOND slot.
        let (pub1, _priv1) = keygen_bytes(768, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let plaintext = b"last-slot recipient";
        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str(), pub2.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv2, &mut enc.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    // ── Fix #6: v6 decompression bomb is capped at original_size ─────────────

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn v6_decompression_bomb_rejected_at_original_size_cap() {
        // LimitedWriter must reject decompressed output that exceeds original_size.
        use super::LimitedWriter;
        use std::io::Write;

        let small_limit: u64 = 10;
        let mut sink = Vec::new();
        let mut lw = LimitedWriter::new(&mut sink, small_limit);

        // Writing up to the limit is fine.
        lw.write_all(&[0u8; 10]).unwrap();

        // One more byte exceeds the limit.
        let result = lw.write(&[0u8; 1]);
        assert!(result.is_err(), "expected error when limit exceeded");
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decrypt_stream_with_progress_fires_and_accurate() {
        use std::sync::{Arc, Mutex};
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 2 + 77).collect();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .unwrap();

        let calls: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let calls2 = Arc::clone(&calls);
        let mut out = Vec::new();
        super::decrypt_stream_with_progress(
            &priv_pem,
            &mut ct.as_slice(),
            &mut out,
            None,
            plaintext.len() as u64,
            &move |done, total| {
                calls2.lock().unwrap().push((done, total));
            },
        )
        .unwrap();

        assert_eq!(out, plaintext);
        let log = calls.lock().unwrap().clone();
        assert!(!log.is_empty(), "progress callback must fire");
        let (last_done, last_total) = *log.last().unwrap();
        assert_eq!(last_done, plaintext.len() as u64);
        assert_eq!(last_total, plaintext.len() as u64);
    }
}
