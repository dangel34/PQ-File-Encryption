use std::io::{Read, Write};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::PqfileError;

/// File magic bytes: ASCII `PQFL`.
pub const MAGIC: &[u8; 4] = b"PQFL";
/// v2 format version byte (whole-file AEAD, single recipient).
pub const VERSION: u8 = 0x02;
/// v3 format version byte (64 KiB chunked STREAM, single recipient).
pub const VERSION_V3: u8 = 0x03;
/// Multi-recipient format: MAGIC | 0x04 | COUNT(2) | [VARIANT(2) | CT(var) | WRAPPED_KEY(48)]... | NONCE(12) | ORIGINAL_SIZE(8)
pub const VERSION_V4: u8 = 0x04;
/// Single-recipient streaming with configurable chunk size: same as v3 but appends CHUNK_SIZE(4) after ORIGINAL_SIZE.
pub const VERSION_V5: u8 = 0x05;
/// Compress-then-encrypt: same as v5 layout but appends COMPRESSION_ALGO(1) after CHUNK_SIZE.
pub const VERSION_V6: u8 = 0x06;
/// Anonymous multi-recipient: like v4 but all KEM ciphertexts are padded to the maximum
/// variant size (1568 bytes) and recipient entries are written in shuffled order.
/// Format: MAGIC | 0x07 | COUNT(2) | [VARIANT(2) | PADDED_CT(1568) | WRAPPED_KEY(48)]... | NONCE(12) | ORIGINAL_SIZE(8)
pub const VERSION_V7: u8 = 0x07;
/// Variant-blind anonymous multi-recipient: like v7 but the per-slot KEM variant field is
/// dropped entirely. An observer learns only the recipient count; no key-type information
/// is exposed. Supersedes v7 for `--anonymous-recipients` in pqfile 4.0+.
/// Format: MAGIC | 0x08 | COUNT(2) | [PADDED_CT(1568) | WRAPPED_KEY(48)]... | NONCE(12) | ORIGINAL_SIZE(8)
pub const VERSION_V8: u8 = 0x08;

/// Maximum KEM ciphertext length across all supported variants (ML-KEM-1024).
/// All v7 recipient entries use this fixed CT slot size.
pub const PADDED_CT_LEN: usize = KEM_CT_LEN_1024;

/// ML-KEM-512 variant identifier.
pub const KEM_VARIANT_512: u16 = 512;
/// ML-KEM-768 variant identifier (default security level).
pub const KEM_VARIANT_768: u16 = 768;
/// ML-KEM-1024 variant identifier.
pub const KEM_VARIANT_1024: u16 = 1024;
/// Hybrid X25519+ML-KEM-768 variant identifier (0x0301).
pub const KEM_VARIANT_HYBRID_768: u16 = 0x0301;

/// ML-KEM-512 ciphertext length in bytes.
pub const KEM_CT_LEN_512: usize = 768;
/// ML-KEM-512 encapsulation key (public key) length in bytes.
pub const EK_LEN_512: usize = 800;

/// ML-KEM-768 ciphertext length in bytes.
pub const KEM_CT_LEN_768: usize = 1088;
/// ML-KEM-768 encapsulation key (public key) length in bytes.
pub const EK_LEN_768: usize = 1184;

/// ML-KEM-1024 ciphertext length in bytes.
pub const KEM_CT_LEN_1024: usize = 1568;
/// ML-KEM-1024 encapsulation key (public key) length in bytes.
pub const EK_LEN_1024: usize = 1568;

/// Hybrid X25519+ML-KEM-768 sizes.
/// KEM CT = X25519 ephemeral public key (32) + ML-KEM-768 ciphertext (1088).
pub const X25519_PUBKEY_LEN: usize = 32;
/// X25519 static public key length (same as ephemeral).
pub const X25519_SCALAR_LEN: usize = 32;
/// Hybrid KEM ciphertext length: X25519 ephemeral pubkey (32) + ML-KEM-768 CT (1088).
pub const HYBRID_CT_LEN_768: usize = X25519_PUBKEY_LEN + KEM_CT_LEN_768;
/// Combined hybrid public key stored in PEM: X25519 pubkey (32) + ML-KEM-768 EK (1184).
pub const HYBRID_EK_LEN_768: usize = X25519_PUBKEY_LEN + EK_LEN_768;
/// Combined hybrid private key stored in PEM: X25519 scalar (32) + ML-KEM-768 seed (64).
pub const HYBRID_SEED_LEN_768: usize = X25519_SCALAR_LEN + 64;

/// AES-256-GCM wrapped session key size: 32-byte key + 16-byte tag.
pub const WRAPPED_KEY_LEN: usize = 48;

/// Full ChaCha20-Poly1305 nonce length (12 bytes = 8-byte base + 4-byte counter).
pub const NONCE_LEN: usize = 12;

/// Fixed prefix: MAGIC(4) + VERSION(1) + KEM_VARIANT_768(2) = 7 bytes.
const HEADER_PREFIX_LEN: usize = 7;
/// Fixed suffix: NONCE(12) + ORIGINAL_SIZE(8) = 20 bytes.
const HEADER_SUFFIX_LEN: usize = 20;

#[allow(dead_code)]
pub(crate) const HEADER_LEN_512: usize = HEADER_PREFIX_LEN + KEM_CT_LEN_512 + HEADER_SUFFIX_LEN;
pub(crate) const HEADER_LEN_768: usize = HEADER_PREFIX_LEN + KEM_CT_LEN_768 + HEADER_SUFFIX_LEN;
#[allow(dead_code)]
pub(crate) const HEADER_LEN_1024: usize = HEADER_PREFIX_LEN + KEM_CT_LEN_1024 + HEADER_SUFFIX_LEN;
/// Extra bytes added to any header when version is VERSION_V5 (the chunk_size u32 field).
pub const V5_CHUNK_SIZE_FIELD_LEN: usize = 4;
/// Extra byte added to VERSION_V6 headers for the compression algorithm identifier.
pub const V6_COMPRESSION_FIELD_LEN: usize = 1;

/// Compression algorithm identifiers used in v6 format.
pub const COMPRESSION_NONE: u8 = 0x00;
/// zstd compression (RFC 8878) for v6 format.
pub const COMPRESSION_ZSTD: u8 = 0x01;

/// Chunk size for v3/v4 streaming encryption (64 KiB).
pub const CHUNK_SIZE: usize = 65536;

/// Length of the base nonce used in v3/v4 streaming (8 bytes; last 4 are the counter).
pub const BASE_NONCE_LEN: usize = 8;

/// AAD prefix for v3/v4 stream chunks.
pub(crate) const STREAM_AAD_PREFIX: &[u8] = b"pqfile";

// ── Single-recipient header (v2 / v3) ────────────────────────────────────

/// Parsed header for single-recipient formats (v2, v3, v5, v6).
pub(crate) struct PqfHeader {
    /// Format version byte.
    pub version: u8,
    /// KEM variant identifier (e.g. 768 for ML-KEM-768).
    pub kem_variant: u16,
    /// KEM ciphertext bytes (length depends on the variant).
    pub kem_ciphertext: Vec<u8>,
    /// Per-file or per-stream base nonce (12 bytes).
    pub nonce: [u8; NONCE_LEN],
    /// Uncompressed plaintext size in bytes (informational; not trusted for allocation).
    pub original_size: u64,
    /// Chunk size for v3/v5/v6 streaming. Stored on disk only in v5/v6; v3 uses CHUNK_SIZE.
    pub chunk_size: u32,
    /// Compression algorithm for v6 format. Always COMPRESSION_NONE for v2/v3/v4/v5.
    pub compression_algo: u8,
}

impl PqfHeader {
    /// Total byte length of this header when serialized.
    pub fn header_len(&self) -> usize {
        let base = HEADER_PREFIX_LEN + self.kem_ciphertext.len() + HEADER_SUFFIX_LEN;
        match self.version {
            v if v == VERSION_V5 => base + V5_CHUNK_SIZE_FIELD_LEN,
            v if v == VERSION_V6 => base + V5_CHUNK_SIZE_FIELD_LEN + V6_COMPRESSION_FIELD_LEN,
            _ => base,
        }
    }

    /// Serializes the header to `w`.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(MAGIC)?;
        w.write_all(&[self.version])?;
        w.write_all(&self.kem_variant.to_le_bytes())?;
        w.write_all(&self.kem_ciphertext)?;
        w.write_all(&self.nonce)?;
        w.write_all(&self.original_size.to_le_bytes())?;
        if self.version == VERSION_V5 || self.version == VERSION_V6 {
            w.write_all(&self.chunk_size.to_le_bytes())?;
        }
        if self.version == VERSION_V6 {
            w.write_all(&[self.compression_algo])?;
        }
        Ok(())
    }

    /// Deserializes a v2/v3/v5/v6 header from `r`. Returns `UnsupportedVersion` for v4/v7.
    pub fn read<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let version = Self::read_magic_version(r)?;
        if version != VERSION
            && version != VERSION_V3
            && version != VERSION_V5
            && version != VERSION_V6
        {
            return Err(PqfileError::UnsupportedVersion(version));
        }
        Self::read_body(r, version)
    }

    /// Reads MAGIC + VERSION byte; returns the version on success.
    pub fn read_magic_version<R: Read + ?Sized>(r: &mut R) -> Result<u8, PqfileError> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(PqfileError::InvalidMagic);
        }
        let mut v = [0u8; 1];
        r.read_exact(&mut v)?;
        Ok(v[0])
    }

    /// Reads the header body (everything after MAGIC + VERSION).
    pub fn read_body<R: Read + ?Sized>(r: &mut R, version: u8) -> Result<Self, PqfileError> {
        let mut kem_variant_bytes = [0u8; 2];
        r.read_exact(&mut kem_variant_bytes)?;
        let kem_variant = u16::from_le_bytes(kem_variant_bytes);

        let ct_len = ct_len_for_variant(kem_variant)?;

        let mut kem_ciphertext = vec![0u8; ct_len];
        r.read_exact(&mut kem_ciphertext)?;

        let (nonce, original_size) = read_nonce_and_size(r)?;
        let (chunk_size, compression_algo) = if version == VERSION_V5 {
            let mut cs = [0u8; 4];
            r.read_exact(&mut cs)?;
            let val = u32::from_le_bytes(cs);
            validate_chunk_size(val)?;
            (val, COMPRESSION_NONE)
        } else if version == VERSION_V6 {
            let mut cs = [0u8; 4];
            r.read_exact(&mut cs)?;
            let val = u32::from_le_bytes(cs);
            validate_chunk_size(val)?;
            let mut algo = [0u8; 1];
            r.read_exact(&mut algo)?;
            (val, algo[0])
        } else {
            (CHUNK_SIZE as u32, COMPRESSION_NONE)
        };
        Ok(PqfHeader {
            version,
            kem_variant,
            kem_ciphertext,
            nonce,
            original_size,
            chunk_size,
            compression_algo,
        })
    }
}

// ── Multi-recipient header (v4) ───────────────────────────────────────────

/// One recipient slot in a v4 multi-recipient header.
pub(crate) struct RecipientEntryV4 {
    /// KEM variant for this recipient's key.
    pub kem_variant: u16,
    /// KEM ciphertext encapsulating the per-file session key for this recipient.
    pub kem_ciphertext: Vec<u8>,
    /// AES-256-GCM encrypted session key (32-byte key + 16-byte tag = 48 bytes).
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// Parsed header for v4 (multi-recipient) format.
pub(crate) struct PqfHeaderV4 {
    /// Ordered list of recipient slots.
    pub recipients: Vec<RecipientEntryV4>,
    /// Base nonce for the STREAM payload.
    pub nonce: [u8; NONCE_LEN],
    /// Uncompressed plaintext size in bytes.
    pub original_size: u64,
}

fn write_multi_header_prefix<W: Write + ?Sized>(
    w: &mut W,
    version: u8,
    count: usize,
) -> Result<(), std::io::Error> {
    w.write_all(MAGIC)?;
    w.write_all(&[version])?;
    w.write_all(&(count as u16).to_le_bytes())
}

fn write_nonce_and_size<W: Write + ?Sized>(
    w: &mut W,
    nonce: &[u8; NONCE_LEN],
    size: u64,
) -> Result<(), std::io::Error> {
    w.write_all(nonce)?;
    w.write_all(&size.to_le_bytes())
}

impl PqfHeaderV4 {
    /// Serializes the v4 header to `w`.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_multi_header_prefix(w, VERSION_V4, self.recipients.len())?;
        for r in &self.recipients {
            w.write_all(&r.kem_variant.to_le_bytes())?;
            w.write_all(&r.kem_ciphertext)?;
            w.write_all(&r.wrapped_key)?;
        }
        write_nonce_and_size(w, &self.nonce, self.original_size)
    }

    /// Reads the v4 header body (everything after MAGIC + VERSION byte).
    pub fn read_body<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let mut count_bytes = [0u8; 2];
        r.read_exact(&mut count_bytes)?;
        let count = u16::from_le_bytes(count_bytes) as usize;
        const MAX_RECIPIENTS: usize = 1000;
        if count > MAX_RECIPIENTS {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("recipient count {count} exceeds maximum ({MAX_RECIPIENTS})"),
            )));
        }

        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            let mut variant_bytes = [0u8; 2];
            r.read_exact(&mut variant_bytes)?;
            let kem_variant = u16::from_le_bytes(variant_bytes);

            let ct_len = ct_len_for_variant(kem_variant)?;
            let mut kem_ciphertext = vec![0u8; ct_len];
            r.read_exact(&mut kem_ciphertext)?;

            let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
            r.read_exact(&mut wrapped_key)?;

            recipients.push(RecipientEntryV4 {
                kem_variant,
                kem_ciphertext,
                wrapped_key,
            });
        }

        let (nonce, original_size) = read_nonce_and_size(r)?;
        Ok(PqfHeaderV4 {
            recipients,
            nonce,
            original_size,
        })
    }
}

// ── Anonymous multi-recipient header (v7) ────────────────────────────────

/// One recipient entry in a v7 header. The KEM ciphertext is zero-padded to PADDED_CT_LEN.
pub(crate) struct RecipientEntryV7 {
    /// KEM variant for this recipient's key.
    pub kem_variant: u16,
    /// Actual KEM ciphertext (only the first `ct_len_for_variant(kem_variant)` bytes are real).
    pub kem_ciphertext: Vec<u8>,
    /// AES-256-GCM encrypted session key.
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// Parsed header for v7 (anonymous multi-recipient) format.
pub(crate) struct PqfHeaderV7 {
    /// Shuffled recipient slots, each with a fixed 1618-byte layout.
    pub recipients: Vec<RecipientEntryV7>,
    /// Base nonce for the STREAM payload.
    pub nonce: [u8; NONCE_LEN],
    /// Uncompressed plaintext size in bytes.
    pub original_size: u64,
}

impl PqfHeaderV7 {
    /// Serializes the v7 header to `w`, zero-padding each KEM ciphertext to PADDED_CT_LEN.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_multi_header_prefix(w, VERSION_V7, self.recipients.len())?;
        let pad = [0u8; PADDED_CT_LEN];
        for r in &self.recipients {
            w.write_all(&r.kem_variant.to_le_bytes())?;
            w.write_all(&r.kem_ciphertext)?;
            let written = r.kem_ciphertext.len();
            if written < PADDED_CT_LEN {
                w.write_all(&pad[..PADDED_CT_LEN - written])?;
            }
            w.write_all(&r.wrapped_key)?;
        }
        write_nonce_and_size(w, &self.nonce, self.original_size)
    }

    /// Reads the v7 header body (everything after MAGIC + VERSION byte).
    pub fn read_body<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let mut count_bytes = [0u8; 2];
        r.read_exact(&mut count_bytes)?;
        let count = u16::from_le_bytes(count_bytes) as usize;
        const MAX_RECIPIENTS: usize = 1000;
        if count > MAX_RECIPIENTS {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("recipient count {count} exceeds maximum ({MAX_RECIPIENTS})"),
            )));
        }

        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            let mut variant_bytes = [0u8; 2];
            r.read_exact(&mut variant_bytes)?;
            let kem_variant = u16::from_le_bytes(variant_bytes);

            // Always read the full PADDED_CT_LEN slot; real CT is first ct_len bytes.
            let mut padded = vec![0u8; PADDED_CT_LEN];
            r.read_exact(&mut padded)?;
            let ct_len = ct_len_for_variant(kem_variant)?;
            padded.truncate(ct_len);

            let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
            r.read_exact(&mut wrapped_key)?;

            recipients.push(RecipientEntryV7 {
                kem_variant,
                kem_ciphertext: padded,
                wrapped_key,
            });
        }

        let (nonce, original_size) = read_nonce_and_size(r)?;
        Ok(PqfHeaderV7 {
            recipients,
            nonce,
            original_size,
        })
    }
}

// ── Variant-blind anonymous multi-recipient header (v8) ──────────────────

/// One recipient entry in a v8 header.
///
/// The full `PADDED_CT_LEN` bytes are stored. The decryptor takes the first
/// `ct_len_for_variant(dk.kem_variant())` bytes as the actual KEM ciphertext;
/// the remainder is padding. No variant field is present on the wire.
pub(crate) struct RecipientEntryV8 {
    /// Raw bytes read from the wire (always `PADDED_CT_LEN` = 1568 bytes).
    pub padded_ct: [u8; PADDED_CT_LEN],
    /// AES-256-GCM encrypted session key (32-byte key + 16-byte tag = 48 bytes).
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

/// Parsed header for v8 (variant-blind anonymous multi-recipient) format.
pub(crate) struct PqfHeaderV8 {
    /// Shuffled recipient slots.
    pub recipients: Vec<RecipientEntryV8>,
    /// Base nonce for the STREAM payload.
    pub nonce: [u8; NONCE_LEN],
    /// Uncompressed plaintext size in bytes.
    pub original_size: u64,
}

impl PqfHeaderV8 {
    /// Serializes the v8 header to `w`.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
        write_multi_header_prefix(w, VERSION_V8, self.recipients.len())?;
        for r in &self.recipients {
            w.write_all(&r.padded_ct)?;
            w.write_all(&r.wrapped_key)?;
        }
        write_nonce_and_size(w, &self.nonce, self.original_size)
    }

    /// Reads the v8 header body (everything after MAGIC + VERSION byte).
    pub fn read_body<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let mut count_bytes = [0u8; 2];
        r.read_exact(&mut count_bytes)?;
        let count = u16::from_le_bytes(count_bytes) as usize;
        const MAX_RECIPIENTS: usize = 1000;
        if count > MAX_RECIPIENTS {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("recipient count {count} exceeds maximum ({MAX_RECIPIENTS})"),
            )));
        }

        let mut recipients = Vec::with_capacity(count);
        for _ in 0..count {
            let mut padded_ct = [0u8; PADDED_CT_LEN];
            r.read_exact(&mut padded_ct)?;
            let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
            r.read_exact(&mut wrapped_key)?;
            recipients.push(RecipientEntryV8 {
                padded_ct,
                wrapped_key,
            });
        }

        let (nonce, original_size) = read_nonce_and_size(r)?;
        Ok(PqfHeaderV8 {
            recipients,
            nonce,
            original_size,
        })
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────

/// Maximum chunk size accepted when reading a v5/v6 header (256 MiB).
/// Matches the upper bound enforced by the CLI `--chunk-size` flag.
pub const MAX_CHUNK_SIZE: u32 = 256 * 1024 * 1024;

fn validate_chunk_size(val: u32) -> Result<(), PqfileError> {
    if val == 0 || val > MAX_CHUNK_SIZE {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("chunk_size {val} is out of valid range (1..={MAX_CHUNK_SIZE})"),
        )));
    }
    Ok(())
}

/// Returns the KEM ciphertext length for a given kem_variant, or UnsupportedKem.
pub(crate) fn ct_len_for_variant(kem_variant: u16) -> Result<usize, PqfileError> {
    match kem_variant {
        KEM_VARIANT_512 => Ok(KEM_CT_LEN_512),
        KEM_VARIANT_768 => Ok(KEM_CT_LEN_768),
        KEM_VARIANT_1024 => Ok(KEM_CT_LEN_1024),
        KEM_VARIANT_HYBRID_768 => Ok(HYBRID_CT_LEN_768),
        v => Err(PqfileError::UnsupportedKem(v)),
    }
}

fn read_nonce_and_size<R: Read + ?Sized>(r: &mut R) -> Result<([u8; NONCE_LEN], u64), PqfileError> {
    let mut nonce = [0u8; NONCE_LEN];
    r.read_exact(&mut nonce)?;
    let mut size_bytes = [0u8; 8];
    r.read_exact(&mut size_bytes)?;
    Ok((nonce, u64::from_le_bytes(size_bytes)))
}

/// Derives the per-chunk nonce for v3/v4 streaming: `base_nonce[0..8] || counter.to_be_bytes()`.
pub(crate) fn chunk_nonce(base_nonce: &[u8; BASE_NONCE_LEN], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BASE_NONCE_LEN].copy_from_slice(base_nonce);
    nonce[BASE_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Builds the AAD for a v3/v4 stream chunk: `"pqfile" || counter.to_be_bytes() || is_last`.
///
/// The counter binds the chunk to its position (prevents reordering); `is_last` flags
/// end-of-stream so truncated ciphertexts fail authentication.
pub(crate) fn chunk_aad(counter: u32, is_last: bool) -> [u8; 11] {
    let mut aad = [0u8; 11];
    aad[..6].copy_from_slice(STREAM_AAD_PREFIX);
    aad[6..10].copy_from_slice(&counter.to_be_bytes());
    aad[10] = is_last as u8;
    aad
}

/// Fills `buf` from `reader`, returning the number of bytes read.
/// Reads until the buffer is full or EOF is reached.
pub(crate) fn fill_chunk<R: Read + ?Sized>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<usize, PqfileError> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

/// Derives the 32-byte hybrid session key via HKDF-SHA256(IKM = x25519_ss || ml_ss).
/// HKDF expand with a 32-byte output cannot fail, so the error arm is unreachable.
pub(crate) fn hybrid_hkdf(
    x25519_ss: &[u8; 32],
    ml_ss: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(ml_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"pqfile-hybrid-v1", okm.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    Ok(okm)
}
