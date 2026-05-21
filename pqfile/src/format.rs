use std::io::{Read, Write};

use crate::error::PqfileError;

pub const MAGIC: &[u8; 4] = b"PQFL";
pub const VERSION: u8 = 0x02;
pub const VERSION_V3: u8 = 0x03;
/// Multi-recipient format: MAGIC | 0x04 | COUNT(2) | [VARIANT(2) | CT(var) | WRAPPED_KEY(48)]... | NONCE(12) | ORIGINAL_SIZE(8)
pub const VERSION_V4: u8 = 0x04;

pub const KEM_VARIANT: u16 = 768;
pub const KEM_VARIANT_1024: u16 = 1024;
/// Hybrid X25519+ML-KEM-768 variant identifier (0x0301).
pub const KEM_VARIANT_HYBRID_768: u16 = 0x0301;

/// ML-KEM-768 sizes.
pub const KEM_CT_LEN: usize = 1088;
pub const EK_LEN: usize = 1184;

/// ML-KEM-1024 sizes.
pub const KEM_CT_LEN_1024: usize = 1568;
pub const EK_LEN_1024: usize = 1568;

/// Hybrid X25519+ML-KEM-768 sizes.
/// KEM CT = X25519 ephemeral public key (32) + ML-KEM-768 ciphertext (1088).
pub const X25519_PUBKEY_LEN: usize = 32;
/// X25519 static public key length (same as ephemeral).
pub const X25519_SCALAR_LEN: usize = 32;
pub const HYBRID_CT_LEN_768: usize = X25519_PUBKEY_LEN + KEM_CT_LEN;
/// Combined hybrid public key stored in PEM: X25519 pubkey (32) + ML-KEM-768 EK (1184).
pub const HYBRID_EK_LEN_768: usize = X25519_PUBKEY_LEN + EK_LEN;
/// Combined hybrid private key stored in PEM: X25519 scalar (32) + ML-KEM-768 seed (64).
pub const HYBRID_SEED_LEN_768: usize = X25519_SCALAR_LEN + 64;

/// AES-256-GCM wrapped session key size: 32-byte key + 16-byte tag.
pub const WRAPPED_KEY_LEN: usize = 48;

pub const NONCE_LEN: usize = 12;

/// Fixed prefix: MAGIC(4) + VERSION(1) + KEM_VARIANT(2) = 7 bytes.
const HEADER_PREFIX_LEN: usize = 7;
/// Fixed suffix: NONCE(12) + ORIGINAL_SIZE(8) = 20 bytes.
const HEADER_SUFFIX_LEN: usize = 20;

/// Header length for a ML-KEM-768 file (kept as a constant for tests).
pub const HEADER_LEN: usize = HEADER_PREFIX_LEN + KEM_CT_LEN + HEADER_SUFFIX_LEN;
/// Header length for a ML-KEM-1024 file.
#[allow(dead_code)]
pub const HEADER_LEN_1024: usize = HEADER_PREFIX_LEN + KEM_CT_LEN_1024 + HEADER_SUFFIX_LEN;
/// Header length for a Hybrid X25519+ML-KEM-768 file.
#[allow(dead_code)]
pub const HEADER_LEN_HYBRID_768: usize = HEADER_PREFIX_LEN + HYBRID_CT_LEN_768 + HEADER_SUFFIX_LEN;

/// Chunk size for v3/v4 streaming encryption (64 KiB).
pub const CHUNK_SIZE: usize = 65536;

/// Length of the base nonce used in v3/v4 streaming (8 bytes; last 4 are the counter).
pub const BASE_NONCE_LEN: usize = 8;

/// AAD prefix for v3/v4 stream chunks.
pub(crate) const STREAM_AAD_PREFIX: &[u8] = b"pqfile";

// ── Single-recipient header (v2 / v3) ────────────────────────────────────

pub struct PqfHeader {
    pub version: u8,
    pub kem_variant: u16,
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub original_size: u64,
}

impl PqfHeader {
    /// Total byte length of this header when serialized.
    pub fn header_len(&self) -> usize {
        HEADER_PREFIX_LEN + self.kem_ciphertext.len() + HEADER_SUFFIX_LEN
    }

    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(MAGIC)?;
        w.write_all(&[self.version])?;
        w.write_all(&self.kem_variant.to_le_bytes())?;
        w.write_all(&self.kem_ciphertext)?;
        w.write_all(&self.nonce)?;
        w.write_all(&self.original_size.to_le_bytes())?;
        Ok(())
    }

    pub fn read<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let version = Self::read_magic_version(r)?;
        if version != VERSION && version != VERSION_V3 {
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
        Ok(PqfHeader { version, kem_variant, kem_ciphertext, nonce, original_size })
    }
}

// ── Multi-recipient header (v4) ───────────────────────────────────────────

pub struct RecipientEntryV4 {
    pub kem_variant: u16,
    pub kem_ciphertext: Vec<u8>,
    /// AES-256-GCM encrypted session key (32-byte key + 16-byte tag = 48 bytes).
    pub wrapped_key: [u8; WRAPPED_KEY_LEN],
}

pub struct PqfHeaderV4 {
    pub recipients: Vec<RecipientEntryV4>,
    pub nonce: [u8; NONCE_LEN],
    pub original_size: u64,
}

impl PqfHeaderV4 {
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<(), std::io::Error> {
        w.write_all(MAGIC)?;
        w.write_all(&[VERSION_V4])?;
        w.write_all(&(self.recipients.len() as u16).to_le_bytes())?;
        for r in &self.recipients {
            w.write_all(&r.kem_variant.to_le_bytes())?;
            w.write_all(&r.kem_ciphertext)?;
            w.write_all(&r.wrapped_key)?;
        }
        w.write_all(&self.nonce)?;
        w.write_all(&self.original_size.to_le_bytes())?;
        Ok(())
    }

    /// Reads the v4 header body (everything after MAGIC + VERSION byte).
    pub fn read_body<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let mut count_bytes = [0u8; 2];
        r.read_exact(&mut count_bytes)?;
        let count = u16::from_le_bytes(count_bytes) as usize;

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

            recipients.push(RecipientEntryV4 { kem_variant, kem_ciphertext, wrapped_key });
        }

        let (nonce, original_size) = read_nonce_and_size(r)?;
        Ok(PqfHeaderV4 { recipients, nonce, original_size })
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────

/// Returns the KEM ciphertext length for a given kem_variant, or UnsupportedKem.
pub fn ct_len_for_variant(kem_variant: u16) -> Result<usize, PqfileError> {
    match kem_variant {
        KEM_VARIANT => Ok(KEM_CT_LEN),
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
