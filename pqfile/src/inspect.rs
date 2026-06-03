/// Read the header of any `.pqf` file without decrypting the payload.
///
/// This is the stable API for programmatically inspecting `.pqf` files.
/// It replaces direct use of the internal header-parsing methods.
use std::io::Read;

use crate::error::PqfileError;
use crate::format::{
    PqfHeader, PqfHeaderV4, PqfHeaderV7, PqfHeaderV8, NONCE_LEN, VERSION, VERSION_V3, VERSION_V4,
    VERSION_V5, VERSION_V6, VERSION_V7, VERSION_V8, VERSION_V9,
};

/// KEM variant information for a single recipient slot.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RecipientInfo {
    /// KEM variant identifier for this slot (e.g. 512, 768, 1024, or 0x0301 for hybrid).
    pub kem_variant: u16,
}

/// Parsed header information from a `.pqf` file.
///
/// Returned by [`inspect_stream`]. The enum is `#[non_exhaustive]` - new format
/// versions may add variants in future releases.
///
/// The named fields of the existing variants (`Single`, `Multi`, `AnonMulti`,
/// `AnonMultiV8`) are considered **stable**: new format versions will always
/// introduce new enum variants rather than new fields on existing variants.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum PqfHeaderInfo {
    /// Single-recipient formats: v2 (whole-file AEAD), v3 (chunked stream),
    /// v5 (configurable chunk size), v6 (compress-then-encrypt).
    Single {
        /// Format version byte.
        version: u8,
        /// KEM variant identifier (512, 768, 1024, or 0x0301 for hybrid).
        kem_variant: u16,
        /// Per-file base nonce (12 bytes).
        nonce: [u8; NONCE_LEN],
        /// Uncompressed plaintext size in bytes (informational; not trusted for allocation).
        original_size: u64,
        /// Chunk size for streaming. Equal to `CHUNK_SIZE` (65536) for v2/v3; stored
        /// in the header for v5/v6.
        chunk_size: u32,
        /// Compression algorithm byte. `0x00` = none; `0x01` = zstd. Always `0x00` for
        /// v2, v3, and v5.
        compression_algo: u8,
    },
    /// Multi-recipient format (v4): each recipient slot has its own KEM ciphertext and
    /// AES-GCM-wrapped session key. Entry order matches the order supplied during encryption.
    Multi {
        /// Ordered list of recipient slots.
        recipients: Vec<RecipientInfo>,
        /// Base nonce for the STREAM payload.
        nonce: [u8; NONCE_LEN],
        /// Uncompressed plaintext size in bytes.
        original_size: u64,
    },
    /// Anonymous multi-recipient format (v7): all KEM ciphertexts are padded to a uniform
    /// size and entries are written in a randomised order. KEM variant is still visible
    /// per slot (read-only; pqfile 4.0+ always writes v8 for new anonymous files).
    AnonMulti {
        /// Recipient slots in the (shuffled) order they appear on disk.
        recipients: Vec<RecipientInfo>,
        /// Base nonce for the STREAM payload.
        nonce: [u8; NONCE_LEN],
        /// Uncompressed plaintext size in bytes.
        original_size: u64,
    },
    /// Variant-blind anonymous multi-recipient format (v8/v9): all slots are a uniform
    /// 1616-byte entry with no KEM variant field. Only the slot count is observable.
    /// v9 additionally pads the count to the next power of two with random dummy slots.
    AnonMultiV8 {
        /// Format version byte: `0x08` for standard or `0x09` for padded.
        version: u8,
        /// Number of recipient slots (includes dummy slots in v9).
        slot_count: usize,
        /// Base nonce for the STREAM payload.
        nonce: [u8; NONCE_LEN],
        /// Uncompressed plaintext size in bytes.
        original_size: u64,
    },
}

/// Read and parse the header of a `.pqf` stream without decrypting the payload.
///
/// Consumes only the header bytes from `reader`; the remaining bytes are the
/// encrypted payload and are left unconsumed.
///
/// Returns `Err(InvalidMagic)` if the stream does not start with `PQFL`.
/// Returns `Err(UnsupportedVersion)` for an unrecognised version byte.
/// Returns `Err(UnsupportedKem)` if a recipient entry uses an unrecognised KEM variant.
#[must_use = "inspect result must be used"]
pub fn inspect_stream<R: Read>(reader: &mut R) -> Result<PqfHeaderInfo, PqfileError> {
    let version = PqfHeader::read_magic_version(reader)?;
    match version {
        VERSION | VERSION_V3 | VERSION_V5 | VERSION_V6 => {
            let h = PqfHeader::read_body(reader, version)?;
            Ok(PqfHeaderInfo::Single {
                version: h.version,
                kem_variant: h.kem_variant,
                nonce: h.nonce,
                original_size: h.original_size,
                chunk_size: h.chunk_size,
                compression_algo: h.compression_algo,
            })
        }
        VERSION_V4 => {
            let h = PqfHeaderV4::read_body(reader)?;
            Ok(PqfHeaderInfo::Multi {
                recipients: h
                    .recipients
                    .iter()
                    .map(|r| RecipientInfo {
                        kem_variant: r.kem_variant,
                    })
                    .collect(),
                nonce: h.nonce,
                original_size: h.original_size,
            })
        }
        VERSION_V7 => {
            let h = PqfHeaderV7::read_body(reader)?;
            Ok(PqfHeaderInfo::AnonMulti {
                recipients: h
                    .recipients
                    .iter()
                    .map(|r| RecipientInfo {
                        kem_variant: r.kem_variant,
                    })
                    .collect(),
                nonce: h.nonce,
                original_size: h.original_size,
            })
        }
        // v9 uses the same wire format as v8; only the version byte differs.
        VERSION_V8 | VERSION_V9 => {
            let h = PqfHeaderV8::read_body(reader)?;
            Ok(PqfHeaderInfo::AnonMultiV8 {
                version,
                slot_count: h.recipients.len(),
                nonce: h.nonce,
                original_size: h.original_size,
            })
        }
        v => Err(PqfileError::UnsupportedVersion(v)),
    }
}
