use std::io::{Read, Write};

use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

use crate::error::PqfileError;
use crate::secret::LockedSecret;

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
/// Padded anonymous multi-recipient: identical wire format to v8 but the slot count
/// is rounded up to the next power of two by inserting random dummy slots.
/// An observer learns only that there are 1, 2, 4, 8, … slots but cannot determine
/// how many are real. Dummy slots fail KEM decapsulation or AES-GCM tag verification
/// and are silently skipped by the decryptor.
/// Format: MAGIC | 0x09 | COUNT(2) | [PADDED_CT(1568) | WRAPPED_KEY(48)]... | NONCE(12) | ORIGINAL_SIZE(8)
pub const VERSION_V9: u8 = 0x09;
/// Passphrase-only format: no key pair required. The session key is derived directly
/// from a passphrase via Argon2id; the KDF parameters are stored in the header.
/// Format: MAGIC | 0x0A | SALT(16) | ARGON2_PARAMS(12: m_kib/t/p as u32 LE each) | NONCE(12) | ORIGINAL_SIZE(8)
/// Payload is chunked identically to v3 (standard AEAD AAD and key commitment).
pub const VERSION_V10: u8 = 0x0A;
/// Time-locked format (`tlock` feature): no key pair required. A random 16-byte seed
/// is time-lock-encrypted (IBE) against a drand beacon round, so the session key
/// (HKDF-derived from the seed) cannot be reconstructed until that round's threshold
/// BLS signature is public. Always written with [`VERSION_AUTH_BIT`] set (there is no
/// legacy layout to stay compatible with).
/// Format: MAGIC | 0x8B | CHAIN_HASH(32) | ROUND(8, BE) | TLOCK_CT_LEN(4, LE) | TLOCK_CT(variable) | NONCE(12) | ORIGINAL_SIZE(8)
/// Payload is chunked identically to v3 (standard AEAD AAD and key commitment).
/// See `pqfile::tlock` and `docs/FORMAT.md`.
pub const VERSION_TLOCK: u8 = 0x0B;

/// Authenticated-header flag bit on the version byte.
///
/// When set (e.g. `0x83` = v3 layout + this bit), the chunk-0 key commitment is
/// computed with `compute_key_commitment`'s v3 definition, which additionally
/// binds the mutable header fields that are *not* self-healing under tampering:
/// `chunk_size`, `compression_algo`, and (for v10) the Argon2id salt/parameters
/// and flags byte. Flipping any of those fields on an authenticated file makes
/// chunk-0's AEAD tag fail. Stripping or adding this bit also fails, because the
/// two commitment definitions use different domain-separation contexts.
///
/// The version byte and `kem_variant` are deliberately *excluded* from the
/// commitment preimage: both change during zero-copy `rekey` (v3 → v4) while the
/// payload is preserved, and tampering with either is already self-healing
/// (structural misparse or a wrong shared secret, ending in a tag failure).
///
/// pqfile ≤ 4.2.4 rejects these version bytes with `UnsupportedVersion`, which
/// is the intended upgrade signal; all files written by older versions (bit
/// clear) remain readable.
pub const VERSION_AUTH_BIT: u8 = 0x80;

/// Strips [`VERSION_AUTH_BIT`], returning the underlying layout version byte.
#[must_use]
pub fn version_layout(version: u8) -> u8 {
    version & !VERSION_AUTH_BIT
}

/// Returns true if the version byte carries [`VERSION_AUTH_BIT`].
#[must_use]
pub fn is_header_authenticated(version: u8) -> bool {
    version & VERSION_AUTH_BIT != 0
}

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

/// Maximum number of recipients accepted in a v4/v7/v8 header.
/// Files claiming more recipients are rejected before any unbounded allocation can occur.
pub(crate) const MAX_RECIPIENTS: usize = 256;

/// Maximum value accepted for the `original_size` header field (1 TiB).
/// Values above this indicate a malformed or malicious header.
pub(crate) const MAX_ORIGINAL_SIZE: u64 = 1u64 << 40;

/// Full ChaCha20-Poly1305 nonce length (12 bytes = 8-byte base + 4-byte counter).
pub const NONCE_LEN: usize = 12;

/// Fixed prefix: MAGIC(4) + VERSION(1) + KEM_VARIANT_768(2) = 7 bytes.
const HEADER_PREFIX_LEN: usize = 7;
/// Fixed suffix: NONCE(12) + ORIGINAL_SIZE(8) = 20 bytes.
const HEADER_SUFFIX_LEN: usize = 20;

// These constants are used in the library tests (cfg(test) blocks in encrypt.rs
// and decrypt.rs). The dead_code lint fires because tests are compiled as a
// separate crate target and the compiler does not see the cross-crate use.
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
    /// Layout version byte with [`VERSION_AUTH_BIT`] stripped.
    pub fn layout(&self) -> u8 {
        version_layout(self.version)
    }

    /// Total byte length of this header when serialized.
    pub fn header_len(&self) -> usize {
        let base = HEADER_PREFIX_LEN + self.kem_ciphertext.len() + HEADER_SUFFIX_LEN;
        match self.layout() {
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
        let layout = self.layout();
        if layout == VERSION_V5 || layout == VERSION_V6 {
            w.write_all(&self.chunk_size.to_le_bytes())?;
        }
        if layout == VERSION_V6 {
            w.write_all(&[self.compression_algo])?;
        }
        Ok(())
    }

    /// Deserializes a v2/v3/v5/v6 header from `r`. Returns `UnsupportedVersion` for v4/v7.
    pub fn read<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let version = Self::read_magic_version(r)?;
        let layout = version_layout(version);
        // v2 predates chunked commitments: the whole header is the AEAD AAD, so an
        // authenticated-header variant of it does not exist and is rejected.
        if version == VERSION_AUTH_BIT | VERSION {
            return Err(PqfileError::UnsupportedVersion(version));
        }
        if layout != VERSION && layout != VERSION_V3 && layout != VERSION_V5 && layout != VERSION_V6
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

    /// Reads the header body (everything after MAGIC + VERSION). `version` is the
    /// full on-the-wire version byte (it may carry [`VERSION_AUTH_BIT`]) and is
    /// stored verbatim; layout decisions use the masked value.
    pub fn read_body<R: Read + ?Sized>(r: &mut R, version: u8) -> Result<Self, PqfileError> {
        let layout = version_layout(version);
        let mut kem_variant_bytes = [0u8; 2];
        r.read_exact(&mut kem_variant_bytes)?;
        let kem_variant = u16::from_le_bytes(kem_variant_bytes);

        let ct_len = ct_len_for_variant(kem_variant)?;

        let mut kem_ciphertext = vec![0u8; ct_len];
        r.read_exact(&mut kem_ciphertext)?;

        let (nonce, original_size) = read_nonce_and_size(r)?;
        let (chunk_size, compression_algo) = if layout == VERSION_V5 {
            let mut cs = [0u8; 4];
            r.read_exact(&mut cs)?;
            let val = u32::from_le_bytes(cs);
            validate_chunk_size(val)?;
            (val, COMPRESSION_NONE)
        } else if layout == VERSION_V6 {
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
    if count > MAX_RECIPIENTS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("recipient count {count} exceeds maximum ({MAX_RECIPIENTS})"),
        ));
    }
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
    /// Serializes the v4 header to `w`. `version` is the full version byte to emit
    /// (`VERSION_V4`, optionally with [`VERSION_AUTH_BIT`]); callers that rewrite an
    /// existing file (`add_recipient`, `rekey`) must preserve the input file's bit so
    /// the payload's chunk-0 commitment stays valid.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W, version: u8) -> Result<(), std::io::Error> {
        write_multi_header_prefix(w, version, self.recipients.len())?;
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
    /// `version` is the full version byte to emit (see [`PqfHeaderV4::write`]).
    pub fn write<W: Write + ?Sized>(&self, w: &mut W, version: u8) -> Result<(), std::io::Error> {
        write_multi_header_prefix(w, version, self.recipients.len())?;
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
    /// Serializes the header with the given version byte (`VERSION_V8` or `VERSION_V9`,
    /// optionally with [`VERSION_AUTH_BIT`]; see [`PqfHeaderV4::write`]).
    pub(crate) fn write_with_version<W: Write + ?Sized>(
        &self,
        w: &mut W,
        version: u8,
    ) -> Result<(), std::io::Error> {
        write_multi_header_prefix(w, version, self.recipients.len())?;
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

// ── Passphrase-only header (v10) ─────────────────────────────────────────

/// v10 header flag bit: key derivation additionally requires a keyfile
/// (its hash is mixed into Argon2id as the secret/pepper input).
pub(crate) const V10_FLAG_KEYFILE: u8 = 0b0000_0001;

/// v10 header flag bit: key derivation additionally requires a FIDO2 hardware
/// token's `hmac-secret` extension output (domain-separated hash mixed into
/// Argon2id as the secret/pepper input, the same slot [`V10_FLAG_KEYFILE`]
/// occupies). Mutually exclusive with [`V10_FLAG_KEYFILE`] and
/// [`V10_FLAG_WEBAUTHN_PRF`]: pqfile never writes more than one of the three
/// bits together, and a header carrying more than one is rejected below.
pub(crate) const V10_FLAG_FIDO2: u8 = 0b0000_0010;

/// v10 header flag bit: key derivation additionally requires a browser
/// WebAuthn credential's `prf` extension output (domain-separated hash mixed
/// into Argon2id as the secret/pepper input, the same slot [`V10_FLAG_KEYFILE`]
/// and [`V10_FLAG_FIDO2`] occupy). Mutually exclusive with both: this is the
/// browser-native equivalent of [`V10_FLAG_FIDO2`]'s hardware-USB mechanism,
/// reachable from wasm32 (where CTAP2/HID is not).
pub(crate) const V10_FLAG_WEBAUTHN_PRF: u8 = 0b0000_0100;

/// All v10 flag bits this build understands. Headers carrying unknown bits are
/// rejected with [`PqfileError::UnsupportedHeaderFlags`] rather than silently
/// decrypted under different assumptions than the sender's.
pub(crate) const V10_KNOWN_FLAGS: u8 = V10_FLAG_KEYFILE | V10_FLAG_FIDO2 | V10_FLAG_WEBAUTHN_PRF;

/// Parsed header for v10 (passphrase-only) format.
pub(crate) struct PqfHeaderV10 {
    /// Random 16-byte Argon2id salt.
    pub salt: [u8; 16],
    /// Argon2id memory cost in KiB (stored in header by the sender).
    pub m_kib: u32,
    /// Argon2id time cost (iterations).
    pub t_cost: u32,
    /// Argon2id parallelism (lanes).
    pub p_cost: u32,
    /// Feature flag bits ([`V10_FLAG_KEYFILE`], [`V10_FLAG_FIDO2`],
    /// [`V10_FLAG_WEBAUTHN_PRF`]; remaining bits reserved; at most one of the
    /// three may be set).
    pub flags: u8,
    /// Per-file base nonce (12 bytes; only first 8 are random, last 4 are the chunk counter).
    pub nonce: [u8; NONCE_LEN],
    /// Uncompressed plaintext size in bytes.
    pub original_size: u64,
}

impl PqfHeaderV10 {
    /// Serializes the v10 header to `w`. `version` is the full version byte to emit
    /// (`VERSION_V10`, optionally with [`VERSION_AUTH_BIT`]).
    pub fn write<W: Write + ?Sized>(&self, w: &mut W, version: u8) -> Result<(), std::io::Error> {
        w.write_all(MAGIC)?;
        w.write_all(&[version])?;
        w.write_all(&self.salt)?;
        w.write_all(&self.m_kib.to_le_bytes())?;
        w.write_all(&self.t_cost.to_le_bytes())?;
        w.write_all(&self.p_cost.to_le_bytes())?;
        w.write_all(&[self.flags])?;
        write_nonce_and_size(w, &self.nonce, self.original_size)
    }

    /// Reads the v10 header body (everything after MAGIC + VERSION byte).
    pub fn read_body<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let mut salt = [0u8; 16];
        r.read_exact(&mut salt)?;
        let mut m = [0u8; 4];
        r.read_exact(&mut m)?;
        let mut t = [0u8; 4];
        r.read_exact(&mut t)?;
        let mut p = [0u8; 4];
        r.read_exact(&mut p)?;
        let mut flags = [0u8; 1];
        r.read_exact(&mut flags)?;
        let known_and_exclusive =
            (flags[0] & !V10_KNOWN_FLAGS) == 0 && (flags[0] & V10_KNOWN_FLAGS).count_ones() <= 1;
        if !known_and_exclusive {
            return Err(PqfileError::UnsupportedHeaderFlags(flags[0]));
        }
        let (nonce, original_size) = read_nonce_and_size(r)?;
        Ok(PqfHeaderV10 {
            salt,
            m_kib: u32::from_le_bytes(m),
            t_cost: u32::from_le_bytes(t),
            p_cost: u32::from_le_bytes(p),
            flags: flags[0],
            nonce,
            original_size,
        })
    }
}

/// Chain hash length in the tlock header: identifies which drand chain the round
/// number is relative to. Public information (not sensitive).
pub const TLOCK_CHAIN_HASH_LEN: usize = 32;

/// Parsed header for the time-locked (`tlock` feature) format.
#[cfg(feature = "tlock")]
pub(crate) struct PqfHeaderTlock {
    /// drand chain identifier the `round` is relative to.
    pub chain_hash: [u8; TLOCK_CHAIN_HASH_LEN],
    /// Target beacon round: the file cannot be decrypted before this round's
    /// threshold BLS signature is published.
    pub round: u64,
    /// tlock IBE ciphertext wrapping a random 16-byte seed. Length depends on the
    /// chain's public key group (see `pqfile::tlock`); stored length-prefixed since
    /// it varies by chain.
    pub tlock_ct: Vec<u8>,
    /// Per-file base nonce (12 bytes; only first 8 are random, last 4 are the chunk counter).
    pub nonce: [u8; NONCE_LEN],
    /// Uncompressed plaintext size in bytes.
    pub original_size: u64,
}

#[cfg(feature = "tlock")]
impl PqfHeaderTlock {
    /// Serializes the tlock header to `w`. `version` is the full version byte to emit
    /// (always [`VERSION_TLOCK`] `| `[`VERSION_AUTH_BIT`]).
    pub fn write<W: Write + ?Sized>(&self, w: &mut W, version: u8) -> Result<(), std::io::Error> {
        w.write_all(MAGIC)?;
        w.write_all(&[version])?;
        w.write_all(&self.chain_hash)?;
        w.write_all(&self.round.to_be_bytes())?;
        w.write_all(&(self.tlock_ct.len() as u32).to_le_bytes())?;
        w.write_all(&self.tlock_ct)?;
        write_nonce_and_size(w, &self.nonce, self.original_size)
    }

    /// Reads the tlock header body (everything after MAGIC + VERSION byte).
    pub fn read_body<R: Read + ?Sized>(r: &mut R) -> Result<Self, PqfileError> {
        let mut chain_hash = [0u8; TLOCK_CHAIN_HASH_LEN];
        r.read_exact(&mut chain_hash)?;
        let mut round_bytes = [0u8; 8];
        r.read_exact(&mut round_bytes)?;
        let mut ct_len_bytes = [0u8; 4];
        r.read_exact(&mut ct_len_bytes)?;
        let ct_len = u32::from_le_bytes(ct_len_bytes) as usize;
        // A tlock IBE ciphertext is at most a G2 point (96) + v(16) + w(16); reject
        // anything wildly larger as a malformed/adversarial header rather than
        // allocating an attacker-controlled amount of memory.
        if ct_len > 512 {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tlock ciphertext length {ct_len} exceeds maximum (512)"),
            )));
        }
        let mut tlock_ct = vec![0u8; ct_len];
        r.read_exact(&mut tlock_ct)?;
        let (nonce, original_size) = read_nonce_and_size(r)?;
        Ok(PqfHeaderTlock {
            chain_hash,
            round: u64::from_be_bytes(round_bytes),
            tlock_ct,
            nonce,
            original_size,
        })
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────

/// Maximum chunk size accepted when reading a v5/v6 header (256 MiB).
/// Matches the upper bound enforced by the CLI `--chunk-size` flag.
pub const MAX_CHUNK_SIZE: u32 = 256 * 1024 * 1024;

/// Picks a chunk size appropriate for the given `file_size`.
///
/// | File size    | Chosen chunk | Format | Rationale |
/// |--------------|-------------|--------|-----------|
/// | < 1 MiB      | 16 KiB      | v5     | Reduces per-file AEAD overhead for small files |
/// | 1-256 MiB    | 64 KiB      | v3     | Standard [`CHUNK_SIZE`] default |
/// | > 256 MiB    | 256 KiB     | v5     | Amortises per-chunk cost for large files |
///
/// The small and large tiers return a value that differs from [`CHUNK_SIZE`], so
/// the encoder writes v5 format (with the chunk size stored in the header).
/// The medium tier returns exactly [`CHUNK_SIZE`] and the encoder writes the
/// more compact v3 header.
pub fn adaptive_chunk_size(file_size: u64) -> usize {
    const MB: u64 = 1024 * 1024;
    if file_size < MB {
        16 * 1024
    } else if file_size > 256 * MB {
        256 * 1024
    } else {
        CHUNK_SIZE
    }
}

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
    let size = u64::from_le_bytes(size_bytes);
    if size > MAX_ORIGINAL_SIZE {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("original_size {size} exceeds maximum ({MAX_ORIGINAL_SIZE})"),
        )));
    }
    Ok((nonce, size))
}

/// Derives the per-chunk nonce for v3/v4 streaming: `base_nonce[0..8] || counter.to_be_bytes()`.
pub(crate) fn chunk_nonce(base_nonce: &[u8; BASE_NONCE_LEN], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..BASE_NONCE_LEN].copy_from_slice(base_nonce);
    nonce[BASE_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Domain separator for the session-key commitment hash (version 2, legacy files).
const KEY_COMMITMENT_CTX: &[u8] = b"pqfile-session-key-commitment-v2";

/// Domain separator for the session-key commitment hash (version 3,
/// [`VERSION_AUTH_BIT`] files).
const KEY_COMMITMENT_CTX_V3: &[u8] = b"pqfile-session-key-commitment-v3";

/// Serialized length of the v10 KDF fields bound into the v3 commitment:
/// salt(16) + m_kib(4) + t_cost(4) + p_cost(4) + flags(1).
const V10_KDF_COMMIT_LEN: usize = 29;

/// SHA3-256 of `KEY_COMMITMENT_CTX || session_key || nonce || original_size`.
///
/// Including `nonce` and `original_size` authenticates the stable header fields:
/// any tampering with the nonce or declared plaintext size causes chunk-0's AEAD
/// tag to fail. The KEM ciphertext and recipient-slot fields are excluded because
/// wrong-CT → wrong-ss → wrong-commitment already covers that attack vector, and
/// excluding them keeps zero-copy operations (`add_recipient`, `rekey`) valid:
/// both operations preserve the session key, nonce, and original_size intact.
pub(crate) fn compute_key_commitment(
    session_key: &[u8],
    nonce: &[u8; NONCE_LEN],
    original_size: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(KEY_COMMITMENT_CTX);
    h.update(session_key);
    h.update(nonce.as_ref());
    h.update(original_size.to_le_bytes());
    h.finalize().into()
}

/// v3 commitment: SHA3-256 of `CTX_V3 || session_key || chunk_size || compression_algo
/// || kdf_fields(29) || nonce || original_size`.
///
/// Extends the v2 commitment with the header fields whose tampering is *not*
/// self-healing: `chunk_size` (v5/v6), `compression_algo` (v6 — flipping
/// zstd → none would otherwise deliver compressed bytes as plaintext with all
/// tags passing), and the v10 Argon2id salt/parameters/flags (zeros for every
/// other layout). See [`VERSION_AUTH_BIT`] for what is deliberately excluded.
fn compute_key_commitment_v3(
    session_key: &[u8],
    nonce: &[u8; NONCE_LEN],
    original_size: u64,
    chunk_size: u32,
    compression_algo: u8,
    kdf_fields: &[u8; V10_KDF_COMMIT_LEN],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(KEY_COMMITMENT_CTX_V3);
    h.update(session_key);
    h.update(chunk_size.to_le_bytes());
    h.update([compression_algo]);
    h.update(kdf_fields);
    h.update(nonce.as_ref());
    h.update(original_size.to_le_bytes());
    h.finalize().into()
}

/// Key commitment for chunked streaming layouts (v3/v4/v5/v6/v7/v8/v9).
///
/// Selects the commitment definition by the [`VERSION_AUTH_BIT`] of `version`:
/// legacy files use the v2 commitment, authenticated-header files bind
/// `chunk_size` and `compression_algo` as well. Multi-recipient layouts always
/// pass `CHUNK_SIZE` / [`COMPRESSION_NONE`] (their only supported values).
pub(crate) fn commitment_for_stream(
    session_key: &[u8],
    version: u8,
    nonce: &[u8; NONCE_LEN],
    original_size: u64,
    chunk_size: u32,
    compression_algo: u8,
) -> [u8; 32] {
    if is_header_authenticated(version) {
        compute_key_commitment_v3(
            session_key,
            nonce,
            original_size,
            chunk_size,
            compression_algo,
            &[0u8; V10_KDF_COMMIT_LEN],
        )
    } else {
        compute_key_commitment(session_key, nonce, original_size)
    }
}

/// Key commitment for the v10 passphrase-only layout.
///
/// Authenticated-header files additionally bind the Argon2id salt, parameters,
/// and flags byte, so a tampered KDF field (or a flipped keyfile flag) fails
/// chunk-0 authentication even before the wrong derived key would.
pub(crate) fn commitment_for_v10(
    session_key: &[u8],
    version: u8,
    header: &PqfHeaderV10,
) -> [u8; 32] {
    if is_header_authenticated(version) {
        let mut kdf = [0u8; V10_KDF_COMMIT_LEN];
        kdf[..16].copy_from_slice(&header.salt);
        kdf[16..20].copy_from_slice(&header.m_kib.to_le_bytes());
        kdf[20..24].copy_from_slice(&header.t_cost.to_le_bytes());
        kdf[24..28].copy_from_slice(&header.p_cost.to_le_bytes());
        kdf[28] = header.flags;
        compute_key_commitment_v3(
            session_key,
            &header.nonce,
            header.original_size,
            CHUNK_SIZE as u32,
            COMPRESSION_NONE,
            &kdf,
        )
    } else {
        compute_key_commitment(session_key, &header.nonce, header.original_size)
    }
}

/// Domain separator for the tlock session-key commitment.
#[cfg(feature = "tlock")]
const KEY_COMMITMENT_CTX_TLOCK: &[u8] = b"pqfile-tlock-key-commitment-v1";

/// Key commitment for the tlock layout: SHA3-256 of
/// `CTX_TLOCK || session_key || chain_hash || round || nonce || original_size`.
///
/// Binds `chain_hash` and `round` into chunk-0's AEAD tag so tampering with either
/// (e.g. pointing the header at an already-fired round) is caught even before the
/// wrong beacon signature would fail to reproduce the session key. Always computed
/// this way: unlike v10, there is no legacy tlock layout predating
/// [`VERSION_AUTH_BIT`] to stay compatible with.
#[cfg(feature = "tlock")]
pub(crate) fn commitment_for_tlock(session_key: &[u8], header: &PqfHeaderTlock) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(KEY_COMMITMENT_CTX_TLOCK);
    h.update(session_key);
    h.update(header.chain_hash);
    h.update(header.round.to_be_bytes());
    h.update(header.nonce.as_ref());
    h.update(header.original_size.to_le_bytes());
    h.finalize().into()
}

/// Maximum AAD byte length across all chunk positions (first chunk is largest).
/// Layout: STREAM_AAD_PREFIX(6) + counter_be(4) + is_last(1) + key_commitment(32).
pub(crate) const MAX_CHUNK_AAD_LEN: usize = STREAM_AAD_PREFIX.len() + 4 + 1 + 32;

/// Builds the chunk-specific AAD into a fixed-size buffer, returning the used length.
///
/// For `counter == 0` the AAD is 43 bytes:
///   `"pqfile" || 0u32_be || is_last || key_commitment(32)`
///
/// The 32-byte `key_commitment` = `compute_key_commitment(session_key)` binds the
/// first chunk's tag to the specific session key, preventing:
///   • KEM ciphertext substitution (different CT → different ss → different commitment)
///   • Multi-key attacks ("invisible salamanders") where a crafted ciphertext
///     authenticates under two distinct ChaCha20 keys
///
/// The `nonce` and `original_size` fields are bound via the `key_commitment` value
/// (see `compute_key_commitment`), so header tampering with those fields is detected
/// by the chunk-0 tag without increasing the AAD length here.
///
/// For `counter > 0` the AAD is the standard 11 bytes:
///   `"pqfile" || counter_be || is_last`
///
/// The caller slices `buf[..len]` when passing the AAD to the AEAD primitive.
pub(crate) fn make_chunk_aad(
    counter: u32,
    is_last: bool,
    key_commitment: &[u8; 32],
) -> ([u8; MAX_CHUNK_AAD_LEN], usize) {
    let mut buf = [0u8; MAX_CHUNK_AAD_LEN];
    buf[..6].copy_from_slice(STREAM_AAD_PREFIX);
    buf[6..10].copy_from_slice(&counter.to_be_bytes());
    buf[10] = is_last as u8;
    if counter == 0 {
        buf[11..43].copy_from_slice(key_commitment);
        (buf, MAX_CHUNK_AAD_LEN)
    } else {
        (buf, 11)
    }
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
) -> Result<LockedSecret<32>, PqfileError> {
    // Both the X25519 DH output and the ML-KEM-768 shared secret are raw key
    // material, so they're combined in mlocked storage rather than a plain
    // `Zeroizing<Vec<u8>>` - the intermediate concatenation is exactly as
    // sensitive as the HKDF output it feeds.
    let mut ikm = LockedSecret::<64>::zeroed();
    ikm[..32].copy_from_slice(x25519_ss);
    ikm[32..].copy_from_slice(ml_ss);
    let hk = Hkdf::<Sha256>::new(None, ikm.as_ref());
    let mut okm = LockedSecret::<32>::zeroed();
    hk.expand(b"pqfile-hybrid-v1", okm.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_chunk_size_small_file() {
        assert_eq!(adaptive_chunk_size(0), 16 * 1024);
        assert_eq!(adaptive_chunk_size(1), 16 * 1024);
        assert_eq!(adaptive_chunk_size(1024 * 1024 - 1), 16 * 1024);
    }

    #[test]
    fn adaptive_chunk_size_medium_file() {
        assert_eq!(adaptive_chunk_size(1024 * 1024), CHUNK_SIZE);
        assert_eq!(adaptive_chunk_size(10 * 1024 * 1024), CHUNK_SIZE);
        assert_eq!(adaptive_chunk_size(256 * 1024 * 1024), CHUNK_SIZE);
    }

    #[test]
    fn adaptive_chunk_size_large_file() {
        assert_eq!(adaptive_chunk_size(256 * 1024 * 1024 + 1), 256 * 1024);
        assert_eq!(adaptive_chunk_size(1024 * 1024 * 1024), 256 * 1024);
    }
}
