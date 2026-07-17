//! Steganographic key backup: embed a file inside a cover image's pixel data,
//! keyed by a passphrase.
//!
//! [`bury`](crate::stego::bury) hides a payload (typically a
//! passphrase-encrypted private key PEM) inside the least-significant bit of
//! every color channel byte of a cover image, and
//! [`exhume`](crate::stego::exhume) recovers it. Both take a passphrase, and
//! the passphrase gates *detection*, not just recovery: everything embedded
//! after the random salt is encrypted with a keystream derived from the
//! passphrase, so there is no plaintext magic, length, or checksum an image
//! scanner could look for. Without the passphrase, a buried image cannot be
//! distinguished from an ordinary one by inspecting the embedded bytes -
//! running [`exhume`](crate::stego::exhume) with the wrong passphrase returns
//! the same [`StegoPayloadNotFound`] as running it against a plain photo.
//!
//! This is still not a steganalysis-hardened scheme: bits are placed
//! sequentially from the start of the pixel buffer, so a statistical attack
//! on LSB randomness (e.g. a chi-square test against the altered region)
//! could flag the image as *carrying something*, even though it cannot
//! reveal or confirm *what*. Treat it as a plausible-deniability backup
//! (a key hidden among ordinary photos), with all real secrecy resting on
//! the passphrase here plus whatever encryption the payload itself carries.
//!
//! # Key derivation (frozen)
//!
//! `kdf_key = Argon2id(passphrase, salt)` with parameters fixed at the values
//! pqfile's passphrase formats used when this module shipped (m=64 MiB, t=3,
//! p=4). They are deliberately *frozen constants* here rather than shared
//! with the passphrase format's tunable defaults: the image cannot record
//! KDF parameters without embedding recognizable plaintext structure, which
//! would defeat keyed detection, so every version of pqfile must derive the
//! same key from the same passphrase forever. Two subkeys are then split off
//! with BLAKE3's KDF mode: a keystream key (BLAKE3 XOF, XORed over the
//! framed payload) and a MAC key (BLAKE3 keyed hash over the payload,
//! verified on exhume in constant time via `blake3::Hash`'s `PartialEq`).
//!
//! # Why PNG, not JPEG
//!
//! Least-significant-bit embedding only survives a *lossless* re-encode.
//! JPEG's lossy DCT quantization would destroy the embedded bits, so the
//! output of [`bury`](crate::stego::bury) is always a PNG regardless of the cover image's
//! original format (`jpeg` is enabled as an input codec so a JPEG photo can
//! still be used as a cover; the round-trip through decode-then-PNG-encode
//! is what makes that safe). A byte-for-byte "hide data directly in a JPEG"
//! mode exists (steghide does this by embedding in DCT coefficients instead
//! of pixels) but is a materially different, larger undertaking; see
//! `docs/ROADMAP.md`, "Steganographic key backup".
//!
//! # Wire format (inside the pixel data, not a pqfile format)
//!
//! ```text
//! SALT(16) || ENC( MAGIC(4="PQST") || LEN(4, u32 LE) || MAC(32, keyed BLAKE3) || PAYLOAD )
//! ```
//!
//! where `ENC` is an XOR with the BLAKE3-XOF keystream. Each byte of this
//! message is embedded MSB-first into the LSB of consecutive bytes of the
//! cover image's RGB8 pixel buffer (alpha, if any, is dropped on both bury
//! and exhume so capacity math and pixel indexing stay simple). BLAKE3 is
//! used per the standing "BLAKE3 for new non-format hashing" guideline:
//! nothing here ever touches the pqfile wire format's own authentication.
//!
//! [`StegoPayloadNotFound`]: PqfileError::StegoPayloadNotFound

use image::{DynamicImage, ImageFormat, ImageReader, Limits, RgbImage};
use std::io::Cursor;
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::secret::LockedSecret;

const MAGIC: [u8; 4] = *b"PQST";
const SALT_LEN: usize = 16;
const LEN_LEN: usize = 4;
const MAC_LEN: usize = 32;
/// Encrypted frame header: MAGIC || LEN || MAC (the payload follows).
const HEADER_LEN: usize = MAGIC.len() + LEN_LEN + MAC_LEN;
/// Everything that precedes the payload in the embedded message.
const PREFIX_LEN: usize = SALT_LEN + HEADER_LEN;

// Frozen Argon2id parameters (see module docs). These intentionally do NOT
// track `passphrase::ARGON2_*`: if those defaults ever change, stego images
// buried under the old values must still exhume.
const STEGO_ARGON2_M_COST: u32 = 65536; // 64 MiB
const STEGO_ARGON2_T_COST: u32 = 3;
const STEGO_ARGON2_P_COST: u32 = 4;

// BLAKE3 KDF context strings (must never change; see module docs).
const KEYSTREAM_CONTEXT: &str = "pqfile stego v1 2026-07-17 keystream";
const MAC_CONTEXT: &str = "pqfile stego v1 2026-07-17 mac";

/// Decode guardrails: `Limits::default()` already caps any single decoder
/// allocation at 512 MiB, but `to_rgb8` afterwards allocates width*height*3
/// outside the decoder's accounting, so cap dimensions too. 100 MP (300 MB
/// of RGB8, ~12 MB of payload capacity) is far beyond any sane cover photo.
const MAX_DIMENSION: u32 = 16_384;
const MAX_PIXELS: u64 = 100_000_000;

/// Decodes `cover` and returns its width, height, and raw RGB8 pixel bytes
/// (row-major, 3 bytes per pixel, alpha dropped).
fn decode_raw_rgb8(cover: &[u8]) -> Result<(u32, u32, Vec<u8>), PqfileError> {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    let mut reader = ImageReader::new(Cursor::new(cover))
        .with_guessed_format()
        .map_err(|e| PqfileError::StegoInvalidImage(e.to_string()))?;
    reader.limits(limits);
    let img = reader
        .decode()
        .map_err(|e| PqfileError::StegoInvalidImage(e.to_string()))?;
    let (width, height) = (img.width(), img.height());
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(PqfileError::StegoInvalidImage(format!(
            "image too large ({width}x{height}); covers are capped at {MAX_PIXELS} pixels"
        )));
    }
    let rgb = img.to_rgb8();
    Ok((width, height, rgb.into_raw()))
}

/// Re-encodes `raw` (width x height RGB8 pixels) as PNG bytes.
fn encode_png(width: u32, height: u32, raw: Vec<u8>) -> Result<Vec<u8>, PqfileError> {
    let img = RgbImage::from_raw(width, height, raw)
        .ok_or_else(|| PqfileError::StegoInvalidImage("pixel buffer size mismatch".into()))?;
    let mut out = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(img)
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|e| PqfileError::StegoInvalidImage(e.to_string()))?;
    Ok(out.into_inner())
}

/// Embeds `bits_src` (MSB-first per byte) into the LSB of `carrier`, starting
/// at byte 0. Caller must ensure `carrier.len() >= bits_src.len() * 8`.
fn embed_bits(carrier: &mut [u8], bits_src: &[u8]) {
    for (byte_idx, &byte) in bits_src.iter().enumerate() {
        for bit_idx in 0..8u8 {
            let bit = (byte >> (7 - bit_idx)) & 1;
            let carrier_idx = byte_idx * 8 + bit_idx as usize;
            carrier[carrier_idx] = (carrier[carrier_idx] & !1) | bit;
        }
    }
}

/// Inverse of [`embed_bits`]: reconstructs `n_bytes` bytes from the LSB of
/// `carrier`, starting at byte 0. Caller must ensure `carrier.len() >= n_bytes * 8`.
fn extract_bits(carrier: &[u8], n_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; n_bytes];
    for (byte_idx, out_byte) in out.iter_mut().enumerate() {
        let mut byte = 0u8;
        for bit_idx in 0..8usize {
            let bit = carrier[byte_idx * 8 + bit_idx] & 1;
            byte = (byte << 1) | bit;
        }
        *out_byte = byte;
    }
    out
}

/// Argon2id under the frozen stego parameters (see module docs).
fn derive_kdf_key(passphrase: &str, salt: &[u8]) -> Result<LockedSecret<32>, PqfileError> {
    crate::passphrase::derive_key_with_params(
        passphrase,
        salt,
        STEGO_ARGON2_M_COST,
        STEGO_ARGON2_T_COST,
        STEGO_ARGON2_P_COST,
    )
}

struct StegoKeys {
    keystream: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

fn subkeys(kdf_key: &LockedSecret<32>) -> StegoKeys {
    StegoKeys {
        keystream: Zeroizing::new(blake3::derive_key(KEYSTREAM_CONTEXT, kdf_key.as_ref())),
        mac: Zeroizing::new(blake3::derive_key(MAC_CONTEXT, kdf_key.as_ref())),
    }
}

/// XORs the BLAKE3-XOF keystream under `key` over `buf`, from stream offset 0.
fn xor_keystream(key: &[u8; 32], buf: &mut [u8]) {
    let mut xof = blake3::Hasher::new_keyed(key).finalize_xof();
    let mut stream = Zeroizing::new(vec![0u8; buf.len()]);
    xof.fill(&mut stream);
    for (b, s) in buf.iter_mut().zip(stream.iter()) {
        *b ^= s;
    }
}

/// Hides `payload` inside `cover` (a PNG or JPEG image) and returns
/// PNG-encoded bytes with `payload` recoverable via [`exhume`] under the
/// same `passphrase`. Returns [`PqfileError::StegoCapacityExceeded`] if the
/// cover image is too small.
pub fn bury(cover: &[u8], payload: &[u8], passphrase: &str) -> Result<Vec<u8>, PqfileError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| PqfileError::EncryptionFailure)?;
    let kdf_key = derive_kdf_key(passphrase, &salt)?;
    bury_with_kdf_key(cover, payload, &salt, &kdf_key)
}

fn bury_with_kdf_key(
    cover: &[u8],
    payload: &[u8],
    salt: &[u8; SALT_LEN],
    kdf_key: &LockedSecret<32>,
) -> Result<Vec<u8>, PqfileError> {
    let (width, height, mut raw) = decode_raw_rgb8(cover)?;
    let needed = PREFIX_LEN + payload.len();
    let available = raw.len() / 8;
    // The u32::MAX guard keeps the LEN field cast below lossless; no real
    // cover has the >32 GiB of pixel data such a payload would also need.
    if needed > available || payload.len() > u32::MAX as usize {
        return Err(PqfileError::StegoCapacityExceeded { available, needed });
    }

    let keys = subkeys(kdf_key);
    let mac = blake3::keyed_hash(&keys.mac, payload);
    let mut frame = Zeroizing::new(Vec::with_capacity(HEADER_LEN + payload.len()));
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(mac.as_bytes());
    frame.extend_from_slice(payload);
    xor_keystream(&keys.keystream, &mut frame);

    let mut embedded = Vec::with_capacity(needed);
    embedded.extend_from_slice(salt);
    embedded.extend_from_slice(&frame);

    embed_bits(&mut raw, &embedded);
    encode_png(width, height, raw)
}

/// Recovers a payload previously hidden by [`bury`] under the same
/// `passphrase`. Returns [`PqfileError::StegoPayloadNotFound`] if
/// `stego_image` has no valid embedded payload - a wrong passphrase, a wrong
/// image, and an image edited/corrupted since burying are indistinguishable
/// by design (keyed detection).
pub fn exhume(stego_image: &[u8], passphrase: &str) -> Result<Vec<u8>, PqfileError> {
    exhume_impl(stego_image, |salt| derive_kdf_key(passphrase, salt))
}

fn exhume_impl(
    stego_image: &[u8],
    kdf: impl FnOnce(&[u8]) -> Result<LockedSecret<32>, PqfileError>,
) -> Result<Vec<u8>, PqfileError> {
    let (_, _, raw) = decode_raw_rgb8(stego_image)?;
    let capacity = raw.len() / 8;
    if capacity < PREFIX_LEN {
        return Err(PqfileError::StegoPayloadNotFound);
    }

    let prefix = extract_bits(&raw, PREFIX_LEN);
    let kdf_key = kdf(&prefix[..SALT_LEN])?;
    let keys = subkeys(&kdf_key);

    let mut header = Zeroizing::new(prefix[SALT_LEN..].to_vec());
    xor_keystream(&keys.keystream, &mut header);
    if header[..MAGIC.len()] != MAGIC {
        return Err(PqfileError::StegoPayloadNotFound);
    }
    let len = u32::from_le_bytes(
        header[MAGIC.len()..MAGIC.len() + LEN_LEN]
            .try_into()
            .unwrap(),
    );
    let mac: [u8; MAC_LEN] = header[MAGIC.len() + LEN_LEN..HEADER_LEN]
        .try_into()
        .unwrap();

    // u64 arithmetic: LEN is attacker-controlled, and on 32-bit targets
    // (wasm) `PREFIX_LEN + len` in usize could wrap past the capacity check.
    let total = PREFIX_LEN as u64 + u64::from(len);
    if total > capacity as u64 {
        return Err(PqfileError::StegoPayloadNotFound);
    }
    let total = total as usize;

    let mut frame = Zeroizing::new(extract_bits(&raw, total).split_off(SALT_LEN));
    xor_keystream(&keys.keystream, &mut frame);
    let payload = &frame[HEADER_LEN..];
    // `blake3::Hash`'s PartialEq is constant-time.
    if blake3::keyed_hash(&keys.mac, payload) != blake3::Hash::from_bytes(mac) {
        return Err(PqfileError::StegoPayloadNotFound);
    }

    Ok(payload.to_vec())
}

/// Returns the maximum payload size (in bytes) `cover` can hold, accounting
/// for the framing overhead (salt plus encrypted header). Useful for a caller
/// to size-check before calling [`bury`] without discarding the
/// capacity-exceeded numbers `bury` itself reports.
pub fn capacity(cover: &[u8]) -> Result<usize, PqfileError> {
    let (_, _, raw) = decode_raw_rgb8(cover)?;
    Ok((raw.len() / 8).saturating_sub(PREFIX_LEN))
}

// ── Fuzzing entry points ───────────────────────────────────────────────────
// Compiled only under `cargo fuzz` (RUSTFLAGS --cfg fuzzing), so they never
// appear in the published API. They skip the Argon2 KDF - at 64 MiB per
// derivation it would reduce fuzz throughput to a crawl - and take the
// 32-byte kdf-stage key directly; everything downstream of the KDF
// (subkey split, keystream, framing, embedding, parsing) is exercised as-is.

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_bury_with_fixed_key(
    cover: &[u8],
    payload: &[u8],
    kdf_key: &[u8; 32],
) -> Result<Vec<u8>, PqfileError> {
    let mut key = LockedSecret::<32>::zeroed();
    key.copy_from_slice(kdf_key);
    bury_with_kdf_key(cover, payload, &[0u8; SALT_LEN], &key)
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_exhume_with_fixed_key(
    stego_image: &[u8],
    kdf_key: &[u8; 32],
) -> Result<Vec<u8>, PqfileError> {
    exhume_impl(stego_image, |_salt| {
        let mut key = LockedSecret::<32>::zeroed();
        key.copy_from_slice(kdf_key);
        Ok(key)
    })
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub fn fuzz_make_cover(width: u32, height: u32) -> Vec<u8> {
    let raw: Vec<u8> = (0..width as usize * height as usize * 3)
        .map(|i| (i * 31 % 256) as u8)
        .collect();
    encode_png(width, height, raw).expect("cover encode")
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::ImageBuffer;

    const PASS: &str = "correct horse battery staple";

    /// Deterministic, non-uniform pixel data (so LSB embedding is visibly
    /// exercised rather than starting from all-zero bytes), encoded as PNG.
    fn make_cover(width: u32, height: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(width, height, |x, y| {
            image::Rgb([
                ((x * 37 + y * 91) % 256) as u8,
                ((x * 13 + y * 7) % 256) as u8,
                ((x + y * 3) % 256) as u8,
            ])
        });
        encode_png(width, height, img.into_raw()).unwrap()
    }

    #[test]
    fn roundtrip_small_payload() {
        let cover = make_cover(64, 64);
        let payload = b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----";
        let stego = bury(&cover, payload, PASS).unwrap();
        let recovered = exhume(&stego, PASS).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let cover = make_cover(32, 32);
        let stego = bury(&cover, b"", PASS).unwrap();
        let recovered = exhume(&stego, PASS).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn roundtrip_payload_near_capacity() {
        let cover = make_cover(32, 32);
        let cap = capacity(&cover).unwrap();
        let payload = vec![0xABu8; cap];
        let stego = bury(&cover, &payload, PASS).unwrap();
        let recovered = exhume(&stego, PASS).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn payload_over_capacity_rejected() {
        let cover = make_cover(16, 16);
        let cap = capacity(&cover).unwrap();
        let payload = vec![0u8; cap + 1];
        let result = bury(&cover, &payload, PASS);
        assert!(matches!(
            result,
            Err(PqfileError::StegoCapacityExceeded { .. })
        ));
    }

    #[test]
    fn exhume_on_plain_cover_fails() {
        let cover = make_cover(64, 64);
        let result = exhume(&cover, PASS);
        assert!(matches!(result, Err(PqfileError::StegoPayloadNotFound)));
    }

    #[test]
    fn exhume_wrong_passphrase_fails_identically_to_no_payload() {
        let cover = make_cover(64, 64);
        let stego = bury(&cover, b"secret key material", PASS).unwrap();
        let result = exhume(&stego, "not the passphrase");
        assert!(matches!(result, Err(PqfileError::StegoPayloadNotFound)));
    }

    #[test]
    fn embedded_bytes_have_no_plaintext_structure() {
        // Keyed detection: the LSB-embedded bytes must not contain the magic,
        // the payload length, or the payload itself in the clear. Only the
        // random salt precedes the keystream-encrypted frame.
        let cover = make_cover(64, 64);
        let payload = b"attributable plaintext";
        let stego = bury(&cover, payload, PASS).unwrap();
        let (_, _, raw) = decode_raw_rgb8(&stego).unwrap();
        let embedded = extract_bits(&raw, PREFIX_LEN + payload.len());
        assert_ne!(&embedded[SALT_LEN..SALT_LEN + MAGIC.len()], &MAGIC);
        let hay = embedded.as_slice();
        assert!(!hay.windows(payload.len()).any(|w| w == payload.as_slice()));
    }

    #[test]
    fn exhume_on_tampered_stego_fails() {
        let cover = make_cover(64, 64);
        let payload = b"secret key material";
        let stego = bury(&cover, payload, PASS).unwrap();

        let (width, height, mut raw) = decode_raw_rgb8(&stego).unwrap();
        // Flip a bit inside the embedded payload region (after the
        // PREFIX_LEN*8-bit salt+header, before the end of the framed message)
        // to prove the MAC, not just magic/length parsing, is checked.
        let idx = PREFIX_LEN * 8 + 3;
        raw[idx] ^= 0x01;
        let tampered = encode_png(width, height, raw).unwrap();

        let result = exhume(&tampered, PASS);
        assert!(matches!(result, Err(PqfileError::StegoPayloadNotFound)));
    }

    #[test]
    fn oversized_recorded_length_rejected_not_panicking() {
        // Craft an image whose decrypted header is valid (magic matches) but
        // whose LEN field is u32::MAX. On 64-bit this exercises the same
        // capacity rejection whose absence would wrap `PREFIX_LEN + len` into
        // a panicking slice range on 32-bit targets (wasm).
        let cover = make_cover(64, 64);
        let (width, height, mut raw) = decode_raw_rgb8(&cover).unwrap();

        let salt = [0x42u8; SALT_LEN];
        let kdf_key = derive_kdf_key(PASS, &salt).unwrap();
        let keys = subkeys(&kdf_key);
        let mut header = Vec::new();
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(&u32::MAX.to_le_bytes());
        header.extend_from_slice(&[0u8; MAC_LEN]);
        xor_keystream(&keys.keystream, &mut header);

        let mut embedded = Vec::new();
        embedded.extend_from_slice(&salt);
        embedded.extend_from_slice(&header);
        embed_bits(&mut raw, &embedded);
        let crafted = encode_png(width, height, raw).unwrap();

        let result = exhume(&crafted, PASS);
        assert!(matches!(result, Err(PqfileError::StegoPayloadNotFound)));
    }

    #[test]
    fn oversized_dimensions_rejected() {
        // 17000x1 exceeds MAX_DIMENSION before any pixel buffer is built.
        let cover = make_cover(17_000, 1);
        let result = capacity(&cover);
        assert!(matches!(result, Err(PqfileError::StegoInvalidImage(_))));
    }

    #[test]
    fn jpeg_cover_input_is_accepted_but_output_is_png() {
        // A round-trip through a lossy JPEG *cover* is fine as input, since
        // bury() decodes to raw pixels and always re-encodes losslessly as
        // PNG; only using JPEG as the *output* would break embedding.
        let img = ImageBuffer::from_fn(64, 64, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
        });
        let mut jpeg_bytes = Cursor::new(Vec::new());
        DynamicImage::ImageRgb8(img)
            .write_to(&mut jpeg_bytes, ImageFormat::Jpeg)
            .unwrap();

        let payload = b"key material";
        let stego = bury(&jpeg_bytes.into_inner(), payload, PASS).unwrap();
        assert_eq!(image::guess_format(&stego).unwrap(), ImageFormat::Png);
        let recovered = exhume(&stego, PASS).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn capacity_matches_manual_calculation() {
        let cover = make_cover(20, 20);
        let raw_len = 20 * 20 * 3;
        assert_eq!(capacity(&cover).unwrap(), raw_len / 8 - PREFIX_LEN);
    }
}
