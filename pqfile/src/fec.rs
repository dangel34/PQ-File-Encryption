//! Forward-error-correction sidecar for cold-storage resilience (`fec` feature).
//!
//! pqfile's AEAD authentication is all-or-nothing: a single flipped bit
//! anywhere in a chunk fails that chunk's tag and the file cannot be
//! decrypted past that point. That is correct behavior against tampering,
//! but it is also the failure mode for ordinary bit rot on optical media,
//! aging cloud storage, or a flaky transfer. This module adds an *opt-in*,
//! purely additive layer that has no interaction with authentication
//! semantics at all: it either restores the exact original bytes, or gives
//! up and leaves the (still tampered/corrupted) bytes for the normal AEAD
//! check to reject exactly as it would without this feature.
//!
//! **Not a wire-format change.** Parity is written to a separate sidecar
//! file (conventionally `<output>.pqf.fec`), computed as a post-pass over
//! the finished ciphertext's raw bytes - header and all - with no awareness
//! of `.pqf` structure at all. This is what makes it apply uniformly to
//! every format version (v2 through v11, single- or multi-recipient,
//! compressed or not) without any format-specific code here.
//!
//! Uses classical Reed-Solomon BCH error *correction* (via the
//! [`reed-solomon`](https://crates.io/crates/reed-solomon) crate), not
//! erasure coding: 8 ECC bytes per 128-byte block correct up to 4 corrupted
//! bytes *anywhere* in that block without knowing their positions in
//! advance, mirroring Picocrypt's own choice of ratio (which tolerates
//! roughly 3% corruption before giving up). See `docs/ROADMAP.md`,
//! "Forward-error-correction for cold-storage resilience".

use std::io::{self, Read};

use reed_solomon::{Decoder, Encoder};

use crate::error::PqfileError;
use crate::io_util::fill_or_eof;

/// Data bytes per FEC block.
const DATA_BLOCK_LEN: usize = 128;
/// ECC bytes appended per block: corrects up to `ECC_LEN / 2` = 4 corrupted
/// bytes anywhere in a 128-byte block.
const ECC_LEN: usize = 8;

const SIDECAR_MAGIC: &[u8; 4] = b"PQFE";
const SIDECAR_VERSION: u8 = 1;
/// `MAGIC(4) | VERSION(1) | ORIGINAL_LEN(8 LE) | ECC_LEN(1) | DATA_BLOCK_LEN(4 LE)`.
const SIDECAR_HEADER_LEN: usize = 4 + 1 + 8 + 1 + 4;

/// Generates a FEC parity sidecar for the byte stream read from `reader` -
/// typically a finished `.pqf` file, read back once after a normal encrypt
/// completes. Streams through `reader` in `DATA_BLOCK_LEN`-byte blocks, so
/// memory use is bounded regardless of file size (parity itself is
/// proportional to file size - roughly 6.25% at the default ratio - so
/// holding the whole sidecar in memory before writing it is fine for
/// reasonable file sizes, but the *input* is never buffered in full).
pub fn generate_sidecar<R: Read>(reader: &mut R) -> Result<Vec<u8>, PqfileError> {
    let encoder = Encoder::new(ECC_LEN);
    let mut out = Vec::with_capacity(SIDECAR_HEADER_LEN);
    out.extend_from_slice(SIDECAR_MAGIC);
    out.push(SIDECAR_VERSION);
    let len_pos = out.len();
    out.extend_from_slice(&0u64.to_le_bytes()); // patched below
    out.push(ECC_LEN as u8);
    out.extend_from_slice(&(DATA_BLOCK_LEN as u32).to_le_bytes());

    let mut buf = vec![0u8; DATA_BLOCK_LEN];
    let mut total_len: u64 = 0;
    loop {
        let n = fill_or_eof(reader, &mut buf).map_err(PqfileError::Io)?;
        if n == 0 {
            break;
        }
        total_len += n as u64;
        let encoded = encoder.encode(&buf[..n]);
        out.extend_from_slice(encoded.ecc());
    }
    out[len_pos..len_pos + 8].copy_from_slice(&total_len.to_le_bytes());
    Ok(out)
}

/// Parsed sidecar header, plus the still-open parity stream positioned right
/// after it (ready to read ECC blocks in order).
struct SidecarHeader {
    #[allow(dead_code)] // kept for diagnostics/future use; not load-bearing today
    original_len: u64,
    ecc_len: usize,
    data_block_len: usize,
}

fn read_sidecar_header<P: Read>(parity: &mut P) -> Result<SidecarHeader, PqfileError> {
    let mut header = [0u8; SIDECAR_HEADER_LEN];
    parity.read_exact(&mut header).map_err(|e| {
        PqfileError::FecSidecarInvalid(format!("could not read sidecar header: {e}"))
    })?;
    if header[..4] != *SIDECAR_MAGIC {
        return Err(PqfileError::FecSidecarInvalid(
            "not a pqfile FEC sidecar (bad magic)".to_string(),
        ));
    }
    if header[4] != SIDECAR_VERSION {
        return Err(PqfileError::FecSidecarInvalid(format!(
            "unsupported FEC sidecar version {}",
            header[4]
        )));
    }
    let original_len = u64::from_le_bytes(header[5..13].try_into().expect("8 bytes"));
    let ecc_len = header[13] as usize;
    let data_block_len = u32::from_le_bytes(header[14..18].try_into().expect("4 bytes")) as usize;
    Ok(SidecarHeader {
        original_len,
        ecc_len,
        data_block_len,
    })
}

/// Wraps a raw ciphertext reader (`data`) and its FEC sidecar (`parity`),
/// transparently repairing each block as it is read so that whatever
/// consumes this `Read` (the normal decrypt/check/inspect path) never sees
/// the corruption in the first place - repair happens *before* the AEAD
/// check runs, not instead of it.
///
/// A block that cannot be corrected (more than 4 bad bytes in that 128-byte
/// window) is passed through unchanged rather than erroring here: the
/// normal downstream authentication then fails exactly as it would without
/// FEC at all. This is deliberate - FEC only ever restores exact original
/// bytes or gets out of the way, never masks a real tamper failure.
pub struct FecRepairReader<D, P> {
    data: D,
    parity: P,
    ecc_len: usize,
    data_block_len: usize,
    buf: Vec<u8>,
    buf_pos: usize,
    exhausted: bool,
}

impl<D: Read, P: Read> FecRepairReader<D, P> {
    /// Reads and validates the sidecar header from `parity`, then returns a
    /// reader ready to serve repaired bytes from `data`.
    pub fn new(data: D, mut parity: P) -> Result<Self, PqfileError> {
        let header = read_sidecar_header(&mut parity)?;
        Ok(Self {
            data,
            parity,
            ecc_len: header.ecc_len,
            data_block_len: header.data_block_len,
            buf: Vec::new(),
            buf_pos: 0,
            exhausted: false,
        })
    }

    /// Reads and repairs the next block into `self.buf`. Returns `false` at
    /// end of the data stream.
    fn fill_next_block(&mut self) -> io::Result<bool> {
        let mut data_buf = vec![0u8; self.data_block_len];
        let n = fill_or_eof(&mut self.data, &mut data_buf)?;
        if n == 0 {
            self.exhausted = true;
            return Ok(false);
        }

        let mut ecc_buf = vec![0u8; self.ecc_len];
        let ecc_n = fill_or_eof(&mut self.parity, &mut ecc_buf)?;
        if ecc_n < self.ecc_len {
            // Sidecar shorter than the data stream (mismatched/truncated
            // parity) - nothing to repair with; pass this block through as-is.
            self.buf = data_buf[..n].to_vec();
        } else {
            let decoder = Decoder::new(self.ecc_len);
            let mut combined = data_buf[..n].to_vec();
            combined.extend_from_slice(&ecc_buf);
            self.buf = match decoder.correct(&combined, None) {
                Ok(recovered) => recovered.data().to_vec(),
                // Uncorrectable: leave the (possibly still-corrupted) data
                // bytes alone. The downstream AEAD/parsing layer discovers
                // and reports this exactly as it would without FEC.
                Err(_) => data_buf[..n].to_vec(),
            };
        }
        self.buf_pos = 0;
        Ok(true)
    }
}

impl<D: Read, P: Read> Read for FecRepairReader<D, P> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.buf_pos >= self.buf.len() {
            if self.exhausted {
                return Ok(0);
            }
            if !self.fill_next_block()? {
                return Ok(0);
            }
        }
        let avail = self.buf.len() - self.buf_pos;
        let take = avail.min(out.len());
        out[..take].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + take]);
        self.buf_pos += take;
        Ok(take)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_no_corruption() {
        let original: Vec<u8> = (0u8..=255).cycle().take(DATA_BLOCK_LEN * 5 + 37).collect();
        let sidecar = generate_sidecar(&mut original.as_slice()).unwrap();

        let mut reader = FecRepairReader::new(original.as_slice(), sidecar.as_slice()).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn corrects_bounded_corruption_per_block() {
        let original: Vec<u8> = (0u8..=255).cycle().take(DATA_BLOCK_LEN * 3 + 11).collect();
        let sidecar = generate_sidecar(&mut original.as_slice()).unwrap();

        // Flip up to 4 bytes (the correctable bound) inside the first block.
        let mut corrupted = original.clone();
        corrupted[0] ^= 0xFF;
        corrupted[10] ^= 0xFF;
        corrupted[50] ^= 0xFF;
        corrupted[100] ^= 0xFF;

        let mut reader = FecRepairReader::new(corrupted.as_slice(), sidecar.as_slice()).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(
            out, original,
            "correctable corruption must be fully repaired"
        );
    }

    #[test]
    fn passes_through_uncorrectable_block_unchanged() {
        let original: Vec<u8> = (0u8..=255).cycle().take(DATA_BLOCK_LEN * 2).collect();
        let sidecar = generate_sidecar(&mut original.as_slice()).unwrap();

        // Flip more bytes than the code can correct (5 > 4) in one block.
        let mut corrupted = original.clone();
        for i in [0, 10, 20, 30, 40] {
            corrupted[i] ^= 0xFF;
        }

        let mut reader = FecRepairReader::new(corrupted.as_slice(), sidecar.as_slice()).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        // Uncorrectable: the reader must not fabricate data. It should come
        // back byte-identical to the (still corrupted) input, so a normal
        // downstream AEAD check fails exactly as it would without FEC.
        assert_eq!(out, corrupted);
        assert_ne!(out, original);
    }

    #[test]
    fn passes_through_when_sidecar_shorter_than_data() {
        // Two full blocks; corrupt one byte in the second block, then drop
        // that block's ECC bytes from the sidecar entirely - a truncated or
        // mismatched `.fec` file, distinct from "the block was uncorrectable"
        // (which still has ECC bytes to try and fail with). Both cases must
        // behave the same way: leave the surviving bytes untouched rather
        // than fabricating anything, so a real tamper failure downstream
        // still fails exactly as it would without FEC.
        let original: Vec<u8> = (0u8..=255).cycle().take(DATA_BLOCK_LEN * 2).collect();
        let sidecar = generate_sidecar(&mut original.as_slice()).unwrap();

        let mut corrupted = original.clone();
        corrupted[DATA_BLOCK_LEN + 5] ^= 0xFF;

        let mut short_sidecar = sidecar.clone();
        short_sidecar.truncate(sidecar.len() - ECC_LEN);

        let mut reader =
            FecRepairReader::new(corrupted.as_slice(), short_sidecar.as_slice()).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(
            out, corrupted,
            "a sidecar too short to cover a block must leave that block's bytes untouched"
        );
        assert_ne!(out, original);
    }

    #[test]
    fn rejects_bad_sidecar_magic() {
        let original = vec![0u8; DATA_BLOCK_LEN];
        let mut sidecar = generate_sidecar(&mut original.as_slice()).unwrap();
        sidecar[0] = !sidecar[0];
        match FecRepairReader::new(original.as_slice(), sidecar.as_slice()) {
            Ok(_) => panic!("expected an error"),
            Err(e) => assert!(matches!(e, PqfileError::FecSidecarInvalid(_))),
        }
    }

    #[test]
    fn empty_input_roundtrips() {
        let original: Vec<u8> = Vec::new();
        let sidecar = generate_sidecar(&mut original.as_slice()).unwrap();
        let mut reader = FecRepairReader::new(original.as_slice(), sidecar.as_slice()).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }
}
