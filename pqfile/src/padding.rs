//! Plaintext-length padding (Padmé) and output truncation.
//!
//! Every `.pqf` header already records `original_size`, the true plaintext
//! length, and that field is already bound into the chunk-0 key commitment
//! (see `format::compute_key_commitment` / `format::commitment_for_stream`),
//! so it cannot be tampered with independently of the payload. These two
//! adapters use that existing field rather than changing the wire format:
//!
//! - [`PadmeReader`] wraps a plaintext reader so it emits extra zero bytes up
//!   to a Padmé-rounded length before EOF. Encrypt with the *real* length
//!   passed as `original_size` (as normal) and the wrapped reader in place of
//!   the real one; the header keeps recording the true size, but the
//!   authenticated ciphertext is now the size of the padded bucket instead.
//! - [`TruncatingWriter`] wraps a decrypt destination so at most
//!   `original_size` bytes are ever forwarded to it, silently dropping the
//!   padding tail. Because non-padded files already decrypt to exactly
//!   `original_size` bytes, wrapping every decrypt destination with this
//!   adapter is a no-op for them - there is no need to know ahead of time
//!   whether a given file was padded.
//!
//! Neither adapter is used automatically by `encrypt_*`/`decrypt_*`; callers
//! opt in by wrapping their reader or writer before calling them.

use std::io::{self, Read, Write};

/// Computes the Padmé-padded length for a plaintext of `len` bytes.
///
/// Padmé (Reardon, Basin & Capkun, *PADMÉ: On the Deployment of Padding for
/// Privacy-Preserving Systems*) rounds `len` up to a value whose low-order
/// bits are masked to zero, where the number of masked bits grows with the
/// bit-length of `len`'s own bit-length. This bounds the padding overhead to
/// roughly `1/2^k` for a length whose bit-length is `k` bits shorter than
/// itself - in practice at most ~12% for real file sizes - while ensuring
/// many distinct real lengths collapse onto the same padded value, which is
/// the point: an observer who only sees the padded (ciphertext) length learns
/// less about the real length than they would from the exact byte count.
///
/// `len` values 0 and 1 pad to themselves (there is no meaningful bucket to
/// round into below that). Lengths whose Padmé bucket would exceed `u64::MAX`
/// saturate to `u64::MAX` instead of overflowing (never reachable for real
/// file sizes, which are capped well below by `MAX_ORIGINAL_SIZE`).
#[must_use]
pub fn padme_length(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    // E = floor(log2(len)): index of len's highest set bit (len >= 2, so E >= 1).
    let e: u32 = 63 - len.leading_zeros();
    // S = floor(log2(E)) + 1 = bit-length of E (E >= 1, so this is well-defined).
    let s: u32 = 32 - e.leading_zeros();
    let last_bits = e - s;
    let bit_mask: u64 = (1u64 << last_bits) - 1;
    len.checked_add(bit_mask)
        .map_or(u64::MAX, |sum| sum & !bit_mask)
}

/// Wraps a plaintext reader so it appears to have Padmé-padded length.
///
/// Yields `inner`'s bytes unchanged, then continues past its EOF with zero
/// bytes until [`padme_length`]`(real_len)` total bytes have been produced.
/// `real_len` must be the exact number of bytes `inner` will yield; passing a
/// smaller value truncates the visible padding boundary, and a larger value
/// makes this reader hang short of the promised length (EOF arrives from
/// `inner` before the padding target is reached, which is otherwise
/// harmless: the wrapped stream just ends early).
pub struct PadmeReader<R: Read> {
    inner: R,
    inner_done: bool,
    padding_remaining: u64,
}

impl<R: Read> PadmeReader<R> {
    /// Wraps `inner`, which must yield exactly `real_len` bytes before EOF.
    #[must_use]
    pub fn new(inner: R, real_len: u64) -> Self {
        let padded_len = padme_length(real_len);
        Self {
            inner,
            inner_done: false,
            padding_remaining: padded_len.saturating_sub(real_len),
        }
    }
}

impl<R: Read> Read for PadmeReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.inner_done {
            let n = self.inner.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.inner_done = true;
        }
        if self.padding_remaining == 0 {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.padding_remaining) as usize;
        buf[..n].fill(0);
        self.padding_remaining -= n as u64;
        Ok(n)
    }
}

/// Wraps a writer so at most `limit` bytes are ever forwarded to it; any
/// further bytes are accepted (to keep `write_all` callers happy) but
/// discarded.
///
/// `limit == 0` means "unknown length" - the existing convention for
/// streaming/stdin encryption where the true size wasn't known upfront - and
/// disables truncation entirely, so every byte is forwarded. This makes
/// wrapping any decrypt destination with this adapter safe by default: a
/// file that was never padded already decrypts to exactly `limit` bytes, so
/// truncating to `limit` changes nothing for it.
pub struct TruncatingWriter<W: Write> {
    inner: W,
    remaining: Option<u64>,
}

impl<W: Write> TruncatingWriter<W> {
    /// Wraps `inner`, capping forwarded bytes at `limit` (0 = no cap).
    #[must_use]
    pub fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            remaining: if limit == 0 { None } else { Some(limit) },
        }
    }

    /// Unwraps this adapter, returning the inner writer.
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for TruncatingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining else {
            return self.inner.write(buf);
        };
        if remaining == 0 {
            return Ok(buf.len());
        }
        let take = (buf.len() as u64).min(remaining) as usize;
        let written = self.inner.write(&buf[..take])?;
        self.remaining = Some(remaining - written as u64);
        if written < take {
            // Inner short-wrote: claiming the discarded tail as consumed here
            // would make the caller skip the unwritten buf[written..take]
            // prefix bytes on retry. Report only the true prefix.
            return Ok(written);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_length_edge_cases() {
        assert_eq!(padme_length(0), 0);
        assert_eq!(padme_length(1), 1);
    }

    #[test]
    fn padme_length_known_values() {
        // Hand-derived from the Padmé algorithm (see module docs); each value's
        // bracket is determined by E = floor(log2(len)).
        assert_eq!(padme_length(2), 2);
        assert_eq!(padme_length(3), 3);
        assert_eq!(padme_length(4), 4);
        assert_eq!(padme_length(7), 7);
        assert_eq!(padme_length(8), 8);
        assert_eq!(padme_length(9), 10);
        assert_eq!(padme_length(10), 10);
        assert_eq!(padme_length(11), 12);
        assert_eq!(padme_length(12), 12);
        assert_eq!(padme_length(13), 14);
        assert_eq!(padme_length(14), 14);
        assert_eq!(padme_length(15), 16);
    }

    #[test]
    fn padme_length_saturates_near_u64_max() {
        // Buckets that would round past u64::MAX saturate instead of
        // overflowing (panic in debug, shrink-below-len in release).
        assert_eq!(padme_length(u64::MAX), u64::MAX);
        assert_eq!(padme_length(u64::MAX - 1), u64::MAX);
        for len in [u64::MAX / 2, u64::MAX - (1 << 57), u64::MAX] {
            assert!(padme_length(len) >= len, "len={len}");
        }
    }

    #[test]
    fn padme_length_never_shrinks() {
        for len in 0..100_000u64 {
            assert!(padme_length(len) >= len, "len={len}");
        }
        for len in (100_000..5_000_000u64).step_by(997) {
            assert!(padme_length(len) >= len, "len={len}");
        }
    }

    #[test]
    fn padme_length_monotonic() {
        let mut prev = padme_length(0);
        for len in 1..200_000u64 {
            let cur = padme_length(len);
            assert!(cur >= prev, "padme_length must not decrease: len={len}");
            prev = cur;
        }
    }

    #[test]
    fn padme_length_overhead_bounded() {
        // Padmé's overhead bound is roughly 1/2^S, which stays under ~12% for
        // any length with at least a handful of significant bits. Use a
        // generous 15% ceiling (avoids flakiness) and skip tiny lengths where
        // the bound doesn't meaningfully apply yet.
        for len in (16..2_000_000u64).step_by(101) {
            let padded = padme_length(len);
            let overhead = (padded - len) as f64 / len as f64;
            assert!(
                overhead <= 0.15,
                "len={len} padded={padded} overhead={overhead:.3}"
            );
        }
    }

    #[test]
    fn padme_reader_yields_padded_length_and_correct_prefix() {
        let real: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let mut reader = PadmeReader::new(real.as_slice(), real.len() as u64);
        let mut out = Vec::new();
        io::Read::read_to_end(&mut reader, &mut out).unwrap();

        let expected_len = padme_length(real.len() as u64) as usize;
        assert_eq!(out.len(), expected_len);
        assert_eq!(&out[..real.len()], real.as_slice());
        assert!(out[real.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn padme_reader_empty_input_is_noop() {
        let mut reader = PadmeReader::new([].as_slice(), 0);
        let mut out = Vec::new();
        io::Read::read_to_end(&mut reader, &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn padme_reader_small_reads_still_reach_padded_length() {
        let real = vec![0xABu8; 9]; // padme_length(9) == 10
        let mut reader = PadmeReader::new(real.as_slice(), real.len() as u64);
        let mut out = Vec::new();
        let mut buf = [0u8; 1];
        loop {
            let n = io::Read::read(&mut reader, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.push(buf[0]);
        }
        assert_eq!(out.len(), 10);
        assert_eq!(&out[..9], real.as_slice());
        assert_eq!(out[9], 0);
    }

    #[test]
    fn truncating_writer_strips_padding_tail() {
        let mut sink = Vec::new();
        {
            let mut w = TruncatingWriter::new(&mut sink, 5);
            w.write_all(b"hello padding tail").unwrap();
        }
        assert_eq!(sink, b"hello");
    }

    #[test]
    fn truncating_writer_zero_limit_passes_everything() {
        let mut sink = Vec::new();
        {
            let mut w = TruncatingWriter::new(&mut sink, 0);
            w.write_all(b"unbounded").unwrap();
        }
        assert_eq!(sink, b"unbounded");
    }

    #[test]
    fn truncating_writer_exact_length_is_noop() {
        let mut sink = Vec::new();
        {
            let mut w = TruncatingWriter::new(&mut sink, 5);
            w.write_all(b"hello").unwrap();
        }
        assert_eq!(sink, b"hello");
    }

    #[test]
    fn truncating_writer_across_multiple_writes() {
        let mut sink = Vec::new();
        {
            let mut w = TruncatingWriter::new(&mut sink, 4);
            w.write_all(b"ab").unwrap();
            w.write_all(b"cd").unwrap();
            w.write_all(b"ef").unwrap();
        }
        assert_eq!(sink, b"abcd");
    }

    /// A legal `Write` impl that accepts at most 3 bytes per call.
    struct ShortWriter(Vec<u8>);

    impl Write for ShortWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = buf.len().min(3);
            self.0.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn truncating_writer_survives_short_writes() {
        // Regression: when the inner writer short-writes (pipes do this), the
        // reported consumed count must not skip unwritten in-limit bytes, or
        // write_all retries from the wrong offset and padding bytes replace
        // real plaintext.
        let mut w = TruncatingWriter::new(ShortWriter(Vec::new()), 6);
        w.write_all(b"ABCDEFpppp").unwrap();
        assert_eq!(w.into_inner().0, b"ABCDEF");
    }

    #[test]
    fn truncating_writer_short_writes_within_limit() {
        let mut w = TruncatingWriter::new(ShortWriter(Vec::new()), 100);
        w.write_all(b"hello world").unwrap();
        assert_eq!(w.into_inner().0, b"hello world");
    }

    #[test]
    fn truncating_writer_into_inner() {
        let w = TruncatingWriter::new(Vec::new(), 3);
        let mut w = w;
        w.write_all(b"abcdef").unwrap();
        assert_eq!(w.into_inner(), b"abc");
    }
}
