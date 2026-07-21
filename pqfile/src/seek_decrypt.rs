//! Random-access decryption: [`SeekableDecryptor`](crate::seek_decrypt::SeekableDecryptor)`<R>`
//! wraps any `R: Read + Seek` and lets a caller jump directly to any chunk -
//! or, via the `Read`/`Seek` trait impls, any byte offset - without
//! decrypting everything before it.
//!
//! Only v3/v5 (chunked, single-recipient) files are supported: v2 has no
//! chunking to seek within, and multi-recipient/compressed/passphrase/
//! stealth/time-locked formats are out of scope for this first cut (see
//! `docs/ROADMAP.md`, "Seekable/random-access decryption API").
//!
//! **This weakens the "authenticate everything before returning any
//! plaintext" invariant** that every other decrypt function in this crate
//! holds: only the chunk(s) actually read are authenticated, not the file as
//! a whole. An attacker who tampers with a chunk that's never requested (or
//! truncates the file, or reorders/duplicates chunks at positions never
//! visited) is not detected. Use this only when true random access is
//! required - previewing part of a huge file, seeking within decrypted
//! media - and prefer [`crate::decrypt::decrypt_stream`] or
//! [`crate::decrypt::decrypt_stream_parallel`] for anything where "the whole
//! file authenticated, or nothing" is the property actually needed, which is
//! almost always the right default.
//!
//! Chunk/plaintext-length accounting here is derived from the physical
//! ciphertext size on disk, not the header's `original_size` field, so it is
//! correct even for a file written with `encrypt --pad` (Padmé padding) -
//! `original_size` in that case is smaller than what this type reports via
//! [`len`](crate::seek_decrypt::SeekableDecryptor::len), since padding is
//! invisible on this path (unlike the sequential decrypt functions, which
//! strip it automatically). Call
//! [`header_original_size`](crate::seek_decrypt::SeekableDecryptor::header_original_size)
//! if the true unpadded length is needed.

use std::io::{self, Read, Seek, SeekFrom};

use chacha20poly1305::{
    aead::{AeadInOut, Tag},
    ChaCha20Poly1305,
};
use zeroize::Zeroizing;

use crate::decrypt::decapsulate_stream_init;
use crate::error::PqfileError;
use crate::format::{
    chunk_nonce, make_chunk_aad, version_layout, BASE_NONCE_LEN, MAGIC, VERSION_V3, VERSION_V5,
};

/// Random-access decryptor for v3/v5 `.pqf` files. See the module docs for
/// the authentication tradeoff this makes versus the sequential decrypt
/// functions.
pub struct SeekableDecryptor<R> {
    reader: R,
    cipher: ChaCha20Poly1305,
    base_nonce: [u8; BASE_NONCE_LEN],
    key_commitment: [u8; 32],
    chunk_size: usize,
    header_len: u64,
    num_chunks: u32,
    last_chunk_plaintext_len: usize,
    total_plaintext_len: u64,
    header_original_size: u64,
    position: u64,
    buffered_chunk_index: Option<u32>,
    buffered_chunk: Zeroizing<Vec<u8>>,
}

/// Maps a chunk-decryption failure to the `io::Error` kind/payload the
/// `Read` impl below should surface, mirroring `PqfReader`'s conventions in
/// `reader.rs`: an I/O error is unwrapped rather than double-wrapped, a
/// truncation maps to `UnexpectedEof`, and everything else (AEAD failure,
/// out-of-range index) maps to `InvalidData` carrying the original
/// `PqfileError` so callers can `downcast_ref` it back out.
fn chunk_error_to_io(e: PqfileError) -> io::Error {
    match e {
        PqfileError::Io(io_err) => io_err,
        PqfileError::Truncated => {
            io::Error::new(io::ErrorKind::UnexpectedEof, PqfileError::Truncated)
        }
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

impl<R: Read + Seek> SeekableDecryptor<R> {
    /// Opens `reader` for random-access decryption: authenticates and parses
    /// the header (same key-derivation/decapsulation path every other
    /// decrypt function uses), then measures the physical ciphertext region
    /// via `Seek` to work out the chunk count. Rejects every format except
    /// v3/v5 with `UnsupportedVersion` before paying for key derivation on a
    /// format this API can't seek within.
    pub fn open(
        mut reader: R,
        privkey_pem: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, PqfileError> {
        reader.seek(SeekFrom::Start(0)).map_err(PqfileError::Io)?;

        let mut preamble = [0u8; 5];
        reader.read_exact(&mut preamble).map_err(PqfileError::Io)?;
        if preamble[..4] != *MAGIC.as_ref() {
            return Err(PqfileError::InvalidMagic);
        }
        let version = preamble[4];
        if version_layout(version) != VERSION_V3 && version_layout(version) != VERSION_V5 {
            return Err(PqfileError::UnsupportedVersion(version));
        }

        reader.seek(SeekFrom::Start(0)).map_err(PqfileError::Io)?;
        let state = decapsulate_stream_init(&mut reader, privkey_pem, passphrase)?;
        debug_assert!(
            state.v2_plaintext.is_none(),
            "v2 was rejected by the version_layout check above"
        );

        let chunk_size = state.chunk_size;
        let base_nonce: [u8; BASE_NONCE_LEN] = state.nonce[..BASE_NONCE_LEN]
            .try_into()
            .expect("BASE_NONCE_LEN <= NONCE_LEN; field type guarantees 12 bytes");

        let header_len = reader.stream_position().map_err(PqfileError::Io)?;
        let total_len = reader.seek(SeekFrom::End(0)).map_err(PqfileError::Io)?;
        let ct_region = total_len
            .checked_sub(header_len)
            .filter(|&n| n >= 16)
            .ok_or(PqfileError::Truncated)?;

        // See the module docs for the derivation: every chunk except the
        // last occupies exactly `chunk_size + 16` bytes on disk, so the
        // chunk count and last chunk's length follow from the physical
        // ciphertext region alone - independent of the header's
        // `original_size`, which may differ under Padmé padding.
        let cs16 = (chunk_size + 16) as u64;
        let full_before = (ct_region - 1) / cs16;
        let last_ct_len = ct_region - full_before * cs16;
        let num_chunks =
            u32::try_from(full_before + 1).map_err(|_| PqfileError::DecryptionFailure)?;
        let last_chunk_plaintext_len = (last_ct_len - 16) as usize;
        let total_plaintext_len = full_before * chunk_size as u64 + last_chunk_plaintext_len as u64;

        Ok(Self {
            reader,
            cipher: state.cipher,
            base_nonce,
            key_commitment: state.key_commitment,
            chunk_size,
            header_len,
            num_chunks,
            last_chunk_plaintext_len,
            total_plaintext_len,
            header_original_size: state.original_size,
            position: 0,
            buffered_chunk_index: None,
            buffered_chunk: Zeroizing::new(Vec::new()),
        })
    }

    /// Total number of chunks in the file.
    #[must_use]
    pub fn num_chunks(&self) -> u32 {
        self.num_chunks
    }

    /// Plaintext chunk size: every chunk except possibly the last is exactly
    /// this many bytes.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Total plaintext length in bytes, computed from the physical file
    /// size. See the module docs for why this can exceed
    /// [`header_original_size`](Self::header_original_size) for a padded file.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.total_plaintext_len
    }

    /// `true` if the file decrypts to zero plaintext bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_plaintext_len == 0
    }

    /// The header's `original_size` field: the true plaintext length at
    /// encryption time. Equal to [`len`](Self::len) unless the file was
    /// written with `encrypt --pad`, in which case it is smaller; this type
    /// does not strip padding automatically (see the module docs).
    #[must_use]
    pub fn header_original_size(&self) -> u64 {
        self.header_original_size
    }

    /// Decrypts and returns chunk `index` (0-based), authenticating only
    /// that chunk's own AEAD tag - see the module docs for what that means
    /// for tamper detection compared to the sequential decrypt functions.
    pub fn read_chunk(&mut self, index: u32) -> Result<Zeroizing<Vec<u8>>, PqfileError> {
        if index >= self.num_chunks {
            return Err(PqfileError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "chunk index out of range",
            )));
        }
        let is_last = index == self.num_chunks - 1;
        let cs16 = self.chunk_size + 16;
        let offset = self.header_len + u64::from(index) * cs16 as u64;
        let ct_len = if is_last {
            self.last_chunk_plaintext_len + 16
        } else {
            cs16
        };

        self.reader
            .seek(SeekFrom::Start(offset))
            .map_err(PqfileError::Io)?;
        let mut buf = vec![0u8; ct_len];
        self.reader.read_exact(&mut buf).map_err(PqfileError::Io)?;

        let pt_len = ct_len - 16;
        let tag: Tag<ChaCha20Poly1305> = buf[pt_len..ct_len].try_into().expect("16-byte tag");
        let cn = chunk_nonce(&self.base_nonce, index);
        let (aad_buf, aad_len) = make_chunk_aad(index, is_last, &self.key_commitment);

        self.cipher
            .decrypt_inout_detached(
                cn.as_slice().try_into().expect("12-byte nonce"),
                &aad_buf[..aad_len],
                (&mut buf[..pt_len]).into(),
                &tag,
            )
            .map_err(|_| PqfileError::DecryptionFailure)?;
        buf.truncate(pt_len);
        Ok(Zeroizing::new(buf))
    }
}

impl<R: Read + Seek> Read for SeekableDecryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.total_plaintext_len {
            return Ok(0);
        }
        let chunk_index = (self.position / self.chunk_size as u64) as u32;
        let offset_in_chunk = (self.position % self.chunk_size as u64) as usize;

        if self.buffered_chunk_index != Some(chunk_index) {
            self.buffered_chunk = self.read_chunk(chunk_index).map_err(chunk_error_to_io)?;
            self.buffered_chunk_index = Some(chunk_index);
        }

        let available = &self.buffered_chunk[offset_in_chunk..];
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for SeekableDecryptor<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos: i128 = match pos {
            SeekFrom::Start(p) => p as i128,
            SeekFrom::End(p) => self.total_plaintext_len as i128 + p as i128,
            SeekFrom::Current(p) => self.position as i128 + p as i128,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to a negative position",
            ));
        }
        self.position = new_pos as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{encrypt_stream, encrypt_stream_multi};
    use crate::format::CHUNK_SIZE;
    use crate::keygen::keygen_bytes;
    use std::io::Cursor;

    fn encrypt_to_vec(pub_pem: &str, chunk_size: usize, plaintext: &[u8]) -> Vec<u8> {
        let mut enc = Vec::new();
        encrypt_stream(
            pub_pem,
            plaintext.len() as u64,
            chunk_size,
            &mut &plaintext[..],
            &mut enc,
        )
        .unwrap();
        enc
    }

    #[test]
    fn open_rejects_multi_recipient_v4() {
        let (pub1, _) = keygen_bytes(768, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let plaintext = b"multi recipient, not seekable";
        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str(), pub2.as_str()],
            plaintext.len() as u64,
            &mut &plaintext[..],
            &mut enc,
        )
        .unwrap();

        match SeekableDecryptor::open(Cursor::new(enc), &priv2, None) {
            Ok(_) => panic!("expected UnsupportedVersion, got Ok"),
            Err(e) => assert!(matches!(e, PqfileError::UnsupportedVersion(_)), "got {e:?}"),
        }
    }

    #[test]
    fn single_chunk_roundtrip() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"small payload fits in one chunk";
        let enc = encrypt_to_vec(&pub_pem, CHUNK_SIZE, plaintext);

        let mut d = SeekableDecryptor::open(Cursor::new(enc), &priv_pem, None).unwrap();
        assert_eq!(d.num_chunks(), 1);
        assert_eq!(d.len(), plaintext.len() as u64);
        assert_eq!(d.header_original_size(), plaintext.len() as u64);

        let mut out = Vec::new();
        d.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn empty_file_is_one_empty_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let enc = encrypt_to_vec(&pub_pem, CHUNK_SIZE, b"");

        let mut d = SeekableDecryptor::open(Cursor::new(enc), &priv_pem, None).unwrap();
        assert_eq!(d.num_chunks(), 1);
        assert!(d.is_empty());
        assert_eq!(d.read_chunk(0).unwrap().as_slice(), b"");
    }

    #[test]
    fn read_chunk_out_of_order_matches_sequential_decrypt() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let chunk_size = 1024;
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(chunk_size * 5 + 37).collect();
        let enc = encrypt_to_vec(&pub_pem, chunk_size, &plaintext);

        let mut d = SeekableDecryptor::open(Cursor::new(enc), &priv_pem, None).unwrap();
        assert_eq!(d.num_chunks(), 6); // 5 full + 1 partial (37 bytes)
        assert_eq!(d.len(), plaintext.len() as u64);

        // Request chunks out of order, including re-requesting one already seen.
        for &i in &[3u32, 0, 5, 1, 3, 4, 2] {
            let expected_start = i as usize * chunk_size;
            let expected_end = (expected_start + chunk_size).min(plaintext.len());
            assert_eq!(
                d.read_chunk(i).unwrap().as_slice(),
                &plaintext[expected_start..expected_end],
                "chunk {i} mismatch"
            );
        }
    }

    #[test]
    fn read_chunk_rejects_index_past_end() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let enc = encrypt_to_vec(&pub_pem, 1024, b"tiny");
        let mut d = SeekableDecryptor::open(Cursor::new(enc), &priv_pem, None).unwrap();
        assert_eq!(d.num_chunks(), 1);
        assert!(d.read_chunk(1).is_err());
    }

    #[test]
    fn read_chunk_detects_tampering() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let chunk_size = 512;
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(chunk_size * 2 + 10).collect();
        let mut enc = encrypt_to_vec(&pub_pem, chunk_size, &plaintext);
        // Flip a byte inside chunk 1's ciphertext.
        let flip_at = enc.len() - 1 - (chunk_size + 16); // well inside chunk 1's tag/ciphertext region
        enc[flip_at] ^= 0x01;

        let mut d = SeekableDecryptor::open(Cursor::new(enc), &priv_pem, None).unwrap();
        assert!(d.read_chunk(1).is_err());
        // Untouched chunk 0 still decrypts fine: only the requested chunk's
        // tag is authenticated, not the file as a whole (see module docs).
        assert!(d.read_chunk(0).is_ok());
    }

    #[test]
    fn seek_and_read_arbitrary_byte_ranges() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let chunk_size = 256;
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(chunk_size * 4 + 13).collect();
        let enc = encrypt_to_vec(&pub_pem, chunk_size, &plaintext);
        let mut d = SeekableDecryptor::open(Cursor::new(enc), &priv_pem, None).unwrap();

        // Seek into the middle of chunk 2 and read across into chunk 3.
        let start = chunk_size * 2 + 100;
        d.seek(SeekFrom::Start(start as u64)).unwrap();
        let mut buf = vec![0u8; 300];
        d.read_exact(&mut buf).unwrap();
        assert_eq!(buf, plaintext[start..start + 300]);

        // SeekFrom::End.
        d.seek(SeekFrom::End(-5)).unwrap();
        let mut tail = Vec::new();
        d.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, plaintext[plaintext.len() - 5..]);

        // SeekFrom::Current.
        d.seek(SeekFrom::Start(0)).unwrap();
        d.seek(SeekFrom::Current(10)).unwrap();
        let mut b = [0u8; 1];
        d.read_exact(&mut b).unwrap();
        assert_eq!(b[0], plaintext[10]);
    }
}
