/// Streaming encryptor: `PqfWriter<W>` wraps any `W: Write` and encrypts on the fly.
///
/// Buffers plaintext into `chunk_size`-byte chunks and writes authenticated
/// ciphertext downstream as each chunk fills. Call [`PqfWriter::finish`] when all
/// plaintext has been written; that seals the final (possibly partial) chunk and
/// returns the inner writer.
///
/// # Example
///
/// ```no_run
/// use pqfile::writer::PqfWriter;
/// use pqfile::{keygen, format::CHUNK_SIZE};
///
/// let (pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();
/// let plaintext = b"streaming plaintext data";
///
/// let sink: Vec<u8> = Vec::new();
/// let mut w = PqfWriter::new(sink, &pub_pem, plaintext.len() as u64, CHUNK_SIZE).unwrap();
/// std::io::Write::write_all(&mut w, plaintext).unwrap();
/// let ciphertext = w.finish().unwrap();
/// ```
use std::io::{self, Write};

use chacha20poly1305::{aead::AeadInOut, ChaCha20Poly1305};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{chunk_nonce, BASE_NONCE_LEN};

/// Streaming encryptor wrapping any `W: Write`.
///
/// Write plaintext via [`Write::write`]; call [`PqfWriter::finish`] when done to
/// seal the final chunk and retrieve the inner writer.
pub struct PqfWriter<W: Write> {
    inner: Option<W>,
    cipher: ChaCha20Poly1305,
    base_nonce: [u8; BASE_NONCE_LEN],
    key_commitment: [u8; 32],
    chunk_size: usize,
    counter: u32,
    buf: Zeroizing<Vec<u8>>,
    finished: bool,
}

impl<W: Write> PqfWriter<W> {
    /// Creates a new `PqfWriter`, writes the `.pqf` header to `sink`, and returns
    /// the encryptor ready to accept plaintext.
    ///
    /// `original_size` is stored in the header as an informational field (not used for
    /// allocation or decryption bounds). `chunk_size` must be in the range
    /// `1..=256 MiB`; pass [`CHUNK_SIZE`](crate::format::CHUNK_SIZE) for the
    /// standard 64 KiB default.
    pub fn new(
        mut sink: W,
        pubkey_pem: &str,
        original_size: u64,
        chunk_size: usize,
    ) -> Result<Self, PqfileError> {
        let stream = crate::encrypt::begin_single_recipient_stream(
            pubkey_pem,
            original_size,
            chunk_size,
            &mut sink,
        )?;

        Ok(Self {
            inner: Some(sink),
            cipher: stream.cipher(),
            base_nonce: stream.base_nonce,
            key_commitment: stream.key_commitment,
            chunk_size,
            counter: 0,
            buf: Zeroizing::new(Vec::with_capacity(chunk_size)),
            finished: false,
        })
    }

    /// Seals the final partial chunk, flushes the underlying writer, and returns it.
    ///
    /// Must be called exactly once when all plaintext has been written. Dropping a
    /// `PqfWriter` without calling `finish` attempts a best-effort seal but silently
    /// discards any I/O error; prefer `finish` when error handling matters.
    #[must_use = "the sealed inner writer must be used or the output file will not be finalized"]
    pub fn finish(mut self) -> Result<W, PqfileError> {
        self.seal_final().map_err(PqfileError::Io)?;
        Ok(self.inner.take().unwrap())
    }

    /// Encrypts the current buffer as a chunk with the given `is_last` flag.
    fn encrypt_chunk(&mut self, is_last: bool) -> io::Result<()> {
        let cn = chunk_nonce(&self.base_nonce, self.counter);
        let (aad_buf, aad_len) =
            crate::format::make_chunk_aad(self.counter, is_last, &self.key_commitment);
        let tag = self
            .cipher
            .encrypt_inout_detached(
                cn.as_slice().try_into().expect("12-byte nonce"),
                &aad_buf[..aad_len],
                self.buf.as_mut_slice().into(),
            )
            .map_err(|_| io::Error::other("encryption failure"))?;
        let inner = self.inner.as_mut().unwrap();
        inner.write_all(&self.buf)?;
        inner.write_all(tag.as_ref())?;
        self.buf.clear();
        if !is_last {
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| io::Error::other("chunk counter overflow"))?;
        }
        Ok(())
    }

    /// Seals the final partial chunk (which may be empty).
    fn seal_final(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.encrypt_chunk(true)?;
        if let Some(inner) = self.inner.as_mut() {
            inner.flush()?;
        }
        self.finished = true;
        Ok(())
    }
}

impl<W: Write> Write for PqfWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "PqfWriter already finished",
            ));
        }
        let space = self.chunk_size - self.buf.len();
        let take = data.len().min(space);
        self.buf.extend_from_slice(&data[..take]);
        if self.buf.len() == self.chunk_size {
            self.encrypt_chunk(false)?;
        }
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(inner) = self.inner.as_mut() {
            inner.flush()
        } else {
            Ok(())
        }
    }
}

impl<W: Write> Drop for PqfWriter<W> {
    fn drop(&mut self) {
        if self.inner.is_some() && !self.finished {
            // In debug builds, panic loudly so callers notice they forgot finish().
            // Guard with !panicking() so a Drop that fires during stack-unwinding
            // from another panic does not cause a double-panic and process abort.
            #[cfg(debug_assertions)]
            if !std::thread::panicking() {
                panic!(
                    "PqfWriter dropped without calling finish(); \
                     I/O errors from the final chunk seal are lost and the output may be corrupt. \
                     Call finish() to handle errors explicitly."
                );
            }
            // In release builds (or when already unwinding), attempt a best-effort
            // seal and discard any error.
            #[cfg(not(debug_assertions))]
            let _ = self.seal_final();
            #[cfg(debug_assertions)]
            let _ = self.seal_final();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::decrypt_stream;
    use crate::format::{CHUNK_SIZE, VERSION_AUTH_BIT, VERSION_V5};
    use crate::keygen::keygen_bytes;
    use std::io::Write;

    fn roundtrip(plaintext: &[u8], chunk_size: usize) {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let sink: Vec<u8> = Vec::new();
        let mut w = PqfWriter::new(sink, &pub_pem, plaintext.len() as u64, chunk_size).unwrap();
        w.write_all(plaintext).unwrap();
        let ct = w.finish().unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn writer_roundtrip_empty() {
        roundtrip(b"", CHUNK_SIZE);
    }

    #[test]
    fn writer_roundtrip_small() {
        roundtrip(b"hello pqfwriter", CHUNK_SIZE);
    }

    #[test]
    fn writer_roundtrip_exact_chunk_boundary() {
        roundtrip(&vec![0xABu8; CHUNK_SIZE], CHUNK_SIZE);
    }

    #[test]
    fn writer_roundtrip_multi_chunk() {
        roundtrip(&vec![0u8; CHUNK_SIZE * 3 + 100], CHUNK_SIZE);
    }

    #[test]
    fn writer_roundtrip_custom_chunk_size() {
        roundtrip(&vec![0u8; 512 * 5 + 7], 512);
    }

    #[test]
    fn writer_interop_with_reader() {
        use crate::reader::PqfReader;
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE + 42).collect();

        let sink: Vec<u8> = Vec::new();
        let mut w = PqfWriter::new(sink, &pub_pem, plaintext.len() as u64, CHUNK_SIZE).unwrap();
        w.write_all(&plaintext).unwrap();
        let ct = w.finish().unwrap();

        let mut r = PqfReader::new(ct.as_slice(), &priv_pem, None).unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn writer_incremental_writes() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(1000).collect();

        let mut ct = Vec::new();
        let mut w = PqfWriter::new(&mut ct, &pub_pem, plaintext.len() as u64, 256).unwrap();
        for chunk in plaintext.chunks(37) {
            w.write_all(chunk).unwrap();
        }
        w.finish().unwrap();

        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn writer_emits_v5_for_custom_chunk_size() {
        use crate::format::MAGIC;
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        let w = PqfWriter::new(&mut ct, &pub_pem, 0u64, 1024).unwrap();
        w.finish().unwrap();
        assert_eq!(&ct[..4], MAGIC);
        assert_eq!(ct[4], VERSION_V5 | VERSION_AUTH_BIT);
    }

    #[test]
    fn writer_rejects_zero_chunk_size() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let result = PqfWriter::new(Vec::<u8>::new(), &pub_pem, 0, 0);
        assert!(matches!(result, Err(PqfileError::EncryptionFailure)));
    }
}
