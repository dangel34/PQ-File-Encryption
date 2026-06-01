/// Streaming decryptor: `PqfReader<R>` wraps any `R: Read` and decrypts on the fly.
///
/// Supports v2 (whole-file), v3/v5 (chunked), and v4 (multi-recipient) formats.
/// Compressed v6 files are not supported (use [`decrypt::decrypt_stream`] instead).
use std::io::{self, Read};

use chacha20poly1305::{
    aead::{AeadInPlace, Tag},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroizing;

use crate::decrypt::decapsulate_stream_init;
use crate::error::PqfileError;
use crate::format::{chunk_aad, chunk_nonce, fill_chunk, BASE_NONCE_LEN};

/// Metadata read from the `.pqf` header.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct PqfInfo {
    /// Format version byte.
    pub version: u8,
    /// KEM variant identifier.
    pub kem_variant: u16,
    /// Uncompressed plaintext size in bytes (informational).
    pub original_size: u64,
    /// Chunk size used for STREAM decryption.
    pub chunk_size: usize,
}

enum ReaderState<R: Read> {
    Streaming {
        inner: R,
        cipher: ChaCha20Poly1305,
        base_nonce: [u8; BASE_NONCE_LEN],
        chunk_size: usize,
        counter: u32,
        current_ct: Vec<u8>,
        current_ct_len: usize,
        next_ct: Vec<u8>,
        next_ct_len: usize,
        plaintext: Vec<u8>,
        plaintext_pos: usize,
        done: bool,
    },
    WholeFile {
        data: Zeroizing<Vec<u8>>,
        pos: usize,
    },
}

/// Streaming decryptor wrapping any `R: Read`.
pub struct PqfReader<R: Read> {
    info: PqfInfo,
    state: ReaderState<R>,
}

impl<R: Read> PqfReader<R> {
    /// Opens a `.pqf` stream, reads and authenticates the header, and prepares
    /// for streaming decryption.
    pub fn new(
        mut reader: R,
        privkey_pem: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, PqfileError> {
        let (version, kem_variant, original_size, chunk_size, cipher, nonce_bytes, plaintext_v2) =
            decapsulate_stream_init(&mut reader, privkey_pem, passphrase)?;

        let info = PqfInfo {
            version,
            kem_variant,
            original_size,
            chunk_size,
        };

        let state = if let Some(data) = plaintext_v2 {
            ReaderState::WholeFile { data, pos: 0 }
        } else {
            let max_ct = chunk_size + 16;
            let mut current_ct = vec![0u8; max_ct];
            let current_ct_len = fill_chunk(&mut reader, &mut current_ct)?;

            if current_ct_len == 0 {
                return Err(PqfileError::DecryptionFailure);
            }

            let mut next_ct = vec![0u8; max_ct];
            let next_ct_len = fill_chunk(&mut reader, &mut next_ct)?;

            let base_nonce: [u8; BASE_NONCE_LEN] =
                nonce_bytes[..BASE_NONCE_LEN].try_into().unwrap();

            ReaderState::Streaming {
                inner: reader,
                cipher,
                base_nonce,
                chunk_size,
                counter: 0,
                current_ct,
                current_ct_len,
                next_ct,
                next_ct_len,
                plaintext: Vec::new(),
                plaintext_pos: 0,
                done: false,
            }
        };

        Ok(PqfReader { info, state })
    }

    /// Returns the header metadata for this file.
    pub fn info(&self) -> &PqfInfo {
        &self.info
    }
}

impl<R: Read> Read for PqfReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        match &mut self.state {
            ReaderState::WholeFile { data, pos } => {
                let remaining = data.len() - *pos;
                if remaining == 0 {
                    return Ok(0);
                }
                let n = remaining.min(buf.len());
                buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                *pos += n;
                Ok(n)
            }

            ReaderState::Streaming {
                inner,
                cipher,
                base_nonce,
                chunk_size,
                counter,
                current_ct,
                current_ct_len,
                next_ct,
                next_ct_len,
                plaintext,
                plaintext_pos,
                done,
            } => {
                // Drain buffered plaintext first.
                if *plaintext_pos < plaintext.len() {
                    let available = plaintext.len() - *plaintext_pos;
                    let n = available.min(buf.len());
                    buf[..n].copy_from_slice(&plaintext[*plaintext_pos..*plaintext_pos + n]);
                    *plaintext_pos += n;
                    return Ok(n);
                }

                if *done {
                    return Ok(0);
                }

                // Decrypt current chunk.
                let is_last = *next_ct_len == 0;
                let cn = chunk_nonce(base_nonce, *counter);
                let aad = chunk_aad(*counter, is_last);

                if *current_ct_len < 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "chunk too short",
                    ));
                }
                let ct_len = *current_ct_len - 16;
                let tag =
                    Tag::<ChaCha20Poly1305>::clone_from_slice(&current_ct[ct_len..*current_ct_len]);
                cipher
                    .decrypt_in_place_detached(
                        Nonce::from_slice(&cn),
                        &aad,
                        &mut current_ct[..ct_len],
                        &tag,
                    )
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "authentication failed")
                    })?;

                plaintext.clear();
                plaintext.extend_from_slice(&current_ct[..ct_len]);
                *plaintext_pos = 0;

                if is_last {
                    *done = true;
                } else {
                    *counter = counter.checked_add(1).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "chunk counter overflow")
                    })?;

                    std::mem::swap(current_ct, next_ct);
                    *current_ct_len = *next_ct_len;

                    let max_ct = *chunk_size + 16;
                    next_ct.resize(max_ct, 0);
                    *next_ct_len = fill_chunk(inner, &mut next_ct[..max_ct])
                        .map_err(|e| io::Error::other(e.to_string()))?;
                }

                let n = plaintext.len().min(buf.len());
                buf[..n].copy_from_slice(&plaintext[..n]);
                *plaintext_pos = n;
                Ok(n)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{encrypt_bytes, encrypt_stream, encrypt_stream_multi};
    use crate::format::CHUNK_SIZE;
    use crate::keygen::keygen_bytes;
    use std::io::Read;

    #[test]
    fn reader_v3_small_payload() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"hello pqf reader";
        let mut enc = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut r = PqfReader::new(enc.as_slice(), &priv_pem, None).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn reader_v3_multi_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 2 + 17).collect();
        let mut enc = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut r = PqfReader::new(enc.as_slice(), &priv_pem, None).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn reader_v2_whole_file() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"v2 whole-file reader test";
        let enc = encrypt_bytes(&pub_pem, plaintext).unwrap();

        let mut r = PqfReader::new(enc.as_slice(), &priv_pem, None).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn reader_v4_multi_recipient() {
        let (pub1, priv1) = keygen_bytes(768, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let plaintext = b"multi-recipient reader test";
        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str(), pub2.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        for priv_pem in [&priv1, &priv2] {
            let mut r = PqfReader::new(enc.as_slice(), priv_pem, None).unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            assert_eq!(out, plaintext);
        }
    }

    #[test]
    fn reader_exposes_header_info() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"info check";
        let mut enc = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let r = PqfReader::new(enc.as_slice(), &priv_pem, None).unwrap();
        assert_eq!(r.info().original_size, plaintext.len() as u64);
        assert_eq!(r.info().chunk_size, CHUNK_SIZE);
    }

    #[test]
    fn reader_incremental_reads() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let mut enc = Vec::new();
        encrypt_stream(
            &pub_pem,
            plaintext.len() as u64,
            256,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut r = PqfReader::new(enc.as_slice(), &priv_pem, None).unwrap();
        let mut out = Vec::new();
        let mut tmp = [0u8; 64];
        loop {
            let n = r.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(out, plaintext);
    }
}
