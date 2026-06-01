/// Async encrypt and decrypt streaming using `tokio::io`.
///
/// Requires the `async` feature flag: `pqfile = { features = ["async"] }`.
///
/// These functions are the async equivalents of [`crate::encrypt::encrypt_stream`]
/// and [`crate::decrypt::decrypt_stream`]. They accept any `tokio::io::AsyncRead +
/// AsyncWrite + Unpin` source and sink, enabling non-blocking encryption in async
/// servers and proxies without spawning a dedicated OS thread per operation.
///
/// The format and ciphertext are identical to the synchronous API — files
/// produced by `encrypt_stream_async` are indistinguishable from those produced
/// by `encrypt_stream` and can be decrypted by either.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::decrypt;
use crate::encrypt;
use crate::error::PqfileError;
use crate::format::CHUNK_SIZE;

/// Async equivalent of [`encrypt::encrypt_stream`] (v3 / v5 format).
///
/// Reads plaintext from `reader`, encrypts it in `chunk_size`-byte chunks, and
/// writes the authenticated ciphertext to `writer`. Emits v3 format when
/// `chunk_size == CHUNK_SIZE` (65536), v5 otherwise.
///
/// # Example
///
/// ```no_run
/// use pqfile::async_io::encrypt_stream_async;
/// use pqfile::format::CHUNK_SIZE;
///
/// # async fn example() {
/// let pub_pem = std::fs::read_to_string("pubkey.pem").unwrap();
/// let mut plaintext: &[u8] = b"hello, post-quantum async world";
/// let mut ciphertext = Vec::new();
/// encrypt_stream_async(&pub_pem, plaintext.len() as u64, CHUNK_SIZE, &mut plaintext, &mut ciphertext)
///     .await
///     .unwrap();
/// # }
/// ```
#[must_use = "encryption result must be checked"]
pub async fn encrypt_stream_async<R, W>(
    pubkey_pem: &str,
    original_size: u64,
    chunk_size: usize,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), PqfileError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if chunk_size == 0 {
        return Err(PqfileError::EncryptionFailure);
    }

    // Buffer the full plaintext asynchronously, then delegate to the sync encrypt
    // path. This keeps the cryptographic core as a single well-tested code path while
    // providing a non-blocking interface for I/O.
    //
    // Future work: a zero-copy streaming implementation would avoid this
    // intermediate buffer for large files.
    let mut plaintext = Vec::with_capacity(original_size.min(64 * 1024 * 1024) as usize);
    reader
        .read_to_end(&mut plaintext)
        .await
        .map_err(PqfileError::Io)?;

    let mut ct = Vec::new();
    encrypt::encrypt_stream(
        pubkey_pem,
        plaintext.len() as u64,
        chunk_size,
        &mut plaintext.as_slice(),
        &mut ct,
    )?;

    writer.write_all(&ct).await.map_err(PqfileError::Io)?;
    writer.flush().await.map_err(PqfileError::Io)?;
    Ok(())
}

/// Async equivalent of [`decrypt::decrypt_stream`].
///
/// Reads a `.pqf` stream from `reader`, authenticates and decrypts it, and
/// writes the plaintext to `writer`. Supports all format versions (v2–v8).
///
/// # Example
///
/// ```no_run
/// use pqfile::async_io::decrypt_stream_async;
///
/// # async fn example() {
/// let priv_pem = std::fs::read_to_string("privkey.pem").unwrap();
/// let ciphertext: &[u8] = &[];
/// let mut plaintext = Vec::new();
/// decrypt_stream_async(&priv_pem, ciphertext, &mut plaintext, None)
///     .await
///     .unwrap();
/// # }
/// ```
#[must_use = "decryption result must be checked"]
pub async fn decrypt_stream_async<R, W>(
    privkey_pem: &str,
    reader: R,
    writer: &mut W,
    passphrase: Option<&str>,
) -> Result<(), PqfileError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Buffer the full ciphertext asynchronously, then delegate to sync decrypt.
    let mut ct_reader = tokio::io::BufReader::new(reader);
    let mut ct = Vec::new();
    ct_reader
        .read_to_end(&mut ct)
        .await
        .map_err(PqfileError::Io)?;

    let mut plaintext = Zeroizing::new(Vec::new());
    decrypt::decrypt_stream(privkey_pem, &mut ct.as_slice(), &mut *plaintext, passphrase)?;

    writer
        .write_all(&plaintext)
        .await
        .map_err(PqfileError::Io)?;
    writer.flush().await.map_err(PqfileError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;

    #[tokio::test]
    async fn async_roundtrip_small() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"hello async pqfile world";

        let mut ct = Vec::new();
        encrypt_stream_async(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .await
        .unwrap();

        let mut out = Vec::new();
        decrypt_stream_async(&priv_pem, ct.as_slice(), &mut out, None)
            .await
            .unwrap();
        assert_eq!(out, plaintext);
    }

    #[tokio::test]
    async fn async_roundtrip_multi_chunk() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 3 + 7).collect();

        let mut ct = Vec::new();
        encrypt_stream_async(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .await
        .unwrap();

        let mut out = Vec::new();
        decrypt_stream_async(&priv_pem, ct.as_slice(), &mut out, None)
            .await
            .unwrap();
        assert_eq!(out, plaintext);
    }

    #[tokio::test]
    async fn async_roundtrip_empty() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream_async(&pub_pem, 0, CHUNK_SIZE, &mut [].as_slice(), &mut ct)
            .await
            .unwrap();
        let mut out = Vec::new();
        decrypt_stream_async(&priv_pem, ct.as_slice(), &mut out, None)
            .await
            .unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn async_roundtrip_with_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("async-pass")).unwrap();
        let plaintext = b"passphrase-protected async roundtrip";
        let mut ct = Vec::new();
        encrypt_stream_async(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        decrypt_stream_async(&priv_pem, ct.as_slice(), &mut out, Some("async-pass"))
            .await
            .unwrap();
        assert_eq!(out, plaintext.as_slice());
    }

    #[tokio::test]
    async fn async_ciphertext_matches_sync() {
        // Files encrypted with encrypt_stream_async must be decryptable by the
        // synchronous decrypt_stream, and vice-versa.
        use crate::decrypt::decrypt_stream as sync_decrypt;
        use crate::encrypt::encrypt_stream as sync_encrypt;

        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext = b"async / sync interop check";

        // Encrypt async, decrypt sync.
        let mut ct = Vec::new();
        encrypt_stream_async(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        sync_decrypt(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);

        // Encrypt sync, decrypt async.
        let mut ct2 = Vec::new();
        sync_encrypt(
            &pub_pem,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct2,
        )
        .unwrap();
        let mut out2 = Vec::new();
        decrypt_stream_async(&priv_pem, ct2.as_slice(), &mut out2, None)
            .await
            .unwrap();
        assert_eq!(out2, plaintext);
    }

    #[tokio::test]
    async fn async_rejects_zero_chunk_size() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let result =
            encrypt_stream_async(&pub_pem, 0, 0, &mut [].as_slice(), &mut Vec::new()).await;
        assert!(result.is_err());
    }
}
