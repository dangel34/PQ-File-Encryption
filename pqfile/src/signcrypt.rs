use std::io::{self, Cursor, Read, Write};

use sha3::{Digest, Sha3_256};

use crate::encrypt;
use crate::error::PqfileError;
use crate::format::CHUNK_SIZE;
use crate::reader::PqfReader;
use crate::sign;

// ML-DSA-65 signature length is always exactly 3309 bytes.
const SIG_LEN: usize = 3309;

/// Payload layout inside the encrypted file:
///   [signature: SIG_LEN bytes][plaintext: remaining bytes]
///
/// The signature covers SHA3-256(plaintext), not the raw plaintext, to allow
/// streaming without buffering the entire plaintext before signing.
///
/// Sign `plaintext_reader` with `sk_pem`, then encrypt the combined payload
/// (signature ++ plaintext) to `pubkey_pem`.  Two-pass: first hashes the input
/// to sign it, then reads it again to prepend the signature and encrypt.
///
/// Because the signature is prepended inside the AEAD-authenticated ciphertext
/// it cannot be stripped after the fact.
pub fn signcrypt<R: Read + io::Seek>(
    sk_pem: &str,
    sign_passphrase: Option<&str>,
    pubkey_pem: &str,
    input: &mut R,
    input_len: u64,
    writer: &mut dyn Write,
    chunk_size: usize,
) -> Result<(), PqfileError> {
    // Pass 1: hash the plaintext
    let hash = hash_stream(input)?;

    // Sign the 32-byte hash
    let sig_bytes = sign::sign_bytes(sk_pem, sign_passphrase, &hash)?;
    debug_assert_eq!(sig_bytes.len(), SIG_LEN);

    // Rewind for pass 2
    input.seek(io::SeekFrom::Start(0)).map_err(PqfileError::Io)?;

    // Build a combined reader: [sig || plaintext]
    let sig_cursor = Cursor::new(sig_bytes);
    let mut combined = sig_cursor.chain(input);

    let combined_size = SIG_LEN as u64 + input_len;
    encrypt::encrypt_stream(pubkey_pem, combined_size, chunk_size, &mut combined, writer)
}

/// Decrypt a signcrypted file, verify the sender's signature, and write plaintext.
///
/// # Streaming write-before-verify hazard
///
/// Plaintext is written to `writer` **while streaming**, before the ML-DSA sender
/// signature is checked.  Each chunk is AEAD-authenticated (integrity guaranteed),
/// but sender identity is only confirmed when this function returns `Ok(())`.
///
/// **To avoid acting on data from an unverified sender, pass a `Vec<u8>` as
/// `writer` and only use the output after the function returns `Ok(())`.**
/// Do NOT pass a `File`, a socket, or any writer whose output you cannot retract,
/// unless you are prepared to discard everything written on a subsequent error.
pub fn signdecrypt<R: Read>(
    privkey_pem: &str,
    vk_pem: &str,
    reader: R,
    writer: &mut dyn Write,
    passphrase: Option<&str>,
) -> Result<(), PqfileError> {
    let mut pqf = PqfReader::new(reader, privkey_pem, passphrase)?;

    // Read the prepended signature
    let mut sig_buf = vec![0u8; SIG_LEN];
    pqf.read_exact(&mut sig_buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            PqfileError::InvalidSignature
        } else {
            PqfileError::Io(e)
        }
    })?;

    // Stream plaintext to output while hashing
    let mut hasher = Sha3_256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = pqf.read(&mut buf).map_err(PqfileError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n]).map_err(PqfileError::Io)?;
    }
    let hash = hasher.finalize();

    // Verify sender identity
    sign::verify_bytes(vk_pem, &hash, &sig_buf)
}

fn hash_stream<R: Read>(reader: &mut R) -> Result<Vec<u8>, PqfileError> {
    let mut hasher = Sha3_256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buf).map_err(PqfileError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use crate::sign::sign_keygen_bytes;
    use std::io::Cursor;

    fn do_signcrypt(plaintext: &[u8]) -> (Vec<u8>, String, String, String) {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let sk_result = sign_keygen_bytes(None).unwrap();
        let mut input = Cursor::new(plaintext);
        let mut output = Vec::new();
        signcrypt(&sk_result.sk_pem, None, &pub_pem, &mut input, plaintext.len() as u64, &mut output, CHUNK_SIZE).unwrap();
        (output, priv_pem, sk_result.vk_pem, pub_pem)
    }

    #[test]
    fn signcrypt_roundtrip_small() {
        let plaintext = b"hello signcrypt world";
        let (ciphertext, priv_pem, vk_pem, _) = do_signcrypt(plaintext);
        let mut output = Vec::new();
        signdecrypt(&priv_pem, &vk_pem, ciphertext.as_slice(), &mut output, None).unwrap();
        assert_eq!(output, plaintext);
    }

    #[test]
    fn signcrypt_roundtrip_large() {
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 3 + 7).collect();
        let (ciphertext, priv_pem, vk_pem, _) = do_signcrypt(&plaintext);
        let mut output = Vec::new();
        signdecrypt(&priv_pem, &vk_pem, ciphertext.as_slice(), &mut output, None).unwrap();
        assert_eq!(output, plaintext);
    }

    #[test]
    fn signcrypt_wrong_verifying_key_fails() {
        let plaintext = b"test payload";
        let (ciphertext, priv_pem, _, _) = do_signcrypt(plaintext);
        let other_sk = sign_keygen_bytes(None).unwrap();
        let mut output = Vec::new();
        let result = signdecrypt(&priv_pem, &other_sk.vk_pem, ciphertext.as_slice(), &mut output, None);
        assert!(matches!(result, Err(PqfileError::SignatureVerificationFailed)));
    }

    #[test]
    fn signdecrypt_wrong_decryption_key_fails() {
        let plaintext = b"test payload";
        let (ciphertext, _, vk_pem, _) = do_signcrypt(plaintext);
        let (_, wrong_priv) = keygen_bytes(768, None).unwrap();
        let mut output = Vec::new();
        let result = signdecrypt(&wrong_priv, &vk_pem, ciphertext.as_slice(), &mut output, None);
        assert!(result.is_err());
    }

    #[test]
    fn signcrypt_empty_plaintext() {
        let plaintext = b"";
        let (ciphertext, priv_pem, vk_pem, _) = do_signcrypt(plaintext);
        let mut output = Vec::new();
        signdecrypt(&priv_pem, &vk_pem, ciphertext.as_slice(), &mut output, None).unwrap();
        assert_eq!(output, plaintext);
    }
}
