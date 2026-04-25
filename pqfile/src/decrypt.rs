use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use aead::{stream::DecryptorBE32, Payload};
use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305, Key};
use ml_kem::{
    kem::{DecapsulationKey, Decapsulate},
    Ciphertext, Encoded, EncodedSizeUser, MlKem768, MlKem768Params,
};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{CHUNK_SIZE, HEADER_SIZE, KEM_CT_LEN, PqfHeader};

/// Decrypt `input_path` to `output_path` using streaming AEAD with an atomic write.
/// On failure the incomplete output is removed; the input is never modified.
pub fn decrypt_file(priv_pem: &str, input_path: &Path, output_path: &Path) -> Result<(), PqfileError> {
    let tmp_path = {
        let mut s = output_path.as_os_str().to_owned();
        s.push(".tmp");
        std::path::PathBuf::from(s)
    };

    let mut reader = BufReader::new(fs::File::open(input_path)?);
    let outcome = {
        let mut writer = BufWriter::new(fs::File::create(&tmp_path)?);
        let r = decrypt_stream(priv_pem, &mut reader, &mut writer, |_, _| {});
        if r.is_ok()
            && let Err(e) = writer.flush()
        {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }
        r
    };

    match outcome {
        Ok(()) => Ok(fs::rename(&tmp_path, output_path)?),
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Core streaming decrypt. Reads a `.pqf` stream from `reader` and writes
/// plaintext to `writer`. `on_progress(bytes_written, original_size)` is
/// called after each chunk.
pub fn decrypt_stream<R: Read, W: Write>(
    priv_pem: &str,
    reader: &mut R,
    writer: &mut W,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<(), PqfileError> {
    let pem = pem::parse(priv_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    type DkType = DecapsulationKey<MlKem768Params>;
    let raw = pem.contents();
    let priv_bytes = Zeroizing::new(raw.to_vec());
    let encoded = Encoded::<DkType>::try_from(priv_bytes.as_slice())
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 2400, got: raw.len() })?;
    let dk = DkType::from_bytes(&encoded);

    let header = PqfHeader::read(reader)?;
    let mut aad = Vec::with_capacity(HEADER_SIZE);
    header.write(&mut aad)?;

    let ct_slice = &header.kem_ciphertext[..];
    let ct = Ciphertext::<MlKem768>::try_from(ct_slice)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: KEM_CT_LEN, got: ct_slice.len() })?;

    let ss = dk.decapsulate(&ct).map_err(|_| PqfileError::KemDecapsulation)?;
    let mut ss_bytes = Zeroizing::new([0u8; 32]);
    ss_bytes.copy_from_slice(ss.as_slice());

    let key = Key::from_slice(ss_bytes.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    let stream_nonce = aead::generic_array::GenericArray::clone_from_slice(&header.nonce);
    let mut dec = DecryptorBE32::<ChaCha20Poly1305>::from_aead(cipher, &stream_nonce);

    let original_size = header.original_size;
    let chunk_ct_len = CHUNK_SIZE + 16;

    if original_size == 0 {
        // Empty plaintext: one empty last chunk = 16-byte tag only.
        let mut buf = vec![0u8; 16];
        reader.read_exact(&mut buf)?;
        dec.decrypt_last(Payload { msg: &buf, aad: &aad })
            .map_err(|_| PqfileError::DecryptionFailure)?;
        on_progress(0, 0);
        return Ok(());
    }

    // Number of encrypted chunks, and size of the final (possibly partial) chunk.
    let num_chunks = original_size.div_ceil(CHUNK_SIZE as u64);
    let last_plain_size = {
        let r = original_size % CHUNK_SIZE as u64;
        if r == 0 { CHUNK_SIZE as u64 } else { r }
    };
    let last_ct_size = last_plain_size as usize + 16;

    let mut buf = vec![0u8; chunk_ct_len];
    let mut plain_done: u64 = 0;

    // All intermediate chunks — decrypt_next takes &mut self.
    for _ in 0..(num_chunks - 1) {
        reader.read_exact(&mut buf)?;
        let pt = dec
            .decrypt_next(Payload { msg: &buf, aad: &aad })
            .map_err(|_| PqfileError::DecryptionFailure)?;
        writer.write_all(&pt)?;
        plain_done += pt.len() as u64;
        on_progress(plain_done, original_size);
    }

    // Final chunk — decrypt_last consumes dec, so it must be outside the loop.
    reader.read_exact(&mut buf[..last_ct_size])?;
    let pt = dec
        .decrypt_last(Payload { msg: &buf[..last_ct_size], aad: &aad })
        .map_err(|_| PqfileError::DecryptionFailure)?;
    writer.write_all(&pt)?;
    plain_done += pt.len() as u64;
    on_progress(plain_done, original_size);

    Ok(())
}

/// In-memory wrapper used by the GUI and WASM target.
pub fn decrypt_bytes(priv_pem: &str, pqf_data: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let mut reader = io::Cursor::new(pqf_data);
    let mut output = Vec::new();
    decrypt_stream(priv_pem, &mut reader, &mut output, |_, _| {})?;
    Ok(output)
}
