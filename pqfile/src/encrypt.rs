use std::fs;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;

use aead::{stream::EncryptorBE32, Payload};
use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305, Key};
use ml_kem::{
    kem::{EncapsulationKey, Encapsulate},
    Encoded, EncodedSizeUser, MlKem768Params,
};
use rand::rngs::OsRng;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{CHUNK_SIZE, HEADER_SIZE, KEM_CT_LEN, NONCE_LEN, PqfHeader};

/// Encrypt `input_path` to `output_path` using streaming AEAD with an atomic write.
/// On failure the incomplete output is removed; the input is never modified.
pub fn encrypt_file(pub_pem: &str, input_path: &Path, output_path: &Path) -> Result<(), PqfileError> {
    let original_size = fs::metadata(input_path)?.len();
    let tmp_path = {
        let mut s = output_path.as_os_str().to_owned();
        s.push(".tmp");
        std::path::PathBuf::from(s)
    };

    let mut reader = BufReader::new(fs::File::open(input_path)?);
    let outcome = {
        let mut writer = BufWriter::new(fs::File::create(&tmp_path)?);
        let r = encrypt_stream(pub_pem, &mut reader, original_size, &mut writer, |_| {});
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

/// Core streaming encrypt. Reads plaintext from `reader` and writes the full
/// `.pqf` stream (header + authenticated ciphertext chunks) to `writer`.
/// `on_progress` is called with bytes of plaintext encrypted after each chunk.
pub fn encrypt_stream<R: Read, W: Write>(
    pub_pem: &str,
    reader: &mut R,
    original_size: u64,
    writer: &mut W,
    mut on_progress: impl FnMut(u64),
) -> Result<(), PqfileError> {
    let pem = pem::parse(pub_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    type EkType = EncapsulationKey<MlKem768Params>;
    let raw = pem.contents();
    let encoded = Encoded::<EkType>::try_from(raw)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 1184, got: raw.len() })?;
    let ek = EkType::from_bytes(&encoded);

    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| PqfileError::KemEncapsulation)?;
    let mut ss_bytes = Zeroizing::new([0u8; 32]);
    ss_bytes.copy_from_slice(ss.as_slice());

    let mut kem_ct = [0u8; KEM_CT_LEN];
    kem_ct.copy_from_slice(ct.as_slice());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let header = PqfHeader { kem_ciphertext: kem_ct, nonce: nonce_bytes, original_size };
    let mut aad = Vec::with_capacity(HEADER_SIZE);
    header.write(&mut aad)?;

    let key = Key::from_slice(ss_bytes.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    let stream_nonce = aead::generic_array::GenericArray::clone_from_slice(&nonce_bytes);
    let mut enc = EncryptorBE32::<ChaCha20Poly1305>::from_aead(cipher, &stream_nonce);

    writer.write_all(&aad)?;

    if original_size == 0 {
        let ct = enc
            .encrypt_last(Payload { msg: &[], aad: &aad })
            .map_err(|_| PqfileError::EncryptionFailure)?;
        writer.write_all(&ct)?;
        on_progress(0);
        return Ok(());
    }

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut bytes_done: u64 = 0;

    loop {
        let remaining = original_size - bytes_done;
        let to_read = remaining.min(CHUNK_SIZE as u64) as usize;
        reader.read_exact(&mut buf[..to_read])?;
        bytes_done += to_read as u64;

        if bytes_done >= original_size {
            let ct = enc
                .encrypt_last(Payload { msg: &buf[..to_read], aad: &aad })
                .map_err(|_| PqfileError::EncryptionFailure)?;
            writer.write_all(&ct)?;
            on_progress(bytes_done);
            break;
        } else {
            let ct = enc
                .encrypt_next(Payload { msg: &buf[..to_read], aad: &aad })
                .map_err(|_| PqfileError::EncryptionFailure)?;
            writer.write_all(&ct)?;
            on_progress(bytes_done);
        }
    }

    Ok(())
}

/// In-memory wrapper used by the GUI and WASM target.
pub fn encrypt_bytes(pub_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let mut reader = io::Cursor::new(plaintext);
    let mut output = Vec::with_capacity(HEADER_SIZE + plaintext.len() + 16);
    encrypt_stream(pub_pem, &mut reader, plaintext.len() as u64, &mut output, |_| {})?;
    Ok(output)
}
