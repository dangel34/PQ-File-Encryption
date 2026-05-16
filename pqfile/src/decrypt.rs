use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ml_kem::{Ciphertext, DecapsulationKey768, MlKem768, Seed, kem::Decapsulate};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{HEADER_LEN, KEM_CT_LEN, PqfHeader};

pub fn decrypt(
    privkey_path: &Path,
    input_path: &Path,
    output_path: Option<&Path>,
) -> Result<(), PqfileError> {
    let privkey_pem = fs::read_to_string(privkey_path)?;
    let pqf_data = fs::read(input_path)?;
    let plaintext = decrypt_bytes(&privkey_pem, &pqf_data)?;
    let out: PathBuf = output_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| input_path.with_extension(""));
    fs::write(&out, &plaintext)?;
    Ok(())
}

pub fn decrypt_bytes(privkey_pem: &str, pqf_data: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let pem = pem::parse(privkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let raw = pem.contents();
    let priv_bytes = Zeroizing::new(raw.to_vec());
    let seed = Seed::try_from(priv_bytes.as_slice())
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 64, got: raw.len() })?;
    let dk = DecapsulationKey768::from_seed(seed);

    let mut cursor = Cursor::new(pqf_data);
    let header = PqfHeader::read(&mut cursor)?;

    let ct_slice = &header.kem_ciphertext[..KEM_CT_LEN];
    let ct = Ciphertext::<MlKem768>::try_from(ct_slice)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: KEM_CT_LEN, got: ct_slice.len() })?;

    let ss = dk.decapsulate(&ct);
    let mut ss_bytes = Zeroizing::new([0u8; 32]);
    ss_bytes.copy_from_slice(ss.as_slice());

    let header_bytes = &pqf_data[..HEADER_LEN];
    let payload = &pqf_data[HEADER_LEN..];
    if payload.len() < 16 {
        return Err(PqfileError::DecryptionFailure);
    }

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&header.nonce);
    let cipher = ChaCha20Poly1305::new(key);
    cipher
        .decrypt(nonce, Payload { msg: payload, aad: header_bytes })
        .map_err(|_| PqfileError::DecryptionFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::encrypt_bytes;
    use crate::keygen::keygen_bytes;
    use tempfile::tempdir;

    fn setup(tmp: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
        let (pub_pem, priv_pem) = keygen_bytes().unwrap();
        let plaintext = b"test payload for decrypt".to_vec();
        let pqf = encrypt_bytes(&pub_pem, &plaintext).unwrap();
        let pqf_path = tmp.join("file.txt.pqf");
        fs::write(&pqf_path, &pqf).unwrap();
        let priv_path = tmp.join("priv.pem");
        fs::write(&priv_path, priv_pem.as_bytes()).unwrap();
        (pqf_path, priv_path, plaintext)
    }

    #[test]
    fn decrypt_writes_to_custom_output_path() {
        let tmp = tempdir().unwrap();
        let (pqf, priv_path, expected) = setup(tmp.path());
        let out = tmp.path().join("recovered.dat");
        decrypt(&priv_path, &pqf, Some(&out)).unwrap();
        assert_eq!(fs::read(&out).unwrap(), expected);
    }

    #[test]
    fn decrypt_defaults_to_stripping_pqf_extension() {
        let tmp = tempdir().unwrap();
        let (pqf, priv_path, expected) = setup(tmp.path());
        decrypt(&priv_path, &pqf, None).unwrap();
        assert_eq!(fs::read(tmp.path().join("file.txt")).unwrap(), expected);
    }
}
