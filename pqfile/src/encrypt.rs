use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ml_kem::{EncapsulationKey768, array::Array, kem::Encapsulate};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{HEADER_LEN, NONCE_LEN, PqfHeader};

pub fn encrypt(
    pubkey_path: &Path,
    input_path: &Path,
    output_path: Option<&Path>,
) -> Result<(), PqfileError> {
    let pubkey_pem = fs::read_to_string(pubkey_path)?;
    let plaintext = fs::read(input_path)?;
    let output = encrypt_bytes(&pubkey_pem, &plaintext)?;
    let out: PathBuf = match output_path {
        Some(p) => p.to_path_buf(),
        None => {
            let mut s = input_path.as_os_str().to_owned();
            s.push(".pqf");
            PathBuf::from(s)
        }
    };
    fs::write(&out, output)?;
    Ok(())
}

pub fn encrypt_bytes(pubkey_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let pem = pem::parse(pubkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let raw = pem.contents();
    let raw_arr = Array::try_from(raw)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 1184, got: raw.len() })?;
    let ek = EncapsulationKey768::new(&raw_arr)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 1184, got: raw.len() })?;

    let (ct, ss) = ek.encapsulate();
    let mut ss_bytes = Zeroizing::new([0u8; 32]);
    ss_bytes.copy_from_slice(ss.as_slice());

    let ct_slice = ct.as_slice();
    use crate::format::KEM_CT_LEN;
    let mut kem_ct = [0u8; KEM_CT_LEN];
    kem_ct.copy_from_slice(ct_slice);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;

    let original_size = plaintext.len() as u64;

    let header = PqfHeader { kem_ciphertext: kem_ct, nonce: nonce_bytes, original_size };
    let mut output = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    header.write(&mut output)?;

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &output })
        .map_err(|_| PqfileError::EncryptionFailure)?;

    output.extend_from_slice(&ciphertext);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use tempfile::tempdir;

    fn write_pubkey(dir: &Path) -> PathBuf {
        let (pub_pem, _) = keygen_bytes().unwrap();
        let path = dir.join("pk.pem");
        fs::write(&path, pub_pem.as_bytes()).unwrap();
        path
    }

    #[test]
    fn encrypt_writes_to_custom_output_path() {
        let tmp = tempdir().unwrap();
        let pk = write_pubkey(tmp.path());
        let input = tmp.path().join("plain.txt");
        fs::write(&input, b"hello custom output").unwrap();
        let out = tmp.path().join("custom.pqf");
        encrypt(&pk, &input, Some(&out)).unwrap();
        assert!(out.exists());
    }

    #[test]
    fn encrypt_defaults_to_input_with_pqf_suffix() {
        let tmp = tempdir().unwrap();
        let pk = write_pubkey(tmp.path());
        let input = tmp.path().join("data.txt");
        fs::write(&input, b"hello default").unwrap();
        encrypt(&pk, &input, None).unwrap();
        assert!(tmp.path().join("data.txt.pqf").exists());
    }
}
