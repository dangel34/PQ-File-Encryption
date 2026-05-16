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
use crate::keygen::{PRIV_ENC_TAG, PRIV_TAG};
use crate::passphrase;

pub fn decrypt(
    privkey_path: &Path,
    input_path: &Path,
    output_path: Option<&Path>,
    passphrase: Option<&str>,
) -> Result<(), PqfileError> {
    let privkey_pem = fs::read_to_string(privkey_path)?;
    let pqf_data = fs::read(input_path)?;
    let plaintext = decrypt_bytes(&privkey_pem, &pqf_data, passphrase)?;
    let out: PathBuf = output_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| input_path.with_extension(""));
    fs::write(&out, &plaintext)?;
    Ok(())
}

pub fn decrypt_bytes(privkey_pem: &str, pqf_data: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, PqfileError> {
    let pem = pem::parse(privkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let raw = pem.contents();

    let seed_bytes: Zeroizing<Vec<u8>> = match pem.tag() {
        t if t == PRIV_ENC_TAG => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            let seed = passphrase::decrypt_seed(raw, pp)?;
            Zeroizing::new(seed.to_vec())
        }
        t if t == PRIV_TAG => Zeroizing::new(raw.to_vec()),
        _ => return Err(PqfileError::InvalidPem("unrecognised private key tag".to_owned())),
    };

    let priv_bytes = seed_bytes;
    let seed = Seed::try_from(priv_bytes.as_slice())
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 64, got: priv_bytes.len() })?;
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
        let (pub_pem, priv_pem) = keygen_bytes(None).unwrap();
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
        decrypt(&priv_path, &pqf, Some(&out), None).unwrap();
        assert_eq!(fs::read(&out).unwrap(), expected);
    }

    #[test]
    fn decrypt_defaults_to_stripping_pqf_extension() {
        let tmp = tempdir().unwrap();
        let (pqf, priv_path, expected) = setup(tmp.path());
        decrypt(&priv_path, &pqf, None, None).unwrap();
        assert_eq!(fs::read(tmp.path().join("file.txt")).unwrap(), expected);
    }

    #[test]
    fn decrypt_rejects_truncated_payload() {
        use crate::format::{KEM_CT_LEN, KEM_VARIANT, MAGIC, NONCE_LEN, VERSION};

        let (_, priv_pem) = keygen_bytes(None).unwrap();

        // Build a valid header followed by only 8 bytes of payload (below the 16-byte AEAD tag minimum).
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(VERSION);
        data.extend_from_slice(&KEM_VARIANT.to_le_bytes());
        data.extend_from_slice(&[0u8; KEM_CT_LEN]);
        data.extend_from_slice(&[0u8; NONCE_LEN]);
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);

        let result = decrypt_bytes(&priv_pem, &data, None);
        assert!(matches!(result, Err(PqfileError::DecryptionFailure)));
    }

    #[test]
    fn decrypt_bytes_with_encrypted_key_and_correct_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(Some("correct horse")).unwrap();
        let plaintext = b"passphrase-protected roundtrip";
        let pqf = encrypt_bytes(&pub_pem, plaintext).unwrap();
        let result = decrypt_bytes(&priv_pem, &pqf, Some("correct horse")).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn decrypt_bytes_with_encrypted_key_wrong_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(Some("correct")).unwrap();
        let plaintext = b"passphrase-protected roundtrip";
        let pqf = encrypt_bytes(&pub_pem, plaintext).unwrap();
        let result = decrypt_bytes(&priv_pem, &pqf, Some("wrong"));
        assert!(matches!(result, Err(PqfileError::WrongPassphrase)));
    }

    #[test]
    fn decrypt_bytes_encrypted_key_without_passphrase_returns_error() {
        let (pub_pem, priv_pem) = keygen_bytes(Some("secret")).unwrap();
        let pqf = encrypt_bytes(&pub_pem, b"data").unwrap();
        let result = decrypt_bytes(&priv_pem, &pqf, None);
        assert!(matches!(result, Err(PqfileError::PassphraseRequired)));
    }
}
