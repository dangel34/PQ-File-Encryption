use std::fs;
use std::io::Cursor;
use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ml_kem::{
    kem::{DecapsulationKey, Decapsulate},
    Ciphertext, Encoded, EncodedSizeUser, MlKem768, MlKem768Params,
};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{KEM_CT_LEN, PqfHeader};

pub fn decrypt(privkey_path: &Path, input_path: &Path) -> Result<(), PqfileError> {
    let privkey_pem = fs::read_to_string(privkey_path)?;
    let pqf_data = fs::read(input_path)?;
    let plaintext = decrypt_bytes(&privkey_pem, &pqf_data)?;
    let output_path = input_path.with_extension("");
    fs::write(&output_path, &plaintext)?;
    Ok(())
}

pub fn decrypt_bytes(privkey_pem: &str, pqf_data: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let pem = pem::parse(privkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    type DkType = DecapsulationKey<MlKem768Params>;
    let raw = pem.contents();
    let priv_bytes = Zeroizing::new(raw.to_vec());
    let encoded = Encoded::<DkType>::try_from(priv_bytes.as_slice())
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 2400, got: raw.len() })?;
    let dk = DkType::from_bytes(&encoded);

    let mut cursor = Cursor::new(pqf_data);
    let header = PqfHeader::read(&mut cursor)?;

    let ct_slice = &header.kem_ciphertext[..];
    let ct = Ciphertext::<MlKem768>::try_from(ct_slice)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: KEM_CT_LEN, got: ct_slice.len() })?;

    let ss = dk.decapsulate(&ct).map_err(|_| PqfileError::KemDecapsulation)?;
    let mut ss_bytes = Zeroizing::new([0u8; 32]);
    ss_bytes.copy_from_slice(ss.as_slice());

    let payload = &pqf_data[cursor.position() as usize..];

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&header.nonce);
    let cipher = ChaCha20Poly1305::new(key);
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| PqfileError::DecryptionFailure)
}
