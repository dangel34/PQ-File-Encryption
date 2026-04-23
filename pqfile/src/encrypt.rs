use std::fs;
use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ml_kem::{
    kem::{EncapsulationKey, Encapsulate},
    Encoded, EncodedSizeUser, MlKem768Params,
};
use rand::rngs::OsRng;
use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{KEM_CT_LEN, NONCE_LEN, PqfHeader};

pub fn encrypt(pubkey_path: &Path, input_path: &Path) -> Result<(), PqfileError> {
    let pubkey_pem = fs::read_to_string(pubkey_path)?;
    let plaintext = fs::read(input_path)?;
    let output = encrypt_bytes(&pubkey_pem, &plaintext)?;

    let output_path = {
        let mut s = input_path.as_os_str().to_owned();
        s.push(".pqf");
        std::path::PathBuf::from(s)
    };
    fs::write(&output_path, output)?;
    Ok(())
}

pub fn encrypt_bytes(pubkey_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let pem = pem::parse(pubkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    type EkType = EncapsulationKey<MlKem768Params>;
    let raw = pem.contents();
    let encoded = Encoded::<EkType>::try_from(raw)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 1184, got: raw.len() })?;
    let ek = EkType::from_bytes(&encoded);

    let mut rng = OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| PqfileError::KemEncapsulation)?;
    let mut ss_bytes = Zeroizing::new([0u8; 32]);
    ss_bytes.copy_from_slice(ss.as_slice());

    let ct_slice = ct.as_slice();
    let mut kem_ct = [0u8; KEM_CT_LEN];
    kem_ct.copy_from_slice(ct_slice);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);

    let original_size = plaintext.len() as u64;

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| PqfileError::KemEncapsulation)?;

    let header = PqfHeader { kem_ciphertext: kem_ct, nonce: nonce_bytes, original_size };
    let mut output = Vec::new();
    header.write(&mut output)?;
    output.extend_from_slice(&ciphertext);

    Ok(output)
}
