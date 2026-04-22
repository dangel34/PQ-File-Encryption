use std::fs;
use std::io::BufReader;
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
    let pem_data = fs::read_to_string(privkey_path)?;
    let pem = pem::parse(&pem_data).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    type DkType = DecapsulationKey<MlKem768Params>;
    let raw = pem.contents();
    let priv_bytes = Zeroizing::new(raw.to_vec());
    let encoded = Encoded::<DkType>::try_from(priv_bytes.as_slice())
        .map_err(|_| PqfileError::InvalidKeyLength { expected: 2400, got: raw.len() })?;
    let dk = DkType::from_bytes(&encoded);

    let in_file = fs::File::open(input_path)?;
    let mut reader = BufReader::new(in_file);
    let header = PqfHeader::read(&mut reader)?;

    let ct_slice = &header.kem_ciphertext[..];
    let ct = Ciphertext::<MlKem768>::try_from(ct_slice)
        .map_err(|_| PqfileError::InvalidKeyLength { expected: KEM_CT_LEN, got: ct_slice.len() })?;

    let ss = dk.decapsulate(&ct).map_err(|_| PqfileError::KemDecapsulation)?;
    let mut ss_bytes = Zeroizing::new([0u8; 32]);
    ss_bytes.copy_from_slice(ss.as_slice());

    let mut payload = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut payload)?;

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&header.nonce);
    let cipher = ChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(nonce, payload.as_ref())
        .map_err(|_| PqfileError::DecryptionFailure)?;

    let output_path = input_path.with_extension("");
    fs::write(&output_path, &plaintext)?;

    Ok(())
}
