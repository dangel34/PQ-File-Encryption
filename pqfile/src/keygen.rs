use std::fs;
use std::path::Path;

use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use pem::Pem;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::PqfileError;

const PUB_TAG: &str = "ML-KEM-768 PUBLIC KEY";
const PRIV_TAG: &str = "ML-KEM-768 PRIVATE KEY";

pub fn keygen(out_dir: &Path) -> Result<(), PqfileError> {
    let (pub_pem, priv_pem) = keygen_bytes()?;
    fs::write(out_dir.join("pubkey.pem"), pub_pem.as_bytes())?;
    fs::write(out_dir.join("privkey.pem"), priv_pem.as_bytes())?;
    Ok(())
}

pub fn keygen_bytes() -> Result<(String, String), PqfileError> {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);

    let pub_pem = pem::encode(&Pem::new(PUB_TAG, ek.as_bytes().as_slice().to_vec()));

    let dk_encoded = dk.as_bytes();
    let priv_bytes = Zeroizing::new(dk_encoded.as_slice().to_vec());
    let priv_pem = pem::encode(&Pem::new(PRIV_TAG, (*priv_bytes).clone()));

    Ok((pub_pem, priv_pem))
}
