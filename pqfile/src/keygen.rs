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
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);

    let ek_encoded = ek.as_bytes();
    let pub_pem = Pem::new(PUB_TAG, ek_encoded.as_slice().to_vec());
    fs::write(out_dir.join("pubkey.pem"), pem::encode(&pub_pem))?;

    let dk_encoded = dk.as_bytes();
    let priv_bytes = Zeroizing::new(dk_encoded.as_slice().to_vec());
    let priv_pem = Pem::new(PRIV_TAG, (*priv_bytes).clone());
    fs::write(out_dir.join("privkey.pem"), pem::encode(&priv_pem))?;

    Ok(())
}
