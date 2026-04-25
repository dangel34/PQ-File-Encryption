use std::fs;
use std::path::Path;

use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use pem::Pem;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::PqfileError;

const PUB_TAG: &str = "ML-KEM-768 PUBLIC KEY";
const PRIV_TAG: &str = "ML-KEM-768 PRIVATE KEY";

/// Generate a key pair, write PEM files to `out_dir`, and return the public-key fingerprint.
pub fn keygen(out_dir: &Path) -> Result<String, PqfileError> {
    let (pub_pem, priv_pem) = keygen_bytes()?;
    let priv_path = out_dir.join("privkey.pem");
    fs::write(out_dir.join("pubkey.pem"), pub_pem.as_bytes())?;
    fs::write(&priv_path, priv_pem.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600))?;
    }
    pubkey_fingerprint(&pub_pem)
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

/// Compute a short fingerprint of a public key PEM: first 8 bytes of SHA-256(raw key), hex-encoded.
pub fn pubkey_fingerprint(pub_pem: &str) -> Result<String, PqfileError> {
    let pem = pem::parse(pub_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let hash = Sha256::digest(pem.contents());
    Ok(hash[..8].iter().map(|b| format!("{b:02x}")).collect())
}
