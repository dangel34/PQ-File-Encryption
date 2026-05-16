use std::fs;
use std::path::Path;

use ml_kem::{Kem, KeyExport, MlKem768};
use pem::Pem;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::error::PqfileError;

const PUB_TAG: &str = "ML-KEM-768 PUBLIC KEY";
const PRIV_TAG: &str = "ML-KEM-768 PRIVATE KEY";

/// Generates a key pair and writes it to `out_dir`.
/// Returns the SHA3-256 fingerprint of the public key (first 8 bytes, colon-separated hex).
/// Errors with `OutputExists` if either key file already exists and `force` is false.
pub fn keygen(out_dir: &Path, force: bool) -> Result<String, PqfileError> {
    if !force {
        for name in ["pubkey.pem", "privkey.pem"] {
            let p = out_dir.join(name);
            if p.exists() {
                return Err(PqfileError::OutputExists(p));
            }
        }
    }
    let (pub_pem, priv_pem) = keygen_bytes()?;
    let raw_pub = pem::parse(&pub_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let fp = fingerprint(raw_pub.contents());
    let pub_path = out_dir.join("pubkey.pem");
    let priv_path = out_dir.join("privkey.pem");
    fs::write(&pub_path, pub_pem.as_bytes())?;
    if let Err(e) = fs::write(&priv_path, priv_pem.as_bytes()) {
        // Clean up the already-written public key so the pair is never left mismatched.
        let _ = fs::remove_file(&pub_path);
        return Err(e.into());
    }
    Ok(fp)
}

pub fn keygen_bytes() -> Result<(String, String), PqfileError> {
    let (dk, ek) = MlKem768::generate_keypair();

    let pub_pem = pem::encode(&Pem::new(PUB_TAG, ek.to_bytes().as_slice().to_vec()));

    let priv_bytes = Zeroizing::new(dk.to_bytes().as_slice().to_vec());
    let priv_pem = pem::encode(&Pem::new(PRIV_TAG, priv_bytes.to_vec()));

    Ok((pub_pem, priv_pem))
}

/// SHA3-256 fingerprint of `raw_bytes`, formatted as the first 8 bytes in colon-separated hex.
pub fn fingerprint(raw_bytes: &[u8]) -> String {
    Sha3_256::digest(raw_bytes)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Convenience wrapper: parses a PEM string and returns its fingerprint.
/// Returns `"unknown"` if the PEM is invalid.
/// Used by downstream crates (pqfile-gui); not called from the CLI binary.
#[allow(dead_code)]
pub fn fingerprint_pem(pem_str: &str) -> String {
    pem::parse(pem_str)
        .map(|p| fingerprint(p.contents()))
        .unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn keygen_writes_key_files() {
        let tmp = tempdir().unwrap();
        keygen(tmp.path(), false).unwrap();
        assert!(tmp.path().join("pubkey.pem").exists());
        assert!(tmp.path().join("privkey.pem").exists());
    }

    #[test]
    fn keygen_returns_fingerprint_string() {
        let tmp = tempdir().unwrap();
        let fp = keygen(tmp.path(), false).unwrap();
        assert_eq!(fp.len(), 23);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
    }

    #[test]
    fn keygen_refuses_existing_pubkey_without_force() {
        let tmp = tempdir().unwrap();
        keygen(tmp.path(), false).unwrap();
        let err = keygen(tmp.path(), false).unwrap_err();
        assert!(matches!(err, PqfileError::OutputExists(_)));
    }

    #[test]
    fn keygen_force_overwrites_existing_keys() {
        let tmp = tempdir().unwrap();
        keygen(tmp.path(), false).unwrap();
        keygen(tmp.path(), true).unwrap();
        assert!(tmp.path().join("pubkey.pem").exists());
        assert!(tmp.path().join("privkey.pem").exists());
    }

    #[test]
    fn keygen_cleans_up_pubkey_when_privkey_write_fails() {
        let tmp = tempdir().unwrap();
        // Making privkey.pem a directory causes fs::write to fail on both Unix and Windows.
        fs::create_dir(tmp.path().join("privkey.pem")).unwrap();
        // force=true bypasses the exists check so we reach the write step.
        let result = keygen(tmp.path(), true);
        assert!(result.is_err(), "expected error when privkey write fails");
        assert!(
            !tmp.path().join("pubkey.pem").exists(),
            "pubkey.pem should be cleaned up after privkey write failure"
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let bytes = [0xab_u8; 32];
        assert_eq!(fingerprint(&bytes), fingerprint(&bytes));
    }

    #[test]
    fn fingerprint_differs_on_different_input() {
        assert_ne!(fingerprint(&[0u8; 32]), fingerprint(&[1u8; 32]));
    }

    #[test]
    fn fingerprint_format_is_colon_separated_hex() {
        let fp = fingerprint(&[0u8; 1184]);
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 8);
        for part in parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn fingerprint_pem_returns_valid_fingerprint_for_real_key() {
        let (pub_pem, _) = keygen_bytes().unwrap();
        let fp = fingerprint_pem(&pub_pem);
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 8);
    }

    #[test]
    fn fingerprint_pem_returns_unknown_for_invalid_pem() {
        assert_eq!(fingerprint_pem("not valid pem"), "unknown");
    }
}
