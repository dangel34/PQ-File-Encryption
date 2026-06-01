use std::fs;
use std::path::Path;

use ml_kem::{Kem, KeyExport, MlKem1024, MlKem512, MlKem768};
use pem::Pem;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{
    HYBRID_EK_LEN_768, HYBRID_SEED_LEN_768, KEM_VARIANT_1024, KEM_VARIANT_512, KEM_VARIANT_768,
};
use crate::passphrase;

pub(crate) const PUB_TAG_512: &str = "ML-KEM-512 PUBLIC KEY";
pub(crate) const PRIV_TAG_512: &str = "ML-KEM-512 PRIVATE KEY";
pub(crate) const PRIV_ENC_TAG_512: &str = "ML-KEM-512 ENCRYPTED PRIVATE KEY";

pub(crate) const PUB_TAG: &str = "ML-KEM-768 PUBLIC KEY";
pub(crate) const PRIV_TAG: &str = "ML-KEM-768 PRIVATE KEY";
pub(crate) const PRIV_ENC_TAG: &str = "ML-KEM-768 ENCRYPTED PRIVATE KEY";

pub(crate) const PUB_TAG_1024: &str = "ML-KEM-1024 PUBLIC KEY";
pub(crate) const PRIV_TAG_1024: &str = "ML-KEM-1024 PRIVATE KEY";
pub(crate) const PRIV_ENC_TAG_1024: &str = "ML-KEM-1024 ENCRYPTED PRIVATE KEY";

pub(crate) const PUB_TAG_HYBRID_768: &str = "X25519+ML-KEM-768 PUBLIC KEY";
pub(crate) const PRIV_TAG_HYBRID_768: &str = "X25519+ML-KEM-768 PRIVATE KEY";
pub(crate) const PRIV_ENC_TAG_HYBRID_768: &str = "X25519+ML-KEM-768 ENCRYPTED PRIVATE KEY";

/// Generates a key pair and writes it to `out_dir`.
/// `level` must be 768 or 1024. Set `hybrid` for X25519+ML-KEM-768 hybrid mode.
/// Returns the SHA3-256 fingerprint of the public key (first 8 bytes, colon-separated hex).
/// Errors with `OutputExists` if either key file already exists and `force` is false.
/// If `passphrase` is `Some`, the private key is encrypted before writing.
#[must_use = "keygen result must be used"]
pub fn keygen(
    out_dir: &Path,
    force: bool,
    level: u16,
    passphrase: Option<&str>,
    hybrid: bool,
) -> Result<String, PqfileError> {
    if !force {
        for name in ["pubkey.pem", "privkey.pem"] {
            let p = out_dir.join(name);
            if p.exists() {
                return Err(PqfileError::OutputExists(p));
            }
        }
    }
    let (pub_pem, priv_pem) = if hybrid {
        keygen_bytes_hybrid_768(passphrase)?
    } else {
        keygen_bytes(level, passphrase)?
    };
    let raw_pub = pem::parse(&pub_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let fp = fingerprint(raw_pub.contents());
    let pub_path = out_dir.join("pubkey.pem");
    let priv_path = out_dir.join("privkey.pem");
    fs::write(&pub_path, pub_pem.as_bytes())?;
    if let Err(e) = fs::write(&priv_path, priv_pem.as_bytes()) {
        let _ = fs::remove_file(&pub_path);
        return Err(e.into());
    }
    Ok(fp)
}

/// Generates a key pair and returns the PEM strings.
/// `level` must be 512, 768, or 1024.
/// If `passphrase` is `Some`, the private key PEM uses the encrypted tag.
#[must_use = "keygen result must be used"]
pub fn keygen_bytes(level: u16, passphrase: Option<&str>) -> Result<(String, String), PqfileError> {
    match level {
        KEM_VARIANT_512 => keygen_bytes_512(passphrase),
        KEM_VARIANT_768 => keygen_bytes_768(passphrase),
        KEM_VARIANT_1024 => keygen_bytes_1024(passphrase),
        _ => Err(PqfileError::UnsupportedKem(level)),
    }
}

fn keygen_bytes_512(passphrase: Option<&str>) -> Result<(String, String), PqfileError> {
    let (dk, ek) = MlKem512::generate_keypair();
    let pub_pem = pem::encode(&Pem::new(PUB_TAG_512, ek.to_bytes().as_slice().to_vec()));
    let seed_bytes = Zeroizing::new(dk.to_bytes().as_slice().to_vec());
    let priv_pem = encode_private_key(&seed_bytes, passphrase, PRIV_TAG_512, PRIV_ENC_TAG_512)?;
    Ok((pub_pem, priv_pem))
}

fn keygen_bytes_768(passphrase: Option<&str>) -> Result<(String, String), PqfileError> {
    let (dk, ek) = MlKem768::generate_keypair();
    let pub_pem = pem::encode(&Pem::new(PUB_TAG, ek.to_bytes().as_slice().to_vec()));
    let seed_bytes = Zeroizing::new(dk.to_bytes().as_slice().to_vec());
    let priv_pem = encode_private_key(&seed_bytes, passphrase, PRIV_TAG, PRIV_ENC_TAG)?;
    Ok((pub_pem, priv_pem))
}

fn keygen_bytes_1024(passphrase: Option<&str>) -> Result<(String, String), PqfileError> {
    let (dk, ek) = MlKem1024::generate_keypair();
    let pub_pem = pem::encode(&Pem::new(PUB_TAG_1024, ek.to_bytes().as_slice().to_vec()));
    let seed_bytes = Zeroizing::new(dk.to_bytes().as_slice().to_vec());
    let priv_pem = encode_private_key(&seed_bytes, passphrase, PRIV_TAG_1024, PRIV_ENC_TAG_1024)?;
    Ok((pub_pem, priv_pem))
}

/// Generates a Hybrid X25519+ML-KEM-768 key pair and returns PEM strings.
/// Public key body: X25519 pubkey (32) || ML-KEM-768 EK (1184) = 1216 bytes.
/// Private key body: X25519 scalar (32) || ML-KEM-768 seed (64) = 96 bytes.
#[must_use = "keygen result must be used"]
pub fn keygen_bytes_hybrid_768(passphrase: Option<&str>) -> Result<(String, String), PqfileError> {
    // Generate X25519 key pair.
    let mut x25519_scalar_bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(x25519_scalar_bytes.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;
    let x25519_sk = X25519StaticSecret::from(*x25519_scalar_bytes);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    // Generate ML-KEM-768 key pair.
    let (ml_dk, ml_ek) = MlKem768::generate_keypair();
    let ml_seed_bytes = Zeroizing::new(ml_dk.to_bytes().as_slice().to_vec());
    let ml_ek_bytes = ml_ek.to_bytes();

    // Build combined public key: X25519 pubkey || ML-KEM EK.
    let mut pub_bytes = Vec::with_capacity(HYBRID_EK_LEN_768);
    pub_bytes.extend_from_slice(x25519_pk.as_bytes());
    pub_bytes.extend_from_slice(ml_ek_bytes.as_slice());
    let pub_pem = pem::encode(&Pem::new(PUB_TAG_HYBRID_768, pub_bytes));

    // Build combined private key: X25519 scalar || ML-KEM seed.
    let mut priv_seed = Zeroizing::new([0u8; HYBRID_SEED_LEN_768]);
    priv_seed[..32].copy_from_slice(x25519_sk.as_bytes());
    priv_seed[32..].copy_from_slice(&ml_seed_bytes);

    let priv_pem = if let Some(pp) = passphrase {
        let body = passphrase::encrypt_hybrid_seed(&priv_seed, pp)?;
        pem::encode(&Pem::new(PRIV_ENC_TAG_HYBRID_768, body))
    } else {
        pem::encode(&Pem::new(PRIV_TAG_HYBRID_768, priv_seed.to_vec()))
    };

    Ok((pub_pem, priv_pem))
}

fn encode_private_key(
    seed_bytes: &Zeroizing<Vec<u8>>,
    passphrase: Option<&str>,
    plain_tag: &str,
    enc_tag: &str,
) -> Result<String, PqfileError> {
    if seed_bytes.len() != 64 {
        return Err(PqfileError::InvalidKeyLength {
            expected: 64,
            got: seed_bytes.len(),
        });
    }
    if let Some(pp) = passphrase {
        let mut seed_arr = Zeroizing::new([0u8; 64]);
        seed_arr.copy_from_slice(seed_bytes);
        let body = passphrase::encrypt_seed(&seed_arr, pp)?;
        Ok(pem::encode(&Pem::new(enc_tag, body)))
    } else {
        Ok(pem::encode(&Pem::new(plain_tag, seed_bytes.to_vec())))
    }
}

/// SHA3-256 fingerprint of `raw_bytes`, formatted as the first 8 bytes in colon-separated hex.
#[must_use]
pub fn fingerprint(raw_bytes: &[u8]) -> String {
    Sha3_256::digest(raw_bytes)
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Returns true if `pem_str` uses an encrypted private key tag (512, 768, 1024, or hybrid).
#[must_use]
pub fn is_encrypted_key(pem_str: &str) -> bool {
    pem::parse(pem_str)
        .map(|p| {
            p.tag() == PRIV_ENC_TAG_512
                || p.tag() == PRIV_ENC_TAG
                || p.tag() == PRIV_ENC_TAG_1024
                || p.tag() == PRIV_ENC_TAG_HYBRID_768
        })
        .unwrap_or(false)
}

/// Convenience wrapper: parses a PEM string and returns its fingerprint.
/// Returns `"unknown"` if the PEM is invalid.
#[must_use]
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
        keygen(tmp.path(), false, 768, None, false).unwrap();
        assert!(tmp.path().join("pubkey.pem").exists());
        assert!(tmp.path().join("privkey.pem").exists());
    }

    #[test]
    fn keygen_returns_fingerprint_string() {
        let tmp = tempdir().unwrap();
        let fp = keygen(tmp.path(), false, 768, None, false).unwrap();
        assert_eq!(fp.len(), 47);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
    }

    #[test]
    fn keygen_refuses_existing_pubkey_without_force() {
        let tmp = tempdir().unwrap();
        keygen(tmp.path(), false, 768, None, false).unwrap();
        let err = keygen(tmp.path(), false, 768, None, false).unwrap_err();
        assert!(matches!(err, PqfileError::OutputExists(_)));
    }

    #[test]
    fn keygen_force_overwrites_existing_keys() {
        let tmp = tempdir().unwrap();
        keygen(tmp.path(), false, 768, None, false).unwrap();
        keygen(tmp.path(), true, 768, None, false).unwrap();
        assert!(tmp.path().join("pubkey.pem").exists());
        assert!(tmp.path().join("privkey.pem").exists());
    }

    #[test]
    fn keygen_cleans_up_pubkey_when_privkey_write_fails() {
        let tmp = tempdir().unwrap();
        fs::create_dir(tmp.path().join("privkey.pem")).unwrap();
        let result = keygen(tmp.path(), true, 768, None, false);
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
        assert_eq!(parts.len(), 16);
        for part in parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn fingerprint_pem_returns_valid_fingerprint_for_real_key() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let fp = fingerprint_pem(&pub_pem);
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 16);
    }

    #[test]
    fn fingerprint_pem_returns_unknown_for_invalid_pem() {
        assert_eq!(fingerprint_pem("not valid pem"), "unknown");
    }

    #[test]
    fn keygen_bytes_with_passphrase_uses_encrypted_tag() {
        let (_, priv_pem) = keygen_bytes(768, Some("secret")).unwrap();
        let parsed = pem::parse(&priv_pem).unwrap();
        assert_eq!(parsed.tag(), PRIV_ENC_TAG);
    }

    #[test]
    fn keygen_bytes_without_passphrase_uses_plain_tag() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        let parsed = pem::parse(&priv_pem).unwrap();
        assert_eq!(parsed.tag(), PRIV_TAG);
    }

    #[test]
    fn keygen_with_passphrase_writes_encrypted_key() {
        let tmp = tempdir().unwrap();
        keygen(
            tmp.path(),
            false,
            768,
            Some("correct horse battery staple"),
            false,
        )
        .unwrap();
        let priv_pem = std::fs::read_to_string(tmp.path().join("privkey.pem")).unwrap();
        let parsed = pem::parse(&priv_pem).unwrap();
        assert_eq!(parsed.tag(), PRIV_ENC_TAG);
    }

    #[test]
    fn keygen_1024_uses_correct_tags() {
        let (pub_pem, priv_pem) = keygen_bytes(1024, None).unwrap();
        assert_eq!(pem::parse(&pub_pem).unwrap().tag(), PUB_TAG_1024);
        assert_eq!(pem::parse(&priv_pem).unwrap().tag(), PRIV_TAG_1024);
    }

    #[test]
    fn keygen_1024_with_passphrase_uses_encrypted_tag() {
        let (_, priv_pem) = keygen_bytes(1024, Some("secret")).unwrap();
        assert_eq!(pem::parse(&priv_pem).unwrap().tag(), PRIV_ENC_TAG_1024);
    }

    #[test]
    fn keygen_1024_pubkey_is_1568_bytes() {
        let (pub_pem, _) = keygen_bytes(1024, None).unwrap();
        let parsed = pem::parse(&pub_pem).unwrap();
        assert_eq!(parsed.contents().len(), 1568);
    }

    #[test]
    fn keygen_unsupported_level_returns_error() {
        let err = keygen_bytes(256, None).unwrap_err();
        assert!(matches!(err, PqfileError::UnsupportedKem(256)));
    }

    #[test]
    fn is_encrypted_key_detects_1024_encrypted_tag() {
        let (_, priv_pem) = keygen_bytes(1024, Some("pass")).unwrap();
        assert!(is_encrypted_key(&priv_pem));
    }

    // ── ML-KEM-512 ────────────────────────────────────────────────────────────

    #[test]
    fn keygen_512_uses_correct_tags() {
        let (pub_pem, priv_pem) = keygen_bytes(512, None).unwrap();
        assert_eq!(pem::parse(&pub_pem).unwrap().tag(), PUB_TAG_512);
        assert_eq!(pem::parse(&priv_pem).unwrap().tag(), PRIV_TAG_512);
    }

    #[test]
    fn keygen_512_pubkey_is_800_bytes() {
        let (pub_pem, _) = keygen_bytes(512, None).unwrap();
        let parsed = pem::parse(&pub_pem).unwrap();
        assert_eq!(parsed.contents().len(), 800);
    }

    #[test]
    fn keygen_512_privkey_seed_is_64_bytes() {
        let (_, priv_pem) = keygen_bytes(512, None).unwrap();
        let parsed = pem::parse(&priv_pem).unwrap();
        assert_eq!(parsed.contents().len(), 64);
    }

    #[test]
    fn keygen_512_with_passphrase_uses_encrypted_tag() {
        let (_, priv_pem) = keygen_bytes(512, Some("secure")).unwrap();
        assert_eq!(pem::parse(&priv_pem).unwrap().tag(), PRIV_ENC_TAG_512);
    }

    #[test]
    fn is_encrypted_key_detects_512_encrypted_tag() {
        let (_, priv_pem) = keygen_bytes(512, Some("pass")).unwrap();
        assert!(is_encrypted_key(&priv_pem));
    }

    #[test]
    fn keygen_512_fingerprint_has_correct_format() {
        let (pub_pem, _) = keygen_bytes(512, None).unwrap();
        let fp = fingerprint_pem(&pub_pem);
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 16);
        for part in parts {
            assert_eq!(part.len(), 2);
            assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}
