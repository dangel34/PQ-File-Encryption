use std::fs;
use std::path::Path;

use hkdf::Hkdf;
use ml_kem::{
    DecapsulationKey1024, DecapsulationKey512, DecapsulationKey768, Kem, KeyExport, MlKem1024,
    MlKem512, MlKem768, Seed,
};
use pem::Pem;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{
    HYBRID_EK_LEN_768, HYBRID_SEED_LEN_768, KEM_VARIANT_1024, KEM_VARIANT_512, KEM_VARIANT_768,
};
use crate::hardware;
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
        // Best-effort: remove the orphaned public key. The caller already receives
        // the write error; if removal also fails (e.g. disk full) there is nothing
        // more we can do from a library crate without a logging dependency.
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

/// Deterministically generates an ML-KEM-768 key pair from the provided 64-byte seed.
///
/// Intended for key import workflows: derive `seed` via HKDF from an existing
/// secret (e.g. an SSH ed25519 seed), then call this function to produce a
/// pqfile-compatible key pair. The resulting key has no mathematical relationship
/// to the source key; it is a one-way derivation.
#[must_use = "keygen result must be used"]
pub fn keygen_bytes_from_seed(
    seed: [u8; 64],
    passphrase: Option<&str>,
) -> Result<(String, String), PqfileError> {
    let seed_arr = Seed::try_from(seed.as_ref()).map_err(|_| PqfileError::EncryptionFailure)?;
    let dk = DecapsulationKey768::from_seed(seed_arr);
    let ek = dk.encapsulation_key();
    let pub_pem = pem::encode(&Pem::new(PUB_TAG, ek.to_bytes().as_slice().to_vec()));
    let seed_bytes = Zeroizing::new(dk.to_bytes().as_slice().to_vec());
    let priv_pem = encode_private_key(&seed_bytes, passphrase, PRIV_TAG, PRIV_ENC_TAG)?;
    Ok((pub_pem, priv_pem))
}

/// Imports an OpenSSH ed25519 private key and derives an ML-KEM-768 key pair from it.
///
/// The ed25519 32-byte seed is extracted from the unencrypted OpenSSH key format
/// and expanded to 64 bytes via HKDF-SHA256 with info `"pqfile-import-from-ssh-ed25519"`.
/// The derived key has no mathematical relationship to the ed25519 key; the import
/// is one-way and the result is not interoperable with SSH.
///
/// Only unencrypted (`-----BEGIN OPENSSH PRIVATE KEY-----`) ed25519 keys are supported.
/// Passphrase-protected SSH keys must be decrypted before import.
pub fn import_key_from_ssh(
    ssh_pem: &str,
    output_passphrase: Option<&str>,
) -> Result<(String, String), PqfileError> {
    let seed = extract_ssh_ed25519_seed(ssh_pem)?;
    let mut derived = Zeroizing::new([0u8; 64]);
    let hk = Hkdf::<Sha256>::new(None, &*seed);
    hk.expand(b"pqfile-import-from-ssh-ed25519", derived.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    keygen_bytes_from_seed(*derived, output_passphrase)
}

/// Parses an unencrypted OpenSSH ed25519 private key and returns the 32-byte seed.
fn extract_ssh_ed25519_seed(pem_str: &str) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let parsed = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if parsed.tag() != "OPENSSH PRIVATE KEY" {
        return Err(PqfileError::InvalidPem(format!(
            "expected OPENSSH PRIVATE KEY, got {}",
            parsed.tag()
        )));
    }
    let data = parsed.into_contents();
    if data.len() < 16 || &data[..15] != b"openssh-key-v1\0" {
        return Err(PqfileError::InvalidPem(
            "not an OpenSSH private key (bad magic)".into(),
        ));
    }
    let mut pos = 16usize;
    let cipher = ssh_read_string(&data, &mut pos)?;
    if cipher != b"none" {
        return Err(PqfileError::InvalidPem(
            "passphrase-protected SSH keys are not supported; \
             decrypt first: ssh-keygen -p -f <key> -N ''"
                .into(),
        ));
    }
    let kdf = ssh_read_string(&data, &mut pos)?;
    if kdf != b"none" {
        return Err(PqfileError::InvalidPem(
            "non-empty KDF in SSH key; only unencrypted keys are supported".into(),
        ));
    }
    let _ = ssh_read_string(&data, &mut pos)?; // kdf_options
    let num_keys = ssh_read_u32(&data, &mut pos)?;
    if num_keys != 1 {
        return Err(PqfileError::InvalidPem(
            "SSH key file must contain exactly one key".into(),
        ));
    }
    let _ = ssh_read_string(&data, &mut pos)?; // public key blob
    let priv_section = ssh_read_string(&data, &mut pos)?;
    // Reject absurdly large private sections before copying to avoid allocating
    // an unbounded amount of heap memory from a crafted SSH key file.
    // A legitimate ed25519 private section is never more than a few hundred bytes.
    const MAX_PRIV_SECTION: usize = 4096;
    if priv_section.len() > MAX_PRIV_SECTION {
        return Err(PqfileError::InvalidPem(
            "SSH key private section exceeds maximum expected size".into(),
        ));
    }
    let priv_data: Vec<u8> = priv_section.to_owned();
    let mut pp = 0usize;
    let check1 = ssh_read_u32(&priv_data, &mut pp)?;
    let check2 = ssh_read_u32(&priv_data, &mut pp)?;
    if check1 != check2 {
        return Err(PqfileError::InvalidPem(
            "SSH key check values do not match (corrupt key)".into(),
        ));
    }
    let key_type = ssh_read_string(&priv_data, &mut pp)?;
    if key_type != b"ssh-ed25519" {
        return Err(PqfileError::InvalidPem(format!(
            "only ssh-ed25519 keys are supported for import; got {:?}",
            String::from_utf8_lossy(key_type)
        )));
    }
    let _ = ssh_read_string(&priv_data, &mut pp)?; // public key (32 bytes)
    let sk = ssh_read_string(&priv_data, &mut pp)?; // 64 bytes: seed || public
    if sk.len() != 64 {
        return Err(PqfileError::InvalidPem(format!(
            "expected 64-byte ed25519 SK, got {} bytes",
            sk.len()
        )));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&sk[..32]);
    Ok(seed)
}

fn ssh_read_u32(data: &[u8], pos: &mut usize) -> Result<u32, PqfileError> {
    if *pos + 4 > data.len() {
        return Err(PqfileError::InvalidPem("truncated SSH key data".into()));
    }
    let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn ssh_read_string<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], PqfileError> {
    let len = ssh_read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(PqfileError::InvalidPem("truncated SSH key string".into()));
    }
    let s = &data[*pos..*pos + len];
    *pos += len;
    Ok(s)
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

/// Generates a Hybrid X25519+ML-KEM-768 key pair and returns `(pub_pem, priv_pem)`.
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

/// Returns true if `pem_str` is a hardware key reference stub (any key type).
#[must_use]
pub fn is_hardware_key(pem_str: &str) -> bool {
    pem::parse(pem_str)
        .map(|p| hardware::is_hardware_tag(p.tag()))
        .unwrap_or(false)
}

// ── Hardware keygen ───────────────────────────────────────────────────────

/// Generates a hardware-backed key pair and writes `pubkey.pem` and
/// `privkey.pem` (a stub with no seed bytes) to `out_dir`.
///
/// The private key seed is stored in the OS credential store under `label`.
/// It can only be recovered on the same machine/user account where it was
/// generated.
#[must_use = "hardware keygen result must be saved or the keys are lost"]
pub fn keygen_hardware(
    out_dir: &Path,
    force: bool,
    level: u16,
    hybrid: bool,
    label: &str,
) -> Result<String, PqfileError> {
    if !force {
        for name in ["pubkey.pem", "privkey.pem"] {
            let p = out_dir.join(name);
            if p.exists() {
                return Err(PqfileError::OutputExists(p));
            }
        }
    }
    let (pub_pem, hw_pem) = if hybrid {
        keygen_bytes_hardware_hybrid(label)?
    } else {
        keygen_bytes_hardware(level, label)?
    };
    let raw_pub = pem::parse(&pub_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let fp = fingerprint(raw_pub.contents());
    let pub_path = out_dir.join("pubkey.pem");
    let priv_path = out_dir.join("privkey.pem");
    fs::write(&pub_path, pub_pem.as_bytes())?;
    if let Err(e) = fs::write(&priv_path, hw_pem.as_bytes()) {
        // Best-effort: remove the orphaned public key. The caller already receives
        // the write error; if removal also fails there is nothing more we can do
        // from a library crate without a logging dependency.
        let _ = fs::remove_file(&pub_path);
        return Err(e.into());
    }
    Ok(fp)
}

/// Generates a hardware-backed key pair and returns `(pub_pem, stub_pem)`.
#[must_use = "hardware keygen result must be used"]
pub fn keygen_bytes_hardware(level: u16, label: &str) -> Result<(String, String), PqfileError> {
    match level {
        KEM_VARIANT_512 => hw_keygen_inner(label, 64, hardware::HW_TAG_512, PUB_TAG_512, |seed| {
            let arr = Seed::try_from(seed).map_err(|_| PqfileError::EncryptionFailure)?;
            Ok(DecapsulationKey512::from_seed(arr)
                .encapsulation_key()
                .to_bytes()
                .as_slice()
                .to_vec())
        }),
        KEM_VARIANT_768 => hw_keygen_inner(label, 64, hardware::HW_TAG_768, PUB_TAG, |seed| {
            let arr = Seed::try_from(seed).map_err(|_| PqfileError::EncryptionFailure)?;
            Ok(DecapsulationKey768::from_seed(arr)
                .encapsulation_key()
                .to_bytes()
                .as_slice()
                .to_vec())
        }),
        KEM_VARIANT_1024 => {
            hw_keygen_inner(label, 64, hardware::HW_TAG_1024, PUB_TAG_1024, |seed| {
                let arr = Seed::try_from(seed).map_err(|_| PqfileError::EncryptionFailure)?;
                Ok(DecapsulationKey1024::from_seed(arr)
                    .encapsulation_key()
                    .to_bytes()
                    .as_slice()
                    .to_vec())
            })
        }
        _ => Err(PqfileError::UnsupportedKem(level)),
    }
}

/// Generates a hardware-backed hybrid X25519+ML-KEM-768 key pair and returns
/// `(pub_pem, stub_pem)`.
#[must_use = "hardware keygen result must be used"]
pub fn keygen_bytes_hardware_hybrid(label: &str) -> Result<(String, String), PqfileError> {
    hw_keygen_inner(
        label,
        HYBRID_SEED_LEN_768,
        hardware::HW_TAG_HYBRID_768,
        PUB_TAG_HYBRID_768,
        |seed| {
            if seed.len() != HYBRID_SEED_LEN_768 {
                return Err(PqfileError::EncryptionFailure);
            }
            let x25519_sk = X25519StaticSecret::from(<[u8; 32]>::try_from(&seed[..32]).unwrap());
            let x25519_pk = X25519PublicKey::from(&x25519_sk);
            let ml_arr = Seed::try_from(&seed[32..]).map_err(|_| PqfileError::EncryptionFailure)?;
            let ml_ek = DecapsulationKey768::from_seed(ml_arr)
                .encapsulation_key()
                .to_bytes();
            let mut out = Vec::with_capacity(HYBRID_EK_LEN_768);
            out.extend_from_slice(x25519_pk.as_bytes());
            out.extend_from_slice(ml_ek.as_slice());
            Ok(out)
        },
    )
}

/// Shared hardware keygen body: generates + stores the seed, derives the
/// public key bytes via `derive_pub`, and returns `(pub_pem, stub_pem)`.
fn hw_keygen_inner(
    label: &str,
    seed_len: usize,
    hw_tag: &str,
    pub_tag: &str,
    derive_pub: impl FnOnce(&[u8]) -> Result<Vec<u8>, PqfileError>,
) -> Result<(String, String), PqfileError> {
    let backend_id = hardware::default_backend_id();
    let (stub_body, seed) = hardware::generate_and_store(label, seed_len, backend_id)?;
    let pub_bytes = derive_pub(&seed)?;
    let pub_pem = pem::encode(&pem::Pem::new(pub_tag, pub_bytes));
    let hw_pem = pem::encode(&pem::Pem::new(hw_tag, stub_body));
    Ok((pub_pem, hw_pem))
}

/// Convenience wrapper: parses a PEM string and returns its fingerprint.
/// Returns `"unknown"` if the PEM is invalid.
#[must_use]
pub fn fingerprint_pem(pem_str: &str) -> String {
    pem::parse(pem_str)
        .map(|p| fingerprint(p.contents()))
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// Score a passphrase from 0 (very weak) to 7 (strong).
///
/// Combines length (3 tiers) and character diversity (4 classes).
/// Score 0-2 = weak, 3-4 = fair, 5-7 = strong.
///
/// This is a heuristic for user feedback only; it does not enforce any minimum.
#[must_use]
pub fn passphrase_strength(s: &str) -> u8 {
    let mut score = 0u8;
    if s.len() >= 8 {
        score += 1;
    }
    if s.len() >= 12 {
        score += 1;
    }
    if s.len() >= 16 {
        score += 1;
    }
    if s.chars().any(|c| c.is_lowercase()) {
        score += 1;
    }
    if s.chars().any(|c| c.is_uppercase()) {
        score += 1;
    }
    if s.chars().any(|c| c.is_ascii_digit()) {
        score += 1;
    }
    if s.chars().any(|c| !c.is_alphanumeric()) {
        score += 1;
    }
    score
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

    // ── keygen_bytes_from_seed tests ───────────────────────────────────────

    #[test]
    fn keygen_from_seed_produces_valid_key_pair() {
        let seed = [0x42u8; 64];
        let (pub_pem, priv_pem) = keygen_bytes_from_seed(seed, None).unwrap();
        assert!(pub_pem.contains("ML-KEM-768 PUBLIC KEY"));
        assert!(priv_pem.contains("ML-KEM-768 PRIVATE KEY"));
    }

    #[test]
    fn keygen_from_seed_is_deterministic() {
        let seed = [0x99u8; 64];
        let (pub1, priv1) = keygen_bytes_from_seed(seed, None).unwrap();
        let (pub2, priv2) = keygen_bytes_from_seed(seed, None).unwrap();
        assert_eq!(pub1, pub2);
        assert_eq!(priv1, priv2);
    }

    #[test]
    fn keygen_from_different_seeds_produce_different_keys() {
        let (pub1, _) = keygen_bytes_from_seed([0u8; 64], None).unwrap();
        let (pub2, _) = keygen_bytes_from_seed([1u8; 64], None).unwrap();
        assert_ne!(pub1, pub2);
    }

    // ── import_key_from_ssh: bad input rejection ───────────────────────────

    #[test]
    fn import_ssh_rejects_wrong_pem_tag() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let err = import_key_from_ssh(&pub_pem, None).unwrap_err();
        assert!(
            err.to_string().contains("OPENSSH PRIVATE KEY"),
            "error should mention expected tag"
        );
    }

    #[test]
    fn import_ssh_rejects_truncated_data() {
        // Construct a PEM block with too-short contents.
        let bad_pem = pem::encode(&pem::Pem::new("OPENSSH PRIVATE KEY", vec![0u8; 4]));
        let err = import_key_from_ssh(&bad_pem, None).unwrap_err();
        assert!(err.to_string().contains("bad magic") || err.to_string().contains("truncated"));
    }

    #[test]
    fn import_ssh_rejects_oversized_private_section() {
        // Craft an OpenSSH private key blob whose priv_section length field
        // announces more than MAX_PRIV_SECTION (4096) bytes. The parser must
        // reject it before allocating the oversized buffer.
        //
        // OpenSSH binary format (simplified):
        //   magic (15 bytes) + NUL + cipher("none",4B) + kdf("none",4B) +
        //   kdf_options("",4B) + num_keys(1,4B) + pubkey_blob("",4B) +
        //   priv_section_len(4B) + priv_section_bytes
        let mut data: Vec<u8> = Vec::new();
        // The parser checks data[..15] against b"openssh-key-v1\0" (15 bytes),
        // then starts reading at pos = 16, so one extra byte must follow the magic.
        data.extend_from_slice(b"openssh-key-v1\0"); // indices 0-14 (15 bytes)
        data.push(0u8); // index 15: consumed by pos = 16, not checked
                        // cipher = "none"
        data.extend_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(b"none");
        // kdf = "none"
        data.extend_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(b"none");
        // kdf_options = ""
        data.extend_from_slice(&0u32.to_be_bytes());
        // num_keys = 1
        data.extend_from_slice(&1u32.to_be_bytes());
        // public key blob = "" (empty)
        data.extend_from_slice(&0u32.to_be_bytes());
        // priv_section = 8000 bytes (exceeds MAX_PRIV_SECTION=4096)
        data.extend_from_slice(&8000u32.to_be_bytes());
        data.extend(std::iter::repeat_n(0u8, 8000));

        let bad_pem = pem::encode(&pem::Pem::new("OPENSSH PRIVATE KEY", data));
        let err = import_key_from_ssh(&bad_pem, None).unwrap_err();
        assert!(
            err.to_string().contains("exceeds maximum"),
            "expected size-cap error, got: {err}"
        );
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
