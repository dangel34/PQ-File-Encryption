use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::{Argon2, Params};
use zeroize::Zeroizing;

use crate::error::PqfileError;

// Current Argon2id parameters (pqfile >= 4.0): m=64 MiB, t=3, p=4.
//
// p=4 (four lanes) forces each brute-force attempt to occupy 4× the memory
// bandwidth compared to p=1, hampering parallel GPU attacks. OWASP 2023
// recommends p=4 for the same m/t values.
pub(crate) const ARGON2_M_COST: u32 = 65536; // 64 MiB
pub(crate) const ARGON2_T_COST: u32 = 3;
pub(crate) const ARGON2_P_COST: u32 = 4;

// Legacy Argon2id p-cost (pqfile < 4.0). Used only to detect and migrate old keys.
const ARGON2_P_COST_LEGACY: u32 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 64;
const HYBRID_SEED_LEN: usize = 96;

// Layout of the encrypted private key PEM body (108 bytes total):
//   0..16   salt
//   16..28  AES-GCM nonce
//   28..108 AES-256-GCM ciphertext (64-byte seed + 16-byte tag)
/// Byte length of an encrypted ML-KEM private key PEM body (108 bytes: salt + nonce + ciphertext).
pub const ENCRYPTED_BODY_LEN: usize = SALT_LEN + NONCE_LEN + SEED_LEN + 16;

// Layout of the encrypted hybrid private key PEM body (140 bytes total):
//   0..16   salt
//   16..28  AES-GCM nonce
//   28..140 AES-256-GCM ciphertext (96-byte hybrid seed + 16-byte tag)
/// Byte length of an encrypted hybrid X25519+ML-KEM-768 private key PEM body (140 bytes).
pub const ENCRYPTED_HYBRID_BODY_LEN: usize = SALT_LEN + NONCE_LEN + HYBRID_SEED_LEN + 16;

/// Encrypts a 64-byte ML-KEM seed under `passphrase`. Returns the 108-byte
/// payload that is stored as the PEM body of an encrypted private key.
pub fn encrypt_seed(seed: &[u8; SEED_LEN], passphrase: &str) -> Result<Vec<u8>, PqfileError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| PqfileError::EncryptionFailure)?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;
    let nonce = nonce_bytes.as_slice().try_into().expect("12-byte nonce");

    let ciphertext = cipher
        .encrypt(nonce, seed.as_slice())
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let mut out = Vec::with_capacity(ENCRYPTED_BODY_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts the 108-byte payload from an encrypted private key PEM body using
/// current (p=4) Argon2id parameters.
///
/// Returns `LegacyKeyFormat` if the body decrypts correctly only with the old
/// p=1 parameters (pqfile < 4.0 key). Use `pqfile repassphrase --from-legacy`
/// to upgrade such keys before use.
pub fn decrypt_seed(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SEED_LEN]>, PqfileError> {
    if body.len() != ENCRYPTED_BODY_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: ENCRYPTED_BODY_LEN,
            got: body.len(),
        });
    }
    // Try current params first.
    if let Ok(seed) = try_decrypt_seed(body, passphrase, ARGON2_P_COST) {
        return Ok(seed);
    }
    // If p=1 succeeds, the key is valid but needs migration.
    if try_decrypt_seed(body, passphrase, ARGON2_P_COST_LEGACY).is_ok() {
        return Err(PqfileError::LegacyKeyFormat);
    }
    Err(PqfileError::WrongPassphrase)
}

/// Decrypts a 108-byte body using the legacy p=1 Argon2id parameters.
/// Only called by the `repassphrase --from-legacy` migration path.
pub(crate) fn decrypt_seed_legacy(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SEED_LEN]>, PqfileError> {
    if body.len() != ENCRYPTED_BODY_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: ENCRYPTED_BODY_LEN,
            got: body.len(),
        });
    }
    try_decrypt_seed(body, passphrase, ARGON2_P_COST_LEGACY)
        .map_err(|_| PqfileError::WrongPassphrase)
}

fn try_decrypt_seed(
    body: &[u8],
    passphrase: &str,
    p_cost: u32,
) -> Result<Zeroizing<[u8; SEED_LEN]>, PqfileError> {
    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    let key = derive_key_with_pcost(passphrase, salt, p_cost)?;
    let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));
    let nonce = nonce_bytes.try_into().expect("12-byte nonce");

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PqfileError::WrongPassphrase)?,
    );

    if plaintext.len() != SEED_LEN {
        return Err(PqfileError::WrongPassphrase);
    }

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Encrypts a 96-byte hybrid seed (X25519 scalar || ML-KEM seed) under `passphrase`.
pub fn encrypt_hybrid_seed(
    seed: &[u8; HYBRID_SEED_LEN],
    passphrase: &str,
) -> Result<Vec<u8>, PqfileError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| PqfileError::EncryptionFailure)?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;
    let nonce = nonce_bytes.as_slice().try_into().expect("12-byte nonce");

    let ciphertext = cipher
        .encrypt(nonce, seed.as_slice())
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let mut out = Vec::with_capacity(ENCRYPTED_HYBRID_BODY_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts the 140-byte payload from an encrypted hybrid private key PEM body.
///
/// Returns `LegacyKeyFormat` if the body was encrypted with legacy p=1 parameters.
pub fn decrypt_hybrid_seed(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; HYBRID_SEED_LEN]>, PqfileError> {
    if body.len() != ENCRYPTED_HYBRID_BODY_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: ENCRYPTED_HYBRID_BODY_LEN,
            got: body.len(),
        });
    }
    if let Ok(seed) = try_decrypt_hybrid_seed(body, passphrase, ARGON2_P_COST) {
        return Ok(seed);
    }
    if try_decrypt_hybrid_seed(body, passphrase, ARGON2_P_COST_LEGACY).is_ok() {
        return Err(PqfileError::LegacyKeyFormat);
    }
    Err(PqfileError::WrongPassphrase)
}

/// Decrypts a 140-byte hybrid body using legacy p=1 parameters.
/// Only called by the `repassphrase --from-legacy` migration path.
pub(crate) fn decrypt_hybrid_seed_legacy(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; HYBRID_SEED_LEN]>, PqfileError> {
    if body.len() != ENCRYPTED_HYBRID_BODY_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: ENCRYPTED_HYBRID_BODY_LEN,
            got: body.len(),
        });
    }
    try_decrypt_hybrid_seed(body, passphrase, ARGON2_P_COST_LEGACY)
        .map_err(|_| PqfileError::WrongPassphrase)
}

fn try_decrypt_hybrid_seed(
    body: &[u8],
    passphrase: &str,
    p_cost: u32,
) -> Result<Zeroizing<[u8; HYBRID_SEED_LEN]>, PqfileError> {
    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    let key = derive_key_with_pcost(passphrase, salt, p_cost)?;
    let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));
    let nonce = nonce_bytes.try_into().expect("12-byte nonce");

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PqfileError::WrongPassphrase)?,
    );

    if plaintext.len() != HYBRID_SEED_LEN {
        return Err(PqfileError::WrongPassphrase);
    }

    let mut seed = Zeroizing::new([0u8; HYBRID_SEED_LEN]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

const SIGNING_SEED_LEN: usize = 32;

/// Layout of the encrypted ML-DSA-65 signing key PEM body (76 bytes total):
///   0..16   salt
///   16..28  AES-GCM nonce
///   28..76  AES-256-GCM ciphertext (32-byte signing seed + 16-byte tag)
pub const ENCRYPTED_SIGNING_BODY_LEN: usize = SALT_LEN + NONCE_LEN + SIGNING_SEED_LEN + 16;

/// Encrypts a 32-byte ML-DSA-65 signing seed under `passphrase`. Returns the 76-byte
/// payload stored as the PEM body of an encrypted signing key.
pub fn encrypt_signing_seed(
    seed: &[u8; SIGNING_SEED_LEN],
    passphrase: &str,
) -> Result<Vec<u8>, PqfileError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| PqfileError::EncryptionFailure)?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;
    let nonce = nonce_bytes.as_slice().try_into().expect("12-byte nonce");

    let ciphertext = cipher
        .encrypt(nonce, seed.as_slice())
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let mut out = Vec::with_capacity(ENCRYPTED_SIGNING_BODY_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts the 76-byte payload from an encrypted ML-DSA-65 signing key PEM body.
///
/// Returns `LegacyKeyFormat` if the body was encrypted with legacy p=1 parameters.
pub fn decrypt_signing_seed(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SIGNING_SEED_LEN]>, PqfileError> {
    if body.len() != ENCRYPTED_SIGNING_BODY_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: ENCRYPTED_SIGNING_BODY_LEN,
            got: body.len(),
        });
    }
    if let Ok(seed) = try_decrypt_signing_seed(body, passphrase, ARGON2_P_COST) {
        return Ok(seed);
    }
    if try_decrypt_signing_seed(body, passphrase, ARGON2_P_COST_LEGACY).is_ok() {
        return Err(PqfileError::LegacyKeyFormat);
    }
    Err(PqfileError::WrongPassphrase)
}

/// Decrypts a 76-byte signing body using legacy p=1 parameters.
/// Only called by the `repassphrase --from-legacy` migration path.
pub(crate) fn decrypt_signing_seed_legacy(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SIGNING_SEED_LEN]>, PqfileError> {
    if body.len() != ENCRYPTED_SIGNING_BODY_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: ENCRYPTED_SIGNING_BODY_LEN,
            got: body.len(),
        });
    }
    try_decrypt_signing_seed(body, passphrase, ARGON2_P_COST_LEGACY)
        .map_err(|_| PqfileError::WrongPassphrase)
}

fn try_decrypt_signing_seed(
    body: &[u8],
    passphrase: &str,
    p_cost: u32,
) -> Result<Zeroizing<[u8; SIGNING_SEED_LEN]>, PqfileError> {
    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    let key = derive_key_with_pcost(passphrase, salt, p_cost)?;
    let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));
    let nonce = nonce_bytes.try_into().expect("12-byte nonce");

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PqfileError::WrongPassphrase)?,
    );

    if plaintext.len() != SIGNING_SEED_LEN {
        return Err(PqfileError::WrongPassphrase);
    }

    let mut seed = Zeroizing::new([0u8; SIGNING_SEED_LEN]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    derive_key_with_pcost(passphrase, salt, ARGON2_P_COST)
}

fn derive_key_with_pcost(
    passphrase: &str,
    salt: &[u8],
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    derive_key_with_params(passphrase, salt, ARGON2_M_COST, ARGON2_T_COST, p_cost)
}

/// Derives a 32-byte key from `passphrase` using Argon2id with arbitrary parameters.
/// Used by v10 passphrase-only format where the sender stores their chosen params in the header.
pub(crate) fn derive_key_with_params(
    passphrase: &str,
    salt: &[u8],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let params =
        Params::new(m_kib, t_cost, p_cost, Some(32)).map_err(|_| PqfileError::EncryptionFailure)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers that produce legacy (p=1) bodies for migration tests ──────────

    fn encrypt_seed_legacy(seed: &[u8; SEED_LEN], passphrase: &str) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).unwrap();
        let key = derive_key_with_pcost(passphrase, &salt, ARGON2_P_COST_LEGACY).unwrap();
        let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let ct = cipher
            .encrypt(
                nonce_bytes.as_slice().try_into().expect("12-byte nonce"),
                seed.as_slice(),
            )
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    fn encrypt_signing_seed_legacy(seed: &[u8; SIGNING_SEED_LEN], passphrase: &str) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).unwrap();
        let key = derive_key_with_pcost(passphrase, &salt, ARGON2_P_COST_LEGACY).unwrap();
        let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let ct = cipher
            .encrypt(
                nonce_bytes.as_slice().try_into().expect("12-byte nonce"),
                seed.as_slice(),
            )
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    fn encrypt_hybrid_seed_legacy(seed: &[u8; HYBRID_SEED_LEN], passphrase: &str) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).unwrap();
        let key = derive_key_with_pcost(passphrase, &salt, ARGON2_P_COST_LEGACY).unwrap();
        let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let ct = cipher
            .encrypt(
                nonce_bytes.as_slice().try_into().expect("12-byte nonce"),
                seed.as_slice(),
            )
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    // ── Current (p=4) round-trips ─────────────────────────────────────────────

    #[test]
    fn roundtrip_correct_passphrase() {
        let seed = [0x42u8; SEED_LEN];
        let body = encrypt_seed(&seed, "hunter2").unwrap();
        assert_eq!(body.len(), ENCRYPTED_BODY_LEN);
        let recovered = decrypt_seed(&body, "hunter2").unwrap();
        assert_eq!(*recovered, seed);
    }

    #[test]
    fn wrong_passphrase_returns_error() {
        let seed = [0x99u8; SEED_LEN];
        let body = encrypt_seed(&seed, "correct").unwrap();
        assert!(matches!(
            decrypt_seed(&body, "wrong"),
            Err(PqfileError::WrongPassphrase)
        ));
    }

    #[test]
    fn different_encryptions_produce_different_bodies() {
        let seed = [0x01u8; SEED_LEN];
        let a = encrypt_seed(&seed, "pass").unwrap();
        let b = encrypt_seed(&seed, "pass").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_body_length_returns_error() {
        assert!(matches!(
            decrypt_seed(&[0u8; 10], "pass"),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    // ── Legacy detection ──────────────────────────────────────────────────────

    #[test]
    fn legacy_key_returns_legacy_key_format_error() {
        let seed = [0x11u8; SEED_LEN];
        let legacy_body = encrypt_seed_legacy(&seed, "correct");
        assert!(matches!(
            decrypt_seed(&legacy_body, "correct"),
            Err(PqfileError::LegacyKeyFormat)
        ));
    }

    #[test]
    fn legacy_key_wrong_passphrase_returns_wrong_passphrase() {
        let seed = [0x22u8; SEED_LEN];
        let legacy_body = encrypt_seed_legacy(&seed, "correct");
        assert!(matches!(
            decrypt_seed(&legacy_body, "wrong"),
            Err(PqfileError::WrongPassphrase)
        ));
    }

    #[test]
    fn decrypt_seed_legacy_roundtrip() {
        let seed = [0x33u8; SEED_LEN];
        let legacy_body = encrypt_seed_legacy(&seed, "migrate-me");
        let recovered = decrypt_seed_legacy(&legacy_body, "migrate-me").unwrap();
        assert_eq!(*recovered, seed);
    }

    #[test]
    fn decrypt_seed_legacy_wrong_passphrase() {
        let seed = [0x44u8; SEED_LEN];
        let legacy_body = encrypt_seed_legacy(&seed, "correct");
        assert!(matches!(
            decrypt_seed_legacy(&legacy_body, "wrong"),
            Err(PqfileError::WrongPassphrase)
        ));
    }

    // ── Hybrid (p=4) ──────────────────────────────────────────────────────────

    #[test]
    fn hybrid_roundtrip_correct_passphrase() {
        let seed = [0x77u8; HYBRID_SEED_LEN];
        let body = encrypt_hybrid_seed(&seed, "hybrid-pass").unwrap();
        assert_eq!(body.len(), ENCRYPTED_HYBRID_BODY_LEN);
        let recovered = decrypt_hybrid_seed(&body, "hybrid-pass").unwrap();
        assert_eq!(*recovered, seed);
    }

    #[test]
    fn hybrid_wrong_passphrase_returns_error() {
        let seed = [0xABu8; HYBRID_SEED_LEN];
        let body = encrypt_hybrid_seed(&seed, "correct").unwrap();
        assert!(matches!(
            decrypt_hybrid_seed(&body, "wrong"),
            Err(PqfileError::WrongPassphrase)
        ));
    }

    #[test]
    fn hybrid_wrong_body_length_returns_error() {
        assert!(matches!(
            decrypt_hybrid_seed(&[0u8; 10], "pass"),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn hybrid_different_encryptions_produce_different_bodies() {
        let seed = [0x55u8; HYBRID_SEED_LEN];
        let a = encrypt_hybrid_seed(&seed, "pass").unwrap();
        let b = encrypt_hybrid_seed(&seed, "pass").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn hybrid_legacy_key_returns_legacy_key_format_error() {
        let seed = [0xCCu8; HYBRID_SEED_LEN];
        let legacy_body = encrypt_hybrid_seed_legacy(&seed, "correct");
        assert!(matches!(
            decrypt_hybrid_seed(&legacy_body, "correct"),
            Err(PqfileError::LegacyKeyFormat)
        ));
    }

    #[test]
    fn decrypt_hybrid_seed_legacy_roundtrip() {
        let seed = [0xDDu8; HYBRID_SEED_LEN];
        let legacy_body = encrypt_hybrid_seed_legacy(&seed, "migrate-me");
        let recovered = decrypt_hybrid_seed_legacy(&legacy_body, "migrate-me").unwrap();
        assert_eq!(*recovered, seed);
    }

    // ── Signing (p=4) ─────────────────────────────────────────────────────────

    #[test]
    fn signing_roundtrip_correct_passphrase() {
        let seed = [0x11u8; SIGNING_SEED_LEN];
        let body = encrypt_signing_seed(&seed, "signpass").unwrap();
        assert_eq!(body.len(), ENCRYPTED_SIGNING_BODY_LEN);
        let recovered = decrypt_signing_seed(&body, "signpass").unwrap();
        assert_eq!(*recovered, seed);
    }

    #[test]
    fn signing_wrong_passphrase_returns_error() {
        let seed = [0x22u8; SIGNING_SEED_LEN];
        let body = encrypt_signing_seed(&seed, "correct").unwrap();
        assert!(matches!(
            decrypt_signing_seed(&body, "wrong"),
            Err(PqfileError::WrongPassphrase)
        ));
    }

    #[test]
    fn signing_wrong_body_length_returns_error() {
        assert!(matches!(
            decrypt_signing_seed(&[0u8; 10], "pass"),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn signing_different_encryptions_produce_different_bodies() {
        let seed = [0x33u8; SIGNING_SEED_LEN];
        let a = encrypt_signing_seed(&seed, "pass").unwrap();
        let b = encrypt_signing_seed(&seed, "pass").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn signing_legacy_key_returns_legacy_key_format_error() {
        let seed = [0x55u8; SIGNING_SEED_LEN];
        let legacy_body = encrypt_signing_seed_legacy(&seed, "correct");
        assert!(matches!(
            decrypt_signing_seed(&legacy_body, "correct"),
            Err(PqfileError::LegacyKeyFormat)
        ));
    }

    #[test]
    fn decrypt_signing_seed_legacy_roundtrip() {
        let seed = [0x66u8; SIGNING_SEED_LEN];
        let legacy_body = encrypt_signing_seed_legacy(&seed, "migrate-me");
        let recovered = decrypt_signing_seed_legacy(&legacy_body, "migrate-me").unwrap();
        assert_eq!(*recovered, seed);
    }
}
