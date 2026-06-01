use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, Params};
use zeroize::Zeroizing;

use crate::error::PqfileError;

// Argon2id parameters: m=64 MiB, t=3 iterations, p=1 lane.
//
// p=1 (single lane) was chosen for single-threaded interactive use (~0.2 s on
// modest hardware). The trade-off: a GPU attacker can run many independent
// 64 MiB instances in parallel, each using p=1. OWASP 2023 recommends p=4
// (four lanes) for the same m/t values — that forces each attempt to occupy
// 4× as much memory bandwidth, hampering parallel hardware attacks.
//
// Increasing p_cost would break backward compatibility with existing encrypted
// keys, so it is tracked as a planned v4.0 format change.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

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
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, seed.as_slice())
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let mut out = Vec::with_capacity(ENCRYPTED_BODY_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts the 108-byte payload from an encrypted private key PEM body.
/// Returns the 64-byte seed on success, or `WrongPassphrase` on failure.
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

    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    let key = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(nonce_bytes);

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
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

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

    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    let key = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(nonce_bytes);

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
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

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
/// Returns the 32-byte signing seed on success, or `WrongPassphrase` on failure.
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

    let salt = &body[..SALT_LEN];
    let nonce_bytes = &body[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &body[SALT_LEN + NONCE_LEN..];

    let key = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(nonce_bytes);

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
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|_| PqfileError::EncryptionFailure)?;
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
        // Different random salt and nonce each time.
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_body_length_returns_error() {
        assert!(matches!(
            decrypt_seed(&[0u8; 10], "pass"),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

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
}
