use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, Params};
use zeroize::Zeroizing;

use crate::error::PqfileError;

// Argon2id parameters: m=64 MiB, t=3 iterations, p=1 lane.
// Chosen to be fast enough for interactive use (~0.2 s on modest hardware)
// while still being costly to brute-force.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 64;

// Layout of the encrypted private key PEM body (108 bytes total):
//   0..16   salt
//   16..28  AES-GCM nonce
//   28..108 AES-256-GCM ciphertext (64-byte seed + 16-byte tag)
pub const ENCRYPTED_BODY_LEN: usize = SALT_LEN + NONCE_LEN + SEED_LEN + 16;

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
pub fn decrypt_seed(body: &[u8], passphrase: &str) -> Result<Zeroizing<[u8; SEED_LEN]>, PqfileError> {
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
            .map_err(|_| PqfileError::WrongPassphrase)?
    );

    if plaintext.len() != SEED_LEN {
        return Err(PqfileError::WrongPassphrase);
    }

    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
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
        assert!(matches!(decrypt_seed(&body, "wrong"), Err(PqfileError::WrongPassphrase)));
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
}
