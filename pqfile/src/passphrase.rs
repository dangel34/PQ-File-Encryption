use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::{Argon2, Params};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::secret::LockedSecret;

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

// ── Shared core: every encrypted-seed PEM body (regardless of key type) is
// salt || nonce || AES-256-GCM(seed), so the actual crypto lives here once,
// parameterized by the seed length N. Each public encrypt_*/decrypt_* below
// is a thin, differently-documented wrapper naming its own seed length -
// the wrapper split exists for the public API/doc-comment surface per key
// type, not because the underlying operation differs.

/// Encrypts an N-byte secret under `passphrase`. `body_len` is the caller's
/// own named `ENCRYPTED_*_BODY_LEN` constant (`SALT_LEN + NONCE_LEN + N +
/// 16`, restated by every key type's own constant rather than recomputed
/// here, so those constants stay the single documented source of truth for
/// each PEM body's on-disk size).
fn encrypt_fixed_secret<const N: usize>(
    secret: &[u8; N],
    passphrase: &str,
    body_len: usize,
) -> Result<Vec<u8>, PqfileError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| PqfileError::EncryptionFailure)?;

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;
    let nonce = nonce_bytes.as_slice().try_into().expect("12-byte nonce");

    let ciphertext = cipher
        .encrypt(nonce, secret.as_slice())
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let mut out = Vec::with_capacity(body_len);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts an already-length-checked body at a specific Argon2 `p_cost`,
/// without deciding what a failure or a length mismatch means - callers
/// layer the current-vs-legacy retry policy and the length check on top.
fn try_decrypt_fixed_secret<const N: usize>(
    body: &[u8],
    passphrase: &str,
    p_cost: u32,
) -> Result<Zeroizing<[u8; N]>, PqfileError> {
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

    if plaintext.len() != N {
        return Err(PqfileError::WrongPassphrase);
    }

    let mut secret = Zeroizing::new([0u8; N]);
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

/// Decrypts a body of a key type that still supports the legacy p=1
/// fallback: tries current (p=4) parameters first, then p=1 to distinguish
/// "wrong passphrase" from "valid but needs `repassphrase --from-legacy`".
/// `body_len` is the caller's own named `ENCRYPTED_*_BODY_LEN` constant.
fn decrypt_fixed_secret_with_legacy<const N: usize>(
    body: &[u8],
    passphrase: &str,
    body_len: usize,
) -> Result<Zeroizing<[u8; N]>, PqfileError> {
    if body.len() != body_len {
        return Err(PqfileError::InvalidKeyLength {
            expected: body_len,
            got: body.len(),
        });
    }
    if let Ok(secret) = try_decrypt_fixed_secret::<N>(body, passphrase, ARGON2_P_COST) {
        return Ok(secret);
    }
    if try_decrypt_fixed_secret::<N>(body, passphrase, ARGON2_P_COST_LEGACY).is_ok() {
        return Err(PqfileError::LegacyKeyFormat);
    }
    Err(PqfileError::WrongPassphrase)
}

/// Decrypts a body using only the legacy p=1 parameters. Only called by the
/// `repassphrase --from-legacy` migration path. `body_len` is the caller's
/// own named `ENCRYPTED_*_BODY_LEN` constant.
fn decrypt_fixed_secret_legacy<const N: usize>(
    body: &[u8],
    passphrase: &str,
    body_len: usize,
) -> Result<Zeroizing<[u8; N]>, PqfileError> {
    if body.len() != body_len {
        return Err(PqfileError::InvalidKeyLength {
            expected: body_len,
            got: body.len(),
        });
    }
    try_decrypt_fixed_secret::<N>(body, passphrase, ARGON2_P_COST_LEGACY)
        .map_err(|_| PqfileError::WrongPassphrase)
}

/// Decrypts a body of a key type that postdates the Argon2 p=4 migration and
/// so never had a legacy p=1 form: only current parameters are ever tried.
/// `body_len` is the caller's own named `ENCRYPTED_*_BODY_LEN` constant.
fn decrypt_fixed_secret_no_legacy<const N: usize>(
    body: &[u8],
    passphrase: &str,
    body_len: usize,
) -> Result<Zeroizing<[u8; N]>, PqfileError> {
    if body.len() != body_len {
        return Err(PqfileError::InvalidKeyLength {
            expected: body_len,
            got: body.len(),
        });
    }
    try_decrypt_fixed_secret::<N>(body, passphrase, ARGON2_P_COST)
}

/// Encrypts a 64-byte ML-KEM seed under `passphrase`. Returns the 108-byte
/// payload that is stored as the PEM body of an encrypted private key.
pub fn encrypt_seed(seed: &[u8; SEED_LEN], passphrase: &str) -> Result<Vec<u8>, PqfileError> {
    encrypt_fixed_secret(seed, passphrase, ENCRYPTED_BODY_LEN)
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
    decrypt_fixed_secret_with_legacy(body, passphrase, ENCRYPTED_BODY_LEN)
}

/// Decrypts a 108-byte body using the legacy p=1 Argon2id parameters.
/// Only called by the `repassphrase --from-legacy` migration path.
pub(crate) fn decrypt_seed_legacy(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SEED_LEN]>, PqfileError> {
    decrypt_fixed_secret_legacy(body, passphrase, ENCRYPTED_BODY_LEN)
}

/// Encrypts a 96-byte hybrid seed (X25519 scalar || ML-KEM seed) under `passphrase`.
pub fn encrypt_hybrid_seed(
    seed: &[u8; HYBRID_SEED_LEN],
    passphrase: &str,
) -> Result<Vec<u8>, PqfileError> {
    encrypt_fixed_secret(seed, passphrase, ENCRYPTED_HYBRID_BODY_LEN)
}

/// Decrypts the 140-byte payload from an encrypted hybrid private key PEM body.
///
/// Returns `LegacyKeyFormat` if the body was encrypted with legacy p=1 parameters.
pub fn decrypt_hybrid_seed(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; HYBRID_SEED_LEN]>, PqfileError> {
    decrypt_fixed_secret_with_legacy(body, passphrase, ENCRYPTED_HYBRID_BODY_LEN)
}

/// Decrypts a 140-byte hybrid body using legacy p=1 parameters.
/// Only called by the `repassphrase --from-legacy` migration path.
pub(crate) fn decrypt_hybrid_seed_legacy(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; HYBRID_SEED_LEN]>, PqfileError> {
    decrypt_fixed_secret_legacy(body, passphrase, ENCRYPTED_HYBRID_BODY_LEN)
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
    encrypt_fixed_secret(seed, passphrase, ENCRYPTED_SIGNING_BODY_LEN)
}

/// Decrypts the 76-byte payload from an encrypted ML-DSA-65 signing key PEM body.
///
/// Returns `LegacyKeyFormat` if the body was encrypted with legacy p=1 parameters.
pub fn decrypt_signing_seed(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SIGNING_SEED_LEN]>, PqfileError> {
    decrypt_fixed_secret_with_legacy(body, passphrase, ENCRYPTED_SIGNING_BODY_LEN)
}

/// Decrypts a 76-byte signing body using legacy p=1 parameters.
/// Only called by the `repassphrase --from-legacy` migration path.
pub(crate) fn decrypt_signing_seed_legacy(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SIGNING_SEED_LEN]>, PqfileError> {
    decrypt_fixed_secret_legacy(body, passphrase, ENCRYPTED_SIGNING_BODY_LEN)
}

const SLH_SIGNING_SEED_LEN: usize = 72;

/// Layout of the encrypted SLH-DSA-SHAKE-192f signing key PEM body (116 bytes total):
///   0..16    salt
///   16..28   AES-GCM nonce
///   28..116  AES-256-GCM ciphertext (72-byte seed triple + 16-byte tag)
pub const ENCRYPTED_SLH_SIGNING_BODY_LEN: usize = SALT_LEN + NONCE_LEN + SLH_SIGNING_SEED_LEN + 16;

/// Encrypts a 72-byte SLH-DSA-SHAKE-192f signing seed triple under `passphrase`.
/// Returns the 116-byte payload stored as the PEM body of an encrypted signing key.
pub fn encrypt_slh_signing_seed(
    seed: &[u8; SLH_SIGNING_SEED_LEN],
    passphrase: &str,
) -> Result<Vec<u8>, PqfileError> {
    encrypt_fixed_secret(seed, passphrase, ENCRYPTED_SLH_SIGNING_BODY_LEN)
}

/// Decrypts the 116-byte payload from an encrypted SLH-DSA-SHAKE-192f signing key
/// PEM body. No legacy-parameter fallback: SLH-DSA keys postdate the Argon2 p=4
/// migration, so only current parameters are ever tried.
pub fn decrypt_slh_signing_seed(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; SLH_SIGNING_SEED_LEN]>, PqfileError> {
    decrypt_fixed_secret_no_legacy(body, passphrase, ENCRYPTED_SLH_SIGNING_BODY_LEN)
}

const IDENTITY_SEED_LEN: usize = 32;

/// Layout of the encrypted sealed-sender identity private key PEM body (76 bytes total):
///   0..16   salt
///   16..28  AES-GCM nonce
///   28..76  AES-256-GCM ciphertext (32-byte X25519 scalar + 16-byte tag)
pub const ENCRYPTED_IDENTITY_BODY_LEN: usize = SALT_LEN + NONCE_LEN + IDENTITY_SEED_LEN + 16;

/// Encrypts a 32-byte X25519 identity seed under `passphrase`. Returns the 76-byte
/// payload stored as the PEM body of an encrypted identity private key.
pub fn encrypt_identity_seed(
    seed: &[u8; IDENTITY_SEED_LEN],
    passphrase: &str,
) -> Result<Vec<u8>, PqfileError> {
    encrypt_fixed_secret(seed, passphrase, ENCRYPTED_IDENTITY_BODY_LEN)
}

/// Decrypts the 76-byte payload from an encrypted sealed-sender identity private key
/// PEM body. No legacy-parameter fallback: identity keys postdate the Argon2 p=4
/// migration, so only current parameters are ever tried.
pub fn decrypt_identity_seed(
    body: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; IDENTITY_SEED_LEN]>, PqfileError> {
    decrypt_fixed_secret_no_legacy(body, passphrase, ENCRYPTED_IDENTITY_BODY_LEN)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<LockedSecret<32>, PqfileError> {
    derive_key_with_pcost(passphrase, salt, ARGON2_P_COST)
}

fn derive_key_with_pcost(
    passphrase: &str,
    salt: &[u8],
    p_cost: u32,
) -> Result<LockedSecret<32>, PqfileError> {
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
) -> Result<LockedSecret<32>, PqfileError> {
    derive_key_with_params_and_secret(passphrase, None, salt, m_kib, t_cost, p_cost)
}

/// [`derive_key_with_params`] with an optional Argon2 secret (pepper) input.
/// Used by v10 keyfile mode: the secret is the keyfile hash from
/// [`keyfile_secret`], making decryption require both the passphrase
/// (something you know) and the keyfile (something you have).
pub(crate) fn derive_key_with_params_and_secret(
    passphrase: &str,
    secret: Option<&[u8]>,
    salt: &[u8],
    m_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<LockedSecret<32>, PqfileError> {
    let params =
        Params::new(m_kib, t_cost, p_cost, Some(32)).map_err(|_| PqfileError::EncryptionFailure)?;
    let argon2 = match secret {
        Some(s) => Argon2::new_with_secret(
            s,
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        )
        .map_err(|_| PqfileError::EncryptionFailure)?,
        None => Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params),
    };
    let mut key = LockedSecret::<32>::zeroed();
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    Ok(key)
}

/// Hashes raw keyfile bytes into the 32-byte Argon2 secret used by v10 keyfile
/// mode. Domain-separated so a keyfile that happens to contain other pqfile
/// material never collides with that material's own hash uses.
pub(crate) fn keyfile_secret(keyfile: &[u8]) -> LockedSecret<32> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"pqfile-keyfile-v1");
    hasher.update(keyfile);
    let mut out = LockedSecret::<32>::zeroed();
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Hashes a FIDO2 `hmac-secret` extension output into the 32-byte Argon2
/// secret used by v10 FIDO2 mode. The extension output is already a uniform
/// 32-byte HMAC-SHA256 value, so this hash exists purely for domain
/// separation from [`keyfile_secret`] and any other future pepper source,
/// mirroring that function's rationale rather than adding entropy.
pub(crate) fn fido2_secret(hmac_secret: &[u8; 32]) -> LockedSecret<32> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"pqfile-fido2-v1");
    hasher.update(hmac_secret);
    let mut out = LockedSecret::<32>::zeroed();
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Hashes a WebAuthn `prf` extension output into the 32-byte Argon2 secret
/// used by v10 WebAuthn-PRF mode. The browser-native equivalent of
/// [`fido2_secret`] - PRF eval output is already a uniform 32-byte value
/// (treated as opaque IKM, same as the FIDO2 hmac-secret output), so this
/// hash exists purely for domain separation from [`keyfile_secret`]/
/// [`fido2_secret`], mirroring their rationale rather than adding entropy.
pub(crate) fn webauthn_prf_secret(prf_output: &[u8; 32]) -> LockedSecret<32> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"pqfile-webauthn-prf-v1");
    hasher.update(prf_output);
    let mut out = LockedSecret::<32>::zeroed();
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Result of benchmarking Argon2id on this machine via [`calibrate`].
#[cfg(not(target_arch = "wasm32"))]
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct CalibrationResult {
    /// Recommended memory cost in KiB.
    pub m_kib: u32,
    /// Recommended time cost (iterations).
    pub t_cost: u32,
    /// Recommended parallelism (always the compiled-in default).
    pub p_cost: u32,
    /// Measured wall-clock time at the recommended parameters, in milliseconds.
    pub measured_ms: u64,
    /// Measured wall-clock time at the compiled-in defaults (m=64 MiB, t=3, p=4),
    /// in milliseconds.
    pub default_ms: u64,
}

/// Benchmarks Argon2id on this machine and recommends parameters whose
/// wall-clock cost is close to `target_ms` milliseconds.
///
/// Keeps t=3 and p=4 (the compiled-in defaults) and scales the memory cost,
/// which dominates both wall-clock time and attack cost; only once the memory
/// cost reaches its 1 GiB ceiling does the time cost grow instead. The memory
/// cost never drops below the compiled-in 64 MiB default — a fast machine gets
/// *stronger* parameters, never weaker ones, and a slow machine simply gets
/// the defaults back.
///
/// Argon2 wall-clock time is close to linear in both memory and time cost, so
/// one proportional jump from the default measurement plus one correction pass
/// lands near the target without a long search. Each probe allocates the full
/// memory cost, so a call may briefly allocate up to 1 GiB.
#[cfg(not(target_arch = "wasm32"))]
pub fn calibrate(target_ms: u64) -> Result<CalibrationResult, PqfileError> {
    const MIN_M_KIB: u32 = ARGON2_M_COST; // 64 MiB floor = compiled-in default
    const MAX_M_KIB: u32 = 1024 * 1024; // 1 GiB ceiling per probe
    const MAX_T_COST: u32 = 16;

    let target_ms = target_ms.max(1);

    let probe = |m_kib: u32, t_cost: u32| -> Result<u64, PqfileError> {
        let salt = [0x5au8; 16];
        let start = std::time::Instant::now();
        derive_key_with_params(
            "pqfile-calibration-probe",
            &salt,
            m_kib,
            t_cost,
            ARGON2_P_COST,
        )?;
        // A probe can complete in under a millisecond with a tiny cost; clamp
        // to 1 so the proportional scaling below never divides by zero.
        Ok((start.elapsed().as_millis() as u64).max(1))
    };

    // Round to whole MiB so the recommendation is stable across runs.
    let round_mib = |m_kib: u64| -> u32 {
        let clamped = m_kib.clamp(MIN_M_KIB as u64, MAX_M_KIB as u64) as u32;
        (clamped / 1024) * 1024
    };

    let default_ms = probe(ARGON2_M_COST, ARGON2_T_COST)?;

    let mut m_kib = round_mib((ARGON2_M_COST as u64 * target_ms) / default_ms);
    let mut t_cost = ARGON2_T_COST;
    let mut measured_ms = if m_kib == ARGON2_M_COST {
        default_ms
    } else {
        let first = probe(m_kib, t_cost)?;
        // One correction pass against the measured (not extrapolated) time.
        let corrected = round_mib((m_kib as u64 * target_ms) / first);
        if corrected == m_kib {
            first
        } else {
            m_kib = corrected;
            probe(m_kib, t_cost)?
        }
    };

    // Memory cost is pinned at the ceiling and still finishing early: grow the
    // time cost instead.
    if m_kib == MAX_M_KIB && measured_ms < target_ms {
        let scaled = (t_cost as u64 * target_ms) / measured_ms;
        let candidate = (scaled as u32).clamp(ARGON2_T_COST, MAX_T_COST);
        if candidate != t_cost {
            t_cost = candidate;
            measured_ms = probe(m_kib, t_cost)?;
        }
    }

    Ok(CalibrationResult {
        m_kib,
        t_cost,
        p_cost: ARGON2_P_COST,
        measured_ms,
        default_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers that produce legacy (p=1) bodies for migration tests ──────────

    fn encrypt_fixed_secret_legacy<const N: usize>(secret: &[u8; N], passphrase: &str) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).unwrap();
        let key = derive_key_with_pcost(passphrase, &salt, ARGON2_P_COST_LEGACY).unwrap();
        let cipher = Aes256Gcm::new(key.as_ref().try_into().expect("32-byte key"));
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).unwrap();
        let ct = cipher
            .encrypt(
                nonce_bytes.as_slice().try_into().expect("12-byte nonce"),
                secret.as_slice(),
            )
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    fn encrypt_seed_legacy(seed: &[u8; SEED_LEN], passphrase: &str) -> Vec<u8> {
        encrypt_fixed_secret_legacy(seed, passphrase)
    }

    fn encrypt_signing_seed_legacy(seed: &[u8; SIGNING_SEED_LEN], passphrase: &str) -> Vec<u8> {
        encrypt_fixed_secret_legacy(seed, passphrase)
    }

    fn encrypt_hybrid_seed_legacy(seed: &[u8; HYBRID_SEED_LEN], passphrase: &str) -> Vec<u8> {
        encrypt_fixed_secret_legacy(seed, passphrase)
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

    // ── Identity (p=4, no legacy form) ────────────────────────────────────────

    #[test]
    fn identity_roundtrip_correct_passphrase() {
        let seed = [0x77u8; IDENTITY_SEED_LEN];
        let body = encrypt_identity_seed(&seed, "identitypass").unwrap();
        assert_eq!(body.len(), ENCRYPTED_IDENTITY_BODY_LEN);
        let recovered = decrypt_identity_seed(&body, "identitypass").unwrap();
        assert_eq!(*recovered, seed);
    }

    #[test]
    fn identity_wrong_passphrase_returns_error() {
        let seed = [0x88u8; IDENTITY_SEED_LEN];
        let body = encrypt_identity_seed(&seed, "correct").unwrap();
        assert!(matches!(
            decrypt_identity_seed(&body, "wrong"),
            Err(PqfileError::WrongPassphrase)
        ));
    }

    #[test]
    fn identity_wrong_body_length_returns_error() {
        assert!(matches!(
            decrypt_identity_seed(&[0u8; 10], "pass"),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn calibrate_never_recommends_below_defaults() {
        // A 1 ms target clamps to the floor: the compiled-in defaults come
        // back and the default measurement is reused rather than re-probed.
        let r = calibrate(1).unwrap();
        assert_eq!(r.m_kib, ARGON2_M_COST);
        assert_eq!(r.t_cost, ARGON2_T_COST);
        assert_eq!(r.p_cost, ARGON2_P_COST);
        assert_eq!(r.measured_ms, r.default_ms);
        assert!(r.measured_ms >= 1);
    }
}
