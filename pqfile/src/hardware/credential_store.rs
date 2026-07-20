/// Credential-store hardware backend.
///
/// Stores the private key seed in the OS credential store:
/// - **Windows**: Windows Credential Manager (user-bound; optionally TPM-backed
///   on machines where the user profile is protected by Windows Hello / TPM)
/// - **macOS**: macOS Keychain (user-session-bound)
/// - **Linux**: Linux kernel keyutils (session keyring; no daemon required)
///
/// The seed is stored as raw bytes via the credential store's byte-native secret
/// API. The credential is keyed by `"pqfile:{label}"` under the service name
/// `"pqfile"`.
///
/// Versions of pqfile prior to the byte-native storage switch hex-encoded the
/// seed and stored it via the string-based password API; [`CredentialStoreBackend::load_seed`]
/// detects and transparently decodes that legacy format so existing hardware
/// keys keep working after an upgrade.
use std::collections::HashMap;
use std::sync::OnceLock;

use keyring_core::{set_default_store, Entry, Error as KeyringError};
use zeroize::Zeroizing;

use crate::error::PqfileError;

use super::stub::HardwareKeyRef;

pub(super) struct CredentialStoreBackend;

static STORE_INIT: OnceLock<Result<(), String>> = OnceLock::new();

fn ensure_store() -> Result<(), PqfileError> {
    STORE_INIT
        .get_or_init(init_platform_store)
        .as_ref()
        .map(|_| ())
        .map_err(|e| {
            PqfileError::Io(std::io::Error::other(format!(
                "hardware key store init failed: {e}"
            )))
        })
}

#[cfg(target_os = "windows")]
fn init_platform_store() -> Result<(), String> {
    use windows_native_keyring_store::Store;
    set_default_store(Store::new_with_configuration(&HashMap::new()).map_err(|e| e.to_string())?);
    Ok(())
}

#[cfg(target_os = "macos")]
fn init_platform_store() -> Result<(), String> {
    use apple_native_keyring_store::keychain::Store;
    set_default_store(Store::new_with_configuration(&HashMap::new()).map_err(|e| e.to_string())?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn init_platform_store() -> Result<(), String> {
    use linux_keyutils_keyring_store::Store;
    set_default_store(Store::new_with_configuration(&HashMap::new()).map_err(|e| e.to_string())?);
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn init_platform_store() -> Result<(), String> {
    Err("hardware keys are not supported on this platform".to_string())
}

impl CredentialStoreBackend {
    /// Stores `seed` in the credential store under the key derived from `key_ref`.
    pub fn store_seed(&self, key_ref: &HardwareKeyRef, seed: &[u8]) -> Result<(), PqfileError> {
        ensure_store()?;
        let account = account_name(&key_ref.label);
        let entry = Entry::new("pqfile", &account).map_err(hw_err)?;
        entry.set_secret(seed).map_err(hw_err)
    }

    /// Loads the seed from the credential store.
    ///
    /// Returns `Io(NotFound)` if no credential exists for this label.
    pub fn load_seed(&self, key_ref: &HardwareKeyRef) -> Result<Zeroizing<Vec<u8>>, PqfileError> {
        ensure_store()?;
        let account = account_name(&key_ref.label);
        let entry = Entry::new("pqfile", &account).map_err(hw_err)?;
        let secret = Zeroizing::new(entry.get_secret().map_err(|e| match e {
            KeyringError::NoEntry => PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "hardware key '{}' not found in the OS credential store; \
                         was it generated on a different machine or user account?",
                    key_ref.label
                ),
            )),
            other => hw_err(other),
        })?);
        Ok(decode_legacy_hex_seed(&secret).unwrap_or(secret))
    }
}

fn account_name(label: &str) -> String {
    format!("pqfile:{label}")
}

fn hw_err(e: impl std::fmt::Display) -> PqfileError {
    PqfileError::Io(std::io::Error::other(format!(
        "hardware key credential store error: {e}"
    )))
}

/// Detects and decodes a seed stored by pqfile versions that hex-encoded the
/// seed before saving it via the string-based password API. Genuine raw seed
/// bytes are effectively never an all-lowercase-hex-digit byte string of even
/// length (each byte would need to fall in a 22/256 subrange), so this check
/// cannot misclassify a real seed as legacy-encoded.
fn decode_legacy_hex_seed(secret: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if secret.is_empty() || !secret.len().is_multiple_of(2) {
        return None;
    }
    if !secret
        .iter()
        .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let decoded: Vec<u8> = (0..secret.len())
        .step_by(2)
        .map(|i| {
            let hi = (secret[i] as char)
                .to_digit(16)
                .expect("validated hex digit above");
            let lo = (secret[i + 1] as char)
                .to_digit(16)
                .expect("validated hex digit above");
            ((hi << 4) | lo) as u8
        })
        .collect();
    Some(Zeroizing::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_legacy_hex_seed_roundtrip() {
        let data = vec![0xDEu8, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        let decoded = decode_legacy_hex_seed(hex.as_bytes()).unwrap();
        assert_eq!(*decoded, data);
    }

    #[test]
    fn decode_legacy_hex_seed_rejects_odd_length() {
        assert!(decode_legacy_hex_seed(b"abc").is_none());
    }

    #[test]
    fn decode_legacy_hex_seed_rejects_non_hex() {
        assert!(decode_legacy_hex_seed(b"zzzz").is_none());
    }

    #[test]
    fn decode_legacy_hex_seed_rejects_raw_seed_bytes() {
        // A real seed is full-range random bytes; this is not a valid hex string
        // (0x9A is outside the ASCII hex-digit range), so it must pass through
        // unchanged rather than being misinterpreted as legacy hex.
        let seed = [0x9Au8; 64];
        assert!(decode_legacy_hex_seed(&seed).is_none());
    }
}
