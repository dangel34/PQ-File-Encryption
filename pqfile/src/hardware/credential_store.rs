/// Credential-store hardware backend.
///
/// Stores the private key seed in the OS credential store:
/// - **Windows**: Windows Credential Manager (user-bound; optionally TPM-backed
///   on machines where the user profile is protected by Windows Hello / TPM)
/// - **macOS**: macOS Keychain (user-session-bound)
/// - **Linux**: Secret Service (GNOME Keyring / KDE Wallet; requires a running
///   session daemon)
///
/// The seed is hex-encoded before storage (credential stores expect string values).
/// The credential is keyed by `"pqfile:{label}"` under the service name `"pqfile"`.
use zeroize::Zeroizing;

use crate::error::PqfileError;

use super::stub::HardwareKeyRef;

pub(super) struct CredentialStoreBackend;

impl CredentialStoreBackend {
    /// Stores `seed` in the credential store under the key derived from `key_ref`.
    pub fn store_seed(&self, key_ref: &HardwareKeyRef, seed: &[u8]) -> Result<(), PqfileError> {
        let account = account_name(&key_ref.label);
        let entry = keyring::Entry::new("pqfile", &account).map_err(hw_err)?;
        let encoded = Zeroizing::new(hex_encode(seed));
        entry.set_password(encoded.as_str()).map_err(hw_err)
    }

    /// Loads the seed from the credential store.
    ///
    /// Returns `Io(NotFound)` if no credential exists for this label.
    pub fn load_seed(&self, key_ref: &HardwareKeyRef) -> Result<Zeroizing<Vec<u8>>, PqfileError> {
        let account = account_name(&key_ref.label);
        let entry = keyring::Entry::new("pqfile", &account).map_err(hw_err)?;
        let encoded = Zeroizing::new(entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "hardware key '{}' not found in the OS credential store; \
                         was it generated on a different machine or user account?",
                    key_ref.label
                ),
            )),
            other => hw_err(other),
        })?);
        hex_decode(encoded.as_str()).map_err(|_| {
            PqfileError::InvalidPem(format!(
                "hardware key '{}' credential store entry is corrupted",
                key_ref.label
            ))
        })
    }

    /// Removes the credential from the store.
    #[allow(dead_code)]
    pub fn delete_seed(&self, key_ref: &HardwareKeyRef) -> Result<(), PqfileError> {
        let account = account_name(&key_ref.label);
        let entry = keyring::Entry::new("pqfile", &account).map_err(hw_err)?;
        entry.delete_password().map_err(hw_err)
    }
}

fn account_name(label: &str) -> String {
    // Prefix with "pqfile:" to namespace our credentials and avoid collisions.
    format!("pqfile:{label}")
}

fn hw_err(e: impl std::fmt::Display) -> PqfileError {
    PqfileError::Io(std::io::Error::other(format!(
        "hardware key credential store error: {e}"
    )))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let bytes: Result<Vec<u8>, _> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect();
    bytes.map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_decode_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "deadbeef00ff");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(*decoded, data);
    }

    #[test]
    fn hex_decode_rejects_odd_length() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_rejects_non_hex() {
        assert!(hex_decode("zz").is_err());
    }
}
