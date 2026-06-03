/// Hardware key PEM stub encode/decode.
///
/// A hardware key PEM stub is a small PEM file whose body identifies:
/// - which backend holds the key
/// - the user-visible label used to retrieve it
///
/// Body layout (version 1):
/// ```text
/// [0]      version   = 0x01
/// [1]      backend_id
/// [2..]    label     (UTF-8, no length prefix; occupies the rest of the body)
/// ```
///
/// The label is also used as the account name inside the credential store,
/// prefixed with "pqfile:" to avoid collisions with other applications.
#[cfg(not(target_arch = "wasm32"))]
use crate::error::PqfileError;

/// Backend ID for the OS credential store (Windows Credential Manager,
/// macOS Keychain, or Linux Secret Service).
pub const BACKEND_CREDENTIAL_STORE: u8 = 0x01;

/// Backend ID reserved for a future PKCS#11 hardware token backend.
pub const BACKEND_PKCS11: u8 = 0x02;

#[cfg(not(target_arch = "wasm32"))]
const STUB_VERSION: u8 = 0x01;

/// Decoded contents of a hardware key PEM stub body.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
pub(crate) struct HardwareKeyRef {
    /// Identifies which backend holds the key (e.g. `BACKEND_CREDENTIAL_STORE`).
    pub backend_id: u8,
    /// User-provided label, used as the credential-store account key.
    pub label: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl HardwareKeyRef {
    /// Encodes the key reference into stub body bytes.
    pub fn encode(&self) -> Vec<u8> {
        let label_bytes = self.label.as_bytes();
        let mut out = Vec::with_capacity(2 + label_bytes.len());
        out.push(STUB_VERSION);
        out.push(self.backend_id);
        out.extend_from_slice(label_bytes);
        out
    }

    /// Decodes stub body bytes into a `HardwareKeyRef`.
    pub fn decode(body: &[u8]) -> Result<Self, PqfileError> {
        if body.len() < 2 {
            return Err(PqfileError::InvalidPem(
                "hardware key stub body too short".into(),
            ));
        }
        if body[0] != STUB_VERSION {
            return Err(PqfileError::InvalidPem(format!(
                "unsupported hardware key stub version: {:#04x}",
                body[0]
            )));
        }
        let backend_id = body[1];
        let label = String::from_utf8(body[2..].to_vec()).map_err(|_| {
            PqfileError::InvalidPem("hardware key stub label is not valid UTF-8".into())
        })?;
        if label.is_empty() {
            return Err(PqfileError::InvalidPem(
                "hardware key stub label is empty".into(),
            ));
        }
        Ok(Self { backend_id, label })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let r = HardwareKeyRef {
            backend_id: BACKEND_CREDENTIAL_STORE,
            label: "my-key".into(),
        };
        let body = r.encode();
        let decoded = HardwareKeyRef::decode(&body).unwrap();
        assert_eq!(decoded.backend_id, BACKEND_CREDENTIAL_STORE);
        assert_eq!(decoded.label, "my-key");
    }

    #[test]
    fn decode_rejects_empty_body() {
        assert!(HardwareKeyRef::decode(&[]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let body = [0xFF, BACKEND_CREDENTIAL_STORE, b'k', b'e', b'y'];
        assert!(HardwareKeyRef::decode(&body).is_err());
    }

    #[test]
    fn decode_rejects_empty_label() {
        let body = [STUB_VERSION, BACKEND_CREDENTIAL_STORE];
        assert!(HardwareKeyRef::decode(&body).is_err());
    }

    #[test]
    fn encode_decode_unicode_label() {
        let r = HardwareKeyRef {
            backend_id: BACKEND_CREDENTIAL_STORE,
            label: "🔑 my key".into(),
        };
        let body = r.encode();
        let decoded = HardwareKeyRef::decode(&body).unwrap();
        assert_eq!(decoded.label, "🔑 my key");
    }
}
