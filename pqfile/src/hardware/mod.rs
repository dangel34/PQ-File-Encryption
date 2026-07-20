/// Hardware-backed private key support.
///
/// Hardware keys store the private key seed in an OS credential store rather than
/// on disk, protecting against disk-theft and offline attacks. The seed is
/// retrieved from the credential store when needed (briefly entering process
/// memory), then zeroized after use.
///
/// # Supported backends
///
/// | Backend ID | Platform | Storage |
/// |-----------|----------|---------|
/// | `BACKEND_CREDENTIAL_STORE` (1) | Windows | Windows Credential Manager |
/// | `BACKEND_CREDENTIAL_STORE` (1) | macOS | macOS Keychain |
/// | `BACKEND_CREDENTIAL_STORE` (1) | Linux | Secret Service (GNOME/KDE) |
///
/// PKCS#11 hardware token support (YubiKey, smart cards) is tracked as a
/// future backend.
///
/// # Security model
///
/// The seed is never stored unprotected on disk. Unlike passphrase-protected
/// keys (which can be brute-forced offline), hardware keys require access to
/// the specific machine/user context managed by the OS credential store.
/// The seed transiently enters process memory only during KEM/signing
/// operations and is zeroized immediately after.
pub mod stub;

#[cfg(not(target_arch = "wasm32"))]
mod credential_store;

use zeroize::Zeroizing;

use crate::error::PqfileError;

// ── PEM tag constants ─────────────────────────────────────────────────────

/// PEM tag for an ML-KEM-512 hardware key reference.
pub const HW_TAG_512: &str = "ML-KEM-512 HARDWARE KEY REFERENCE";
/// PEM tag for an ML-KEM-768 hardware key reference.
pub const HW_TAG_768: &str = "ML-KEM-768 HARDWARE KEY REFERENCE";
/// PEM tag for an ML-KEM-1024 hardware key reference.
pub const HW_TAG_1024: &str = "ML-KEM-1024 HARDWARE KEY REFERENCE";
/// PEM tag for a hybrid X25519+ML-KEM-768 hardware key reference.
pub const HW_TAG_HYBRID_768: &str = "X25519+ML-KEM-768 HARDWARE KEY REFERENCE";
/// PEM tag for an ML-DSA-65 hardware signing key reference.
pub const HW_TAG_SIGNING: &str = "ML-DSA-65 HARDWARE SIGNING KEY REFERENCE";
/// PEM tag for an SLH-DSA-SHAKE-192f hardware signing key reference.
pub const HW_TAG_SIGNING_SLH: &str = "SLH-DSA-SHAKE-192F HARDWARE SIGNING KEY REFERENCE";

/// Returns `true` if `tag` is any hardware key PEM tag.
///
/// Useful for library consumers that receive a raw PEM string and need to
/// distinguish hardware stubs from plaintext or passphrase-encrypted keys
/// before deciding how to proceed.
pub fn is_hardware_tag(tag: &str) -> bool {
    matches!(
        tag,
        HW_TAG_512
            | HW_TAG_768
            | HW_TAG_1024
            | HW_TAG_HYBRID_768
            | HW_TAG_SIGNING
            | HW_TAG_SIGNING_SLH
    )
}

// ── Seed operations ───────────────────────────────────────────────────────

/// Generates a new random seed, stores it in the hardware backend identified
/// by `backend_id`, and returns `(stub_body, seed)`.
///
/// The caller uses `seed` once to derive the public key PEM, then drops it
/// (triggering zeroization). Subsequent access to the seed goes through
/// [`load_seed`].
pub(crate) fn generate_and_store(
    label: &str,
    seed_len: usize,
    backend_id: u8,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), PqfileError> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (label, seed_len, backend_id);
        return Err(wasm_unsupported());
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut seed = Zeroizing::new(vec![0u8; seed_len]);
        getrandom::fill(seed.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;

        let key_ref = stub::HardwareKeyRef {
            backend_id,
            label: label.to_owned(),
        };

        dispatch_store(backend_id, &key_ref, &seed)?;

        let stub_body = key_ref.encode();
        Ok((stub_body, seed))
    }
}

/// Loads a seed from the hardware backend described by the stub PEM body bytes.
pub(crate) fn load_seed(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, PqfileError> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = body;
        return Err(wasm_unsupported());
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let key_ref = stub::HardwareKeyRef::decode(body)?;
        dispatch_load(key_ref.backend_id, &key_ref)
    }
}

/// Returns the recommended backend ID for the current platform.
pub fn default_backend_id() -> u8 {
    stub::BACKEND_CREDENTIAL_STORE
}

// ── Internal dispatch ─────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn dispatch_store(
    backend_id: u8,
    key_ref: &stub::HardwareKeyRef,
    seed: &[u8],
) -> Result<(), PqfileError> {
    match backend_id {
        stub::BACKEND_CREDENTIAL_STORE => {
            credential_store::CredentialStoreBackend.store_seed(key_ref, seed)
        }
        id => Err(unknown_backend(id)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn dispatch_load(
    backend_id: u8,
    key_ref: &stub::HardwareKeyRef,
) -> Result<Zeroizing<Vec<u8>>, PqfileError> {
    match backend_id {
        stub::BACKEND_CREDENTIAL_STORE => {
            credential_store::CredentialStoreBackend.load_seed(key_ref)
        }
        id => Err(unknown_backend(id)),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn unknown_backend(id: u8) -> PqfileError {
    PqfileError::Io(std::io::Error::other(format!(
        "unknown hardware key backend: {id:#04x}"
    )))
}

#[cfg(target_arch = "wasm32")]
fn wasm_unsupported() -> PqfileError {
    PqfileError::Io(std::io::Error::other(
        "hardware keys are not supported on WASM builds",
    ))
}
