//! Interactive passphrase prompting, shared by every command that loads a
//! possibly passphrase-protected private/signing/identity key.

use pqfile::error::PqfileError;
use pqfile::{keygen, sealed_sender};

/// Prompts for a passphrase if `pem_str` is an encrypted (non-hardware) private key.
/// Returns `None` for plaintext keys and hardware stubs; hardware backends
/// handle their own authentication inside the OS credential store.
pub(crate) fn maybe_prompt_passphrase(
    pem_str: &str,
    prompt: &str,
) -> Result<Option<zeroize::Zeroizing<String>>, PqfileError> {
    if keygen::is_hardware_key(pem_str) {
        Ok(None)
    } else if keygen::is_encrypted_key(pem_str)
        || sealed_sender::is_identity_key_encrypted(pem_str)
        || pqfile::keys::PqfSigningKey::from_pem(pem_str)
            .map(|k| k.is_encrypted())
            .unwrap_or(false)
    {
        Ok(Some(prompt_passphrase(prompt)?))
    } else {
        Ok(None)
    }
}

pub(crate) fn prompt_new_passphrase() -> Result<zeroize::Zeroizing<String>, PqfileError> {
    let pp = zeroize::Zeroizing::new(
        rpassword::prompt_password("Enter passphrase: ").map_err(PqfileError::Io)?,
    );
    let confirm = zeroize::Zeroizing::new(
        rpassword::prompt_password("Confirm passphrase: ").map_err(PqfileError::Io)?,
    );
    if *pp != *confirm {
        return Err(PqfileError::PassphraseMismatch);
    }
    Ok(pp)
}

pub(crate) fn prompt_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>, PqfileError> {
    Ok(zeroize::Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(PqfileError::Io)?,
    ))
}
