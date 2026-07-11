//! CLI-specific glue for the FIDO2 hardware token second factor. The
//! enrollment-file format and CTAP2 plumbing shared with pqfile-gui live in
//! [`fido2_common`]; this module adds the one CLI-specific behavior that
//! genuinely differs from the GUI: blocking on a terminal PIN prompt before
//! deriving the secret, since a CLI (unlike a GUI event loop) is free to
//! block on stdin.

#[path = "fido2_common.rs"]
mod fido2_common;

use std::path::Path;

use zeroize::Zeroizing;

use pqfile::error::PqfileError;

/// Creates a non-resident CTAP2 credential on the attached authenticator with
/// the `hmac-secret` extension requested, generates a fresh random salt, and
/// writes both (plus whether `pin` was supplied) to `output`.
///
/// Caller is responsible for any overwrite-existing-file policy before
/// calling this: the device is touched (and the credential created) before
/// anything is written, so failing an overwrite check afterward would waste
/// the user's touch for nothing.
pub fn enroll(output: &Path, pin: Option<&str>) -> Result<(), PqfileError> {
    fido2_common::enroll(output, pin)
}

/// Re-derives the 32-byte secret enrolled at `enrollment_path` by presenting
/// its credential ID and salt back to an attached token via the CTAP2
/// `hmac-secret` extension. Requires physically touching the token; prompts
/// for a PIN first if the enrollment recorded one.
pub fn derive_secret(enrollment_path: &Path) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let requires_pin = fido2_common::enrollment_requires_pin(enrollment_path).unwrap_or(false);
    let pin = if requires_pin {
        Some(Zeroizing::new(
            rpassword::prompt_password("Enter FIDO2 PIN: ").map_err(PqfileError::Io)?,
        ))
    } else {
        None
    };
    fido2_common::derive_secret(enrollment_path, pin.as_deref().map(|z| z.as_str()))
}
