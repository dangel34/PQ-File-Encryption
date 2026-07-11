//! GUI-specific glue for the FIDO2 hardware token second factor (desktop
//! only). The enrollment-file format and CTAP2 plumbing shared with
//! pqfile-cli live in `fido2_common`, physically reused here via `#[path]`
//! rather than a hand-copied twin - see that file's header comment for why it
//! lives inside pqfile-cli's source tree instead of a separate workspace
//! crate (pqfile-cli is published to crates.io; pqfile-gui is not, so only
//! pqfile-gui can safely reach across the workspace like this).
//!
//! The one API difference from the CLI is deliberate: the CLI blocks on a
//! terminal PIN prompt inside `derive_secret`, but a GUI can't block the UI
//! thread on stdin, so PIN entry here is a plain text field the caller reads
//! first (see [`enrollment_requires_pin`]) and passes in explicitly.

#[path = "../../pqfile-cli/src/fido2_common.rs"]
mod fido2_common;

use std::path::Path;

use zeroize::Zeroizing;

use pqfile::error::PqfileError;

/// Peeks whether an enrollment file was created with a PIN, without touching
/// the token. Returns `None` if the file can't be read or parsed - callers
/// treat that the same as "unknown", surfacing the real error later when the
/// operation actually runs.
pub fn enrollment_requires_pin(enrollment_path: &Path) -> Option<bool> {
    fido2_common::enrollment_requires_pin(enrollment_path)
}

/// Creates a non-resident CTAP2 credential on the attached authenticator with
/// the `hmac-secret` extension requested, generates a fresh random salt, and
/// writes both (plus whether `pin` was supplied) to `output`. Blocks on
/// physical touch; run on a background thread.
pub fn enroll(output: &Path, pin: Option<&str>) -> Result<(), PqfileError> {
    fido2_common::enroll(output, pin)
}

/// Re-derives the 32-byte secret enrolled at `enrollment_path` by presenting
/// its credential ID and salt back to an attached token via the CTAP2
/// `hmac-secret` extension. Blocks on physical touch; run on a background
/// thread. `pin` must be `Some` whenever [`enrollment_requires_pin`] returned
/// `Some(true)` for the same file - unlike the CLI, this never prompts itself.
pub fn derive_secret(
    enrollment_path: &Path,
    pin: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    fido2_common::derive_secret(enrollment_path, pin)
}
