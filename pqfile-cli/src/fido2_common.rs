//! Shared FIDO2 enrollment-file format and CTAP2 plumbing for the `fido2`
//! feature of both pqfile-cli and pqfile-gui.
//!
//! This file is the single source of truth: pqfile-gui's `fido2.rs` pulls it
//! in via `#[path = "../../pqfile-cli/src/fido2_common.rs"]` rather than
//! keeping a hand-copied twin. It lives inside pqfile-cli's own source tree
//! (not a separate workspace crate) specifically because pqfile-cli is
//! published to crates.io: a path dependency on an unpublished internal crate
//! would break `cargo publish -p pqfile-cli` (verified empirically - `cargo
//! publish` requires every dependency, including optional ones behind a
//! non-default feature, to already exist on the target registry). pqfile-gui
//! is never published, so it can safely reach across the workspace like this;
//! pqfile-cli cannot.
//!
//! Enrolls a non-resident CTAP2 credential requesting the `hmac-secret`
//! extension, then re-derives the same 32-byte secret later by presenting the
//! enrolled credential ID and a fixed salt back to the same physical token.
//! The token's internal per-credential key never leaves the device; only the
//! HMAC output crosses USB.
//!
//! The enrollment file this writes down (credential ID, salt, whether a PIN
//! is needed) is not sensitive on its own: reproducing the secret requires
//! physically touching the same token, so the file is handled like ordinary
//! configuration, not like key material. Non-resident (non-discoverable)
//! credentials are used deliberately: they don't consume a token's limited
//! resident-credential storage, and every FIDO2 authenticator supports them.

use std::fs;
use std::path::Path;

use ctap_hid_fido2::fidokey::{
    AssertionExtension, CredentialExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
use zeroize::Zeroizing;

use pqfile::error::PqfileError;

/// Fixed relying-party ID for every pqfile FIDO2 credential. pqfile is not a
/// web origin and enrollments are looked up by their stored credential ID
/// rather than enumerated per RP, so any constant string works here.
const RPID: &str = "pqfile";

pub(crate) fn ctap_err(context: &str, e: impl std::fmt::Display) -> PqfileError {
    PqfileError::Io(std::io::Error::other(format!(
        "FIDO2 {context} failed: {e}. Is a compatible security key plugged in \
         (and touched, if it is waiting for a touch)?"
    )))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    // Byte-oriented on purpose: indexing the original `&str` by offset would
    // panic if a multi-byte UTF-8 character straddled an odd boundary.
    // `from_utf8` on each 2-byte pair fails cleanly (`None`) instead. This
    // matters here more than most parsers: the GUI's `enrollment_requires_pin`
    // re-reads and re-parses the enrollment file every UI frame it's on
    // screen, so a panic here would crash the whole egui event loop, not just
    // one operation.
    bytes
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

pub(crate) struct Enrollment {
    pub(crate) credential_id: Vec<u8>,
    pub(crate) salt: [u8; 32],
    pub(crate) pin_required: bool,
}

impl Enrollment {
    fn serialize(&self) -> String {
        format!(
            "# pqfile FIDO2 enrollment file.\n\
             #\n\
             # Not sensitive on its own: reproducing the derived secret requires\n\
             # physically touching the same hardware token that created this\n\
             # credential. Safe to store or transmit like ordinary configuration.\n\
             credential_id = {}\n\
             salt = {}\n\
             pin_required = {}\n",
            to_hex(&self.credential_id),
            to_hex(&self.salt),
            self.pin_required,
        )
    }

    pub(crate) fn parse(text: &str) -> Result<Self, PqfileError> {
        fn bad(msg: &str) -> PqfileError {
            PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("malformed FIDO2 enrollment file: {msg}"),
            ))
        }

        let mut credential_id = None;
        let mut salt = None;
        let mut pin_required = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(bad(&format!("expected 'key = value', got {line:?}")));
            };
            let (key, value) = (key.trim(), value.trim());
            match key {
                "credential_id" => {
                    credential_id =
                        Some(from_hex(value).ok_or_else(|| bad("credential_id is not valid hex"))?);
                }
                "salt" => {
                    let bytes = from_hex(value).ok_or_else(|| bad("salt is not valid hex"))?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| bad("salt must be exactly 32 bytes"))?;
                    salt = Some(arr);
                }
                "pin_required" => {
                    pin_required = Some(match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err(bad("pin_required must be true or false")),
                    });
                }
                other => return Err(bad(&format!("unknown key '{other}'"))),
            }
        }
        Ok(Enrollment {
            credential_id: credential_id.ok_or_else(|| bad("missing credential_id"))?,
            salt: salt.ok_or_else(|| bad("missing salt"))?,
            pin_required: pin_required.ok_or_else(|| bad("missing pin_required"))?,
        })
    }
}

/// Peeks whether an enrollment file was created with a PIN, without touching
/// the token. Returns `None` if the file can't be read or parsed - callers
/// treat that the same as "unknown", surfacing the real error later when the
/// operation actually runs.
pub(crate) fn enrollment_requires_pin(enrollment_path: &Path) -> Option<bool> {
    let text = fs::read_to_string(enrollment_path).ok()?;
    Enrollment::parse(&text).ok().map(|e| e.pin_required)
}

/// Creates a non-resident CTAP2 credential on the attached authenticator with
/// the `hmac-secret` extension requested, generates a fresh random salt, and
/// writes both (plus whether `pin` was supplied) to `output`.
///
/// Caller is responsible for any overwrite-existing-file policy before
/// calling this: the device is touched (and the credential created) before
/// anything is written, so failing an overwrite check afterward would waste
/// the user's touch for nothing.
pub(crate) fn enroll(output: &Path, pin: Option<&str>) -> Result<(), PqfileError> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| ctap_err("device open", e))?;

    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| PqfileError::EncryptionFailure)?;

    let mut builder = MakeCredentialArgsBuilder::new(RPID, &challenge)
        .extensions(&[CredentialExtension::HmacSecret(Some(true))]);
    if let Some(pin) = pin {
        builder = builder.pin(pin);
    }
    let attestation = device
        .make_credential_with_args(&builder.build())
        .map_err(|e| ctap_err("credential creation", e))?;

    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|_| PqfileError::EncryptionFailure)?;

    let enrollment = Enrollment {
        credential_id: attestation.credential_descriptor.id,
        salt,
        pin_required: pin.is_some(),
    };
    fs::write(output, enrollment.serialize())?;
    Ok(())
}

/// Re-derives the 32-byte secret enrolled at `enrollment_path` by presenting
/// its credential ID and salt back to an attached token via the CTAP2
/// `hmac-secret` extension. Requires physically touching the token.
///
/// `pin` must already be resolved by the caller (a terminal prompt for the
/// CLI, a GUI text field for pqfile-gui) - this function never itself blocks
/// on stdin, so it works the same way from a background GUI thread as it does
/// from a CLI's main thread.
pub(crate) fn derive_secret(
    enrollment_path: &Path,
    pin: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let text = fs::read_to_string(enrollment_path)?;
    let enrollment = Enrollment::parse(&text)?;

    let device = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| ctap_err("device open", e))?;

    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| PqfileError::EncryptionFailure)?;

    let mut builder = GetAssertionArgsBuilder::new(RPID, &challenge)
        .credential_id(&enrollment.credential_id)
        .extensions(&[AssertionExtension::HmacSecret(Some(enrollment.salt))]);
    if let Some(pin) = pin {
        builder = builder.pin(pin);
    }
    let assertions = device
        .get_assertion_with_args(&builder.build())
        .map_err(|e| ctap_err("assertion", e))?;

    assertions
        .first()
        .and_then(|a| {
            a.extensions.iter().find_map(|e| {
                if let AssertionExtension::HmacSecret(Some(output)) = e {
                    Some(*output)
                } else {
                    None
                }
            })
        })
        .map(Zeroizing::new)
        .ok_or_else(|| {
            PqfileError::Io(std::io::Error::other(
                "FIDO2 token did not return an hmac-secret output; it may not support the \
                 extension",
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes = [0x00, 0x01, 0x0a, 0xff, 0x42];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn from_hex_rejects_odd_length() {
        assert!(from_hex("abc").is_none());
    }

    #[test]
    fn from_hex_rejects_non_hex_chars() {
        assert!(from_hex("zz").is_none());
    }

    #[test]
    fn from_hex_rejects_multibyte_utf8_without_panicking() {
        assert!(from_hex("a€bc").is_none());
    }

    #[test]
    fn enrollment_roundtrip_without_pin() {
        let e = Enrollment {
            credential_id: vec![0xDE, 0xAD, 0xBE, 0xEF],
            salt: [0x5A; 32],
            pin_required: false,
        };
        let parsed = Enrollment::parse(&e.serialize()).unwrap();
        assert_eq!(parsed.credential_id, e.credential_id);
        assert_eq!(parsed.salt, e.salt);
        assert_eq!(parsed.pin_required, e.pin_required);
    }

    #[test]
    fn enrollment_roundtrip_with_pin() {
        let e = Enrollment {
            credential_id: vec![1, 2, 3],
            salt: [0x11; 32],
            pin_required: true,
        };
        let parsed = Enrollment::parse(&e.serialize()).unwrap();
        assert!(parsed.pin_required);
    }

    #[test]
    fn enrollment_parse_rejects_missing_field() {
        let text = "credential_id = aabb\nsalt = ".to_string() + &"11".repeat(32);
        // pin_required omitted entirely.
        assert!(Enrollment::parse(&text).is_err());
    }

    #[test]
    fn enrollment_parse_rejects_short_salt() {
        let text = format!(
            "credential_id = aabb\nsalt = {}\npin_required = false\n",
            "11".repeat(16) // 16 bytes, not 32
        );
        assert!(Enrollment::parse(&text).is_err());
    }

    #[test]
    fn enrollment_parse_rejects_unknown_key() {
        let text = format!(
            "credential_id = aabb\nsalt = {}\npin_required = false\nbogus = 1\n",
            "11".repeat(32)
        );
        assert!(Enrollment::parse(&text).is_err());
    }

    #[test]
    fn enrollment_parse_ignores_comments_and_blank_lines() {
        let text = format!(
            "# a comment\n\n   \ncredential_id = aabb\nsalt = {}\npin_required = true\n",
            "22".repeat(32)
        );
        let parsed = Enrollment::parse(&text).unwrap();
        assert_eq!(parsed.credential_id, vec![0xaa, 0xbb]);
        assert!(parsed.pin_required);
    }

    #[test]
    fn enrollment_requires_pin_none_on_missing_file() {
        assert_eq!(
            enrollment_requires_pin(Path::new("/does/not/exist/pqfile-fido2.txt")),
            None
        );
    }
}
