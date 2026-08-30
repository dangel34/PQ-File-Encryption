//! Minimal hex encode/decode and enrollment-file field parsing, shared by the
//! two second-factor enrollment-file formats: pqfile-cli/pqfile-gui's native
//! FIDO2 (`fido2_common`) and pqfile-gui's WASM WebAuthn PRF (`webauthn`,
//! pulled in via `#[path]` since it must compile on `wasm32-unknown-unknown`
//! where `fido2_common` cannot - it depends on `ctap-hid-fido2`, a
//! native-only crate). Dependency-free on purpose so both targets can pull it
//! in without complication.

/// Unused when pqfile-gui's `webauthn` module pulls this file in for a
/// native (non-wasm32) build: only its `Enrollment::serialize`, which is
/// wasm32-only, calls this.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// Fields common to every pqfile second-factor enrollment file, plus any
/// unrecognized `key = value` lines for the caller's own format-specific
/// fields (e.g. FIDO2's `pin_required`) to handle.
type CommonEnrollmentFields<'a> = (Vec<u8>, [u8; 32], Vec<(&'a str, &'a str)>);

/// Parses the `credential_id`/`salt` fields common to every pqfile
/// second-factor enrollment file, skipping blank lines and `#` comments.
/// Lines with any other key are returned unparsed so callers with additional
/// fields (FIDO2's `pin_required`) can handle those themselves; `bad` builds
/// this format's own error message/type.
pub(crate) fn parse_enrollment_common<E>(
    text: &str,
    bad: impl Fn(&str) -> E,
) -> Result<CommonEnrollmentFields<'_>, E> {
    let mut credential_id = None;
    let mut salt = None;
    let mut extra = Vec::new();
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
            _ => extra.push((key, value)),
        }
    }
    Ok((
        credential_id.ok_or_else(|| bad("missing credential_id"))?,
        salt.ok_or_else(|| bad("missing salt"))?,
        extra,
    ))
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
}
