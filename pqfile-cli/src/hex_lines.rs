//! Minimal hex encode/decode, shared by the two second-factor enrollment-file
//! formats: pqfile-cli/pqfile-gui's native FIDO2 (`fido2_common`) and
//! pqfile-gui's WASM WebAuthn PRF (`webauthn`, pulled in via `#[path]` since
//! it must compile on `wasm32-unknown-unknown` where `fido2_common` cannot -
//! it depends on `ctap-hid-fido2`, a native-only crate). Dependency-free on
//! purpose so both targets can pull it in without complication.

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
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
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
