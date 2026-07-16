//! WebAuthn `prf` extension glue for the WASM web build - the browser-native
//! equivalent of `fido2.rs`/`fido2_common.rs`'s CTAP2 hmac-secret second
//! factor (native only, unreachable from wasm32). Talks to
//! `navigator.credentials` via hand-written inline JS rather than web-sys's
//! unstable Credential Management bindings, so no `web_sys_unstable_apis`
//! cfg flag is needed anywhere in this build (local dev, CI, or trunk).
//!
//! `rp.id` is omitted in both the registration and derivation calls, letting
//! the browser default it to the page's effective domain; both calls always
//! happen on the same origin so this is consistent without plumbing a domain
//! string across the FFI boundary. `challenge` is required by the spec shape
//! but never verified (no server exists to verify it against) - generated
//! with `crypto.getRandomValues` inside the JS.
//!
//! Registers with `residentKey: "required"` (a discoverable credential),
//! matching the W3C PRF explainer's own example. This was *not* the original
//! design - an earlier version used a non-resident credential to mirror the
//! native FIDO2 second factor's own choice, on the theory that not consuming
//! an authenticator's limited resident-credential storage was worth it. That
//! turned out to be wrong in practice: Windows Hello's OS-level WebAuthn API
//! (`webauthn.dll`) hard-requires a resident credential before it will even
//! expose `hmac-secret`/PRF at all, so the non-resident choice silently broke
//! PRF on the most common desktop platform authenticator. Platform
//! authenticators (Windows Hello, iCloud Keychain, Android) don't have the
//! same tight resident-credential storage limits hardware security keys do,
//! so this tradeoff is a much better default overall.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::hex_lines::{from_hex, to_hex};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = "
export async function webauthnRegister() {
    if (!window.PublicKeyCredential) {
        throw 'WebAuthn is not supported in this browser.';
    }
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    const userId = new Uint8Array(16);
    crypto.getRandomValues(userId);
    let cred;
    try {
        cred = await navigator.credentials.create({
            publicKey: {
                challenge: challenge,
                rp: { name: 'pqfile' },
                user: { id: userId, name: 'pqfile-passkey', displayName: 'pqfile' },
                // ES256 only: RS256 buys nothing here (there is no server to
                // verify an attestation signature against), and RSA resident-
                // credential generation on TPM-backed platform authenticators
                // is a known source of flaky/transient CTAP2 failures.
                pubKeyCredParams: [
                    { type: 'public-key', alg: -7 }, // ES256
                ],
                authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
                extensions: { prf: {} },
            },
        });
    } catch (e) {
        throw (e && e.message) ? e.message : String(e);
    }
    const ext = cred.getClientExtensionResults();
    if (!ext || !ext.prf || !ext.prf.enabled) {
        throw 'This authenticator does not support the WebAuthn PRF extension.';
    }
    return new Uint8Array(cred.rawId);
}

export async function webauthnDerive(credentialId, salt) {
    if (!window.PublicKeyCredential) {
        throw 'WebAuthn is not supported in this browser.';
    }
    // Copy out of wasm linear memory before the await below - holding a raw
    // view across it risks pointing at stale/detached memory if the wasm
    // heap grows while we're waiting on the browser prompt.
    const credId = credentialId.slice();
    const saltBytes = salt.slice();
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                allowCredentials: [{ id: credId, type: 'public-key' }],
                userVerification: 'preferred',
                extensions: { prf: { eval: { first: saltBytes } } },
            },
        });
    } catch (e) {
        throw (e && e.message) ? e.message : String(e);
    }
    const ext = assertion.getClientExtensionResults();
    const result = ext && ext.prf && ext.prf.results && ext.prf.results.first;
    if (!result) {
        throw 'The authenticator did not return a PRF output.';
    }
    return new Uint8Array(result);
}
")]
extern "C" {
    #[wasm_bindgen(catch, js_name = webauthnRegister)]
    async fn register_js() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_name = webauthnDerive)]
    async fn derive_js(credential_id: &[u8], salt: &[u8]) -> Result<JsValue, JsValue>;
}

/// A WASM WebAuthn enrollment: just enough to re-derive the same secret
/// later. No `pin_required` field - browsers own their own passkey UX;
/// pqfile never sees a PIN. Serialized with the same hex-lines shape as
/// `fido2_common::Enrollment` for a consistent look across enrollment files,
/// but kept as its own, smaller type: that module pulls in `ctap-hid-fido2`
/// (native-only) and per its own doc comment isn't meant to be reused outside
/// pqfile-cli/pqfile-gui's native path.
pub(crate) struct Enrollment {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) credential_id: Vec<u8>,
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) salt: [u8; 32],
}

impl Enrollment {
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) fn serialize(&self) -> String {
        format!(
            "# pqfile WebAuthn passkey enrollment file.\n\
             #\n\
             # Not sensitive on its own: reproducing the derived secret requires\n\
             # presenting the same passkey (biometric/PIN unlock) that created this\n\
             # credential. Safe to store or transmit like ordinary configuration.\n\
             credential_id = {}\n\
             salt = {}\n",
            to_hex(&self.credential_id),
            to_hex(&self.salt),
        )
    }

    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        fn bad(msg: &str) -> String {
            format!("malformed WebAuthn enrollment file: {msg}")
        }

        let mut credential_id = None;
        let mut salt = None;
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
                other => return Err(bad(&format!("unknown key '{other}'"))),
            }
        }
        Ok(Enrollment {
            credential_id: credential_id.ok_or_else(|| bad("missing credential_id"))?,
            salt: salt.ok_or_else(|| bad("missing salt"))?,
        })
    }
}

#[cfg(target_arch = "wasm32")]
fn js_to_bytes(value: JsValue) -> Vec<u8> {
    js_sys::Uint8Array::new(&value).to_vec()
}

#[cfg(target_arch = "wasm32")]
fn js_err_to_string(e: JsValue) -> String {
    e.as_string().unwrap_or_else(|| format!("{e:?}"))
}

/// Registers a new non-resident WebAuthn credential requesting the `prf`
/// extension, generates a fresh random salt, and returns the resulting
/// [`Enrollment`]. Fails if the browser doesn't support WebAuthn or the
/// chosen authenticator doesn't support PRF.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn register() -> Result<Enrollment, String> {
    let credential_id = register_js()
        .await
        .map(js_to_bytes)
        .map_err(js_err_to_string)?;
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
    Ok(Enrollment {
        credential_id,
        salt,
    })
}

/// Presents `enrollment`'s credential and evaluates the `prf` extension with
/// its stored salt, returning the derived 32-byte secret. Prompts the user
/// for their passkey (biometric/PIN/security key touch).
#[cfg(target_arch = "wasm32")]
pub(crate) async fn derive_secret(
    enrollment: &Enrollment,
) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let bytes = derive_js(&enrollment.credential_id, &enrollment.salt)
        .await
        .map(js_to_bytes)
        .map_err(js_err_to_string)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "WebAuthn PRF output was not 32 bytes".to_owned())?;
    Ok(zeroize::Zeroizing::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_roundtrip() {
        let e = Enrollment {
            credential_id: vec![1, 2, 3, 4, 0xff],
            salt: [0x42u8; 32],
        };
        let text = e.serialize();
        let parsed = Enrollment::parse(&text).unwrap();
        assert_eq!(parsed.credential_id, e.credential_id);
        assert_eq!(parsed.salt, e.salt);
    }

    #[test]
    fn enrollment_parse_rejects_malformed() {
        assert!(Enrollment::parse("credential_id = zz\nsalt = 00\n").is_err());
        assert!(Enrollment::parse("salt = 00\n").is_err()); // missing credential_id
        assert!(Enrollment::parse("credential_id = 01\nsalt = 00\n").is_err()); // salt too short
        assert!(Enrollment::parse(
            "credential_id = 01\n\
             salt = 00112233445566778899aabbccddeeff00112233445566778899aabbccddee\n\
             bogus = 1\n"
        )
        .is_err());
    }
}
