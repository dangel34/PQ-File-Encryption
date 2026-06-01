use std::fs;
use std::path::{Path, PathBuf};

use crate::error::PqfileError;
use crate::keygen::fingerprint_pem;

/// Returns the path of the `.revoked` sidecar for a given public key path.
#[must_use]
pub fn revoked_path_for(pubkey_path: &Path) -> PathBuf {
    let mut s = pubkey_path.as_os_str().to_owned();
    s.push(".revoked");
    PathBuf::from(s)
}

/// Creates a `.revoked` sidecar file alongside the public key.
///
/// The sidecar contains the key fingerprint and an optional reason string.
/// On the next encrypt with this key path, `check_not_revoked` will fail.
#[must_use = "revocation result must be checked"]
pub fn revoke_key(pubkey_path: &Path, reason: &str) -> Result<String, PqfileError> {
    let pubkey_pem = fs::read_to_string(pubkey_path)?;
    let fingerprint = fingerprint_pem(&pubkey_pem);

    let revoked_path = revoked_path_for(pubkey_path);
    let content = format!(
        "{{\"fingerprint\":\"{fingerprint}\",\"reason\":{}}}",
        json_str(reason),
    );
    fs::write(&revoked_path, content.as_bytes())?;
    Ok(fingerprint)
}

/// Checks whether the public key file at `pubkey_path` has been revoked.
///
/// Reads the `.revoked` sidecar if it exists and compares the fingerprint.
/// Returns `Err(KeyRevoked)` if revoked, `Ok(())` otherwise.
#[must_use = "revocation check must be inspected; ignoring it means encrypting to revoked keys"]
pub fn check_not_revoked(pubkey_path: &Path, pubkey_pem: &str) -> Result<(), PqfileError> {
    let revoked_path = revoked_path_for(pubkey_path);
    if !revoked_path.exists() {
        return Ok(());
    }

    let json = fs::read_to_string(&revoked_path).unwrap_or_default();
    let fp_in_file = extract_json_str(&json, "fingerprint").unwrap_or_default();
    let reason = extract_json_str(&json, "reason").unwrap_or_default();
    let fp_of_key = fingerprint_pem(pubkey_pem);

    // If fingerprints are present and match (or sidecar has no valid fingerprint), refuse.
    if fp_in_file.is_empty() || fp_of_key == fp_in_file {
        return Err(PqfileError::KeyRevoked {
            fingerprint: fp_of_key,
            reason,
        });
    }
    Ok(())
}

// ── minimal JSON helpers (avoids pulling in serde_json at runtime) ─────────

fn json_str(s: &str) -> String {
    let escaped: String = s
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c => vec![c],
        })
        .collect();
    format!("\"{escaped}\"")
}

/// Extracts the value of `key` from a simple flat JSON object (no nesting).
fn extract_json_str(json: &str, key: &str) -> Option<String> {
    // Include the colon in the needle so "fingerprint": never matches a
    // key like "fingerprint_extra": (prefix-key bypass prevention).
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let after_colon = json[pos + needle.len()..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let inner = &after_colon[1..];
    let mut result = String::new();
    let mut chars = inner.chars();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                c => {
                    result.push('\\');
                    result.push(c);
                }
            },
            c => result.push(c),
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use tempfile::tempdir;

    #[test]
    fn revoke_creates_sidecar_file() {
        let tmp = tempdir().unwrap();
        let pub_path = tmp.path().join("pubkey.pem");
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        std::fs::write(&pub_path, &pub_pem).unwrap();
        revoke_key(&pub_path, "test reason").unwrap();
        assert!(revoked_path_for(&pub_path).exists());
    }

    #[test]
    fn check_not_revoked_passes_without_sidecar() {
        let tmp = tempdir().unwrap();
        let pub_path = tmp.path().join("pubkey.pem");
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        std::fs::write(&pub_path, &pub_pem).unwrap();
        check_not_revoked(&pub_path, &pub_pem).unwrap();
    }

    #[test]
    fn check_not_revoked_fails_after_revoke() {
        let tmp = tempdir().unwrap();
        let pub_path = tmp.path().join("pubkey.pem");
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        std::fs::write(&pub_path, &pub_pem).unwrap();
        revoke_key(&pub_path, "compromised").unwrap();
        let err = check_not_revoked(&pub_path, &pub_pem).unwrap_err();
        assert!(matches!(err, PqfileError::KeyRevoked { .. }));
    }

    #[test]
    fn revoke_returns_fingerprint() {
        let tmp = tempdir().unwrap();
        let pub_path = tmp.path().join("pubkey.pem");
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        std::fs::write(&pub_path, &pub_pem).unwrap();
        let fp = revoke_key(&pub_path, "").unwrap();
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 16);
    }

    #[test]
    fn revoke_stores_reason_in_sidecar() {
        let tmp = tempdir().unwrap();
        let pub_path = tmp.path().join("pubkey.pem");
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        std::fs::write(&pub_path, &pub_pem).unwrap();
        revoke_key(&pub_path, "key was leaked").unwrap();
        let sidecar = std::fs::read_to_string(revoked_path_for(&pub_path)).unwrap();
        assert!(sidecar.contains("key was leaked"));
    }

    #[test]
    fn revoke_error_message_includes_reason() {
        let tmp = tempdir().unwrap();
        let pub_path = tmp.path().join("pubkey.pem");
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        std::fs::write(&pub_path, &pub_pem).unwrap();
        revoke_key(&pub_path, "lost my laptop").unwrap();
        let err = check_not_revoked(&pub_path, &pub_pem).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("lost my laptop"));
    }
}
