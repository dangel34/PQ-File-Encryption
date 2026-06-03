use pem::Pem;

use crate::error::PqfileError;
use crate::keygen::{PRIV_ENC_TAG, PRIV_ENC_TAG_1024, PRIV_ENC_TAG_512, PRIV_ENC_TAG_HYBRID_768};
use crate::passphrase;
use crate::sign::{SK_ENC_TAG, SK_TAG, VK_TAG};

/// Result of a successful `repassphrase` operation.
#[non_exhaustive]
pub struct RepassphraseResult {
    /// The re-encrypted private key PEM, ready to be written to disk.
    pub privkey_pem: String,
}

/// Changes or upgrades the passphrase on any encrypted private key.
///
/// # Parameters
///
/// - `privkey_pem` - The current (encrypted) private key PEM.
/// - `old_passphrase` - The passphrase currently protecting the key.
/// - `new_passphrase` - The passphrase to apply after re-encryption.
/// - `from_legacy` - When `true`, reads the key using legacy Argon2id p=1
///   parameters (pqfile < 4.0). **Must** be set when migrating an old key;
///   omitting it on a p=1 key returns `PqfileError::LegacyKeyFormat`.
///
/// # Supported key types
///
/// ML-KEM-512, ML-KEM-768, ML-KEM-1024, hybrid X25519+ML-KEM-768, and
/// ML-DSA-65 signing keys. Passing an unencrypted or public key returns
/// `PqfileError::InvalidPem`.
///
/// # Errors
///
/// - `LegacyKeyFormat` - key is p=1 and `from_legacy` was not set.
/// - `WrongPassphrase` - `old_passphrase` is incorrect.
/// - `InvalidPem` - not an encrypted private key.
#[must_use = "repassphrase result must be saved or the re-encrypted key is lost"]
pub fn repassphrase(
    privkey_pem: &str,
    old_passphrase: &str,
    new_passphrase: &str,
    from_legacy: bool,
) -> Result<RepassphraseResult, PqfileError> {
    let parsed = pem::parse(privkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    let new_pem = match parsed.tag() {
        // ── ML-KEM-512/768/1024 encrypted keys (64-byte seed) ────────────────
        t @ (PRIV_ENC_TAG | PRIV_ENC_TAG_512 | PRIV_ENC_TAG_1024) => {
            let seed = if from_legacy {
                passphrase::decrypt_seed_legacy(parsed.contents(), old_passphrase)?
            } else {
                passphrase::decrypt_seed(parsed.contents(), old_passphrase)?
            };
            let new_body = passphrase::encrypt_seed(&seed, new_passphrase)?;
            pem::encode(&Pem::new(t, new_body))
        }

        // ── Hybrid X25519+ML-KEM-768 encrypted key (96-byte seed) ────────────
        t @ PRIV_ENC_TAG_HYBRID_768 => {
            let seed = if from_legacy {
                passphrase::decrypt_hybrid_seed_legacy(parsed.contents(), old_passphrase)?
            } else {
                passphrase::decrypt_hybrid_seed(parsed.contents(), old_passphrase)?
            };
            let new_body = passphrase::encrypt_hybrid_seed(&seed, new_passphrase)?;
            pem::encode(&Pem::new(t, new_body))
        }

        // ── ML-DSA-65 encrypted signing key (32-byte seed) ───────────────────
        t @ SK_ENC_TAG => {
            let seed = if from_legacy {
                passphrase::decrypt_signing_seed_legacy(parsed.contents(), old_passphrase)?
            } else {
                passphrase::decrypt_signing_seed(parsed.contents(), old_passphrase)?
            };
            let new_body = passphrase::encrypt_signing_seed(&seed, new_passphrase)?;
            pem::encode(&Pem::new(t, new_body))
        }

        // ── Unencrypted or public keys ────────────────────────────────────────
        t @ SK_TAG => Err(PqfileError::InvalidPem(format!(
            "'{t}' is not encrypted; use `pqfile sign-keygen --passphrase` to create \
             an encrypted signing key"
        )))?,

        t @ VK_TAG => Err(PqfileError::InvalidPem(format!(
            "'{t}' is a public verifying key, not a private key"
        )))?,

        tag => Err(PqfileError::InvalidPem(format!(
            "expected an encrypted private key PEM, got '{tag}'; \
             unencrypted keys do not need repassphrase"
        )))?,
    };

    Ok(RepassphraseResult {
        privkey_pem: new_pem,
    })
}

/// Write the re-encrypted private key in-place, replacing the file at `path`.
///
/// The file is only overwritten after the re-encryption succeeds; on error the
/// original file is untouched.
#[must_use = "write result must be checked"]
pub fn repassphrase_file(
    path: &std::path::Path,
    old_passphrase: &str,
    new_passphrase: &str,
    from_legacy: bool,
) -> Result<(), PqfileError> {
    let pem_str = std::fs::read_to_string(path)?;
    let result = repassphrase(&pem_str, old_passphrase, new_passphrase, from_legacy)?;
    std::fs::write(path, result.privkey_pem.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use crate::sign::sign_keygen_bytes;

    // ── Current p=4 keys: change passphrase ──────────────────────────────────

    // Helper: encrypt a small payload to pub_pem, then decrypt with priv_pem + passphrase.
    fn enc_dec_roundtrip(pub_pem: &str, priv_pem: &str, passphrase: &str) {
        let plaintext = b"repassphrase roundtrip";
        let mut enc = Vec::new();
        crate::encrypt::encrypt_stream(
            pub_pem,
            plaintext.len() as u64,
            crate::format::CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();
        let mut out = Vec::new();
        crate::decrypt::decrypt_stream(priv_pem, &mut enc.as_slice(), &mut out, Some(passphrase))
            .expect("decrypt with new passphrase should succeed");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn repassphrase_768_changes_passphrase() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("old")).unwrap();
        let r = repassphrase(&priv_pem, "old", "new", false).unwrap();
        enc_dec_roundtrip(&pub_pem, &r.privkey_pem, "new");
    }

    #[test]
    fn repassphrase_768_old_passphrase_no_longer_works() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("old")).unwrap();
        let r = repassphrase(&priv_pem, "old", "new", false).unwrap();
        let plaintext = b"test";
        let mut enc = Vec::new();
        crate::encrypt::encrypt_stream(
            &pub_pem,
            4,
            crate::format::CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();
        let mut out = Vec::new();
        let result = crate::decrypt::decrypt_stream(
            &r.privkey_pem,
            &mut enc.as_slice(),
            &mut out,
            Some("old"),
        );
        assert!(
            result.is_err(),
            "old passphrase should no longer decrypt the key"
        );
    }

    #[test]
    fn repassphrase_512_roundtrip() {
        let (pub_pem, priv_pem) = keygen_bytes(512, Some("old512")).unwrap();
        let r = repassphrase(&priv_pem, "old512", "new512", false).unwrap();
        enc_dec_roundtrip(&pub_pem, &r.privkey_pem, "new512");
    }

    #[test]
    fn repassphrase_1024_roundtrip() {
        let (pub_pem, priv_pem) = keygen_bytes(1024, Some("old1024")).unwrap();
        let r = repassphrase(&priv_pem, "old1024", "new1024", false).unwrap();
        enc_dec_roundtrip(&pub_pem, &r.privkey_pem, "new1024");
    }

    #[test]
    fn repassphrase_hybrid_roundtrip() {
        let (pub_pem, priv_pem) =
            crate::keygen::keygen_bytes_hybrid_768(Some("old-hybrid")).unwrap();
        let r = repassphrase(&priv_pem, "old-hybrid", "new-hybrid", false).unwrap();
        enc_dec_roundtrip(&pub_pem, &r.privkey_pem, "new-hybrid");
    }

    #[test]
    fn repassphrase_hybrid_old_passphrase_no_longer_works() {
        let (pub_pem, priv_pem) = crate::keygen::keygen_bytes_hybrid_768(Some("old")).unwrap();
        let r = repassphrase(&priv_pem, "old", "new", false).unwrap();
        let plaintext = b"test";
        let mut enc = Vec::new();
        crate::encrypt::encrypt_stream(
            &pub_pem,
            4,
            crate::format::CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();
        let mut out = Vec::new();
        let err = crate::decrypt::decrypt_stream(
            &r.privkey_pem,
            &mut enc.as_slice(),
            &mut out,
            Some("old"),
        );
        assert!(
            err.is_err(),
            "old passphrase should no longer work after repassphrase"
        );
    }

    #[test]
    fn repassphrase_signing_key_roundtrip() {
        let sk = sign_keygen_bytes(Some("oldsign")).unwrap();
        let r = repassphrase(&sk.sk_pem, "oldsign", "newsign", false).unwrap();
        // Verify the new key signs and verifies correctly.
        let sig = crate::sign::sign_bytes(&r.privkey_pem, b"hello", Some("newsign")).unwrap();
        crate::sign::verify_bytes(&sk.vk_pem, b"hello", &sig).unwrap();
    }

    #[test]
    fn repassphrase_wrong_old_passphrase_returns_wrong_passphrase() {
        let (_, priv_pem) = keygen_bytes(768, Some("correct")).unwrap();
        assert!(matches!(
            repassphrase(&priv_pem, "wrong", "new", false),
            Err(PqfileError::WrongPassphrase)
        ));
    }

    #[test]
    fn repassphrase_unencrypted_key_returns_invalid_pem() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        assert!(matches!(
            repassphrase(&priv_pem, "any", "new", false),
            Err(PqfileError::InvalidPem(_))
        ));
    }

    #[test]
    fn repassphrase_public_key_returns_invalid_pem() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        assert!(matches!(
            repassphrase(&pub_pem, "any", "new", false),
            Err(PqfileError::InvalidPem(_))
        ));
    }

    // ── Legacy (p=1) migration ────────────────────────────────────────────────

    #[test]
    fn legacy_key_without_from_legacy_returns_legacy_key_format() {
        let (pub_pem, priv_pem) = keygen_bytes(768, Some("pass")).unwrap();
        // Simulate a legacy key by re-encrypting the seed with p=1 manually.
        let parsed = pem::parse(&priv_pem).unwrap();
        let seed = crate::passphrase::decrypt_seed(parsed.contents(), "pass").unwrap();
        let legacy_body = {
            use aes_gcm::{
                aead::{Aead, KeyInit},
                Aes256Gcm, Key, Nonce,
            };
            let mut salt = [0u8; 16];
            getrandom::fill(&mut salt).unwrap();
            let params = argon2::Params::new(65536, 3, 1, Some(32)).unwrap();
            let argon2 =
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut key_bytes = [0u8; 32];
            argon2
                .hash_password_into("pass".as_bytes(), &salt, &mut key_bytes)
                .unwrap();
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
            let mut nonce_bytes = [0u8; 12];
            getrandom::fill(&mut nonce_bytes).unwrap();
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), seed.as_slice())
                .unwrap();
            let mut b = Vec::new();
            b.extend_from_slice(&salt);
            b.extend_from_slice(&nonce_bytes);
            b.extend_from_slice(&ct);
            b
        };
        let legacy_pem = pem::encode(&pem::Pem::new(crate::keygen::PRIV_ENC_TAG, legacy_body));

        // Without --from-legacy: LegacyKeyFormat
        assert!(matches!(
            repassphrase(&legacy_pem, "pass", "new", false),
            Err(PqfileError::LegacyKeyFormat)
        ));

        // With --from-legacy: success; result decrypts correctly with new passphrase.
        let r = repassphrase(&legacy_pem, "pass", "new", true).unwrap();
        // pub_pem matches the same underlying key seed as legacy_pem (both derived from priv_pem).
        enc_dec_roundtrip(&pub_pem, &r.privkey_pem, "new");
    }
}
