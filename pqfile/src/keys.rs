/// Typed key wrappers for the pqfile public API.
///
/// These types let downstream crates work with keys as structured values
/// instead of passing raw PEM strings everywhere.  Each type is a thin
/// wrapper that parses and validates the PEM on construction, caches the
/// KEM variant and fingerprint, and re-exposes the PEM string for use with
/// the existing encrypt/decrypt/sign functions.
///
/// Encryption key pair:
///   ```no_run
///   use pqfile::keys::{PqfPublicKey, PqfPrivateKey};
///
///   let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(768, None).unwrap();
///   let pubkey = PqfPublicKey::from_pem(&pub_pem).unwrap();
///   let privkey = PqfPrivateKey::from_pem(&priv_pem).unwrap();
///
///   println!("variant: {}", pubkey.kem_variant());
///   println!("fingerprint: {}", pubkey.fingerprint());
///   ```
use crate::error::PqfileError;
use crate::format::{KEM_VARIANT_1024, KEM_VARIANT_512, KEM_VARIANT_768, KEM_VARIANT_HYBRID_768};
use crate::keygen::{
    fingerprint, PRIV_ENC_TAG, PRIV_ENC_TAG_1024, PRIV_ENC_TAG_512, PRIV_ENC_TAG_HYBRID_768,
    PRIV_TAG, PRIV_TAG_1024, PRIV_TAG_512, PRIV_TAG_HYBRID_768, PUB_TAG, PUB_TAG_1024, PUB_TAG_512,
    PUB_TAG_HYBRID_768,
};

/// A parsed and validated ML-KEM (or hybrid) public key.
///
/// Construct with [`PqfPublicKey::from_pem`]. The PEM is validated on
/// construction; subsequent uses of [`PqfPublicKey::as_pem`] are infallible.
#[derive(Clone)]
pub struct PqfPublicKey {
    pem: String,
    kem_variant: u16,
    fingerprint: String,
}

impl PqfPublicKey {
    /// Parse a public key PEM string and return a typed key.
    ///
    /// Returns `Err(InvalidPem)` if the PEM tag is not a recognised public key
    /// tag, or if the key bytes have the wrong length.
    pub fn from_pem(pem_str: &str) -> Result<Self, PqfileError> {
        let parsed = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
        let kem_variant = match parsed.tag() {
            t if t == PUB_TAG_512 => KEM_VARIANT_512,
            t if t == PUB_TAG => KEM_VARIANT_768,
            t if t == PUB_TAG_1024 => KEM_VARIANT_1024,
            t if t == PUB_TAG_HYBRID_768 => KEM_VARIANT_HYBRID_768,
            tag => {
                return Err(PqfileError::InvalidPem(format!(
                    "unrecognised public key tag: {tag}"
                )))
            }
        };
        let fp = fingerprint(parsed.contents());
        Ok(PqfPublicKey {
            pem: pem_str.to_owned(),
            kem_variant,
            fingerprint: fp,
        })
    }

    /// The KEM variant identifier (512, 768, 1024, or 0x0301 for hybrid).
    pub fn kem_variant(&self) -> u16 {
        self.kem_variant
    }

    /// SHA3-256 fingerprint of the public key bytes (first 16 bytes, colon-separated hex).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// The PEM string, suitable for passing to `encrypt::encrypt_stream` etc.
    pub fn as_pem(&self) -> &str {
        &self.pem
    }

    /// Friendly name for the algorithm (e.g. `"ML-KEM-768"`, `"X25519+ML-KEM-768"`).
    pub fn algorithm_name(&self) -> &'static str {
        algorithm_name(self.kem_variant)
    }
}

impl std::fmt::Display for PqfPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PqfPublicKey({}, {})",
            self.algorithm_name(),
            self.fingerprint
        )
    }
}

impl std::fmt::Debug for PqfPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqfPublicKey")
            .field("algorithm", &self.algorithm_name())
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// A parsed and validated ML-KEM (or hybrid) private key.
///
/// Encrypted keys are identified at construction time; to use an encrypted key
/// you must supply the passphrase to the relevant decrypt/rekey function.
#[derive(Clone)]
pub struct PqfPrivateKey {
    pem: String,
    kem_variant: u16,
    encrypted: bool,
}

impl PqfPrivateKey {
    /// Parse a private key PEM string and return a typed key.
    ///
    /// Validates the PEM tag and identifies the KEM variant and whether the key is
    /// passphrase-encrypted. Returns `Err(InvalidPem)` if the tag is not a recognised
    /// private key tag.
    ///
    /// To use an encrypted private key for decryption or rekeying, pass the passphrase
    /// to the relevant function (e.g. [`crate::decrypt::decrypt_stream`]). To derive
    /// the corresponding public key from an encrypted private key, use
    /// [`PqfPrivateKey::to_public_key`] with the passphrase.
    pub fn from_pem(pem_str: &str) -> Result<Self, PqfileError> {
        let parsed = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
        let (kem_variant, encrypted) = match parsed.tag() {
            t if t == PRIV_TAG_512 => (KEM_VARIANT_512, false),
            t if t == PRIV_TAG => (KEM_VARIANT_768, false),
            t if t == PRIV_TAG_1024 => (KEM_VARIANT_1024, false),
            t if t == PRIV_TAG_HYBRID_768 => (KEM_VARIANT_HYBRID_768, false),
            t if t == PRIV_ENC_TAG_512 => (KEM_VARIANT_512, true),
            t if t == PRIV_ENC_TAG => (KEM_VARIANT_768, true),
            t if t == PRIV_ENC_TAG_1024 => (KEM_VARIANT_1024, true),
            t if t == PRIV_ENC_TAG_HYBRID_768 => (KEM_VARIANT_HYBRID_768, true),
            tag => {
                return Err(PqfileError::InvalidPem(format!(
                    "unrecognised private key tag: {tag}"
                )))
            }
        };
        Ok(PqfPrivateKey {
            pem: pem_str.to_owned(),
            kem_variant,
            encrypted,
        })
    }

    /// The KEM variant identifier.
    pub fn kem_variant(&self) -> u16 {
        self.kem_variant
    }

    /// Whether the key seed is passphrase-encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// The PEM string, suitable for passing to `decrypt::decrypt_stream` etc.
    pub fn as_pem(&self) -> &str {
        &self.pem
    }

    /// Friendly algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        algorithm_name(self.kem_variant)
    }

    /// Derives the corresponding public key from this unencrypted private key.
    ///
    /// Returns `Err(PassphraseRequired)` if the key is encrypted and no passphrase
    /// was provided.
    pub fn to_public_key(&self, passphrase: Option<&str>) -> Result<PqfPublicKey, PqfileError> {
        if self.encrypted && passphrase.is_none() {
            return Err(PqfileError::PassphraseRequired);
        }
        // Use the existing keygen module to regenerate the public key from the seed.
        // For unencrypted keys we can read the seed directly; for encrypted keys we
        // decrypt it using the passphrase.
        let pub_pem = derive_public_pem_from_private(&self.pem, passphrase)?;
        PqfPublicKey::from_pem(&pub_pem)
    }
}

impl std::fmt::Debug for PqfPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqfPrivateKey")
            .field("algorithm", &self.algorithm_name())
            .field("encrypted", &self.encrypted)
            .finish()
    }
}

/// A parsed and validated signing key (ML-DSA-65 or SLH-DSA-SHAKE-192f).
///
/// Encrypted signing keys are identified at construction; supply the passphrase
/// to the relevant sign/signcrypt function.
#[derive(Clone)]
pub struct PqfSigningKey {
    pem: String,
    encrypted: bool,
    algorithm: &'static str,
}

impl PqfSigningKey {
    /// Parse a signing key PEM string (ML-DSA-65 or SLH-DSA-SHAKE-192f).
    pub fn from_pem(pem_str: &str) -> Result<Self, PqfileError> {
        let parsed = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
        let (encrypted, algorithm) = match parsed.tag() {
            t if t == crate::sign::SK_TAG => (false, "ML-DSA-65"),
            t if t == crate::sign::SK_ENC_TAG => (true, "ML-DSA-65"),
            t if t == crate::sign::SLH_SK_TAG => (false, "SLH-DSA-SHAKE-192f"),
            t if t == crate::sign::SLH_SK_ENC_TAG => (true, "SLH-DSA-SHAKE-192f"),
            tag => {
                return Err(PqfileError::InvalidPem(format!(
                    "unrecognised signing key tag: {tag}"
                )))
            }
        };
        Ok(PqfSigningKey {
            pem: pem_str.to_owned(),
            encrypted,
            algorithm,
        })
    }

    /// Whether the signing seed is passphrase-encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Human-readable signature algorithm name.
    pub fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// The PEM string, suitable for passing to `sign::sign_bytes` etc.
    pub fn as_pem(&self) -> &str {
        &self.pem
    }
}

impl std::fmt::Debug for PqfSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqfSigningKey")
            .field("algorithm", &self.algorithm)
            .field("encrypted", &self.encrypted)
            .finish()
    }
}

/// A parsed and validated verifying (public) key (ML-DSA-65 or SLH-DSA-SHAKE-192f).
#[derive(Clone)]
pub struct PqfVerifyingKey {
    pem: String,
    fingerprint: String,
    algorithm: &'static str,
}

impl PqfVerifyingKey {
    /// Parse a verifying key PEM string (ML-DSA-65 or SLH-DSA-SHAKE-192f).
    pub fn from_pem(pem_str: &str) -> Result<Self, PqfileError> {
        let parsed = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
        let algorithm = match parsed.tag() {
            t if t == crate::sign::VK_TAG => "ML-DSA-65",
            t if t == crate::sign::SLH_VK_TAG => "SLH-DSA-SHAKE-192f",
            tag => {
                return Err(PqfileError::InvalidPem(format!(
                    "expected '{}' or '{}', got '{tag}'",
                    crate::sign::VK_TAG,
                    crate::sign::SLH_VK_TAG,
                )))
            }
        };
        let fp = fingerprint(parsed.contents());
        Ok(PqfVerifyingKey {
            pem: pem_str.to_owned(),
            fingerprint: fp,
            algorithm,
        })
    }

    /// SHA3-256 fingerprint of the verifying key bytes.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Human-readable signature algorithm name.
    pub fn algorithm(&self) -> &'static str {
        self.algorithm
    }

    /// The PEM string, suitable for passing to `sign::verify_bytes` etc.
    pub fn as_pem(&self) -> &str {
        &self.pem
    }
}

impl std::fmt::Debug for PqfVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqfVerifyingKey")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

pub(crate) fn algorithm_name(kem_variant: u16) -> &'static str {
    match kem_variant {
        KEM_VARIANT_512 => "ML-KEM-512",
        KEM_VARIANT_768 => "ML-KEM-768",
        KEM_VARIANT_1024 => "ML-KEM-1024",
        KEM_VARIANT_HYBRID_768 => "X25519+ML-KEM-768",
        _ => "unknown",
    }
}

/// Derives the public key PEM from a private key PEM, handling all variants.
fn derive_public_pem_from_private(
    priv_pem: &str,
    passphrase: Option<&str>,
) -> Result<String, PqfileError> {
    use crate::format::HYBRID_SEED_LEN_768;
    use crate::kem_backend::{ActiveKemBackend, KemBackend, KemSize};
    use crate::passphrase;
    use pem::Pem;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
    use zeroize::Zeroizing;

    let parsed = pem::parse(priv_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    match parsed.tag() {
        t if t == PRIV_TAG_512 || t == PRIV_ENC_TAG_512 => {
            let seed = load_seed_64(t, parsed.contents(), passphrase)?;
            let s: &[u8; 64] = seed
                .as_slice()
                .try_into()
                .map_err(|_| bad_len(64, seed.len()))?;
            let ek_bytes = ActiveKemBackend::ek_from_seed(KemSize::Kem512, s);
            Ok(pem::encode(&Pem::new(PUB_TAG_512, ek_bytes)))
        }
        t if t == PRIV_TAG || t == PRIV_ENC_TAG => {
            let seed = load_seed_64(t, parsed.contents(), passphrase)?;
            let s: &[u8; 64] = seed
                .as_slice()
                .try_into()
                .map_err(|_| bad_len(64, seed.len()))?;
            let ek_bytes = ActiveKemBackend::ek_from_seed(KemSize::Kem768, s);
            Ok(pem::encode(&Pem::new(PUB_TAG, ek_bytes)))
        }
        t if t == PRIV_TAG_1024 || t == PRIV_ENC_TAG_1024 => {
            let seed = load_seed_64(t, parsed.contents(), passphrase)?;
            let s: &[u8; 64] = seed
                .as_slice()
                .try_into()
                .map_err(|_| bad_len(64, seed.len()))?;
            let ek_bytes = ActiveKemBackend::ek_from_seed(KemSize::Kem1024, s);
            Ok(pem::encode(&Pem::new(PUB_TAG_1024, ek_bytes)))
        }
        t if t == PRIV_TAG_HYBRID_768 || t == PRIV_ENC_TAG_HYBRID_768 => {
            let seed: Zeroizing<Vec<u8>> = if t == PRIV_ENC_TAG_HYBRID_768 {
                let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
                Zeroizing::new(passphrase::decrypt_hybrid_seed(parsed.contents(), pp)?.to_vec())
            } else {
                if parsed.contents().len() != HYBRID_SEED_LEN_768 {
                    return Err(bad_len(HYBRID_SEED_LEN_768, parsed.contents().len()));
                }
                Zeroizing::new(parsed.contents().to_vec())
            };
            let x25519_sk = X25519StaticSecret::from(<[u8; 32]>::try_from(&seed[..32]).unwrap());
            let x25519_pk = X25519PublicKey::from(&x25519_sk);
            let ml_s: &[u8; 64] = seed[32..]
                .try_into()
                .map_err(|_| bad_len(64, seed.len() - 32))?;
            let ml_ek = ActiveKemBackend::ek_from_seed(KemSize::Kem768, ml_s);
            let mut pub_bytes = Vec::new();
            pub_bytes.extend_from_slice(x25519_pk.as_bytes());
            pub_bytes.extend_from_slice(&ml_ek);
            Ok(pem::encode(&Pem::new(PUB_TAG_HYBRID_768, pub_bytes)))
        }
        tag => Err(PqfileError::InvalidPem(format!(
            "unrecognised private key tag: {tag}"
        ))),
    }
}

fn load_seed_64(
    tag: &str,
    body: &[u8],
    passphrase: Option<&str>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, PqfileError> {
    use crate::passphrase;
    use zeroize::Zeroizing;

    if tag == PRIV_ENC_TAG_512 || tag == PRIV_ENC_TAG || tag == PRIV_ENC_TAG_1024 {
        let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
        Ok(Zeroizing::new(passphrase::decrypt_seed(body, pp)?.to_vec()))
    } else {
        if body.len() != 64 {
            return Err(bad_len(64, body.len()));
        }
        Ok(Zeroizing::new(body.to_vec()))
    }
}

fn bad_len(expected: usize, got: usize) -> PqfileError {
    PqfileError::InvalidKeyLength { expected, got }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{keygen_bytes, keygen_bytes_hybrid_768};
    use crate::sign::sign_keygen_bytes;

    #[test]
    fn public_key_from_pem_768() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let k = PqfPublicKey::from_pem(&pub_pem).unwrap();
        assert_eq!(k.kem_variant(), KEM_VARIANT_768);
        assert_eq!(k.algorithm_name(), "ML-KEM-768");
        assert_eq!(k.fingerprint().split(':').count(), 16);
    }

    #[test]
    fn public_key_from_pem_512() {
        let (pub_pem, _) = keygen_bytes(512, None).unwrap();
        let k = PqfPublicKey::from_pem(&pub_pem).unwrap();
        assert_eq!(k.kem_variant(), KEM_VARIANT_512);
        assert_eq!(k.algorithm_name(), "ML-KEM-512");
    }

    #[test]
    fn public_key_from_pem_1024() {
        let (pub_pem, _) = keygen_bytes(1024, None).unwrap();
        let k = PqfPublicKey::from_pem(&pub_pem).unwrap();
        assert_eq!(k.kem_variant(), KEM_VARIANT_1024);
        assert_eq!(k.algorithm_name(), "ML-KEM-1024");
    }

    #[test]
    fn public_key_from_pem_hybrid() {
        let (pub_pem, _) = keygen_bytes_hybrid_768(None).unwrap();
        let k = PqfPublicKey::from_pem(&pub_pem).unwrap();
        assert_eq!(k.kem_variant(), KEM_VARIANT_HYBRID_768);
        assert_eq!(k.algorithm_name(), "X25519+ML-KEM-768");
    }

    #[test]
    fn public_key_rejects_invalid_pem() {
        assert!(PqfPublicKey::from_pem("not pem").is_err());
    }

    #[test]
    fn public_key_rejects_private_key_pem() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        assert!(PqfPublicKey::from_pem(&priv_pem).is_err());
    }

    #[test]
    fn private_key_from_pem_768() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        let k = PqfPrivateKey::from_pem(&priv_pem).unwrap();
        assert_eq!(k.kem_variant(), KEM_VARIANT_768);
        assert!(!k.is_encrypted());
    }

    #[test]
    fn private_key_from_pem_encrypted() {
        let (_, priv_pem) = keygen_bytes(768, Some("pass")).unwrap();
        let k = PqfPrivateKey::from_pem(&priv_pem).unwrap();
        assert!(k.is_encrypted());
    }

    #[test]
    fn private_key_to_public_key_matches_original() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let priv_key = PqfPrivateKey::from_pem(&priv_pem).unwrap();
        let derived_pub = priv_key.to_public_key(None).unwrap();
        let original_pub = PqfPublicKey::from_pem(&pub_pem).unwrap();
        assert_eq!(derived_pub.fingerprint(), original_pub.fingerprint());
    }

    #[test]
    fn private_key_to_public_key_512() {
        let (pub_pem, priv_pem) = keygen_bytes(512, None).unwrap();
        let derived = PqfPrivateKey::from_pem(&priv_pem)
            .unwrap()
            .to_public_key(None)
            .unwrap();
        assert_eq!(
            derived.fingerprint(),
            PqfPublicKey::from_pem(&pub_pem).unwrap().fingerprint()
        );
    }

    #[test]
    fn private_key_to_public_key_1024() {
        let (pub_pem, priv_pem) = keygen_bytes(1024, None).unwrap();
        let derived = PqfPrivateKey::from_pem(&priv_pem)
            .unwrap()
            .to_public_key(None)
            .unwrap();
        assert_eq!(
            derived.fingerprint(),
            PqfPublicKey::from_pem(&pub_pem).unwrap().fingerprint()
        );
    }

    #[test]
    fn private_key_to_public_key_hybrid() {
        let (pub_pem, priv_pem) = keygen_bytes_hybrid_768(None).unwrap();
        let derived = PqfPrivateKey::from_pem(&priv_pem)
            .unwrap()
            .to_public_key(None)
            .unwrap();
        assert_eq!(
            derived.fingerprint(),
            PqfPublicKey::from_pem(&pub_pem).unwrap().fingerprint()
        );
    }

    #[test]
    fn private_key_encrypted_requires_passphrase_for_public_key() {
        let (_, priv_pem) = keygen_bytes(768, Some("pass")).unwrap();
        let k = PqfPrivateKey::from_pem(&priv_pem).unwrap();
        assert!(k.to_public_key(None).is_err());
        assert!(k.to_public_key(Some("pass")).is_ok());
    }

    #[test]
    fn signing_key_from_pem() {
        let r = sign_keygen_bytes(None).unwrap();
        let sk = PqfSigningKey::from_pem(&r.sk_pem).unwrap();
        assert!(!sk.is_encrypted());
    }

    #[test]
    fn signing_key_from_encrypted_pem() {
        let r = sign_keygen_bytes(Some("pass")).unwrap();
        let sk = PqfSigningKey::from_pem(&r.sk_pem).unwrap();
        assert!(sk.is_encrypted());
    }

    #[test]
    fn signing_key_rejects_invalid_pem() {
        assert!(PqfSigningKey::from_pem("bad pem").is_err());
    }

    #[test]
    fn slh_signing_and_verifying_keys_parse_with_algorithm() {
        use crate::sign::{sign_keygen_bytes_with_algorithm, SigAlgorithm};
        let r = sign_keygen_bytes_with_algorithm(SigAlgorithm::SlhDsaShake192f, None).unwrap();

        let sk = PqfSigningKey::from_pem(&r.sk_pem).unwrap();
        assert!(!sk.is_encrypted());
        assert_eq!(sk.algorithm(), "SLH-DSA-SHAKE-192f");

        let vk = PqfVerifyingKey::from_pem(&r.vk_pem).unwrap();
        assert_eq!(vk.algorithm(), "SLH-DSA-SHAKE-192f");
        assert_eq!(vk.fingerprint(), r.vk_fingerprint);

        let enc =
            sign_keygen_bytes_with_algorithm(SigAlgorithm::SlhDsaShake192f, Some("pw")).unwrap();
        let sk_enc = PqfSigningKey::from_pem(&enc.sk_pem).unwrap();
        assert!(sk_enc.is_encrypted());
        assert_eq!(sk_enc.algorithm(), "SLH-DSA-SHAKE-192f");
    }

    #[test]
    fn verifying_key_from_pem() {
        let r = sign_keygen_bytes(None).unwrap();
        let vk = PqfVerifyingKey::from_pem(&r.vk_pem).unwrap();
        assert_eq!(vk.fingerprint().split(':').count(), 16);
    }

    #[test]
    fn verifying_key_fingerprint_matches_keygen_result() {
        let r = sign_keygen_bytes(None).unwrap();
        let vk = PqfVerifyingKey::from_pem(&r.vk_pem).unwrap();
        assert_eq!(vk.fingerprint(), r.vk_fingerprint);
    }

    #[test]
    fn public_key_display_contains_algorithm_and_fingerprint() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let k = PqfPublicKey::from_pem(&pub_pem).unwrap();
        let s = format!("{k}");
        assert!(s.contains("ML-KEM-768"));
        assert!(s.contains(':'));
    }

    #[test]
    fn public_key_as_pem_roundtrips() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let k = PqfPublicKey::from_pem(&pub_pem).unwrap();
        assert_eq!(k.as_pem(), pub_pem);
    }
}
