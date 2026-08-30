use std::fs;
use std::path::{Path, PathBuf};

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa65, Signature, Signer,
    SigningKey, Verifier, VerifyingKey,
};
use pem::Pem;
use slh_dsa::signature::{
    Keypair as SlhKeypairTrait, Signer as SlhSignerTrait, Verifier as SlhVerifierTrait,
};
use slh_dsa::Shake192f;
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::hardware;
use crate::passphrase;

pub(crate) const VK_TAG: &str = "ML-DSA-65 VERIFYING KEY";
pub(crate) const SK_TAG: &str = "ML-DSA-65 SIGNING KEY";
pub(crate) const SK_ENC_TAG: &str = "ML-DSA-65 ENCRYPTED SIGNING KEY";
const SIG_TAG: &str = "ML-DSA-65 SIGNATURE";

pub(crate) const VK_LEN: usize = 1952;
pub(crate) const SK_SEED_LEN: usize = 32;
const SIG_LEN: usize = 3309;

pub(crate) const SLH_VK_TAG: &str = "SLH-DSA-SHAKE-192F VERIFYING KEY";
pub(crate) const SLH_SK_TAG: &str = "SLH-DSA-SHAKE-192F SIGNING KEY";
pub(crate) const SLH_SK_ENC_TAG: &str = "SLH-DSA-SHAKE-192F ENCRYPTED SIGNING KEY";
const SLH_SIG_TAG: &str = "SLH-DSA-SHAKE-192F SIGNATURE";

/// FIPS 205 security parameter n for the SHAKE-192 parameter sets.
const SLH_N: usize = 24;
/// Verifying key is PK.seed ‖ PK.root.
pub(crate) const SLH_VK_LEN: usize = 2 * SLH_N;
/// The stored private key is the seed triple SK.seed ‖ SK.prf ‖ PK.seed;
/// the full signing key is deterministically recomputed from it (FIPS 205
/// `slh_keygen_internal`), which also revalidates PK.root on every load.
pub(crate) const SLH_SK_SEED_LEN: usize = 3 * SLH_N;
const SLH_SIG_LEN: usize = 35664;

/// Signature algorithm selector for key generation.
///
/// Detached signatures, signcrypt payloads, and key PEMs are all
/// self-describing (the PEM tag carries the algorithm), so only key
/// generation needs an explicit choice; `sign_bytes`/`verify_bytes`
/// dispatch on the key that is supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigAlgorithm {
    /// ML-DSA-65 (FIPS 204), lattice-based. Fast signing, 3309-byte
    /// signatures. The default.
    MlDsa65,
    /// SLH-DSA-SHAKE-192f (FIPS 205), hash-based. Rests on much more
    /// conservative assumptions than lattices, at the cost of slower
    /// signing and 35664-byte signatures. Suited to long-lived
    /// signatures such as archival or release signing.
    SlhDsaShake192f,
}

impl SigAlgorithm {
    /// Human-readable algorithm name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SigAlgorithm::MlDsa65 => "ML-DSA-65",
            SigAlgorithm::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
        }
    }
}

/// Result of generating an ML-DSA-65 signing key pair.
#[non_exhaustive]
pub struct SignKeygenResult {
    /// PEM-encoded verifying (public) key.
    pub vk_pem: String,
    /// PEM-encoded signing (private) key, optionally passphrase-encrypted.
    pub sk_pem: String,
    /// SHA3-256 fingerprint of the verifying key (first 16 bytes, colon-separated hex).
    pub vk_fingerprint: String,
}

/// Generates an ML-DSA-65 signing key pair in memory.
/// If `passphrase` is `Some`, the signing seed is encrypted before PEM encoding.
#[must_use = "signing key pair must be saved or the generated keys are lost"]
pub fn sign_keygen_bytes(passphrase: Option<&str>) -> Result<SignKeygenResult, PqfileError> {
    sign_keygen_bytes_with_algorithm(SigAlgorithm::MlDsa65, passphrase)
}

/// Generates a signing key pair for `algorithm` in memory.
/// If `passphrase` is `Some`, the signing seed is encrypted before PEM encoding.
#[must_use = "signing key pair must be saved or the generated keys are lost"]
pub fn sign_keygen_bytes_with_algorithm(
    algorithm: SigAlgorithm,
    passphrase: Option<&str>,
) -> Result<SignKeygenResult, PqfileError> {
    match algorithm {
        SigAlgorithm::MlDsa65 => ml_dsa_keygen_bytes(passphrase),
        SigAlgorithm::SlhDsaShake192f => slh_dsa_keygen_bytes(passphrase),
    }
}

/// Deterministically rebuilds an SLH-DSA-SHAKE-192f signing key from its
/// 72-byte seed triple (FIPS 205 Algorithm 18, `slh_keygen_internal`).
///
/// Calling `slh_keygen_internal` with freshly generated randomness is exactly
/// FIPS 205 `slh_keygen` (Algorithm 21) with the RNG factored out; storing the
/// seed triple instead of the expanded key mirrors the ML-DSA seed design and
/// recomputes PK.root on every load, so a corrupted key cannot go unnoticed.
fn slh_signing_key_from_seed(seed: &[u8]) -> Result<slh_dsa::SigningKey<Shake192f>, PqfileError> {
    if seed.len() != SLH_SK_SEED_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: SLH_SK_SEED_LEN,
            got: seed.len(),
        });
    }
    Ok(slh_dsa::SigningKey::<Shake192f>::slh_keygen_internal(
        &seed[..SLH_N],
        &seed[SLH_N..2 * SLH_N],
        &seed[2 * SLH_N..],
    ))
}

fn slh_dsa_keygen_bytes(passphrase: Option<&str>) -> Result<SignKeygenResult, PqfileError> {
    let mut seed = Zeroizing::new([0u8; SLH_SK_SEED_LEN]);
    getrandom::fill(seed.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;
    let sk = slh_signing_key_from_seed(seed.as_ref())?;
    let vk_bytes = SlhKeypairTrait::verifying_key(&sk).to_vec();

    let vk_pem = pem::encode(&Pem::new(SLH_VK_TAG, vk_bytes.clone()));
    let sk_pem = if let Some(pp) = passphrase {
        let body = passphrase::encrypt_slh_signing_seed(&seed, pp)?;
        pem::encode(&Pem::new(SLH_SK_ENC_TAG, body))
    } else {
        pem::encode(&Pem::new(SLH_SK_TAG, seed.to_vec()))
    };

    let vk_fingerprint = crate::keygen::fingerprint(&vk_bytes);

    Ok(SignKeygenResult {
        vk_pem,
        sk_pem,
        vk_fingerprint,
    })
}

fn ml_dsa_keygen_bytes(passphrase: Option<&str>) -> Result<SignKeygenResult, PqfileError> {
    let sk = SigningKey::<MlDsa65>::generate();
    let vk = sk.verifying_key();

    let vk_encoded: EncodedVerifyingKey<MlDsa65> = vk.encode();
    let vk_bytes: &[u8] = vk_encoded.as_ref();

    let seed = Zeroizing::new(sk.to_seed());
    let seed_bytes: &[u8] = seed.as_slice();

    let vk_pem = pem::encode(&Pem::new(VK_TAG, vk_bytes.to_vec()));
    let sk_pem = if let Some(pp) = passphrase {
        if seed_bytes.len() != SK_SEED_LEN {
            return Err(PqfileError::InvalidKeyLength {
                expected: SK_SEED_LEN,
                got: seed_bytes.len(),
            });
        }
        let mut seed_arr = Zeroizing::new([0u8; SK_SEED_LEN]);
        seed_arr.copy_from_slice(seed_bytes);
        let body = passphrase::encrypt_signing_seed(&seed_arr, pp)?;
        pem::encode(&Pem::new(SK_ENC_TAG, body))
    } else {
        pem::encode(&Pem::new(SK_TAG, seed_bytes.to_vec()))
    };

    let vk_fingerprint = crate::keygen::fingerprint(vk_bytes);

    Ok(SignKeygenResult {
        vk_pem,
        sk_pem,
        vk_fingerprint,
    })
}

/// Generates an ML-DSA-65 signing key pair and writes it to `out_dir`.
/// Returns `OutputExists` if key files already exist and `force` is false.
pub fn sign_keygen(
    out_dir: &Path,
    force: bool,
    passphrase: Option<&str>,
) -> Result<SignKeygenResult, PqfileError> {
    sign_keygen_with_algorithm(out_dir, force, passphrase, SigAlgorithm::MlDsa65)
}

/// Generates a signing key pair for `algorithm` and writes it to `out_dir`.
/// Returns `OutputExists` if key files already exist and `force` is false.
pub fn sign_keygen_with_algorithm(
    out_dir: &Path,
    force: bool,
    passphrase: Option<&str>,
    algorithm: SigAlgorithm,
) -> Result<SignKeygenResult, PqfileError> {
    let vk_path = out_dir.join("sign_pubkey.pem");
    let sk_path = out_dir.join("sign_privkey.pem");

    if !force {
        if vk_path.exists() {
            return Err(PqfileError::OutputExists(vk_path));
        }
        if sk_path.exists() {
            return Err(PqfileError::OutputExists(sk_path));
        }
    }

    let result = sign_keygen_bytes_with_algorithm(algorithm, passphrase)?;
    fs::write(&vk_path, &result.vk_pem)?;
    crate::fsutil::write_private_file(&sk_path, result.sk_pem.as_bytes())?;

    Ok(result)
}

/// Generates a hardware-backed ML-DSA-65 signing key pair and writes it to `out_dir`.
///
/// The signing key seed is stored in the OS credential store under `label`;
/// only a PEM stub is written to disk. Returns `OutputExists` if key files
/// already exist and `force` is false.
#[must_use = "hardware sign keygen result must be saved"]
pub fn sign_keygen_hardware(
    out_dir: &Path,
    force: bool,
    label: &str,
) -> Result<SignKeygenResult, PqfileError> {
    sign_keygen_hardware_with_algorithm(out_dir, force, label, SigAlgorithm::MlDsa65)
}

/// Generates a hardware-backed signing key pair for `algorithm` and writes it
/// to `out_dir`.
///
/// The signing key seed is stored in the OS credential store under `label`;
/// only a PEM stub is written to disk. Returns `OutputExists` if key files
/// already exist and `force` is false.
#[must_use = "hardware sign keygen result must be saved"]
pub fn sign_keygen_hardware_with_algorithm(
    out_dir: &Path,
    force: bool,
    label: &str,
    algorithm: SigAlgorithm,
) -> Result<SignKeygenResult, PqfileError> {
    let vk_path = out_dir.join("sign_pubkey.pem");
    let sk_path = out_dir.join("sign_privkey.pem");

    if !force {
        if vk_path.exists() {
            return Err(PqfileError::OutputExists(vk_path));
        }
        if sk_path.exists() {
            return Err(PqfileError::OutputExists(sk_path));
        }
    }

    let result = sign_keygen_hardware_bytes_with_algorithm(label, algorithm)?;
    fs::write(&vk_path, &result.vk_pem)?;
    crate::fsutil::write_private_file(&sk_path, result.sk_pem.as_bytes())?;
    Ok(result)
}

/// Generates a hardware-backed ML-DSA-65 signing key pair in memory.
///
/// The seed (32 bytes) is stored in the OS credential store under `label`.
/// Returns `(vk_pem, hw_stub_pem)` via `SignKeygenResult`.
#[must_use = "hardware sign keygen result must be saved"]
pub fn sign_keygen_hardware_bytes(label: &str) -> Result<SignKeygenResult, PqfileError> {
    sign_keygen_hardware_bytes_with_algorithm(label, SigAlgorithm::MlDsa65)
}

/// Generates a hardware-backed signing key pair for `algorithm` in memory.
///
/// The seed (32 bytes for ML-DSA-65, 72 bytes for SLH-DSA-SHAKE-192f) is
/// stored in the OS credential store under `label`. Returns
/// `(vk_pem, hw_stub_pem)` via `SignKeygenResult`.
#[must_use = "hardware sign keygen result must be saved"]
pub fn sign_keygen_hardware_bytes_with_algorithm(
    label: &str,
    algorithm: SigAlgorithm,
) -> Result<SignKeygenResult, PqfileError> {
    let backend_id = hardware::default_backend_id();

    if algorithm == SigAlgorithm::SlhDsaShake192f {
        let (stub_body, seed) = hardware::generate_and_store(label, SLH_SK_SEED_LEN, backend_id)?;
        let sk = slh_signing_key_from_seed(&seed)?;
        let vk_bytes = SlhKeypairTrait::verifying_key(&sk).to_vec();
        let vk_pem = pem::encode(&Pem::new(SLH_VK_TAG, vk_bytes.clone()));
        let sk_pem = pem::encode(&Pem::new(hardware::HW_TAG_SIGNING_SLH, stub_body));
        let vk_fingerprint = crate::keygen::fingerprint(&vk_bytes);
        return Ok(SignKeygenResult {
            vk_pem,
            sk_pem,
            vk_fingerprint,
        });
    }

    let (stub_body, seed) = hardware::generate_and_store(label, SK_SEED_LEN, backend_id)?;

    if seed.len() != SK_SEED_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: SK_SEED_LEN,
            got: seed.len(),
        });
    }
    let mut seed_arr = [0u8; SK_SEED_LEN];
    seed_arr.copy_from_slice(&seed);
    let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr.into());
    let vk = sk.verifying_key();

    let vk_encoded: EncodedVerifyingKey<MlDsa65> = vk.encode();
    let vk_bytes: &[u8] = vk_encoded.as_ref();
    let vk_pem = pem::encode(&Pem::new(VK_TAG, vk_bytes.to_vec()));
    let sk_pem = pem::encode(&Pem::new(hardware::HW_TAG_SIGNING, stub_body));
    let vk_fingerprint = crate::keygen::fingerprint(vk_bytes);

    Ok(SignKeygenResult {
        vk_pem,
        sk_pem,
        vk_fingerprint,
    })
}

/// Signs `data` with the signing key in `sk_pem` and returns the raw signature
/// bytes. The algorithm (ML-DSA-65 or SLH-DSA-SHAKE-192f) is determined by the
/// key's PEM tag.
#[must_use = "sign result must be used"]
pub fn sign_bytes(
    sk_pem: &str,
    data: &[u8],
    passphrase: Option<&str>,
) -> Result<Vec<u8>, PqfileError> {
    match parse_signing_key(sk_pem, passphrase)? {
        AnySigningKey::MlDsa(sk) => {
            let sig: Signature<MlDsa65> = sk.sign(data);
            let encoded: EncodedSignature<MlDsa65> = sig.encode();
            let bytes: &[u8] = encoded.as_ref();
            Ok(bytes.to_vec())
        }
        AnySigningKey::SlhDsa(sk) => {
            let sig = SlhSignerTrait::sign(&*sk, data);
            Ok(sig.to_vec())
        }
    }
}

/// Signs the file at `input` and writes a PEM signature to `sig_out`.
#[must_use = "sign result must be used"]
pub fn sign_file(
    sk_pem: &str,
    input: &Path,
    sig_out: &Path,
    passphrase: Option<&str>,
) -> Result<(), PqfileError> {
    let data = fs::read(input)?;
    let sig_bytes = sign_bytes(sk_pem, &data, passphrase)?;
    let sig_pem = pem::encode(&Pem::new(sig_tag_for_len(sig_bytes.len()), sig_bytes));
    fs::write(sig_out, sig_pem)?;
    Ok(())
}

/// PEM tag for a raw signature, inferred from its length. The two supported
/// algorithms have distinct fixed signature lengths.
fn sig_tag_for_len(len: usize) -> &'static str {
    if len == SLH_SIG_LEN {
        SLH_SIG_TAG
    } else {
        SIG_TAG
    }
}

/// Verifies `sig_bytes` against `data` using the verifying key in `vk_pem`.
/// The algorithm (ML-DSA-65 or SLH-DSA-SHAKE-192f) is determined by the key's
/// PEM tag.
#[must_use = "verify result must be used"]
pub fn verify_bytes(vk_pem: &str, data: &[u8], sig_bytes: &[u8]) -> Result<(), PqfileError> {
    let p = pem::parse(vk_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    match p.tag() {
        VK_TAG => {
            let vk = decode_ml_verifying_key(p.contents())?;
            if sig_bytes.len() != SIG_LEN {
                return Err(PqfileError::InvalidSignature);
            }
            let sig = Signature::<MlDsa65>::try_from(sig_bytes)
                .map_err(|_| PqfileError::InvalidSignature)?;
            vk.verify(data, &sig)
                .map_err(|_| PqfileError::SignatureVerificationFailed)
        }
        SLH_VK_TAG => {
            let vk_bytes = p.contents();
            if vk_bytes.len() != SLH_VK_LEN {
                return Err(PqfileError::InvalidKeyLength {
                    expected: SLH_VK_LEN,
                    got: vk_bytes.len(),
                });
            }
            let vk = slh_dsa::VerifyingKey::<Shake192f>::try_from(vk_bytes)
                .map_err(|_| PqfileError::InvalidPem("malformed SLH-DSA verifying key".into()))?;
            if sig_bytes.len() != SLH_SIG_LEN {
                return Err(PqfileError::InvalidSignature);
            }
            let sig = slh_dsa::Signature::<Shake192f>::try_from(sig_bytes)
                .map_err(|_| PqfileError::InvalidSignature)?;
            SlhVerifierTrait::verify(&vk, data, &sig)
                .map_err(|_| PqfileError::SignatureVerificationFailed)
        }
        tag => Err(PqfileError::InvalidPem(format!(
            "expected tag '{VK_TAG}' or '{SLH_VK_TAG}', got '{tag}'"
        ))),
    }
}

/// Signature length implied by the algorithm of the verifying key in `vk_pem`.
/// Used by signcrypt to know how many payload bytes to treat as the signature.
pub(crate) fn sig_len_for_vk(vk_pem: &str) -> Result<usize, PqfileError> {
    let p = pem::parse(vk_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    match p.tag() {
        VK_TAG => Ok(SIG_LEN),
        SLH_VK_TAG => Ok(SLH_SIG_LEN),
        tag => Err(PqfileError::InvalidPem(format!(
            "expected tag '{VK_TAG}' or '{SLH_VK_TAG}', got '{tag}'"
        ))),
    }
}

/// Reads `input` and its detached PEM signature from `sig_path`, then verifies.
#[must_use = "verify result must be used"]
pub fn verify_file(vk_pem: &str, input: &Path, sig_path: &Path) -> Result<(), PqfileError> {
    let data = fs::read(input)?;
    let sig_pem_str = fs::read_to_string(sig_path)?;
    let sig_bytes = parse_sig_pem(&sig_pem_str)?;
    verify_bytes(vk_pem, &data, &sig_bytes)
}

/// Returns the default signature output path for `input` (appends `.sig` to the extension).
#[must_use]
pub fn default_sig_path(input: &Path) -> PathBuf {
    let mut p = input.to_path_buf();
    let ext = match p.extension() {
        Some(e) => format!("{}.sig", e.to_string_lossy()),
        None => "sig".to_owned(),
    };
    p.set_extension(ext);
    p
}

/// A parsed signing key of either supported algorithm.
enum AnySigningKey {
    MlDsa(Box<SigningKey<MlDsa65>>),
    SlhDsa(Box<slh_dsa::SigningKey<Shake192f>>),
}

fn ml_signing_key_from_seed(seed_bytes: &[u8]) -> Result<SigningKey<MlDsa65>, PqfileError> {
    let seed_arr: &[u8; SK_SEED_LEN] =
        seed_bytes
            .try_into()
            .map_err(|_| PqfileError::InvalidKeyLength {
                expected: SK_SEED_LEN,
                got: seed_bytes.len(),
            })?;
    Ok(SigningKey::<MlDsa65>::from_seed(seed_arr.into()))
}

fn parse_signing_key(
    pem_str: &str,
    passphrase: Option<&str>,
) -> Result<AnySigningKey, PqfileError> {
    let p = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    match p.tag() {
        // Hardware stubs: load seed from OS credential store.
        hardware::HW_TAG_SIGNING => {
            let seed_bytes = hardware::load_seed(p.contents())?;
            Ok(AnySigningKey::MlDsa(Box::new(ml_signing_key_from_seed(
                &seed_bytes,
            )?)))
        }
        hardware::HW_TAG_SIGNING_SLH => {
            let seed_bytes = hardware::load_seed(p.contents())?;
            Ok(AnySigningKey::SlhDsa(Box::new(slh_signing_key_from_seed(
                &seed_bytes,
            )?)))
        }
        SK_ENC_TAG => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            let seed = passphrase::decrypt_signing_seed(p.contents(), pp)?;
            Ok(AnySigningKey::MlDsa(Box::new(ml_signing_key_from_seed(
                seed.as_slice(),
            )?)))
        }
        SK_TAG => {
            let seed = Zeroizing::new(p.contents().to_vec());
            Ok(AnySigningKey::MlDsa(Box::new(ml_signing_key_from_seed(
                &seed,
            )?)))
        }
        SLH_SK_ENC_TAG => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            let seed = passphrase::decrypt_slh_signing_seed(p.contents(), pp)?;
            Ok(AnySigningKey::SlhDsa(Box::new(slh_signing_key_from_seed(
                seed.as_slice(),
            )?)))
        }
        SLH_SK_TAG => {
            let seed = Zeroizing::new(p.contents().to_vec());
            Ok(AnySigningKey::SlhDsa(Box::new(slh_signing_key_from_seed(
                &seed,
            )?)))
        }
        tag => Err(PqfileError::InvalidPem(format!(
            "expected tag '{}', '{}', '{}', '{}', '{}', or '{}', got '{tag}'",
            SK_TAG,
            SK_ENC_TAG,
            SLH_SK_TAG,
            SLH_SK_ENC_TAG,
            hardware::HW_TAG_SIGNING,
            hardware::HW_TAG_SIGNING_SLH,
        ))),
    }
}

fn decode_ml_verifying_key(vk_bytes: &[u8]) -> Result<VerifyingKey<MlDsa65>, PqfileError> {
    if vk_bytes.len() != VK_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: VK_LEN,
            got: vk_bytes.len(),
        });
    }
    let vk_arr: &[u8; VK_LEN] = vk_bytes
        .try_into()
        .map_err(|_| PqfileError::InvalidKeyLength {
            expected: VK_LEN,
            got: vk_bytes.len(),
        })?;
    Ok(VerifyingKey::<MlDsa65>::decode(vk_arr.into()))
}

/// Encodes raw signature bytes into a PEM string suitable for writing to a `.sig` file.
/// The PEM tag is inferred from the signature length (ML-DSA-65 or SLH-DSA-SHAKE-192f).
#[must_use = "encoded signature must be used"]
pub fn encode_sig_pem(sig_bytes: &[u8]) -> Vec<u8> {
    pem::encode(&pem::Pem::new(
        sig_tag_for_len(sig_bytes.len()),
        sig_bytes.to_vec(),
    ))
    .into_bytes()
}

/// Decodes a PEM signature file and returns the raw signature bytes.
#[must_use = "decoded signature bytes must be used"]
pub fn decode_sig_pem(pem_bytes: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let s = std::str::from_utf8(pem_bytes)
        .map_err(|_| PqfileError::InvalidPem("not valid UTF-8".into()))?;
    parse_sig_pem(s)
}

fn parse_sig_pem(pem_str: &str) -> Result<Vec<u8>, PqfileError> {
    let p = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != SIG_TAG && p.tag() != SLH_SIG_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{}' or '{}', got '{}'",
            SIG_TAG,
            SLH_SIG_TAG,
            p.tag()
        )));
    }
    Ok(p.contents().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_keygen_bytes_produces_correct_pem_tags() {
        let r = sign_keygen_bytes(None).unwrap();
        assert!(r.vk_pem.contains(VK_TAG));
        assert!(r.sk_pem.contains(SK_TAG));
    }

    #[test]
    fn sign_keygen_bytes_vk_is_1952_bytes() {
        let r = sign_keygen_bytes(None).unwrap();
        let p = pem::parse(&r.vk_pem).unwrap();
        assert_eq!(p.contents().len(), VK_LEN);
    }

    #[test]
    fn sign_keygen_bytes_sk_seed_is_32_bytes() {
        let r = sign_keygen_bytes(None).unwrap();
        let p = pem::parse(&r.sk_pem).unwrap();
        assert_eq!(p.contents().len(), SK_SEED_LEN);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let r = sign_keygen_bytes(None).unwrap();
        let msg = b"hello pqfile";
        let sig = sign_bytes(&r.sk_pem, msg, None).unwrap();
        verify_bytes(&r.vk_pem, msg, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let r = sign_keygen_bytes(None).unwrap();
        let msg = b"hello pqfile";
        let sig = sign_bytes(&r.sk_pem, msg, None).unwrap();
        let result = verify_bytes(&r.vk_pem, b"tampered", &sig);
        assert!(matches!(
            result,
            Err(PqfileError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let r = sign_keygen_bytes(None).unwrap();
        let msg = b"hello pqfile";
        let mut sig = sign_bytes(&r.sk_pem, msg, None).unwrap();
        sig[0] ^= 0xff;
        let result = verify_bytes(&r.vk_pem, msg, &sig);
        assert!(matches!(
            result,
            Err(PqfileError::InvalidSignature | PqfileError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let r1 = sign_keygen_bytes(None).unwrap();
        let r2 = sign_keygen_bytes(None).unwrap();
        let msg = b"hello pqfile";
        let sig = sign_bytes(&r1.sk_pem, msg, None).unwrap();
        let result = verify_bytes(&r2.vk_pem, msg, &sig);
        assert!(matches!(
            result,
            Err(PqfileError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn sign_keygen_files_written_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_keygen(dir.path(), false, None).unwrap();
        assert!(dir.path().join("sign_pubkey.pem").exists());
        assert!(dir.path().join("sign_privkey.pem").exists());
        assert!(!r.vk_fingerprint.is_empty());
    }

    #[test]
    fn sign_keygen_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        sign_keygen(dir.path(), false, None).unwrap();
        let result = sign_keygen(dir.path(), false, None);
        assert!(matches!(result, Err(PqfileError::OutputExists(_))));
    }

    #[test]
    fn sign_keygen_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        sign_keygen(dir.path(), false, None).unwrap();
        sign_keygen(dir.path(), true, None).unwrap();
    }

    #[test]
    fn sign_file_and_verify_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_keygen(dir.path(), false, None).unwrap();
        let input = dir.path().join("data.txt");
        fs::write(&input, b"some file content").unwrap();
        let sig_path = dir.path().join("data.txt.sig");
        let sk_pem = fs::read_to_string(dir.path().join("sign_privkey.pem")).unwrap();
        sign_file(&sk_pem, &input, &sig_path, None).unwrap();
        let vk_pem = fs::read_to_string(dir.path().join("sign_pubkey.pem")).unwrap();
        verify_file(&vk_pem, &input, &sig_path).unwrap();
        drop(r);
    }

    #[test]
    fn default_sig_path_appends_sig_extension() {
        let p = Path::new("file.txt");
        assert_eq!(default_sig_path(p), PathBuf::from("file.txt.sig"));

        let p2 = Path::new("file");
        assert_eq!(default_sig_path(p2), PathBuf::from("file.sig"));
    }

    #[test]
    fn sign_bytes_wrong_pem_tag_returns_error() {
        let wrong_pem = pem::encode(&Pem::new("WRONG TAG", vec![0u8; SK_SEED_LEN]));
        assert!(matches!(
            sign_bytes(&wrong_pem, b"data", None),
            Err(PqfileError::InvalidPem(_))
        ));
    }

    #[test]
    fn sign_bytes_wrong_seed_length_returns_error() {
        let wrong_pem = pem::encode(&Pem::new(SK_TAG, vec![0u8; 16]));
        assert!(matches!(
            sign_bytes(&wrong_pem, b"data", None),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn verify_bytes_wrong_vk_pem_tag_returns_error() {
        let r = sign_keygen_bytes(None).unwrap();
        let msg = b"hello";
        let sig = sign_bytes(&r.sk_pem, msg, None).unwrap();
        let wrong_pem = pem::encode(&Pem::new("WRONG TAG", vec![0u8; VK_LEN]));
        assert!(matches!(
            verify_bytes(&wrong_pem, msg, &sig),
            Err(PqfileError::InvalidPem(_))
        ));
    }

    #[test]
    fn verify_bytes_wrong_vk_length_returns_error() {
        let r = sign_keygen_bytes(None).unwrap();
        let msg = b"hello";
        let sig = sign_bytes(&r.sk_pem, msg, None).unwrap();
        let wrong_pem = pem::encode(&Pem::new(VK_TAG, vec![0u8; 16]));
        assert!(matches!(
            verify_bytes(&wrong_pem, msg, &sig),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn verify_bytes_wrong_sig_length_returns_error() {
        let r = sign_keygen_bytes(None).unwrap();
        let short_sig = vec![0u8; 16];
        assert!(matches!(
            verify_bytes(&r.vk_pem, b"data", &short_sig),
            Err(PqfileError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_file_wrong_sig_pem_tag_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_keygen_bytes(None).unwrap();
        let input = dir.path().join("data.txt");
        fs::write(&input, b"payload").unwrap();
        let sig_path = dir.path().join("data.txt.sig");
        let wrong_sig_pem = pem::encode(&Pem::new("WRONG TAG", vec![0u8; SIG_LEN]));
        fs::write(&sig_path, wrong_sig_pem).unwrap();
        assert!(matches!(
            verify_file(&r.vk_pem, &input, &sig_path),
            Err(PqfileError::InvalidPem(_))
        ));
    }

    #[test]
    fn sign_keygen_blocks_when_only_privkey_exists() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("sign_privkey.pem"), b"dummy").unwrap();
        assert!(matches!(
            sign_keygen(dir.path(), false, None),
            Err(PqfileError::OutputExists(_))
        ));
    }

    // ── SLH-DSA-SHAKE-192f ─────────────────────────────────────────────────
    // Signing is expensive in debug builds (~3 s per signature), so these
    // tests sign once and reuse the signature for several assertions.

    #[test]
    fn slh_keygen_bytes_produces_correct_tags_and_lengths() {
        let r = sign_keygen_bytes_with_algorithm(SigAlgorithm::SlhDsaShake192f, None).unwrap();
        assert!(r.vk_pem.contains(SLH_VK_TAG));
        assert!(r.sk_pem.contains(SLH_SK_TAG));
        let vk = pem::parse(&r.vk_pem).unwrap();
        assert_eq!(vk.contents().len(), SLH_VK_LEN);
        let sk = pem::parse(&r.sk_pem).unwrap();
        assert_eq!(sk.contents().len(), SLH_SK_SEED_LEN);
        assert!(!r.vk_fingerprint.is_empty());
    }

    #[test]
    fn slh_sign_verify_roundtrip_and_rejects_tampering() {
        let r = sign_keygen_bytes_with_algorithm(SigAlgorithm::SlhDsaShake192f, None).unwrap();
        let msg = b"hello slh-dsa";
        let sig = sign_bytes(&r.sk_pem, msg, None).unwrap();
        assert_eq!(sig.len(), SLH_SIG_LEN);

        // Valid signature verifies.
        verify_bytes(&r.vk_pem, msg, &sig).unwrap();

        // Tampered message rejected.
        assert!(matches!(
            verify_bytes(&r.vk_pem, b"tampered", &sig),
            Err(PqfileError::SignatureVerificationFailed)
        ));

        // Tampered signature rejected.
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xff;
        assert!(matches!(
            verify_bytes(&r.vk_pem, msg, &bad_sig),
            Err(PqfileError::InvalidSignature | PqfileError::SignatureVerificationFailed)
        ));

        // Wrong-algorithm verifying key rejects by signature length.
        let ml = sign_keygen_bytes(None).unwrap();
        assert!(matches!(
            verify_bytes(&ml.vk_pem, msg, &sig),
            Err(PqfileError::InvalidSignature)
        ));

        // Detached-signature PEM helpers pick the SLH tag and roundtrip.
        let sig_pem = encode_sig_pem(&sig);
        assert!(String::from_utf8_lossy(&sig_pem).contains(SLH_SIG_TAG));
        assert_eq!(decode_sig_pem(&sig_pem).unwrap(), sig);
    }

    #[test]
    fn slh_sign_verify_roundtrip_with_passphrase() {
        let r = sign_keygen_bytes_with_algorithm(SigAlgorithm::SlhDsaShake192f, Some("mypass"))
            .unwrap();
        let p = pem::parse(&r.sk_pem).unwrap();
        assert_eq!(p.tag(), SLH_SK_ENC_TAG);
        assert_eq!(
            p.contents().len(),
            crate::passphrase::ENCRYPTED_SLH_SIGNING_BODY_LEN
        );

        // Wrong passphrase and missing passphrase both fail before signing.
        assert!(matches!(
            sign_bytes(&r.sk_pem, b"data", Some("wrong")),
            Err(PqfileError::WrongPassphrase)
        ));
        assert!(matches!(
            sign_bytes(&r.sk_pem, b"data", None),
            Err(PqfileError::PassphraseRequired)
        ));

        let msg = b"signed with encrypted slh key";
        let sig = sign_bytes(&r.sk_pem, msg, Some("mypass")).unwrap();
        verify_bytes(&r.vk_pem, msg, &sig).unwrap();
    }

    #[test]
    fn slh_keygen_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_keygen_with_algorithm(dir.path(), false, None, SigAlgorithm::SlhDsaShake192f)
            .unwrap();
        assert!(dir.path().join("sign_pubkey.pem").exists());
        assert!(dir.path().join("sign_privkey.pem").exists());
        assert!(!r.vk_fingerprint.is_empty());
        // Second call without force refuses to overwrite.
        assert!(matches!(
            sign_keygen_with_algorithm(dir.path(), false, None, SigAlgorithm::SlhDsaShake192f),
            Err(PqfileError::OutputExists(_))
        ));
    }

    #[test]
    fn slh_seed_is_deterministic() {
        // The same 72-byte seed triple must always rebuild the same key pair.
        let seed = [7u8; SLH_SK_SEED_LEN];
        let sk1 = slh_signing_key_from_seed(&seed).unwrap();
        let sk2 = slh_signing_key_from_seed(&seed).unwrap();
        assert_eq!(
            SlhKeypairTrait::verifying_key(&sk1).to_vec(),
            SlhKeypairTrait::verifying_key(&sk2).to_vec()
        );
    }

    #[test]
    fn slh_wrong_seed_length_returns_error() {
        let wrong_pem = pem::encode(&Pem::new(SLH_SK_TAG, vec![0u8; 32]));
        assert!(matches!(
            sign_bytes(&wrong_pem, b"data", None),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn sig_len_for_vk_dispatches_on_tag() {
        let ml = sign_keygen_bytes(None).unwrap();
        assert_eq!(sig_len_for_vk(&ml.vk_pem).unwrap(), SIG_LEN);
        let slh_vk_pem = pem::encode(&Pem::new(SLH_VK_TAG, vec![0u8; SLH_VK_LEN]));
        assert_eq!(sig_len_for_vk(&slh_vk_pem).unwrap(), SLH_SIG_LEN);
        assert!(sig_len_for_vk(&ml.sk_pem).is_err());
    }

    #[test]
    fn sign_keygen_bytes_with_passphrase_uses_encrypted_tag() {
        let r = sign_keygen_bytes(Some("secret")).unwrap();
        let p = pem::parse(&r.sk_pem).unwrap();
        assert_eq!(p.tag(), SK_ENC_TAG);
    }

    #[test]
    fn sign_keygen_bytes_encrypted_body_is_76_bytes() {
        let r = sign_keygen_bytes(Some("secret")).unwrap();
        let p = pem::parse(&r.sk_pem).unwrap();
        assert_eq!(
            p.contents().len(),
            crate::passphrase::ENCRYPTED_SIGNING_BODY_LEN
        );
    }

    #[test]
    fn sign_and_verify_roundtrip_with_passphrase() {
        let r = sign_keygen_bytes(Some("mypass")).unwrap();
        let msg = b"signed with encrypted key";
        let sig = sign_bytes(&r.sk_pem, msg, Some("mypass")).unwrap();
        verify_bytes(&r.vk_pem, msg, &sig).unwrap();
    }

    #[test]
    fn sign_bytes_wrong_passphrase_returns_error() {
        let r = sign_keygen_bytes(Some("correct")).unwrap();
        let result = sign_bytes(&r.sk_pem, b"data", Some("wrong"));
        assert!(matches!(result, Err(PqfileError::WrongPassphrase)));
    }

    #[test]
    fn sign_bytes_encrypted_key_no_passphrase_returns_error() {
        let r = sign_keygen_bytes(Some("secret")).unwrap();
        let result = sign_bytes(&r.sk_pem, b"data", None);
        assert!(matches!(result, Err(PqfileError::PassphraseRequired)));
    }

    #[test]
    fn sign_keygen_with_passphrase_writes_encrypted_key() {
        let dir = tempfile::tempdir().unwrap();
        sign_keygen(dir.path(), false, Some("secret")).unwrap();
        let sk_pem = fs::read_to_string(dir.path().join("sign_privkey.pem")).unwrap();
        let p = pem::parse(&sk_pem).unwrap();
        assert_eq!(p.tag(), SK_ENC_TAG);
    }
}
