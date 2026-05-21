use std::fs;
use std::path::{Path, PathBuf};

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa65, Signature, Signer,
    SigningKey, Verifier, VerifyingKey,
};
use pem::Pem;
use zeroize::Zeroizing;

use crate::error::PqfileError;

const VK_TAG: &str = "ML-DSA-65 VERIFYING KEY";
const SK_TAG: &str = "ML-DSA-65 SIGNING KEY";
const SIG_TAG: &str = "ML-DSA-65 SIGNATURE";

const VK_LEN: usize = 1952;
const SK_SEED_LEN: usize = 32;
const SIG_LEN: usize = 3309;

pub struct SignKeygenResult {
    pub vk_pem: String,
    pub sk_pem: String,
    pub vk_fingerprint: String,
}

pub fn sign_keygen_bytes() -> Result<SignKeygenResult, PqfileError> {
    let sk = SigningKey::<MlDsa65>::generate();
    let vk = sk.verifying_key();

    let vk_encoded: EncodedVerifyingKey<MlDsa65> = vk.encode();
    let vk_bytes: &[u8] = vk_encoded.as_ref();

    let seed = Zeroizing::new(sk.to_seed());
    let seed_bytes: &[u8] = seed.as_slice();

    let vk_pem = pem::encode(&Pem::new(VK_TAG, vk_bytes.to_vec()));
    let sk_pem = pem::encode(&Pem::new(SK_TAG, seed_bytes.to_vec()));

    let vk_fingerprint = crate::keygen::fingerprint(vk_bytes);

    Ok(SignKeygenResult {
        vk_pem,
        sk_pem,
        vk_fingerprint,
    })
}

pub fn sign_keygen(out_dir: &Path, force: bool) -> Result<SignKeygenResult, PqfileError> {
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

    let result = sign_keygen_bytes()?;
    fs::write(&vk_path, &result.vk_pem)?;
    fs::write(&sk_path, &result.sk_pem)?;

    Ok(result)
}

pub fn sign_bytes(sk_pem: &str, data: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let sk = parse_signing_key(sk_pem)?;
    let sig: Signature<MlDsa65> = sk.sign(data);
    let encoded: EncodedSignature<MlDsa65> = sig.encode();
    let bytes: &[u8] = encoded.as_ref();
    Ok(bytes.to_vec())
}

pub fn sign_file(sk_pem: &str, input: &Path, sig_out: &Path) -> Result<(), PqfileError> {
    let data = fs::read(input)?;
    let sig_bytes = sign_bytes(sk_pem, &data)?;
    let sig_pem = pem::encode(&Pem::new(SIG_TAG, sig_bytes));
    fs::write(sig_out, sig_pem)?;
    Ok(())
}

pub fn verify_bytes(vk_pem: &str, data: &[u8], sig_bytes: &[u8]) -> Result<(), PqfileError> {
    let vk = parse_verifying_key(vk_pem)?;

    if sig_bytes.len() != SIG_LEN {
        return Err(PqfileError::InvalidSignature);
    }
    let sig = Signature::<MlDsa65>::try_from(sig_bytes)
        .map_err(|_| PqfileError::InvalidSignature)?;

    vk.verify(data, &sig)
        .map_err(|_| PqfileError::SignatureVerificationFailed)
}

pub fn verify_file(vk_pem: &str, input: &Path, sig_path: &Path) -> Result<(), PqfileError> {
    let data = fs::read(input)?;
    let sig_pem_str = fs::read_to_string(sig_path)?;
    let sig_bytes = parse_sig_pem(&sig_pem_str)?;
    verify_bytes(vk_pem, &data, &sig_bytes)
}

pub fn default_sig_path(input: &Path) -> PathBuf {
    let mut p = input.to_path_buf();
    let ext = match p.extension() {
        Some(e) => format!("{}.sig", e.to_string_lossy()),
        None => "sig".to_owned(),
    };
    p.set_extension(ext);
    p
}

fn parse_signing_key(pem_str: &str) -> Result<SigningKey<MlDsa65>, PqfileError> {
    let p = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != SK_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{}', got '{}'",
            SK_TAG,
            p.tag()
        )));
    }
    let seed_bytes = p.contents();
    if seed_bytes.len() != SK_SEED_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: SK_SEED_LEN,
            got: seed_bytes.len(),
        });
    }
    let seed_arr: &[u8; SK_SEED_LEN] = seed_bytes
        .try_into()
        .map_err(|_| PqfileError::InvalidKeyLength {
            expected: SK_SEED_LEN,
            got: seed_bytes.len(),
        })?;
    Ok(SigningKey::<MlDsa65>::from_seed(seed_arr.into()))
}

fn parse_verifying_key(pem_str: &str) -> Result<VerifyingKey<MlDsa65>, PqfileError> {
    let p = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != VK_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{}', got '{}'",
            VK_TAG,
            p.tag()
        )));
    }
    let vk_bytes = p.contents();
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

fn parse_sig_pem(pem_str: &str) -> Result<Vec<u8>, PqfileError> {
    let p = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != SIG_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{}', got '{}'",
            SIG_TAG,
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
        let r = sign_keygen_bytes().unwrap();
        assert!(r.vk_pem.contains(VK_TAG));
        assert!(r.sk_pem.contains(SK_TAG));
    }

    #[test]
    fn sign_keygen_bytes_vk_is_1952_bytes() {
        let r = sign_keygen_bytes().unwrap();
        let p = pem::parse(&r.vk_pem).unwrap();
        assert_eq!(p.contents().len(), VK_LEN);
    }

    #[test]
    fn sign_keygen_bytes_sk_seed_is_32_bytes() {
        let r = sign_keygen_bytes().unwrap();
        let p = pem::parse(&r.sk_pem).unwrap();
        assert_eq!(p.contents().len(), SK_SEED_LEN);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let r = sign_keygen_bytes().unwrap();
        let msg = b"hello pqfile";
        let sig = sign_bytes(&r.sk_pem, msg).unwrap();
        verify_bytes(&r.vk_pem, msg, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let r = sign_keygen_bytes().unwrap();
        let msg = b"hello pqfile";
        let sig = sign_bytes(&r.sk_pem, msg).unwrap();
        let result = verify_bytes(&r.vk_pem, b"tampered", &sig);
        assert!(matches!(result, Err(PqfileError::SignatureVerificationFailed)));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let r = sign_keygen_bytes().unwrap();
        let msg = b"hello pqfile";
        let mut sig = sign_bytes(&r.sk_pem, msg).unwrap();
        sig[0] ^= 0xff;
        let result = verify_bytes(&r.vk_pem, msg, &sig);
        assert!(matches!(
            result,
            Err(PqfileError::InvalidSignature | PqfileError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let r1 = sign_keygen_bytes().unwrap();
        let r2 = sign_keygen_bytes().unwrap();
        let msg = b"hello pqfile";
        let sig = sign_bytes(&r1.sk_pem, msg).unwrap();
        let result = verify_bytes(&r2.vk_pem, msg, &sig);
        assert!(matches!(result, Err(PqfileError::SignatureVerificationFailed)));
    }

    #[test]
    fn sign_keygen_files_written_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_keygen(dir.path(), false).unwrap();
        assert!(dir.path().join("sign_pubkey.pem").exists());
        assert!(dir.path().join("sign_privkey.pem").exists());
        assert!(!r.vk_fingerprint.is_empty());
    }

    #[test]
    fn sign_keygen_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        sign_keygen(dir.path(), false).unwrap();
        let result = sign_keygen(dir.path(), false);
        assert!(matches!(result, Err(PqfileError::OutputExists(_))));
    }

    #[test]
    fn sign_keygen_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        sign_keygen(dir.path(), false).unwrap();
        sign_keygen(dir.path(), true).unwrap();
    }

    #[test]
    fn sign_file_and_verify_file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_keygen(dir.path(), false).unwrap();
        let input = dir.path().join("data.txt");
        fs::write(&input, b"some file content").unwrap();
        let sig_path = dir.path().join("data.txt.sig");
        let sk_pem = fs::read_to_string(dir.path().join("sign_privkey.pem")).unwrap();
        sign_file(&sk_pem, &input, &sig_path).unwrap();
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
        assert!(matches!(sign_bytes(&wrong_pem, b"data"), Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn sign_bytes_wrong_seed_length_returns_error() {
        let wrong_pem = pem::encode(&Pem::new(SK_TAG, vec![0u8; 16]));
        assert!(matches!(
            sign_bytes(&wrong_pem, b"data"),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn verify_bytes_wrong_vk_pem_tag_returns_error() {
        let r = sign_keygen_bytes().unwrap();
        let msg = b"hello";
        let sig = sign_bytes(&r.sk_pem, msg).unwrap();
        let wrong_pem = pem::encode(&Pem::new("WRONG TAG", vec![0u8; VK_LEN]));
        assert!(matches!(verify_bytes(&wrong_pem, msg, &sig), Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn verify_bytes_wrong_vk_length_returns_error() {
        let r = sign_keygen_bytes().unwrap();
        let msg = b"hello";
        let sig = sign_bytes(&r.sk_pem, msg).unwrap();
        let wrong_pem = pem::encode(&Pem::new(VK_TAG, vec![0u8; 16]));
        assert!(matches!(
            verify_bytes(&wrong_pem, msg, &sig),
            Err(PqfileError::InvalidKeyLength { .. })
        ));
    }

    #[test]
    fn verify_bytes_wrong_sig_length_returns_error() {
        let r = sign_keygen_bytes().unwrap();
        let short_sig = vec![0u8; 16];
        assert!(matches!(
            verify_bytes(&r.vk_pem, b"data", &short_sig),
            Err(PqfileError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_file_wrong_sig_pem_tag_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = sign_keygen_bytes().unwrap();
        let input = dir.path().join("data.txt");
        fs::write(&input, b"payload").unwrap();
        let sig_path = dir.path().join("data.txt.sig");
        let wrong_sig_pem = pem::encode(&Pem::new("WRONG TAG", vec![0u8; SIG_LEN]));
        fs::write(&sig_path, wrong_sig_pem).unwrap();
        assert!(matches!(verify_file(&r.vk_pem, &input, &sig_path), Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn sign_keygen_blocks_when_only_privkey_exists() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("sign_privkey.pem"), b"dummy").unwrap();
        assert!(matches!(
            sign_keygen(dir.path(), false),
            Err(PqfileError::OutputExists(_))
        ));
    }
}
