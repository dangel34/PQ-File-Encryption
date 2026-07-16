//! Sealed sender: deniable sender authentication for encrypted files.
//!
//! Unlike [`crate::signcrypt`], which embeds a non-repudiable ML-DSA/SLH-DSA
//! signature, sealed sender proves the sender's identity only to the specific
//! intended recipient. The mechanism is a static-static X25519
//! Diffie-Hellman between the sender's and recipient's long-term *identity*
//! keys (separate from their ML-KEM encryption keys and any ML-DSA signing
//! keys), following the same shape as OTR/Signal-style deniable
//! authentication: the derived key authenticates a MAC-like tag over the
//! plaintext, and because computing that tag requires only *one* of the two
//! private keys plus the other's public key, the recipient could have forged
//! an identical tag themselves. A third party - even one who later obtains
//! the plaintext, the ciphertext, and the sender's identity public key -
//! cannot distinguish "the sender really sent this" from "the recipient
//! fabricated it," which a signature can never provide.
//!
//! # Scope
//!
//! This module intentionally ships only the safe, buffered decrypt path
//! ([`unseal_bytes`]), mirroring [`crate::signcrypt::signdecrypt_bytes`]. A
//! streaming write-before-verify variant (mirroring
//! [`crate::signcrypt::signdecrypt`]) is not provided; add one later if a
//! real large-file use case needs it.

use std::io::{self, Cursor, Read, Write};

use hkdf::Hkdf;
use pem::Pem;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::encrypt;
use crate::error::PqfileError;
use crate::format::CHUNK_SIZE;
use crate::passphrase;
use crate::reader::PqfReader;
use crate::secret::LockedSecret;

pub(crate) const IDENTITY_PUB_TAG: &str = "X25519 IDENTITY PUBLIC KEY";
pub(crate) const IDENTITY_PRIV_TAG: &str = "X25519 IDENTITY PRIVATE KEY";
pub(crate) const IDENTITY_PRIV_ENC_TAG: &str = "X25519 IDENTITY ENCRYPTED PRIVATE KEY";

const IDENTITY_SEED_LEN: usize = 32;
const IDENTITY_PK_LEN: usize = 32;

/// Length of the deniable-authentication tag prepended to the plaintext.
const TAG_LEN: usize = 32;

/// Domain separator for the HKDF that turns the raw X25519 DH output into an
/// authentication key. Distinct from `hybrid_hkdf`'s `"pqfile-hybrid-v1"` info
/// string so the two HKDF calls can never collide even if fed the same bytes.
const AUTH_HKDF_INFO: &[u8] = b"pqfile-sealed-sender-auth-v1";

/// Domain separator for the tag itself. SHA3-256(ctx || key || message) is a
/// secure keyed hash (not vulnerable to length-extension, unlike SHA-2)
/// because SHA3 is a sponge construction - the same reasoning already used
/// for the session-key commitment in `format.rs`.
const TAG_CTX: &[u8] = b"pqfile-sealed-sender-tag-v1";

/// Result of generating a sealed-sender identity key pair.
#[non_exhaustive]
pub struct IdentityKeygenResult {
    /// PEM-encoded identity public key, shared with counterparties out of band.
    pub pk_pem: String,
    /// PEM-encoded identity private key, optionally passphrase-encrypted.
    pub sk_pem: String,
    /// SHA3-256 fingerprint of the identity public key.
    pub pk_fingerprint: String,
}

/// Generates an X25519 identity key pair for sealed-sender authentication.
///
/// This is a separate keypair from a recipient's ML-KEM encryption key and
/// from any ML-DSA/SLH-DSA signing key: identity keys exist solely to derive
/// the deniable-authentication tag in [`seal`]/[`unseal_bytes`]. If
/// `passphrase` is `Some`, the identity seed is encrypted before PEM encoding.
#[must_use = "identity key pair must be saved or the generated keys are lost"]
pub fn identity_keygen_bytes(
    passphrase: Option<&str>,
) -> Result<IdentityKeygenResult, PqfileError> {
    let mut seed = Zeroizing::new([0u8; IDENTITY_SEED_LEN]);
    getrandom::fill(seed.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;

    let sk = X25519StaticSecret::from(*seed);
    let pk = X25519PublicKey::from(&sk);

    let pk_pem = pem::encode(&Pem::new(IDENTITY_PUB_TAG, pk.as_bytes().to_vec()));
    let sk_pem = if let Some(pp) = passphrase {
        let body = crate::passphrase::encrypt_identity_seed(&seed, pp)?;
        pem::encode(&Pem::new(IDENTITY_PRIV_ENC_TAG, body))
    } else {
        pem::encode(&Pem::new(IDENTITY_PRIV_TAG, seed.to_vec()))
    };

    let pk_fingerprint = crate::keygen::fingerprint(pk.as_bytes());

    Ok(IdentityKeygenResult {
        pk_pem,
        sk_pem,
        pk_fingerprint,
    })
}

/// Generates an identity key pair and writes it to `out_dir` as
/// `identity_pubkey.pem` / `identity_privkey.pem`.
/// Returns `OutputExists` if either file already exists and `force` is false.
pub fn identity_keygen(
    out_dir: &std::path::Path,
    force: bool,
    passphrase: Option<&str>,
) -> Result<IdentityKeygenResult, PqfileError> {
    let pk_path = out_dir.join("identity_pubkey.pem");
    let sk_path = out_dir.join("identity_privkey.pem");

    if !force {
        if pk_path.exists() {
            return Err(PqfileError::OutputExists(pk_path));
        }
        if sk_path.exists() {
            return Err(PqfileError::OutputExists(sk_path));
        }
    }

    let result = identity_keygen_bytes(passphrase)?;
    std::fs::write(&pk_path, &result.pk_pem)?;
    crate::fsutil::write_private_file(&sk_path, result.sk_pem.as_bytes())?;

    Ok(result)
}

/// Returns true if `pem_str` is a passphrase-encrypted identity private key.
/// Mirrors [`crate::keygen::is_encrypted_key`] for the CLI's passphrase-prompt logic.
#[must_use]
pub fn is_identity_key_encrypted(pem_str: &str) -> bool {
    pem::parse(pem_str)
        .map(|p| p.tag() == IDENTITY_PRIV_ENC_TAG)
        .unwrap_or(false)
}

fn parse_identity_sk(
    sk_pem: &str,
    passphrase: Option<&str>,
) -> Result<X25519StaticSecret, PqfileError> {
    let parsed = pem::parse(sk_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let seed: Zeroizing<[u8; IDENTITY_SEED_LEN]> = match parsed.tag() {
        IDENTITY_PRIV_TAG => {
            if parsed.contents().len() != IDENTITY_SEED_LEN {
                return Err(PqfileError::InvalidKeyLength {
                    expected: IDENTITY_SEED_LEN,
                    got: parsed.contents().len(),
                });
            }
            let mut s = Zeroizing::new([0u8; IDENTITY_SEED_LEN]);
            s.copy_from_slice(parsed.contents());
            s
        }
        IDENTITY_PRIV_ENC_TAG => {
            let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
            passphrase::decrypt_identity_seed(parsed.contents(), pp)?
        }
        tag => {
            return Err(PqfileError::InvalidPem(format!(
                "expected '{IDENTITY_PRIV_TAG}' or '{IDENTITY_PRIV_ENC_TAG}', got '{tag}'"
            )))
        }
    };
    Ok(X25519StaticSecret::from(*seed))
}

fn parse_identity_pk(pk_pem: &str) -> Result<X25519PublicKey, PqfileError> {
    let parsed = pem::parse(pk_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if parsed.tag() != IDENTITY_PUB_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected '{IDENTITY_PUB_TAG}', got '{}'",
            parsed.tag()
        )));
    }
    if parsed.contents().len() != IDENTITY_PK_LEN {
        return Err(PqfileError::InvalidKeyLength {
            expected: IDENTITY_PK_LEN,
            got: parsed.contents().len(),
        });
    }
    let mut bytes = [0u8; IDENTITY_PK_LEN];
    bytes.copy_from_slice(parsed.contents());
    Ok(X25519PublicKey::from(bytes))
}

/// Derives the 32-byte authentication key from the raw DH shared secret,
/// binding in both parties' identity public keys so the same shared secret
/// can never be replayed across a different (sender, recipient) pairing.
fn derive_auth_key(
    dh_shared: &[u8; 32],
    sender_pk: &X25519PublicKey,
    recipient_pk: &X25519PublicKey,
) -> Result<LockedSecret<32>, PqfileError> {
    let hk = Hkdf::<Sha256>::new(None, dh_shared);
    let mut info = Vec::with_capacity(AUTH_HKDF_INFO.len() + 64);
    info.extend_from_slice(AUTH_HKDF_INFO);
    info.extend_from_slice(sender_pk.as_bytes());
    info.extend_from_slice(recipient_pk.as_bytes());
    let mut okm = LockedSecret::<32>::zeroed();
    hk.expand(&info, okm.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    Ok(okm)
}

fn compute_tag(auth_key: &[u8], plaintext_hash: &[u8]) -> [u8; TAG_LEN] {
    let mut h = Sha3_256::new();
    h.update(TAG_CTX);
    h.update(auth_key);
    h.update(plaintext_hash);
    h.finalize().into()
}

/// Seals `input` with a deniable-authentication tag from `sender_identity_sk_pem`
/// (bound to `recipient_identity_pk_pem`), then encrypts the combined payload
/// (tag ++ plaintext) to `recipient_pubkey_pem`. Two-pass: first hashes the
/// input to compute the tag, then reads it again to prepend the tag and encrypt.
///
/// Because the tag is prepended inside the AEAD-authenticated ciphertext it
/// cannot be stripped after the fact.
#[must_use = "seal result must be checked"]
#[allow(clippy::too_many_arguments)]
pub fn seal<R: Read + io::Seek>(
    sender_identity_sk_pem: &str,
    sender_identity_passphrase: Option<&str>,
    recipient_identity_pk_pem: &str,
    recipient_pubkey_pem: &str,
    input: &mut R,
    input_len: u64,
    writer: &mut dyn Write,
    chunk_size: usize,
) -> Result<(), PqfileError> {
    let sender_sk = parse_identity_sk(sender_identity_sk_pem, sender_identity_passphrase)?;
    let sender_pk = X25519PublicKey::from(&sender_sk);
    let recipient_identity_pk = parse_identity_pk(recipient_identity_pk_pem)?;

    let dh = sender_sk.diffie_hellman(&recipient_identity_pk);
    let auth_key = derive_auth_key(dh.as_bytes(), &sender_pk, &recipient_identity_pk)?;

    let hash = crate::signcrypt::hash_stream(input)?;
    let tag = compute_tag(auth_key.as_ref(), &hash);

    input
        .seek(io::SeekFrom::Start(0))
        .map_err(PqfileError::Io)?;

    let tag_cursor = Cursor::new(tag.to_vec());
    let mut combined = tag_cursor.chain(input);
    let combined_size = TAG_LEN as u64 + input_len;
    encrypt::encrypt_stream(
        recipient_pubkey_pem,
        combined_size,
        chunk_size,
        &mut combined,
        writer,
    )
}

/// Seals `data` (in a single pass) and encrypts the combined payload to
/// `recipient_pubkey_pem`. Unlike [`seal`], this variant does not require
/// `Seek` and can accept any byte slice.
#[must_use = "seal_bytes result must be checked"]
pub fn seal_bytes(
    sender_identity_sk_pem: &str,
    sender_identity_passphrase: Option<&str>,
    recipient_identity_pk_pem: &str,
    recipient_pubkey_pem: &str,
    data: &[u8],
    writer: &mut dyn Write,
    chunk_size: usize,
) -> Result<(), PqfileError> {
    let sender_sk = parse_identity_sk(sender_identity_sk_pem, sender_identity_passphrase)?;
    let sender_pk = X25519PublicKey::from(&sender_sk);
    let recipient_identity_pk = parse_identity_pk(recipient_identity_pk_pem)?;

    let dh = sender_sk.diffie_hellman(&recipient_identity_pk);
    let auth_key = derive_auth_key(dh.as_bytes(), &sender_pk, &recipient_identity_pk)?;

    let hash: [u8; 32] = Sha3_256::digest(data).into();
    let tag = compute_tag(auth_key.as_ref(), &hash);

    let tag_cursor = Cursor::new(tag.to_vec());
    let mut combined = tag_cursor.chain(data);
    let combined_size = TAG_LEN as u64 + data.len() as u64;
    encrypt::encrypt_stream(
        recipient_pubkey_pem,
        combined_size,
        chunk_size,
        &mut combined,
        writer,
    )
}

/// Decrypts a sealed-sender file in memory and verifies the deniable
/// authentication tag against `sender_identity_pk_pem` before returning any data.
///
/// No plaintext bytes are accessible until the tag verifies. Every byte is
/// buffered internally; the caller receives data only when this function
/// returns `Ok(plaintext)`.
///
/// # Format limitation
///
/// This function uses `PqfReader` internally and therefore does not support v6
/// (compress-then-encrypt) files. Since `seal` never produces v6 output this
/// is not a problem in practice.
#[must_use = "unseal_bytes result must be checked; plaintext is only returned on Ok(())"]
pub fn unseal_bytes<R: Read>(
    recipient_privkey_pem: &str,
    recipient_privkey_passphrase: Option<&str>,
    recipient_identity_sk_pem: &str,
    recipient_identity_passphrase: Option<&str>,
    sender_identity_pk_pem: &str,
    reader: R,
) -> Result<Vec<u8>, PqfileError> {
    let recipient_identity_sk =
        parse_identity_sk(recipient_identity_sk_pem, recipient_identity_passphrase)?;
    let recipient_identity_pk = X25519PublicKey::from(&recipient_identity_sk);
    let sender_pk = parse_identity_pk(sender_identity_pk_pem)?;

    let mut pqf = PqfReader::new(reader, recipient_privkey_pem, recipient_privkey_passphrase)?;

    let mut tag_buf = [0u8; TAG_LEN];
    pqf.read_exact(&mut tag_buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            PqfileError::SealedSenderAuthFailed
        } else {
            PqfileError::Io(e)
        }
    })?;

    let mut hasher = Sha3_256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut plaintext: Vec<u8> = Vec::new();
    loop {
        let n = pqf.read(&mut buf).map_err(PqfileError::Io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        plaintext.extend_from_slice(&buf[..n]);
    }
    let hash = hasher.finalize();

    let dh = recipient_identity_sk.diffie_hellman(&sender_pk);
    let auth_key = derive_auth_key(dh.as_bytes(), &sender_pk, &recipient_identity_pk)?;
    let expected_tag = compute_tag(auth_key.as_ref(), &hash);

    if expected_tag.ct_eq(&tag_buf).unwrap_u8() != 1 {
        return Err(PqfileError::SealedSenderAuthFailed);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;

    fn do_seal(plaintext: &[u8]) -> (Vec<u8>, String, String, String, String) {
        let (recipient_pub, recipient_priv) = keygen_bytes(768, None).unwrap();
        let sender_id = identity_keygen_bytes(None).unwrap();
        let recipient_id = identity_keygen_bytes(None).unwrap();
        let mut output = Vec::new();
        seal_bytes(
            &sender_id.sk_pem,
            None,
            &recipient_id.pk_pem,
            &recipient_pub,
            plaintext,
            &mut output,
            CHUNK_SIZE,
        )
        .unwrap();
        (
            output,
            recipient_priv,
            recipient_id.sk_pem,
            sender_id.pk_pem,
            recipient_pub,
        )
    }

    #[test]
    fn seal_roundtrip_small() {
        let plaintext = b"hello sealed sender";
        let (ciphertext, recipient_priv, recipient_id_sk, sender_id_pk, _) = do_seal(plaintext);
        let out = unseal_bytes(
            &recipient_priv,
            None,
            &recipient_id_sk,
            None,
            &sender_id_pk,
            ciphertext.as_slice(),
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn seal_roundtrip_empty() {
        let plaintext = b"";
        let (ciphertext, recipient_priv, recipient_id_sk, sender_id_pk, _) = do_seal(plaintext);
        let out = unseal_bytes(
            &recipient_priv,
            None,
            &recipient_id_sk,
            None,
            &sender_id_pk,
            ciphertext.as_slice(),
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn seal_roundtrip_large() {
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 3 + 7).collect();
        let (ciphertext, recipient_priv, recipient_id_sk, sender_id_pk, _) = do_seal(&plaintext);
        let out = unseal_bytes(
            &recipient_priv,
            None,
            &recipient_id_sk,
            None,
            &sender_id_pk,
            ciphertext.as_slice(),
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn seal_stream_roundtrip() {
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE + 100).collect();
        let (recipient_pub, recipient_priv) = keygen_bytes(768, None).unwrap();
        let sender_id = identity_keygen_bytes(None).unwrap();
        let recipient_id = identity_keygen_bytes(None).unwrap();

        let mut input = std::io::Cursor::new(plaintext.clone());
        let mut output = Vec::new();
        seal(
            &sender_id.sk_pem,
            None,
            &recipient_id.pk_pem,
            &recipient_pub,
            &mut input,
            plaintext.len() as u64,
            &mut output,
            CHUNK_SIZE,
        )
        .unwrap();

        let out = unseal_bytes(
            &recipient_priv,
            None,
            &recipient_id.sk_pem,
            None,
            &sender_id.pk_pem,
            output.as_slice(),
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_sender_identity_fails() {
        let plaintext = b"test payload";
        let (ciphertext, recipient_priv, recipient_id_sk, _, _) = do_seal(plaintext);
        let other_sender_id = identity_keygen_bytes(None).unwrap();
        let result = unseal_bytes(
            &recipient_priv,
            None,
            &recipient_id_sk,
            None,
            &other_sender_id.pk_pem,
            ciphertext.as_slice(),
        );
        assert!(matches!(result, Err(PqfileError::SealedSenderAuthFailed)));
    }

    #[test]
    fn wrong_recipient_identity_fails() {
        let plaintext = b"test payload";
        let (ciphertext, recipient_priv, _, sender_id_pk, _) = do_seal(plaintext);
        let other_recipient_id = identity_keygen_bytes(None).unwrap();
        let result = unseal_bytes(
            &recipient_priv,
            None,
            &other_recipient_id.sk_pem,
            None,
            &sender_id_pk,
            ciphertext.as_slice(),
        );
        assert!(matches!(result, Err(PqfileError::SealedSenderAuthFailed)));
    }

    #[test]
    fn wrong_decryption_key_fails() {
        let plaintext = b"test payload";
        let (ciphertext, _, recipient_id_sk, sender_id_pk, _) = do_seal(plaintext);
        let (_, wrong_priv) = keygen_bytes(768, None).unwrap();
        let result = unseal_bytes(
            &wrong_priv,
            None,
            &recipient_id_sk,
            None,
            &sender_id_pk,
            ciphertext.as_slice(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn identity_keygen_passphrase_roundtrip() {
        let sender_id = identity_keygen_bytes(Some("pw")).unwrap();
        assert!(is_identity_key_encrypted(&sender_id.sk_pem));
        // Requires the passphrase to parse.
        let (recipient_pub, recipient_priv) = keygen_bytes(768, None).unwrap();
        let recipient_id = identity_keygen_bytes(None).unwrap();
        let plaintext = b"encrypted identity key";
        let mut output = Vec::new();
        seal_bytes(
            &sender_id.sk_pem,
            Some("pw"),
            &recipient_id.pk_pem,
            &recipient_pub,
            plaintext,
            &mut output,
            CHUNK_SIZE,
        )
        .unwrap();
        let out = unseal_bytes(
            &recipient_priv,
            None,
            &recipient_id.sk_pem,
            None,
            &sender_id.pk_pem,
            output.as_slice(),
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn identity_keygen_wrong_passphrase_fails() {
        let sender_id = identity_keygen_bytes(Some("pw")).unwrap();
        let mut output = Vec::new();
        let (recipient_pub, _) = keygen_bytes(768, None).unwrap();
        let recipient_id = identity_keygen_bytes(None).unwrap();
        let result = seal_bytes(
            &sender_id.sk_pem,
            Some("wrong"),
            &recipient_id.pk_pem,
            &recipient_pub,
            b"data",
            &mut output,
            CHUNK_SIZE,
        );
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_aead_before_tag_check() {
        let plaintext = b"test payload";
        let (mut ciphertext, recipient_priv, recipient_id_sk, sender_id_pk, _) = do_seal(plaintext);
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        let result = unseal_bytes(
            &recipient_priv,
            None,
            &recipient_id_sk,
            None,
            &sender_id_pk,
            ciphertext.as_slice(),
        );
        assert!(result.is_err());
    }
}
