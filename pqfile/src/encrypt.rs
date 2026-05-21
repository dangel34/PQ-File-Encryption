use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    EncapsulationKey768, EncapsulationKey1024,
    array::Array,
    kem::Encapsulate,
};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

use crate::format::{
    BASE_NONCE_LEN, CHUNK_SIZE, EK_LEN, EK_LEN_1024, HEADER_LEN, HYBRID_CT_LEN_768,
    HYBRID_EK_LEN_768, KEM_VARIANT, KEM_VARIANT_1024, KEM_VARIANT_HYBRID_768, NONCE_LEN,
    VERSION, VERSION_V3, PqfHeader, PqfHeaderV4, RecipientEntryV4, WRAPPED_KEY_LEN,
    chunk_aad, chunk_nonce,
};
use crate::keygen::{PUB_TAG, PUB_TAG_1024, PUB_TAG_HYBRID_768};

enum EkVariant {
    Kem768(EncapsulationKey768),
    Kem1024(EncapsulationKey1024),
    HybridKem768 { x25519_pk: [u8; 32], ml_ek: EncapsulationKey768 },
}

#[allow(dead_code)]
pub fn encrypt(
    pubkey_path: &Path,
    input_path: &Path,
    output_path: Option<&Path>,
) -> Result<(), PqfileError> {
    let pubkey_pem = fs::read_to_string(pubkey_path)?;
    let plaintext = fs::read(input_path)?;
    let output = encrypt_bytes(&pubkey_pem, &plaintext)?;
    let out: PathBuf = match output_path {
        Some(p) => p.to_path_buf(),
        None => {
            let mut s = input_path.as_os_str().to_owned();
            s.push(".pqf");
            PathBuf::from(s)
        }
    };
    fs::write(&out, output)?;
    Ok(())
}

/// Encrypts `plaintext` in a single pass (v2 format). Kept for library consumers
/// and backward-compatibility tests; new code should use [`encrypt_stream`].
pub fn encrypt_bytes(pubkey_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, PqfileError> {
    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;

    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| PqfileError::EncryptionFailure)?;

    let original_size = plaintext.len() as u64;

    let header = PqfHeader { version: VERSION, kem_variant, kem_ciphertext: kem_ct_bytes, nonce: nonce_bytes, original_size };
    let mut output = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
    header.write(&mut output)?;

    let key = Key::from_slice(ss_bytes.as_ref());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &output })
        .map_err(|_| PqfileError::EncryptionFailure)?;

    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Encrypts a stream of plaintext bytes using v3 chunked AEAD.
///
/// Each 64 KiB chunk is independently authenticated with a position-bound nonce
/// and an AAD that includes the chunk counter and an end-of-stream flag. This
/// prevents truncation and reordering attacks while bounding peak memory use to
/// a constant number of chunks regardless of file size.
///
/// `original_size` is written into the header for informational purposes (pass 0
/// when unknown, e.g. when reading from stdin).
pub fn encrypt_stream(
    pubkey_pem: &str,
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;

    let (kem_ct_bytes, ss_bytes) = encapsulate(ek)?;

    // Use 8 random bytes as the base nonce; the last 4 bytes of the 12-byte
    // header nonce field are zeroed (the per-chunk counter is added at runtime).
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let header = PqfHeader {
        version: VERSION_V3,
        kem_variant,
        kem_ciphertext: kem_ct_bytes,
        nonce: nonce_bytes,
        original_size,
    };
    header.write(writer)?;

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN].try_into().unwrap();
    let key = Key::from_slice(ss_bytes.as_ref());
    let cipher = ChaCha20Poly1305::new(key);

    // Lookahead buffering: read the current chunk, then peek at the next one to
    // determine whether current is the last chunk before encrypting it.
    let mut current = vec![0u8; CHUNK_SIZE];
    let mut current_len = fill_chunk(reader, &mut current)?;
    let mut counter: u32 = 0;

    loop {
        let mut next = vec![0u8; CHUNK_SIZE];
        let next_len = fill_chunk(reader, &mut next)?;
        let is_last = next_len == 0;

        let cn = chunk_nonce(base_nonce, counter);
        let aad = chunk_aad(counter, is_last);
        let chunk_ct = cipher
            .encrypt(
                Nonce::from_slice(&cn),
                Payload { msg: &current[..current_len], aad: &aad },
            )
            .map_err(|_| PqfileError::EncryptionFailure)?;
        writer.write_all(&chunk_ct)?;

        if is_last {
            break;
        }

        counter = counter.checked_add(1).ok_or(PqfileError::EncryptionFailure)?;
        current = next;
        current_len = next_len;
    }

    Ok(())
}

fn parse_encapsulation_key(pubkey_pem: &str) -> Result<(EkVariant, u16), PqfileError> {
    let pem = pem::parse(pubkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let raw = pem.contents();
    match pem.tag() {
        t if t == PUB_TAG => {
            let raw_arr = Array::try_from(raw)
                .map_err(|_| PqfileError::InvalidKeyLength { expected: EK_LEN, got: raw.len() })?;
            let ek = EncapsulationKey768::new(&raw_arr)
                .map_err(|_| PqfileError::InvalidPem("invalid ML-KEM-768 public key".to_owned()))?;
            Ok((EkVariant::Kem768(ek), KEM_VARIANT))
        }
        t if t == PUB_TAG_1024 => {
            let raw_arr = Array::try_from(raw)
                .map_err(|_| PqfileError::InvalidKeyLength { expected: EK_LEN_1024, got: raw.len() })?;
            let ek = EncapsulationKey1024::new(&raw_arr)
                .map_err(|_| PqfileError::InvalidPem("invalid ML-KEM-1024 public key".to_owned()))?;
            Ok((EkVariant::Kem1024(ek), KEM_VARIANT_1024))
        }
        t if t == PUB_TAG_HYBRID_768 => {
            if raw.len() != HYBRID_EK_LEN_768 {
                return Err(PqfileError::InvalidKeyLength { expected: HYBRID_EK_LEN_768, got: raw.len() });
            }
            let x25519_pk_bytes: [u8; 32] = raw[..32].try_into().unwrap();
            let ml_raw = &raw[32..];
            let ml_arr = Array::try_from(ml_raw)
                .map_err(|_| PqfileError::InvalidKeyLength { expected: EK_LEN, got: ml_raw.len() })?;
            let ml_ek = EncapsulationKey768::new(&ml_arr)
                .map_err(|_| PqfileError::InvalidPem("invalid ML-KEM-768 public key in hybrid".to_owned()))?;
            Ok((EkVariant::HybridKem768 { x25519_pk: x25519_pk_bytes, ml_ek }, KEM_VARIANT_HYBRID_768))
        }
        _ => Err(PqfileError::InvalidPem("unrecognised public key tag".to_owned())),
    }
}

fn encapsulate(ek: EkVariant) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), PqfileError> {
    match ek {
        EkVariant::Kem768(ek) => {
            let (ct, ss) = ek.encapsulate();
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok((ct.as_slice().to_vec(), ss_bytes))
        }
        EkVariant::Kem1024(ek) => {
            let (ct, ss) = ek.encapsulate();
            let mut ss_bytes = Zeroizing::new([0u8; 32]);
            ss_bytes.copy_from_slice(ss.as_slice());
            Ok((ct.as_slice().to_vec(), ss_bytes))
        }
        EkVariant::HybridKem768 { x25519_pk, ml_ek } => {
            // Generate a fresh ephemeral X25519 scalar.
            let mut eph_scalar = Zeroizing::new([0u8; 32]);
            getrandom::fill(eph_scalar.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;
            let eph_sk = X25519StaticSecret::from(*eph_scalar);
            let eph_pk = X25519PublicKey::from(&eph_sk);

            // X25519 DH.
            let recipient_pk = X25519PublicKey::from(x25519_pk);
            let x25519_ss = Zeroizing::new(eph_sk.diffie_hellman(&recipient_pk));

            // ML-KEM-768 encapsulate.
            let (ml_ct, ml_ss) = ml_ek.encapsulate();

            // Combined KEM ciphertext: eph_pk(32) || ml_ct(1088).
            let mut kem_ct = Vec::with_capacity(HYBRID_CT_LEN_768);
            kem_ct.extend_from_slice(eph_pk.as_bytes());
            kem_ct.extend_from_slice(ml_ct.as_slice());

            // Derive 32-byte key via HKDF-SHA256(IKM = x25519_ss || ml_ss).
            let ss = hybrid_hkdf(x25519_ss.as_bytes(), ml_ss.as_slice())?;
            Ok((kem_ct, ss))
        }
    }
}

fn hybrid_hkdf(x25519_ss: &[u8; 32], ml_ss: &[u8]) -> Result<Zeroizing<[u8; 32]>, PqfileError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(ml_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"pqfile-hybrid-v1", okm.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    Ok(okm)
}

/// Encrypts a stream to multiple recipients (v4 format).
///
/// Each recipient's public key is used to encapsulate a fresh shared secret that wraps
/// a single random 32-byte session key K under AES-256-GCM. Any holder of a matching
/// private key can recover K and decrypt the file.
pub fn encrypt_stream_multi(
    pubkey_pems: &[&str],
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    // Generate a random session key K that will encrypt the file.
    let mut session_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(session_key.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;

    // For each recipient, encapsulate and wrap the session key.
    let mut recipients: Vec<RecipientEntryV4> = Vec::with_capacity(pubkey_pems.len());
    for pubkey_pem in pubkey_pems {
        let (ek, kem_variant) = parse_encapsulation_key(pubkey_pem)?;
        let (kem_ct, ss) = encapsulate(ek)?;
        let wrapped_key = wrap_session_key(&session_key, &ss)?;
        recipients.push(RecipientEntryV4 { kem_variant, kem_ciphertext: kem_ct, wrapped_key });
    }

    // Generate the base nonce (8 random bytes; last 4 are the per-chunk counter).
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let header = PqfHeaderV4 { recipients, nonce: nonce_bytes, original_size };
    header.write(writer)?;

    let base_nonce: &[u8; BASE_NONCE_LEN] = nonce_bytes[..BASE_NONCE_LEN].try_into().unwrap();
    let key = chacha20poly1305::Key::from_slice(session_key.as_ref());
    let cipher = ChaCha20Poly1305::new(key);

    let mut current = vec![0u8; CHUNK_SIZE];
    let mut current_len = fill_chunk(reader, &mut current)?;
    let mut counter: u32 = 0;

    loop {
        let mut next = vec![0u8; CHUNK_SIZE];
        let next_len = fill_chunk(reader, &mut next)?;
        let is_last = next_len == 0;

        let cn = chunk_nonce(base_nonce, counter);
        let aad = chunk_aad(counter, is_last);
        let chunk_ct = cipher
            .encrypt(
                chacha20poly1305::Nonce::from_slice(&cn),
                chacha20poly1305::aead::Payload { msg: &current[..current_len], aad: &aad },
            )
            .map_err(|_| PqfileError::EncryptionFailure)?;
        writer.write_all(&chunk_ct)?;

        if is_last { break; }
        counter = counter.checked_add(1).ok_or(PqfileError::EncryptionFailure)?;
        current = next;
        current_len = next_len;
    }

    Ok(())
}

/// Wraps `session_key` under `ss` using AES-256-GCM with a zero nonce.
/// The zero nonce is safe because `ss` is a fresh random KEM shared secret per encryption.
fn wrap_session_key(session_key: &[u8; 32], ss: &[u8; 32]) -> Result<[u8; WRAPPED_KEY_LEN], PqfileError> {
    let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(ss));
    let nonce = AesNonce::from([0u8; 12]);
    let ct = cipher
        .encrypt(&nonce, session_key.as_slice())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    let mut out = [0u8; WRAPPED_KEY_LEN];
    out.copy_from_slice(&ct);
    Ok(out)
}

/// Fills `buf` from `reader`, returning the number of bytes read.
/// Reads until the buffer is full or EOF is reached.
fn fill_chunk<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> Result<usize, PqfileError> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use tempfile::tempdir;

    fn keypair() -> (String, String) {
        keygen_bytes(768, None).unwrap()
    }

    fn keypair_1024() -> (String, String) {
        keygen_bytes(1024, None).unwrap()
    }

    fn write_pubkey(dir: &Path) -> PathBuf {
        let (pub_pem, _) = keypair();
        let path = dir.join("pk.pem");
        fs::write(&path, pub_pem.as_bytes()).unwrap();
        path
    }

    #[test]
    fn encrypt_writes_to_custom_output_path() {
        let tmp = tempdir().unwrap();
        let pk = write_pubkey(tmp.path());
        let input = tmp.path().join("plain.txt");
        fs::write(&input, b"hello custom output").unwrap();
        let out = tmp.path().join("custom.pqf");
        encrypt(&pk, &input, Some(&out)).unwrap();
        assert!(out.exists());
    }

    #[test]
    fn encrypt_defaults_to_input_with_pqf_suffix() {
        let tmp = tempdir().unwrap();
        let pk = write_pubkey(tmp.path());
        let input = tmp.path().join("data.txt");
        fs::write(&input, b"hello default").unwrap();
        encrypt(&pk, &input, None).unwrap();
        assert!(tmp.path().join("data.txt.pqf").exists());
    }

    #[test]
    fn encrypt_rejects_malformed_public_key_bytes() {
        let bad_key = pem::encode(&pem::Pem::new("ML-KEM-768 PUBLIC KEY", vec![0xFFu8; 1184]));
        let result = encrypt_bytes(&bad_key, b"hello");
        assert!(matches!(result, Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn encrypt_rejects_unrecognised_key_tag() {
        let bad_key = pem::encode(&pem::Pem::new("UNKNOWN KEY", vec![0u8; 1184]));
        let result = encrypt_bytes(&bad_key, b"hello");
        assert!(matches!(result, Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn encrypt_stream_rejects_malformed_public_key() {
        let bad_key = pem::encode(&pem::Pem::new("ML-KEM-768 PUBLIC KEY", vec![0xFFu8; 1184]));
        let mut reader: &[u8] = b"data";
        let mut writer = Vec::new();
        let result = encrypt_stream(&bad_key, 4, &mut reader, &mut writer);
        assert!(matches!(result, Err(PqfileError::InvalidPem(_))));
    }

    #[test]
    fn encrypt_stream_empty_input() {
        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = &[];
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 0, &mut reader, &mut writer).unwrap();
        // Header (1115 bytes for 768) + one empty chunk AEAD tag (16 bytes)
        assert_eq!(writer.len(), HEADER_LEN + 16);
    }

    #[test]
    fn encrypt_stream_small_input_produces_header_plus_one_chunk() {
        let (pub_pem, _) = keypair();
        let plaintext = b"small payload";
        let mut reader: &[u8] = plaintext;
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, plaintext.len() as u64, &mut reader, &mut writer).unwrap();
        assert_eq!(writer.len(), HEADER_LEN + plaintext.len() + 16);
    }

    #[test]
    fn encrypt_stream_exact_chunk_boundary() {
        let (pub_pem, _) = keypair();
        let plaintext = vec![0xABu8; CHUNK_SIZE];
        let mut reader: &[u8] = &plaintext;
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, plaintext.len() as u64, &mut reader, &mut writer).unwrap();
        assert_eq!(writer.len(), HEADER_LEN + CHUNK_SIZE + 16);
    }

    #[test]
    fn encrypt_stream_multi_chunk() {
        let (pub_pem, _) = keypair();
        let plaintext = vec![0x42u8; CHUNK_SIZE * 2 + 1];
        let mut reader: &[u8] = &plaintext;
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, plaintext.len() as u64, &mut reader, &mut writer).unwrap();
        let expected = HEADER_LEN + (CHUNK_SIZE + 16) * 2 + (1 + 16);
        assert_eq!(writer.len(), expected);
    }

    #[test]
    fn encrypt_stream_writes_v3_version_byte() {
        use std::io::Cursor;
        use crate::format::VERSION_V3;

        let (pub_pem, _) = keypair();
        let mut reader: &[u8] = b"test";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 4, &mut reader, &mut writer).unwrap();

        let header = PqfHeader::read(&mut Cursor::new(&writer)).unwrap();
        assert_eq!(header.version, VERSION_V3);
    }

    #[test]
    fn encrypt_stream_1024_writes_correct_header() {
        use std::io::Cursor;
        use crate::format::{HEADER_LEN_1024, KEM_VARIANT_1024, VERSION_V3};

        let (pub_pem, _) = keypair_1024();
        let mut reader: &[u8] = b"test";
        let mut writer = Vec::new();
        encrypt_stream(&pub_pem, 4, &mut reader, &mut writer).unwrap();

        let header = PqfHeader::read(&mut Cursor::new(&writer)).unwrap();
        assert_eq!(header.version, VERSION_V3);
        assert_eq!(header.kem_variant, KEM_VARIANT_1024);
        assert_eq!(header.kem_ciphertext.len(), 1568);
        // header + one small chunk
        assert_eq!(writer.len(), HEADER_LEN_1024 + 4 + 16);
    }
}
