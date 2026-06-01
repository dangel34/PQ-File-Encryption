/// Rekey a v3/v5 `.pqf` file to a new recipient without re-encrypting the payload.
///
/// Strategy: decapsulate the old shared secret (which is the AEAD key), encapsulate
/// it under the new public key wrapped in AES-256-GCM, and write a v4 multi-recipient
/// header pointing at the same AEAD payload. The ciphertext bytes are copied unchanged.
///
/// Restriction: only v3 and v5 files that use the default chunk size (65536 bytes) can
/// be zero-copy rekeyed, because v4 format always uses that chunk size. For v5 files with
/// a custom chunk size, re-encrypt the file with the new key instead.
use std::io::{Read, Write};

use crate::decrypt::decapsulate_for_rekey;
use crate::encrypt::encapsulate_for_rekey;
use crate::error::PqfileError;
use crate::format::{
    fill_chunk, PqfHeader, PqfHeaderV4, RecipientEntryV4, CHUNK_SIZE, VERSION_V3, VERSION_V5,
};

/// Rekeys a v3/v5 file to a new public key without re-encrypting the payload.
///
/// Reads from `reader` (positioned at the start of the `.pqf` file), decapsulates
/// using `old_privkey_pem`, re-wraps the payload key under `new_pubkey_pem`, and
/// writes a v4-format file to `writer`.
#[must_use = "rekey result must be used"]
pub fn rekey_stream(
    old_privkey_pem: &str,
    new_pubkey_pem: &str,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    passphrase: Option<&str>,
) -> Result<(), PqfileError> {
    let version = PqfHeader::read_magic_version(reader)?;
    match version {
        VERSION_V3 | VERSION_V5 => {}
        v => return Err(PqfileError::UnsupportedVersion(v)),
    }

    let header = PqfHeader::read_body(reader, version)?;

    if header.chunk_size as usize != CHUNK_SIZE {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "rekey requires the default chunk size ({CHUNK_SIZE} bytes); \
                 this file uses {} bytes. Re-encrypt with the new key instead.",
                header.chunk_size
            ),
        )));
    }

    let old_ss = decapsulate_for_rekey(old_privkey_pem, passphrase, &header)?;
    let (new_kem_ct, new_kem_variant, wrapped_key) =
        encapsulate_for_rekey(new_pubkey_pem, &old_ss)?;

    let v4_header = PqfHeaderV4 {
        recipients: vec![RecipientEntryV4 {
            kem_variant: new_kem_variant,
            kem_ciphertext: new_kem_ct,
            wrapped_key,
        }],
        nonce: header.nonce,
        original_size: header.original_size,
    };
    v4_header.write(writer)?;

    let mut buf = vec![0u8; CHUNK_SIZE + 16];
    loop {
        let n = fill_chunk(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::decrypt_stream;
    use crate::encrypt::encrypt_stream;
    use crate::keygen::keygen_bytes;

    #[test]
    fn rekey_v3_roundtrip() {
        let (pub_old, priv_old) = keygen_bytes(768, None).unwrap();
        let (pub_new, priv_new) = keygen_bytes(768, None).unwrap();
        let plaintext = b"rekey test payload";
        let mut enc = Vec::new();
        encrypt_stream(
            &pub_old,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut rekeyed = Vec::new();
        rekey_stream(&priv_old, &pub_new, &mut enc.as_slice(), &mut rekeyed, None).unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(&priv_new, &mut rekeyed.as_slice(), &mut decrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rekey_v3_old_key_cannot_decrypt() {
        let (pub_old, priv_old) = keygen_bytes(768, None).unwrap();
        let (pub_new, _) = keygen_bytes(768, None).unwrap();
        let plaintext = b"old key must not work after rekey";
        let mut enc = Vec::new();
        encrypt_stream(
            &pub_old,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut rekeyed = Vec::new();
        rekey_stream(&priv_old, &pub_new, &mut enc.as_slice(), &mut rekeyed, None).unwrap();

        let mut out = Vec::new();
        let result = decrypt_stream(&priv_old, &mut rekeyed.as_slice(), &mut out, None);
        assert!(result.is_err());
    }

    #[test]
    fn rekey_rejects_v2_input() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let (pub2, _) = keygen_bytes(768, None).unwrap();
        let pqf = crate::encrypt::encrypt_bytes(&pub_pem, b"v2 payload").unwrap();
        let mut out = Vec::new();
        let result = rekey_stream(&priv_pem, &pub2, &mut pqf.as_slice(), &mut out, None);
        assert!(matches!(result, Err(PqfileError::UnsupportedVersion(0x02))));
    }

    #[test]
    fn rekey_rejects_v4_input() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let (pub2, _) = keygen_bytes(768, None).unwrap();
        let mut enc = Vec::new();
        crate::encrypt::encrypt_stream_multi(
            &[pub_pem.as_str()],
            3,
            &mut b"abc".as_slice(),
            &mut enc,
        )
        .unwrap();
        let mut out = Vec::new();
        let result = rekey_stream(&priv_pem, &pub2, &mut enc.as_slice(), &mut out, None);
        assert!(matches!(result, Err(PqfileError::UnsupportedVersion(0x04))));
    }

    #[test]
    fn rekey_rejects_v5_custom_chunk_size() {
        let (pub_old, priv_old) = keygen_bytes(768, None).unwrap();
        let (pub_new, _) = keygen_bytes(768, None).unwrap();
        let mut enc = Vec::new();
        encrypt_stream(&pub_old, 5, 4096, &mut b"hello".as_slice(), &mut enc).unwrap();
        let mut out = Vec::new();
        let result = rekey_stream(&priv_old, &pub_new, &mut enc.as_slice(), &mut out, None);
        assert!(matches!(result, Err(PqfileError::Io(_))));
    }

    #[test]
    fn rekey_with_passphrase_old_key() {
        let (pub_old, priv_old) = keygen_bytes(768, Some("oldpass")).unwrap();
        let (pub_new, priv_new) = keygen_bytes(768, None).unwrap();
        let plaintext = b"passphrase rekey roundtrip";
        let mut enc = Vec::new();
        encrypt_stream(
            &pub_old,
            plaintext.len() as u64,
            CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut rekeyed = Vec::new();
        rekey_stream(
            &priv_old,
            &pub_new,
            &mut enc.as_slice(),
            &mut rekeyed,
            Some("oldpass"),
        )
        .unwrap();

        let mut decrypted = Vec::new();
        decrypt_stream(&priv_new, &mut rekeyed.as_slice(), &mut decrypted, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
