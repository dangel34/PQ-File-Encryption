/// Add a recipient to an existing v4, v7, or v8 multi-recipient file.
///
/// Strategy: decapsulate the session key using an existing recipient's private
/// key, re-encapsulate it under the new public key, and append a new recipient
/// entry to the header without touching the payload ciphertext.  The payload
/// bytes are streamed through unchanged (zero-copy).
///
/// Supported input formats: v4 (multi-recipient), v7 (anonymous multi-recipient),
/// and v8 (variant-blind anonymous multi-recipient).
/// For v3/v5 single-recipient files, use `rekey` to change the recipient or
/// `encrypt_stream_multi` to produce a new multi-recipient file.
///
/// **Anonymity note for v7/v8 files:** the new recipient entry is appended without
/// re-shuffling the existing entries.  An observer who can compare the file before
/// and after the operation will see the new entry at the end.  To restore full
/// entry-order anonymity, re-encrypt all recipients with `--anonymous-recipients`.
use std::io::{Read, Write};

use crate::decrypt::{recover_session_key_multi, recover_session_key_v8};
use crate::encrypt::encapsulate_for_rekey;
use crate::error::PqfileError;
use crate::format::{
    fill_chunk, PqfHeader, PqfHeaderV4, PqfHeaderV7, PqfHeaderV8, RecipientEntryV4,
    RecipientEntryV7, RecipientEntryV8, CHUNK_SIZE, PADDED_CT_LEN, VERSION_V4, VERSION_V7,
    VERSION_V8,
};

/// Adds `new_pubkey_pem` as a recipient to an existing v4 or v7 file.
///
/// `reader` must be positioned at the start of the `.pqf` file.
/// The result written to `writer` is:
/// - v4 input: a v4 file with all original recipients plus the new one.
/// - v7 input: a v7 file with all original recipients (padded) plus the new one (padded).
#[must_use = "add-recipient result must be used"]
pub fn add_recipient_stream(
    existing_privkey_pem: &str,
    new_pubkey_pem: &str,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    passphrase: Option<&str>,
) -> Result<AddRecipientInfo, PqfileError> {
    let version = PqfHeader::read_magic_version(reader)?;

    match version {
        VERSION_V4 => add_to_v4(
            existing_privkey_pem,
            new_pubkey_pem,
            passphrase,
            reader,
            writer,
        ),
        VERSION_V7 => add_to_v7(
            existing_privkey_pem,
            new_pubkey_pem,
            passphrase,
            reader,
            writer,
        ),
        VERSION_V8 => add_to_v8(
            existing_privkey_pem,
            new_pubkey_pem,
            passphrase,
            reader,
            writer,
        ),
        v => Err(PqfileError::UnsupportedVersion(v)),
    }
}

/// Metadata returned by a successful `add_recipient_stream` call.
#[non_exhaustive]
#[derive(Debug)]
pub struct AddRecipientInfo {
    /// Total number of recipients in the resulting file (original + 1).
    pub recipient_count: usize,
    /// KEM variant of the newly added recipient.
    pub new_recipient_variant: u16,
}

fn add_to_v4(
    existing_privkey_pem: &str,
    new_pubkey_pem: &str,
    passphrase: Option<&str>,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<AddRecipientInfo, PqfileError> {
    let header = PqfHeaderV4::read_body(reader)?;

    let session_key = recover_session_key_multi(
        existing_privkey_pem,
        passphrase,
        &header
            .recipients
            .iter()
            .map(|e| (e.kem_variant, e.kem_ciphertext.as_slice(), &e.wrapped_key))
            .collect::<Vec<_>>(),
    )?;

    let (new_kem_ct, new_kem_variant, new_wrapped_key) =
        encapsulate_for_rekey(new_pubkey_pem, &session_key)?;

    let mut recipients = header.recipients;
    recipients.push(RecipientEntryV4 {
        kem_variant: new_kem_variant,
        kem_ciphertext: new_kem_ct,
        wrapped_key: new_wrapped_key,
    });
    let recipient_count = recipients.len();

    let new_header = PqfHeaderV4 {
        recipients,
        nonce: header.nonce,
        original_size: header.original_size,
    };
    new_header.write(writer)?;
    stream_payload(reader, writer)?;

    Ok(AddRecipientInfo {
        recipient_count,
        new_recipient_variant: new_kem_variant,
    })
}

fn add_to_v7(
    existing_privkey_pem: &str,
    new_pubkey_pem: &str,
    passphrase: Option<&str>,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<AddRecipientInfo, PqfileError> {
    let header = PqfHeaderV7::read_body(reader)?;

    let session_key = recover_session_key_multi(
        existing_privkey_pem,
        passphrase,
        &header
            .recipients
            .iter()
            .map(|e| (e.kem_variant, e.kem_ciphertext.as_slice(), &e.wrapped_key))
            .collect::<Vec<_>>(),
    )?;

    let (new_kem_ct, new_kem_variant, new_wrapped_key) =
        encapsulate_for_rekey(new_pubkey_pem, &session_key)?;

    let mut recipients = header.recipients;
    recipients.push(RecipientEntryV7 {
        kem_variant: new_kem_variant,
        kem_ciphertext: new_kem_ct,
        wrapped_key: new_wrapped_key,
    });
    let recipient_count = recipients.len();

    let new_header = PqfHeaderV7 {
        recipients,
        nonce: header.nonce,
        original_size: header.original_size,
    };
    new_header.write(writer)?;
    stream_payload(reader, writer)?;

    Ok(AddRecipientInfo {
        recipient_count,
        new_recipient_variant: new_kem_variant,
    })
}

/// Streams the AEAD payload from `reader` to `writer` unchanged.
fn stream_payload(reader: &mut dyn Read, writer: &mut dyn Write) -> Result<(), PqfileError> {
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

fn add_to_v8(
    existing_privkey_pem: &str,
    new_pubkey_pem: &str,
    passphrase: Option<&str>,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<AddRecipientInfo, PqfileError> {
    let header = PqfHeaderV8::read_body(reader)?;

    let session_key = recover_session_key_v8(existing_privkey_pem, passphrase, &header.recipients)?;

    let (new_kem_ct, new_kem_variant, new_wrapped_key) =
        encapsulate_for_rekey(new_pubkey_pem, &session_key)?;

    let mut padded_ct = [0u8; PADDED_CT_LEN];
    padded_ct[..new_kem_ct.len()].copy_from_slice(&new_kem_ct);

    let mut recipients = header.recipients;
    recipients.push(RecipientEntryV8 {
        padded_ct,
        wrapped_key: new_wrapped_key,
    });
    let recipient_count = recipients.len();

    let new_header = PqfHeaderV8 {
        recipients,
        nonce: header.nonce,
        original_size: header.original_size,
    };
    new_header.write(writer)?;
    stream_payload(reader, writer)?;

    Ok(AddRecipientInfo {
        recipient_count,
        new_recipient_variant: new_kem_variant,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::decrypt_stream;
    use crate::encrypt::{encrypt_stream_multi, encrypt_stream_multi_anon};
    use crate::keygen::keygen_bytes;

    #[test]
    fn add_recipient_v4_new_key_can_decrypt() {
        let (pub1, priv1) = keygen_bytes(768, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let plaintext = b"add recipient v4 test";

        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut result = Vec::new();
        let info =
            add_recipient_stream(&priv1, &pub2, &mut enc.as_slice(), &mut result, None).unwrap();

        assert_eq!(info.recipient_count, 2);

        // Both old and new key should decrypt successfully.
        for priv_pem in [&priv1, &priv2] {
            let mut out = Vec::new();
            decrypt_stream(priv_pem, &mut result.as_slice(), &mut out, None).unwrap();
            assert_eq!(out, plaintext);
        }
    }

    #[test]
    fn add_recipient_v4_original_key_still_works() {
        let (pub1, priv1) = keygen_bytes(768, None).unwrap();
        let (pub2, _priv2) = keygen_bytes(768, None).unwrap();
        let plaintext = b"original key must still decrypt";

        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut result = Vec::new();
        add_recipient_stream(&priv1, &pub2, &mut enc.as_slice(), &mut result, None).unwrap();

        let mut out = Vec::new();
        decrypt_stream(&priv1, &mut result.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn add_recipient_v4_wrong_existing_key_fails() {
        let (pub1, _priv1) = keygen_bytes(768, None).unwrap();
        let (_pub2, priv2) = keygen_bytes(768, None).unwrap();
        let (pub3, _priv3) = keygen_bytes(768, None).unwrap();
        let plaintext = b"wrong key test";

        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut result = Vec::new();
        let err = add_recipient_stream(&priv2, &pub3, &mut enc.as_slice(), &mut result, None)
            .unwrap_err();
        assert!(matches!(err, PqfileError::NoMatchingRecipient));
    }

    #[test]
    fn add_recipient_v4_mixed_variants() {
        let (pub768, priv768) = keygen_bytes(768, None).unwrap();
        let (pub1024, priv1024) = keygen_bytes(1024, None).unwrap();
        let plaintext = b"mixed variant add recipient";

        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub768.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut result = Vec::new();
        let info = add_recipient_stream(&priv768, &pub1024, &mut enc.as_slice(), &mut result, None)
            .unwrap();

        assert_eq!(info.recipient_count, 2);
        assert_eq!(info.new_recipient_variant, crate::format::KEM_VARIANT_1024);

        let mut out = Vec::new();
        decrypt_stream(&priv1024, &mut result.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn add_recipient_v4_rejects_non_v4_input() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let (pub2, _) = keygen_bytes(768, None).unwrap();
        let pqf = crate::encrypt::encrypt_bytes(&pub_pem, b"v2 payload").unwrap();

        let mut out = Vec::new();
        let err = add_recipient_stream(&priv_pem, &pub2, &mut pqf.as_slice(), &mut out, None)
            .unwrap_err();
        assert!(matches!(err, PqfileError::UnsupportedVersion(0x02)));
    }

    #[test]
    fn add_recipient_v7_new_key_can_decrypt() {
        let (pub1, priv1) = keygen_bytes(768, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let plaintext = b"add recipient v7 test";

        let mut enc = Vec::new();
        encrypt_stream_multi_anon(
            &[pub1.as_str(), pub2.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let (pub3, priv3) = keygen_bytes(768, None).unwrap();
        let mut result = Vec::new();
        let info =
            add_recipient_stream(&priv1, &pub3, &mut enc.as_slice(), &mut result, None).unwrap();

        assert_eq!(info.recipient_count, 3);

        let mut out = Vec::new();
        decrypt_stream(&priv3, &mut result.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);

        // Existing recipients still work.
        let mut out2 = Vec::new();
        decrypt_stream(&priv2, &mut result.as_slice(), &mut out2, None).unwrap();
        assert_eq!(out2, plaintext);
    }

    #[test]
    fn add_recipient_v4_accumulate_three_recipients() {
        let (pub1, priv1) = keygen_bytes(768, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let (pub3, priv3) = keygen_bytes(768, None).unwrap();
        let plaintext = b"three recipients";

        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str()],
            plaintext.len() as u64,
            &mut plaintext.as_slice(),
            &mut enc,
        )
        .unwrap();

        let mut enc2 = Vec::new();
        add_recipient_stream(&priv1, &pub2, &mut enc.as_slice(), &mut enc2, None).unwrap();

        let mut enc3 = Vec::new();
        let info =
            add_recipient_stream(&priv2, &pub3, &mut enc2.as_slice(), &mut enc3, None).unwrap();
        assert_eq!(info.recipient_count, 3);

        for priv_pem in [&priv1, &priv2, &priv3] {
            let mut out = Vec::new();
            decrypt_stream(priv_pem, &mut enc3.as_slice(), &mut out, None).unwrap();
            assert_eq!(out, plaintext);
        }
    }
}
