use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Checksum, Fe1024, Fe32, Hrp};
use pem::Pem;

use crate::error::PqfileError;
use crate::format::{
    EK_LEN_1024, EK_LEN_512, EK_LEN_768, HYBRID_EK_LEN_768, KEM_VARIANT_1024, KEM_VARIANT_512,
    KEM_VARIANT_768, KEM_VARIANT_HYBRID_768,
};
use crate::keygen::{PUB_TAG, PUB_TAG_1024, PUB_TAG_512, PUB_TAG_HYBRID_768};

const HRP_STR: &str = "pqf";

// Bech32m with CODE_LENGTH = usize::MAX so long ML-KEM keys (ML-KEM-768 produces
// ~1900-char strings, above bech32m's 1023-char limit) don't trigger TooLong errors.
// Generator polynomial and TARGET_RESIDUE are identical to Bech32m so the checksum
// is fully compatible with any Bech32m verifier that doesn't enforce code-length.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum PqfChecksum {}

impl Checksum for PqfChecksum {
    type MidstateRepr = u32;
    type CorrectionField = Fe1024;
    const ROOT_GENERATOR: Fe1024 = Fe1024::new([Fe32::P, Fe32::X]);
    const ROOT_EXPONENTS: core::ops::RangeInclusive<usize> = 24..=26;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    const TARGET_RESIDUE: u32 = 0x2bc8_30a3;
}

/// Encodes a PEM public key as a compact `pqf1…` Bech32m string.
///
/// The payload is `variant_u16_le(2) || raw_key_bytes`. Supports all four KEM
/// variants (ML-KEM-512/768/1024, Hybrid X25519+ML-KEM-768).
pub fn encode_pubkey(pubkey_pem: &str) -> Result<String, PqfileError> {
    let p = pem::parse(pubkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let variant = variant_for_tag(p.tag()).ok_or_else(|| {
        PqfileError::InvalidPem(format!(
            "recipient_string: unsupported PEM tag '{}'; only public key PEMs are supported",
            p.tag()
        ))
    })?;

    let mut payload = Vec::with_capacity(2 + p.contents().len());
    payload.extend_from_slice(&variant.to_le_bytes());
    payload.extend_from_slice(p.contents());

    let hrp = Hrp::parse(HRP_STR).expect("'pqf' is a valid hrp");
    bech32::encode::<PqfChecksum>(hrp, &payload).map_err(|e| PqfileError::InvalidPem(e.to_string()))
}

/// Decodes a `pqf1…` Bech32m string into a PEM public key string.
///
/// Returns `InvalidPem` if the string has the wrong HRP, is not a valid Bech32m
/// encoding, carries an unknown KEM variant, or has the wrong key length.
pub fn decode_pubkey(recipient_str: &str) -> Result<String, PqfileError> {
    let checked = CheckedHrpstring::new::<PqfChecksum>(recipient_str)
        .map_err(|e| PqfileError::InvalidPem(format!("invalid recipient string: {e}")))?;

    if checked.hrp().as_str() != HRP_STR {
        return Err(PqfileError::InvalidPem(format!(
            "expected HRP '{}', got '{}'",
            HRP_STR,
            checked.hrp()
        )));
    }

    let payload: Vec<u8> = checked.byte_iter().collect();

    if payload.len() < 2 {
        return Err(PqfileError::InvalidPem(
            "recipient string payload too short".into(),
        ));
    }

    let kem_variant = u16::from_le_bytes([payload[0], payload[1]]);
    let key_bytes = &payload[2..];

    let expected_len = expected_ek_len(kem_variant).ok_or_else(|| {
        PqfileError::InvalidPem(format!(
            "recipient string: unknown KEM variant {kem_variant:#06x}"
        ))
    })?;

    if key_bytes.len() != expected_len {
        return Err(PqfileError::InvalidKeyLength {
            expected: expected_len,
            got: key_bytes.len(),
        });
    }

    let tag = tag_for_variant(kem_variant).expect("variant validated above");
    Ok(pem::encode(&Pem::new(tag, key_bytes)))
}

/// Returns `true` if `s` looks like a pqfile Bech32 recipient string (`pqf1…`).
/// Does not validate the encoding; use [`decode_pubkey`] for that.
pub fn is_recipient_string(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("pqf1")
}

fn variant_for_tag(tag: &str) -> Option<u16> {
    match tag {
        t if t == PUB_TAG_512 => Some(KEM_VARIANT_512),
        t if t == PUB_TAG => Some(KEM_VARIANT_768),
        t if t == PUB_TAG_1024 => Some(KEM_VARIANT_1024),
        t if t == PUB_TAG_HYBRID_768 => Some(KEM_VARIANT_HYBRID_768),
        _ => None,
    }
}

fn expected_ek_len(variant: u16) -> Option<usize> {
    match variant {
        KEM_VARIANT_512 => Some(EK_LEN_512),
        KEM_VARIANT_768 => Some(EK_LEN_768),
        KEM_VARIANT_1024 => Some(EK_LEN_1024),
        KEM_VARIANT_HYBRID_768 => Some(HYBRID_EK_LEN_768),
        _ => None,
    }
}

fn tag_for_variant(variant: u16) -> Option<&'static str> {
    match variant {
        KEM_VARIANT_512 => Some(PUB_TAG_512),
        KEM_VARIANT_768 => Some(PUB_TAG),
        KEM_VARIANT_1024 => Some(PUB_TAG_1024),
        KEM_VARIANT_HYBRID_768 => Some(PUB_TAG_HYBRID_768),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;

    #[test]
    fn roundtrip_768() {
        let (pub_pem, _) = keygen_bytes(768, None).unwrap();
        let encoded = encode_pubkey(&pub_pem).unwrap();
        assert!(
            encoded.starts_with("pqf1"),
            "must start with pqf1, got: {encoded}"
        );
        let decoded_pem = decode_pubkey(&encoded).unwrap();
        let re_encoded = encode_pubkey(&decoded_pem).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn roundtrip_512() {
        let (pub_pem, _) = keygen_bytes(512, None).unwrap();
        let encoded = encode_pubkey(&pub_pem).unwrap();
        assert!(encoded.starts_with("pqf1"));
        let decoded_pem = decode_pubkey(&encoded).unwrap();
        let re_encoded = encode_pubkey(&decoded_pem).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn roundtrip_1024() {
        let (pub_pem, _) = keygen_bytes(1024, None).unwrap();
        let encoded = encode_pubkey(&pub_pem).unwrap();
        assert!(encoded.starts_with("pqf1"));
        let decoded_pem = decode_pubkey(&encoded).unwrap();
        let re_encoded = encode_pubkey(&decoded_pem).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn is_recipient_string_detection() {
        assert!(is_recipient_string("pqf1abcdef"));
        assert!(is_recipient_string("PQF1ABCDEF"));
        assert!(!is_recipient_string("/path/to/pubkey.pem"));
        assert!(!is_recipient_string("not-a-string"));
    }

    #[test]
    fn decode_rejects_wrong_hrp() {
        let err = decode_pubkey("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh").unwrap_err();
        assert!(
            matches!(err, PqfileError::InvalidPem(_)),
            "wrong HRP should return InvalidPem"
        );
    }

    #[test]
    fn encode_rejects_private_key_pem() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        let err = encode_pubkey(&priv_pem).unwrap_err();
        assert!(
            matches!(err, PqfileError::InvalidPem(_)),
            "private key should be rejected"
        );
    }

    #[test]
    fn encrypt_decrypt_with_recipient_string() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let recipient_str = encode_pubkey(&pub_pem).unwrap();
        let decoded_pem = decode_pubkey(&recipient_str).unwrap();

        let plaintext = b"testing recipient string";
        let mut ct = Vec::new();
        crate::encrypt::encrypt_stream(
            &decoded_pem,
            plaintext.len() as u64,
            crate::format::CHUNK_SIZE,
            &mut plaintext.as_slice(),
            &mut ct,
        )
        .unwrap();

        let mut out = Vec::new();
        crate::decrypt::decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }
}
