//! Signable public key certificates: a minimal PKI layer built entirely from
//! existing primitives (no new dependencies).
//!
//! A CA signing key (ML-DSA-65 or SLH-DSA-SHAKE-192f, via [`crate::sign`])
//! attests to a subject public key together with a human-readable label, a
//! validity window, and an allowed-use bitmask ([`cert_use`]). The subject key
//! itself is opaque to this module - it is stored and returned as its own
//! self-describing PEM (a KEM public key, a hybrid public key, or a verifying
//! key), so any current or future pqfile public key type can be certified
//! without a change here.
//!
//! Certificates do not chain: each is verified directly against a CA
//! verifying key supplied by the caller. There is no revocation mechanism
//! beyond the validity window; use short windows and re-issue as needed.

use pem::Pem;

use crate::error::PqfileError;
use crate::sign;

const CERT_TAG: &str = "PQFILE CERTIFICATE";
const CERT_MAGIC: &[u8; 4] = b"PQFC";
const CERT_VERSION: u8 = 1;

/// Longest label accepted, in bytes. Purely a sanity cap; labels are free text.
const MAX_LABEL_LEN: usize = 256;
/// Longest subject PEM tag accepted, in bytes.
const MAX_TAG_LEN: usize = 64;
/// Longest subject key body accepted, in bytes. The largest real subject key
/// today is an ML-DSA-65 verifying key (1952 bytes); this leaves generous room
/// for future key types without allowing unbounded allocation from a crafted
/// certificate.
const MAX_SUBJECT_KEY_LEN: usize = 16_384;

/// Bitmask of permitted uses for a certified public key. Combine with `|`.
pub mod cert_use {
    /// The certified key may be used as an encryption recipient (KEM public key).
    pub const ENCRYPT: u8 = 0x01;
    /// The certified key may be used to verify signatures (verifying key).
    pub const SIGN: u8 = 0x02;
}

/// A verified certificate: the CA signature has already been checked.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Human-readable label describing the subject (free text, CA-assigned).
    pub label: String,
    /// Validity window start, Unix seconds (inclusive).
    pub not_before: u64,
    /// Validity window end, Unix seconds (inclusive).
    pub not_after: u64,
    /// Bitmask of [`cert_use`] flags the CA authorizes for the subject key.
    pub allowed_use: u8,
    /// PEM-encoded subject public key, self-describing via its own PEM tag.
    pub subject_pem: String,
}

impl Certificate {
    /// Returns `true` if `now` (Unix seconds) falls within the validity window.
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    /// Returns `true` if every bit set in `use_mask` is also set in `allowed_use`.
    #[must_use]
    pub fn permits(&self, use_mask: u8) -> bool {
        self.allowed_use & use_mask == use_mask
    }
}

/// Issues a certificate: the CA (`ca_sk_pem`) signs `subject_pem` together
/// with `label`, the validity window (`not_before`..=`not_after`, Unix
/// seconds), and `allowed_use` ([`cert_use`] bits). Returns the PEM-encoded
/// certificate.
///
/// `subject_pem` may be any pqfile public key PEM (KEM public key, hybrid
/// public key, or verifying key); its own PEM tag is embedded and carried
/// through unchanged, so [`verify_cert`] can hand it straight to `encrypt` or
/// `verify` without the caller needing to know the key type in advance.
#[must_use = "issued certificate must be saved or distributed"]
pub fn issue_cert(
    ca_sk_pem: &str,
    ca_passphrase: Option<&str>,
    subject_pem: &str,
    label: &str,
    not_before: u64,
    not_after: u64,
    allowed_use: u8,
) -> Result<String, PqfileError> {
    if label.len() > MAX_LABEL_LEN {
        return Err(PqfileError::InvalidPem(format!(
            "certificate label exceeds {MAX_LABEL_LEN} bytes"
        )));
    }
    if not_after < not_before {
        return Err(PqfileError::InvalidPem(
            "certificate not_after precedes not_before".into(),
        ));
    }

    let subject = pem::parse(subject_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if subject.tag().len() > MAX_TAG_LEN {
        return Err(PqfileError::InvalidPem(
            "certificate subject PEM tag exceeds maximum length".into(),
        ));
    }
    // The `pem` crate's tag scanner doesn't reject embedded control characters
    // (e.g. newlines), and this tag round-trips verbatim through the signed
    // body into `verify_cert`'s output PEM. Nothing downstream currently does
    // anything riskier than an exact-string match against it, but reject the
    // class here defensively rather than relying on every future consumer to.
    if subject.tag().chars().any(|c| c.is_control()) {
        return Err(PqfileError::InvalidPem(
            "certificate subject PEM tag contains control characters".into(),
        ));
    }
    if subject.contents().len() > MAX_SUBJECT_KEY_LEN {
        return Err(PqfileError::InvalidPem(
            "certificate subject key exceeds maximum size".into(),
        ));
    }

    let body = encode_body(
        label,
        not_before,
        not_after,
        allowed_use,
        subject.tag(),
        subject.contents(),
    );
    let sig = sign::sign_bytes(ca_sk_pem, &body, ca_passphrase)?;

    let mut out = body;
    out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    out.extend_from_slice(&sig);

    Ok(pem::encode(&Pem::new(CERT_TAG, out)))
}

/// Verifies `cert_pem`'s signature against the CA verifying key `ca_vk_pem`
/// and checks the validity window against `now` (Unix seconds).
///
/// Does not check [`cert_use`]; callers that need a specific use should call
/// [`Certificate::permits`] on the result before trusting the subject key for
/// that purpose.
#[must_use = "verify result must be used"]
pub fn verify_cert(ca_vk_pem: &str, cert_pem: &str, now: u64) -> Result<Certificate, PqfileError> {
    let p = pem::parse(cert_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != CERT_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{CERT_TAG}', got '{}'",
            p.tag()
        )));
    }

    let data = p.contents();
    let (cert, body_end) = parse_fields(data)?;
    let body = &data[..body_end];
    let mut pos = body_end;
    let sig_len = u32::from_le_bytes(take(data, &mut pos, 4)?.try_into().unwrap()) as usize;
    let sig = take(data, &mut pos, sig_len)?;
    if pos != data.len() {
        return Err(PqfileError::InvalidPem(
            "certificate has trailing bytes after signature".into(),
        ));
    }
    sign::verify_bytes(ca_vk_pem, body, sig)?;

    if !cert.is_valid_at(now) {
        return Err(PqfileError::CertNotValid {
            not_before: cert.not_before,
            not_after: cert.not_after,
            now,
        });
    }
    Ok(cert)
}

/// Returns `true` if `pem_str` looks like a pqfile certificate (correct PEM
/// tag). Does not validate the signature or structure; use [`verify_cert`]
/// for that.
#[must_use]
pub fn is_certificate(pem_str: &str) -> bool {
    pem::parse(pem_str)
        .map(|p| p.tag() == CERT_TAG)
        .unwrap_or(false)
}

// ── binary framing ──────────────────────────────────────────────────────────
//
// body = MAGIC(4) || VERSION(1) || NOT_BEFORE(8 LE) || NOT_AFTER(8 LE) ||
//        ALLOWED_USE(1) || LABEL_LEN(2 LE) || LABEL || SUBJECT_TAG_LEN(1) ||
//        SUBJECT_TAG || SUBJECT_KEY_LEN(4 LE) || SUBJECT_KEY
// cert  = body || SIG_LEN(4 LE) || SIG
//
// The body is self-delimiting (every variable-length field carries its own
// length prefix), so parsing it also tells us exactly where it ends and the
// trailing SIG_LEN field begins - no outer length prefix is needed.

fn encode_body(
    label: &str,
    not_before: u64,
    not_after: u64,
    allowed_use: u8,
    subject_tag: &str,
    subject_key: &[u8],
) -> Vec<u8> {
    let label_bytes = label.as_bytes();
    let tag_bytes = subject_tag.as_bytes();
    let mut out = Vec::with_capacity(
        4 + 1 + 8 + 8 + 1 + 2 + label_bytes.len() + 1 + tag_bytes.len() + 4 + subject_key.len(),
    );
    out.extend_from_slice(CERT_MAGIC);
    out.push(CERT_VERSION);
    out.extend_from_slice(&not_before.to_le_bytes());
    out.extend_from_slice(&not_after.to_le_bytes());
    out.push(allowed_use);
    out.extend_from_slice(&(label_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(label_bytes);
    out.push(tag_bytes.len() as u8);
    out.extend_from_slice(tag_bytes);
    out.extend_from_slice(&(subject_key.len() as u32).to_le_bytes());
    out.extend_from_slice(subject_key);
    out
}

/// Parses the self-delimiting body fields from the front of `data` (which is
/// `body || SIG_LEN(4) || SIG`) and returns the decoded [`Certificate`]
/// together with the byte offset where the body ends (and `SIG_LEN` begins).
/// Does not touch the signature; the caller slices `&data[..body_end]` as the
/// exact bytes that were signed.
fn parse_fields(data: &[u8]) -> Result<(Certificate, usize), PqfileError> {
    let mut pos = 0usize;
    let magic = take(data, &mut pos, 4)?;
    if magic != CERT_MAGIC {
        return Err(PqfileError::InvalidPem(
            "not a pqfile certificate (bad magic)".into(),
        ));
    }
    let version = take(data, &mut pos, 1)?[0];
    if version != CERT_VERSION {
        return Err(PqfileError::InvalidPem(format!(
            "unsupported certificate version: {version}"
        )));
    }
    let not_before = u64::from_le_bytes(take(data, &mut pos, 8)?.try_into().unwrap());
    let not_after = u64::from_le_bytes(take(data, &mut pos, 8)?.try_into().unwrap());
    let allowed_use = take(data, &mut pos, 1)?[0];

    let label_len = u16::from_le_bytes(take(data, &mut pos, 2)?.try_into().unwrap()) as usize;
    if label_len > MAX_LABEL_LEN {
        return Err(PqfileError::InvalidPem(
            "certificate label exceeds maximum length".into(),
        ));
    }
    let label = String::from_utf8(take(data, &mut pos, label_len)?.to_vec())
        .map_err(|_| PqfileError::InvalidPem("certificate label is not valid UTF-8".into()))?;

    let tag_len = take(data, &mut pos, 1)?[0] as usize;
    if tag_len > MAX_TAG_LEN {
        return Err(PqfileError::InvalidPem(
            "certificate subject PEM tag exceeds maximum length".into(),
        ));
    }
    let subject_tag = String::from_utf8(take(data, &mut pos, tag_len)?.to_vec()).map_err(|_| {
        PqfileError::InvalidPem("certificate subject tag is not valid UTF-8".into())
    })?;

    let key_len = u32::from_le_bytes(take(data, &mut pos, 4)?.try_into().unwrap()) as usize;
    if key_len > MAX_SUBJECT_KEY_LEN {
        return Err(PqfileError::InvalidPem(
            "certificate subject key exceeds maximum size".into(),
        ));
    }
    let subject_key = take(data, &mut pos, key_len)?;
    let subject_pem = pem::encode(&Pem::new(subject_tag, subject_key.to_vec()));

    Ok((
        Certificate {
            label,
            not_before,
            not_after,
            allowed_use,
            subject_pem,
        },
        pos,
    ))
}

fn take<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], PqfileError> {
    if *pos + len > data.len() {
        return Err(PqfileError::InvalidPem("certificate truncated".into()));
    }
    let slice = &data[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use crate::sign::sign_keygen_bytes;

    fn ca() -> (String, String) {
        let r = sign_keygen_bytes(None).unwrap();
        (r.vk_pem, r.sk_pem)
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let (ca_vk, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();

        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "alice's laptop",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();

        let cert = verify_cert(&ca_vk, &cert_pem, 1_500).unwrap();
        assert_eq!(cert.label, "alice's laptop");
        assert_eq!(cert.not_before, 1_000);
        assert_eq!(cert.not_after, 2_000);
        assert!(cert.permits(cert_use::ENCRYPT));
        assert!(!cert.permits(cert_use::SIGN));
        assert_eq!(
            pem::parse(&cert.subject_pem).unwrap().tag(),
            "ML-KEM-768 PUBLIC KEY"
        );
    }

    #[test]
    fn verify_rejects_before_validity_window() {
        let (ca_vk, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        let err = verify_cert(&ca_vk, &cert_pem, 999).unwrap_err();
        assert!(matches!(err, PqfileError::CertNotValid { .. }));
    }

    #[test]
    fn verify_rejects_after_validity_window() {
        let (ca_vk, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        let err = verify_cert(&ca_vk, &cert_pem, 2_001).unwrap_err();
        assert!(matches!(err, PqfileError::CertNotValid { .. }));
    }

    #[test]
    fn verify_accepts_window_boundaries() {
        let (ca_vk, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        verify_cert(&ca_vk, &cert_pem, 1_000).unwrap();
        verify_cert(&ca_vk, &cert_pem, 2_000).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_ca_key() {
        let (_, ca_sk) = ca();
        let (other_ca_vk, _) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        let err = verify_cert(&other_ca_vk, &cert_pem, 1_500).unwrap_err();
        assert!(matches!(err, PqfileError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let (ca_vk, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        let p = pem::parse(&cert_pem).unwrap();
        let tag = p.tag().to_owned();
        let mut contents = p.into_contents();
        // Flip a byte inside the label, well before the trailing signature.
        contents[10] ^= 0xff;
        let tampered = pem::encode(&Pem::new(tag, contents));
        let err = verify_cert(&ca_vk, &tampered, 1_500).unwrap_err();
        assert!(matches!(err, PqfileError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_rejects_wrong_pem_tag() {
        let (ca_vk, _) = ca();
        let wrong = pem::encode(&Pem::new("WRONG TAG", vec![0u8; 16]));
        let err = verify_cert(&ca_vk, &wrong, 0).unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }

    #[test]
    fn issue_rejects_not_after_before_not_before() {
        let (_, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let err = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            2_000,
            1_000,
            cert_use::ENCRYPT,
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }

    #[test]
    fn issue_rejects_oversized_label() {
        let (_, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let label = "x".repeat(MAX_LABEL_LEN + 1);
        let err = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            &label,
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }

    #[test]
    fn issue_rejects_subject_tag_with_control_characters() {
        let (_, ca_sk) = ca();
        let subject_pub = pem::encode(&Pem::new("ML-KEM-768 PUBLIC\nKEY", vec![0u8; 1184]));
        let err = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }

    #[test]
    fn permits_checks_combined_bits() {
        let (ca_vk, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT | cert_use::SIGN,
        )
        .unwrap();
        let cert = verify_cert(&ca_vk, &cert_pem, 1_500).unwrap();
        assert!(cert.permits(cert_use::ENCRYPT));
        assert!(cert.permits(cert_use::SIGN));
        assert!(cert.permits(cert_use::ENCRYPT | cert_use::SIGN));
    }

    #[test]
    fn certifies_a_verifying_key_for_sign_use() {
        let (ca_vk, ca_sk) = ca();
        let subject_signer = sign_keygen_bytes(None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_signer.vk_pem,
            "release signing key",
            1_000,
            2_000,
            cert_use::SIGN,
        )
        .unwrap();
        let cert = verify_cert(&ca_vk, &cert_pem, 1_500).unwrap();
        assert!(cert.permits(cert_use::SIGN));
        assert_eq!(
            pem::parse(&cert.subject_pem).unwrap().tag(),
            "ML-DSA-65 VERIFYING KEY"
        );
    }

    #[test]
    fn is_certificate_detects_tag() {
        let (_, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        assert!(is_certificate(&cert_pem));
        assert!(!is_certificate(&subject_pub));
        assert!(!is_certificate("not pem at all"));
    }

    #[test]
    fn verify_rejects_truncated_certificate() {
        let (ca_vk, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        let cert_pem = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        let p = pem::parse(&cert_pem).unwrap();
        let tag = p.tag().to_owned();
        let short: Vec<u8> = p.contents()[..2].to_vec();
        let truncated = pem::encode(&Pem::new(tag, short));
        let err = verify_cert(&ca_vk, &truncated, 1_500).unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }
}
