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
//! verifying key supplied by the caller. Revocation before a certificate's
//! own validity window naturally expires is available via
//! [`RevocationList`]/[`revoke_cert`], a CA-signed list of revoked
//! certificate identifiers analogous to a compact CRL - optional and
//! separate from [`verify_cert`] itself, mirroring how the `.revoked`
//! sidecar convention for raw keys ([`crate::revoke`]) is a separate check
//! from decoding the key.

use pem::Pem;
use sha3::{Digest, Sha3_256};

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

const REVOCATION_TAG: &str = "PQFILE CERTIFICATE REVOCATION LIST";
const REVOCATION_MAGIC: &[u8; 4] = b"PQRL";
const REVOCATION_VERSION: u8 = 1;
/// Longest revocation reason accepted, in bytes. Same cap as a cert label.
const MAX_REVOCATION_REASON_LEN: usize = MAX_LABEL_LEN;
/// Largest revocation-list entry count accepted on read, bounding allocation
/// from a crafted list. A CA managing more revocations than this should
/// rotate to a fresh CA key rather than growing one list indefinitely.
const MAX_REVOCATION_ENTRIES: usize = 65_536;
const CERT_ID_LEN: usize = 32;

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

/// Computes a stable identifier for `cert_pem`, used as the lookup key in a
/// [`RevocationList`]. Derived from SHA3-256 of the certificate's signed body
/// (everything the CA's signature covers: label, validity window, allowed
/// use, and subject key), so two certificates with byte-identical fields
/// share an identifier and re-issuing with different parameters produces a
/// new one. Does not check the certificate's signature - computing the id of
/// a bogus certificate just produces a meaningless one.
pub fn cert_id(cert_pem: &str) -> Result<[u8; CERT_ID_LEN], PqfileError> {
    let p = pem::parse(cert_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != CERT_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{CERT_TAG}', got '{}'",
            p.tag()
        )));
    }
    let data = p.contents();
    let (_, body_end) = parse_fields(data)?;
    Ok(Sha3_256::digest(&data[..body_end]).into())
}

/// One revoked-certificate entry in a [`RevocationList`].
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// Identifier of the revoked certificate; see [`cert_id`].
    pub cert_id: [u8; CERT_ID_LEN],
    /// When the certificate was revoked, Unix seconds.
    pub revoked_at: u64,
    /// Free-text reason supplied at revocation time (CA-assigned).
    pub reason: String,
}

/// A verified, CA-signed list of revoked certificate identifiers - a compact
/// analogue of an X.509 CRL. Produced by [`revoke_cert`], read back by
/// [`verify_revocation_list`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct RevocationList {
    /// When this list was most recently generated and signed, Unix seconds.
    pub issued_at: u64,
    /// Revoked-certificate entries, in the order they were appended.
    pub entries: Vec<RevokedEntry>,
}

impl RevocationList {
    /// Returns the matching entry, if `id` (see [`cert_id`]) is present.
    #[must_use]
    pub fn find(&self, id: &[u8; CERT_ID_LEN]) -> Option<&RevokedEntry> {
        self.entries.iter().find(|e| &e.cert_id == id)
    }
}

/// Revokes `cert_pem_to_revoke`: computes its [`cert_id`], appends a new
/// [`RevokedEntry`] to `existing_list_pem`'s entries (or starts a fresh list
/// when `None`), and re-signs the whole list with `ca_sk_pem`. `now` is used
/// as both the new entry's `revoked_at` and the list's `issued_at`. Returns
/// the new PEM-encoded revocation list, which replaces any previous one -
/// there is no way to un-revoke a certificate; re-issue a new one instead.
///
/// `existing_list_pem`'s entries are carried forward structurally without
/// re-checking its own signature first - the same trust boundary
/// [`issue_cert`] already assumes for its inputs (a CA controls the files on
/// its own machine). Verify a list obtained from elsewhere with
/// [`verify_revocation_list`] before passing it here if that boundary does
/// not hold for your deployment.
#[must_use = "revoked list must be saved or distributed"]
pub fn revoke_cert(
    ca_sk_pem: &str,
    ca_passphrase: Option<&str>,
    existing_list_pem: Option<&str>,
    cert_pem_to_revoke: &str,
    reason: &str,
    now: u64,
) -> Result<String, PqfileError> {
    if reason.len() > MAX_REVOCATION_REASON_LEN {
        return Err(PqfileError::InvalidPem(format!(
            "revocation reason exceeds {MAX_REVOCATION_REASON_LEN} bytes"
        )));
    }
    let id = cert_id(cert_pem_to_revoke)?;

    let mut entries = match existing_list_pem {
        Some(pem_str) => parse_revocation_list_structural(pem_str)?.1,
        None => Vec::new(),
    };
    if entries.len() >= MAX_REVOCATION_ENTRIES {
        return Err(PqfileError::InvalidPem(format!(
            "revocation list already holds the maximum of {MAX_REVOCATION_ENTRIES} entries"
        )));
    }
    entries.push(RevokedEntry {
        cert_id: id,
        revoked_at: now,
        reason: reason.to_owned(),
    });

    let body = encode_revocation_body(now, &entries);
    let sig = sign::sign_bytes(ca_sk_pem, &body, ca_passphrase)?;

    let mut out = body;
    out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    out.extend_from_slice(&sig);

    Ok(pem::encode(&Pem::new(REVOCATION_TAG, out)))
}

/// Verifies `list_pem`'s signature against the CA verifying key `ca_vk_pem`.
/// Unlike [`verify_cert`], there is no validity window to check - a
/// revocation list never expires on its own; consult a freshly obtained copy
/// if staleness matters for your threat model.
#[must_use = "verify result must be used"]
pub fn verify_revocation_list(
    ca_vk_pem: &str,
    list_pem: &str,
) -> Result<RevocationList, PqfileError> {
    let p = pem::parse(list_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != REVOCATION_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{REVOCATION_TAG}', got '{}'",
            p.tag()
        )));
    }
    let data = p.contents();
    let (issued_at, entries, body_end) = parse_revocation_fields(data)?;
    let body = &data[..body_end];
    let mut pos = body_end;
    let sig_len = u32::from_le_bytes(take(data, &mut pos, 4)?.try_into().unwrap()) as usize;
    let sig = take(data, &mut pos, sig_len)?;
    if pos != data.len() {
        return Err(PqfileError::InvalidPem(
            "revocation list has trailing bytes after signature".into(),
        ));
    }
    sign::verify_bytes(ca_vk_pem, body, sig)?;

    Ok(RevocationList { issued_at, entries })
}

/// Returns `true` if `pem_str` looks like a pqfile revocation list (correct
/// PEM tag). Does not validate the signature or structure; use
/// [`verify_revocation_list`] for that.
#[must_use]
pub fn is_revocation_list(pem_str: &str) -> bool {
    pem::parse(pem_str)
        .map(|p| p.tag() == REVOCATION_TAG)
        .unwrap_or(false)
}

/// Renders a [`cert_id`] as the same 16-byte colon-hex prefix used elsewhere
/// in pqfile for fingerprint display (see [`crate::keygen::fingerprint`]).
#[must_use]
pub fn cert_id_hex(id: &[u8; CERT_ID_LEN]) -> String {
    id.iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Checks `cert_pem` against an already-[`verify_revocation_list`]-verified
/// `list`, failing with [`PqfileError::CertRevoked`] if its [`cert_id`]
/// appears in the list. Callers that want revocation enforced call this
/// after [`verify_cert`] succeeds; mirrors [`crate::revoke::check_not_revoked`]
/// being a separate step from decoding a raw key.
#[must_use = "revocation check must be inspected; ignoring it means trusting a revoked certificate"]
pub fn check_cert_not_revoked(list: &RevocationList, cert_pem: &str) -> Result<(), PqfileError> {
    let id = cert_id(cert_pem)?;
    if let Some(entry) = list.find(&id) {
        return Err(PqfileError::CertRevoked {
            cert_id: cert_id_hex(&id),
            reason: entry.reason.clone(),
        });
    }
    Ok(())
}

/// Convenience wrapper for the common "revocation checking is opt-in" shape
/// every caller of [`verify_cert`] ends up needing: if `revocation_list_pem`
/// is `Some`, verifies it against `ca_vk_pem` and checks `cert_pem` against
/// it; a `None` list is a no-op. Equivalent to calling
/// [`verify_revocation_list`] then [`check_cert_not_revoked`] by hand.
#[must_use = "revocation check must be inspected; ignoring it means trusting a revoked certificate"]
pub fn check_cert_not_revoked_pem(
    ca_vk_pem: &str,
    revocation_list_pem: Option<&str>,
    cert_pem: &str,
) -> Result<(), PqfileError> {
    let Some(list_pem) = revocation_list_pem else {
        return Ok(());
    };
    let list = verify_revocation_list(ca_vk_pem, list_pem)?;
    check_cert_not_revoked(&list, cert_pem)
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

// ── revocation list binary framing ──────────────────────────────────────────
//
// body = MAGIC(4) || VERSION(1) || ISSUED_AT(8 LE) || COUNT(4 LE) || ENTRY*COUNT
// entry = CERT_ID(32) || REVOKED_AT(8 LE) || REASON_LEN(2 LE) || REASON
// list  = body || SIG_LEN(4 LE) || SIG
//
// Self-delimiting for the same reason as the certificate body above: every
// variable-length field carries its own length prefix, so parsing tells us
// exactly where the signed body ends and SIG_LEN begins.

fn encode_revocation_body(issued_at: u64, entries: &[RevokedEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 8 + 4 + entries.len() * (CERT_ID_LEN + 8 + 2));
    out.extend_from_slice(REVOCATION_MAGIC);
    out.push(REVOCATION_VERSION);
    out.extend_from_slice(&issued_at.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&e.cert_id);
        out.extend_from_slice(&e.revoked_at.to_le_bytes());
        let reason_bytes = e.reason.as_bytes();
        out.extend_from_slice(&(reason_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(reason_bytes);
    }
    out
}

/// Parses the self-delimiting body fields from the front of `data` (which is
/// `body || SIG_LEN(4) || SIG`) and returns `(issued_at, entries, body_end)`.
/// Does not touch the signature; callers slice `&data[..body_end]` as the
/// exact bytes that were signed.
fn parse_revocation_fields(data: &[u8]) -> Result<(u64, Vec<RevokedEntry>, usize), PqfileError> {
    let mut pos = 0usize;
    let magic = take(data, &mut pos, 4)?;
    if magic != REVOCATION_MAGIC {
        return Err(PqfileError::InvalidPem(
            "not a pqfile revocation list (bad magic)".into(),
        ));
    }
    let version = take(data, &mut pos, 1)?[0];
    if version != REVOCATION_VERSION {
        return Err(PqfileError::InvalidPem(format!(
            "unsupported revocation list version: {version}"
        )));
    }
    let issued_at = u64::from_le_bytes(take(data, &mut pos, 8)?.try_into().unwrap());
    let count = u32::from_le_bytes(take(data, &mut pos, 4)?.try_into().unwrap()) as usize;
    if count > MAX_REVOCATION_ENTRIES {
        return Err(PqfileError::InvalidPem(
            "revocation list entry count exceeds maximum".into(),
        ));
    }

    let mut entries = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let cert_id: [u8; CERT_ID_LEN] = take(data, &mut pos, CERT_ID_LEN)?.try_into().unwrap();
        let revoked_at = u64::from_le_bytes(take(data, &mut pos, 8)?.try_into().unwrap());
        let reason_len = u16::from_le_bytes(take(data, &mut pos, 2)?.try_into().unwrap()) as usize;
        if reason_len > MAX_REVOCATION_REASON_LEN {
            return Err(PqfileError::InvalidPem(
                "revocation reason exceeds maximum length".into(),
            ));
        }
        let reason = String::from_utf8(take(data, &mut pos, reason_len)?.to_vec())
            .map_err(|_| PqfileError::InvalidPem("revocation reason is not valid UTF-8".into()))?;
        entries.push(RevokedEntry {
            cert_id,
            revoked_at,
            reason,
        });
    }
    Ok((issued_at, entries, pos))
}

/// Parses `list_pem`'s entries without checking its signature - used only by
/// [`revoke_cert`] to carry forward an existing list's entries under the
/// trust boundary documented there. Not exported: external callers that have
/// a list PEM should use [`verify_revocation_list`] instead.
fn parse_revocation_list_structural(
    list_pem: &str,
) -> Result<(u64, Vec<RevokedEntry>), PqfileError> {
    let p = pem::parse(list_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    if p.tag() != REVOCATION_TAG {
        return Err(PqfileError::InvalidPem(format!(
            "expected tag '{REVOCATION_TAG}', got '{}'",
            p.tag()
        )));
    }
    let (issued_at, entries, _) = parse_revocation_fields(p.contents())?;
    Ok((issued_at, entries))
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

    // ── revocation ────────────────────────────────────────────────────────

    fn issued(ca_sk: &str, label: &str) -> String {
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        issue_cert(
            ca_sk,
            None,
            &subject_pub,
            label,
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap()
    }

    #[test]
    fn cert_id_is_stable_for_identical_bodies() {
        let (_, ca_sk) = ca();
        let (subject_pub, _) = keygen_bytes(768, None).unwrap();
        // Two separate issuances with identical fields sign identical bodies
        // (this crate's ML-DSA signing is deterministic), so both certs must
        // carry the same id.
        let a = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        let b = issue_cert(
            &ca_sk,
            None,
            &subject_pub,
            "x",
            1_000,
            2_000,
            cert_use::ENCRYPT,
        )
        .unwrap();
        assert_eq!(cert_id(&a).unwrap(), cert_id(&b).unwrap());
    }

    #[test]
    fn cert_id_differs_for_different_labels() {
        let (_, ca_sk) = ca();
        let a = issued(&ca_sk, "alice");
        let b = issued(&ca_sk, "bob");
        assert_ne!(cert_id(&a).unwrap(), cert_id(&b).unwrap());
    }

    #[test]
    fn revoke_then_check_fails() {
        let (ca_vk, ca_sk) = ca();
        let cert_pem = issued(&ca_sk, "x");
        let list_pem = revoke_cert(&ca_sk, None, None, &cert_pem, "compromised", 5_000).unwrap();
        let list = verify_revocation_list(&ca_vk, &list_pem).unwrap();
        assert_eq!(list.issued_at, 5_000);
        let err = check_cert_not_revoked(&list, &cert_pem).unwrap_err();
        assert!(matches!(err, PqfileError::CertRevoked { .. }));
    }

    #[test]
    fn check_passes_for_unrevoked_cert() {
        let (ca_vk, ca_sk) = ca();
        let revoked = issued(&ca_sk, "revoked");
        let untouched = issued(&ca_sk, "untouched");
        let list_pem = revoke_cert(&ca_sk, None, None, &revoked, "x", 5_000).unwrap();
        let list = verify_revocation_list(&ca_vk, &list_pem).unwrap();
        check_cert_not_revoked(&list, &untouched).unwrap();
    }

    #[test]
    fn revoke_cert_appends_to_existing_list() {
        let (ca_vk, ca_sk) = ca();
        let a = issued(&ca_sk, "a");
        let b = issued(&ca_sk, "b");
        let list1 = revoke_cert(&ca_sk, None, None, &a, "first", 5_000).unwrap();
        let list2 = revoke_cert(&ca_sk, None, Some(&list1), &b, "second", 6_000).unwrap();
        let list = verify_revocation_list(&ca_vk, &list2).unwrap();
        assert_eq!(list.entries.len(), 2);
        assert_eq!(list.issued_at, 6_000);
        check_cert_not_revoked(&list, &a).unwrap_err();
        check_cert_not_revoked(&list, &b).unwrap_err();
    }

    #[test]
    fn revocation_reason_carries_through() {
        let (ca_vk, ca_sk) = ca();
        let cert_pem = issued(&ca_sk, "x");
        let list_pem =
            revoke_cert(&ca_sk, None, None, &cert_pem, "private key leaked", 5_000).unwrap();
        let list = verify_revocation_list(&ca_vk, &list_pem).unwrap();
        let err = check_cert_not_revoked(&list, &cert_pem).unwrap_err();
        assert!(err.to_string().contains("private key leaked"));
    }

    #[test]
    fn verify_revocation_list_rejects_wrong_ca_key() {
        let (_, ca_sk) = ca();
        let (other_ca_vk, _) = ca();
        let cert_pem = issued(&ca_sk, "x");
        let list_pem = revoke_cert(&ca_sk, None, None, &cert_pem, "x", 5_000).unwrap();
        let err = verify_revocation_list(&other_ca_vk, &list_pem).unwrap_err();
        assert!(matches!(err, PqfileError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_revocation_list_rejects_tampered_body() {
        let (ca_vk, ca_sk) = ca();
        let cert_pem = issued(&ca_sk, "x");
        let list_pem = revoke_cert(&ca_sk, None, None, &cert_pem, "tamper me", 5_000).unwrap();
        let p = pem::parse(&list_pem).unwrap();
        let tag = p.tag().to_owned();
        let mut contents = p.into_contents();
        // Flip a byte inside the (raw, non-UTF-8-validated) cert_id field,
        // well before the trailing signature - mirrors
        // `verify_rejects_tampered_body` above, which likewise avoids the
        // UTF-8-validated label/reason text so the tamper cannot surface as
        // a structural parse error instead of a signature mismatch.
        contents[20] ^= 0xff;
        let tampered = pem::encode(&Pem::new(tag, contents));
        let err = verify_revocation_list(&ca_vk, &tampered).unwrap_err();
        assert!(matches!(err, PqfileError::SignatureVerificationFailed));
    }

    #[test]
    fn revoke_cert_rejects_oversized_reason() {
        let (_, ca_sk) = ca();
        let cert_pem = issued(&ca_sk, "x");
        let reason = "x".repeat(MAX_REVOCATION_REASON_LEN + 1);
        let err = revoke_cert(&ca_sk, None, None, &cert_pem, &reason, 5_000).unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }

    #[test]
    fn verify_revocation_list_rejects_oversized_entry_count() {
        let (ca_vk, ca_sk) = ca();
        let mut body = Vec::new();
        body.extend_from_slice(REVOCATION_MAGIC);
        body.push(REVOCATION_VERSION);
        body.extend_from_slice(&5_000u64.to_le_bytes());
        body.extend_from_slice(&((MAX_REVOCATION_ENTRIES as u32) + 1).to_le_bytes());
        let sig = sign::sign_bytes(&ca_sk, &body, None).unwrap();
        let mut out = body;
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(&sig);
        let crafted = pem::encode(&Pem::new(REVOCATION_TAG, out));
        let err = verify_revocation_list(&ca_vk, &crafted).unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }

    #[test]
    fn is_revocation_list_detects_tag() {
        let (_, ca_sk) = ca();
        let cert_pem = issued(&ca_sk, "x");
        let list_pem = revoke_cert(&ca_sk, None, None, &cert_pem, "x", 5_000).unwrap();
        assert!(is_revocation_list(&list_pem));
        assert!(!is_revocation_list(&cert_pem));
        assert!(!is_revocation_list("not pem at all"));
    }

    #[test]
    fn verify_revocation_list_rejects_wrong_pem_tag() {
        let (ca_vk, _) = ca();
        let wrong = pem::encode(&Pem::new("WRONG TAG", vec![0u8; 16]));
        let err = verify_revocation_list(&ca_vk, &wrong).unwrap_err();
        assert!(matches!(err, PqfileError::InvalidPem(_)));
    }
}
