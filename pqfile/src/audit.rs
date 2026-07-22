//! Encrypted, signed, hash-chained audit log for encrypt/decrypt events.
//!
//! Each event becomes an [`AuditRecord`] (timestamp, command name, a BLAKE3
//! fingerprint of the file involved, and a fingerprint of the key involved),
//! signed by the operator's own ML-DSA/SLH-DSA key, then encrypted to a
//! separate auditor's ML-KEM public key so the log's *contents* stay
//! confidential from anyone but the auditor - while its *chain* (each
//! record links to the previous one via a BLAKE3 hash) lets anyone holding
//! the operator's verifying key detect deletion or reordering, without
//! needing the auditor's private key at all.
//!
//! **Not a `.pqf` wire format.** Each log entry is a length-prefixed,
//! ordinary single-recipient v3 `.pqf` payload (built via
//! [`crate::encrypt::encrypt_stream`]/[`crate::decrypt::decrypt_stream`]),
//! so nothing here changes `format.rs`. The chaining and signing framing is
//! this module's own, internal to the log file.
//!
//! **Why the operator can't read their own log back**: the whole point is
//! that only the auditor's private key decrypts entries. This means an
//! operator appending a new record cannot decrypt the log's tail to learn
//! the previous record's chain hash. Callers are expected to track the tip
//! hash themselves between invocations (a small sidecar holding 32
//! non-secret hash bytes is enough - see `pqfile-cli`'s wiring for the
//! convention) and pass it back in as `prev_hash`; [`verify_log`] never
//! needs this, since it recomputes the chain from scratch while decrypting.
//! See `docs/ROADMAP.md`, "Encrypted audit log".

use std::io::Read;

use crate::encrypt;
use crate::error::PqfileError;
use crate::format::CHUNK_SIZE;
use crate::sign;

const RECORD_MAGIC: &[u8; 4] = b"PQAR";
const RECORD_VERSION: u8 = 1;

/// One audit event: an encrypt or decrypt operation on a specific file with
/// a specific key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Unix seconds when the event was recorded.
    pub timestamp: u64,
    /// Short command name, e.g. `"encrypt"` or `"decrypt"`.
    pub command: String,
    /// BLAKE3 hash of the file involved (the ciphertext for `encrypt`, the
    /// file being decrypted for `decrypt`).
    pub file_fingerprint: [u8; 32],
    /// Fingerprint of the key involved, in this crate's existing
    /// colon-hex fingerprint format (see [`crate::keygen::fingerprint`]).
    pub key_fingerprint: String,
    /// BLAKE3 hash of the previous entry's signed record bytes (all-zero
    /// for the first entry in a log). Links this record into the chain.
    pub prev_hash: [u8; 32],
}

impl AuditRecord {
    /// `MAGIC(4) | VERSION(1) | TIMESTAMP(8 LE) | COMMAND_LEN(1) | COMMAND |
    /// FILE_FINGERPRINT(32) | KEY_FINGERPRINT_LEN(1) | KEY_FINGERPRINT |
    /// PREV_HASH(32)`.
    fn to_bytes(&self) -> Result<Vec<u8>, PqfileError> {
        if self.command.len() > 255 {
            return Err(PqfileError::AuditLogInvalid(
                "command name too long (max 255 bytes)".to_string(),
            ));
        }
        if self.key_fingerprint.len() > 255 {
            return Err(PqfileError::AuditLogInvalid(
                "key fingerprint too long (max 255 bytes)".to_string(),
            ));
        }
        let mut out = Vec::new();
        out.extend_from_slice(RECORD_MAGIC);
        out.push(RECORD_VERSION);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.push(self.command.len() as u8);
        out.extend_from_slice(self.command.as_bytes());
        out.extend_from_slice(&self.file_fingerprint);
        out.push(self.key_fingerprint.len() as u8);
        out.extend_from_slice(self.key_fingerprint.as_bytes());
        out.extend_from_slice(&self.prev_hash);
        Ok(out)
    }

    /// Parses a record from the *start* of `bytes`, returning it alongside
    /// how many bytes it consumed - `bytes` may have more after it (the
    /// trailing `sig_len || sig` this record's own length can't be known
    /// without parsing the variable-length fields first, so
    /// [`build_signed_blob`]/[`verify_log`] locate the signature by parsing
    /// the record prefix forward rather than the blob backward).
    fn parse_prefix(bytes: &[u8]) -> Result<(Self, usize), PqfileError> {
        let err = |msg: &str| PqfileError::AuditLogInvalid(msg.to_string());
        if bytes.len() < 4 + 1 + 8 + 1 {
            return Err(err("record too short"));
        }
        if bytes[..4] != *RECORD_MAGIC {
            return Err(err("not a pqfile audit record (bad magic)"));
        }
        if bytes[4] != RECORD_VERSION {
            return Err(err("unsupported audit record version"));
        }
        let timestamp = u64::from_le_bytes(bytes[5..13].try_into().expect("8 bytes"));
        let cmd_len = bytes[13] as usize;
        let mut pos = 14;
        if bytes.len() < pos + cmd_len + 32 + 1 {
            return Err(err("record truncated (command/fingerprint)"));
        }
        let command = String::from_utf8(bytes[pos..pos + cmd_len].to_vec())
            .map_err(|_| err("command is not valid UTF-8"))?;
        pos += cmd_len;
        let file_fingerprint: [u8; 32] = bytes[pos..pos + 32].try_into().expect("32 bytes");
        pos += 32;
        let kfp_len = bytes[pos] as usize;
        pos += 1;
        if bytes.len() < pos + kfp_len + 32 {
            return Err(err("record truncated (key fingerprint/prev hash)"));
        }
        let key_fingerprint = String::from_utf8(bytes[pos..pos + kfp_len].to_vec())
            .map_err(|_| err("key fingerprint is not valid UTF-8"))?;
        pos += kfp_len;
        let prev_hash: [u8; 32] = bytes[pos..pos + 32].try_into().expect("32 bytes");
        pos += 32;
        Ok((
            Self {
                timestamp,
                command,
                file_fingerprint,
                key_fingerprint,
                prev_hash,
            },
            pos,
        ))
    }
}

/// `record_bytes || SIG_LEN(2 LE) || sig_bytes`. This, not just the record
/// fields alone, is what gets encrypted and what the *next* record's
/// `prev_hash` chains from - so a forged record without a matching
/// signature can never extend the chain.
fn build_signed_blob(
    record: &AuditRecord,
    operator_sk_pem: &str,
    operator_sk_passphrase: Option<&str>,
) -> Result<Vec<u8>, PqfileError> {
    let record_bytes = record.to_bytes()?;
    let sig = sign::sign_bytes(operator_sk_pem, &record_bytes, operator_sk_passphrase)?;
    if sig.len() > u16::MAX as usize {
        return Err(PqfileError::AuditLogInvalid(
            "signature unexpectedly large".to_string(),
        ));
    }
    let mut blob = Vec::with_capacity(record_bytes.len() + 2 + sig.len());
    blob.extend_from_slice(&record_bytes);
    blob.extend_from_slice(&(sig.len() as u16).to_le_bytes());
    blob.extend_from_slice(&sig);
    Ok(blob)
}

fn chain_hash(signed_blob: &[u8]) -> [u8; 32] {
    *blake3::hash(signed_blob).as_bytes()
}

/// Builds one audit log entry: signs `record`'s fields with the operator's
/// key, encrypts the signed bytes to the auditor's public key, and frames
/// the result with a 4-byte little-endian length prefix, ready to append to
/// a log file as-is.
///
/// Returns the framed entry bytes plus the chain hash to pass as
/// `prev_hash` on the *next* call - see the module docs for why the caller,
/// not this function, is responsible for remembering it across invocations.
#[allow(clippy::too_many_arguments)]
pub fn build_entry(
    prev_hash: [u8; 32],
    timestamp: u64,
    command: &str,
    file_fingerprint: [u8; 32],
    key_fingerprint: &str,
    operator_sk_pem: &str,
    operator_sk_passphrase: Option<&str>,
    auditor_pubkey_pem: &str,
) -> Result<(Vec<u8>, [u8; 32]), PqfileError> {
    let record = AuditRecord {
        timestamp,
        command: command.to_string(),
        file_fingerprint,
        key_fingerprint: key_fingerprint.to_string(),
        prev_hash,
    };
    let signed_blob = build_signed_blob(&record, operator_sk_pem, operator_sk_passphrase)?;
    let new_chain_hash = chain_hash(&signed_blob);

    let mut encrypted = Vec::new();
    encrypt::encrypt_stream(
        auditor_pubkey_pem,
        signed_blob.len() as u64,
        CHUNK_SIZE,
        &mut signed_blob.as_slice(),
        &mut encrypted,
    )?;

    let mut entry = Vec::with_capacity(4 + encrypted.len());
    let len = u32::try_from(encrypted.len())
        .map_err(|_| PqfileError::AuditLogInvalid("entry unexpectedly large".to_string()))?;
    entry.extend_from_slice(&len.to_le_bytes());
    entry.extend_from_slice(&encrypted);
    Ok((entry, new_chain_hash))
}

/// Reads every length-prefixed entry from `log` in order, decrypts each
/// with the auditor's private key, and verifies its signature against the
/// operator's verifying key plus its chain link to the previous entry.
///
/// Stops at the first entry that fails any check and returns
/// [`PqfileError::AuditLogInvalid`] naming the entry's position and the
/// reason - this answers "is the log intact end to end," not "salvage what
/// you can from a partially tampered log." On success, returns every
/// decrypted, verified [`AuditRecord`] in order.
///
/// Scope of the chain check: verifying every entry's `prev_hash` link
/// detects deletion or reordering of any entry followed by another entry,
/// since a gap anywhere but the very end breaks the chain the next record
/// relies on. It cannot, by itself, detect entries deleted off the end of
/// the log, since a truncated log is still internally consistent up to
/// wherever it stops.
///
/// Pass `expected_tip` (the BLAKE3 hash of the log's last signed entry,
/// independently known to the caller in advance - not read back from the
/// log or its own sidecar, since a log the caller doesn't already trust
/// can't be asked to supply its own expected ending) to additionally catch
/// trailing deletion: if the log's last computed chain hash doesn't match,
/// this returns [`PqfileError::AuditLogInvalid`] even though every
/// individual entry verified. Pass `None` to skip that check (e.g. when no
/// independently-held tip is available yet, such as verifying a log for the
/// first time).
///
/// Returns the verified records plus the log's actual final chain hash (all-
/// zero for an empty log), so a caller with no `expected_tip` yet can save
/// it and supply it as `expected_tip` on the *next* verification, closing
/// the trailing-deletion gap going forward even without an out-of-band tip
/// today.
pub fn verify_log<R: Read>(
    log: &mut R,
    operator_vk_pem: &str,
    auditor_sk_pem: &str,
    auditor_sk_passphrase: Option<&str>,
    expected_tip: Option<[u8; 32]>,
) -> Result<(Vec<AuditRecord>, [u8; 32]), PqfileError> {
    let mut records = Vec::new();
    let mut expected_prev_hash = [0u8; 32];
    let mut index: usize = 0;

    loop {
        let mut len_buf = [0u8; 4];
        match read_exact_or_eof(log, &mut len_buf)? {
            0 => break,
            n if n < 4 => {
                return Err(PqfileError::AuditLogInvalid(format!(
                    "entry {index}: truncated length prefix"
                )))
            }
            _ => {}
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut encrypted = vec![0u8; len];
        log.read_exact(&mut encrypted).map_err(|e| {
            PqfileError::AuditLogInvalid(format!("entry {index}: truncated body: {e}"))
        })?;

        let mut signed_blob = Vec::new();
        crate::decrypt::decrypt_stream(
            auditor_sk_pem,
            &mut encrypted.as_slice(),
            &mut signed_blob,
            auditor_sk_passphrase,
        )
        .map_err(|e| {
            PqfileError::AuditLogInvalid(format!("entry {index}: could not decrypt: {e}"))
        })?;

        // Layout is record_bytes || sig_len(2 LE) || sig_bytes. record_bytes
        // has variable-length fields (command, key fingerprint), so its own
        // length can only be recovered by parsing it forward - not by
        // assuming a fixed offset from either end of the blob.
        let (record, record_len) = AuditRecord::parse_prefix(&signed_blob)
            .map_err(|e| PqfileError::AuditLogInvalid(format!("entry {index}: {e}")))?;
        if signed_blob.len() < record_len + 2 {
            return Err(PqfileError::AuditLogInvalid(format!(
                "entry {index}: decrypted blob too short for a signature length field"
            )));
        }
        let sig_len = u16::from_le_bytes(
            signed_blob[record_len..record_len + 2]
                .try_into()
                .expect("2 bytes"),
        ) as usize;
        if signed_blob.len() != record_len + 2 + sig_len {
            return Err(PqfileError::AuditLogInvalid(format!(
                "entry {index}: signature length does not match the decrypted blob's size"
            )));
        }
        let record_bytes = &signed_blob[..record_len];
        let sig_bytes = &signed_blob[record_len + 2..];

        sign::verify_bytes(operator_vk_pem, record_bytes, sig_bytes).map_err(|e| {
            PqfileError::AuditLogInvalid(format!(
                "entry {index}: signature verification failed: {e}"
            ))
        })?;

        if record.prev_hash != expected_prev_hash {
            return Err(PqfileError::AuditLogInvalid(format!(
                "entry {index}: chain broken (prev_hash does not match the previous entry)"
            )));
        }

        expected_prev_hash = chain_hash(&signed_blob);
        records.push(record);
        index += 1;
    }

    if let Some(tip) = expected_tip {
        if expected_prev_hash != tip {
            return Err(PqfileError::AuditLogInvalid(format!(
                "log ends after {index} record{} but does not match the expected chain tip \
                 (entries may have been deleted from the end of the log)",
                if index == 1 { "" } else { "s" }
            )));
        }
    }

    Ok((records, expected_prev_hash))
}

/// [`crate::io_util::fill_or_eof`], mapped to this module's error type -
/// callers here distinguish "no more entries" (`Ok(0)`) from a genuinely
/// truncated entry (`Ok(n)` with `0 < n < buf.len()`).
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, PqfileError> {
    crate::io_util::fill_or_eof(r, buf).map_err(PqfileError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use crate::sign::sign_keygen_bytes;

    fn blake3_of(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    #[test]
    fn single_entry_roundtrip() {
        let (auditor_pub, auditor_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();

        let (entry, _tip) = build_entry(
            [0u8; 32],
            1_700_000_000,
            "encrypt",
            blake3_of(b"some ciphertext"),
            "aa:bb:cc",
            &signer.sk_pem,
            None,
            &auditor_pub,
        )
        .unwrap();

        let (records, _tip) = verify_log(
            &mut entry.as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            None,
        )
        .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].command, "encrypt");
        assert_eq!(records[0].key_fingerprint, "aa:bb:cc");
        assert_eq!(records[0].file_fingerprint, blake3_of(b"some ciphertext"));
        assert_eq!(records[0].prev_hash, [0u8; 32]);
    }

    #[test]
    fn multi_entry_chain_verifies() {
        let (auditor_pub, auditor_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();

        let mut log = Vec::new();
        let mut tip = [0u8; 32];
        for i in 0..5u64 {
            let (entry, new_tip) = build_entry(
                tip,
                1_700_000_000 + i,
                if i % 2 == 0 { "encrypt" } else { "decrypt" },
                blake3_of(format!("file-{i}").as_bytes()),
                "11:22:33",
                &signer.sk_pem,
                None,
                &auditor_pub,
            )
            .unwrap();
            log.extend_from_slice(&entry);
            tip = new_tip;
        }

        let (records, computed_tip) = verify_log(
            &mut log.as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            None,
        )
        .unwrap();
        assert_eq!(records.len(), 5);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.timestamp, 1_700_000_000 + i as u64);
        }
        assert_eq!(
            computed_tip, tip,
            "verify_log's own tip must match build_entry's"
        );

        // The caller who watched every append knows the real final tip and
        // can confirm the log ends exactly there.
        let (records, _tip) = verify_log(
            &mut log.as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            Some(tip),
        )
        .unwrap();
        assert_eq!(records.len(), 5);
    }

    #[test]
    fn detects_deleted_middle_entry() {
        let (auditor_pub, auditor_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();

        let mut entries = Vec::new();
        let mut tip = [0u8; 32];
        for i in 0..3u64 {
            let (entry, new_tip) = build_entry(
                tip,
                i,
                "encrypt",
                blake3_of(format!("file-{i}").as_bytes()),
                "aa:aa:aa",
                &signer.sk_pem,
                None,
                &auditor_pub,
            )
            .unwrap();
            entries.push(entry);
            tip = new_tip;
        }

        // Silently delete the middle entry - the chain must catch this.
        let mut tampered_log = Vec::new();
        tampered_log.extend_from_slice(&entries[0]);
        tampered_log.extend_from_slice(&entries[2]);

        let err = verify_log(
            &mut tampered_log.as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::AuditLogInvalid(_)));
    }

    #[test]
    fn trailing_deletion_undetected_without_expected_tip() {
        // Documents the scope limit called out in `verify_log`'s doc
        // comment: deleting entries off the *end* of an otherwise-untouched
        // log is invisible to the chain check alone, since a truncated log
        // is still internally consistent up to wherever it stops.
        let (auditor_pub, auditor_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();

        let mut entries = Vec::new();
        let mut tip = [0u8; 32];
        for i in 0..3u64 {
            let (entry, new_tip) = build_entry(
                tip,
                i,
                "encrypt",
                blake3_of(format!("file-{i}").as_bytes()),
                "aa:aa:aa",
                &signer.sk_pem,
                None,
                &auditor_pub,
            )
            .unwrap();
            entries.push(entry);
            tip = new_tip;
        }

        // Drop the last entry entirely - no gap in the chain remains.
        let mut truncated_log = Vec::new();
        truncated_log.extend_from_slice(&entries[0]);
        truncated_log.extend_from_slice(&entries[1]);

        let (records, _tip) = verify_log(
            &mut truncated_log.as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            records.len(),
            2,
            "truncation alone does not break the chain"
        );

        // But supplying the real final tip catches exactly this.
        let err = verify_log(
            &mut truncated_log.as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            Some(tip),
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::AuditLogInvalid(_)));
    }

    #[test]
    fn detects_wrong_operator_verifying_key() {
        let (auditor_pub, auditor_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();
        let other_signer = sign_keygen_bytes(None).unwrap();

        let (entry, _tip) = build_entry(
            [0u8; 32],
            0,
            "encrypt",
            blake3_of(b"data"),
            "aa:aa:aa",
            &signer.sk_pem,
            None,
            &auditor_pub,
        )
        .unwrap();

        let err = verify_log(
            &mut entry.as_slice(),
            &other_signer.vk_pem,
            &auditor_priv,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::AuditLogInvalid(_)));
    }

    #[test]
    fn detects_wrong_auditor_key() {
        let (auditor_pub, _auditor_priv) = keygen_bytes(768, None).unwrap();
        let (_other_pub, other_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();

        let (entry, _tip) = build_entry(
            [0u8; 32],
            0,
            "encrypt",
            blake3_of(b"data"),
            "aa:aa:aa",
            &signer.sk_pem,
            None,
            &auditor_pub,
        )
        .unwrap();

        let err = verify_log(
            &mut entry.as_slice(),
            &signer.vk_pem,
            &other_priv,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::AuditLogInvalid(_)));
    }

    #[test]
    fn empty_log_verifies_to_no_records() {
        let (_auditor_pub, auditor_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();
        let (records, tip) = verify_log(
            &mut [].as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            None,
        )
        .unwrap();
        assert!(records.is_empty());
        assert_eq!(tip, [0u8; 32]);
    }

    #[test]
    fn empty_log_rejected_if_nonzero_tip_expected() {
        let (_auditor_pub, auditor_priv) = keygen_bytes(768, None).unwrap();
        let signer = sign_keygen_bytes(None).unwrap();
        let err = verify_log(
            &mut [].as_slice(),
            &signer.vk_pem,
            &auditor_priv,
            None,
            Some([1u8; 32]),
        )
        .unwrap_err();
        assert!(matches!(err, PqfileError::AuditLogInvalid(_)));
    }
}
