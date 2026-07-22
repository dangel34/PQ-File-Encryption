//! CLI-level plumbing for `--audit-log`: chain-tip sidecar tracking, the
//! shared "append one event" helper used by both `encrypt` and `decrypt`,
//! and the `audit-verify` subcommand.
//!
//! `pqfile::audit` only builds/verifies byte blobs; it never touches the
//! filesystem (same convention as `pqfile::resume`/`pqfile::fec`). This
//! module owns the actual log-file append and a small `<log>.chainhash`
//! sidecar that lets the operator - who cannot decrypt their own log, since
//! only the auditor's private key can - still correctly chain a new entry
//! onto the last one without needing to decrypt anything. See
//! `pqfile::audit`'s module docs for why that's necessary at all.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;

use crate::config::CliConfig;
use crate::json_util::{json_object, kv_raw, kv_str};
use crate::prompts::maybe_prompt_passphrase;

/// A fully resolved `--audit-log` target: all three of log path, operator
/// signing key, and auditor public key. There is no partially-configured
/// state - see [`AuditTarget::resolve`].
pub(crate) struct AuditTarget {
    log_path: PathBuf,
    operator_sk_pem: String,
    operator_sk_passphrase: Option<zeroize::Zeroizing<String>>,
    auditor_pubkey_pem: String,
}

impl AuditTarget {
    /// Resolves `--audit-log`/`--audit-key`/`--audit-recipient`, falling
    /// back to the config file's `audit_log`/`audit_key`/`audit_recipient`
    /// defaults for whichever flag is omitted. Returns `Ok(None)` if none of
    /// the three end up set at all - audit logging is simply off. Returns
    /// an error if only some of the three are set, since a partially
    /// configured audit log is always a mistake, never a valid state to
    /// silently downgrade from.
    pub(crate) fn resolve(
        audit_log: Option<PathBuf>,
        audit_key: Option<PathBuf>,
        audit_recipient: Option<String>,
        config: &CliConfig,
    ) -> Result<Option<Self>, PqfileError> {
        let log_path = audit_log.or_else(|| config.audit_log.clone());
        let key_path = audit_key.or_else(|| config.audit_key.clone());
        let recipient = audit_recipient.or_else(|| config.audit_recipient.clone());

        match (log_path, key_path, recipient) {
            (None, None, None) => Ok(None),
            (Some(log_path), Some(key_path), Some(recipient)) => {
                let operator_sk_pem = std::fs::read_to_string(&key_path)?;
                let operator_sk_passphrase = maybe_prompt_passphrase(
                    &operator_sk_pem,
                    "Enter passphrase for audit signing key: ",
                )?;
                let auditor_pubkey_pem =
                    if pqfile::recipient_string::is_recipient_string(&recipient) {
                        pqfile::recipient_string::decode_pubkey(&recipient)?
                    } else {
                        std::fs::read_to_string(&recipient)?
                    };
                Ok(Some(Self {
                    log_path,
                    operator_sk_pem,
                    operator_sk_passphrase,
                    auditor_pubkey_pem,
                }))
            }
            _ => Err(PqfileError::Io(std::io::Error::other(
                "--audit-log, --audit-key, and --audit-recipient must all be set together \
                 (whether via flags or the config file's audit_log/audit_key/audit_recipient), \
                 not just some of them",
            ))),
        }
    }

    /// `<log_path>.chainhash` - see the module docs for why the operator
    /// needs this non-secret local cache at all.
    fn chainhash_path(&self) -> PathBuf {
        let mut s = self.log_path.as_os_str().to_owned();
        s.push(".chainhash");
        PathBuf::from(s)
    }

    fn read_tip(&self) -> [u8; 32] {
        std::fs::read(self.chainhash_path())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .unwrap_or([0u8; 32])
    }

    /// Appends one signed+encrypted event to the log and updates the
    /// chain-tip sidecar. `file_fingerprint` should be a BLAKE3 hash of the
    /// file the event concerns (the output ciphertext for `encrypt`, the
    /// input ciphertext for `decrypt`) - callers compute it, since only
    /// they know which file that is and whether it's already in memory.
    pub(crate) fn append(
        &self,
        command: &str,
        file_fingerprint: [u8; 32],
        key_fingerprint: &str,
    ) -> Result<(), PqfileError> {
        let prev_hash = self.read_tip();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (entry, new_tip) = pqfile::audit::build_entry(
            prev_hash,
            timestamp,
            command,
            file_fingerprint,
            key_fingerprint,
            &self.operator_sk_pem,
            self.operator_sk_passphrase.as_deref().map(|z| z.as_str()),
            &self.auditor_pubkey_pem,
        )?;

        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        f.write_all(&entry)?;
        f.sync_all()?;

        std::fs::write(self.chainhash_path(), new_tip)?;
        Ok(())
    }
}

/// BLAKE3 hash of the file at `path`, for use as an [`AuditTarget::append`]
/// `file_fingerprint`. Streams the file rather than reading it fully into
/// memory, so this stays cheap even for very large ciphertexts.
pub(crate) fn fingerprint_file(path: &Path) -> Result<[u8; 32], PqfileError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(*hasher.finalize().as_bytes())
}

/// Parses a 64-character lowercase/uppercase hex string (as printed on the
/// `tip:` line of a prior `audit-verify` run) into the 32 raw bytes
/// [`pqfile::audit::verify_log`]'s `expected_tip` expects.
fn parse_tip_hex(s: &str) -> Result<[u8; 32], PqfileError> {
    let bad = || {
        PqfileError::Io(std::io::Error::other(
            "--expect-tip must be 64 hex characters (32 bytes)",
        ))
    };
    if s.len() != 64 {
        return Err(bad());
    }
    let mut tip = [0u8; 32];
    for (i, b) in tip.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    Ok(tip)
}

fn tip_hex(tip: &[u8; 32]) -> String {
    tip.iter().map(|b| format!("{b:02x}")).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_audit_verify(
    log_path: &Path,
    auditor_key: &Path,
    operator_key: &Path,
    expect_tip: Option<&str>,
    json: bool,
) -> Result<(), PqfileError> {
    let auditor_sk_pem = std::fs::read_to_string(auditor_key)?;
    let auditor_sk_passphrase = maybe_prompt_passphrase(
        &auditor_sk_pem,
        "Enter passphrase for auditor private key: ",
    )?;
    let operator_vk_pem = std::fs::read_to_string(operator_key)?;
    let expected_tip = expect_tip.map(parse_tip_hex).transpose()?;

    let mut log_file = std::fs::File::open(log_path)?;
    // `verify_log` also returns the log's actual final chain hash - printed
    // below regardless of whether `--expect-tip` was given, so the caller
    // can save it and pass it back as `--expect-tip` on the *next* run. The
    // chain check alone can't see entries deleted off the *end* of the log
    // (see `verify_log`'s doc comment); only comparing against a tip from a
    // prior run closes that gap.
    let (records, final_tip) = pqfile::audit::verify_log(
        &mut log_file,
        &operator_vk_pem,
        &auditor_sk_pem,
        auditor_sk_passphrase.as_deref().map(|z| z.as_str()),
        expected_tip,
    )?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_raw("records", &records.len().to_string()),
                kv_str("tip", &tip_hex(&final_tip)),
            ])
        );
    } else {
        println!(
            "OK: {} verified ({} record{})",
            log_path.display(),
            records.len(),
            if records.len() == 1 { "" } else { "s" }
        );
        for r in &records {
            println!(
                "  {} {} file={} key={}",
                r.timestamp,
                r.command,
                hex_prefix(&r.file_fingerprint),
                r.key_fingerprint
            );
        }
        println!(
            "tip: {} (pass as --expect-tip next time to also catch trailing deletion)",
            tip_hex(&final_tip)
        );
    }
    Ok(())
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}
