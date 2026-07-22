//! Native-only GUI wiring for the encrypted audit log (`audit` feature).
//!
//! See `pqfile::audit`'s module docs for the underlying design. This is the
//! GUI-side counterpart to `pqfile-cli`'s `commands::audit::AuditTarget` -
//! same chain-tip sidecar convention (`<log>.chainhash`, holding 32
//! non-secret hash bytes so a caller who can't decrypt their own log can
//! still correctly chain a new entry onto the last one) - adapted to the
//! GUI's in-memory data flow: the ciphertext/ciphertext-being-decrypted
//! bytes are already in memory here, so fingerprinting never needs to
//! reread a file the way the CLI does.
//!
//! Native only: an append-only log needs real persistent storage, which the
//! web build's download-only file model can't provide (unlike the FEC
//! sidecar, a one-time artifact a browser download works fine for).

use std::path::PathBuf;

use zeroize::Zeroizing;

/// Resolved audit-log target: log path plus the operator/auditor key
/// material needed to sign and encrypt a record. See [`AuditTarget::resolve`].
pub(crate) struct AuditTarget {
    log_path: PathBuf,
    operator_sk_pem: String,
    operator_sk_passphrase: Option<Zeroizing<String>>,
    auditor_pubkey_pem: String,
}

impl AuditTarget {
    /// Resolves from the Settings tab's three path fields plus the
    /// in-memory (never persisted) signing-key passphrase. Returns `None`
    /// if any path is empty - audit logging is simply off, not a
    /// misconfiguration to reject, since Settings fields fill in one at a
    /// time as the user types rather than all-or-nothing like CLI flags.
    pub(crate) fn resolve(
        log_path: &str,
        key_path: &str,
        recipient_path: &str,
        key_passphrase: &str,
    ) -> Result<Option<Self>, String> {
        if log_path.trim().is_empty()
            || key_path.trim().is_empty()
            || recipient_path.trim().is_empty()
        {
            return Ok(None);
        }
        let operator_sk_pem = std::fs::read_to_string(key_path)
            .map_err(|e| format!("could not read audit signing key: {e}"))?;
        let auditor_pubkey_pem = if pqfile::recipient_string::is_recipient_string(recipient_path) {
            pqfile::recipient_string::decode_pubkey(recipient_path).map_err(|e| e.to_string())?
        } else {
            std::fs::read_to_string(recipient_path)
                .map_err(|e| format!("could not read audit recipient key: {e}"))?
        };
        let operator_sk_passphrase = if key_passphrase.is_empty() {
            None
        } else {
            Some(Zeroizing::new(key_passphrase.to_string()))
        };
        Ok(Some(Self {
            log_path: PathBuf::from(log_path),
            operator_sk_pem,
            operator_sk_passphrase,
            auditor_pubkey_pem,
        }))
    }

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

    /// Appends one event, fingerprinting `file_bytes` directly - already in
    /// memory here, unlike the CLI's file-based flow, so no reread is
    /// needed. A logging failure is returned as a plain `String` (this
    /// module's error convention throughout the GUI) rather than aborting
    /// the encrypt/decrypt operation that already succeeded.
    pub(crate) fn append(
        &self,
        command: &str,
        file_bytes: &[u8],
        key_fingerprint: &str,
    ) -> Result<(), String> {
        let prev_hash = self.read_tip();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let file_fingerprint = *blake3::hash(file_bytes).as_bytes();
        let (entry, new_tip) = pqfile::audit::build_entry(
            prev_hash,
            timestamp,
            command,
            file_fingerprint,
            key_fingerprint,
            &self.operator_sk_pem,
            self.operator_sk_passphrase.as_deref().map(|z| z.as_str()),
            &self.auditor_pubkey_pem,
        )
        .map_err(|e| e.to_string())?;

        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| e.to_string())?;
        f.write_all(&entry).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;

        std::fs::write(self.chainhash_path(), new_tip).map_err(|e| e.to_string())?;
        Ok(())
    }
}
