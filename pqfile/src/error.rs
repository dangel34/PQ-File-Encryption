use thiserror::Error;

/// Errors returned by all pqfile operations.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum PqfileError {
    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File does not begin with the `PQFL` magic bytes.
    #[error("invalid magic bytes: expected PQFL")]
    InvalidMagic,

    /// Version byte in the header is not recognized.
    #[error("unsupported version: {0:#04x}")]
    UnsupportedVersion(u8),

    /// KEM variant field in the header is not recognized.
    #[error("unsupported KEM variant: {0}")]
    UnsupportedKem(u16),

    /// The decryption key uses a different KEM variant than the file was encrypted with.
    #[error("KEM variant mismatch: key is {key}, file uses {file}")]
    KemVariantMismatch {
        /// KEM variant identifier of the supplied private key.
        key: u16,
        /// KEM variant identifier recorded in the file header.
        file: u16,
    },

    /// An encryption or key-encapsulation operation failed.
    #[error("encryption failure")]
    EncryptionFailure,

    /// AEAD authentication tag did not verify; ciphertext is corrupt or tampered.
    #[error("decryption failure: authentication tag mismatch")]
    DecryptionFailure,

    /// PEM data could not be parsed.
    #[error("invalid PEM: {0}")]
    InvalidPem(String),

    /// Key material has an unexpected byte length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length encountered.
        got: usize,
    },

    /// Output file already exists and `--force` was not specified.
    #[error("output file already exists (use --force to overwrite): {0}")]
    OutputExists(std::path::PathBuf),

    /// Passphrase did not decrypt the key, or the encrypted key body is corrupt.
    #[error("wrong passphrase or corrupted key")]
    WrongPassphrase,

    /// Operation requires a passphrase but none was supplied.
    #[error("private key is passphrase-protected; provide a passphrase to decrypt it")]
    PassphraseRequired,

    /// New-passphrase confirmation did not match.
    #[error("passphrases do not match")]
    PassphraseMismatch,

    /// Signature bytes are malformed (wrong length or structure).
    #[error("invalid signature: malformed bytes")]
    InvalidSignature,

    /// ML-DSA signature is well-formed but does not verify against the data.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// None of the recipient slots in a v4/v7/v8/v9 file matched the supplied private key.
    #[error("no matching recipient found: {slots_tried} slot(s) tried with the given private key")]
    NoMatchingRecipient {
        /// Number of recipient slots that were attempted during decryption.
        slots_tried: usize,
    },

    /// The key has been explicitly revoked.
    #[error("key has been revoked (fingerprint: {fingerprint}): {reason}")]
    KeyRevoked {
        /// Colon-separated hex fingerprint of the revoked key.
        fingerprint: String,
        /// Human-readable reason supplied at revocation time.
        reason: String,
    },

    /// v6 compressed files require the `zstd` feature, which is absent in this build.
    #[error("compressed .pqf files (v6) are not supported in this build")]
    CompressionNotSupported,

    /// The private key was encrypted with legacy Argon2id parameters (p=1, pqfile < 4.0).
    /// Run `pqfile repassphrase --from-legacy` to upgrade it before use.
    #[error(
        "private key uses legacy Argon2id parameters (p=1); \
         run `pqfile repassphrase --from-legacy` to upgrade it to p=4 before use"
    )]
    LegacyKeyFormat,

    /// Shamir share fingerprints did not agree; shares may be from different keys.
    #[error("key share reconstruction failed: fingerprint mismatch, ensure you have the correct shares for this key")]
    ShareVerificationFailed,

    /// Argon2id parameters in a v10 passphrase-only file exceed the configured ceiling.
    ///
    /// A crafted file could specify extreme Argon2 parameters to force excessive memory or
    /// CPU use on decryption. The ceiling is checked before the KDF runs. Raise
    /// `--max-kdf-mem` / `--max-kdf-time` flags to accept a higher cost, or reject the file.
    #[error(
        "KDF parameters in file (m={m_kib} KiB, t={t}) exceed ceiling \
         (max_m={max_m_kib} KiB, max_t={max_t})"
    )]
    KdfLimitExceeded {
        /// Memory cost (KiB) requested by the file.
        m_kib: u32,
        /// Time cost (iterations) requested by the file.
        t: u32,
        /// Maximum memory cost (KiB) the caller will allow.
        max_m_kib: u32,
        /// Maximum time cost the caller will allow.
        max_t: u32,
    },

    /// The `.pqf` stream ended without a terminal chunk (is_last flag never seen).
    /// The file was most likely truncated during download or transfer; re-downloading
    /// is the appropriate recovery action. Distinguished from [`DecryptionFailure`]
    /// which indicates bytes are present but the authentication tag is wrong.
    #[error("stream truncated: file ended before the final authenticated chunk was seen; re-download and try again")]
    Truncated,

    /// The v10 file was encrypted with a keyfile second factor but none was supplied.
    #[error(
        "this file requires a keyfile: it was encrypted with a keyfile second factor; \
         pass --keyfile <PATH> with the same keyfile used at encryption"
    )]
    KeyfileRequired,

    /// A keyfile was supplied but the v10 file was not encrypted with one.
    /// Failing loudly here avoids silently deriving a wrong key (which would
    /// surface as an opaque authentication failure) and tells the caller the
    /// keyfile is not protecting this file.
    #[error("file was not encrypted with a keyfile; remove --keyfile and retry")]
    KeyfileNotRequired,

    /// The v10 header carries feature flag bits this build does not understand.
    /// The file was likely produced by a newer pqfile; upgrade to decrypt it.
    #[error(
        "unsupported header flags: {0:#04x}; file was likely written by a newer pqfile version"
    )]
    UnsupportedHeaderFlags(u8),
}

impl PqfileError {
    /// Stable numeric code for this error, as emitted in the CLI's `--json`
    /// error output and documented in `docs/ERROR_CODES.md`.
    ///
    /// Codes are append-only: new variants are always assigned new codes, and
    /// existing codes are never reused or reassigned. The match below is
    /// deliberately exhaustive (no `_` arm) so adding a variant without
    /// assigning it a code is a compile error rather than a silent fallthrough.
    #[must_use]
    pub fn code(&self) -> u32 {
        match self {
            PqfileError::Io(_) => 1,
            PqfileError::InvalidMagic => 2,
            PqfileError::UnsupportedVersion(_) => 3,
            PqfileError::UnsupportedKem(_) => 4,
            PqfileError::KemVariantMismatch { .. } => 5,
            PqfileError::EncryptionFailure => 6,
            PqfileError::DecryptionFailure => 7,
            PqfileError::InvalidPem(_) => 8,
            PqfileError::InvalidKeyLength { .. } => 9,
            PqfileError::OutputExists(_) => 10,
            PqfileError::WrongPassphrase => 11,
            PqfileError::PassphraseRequired => 12,
            PqfileError::PassphraseMismatch => 13,
            PqfileError::InvalidSignature => 14,
            PqfileError::SignatureVerificationFailed => 15,
            PqfileError::NoMatchingRecipient { .. } => 16,
            PqfileError::KeyRevoked { .. } => 17,
            PqfileError::CompressionNotSupported => 18,
            PqfileError::LegacyKeyFormat => 19,
            PqfileError::ShareVerificationFailed => 20,
            PqfileError::Truncated => 21,
            PqfileError::KdfLimitExceeded { .. } => 22,
            PqfileError::KeyfileRequired => 23,
            PqfileError::KeyfileNotRequired => 24,
            PqfileError::UnsupportedHeaderFlags(_) => 25,
        }
    }
}
