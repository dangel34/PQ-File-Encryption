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

    /// None of the recipient slots in a v4/v7 file matched the supplied private key.
    #[error("no matching recipient found in this file for the given private key")]
    NoMatchingRecipient,

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

    /// Shamir share fingerprints did not agree; shares may be from different keys.
    #[error("key share reconstruction failed: fingerprint mismatch, ensure you have the correct shares for this key")]
    ShareVerificationFailed,
}
