use thiserror::Error;

#[derive(Debug, Error)]
pub enum PqfileError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid magic bytes: expected PQFL")]
    InvalidMagic,

    #[error("unsupported version: {0:#04x}")]
    UnsupportedVersion(u8),

    #[error("unsupported KEM variant: {0}")]
    UnsupportedKem(u16),

    #[error("encryption failure")]
    EncryptionFailure,

    #[error("decryption failure: authentication tag mismatch")]
    DecryptionFailure,

    #[error("invalid PEM: {0}")]
    InvalidPem(String),

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("output file already exists (use --force to overwrite): {0}")]
    OutputExists(std::path::PathBuf),

    #[error("wrong passphrase or corrupted key")]
    WrongPassphrase,

    #[error("private key is passphrase-protected; provide a passphrase to decrypt it")]
    PassphraseRequired,

    #[error("passphrases do not match")]
    PassphraseMismatch,

    #[error("invalid signature: malformed bytes")]
    InvalidSignature,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("no matching recipient found in this file for the given private key")]
    NoMatchingRecipient,

    #[error("key has been revoked (fingerprint: {fingerprint}): {reason}")]
    KeyRevoked { fingerprint: String, reason: String },

    #[error("compressed .pqf files (v6) are not supported in this build")]
    CompressionNotSupported,

    #[error("key share reconstruction failed: fingerprint mismatch, ensure you have the correct shares for this key")]
    ShareVerificationFailed,
}
