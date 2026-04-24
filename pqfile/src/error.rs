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

    #[error("KEM encapsulation error")]
    KemEncapsulation,

    #[error("KEM decapsulation error")]
    KemDecapsulation,

    #[error("encryption failure")]
    EncryptionFailure,

    #[error("decryption failure: authentication tag mismatch")]
    DecryptionFailure,

    #[error("invalid PEM: {0}")]
    InvalidPem(String),

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
}
