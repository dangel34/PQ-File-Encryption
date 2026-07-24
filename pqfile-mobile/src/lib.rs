//! uniffi-rs bindings for the `pqfile` crate, generating Kotlin (Android) and
//! Swift (iOS) bindings from this single Rust interface definition. Thin
//! wrappers only - all crypto lives in the `pqfile` Rust crate; see
//! `../pqfile/src` for the implementation and `docs/FORMAT.md` for the
//! on-disk format this reads and writes.
//!
//! Unlike the Python and Node.js bindings, these calls are synchronous: there
//! is no single native async runtime shared by both Kotlin coroutines and
//! Swift's `async`/`await`, so callers are expected to invoke these from a
//! background thread/coroutine themselves (`Dispatch.global()` /
//! `withContext(Dispatchers.IO)`), same as any other blocking native call on
//! either platform.

use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor};

uniffi::setup_scaffolding!();

/// A generated ML-KEM (or hybrid X25519+ML-KEM) key pair, PEM-encoded.
#[derive(uniffi::Record)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

impl From<(String, String)> for KeyPair {
    fn from((public_key, private_key): (String, String)) -> Self {
        KeyPair { public_key, private_key }
    }
}

/// Raised for all pqfile encryption/decryption/key errors. `code` is the
/// stable numeric code from `PqfileError::code()`, documented in
/// `docs/ERROR_CODES.md`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PqfileMobileError {
    #[error("{message} (code {code})")]
    Failed { message: String, code: u32 },
}

impl From<pqfile::PqfileError> for PqfileMobileError {
    fn from(e: pqfile::PqfileError) -> Self {
        PqfileMobileError::Failed {
            code: e.code(),
            message: e.to_string(),
        }
    }
}

/// Generates an ML-KEM key pair. `level` must be 512, 768, or 1024.
/// If `passphrase` is given, the private key PEM is Argon2id + AES-256-GCM encrypted.
#[uniffi::export]
pub fn keygen(level: u16, passphrase: Option<String>) -> Result<KeyPair, PqfileMobileError> {
    Ok(pqfile::keygen::keygen_bytes(level, passphrase.as_deref())?.into())
}

/// Generates a hybrid X25519 + ML-KEM-768 key pair.
#[uniffi::export]
pub fn keygen_hybrid(passphrase: Option<String>) -> Result<KeyPair, PqfileMobileError> {
    Ok(pqfile::keygen::keygen_bytes_hybrid_768(passphrase.as_deref())?.into())
}

/// Encrypts `plaintext` to a `.pqf`-format byte array for the recipient
/// identified by `pubkey_pem`.
#[uniffi::export]
pub fn encrypt_bytes(pubkey_pem: String, plaintext: Vec<u8>) -> Result<Vec<u8>, PqfileMobileError> {
    let mut output = Vec::new();
    pqfile::encrypt::encrypt_stream(
        &pubkey_pem,
        plaintext.len() as u64,
        pqfile::CHUNK_SIZE,
        &mut Cursor::new(plaintext),
        &mut output,
    )?;
    Ok(output)
}

/// Decrypts a `.pqf`-format byte array produced by [`encrypt_bytes`] (or the
/// pqfile CLI/GUI) using the matching private key.
#[uniffi::export]
pub fn decrypt_bytes(
    privkey_pem: String,
    ciphertext: Vec<u8>,
    passphrase: Option<String>,
) -> Result<Vec<u8>, PqfileMobileError> {
    let mut output = Vec::new();
    pqfile::decrypt::decrypt_stream(
        &privkey_pem,
        &mut Cursor::new(ciphertext),
        &mut output,
        passphrase.as_deref(),
    )?;
    Ok(output)
}

/// Encrypts the file at `input_path` to `output_path`, streaming so memory
/// use stays flat regardless of file size.
#[uniffi::export]
pub fn encrypt_file(
    pubkey_pem: String,
    input_path: String,
    output_path: String,
) -> Result<(), PqfileMobileError> {
    let input = File::open(input_path).map_err(pqfile::PqfileError::from)?;
    let original_size = input.metadata().map_err(pqfile::PqfileError::from)?.len();
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(File::create(output_path).map_err(pqfile::PqfileError::from)?);
    pqfile::encrypt::encrypt_stream(
        &pubkey_pem,
        original_size,
        pqfile::CHUNK_SIZE,
        &mut reader,
        &mut writer,
    )?;
    Ok(())
}

/// Decrypts the `.pqf` file at `input_path` to `output_path`, streaming so
/// memory use stays flat regardless of file size.
#[uniffi::export]
pub fn decrypt_file(
    privkey_pem: String,
    input_path: String,
    output_path: String,
    passphrase: Option<String>,
) -> Result<(), PqfileMobileError> {
    let mut reader = BufReader::new(File::open(input_path).map_err(pqfile::PqfileError::from)?);
    let mut writer = BufWriter::new(File::create(output_path).map_err(pqfile::PqfileError::from)?);
    pqfile::decrypt::decrypt_stream(&privkey_pem, &mut reader, &mut writer, passphrase.as_deref())?;
    Ok(())
}
