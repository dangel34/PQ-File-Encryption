//! napi-rs bindings for the `pqfile` crate. Thin wrappers only - all crypto
//! lives in the `pqfile` Rust crate; see `../pqfile/src` for the
//! implementation and `docs/FORMAT.md` for the on-disk format this reads and
//! writes.
//!
//! Every operation runs as a napi-rs [`Task`] on libuv's worker thread pool
//! (`AsyncTask`), resolving a JS `Promise`, rather than running synchronously
//! on the calling thread. Argon2id key derivation and ML-KEM operations are
//! CPU-heavy enough that running them inline would block Node's single-threaded
//! event loop for the duration - fine for a one-off CLI-style script, but a
//! correctness problem for anything serving concurrent requests.

#![deny(clippy::all)]

use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor};

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Converts a `pqfile::PqfileError` into a `napi::Error`, preserving the
/// human-readable message. The stable numeric code from `PqfileError::code()`
/// (documented in `docs/ERROR_CODES.md`) is appended so scripts can match on
/// it without parsing the message text.
fn map_err(e: pqfile::PqfileError) -> Error {
    let code = e.code();
    Error::new(Status::GenericFailure, format!("{e} (code {code})"))
}

/// A generated ML-KEM (or hybrid X25519+ML-KEM) key pair, PEM-encoded.
#[napi(object)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

impl From<(String, String)> for KeyPair {
    fn from((public_key, private_key): (String, String)) -> Self {
        KeyPair { public_key, private_key }
    }
}

pub struct KeygenTask {
    level: u16,
    passphrase: Option<String>,
}

impl Task for KeygenTask {
    type Output = (String, String);
    type JsValue = KeyPair;

    fn compute(&mut self) -> Result<Self::Output> {
        pqfile::keygen::keygen_bytes(self.level, self.passphrase.as_deref()).map_err(map_err)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

/// Generates an ML-KEM key pair. `level` must be 512, 768, or 1024 (default 768).
/// If `passphrase` is given, the private key PEM is Argon2id + AES-256-GCM encrypted.
#[napi(ts_return_type = "Promise<KeyPair>")]
pub fn keygen(level: Option<u32>, passphrase: Option<String>) -> AsyncTask<KeygenTask> {
    AsyncTask::new(KeygenTask {
        level: level.unwrap_or(768) as u16,
        passphrase,
    })
}

pub struct KeygenHybridTask {
    passphrase: Option<String>,
}

impl Task for KeygenHybridTask {
    type Output = (String, String);
    type JsValue = KeyPair;

    fn compute(&mut self) -> Result<Self::Output> {
        pqfile::keygen::keygen_bytes_hybrid_768(self.passphrase.as_deref()).map_err(map_err)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

/// Generates a hybrid X25519 + ML-KEM-768 key pair.
#[napi(ts_return_type = "Promise<KeyPair>")]
pub fn keygen_hybrid(passphrase: Option<String>) -> AsyncTask<KeygenHybridTask> {
    AsyncTask::new(KeygenHybridTask { passphrase })
}

pub struct EncryptBytesTask {
    pubkey_pem: String,
    plaintext: Vec<u8>,
}

impl Task for EncryptBytesTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut output = Vec::new();
        pqfile::encrypt::encrypt_stream(
            &self.pubkey_pem,
            self.plaintext.len() as u64,
            pqfile::CHUNK_SIZE,
            &mut Cursor::new(&self.plaintext),
            &mut output,
        )
        .map_err(map_err)?;
        Ok(output)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

/// Encrypts `plaintext` to a `.pqf`-format buffer for the recipient identified
/// by `pubkey_pem`.
#[napi(ts_return_type = "Promise<Buffer>")]
pub fn encrypt_bytes(pubkey_pem: String, plaintext: Buffer) -> AsyncTask<EncryptBytesTask> {
    AsyncTask::new(EncryptBytesTask {
        pubkey_pem,
        plaintext: plaintext.to_vec(),
    })
}

pub struct DecryptBytesTask {
    privkey_pem: String,
    ciphertext: Vec<u8>,
    passphrase: Option<String>,
}

impl Task for DecryptBytesTask {
    type Output = Vec<u8>;
    type JsValue = Buffer;

    fn compute(&mut self) -> Result<Self::Output> {
        let mut output = Vec::new();
        pqfile::decrypt::decrypt_stream(
            &self.privkey_pem,
            &mut Cursor::new(&self.ciphertext),
            &mut output,
            self.passphrase.as_deref(),
        )
        .map_err(map_err)?;
        Ok(output)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into())
    }
}

/// Decrypts a `.pqf`-format buffer produced by [`encrypt_bytes`] (or the
/// pqfile CLI/GUI) using the matching private key.
#[napi(ts_return_type = "Promise<Buffer>")]
pub fn decrypt_bytes(
    privkey_pem: String,
    ciphertext: Buffer,
    passphrase: Option<String>,
) -> AsyncTask<DecryptBytesTask> {
    AsyncTask::new(DecryptBytesTask {
        privkey_pem,
        ciphertext: ciphertext.to_vec(),
        passphrase,
    })
}

pub struct EncryptFileTask {
    pubkey_pem: String,
    input_path: String,
    output_path: String,
}

impl Task for EncryptFileTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        let run = || -> std::result::Result<(), pqfile::PqfileError> {
            let input = File::open(&self.input_path)?;
            let original_size = input.metadata()?.len();
            let mut reader = BufReader::new(input);
            let mut writer = BufWriter::new(File::create(&self.output_path)?);
            pqfile::encrypt::encrypt_stream(
                &self.pubkey_pem,
                original_size,
                pqfile::CHUNK_SIZE,
                &mut reader,
                &mut writer,
            )
        };
        run().map_err(map_err)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Encrypts the file at `input_path` to `output_path`, streaming so memory
/// use stays flat regardless of file size.
#[napi(ts_return_type = "Promise<void>")]
pub fn encrypt_file(
    pubkey_pem: String,
    input_path: String,
    output_path: String,
) -> AsyncTask<EncryptFileTask> {
    AsyncTask::new(EncryptFileTask {
        pubkey_pem,
        input_path,
        output_path,
    })
}

pub struct DecryptFileTask {
    privkey_pem: String,
    input_path: String,
    output_path: String,
    passphrase: Option<String>,
}

impl Task for DecryptFileTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        let run = || -> std::result::Result<(), pqfile::PqfileError> {
            let mut reader = BufReader::new(File::open(&self.input_path)?);
            let mut writer = BufWriter::new(File::create(&self.output_path)?);
            pqfile::decrypt::decrypt_stream(
                &self.privkey_pem,
                &mut reader,
                &mut writer,
                self.passphrase.as_deref(),
            )
        };
        run().map_err(map_err)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Decrypts the `.pqf` file at `input_path` to `output_path`, streaming so
/// memory use stays flat regardless of file size.
#[napi(ts_return_type = "Promise<void>")]
pub fn decrypt_file(
    privkey_pem: String,
    input_path: String,
    output_path: String,
    passphrase: Option<String>,
) -> AsyncTask<DecryptFileTask> {
    AsyncTask::new(DecryptFileTask {
        privkey_pem,
        input_path,
        output_path,
        passphrase,
    })
}
