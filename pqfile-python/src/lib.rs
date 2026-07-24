//! PyO3 bindings for the `pqfile` crate. Thin wrappers only - all crypto lives
//! in the `pqfile` Rust crate; see `../pqfile/src` for the implementation and
//! `docs/FORMAT.md` for the on-disk format this reads and writes.
//!
//! The pure-Python package in `python/pqfile/` re-exports this native module
//! (built as `_pqfile`) with a friendlier surface (pathlib support, docstrings).

use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor};

use pyo3::exceptions::PyException;
use pyo3::prelude::*;

/// Converts a `pqfile::PqfileError` into a Python exception, preserving the
/// human-readable message. The stable numeric code from `PqfileError::code()`
/// (documented in `docs/ERROR_CODES.md`) is appended so scripts can match on
/// it without parsing the message text.
fn map_err(e: pqfile::PqfileError) -> PyErr {
    let code = e.code();
    PqfileError::new_err(format!("{e} (code {code})"))
}

pyo3::create_exception!(
    _pqfile,
    PqfileError,
    PyException,
    "Raised for all pqfile encryption/decryption/key errors."
);

/// Generates an ML-KEM key pair. `level` must be 512, 768, or 1024.
/// Returns `(public_key_pem, private_key_pem)`. If `passphrase` is given, the
/// private key PEM is Argon2id + AES-256-GCM encrypted.
#[pyfunction]
#[pyo3(signature = (level=768, passphrase=None))]
fn keygen(py: Python<'_>, level: u16, passphrase: Option<String>) -> PyResult<(String, String)> {
    py.detach(|| pqfile::keygen::keygen_bytes(level, passphrase.as_deref()))
        .map_err(map_err)
}

/// Generates a hybrid X25519 + ML-KEM-768 key pair. Returns
/// `(public_key_pem, private_key_pem)`.
#[pyfunction]
#[pyo3(signature = (passphrase=None))]
fn keygen_hybrid(py: Python<'_>, passphrase: Option<String>) -> PyResult<(String, String)> {
    py.detach(|| pqfile::keygen::keygen_bytes_hybrid_768(passphrase.as_deref()))
        .map_err(map_err)
}

/// Encrypts `plaintext` to a `.pqf`-format byte string for the recipient
/// identified by `pubkey_pem`.
#[pyfunction]
fn encrypt_bytes(py: Python<'_>, pubkey_pem: &str, plaintext: &[u8]) -> PyResult<Vec<u8>> {
    py.detach(|| {
        let mut output = Vec::new();
        pqfile::encrypt::encrypt_stream(
            pubkey_pem,
            plaintext.len() as u64,
            pqfile::CHUNK_SIZE,
            &mut Cursor::new(plaintext),
            &mut output,
        )?;
        Ok(output)
    })
    .map_err(map_err)
}

/// Decrypts a `.pqf`-format byte string produced by [`encrypt_bytes`] (or the
/// pqfile CLI/GUI) using the matching private key.
#[pyfunction]
#[pyo3(signature = (privkey_pem, ciphertext, passphrase=None))]
fn decrypt_bytes(
    py: Python<'_>,
    privkey_pem: &str,
    ciphertext: &[u8],
    passphrase: Option<String>,
) -> PyResult<Vec<u8>> {
    py.detach(|| {
        let mut output = Vec::new();
        pqfile::decrypt::decrypt_stream(
            privkey_pem,
            &mut Cursor::new(ciphertext),
            &mut output,
            passphrase.as_deref(),
        )?;
        Ok(output)
    })
    .map_err(map_err)
}

/// Encrypts the file at `input_path` to `output_path`, streaming so memory
/// use stays flat regardless of file size.
#[pyfunction]
fn encrypt_file(
    py: Python<'_>,
    pubkey_pem: &str,
    input_path: &str,
    output_path: &str,
) -> PyResult<()> {
    py.detach(|| {
        let input = File::open(input_path)?;
        let original_size = input.metadata()?.len();
        let mut reader = BufReader::new(input);
        let mut writer = BufWriter::new(File::create(output_path)?);
        pqfile::encrypt::encrypt_stream(
            pubkey_pem,
            original_size,
            pqfile::CHUNK_SIZE,
            &mut reader,
            &mut writer,
        )
    })
    .map_err(map_err)
}

/// Decrypts the file at `input_path` to `output_path`, streaming so memory
/// use stays flat regardless of file size.
#[pyfunction]
#[pyo3(signature = (privkey_pem, input_path, output_path, passphrase=None))]
fn decrypt_file(
    py: Python<'_>,
    privkey_pem: &str,
    input_path: &str,
    output_path: &str,
    passphrase: Option<String>,
) -> PyResult<()> {
    py.detach(|| {
        let mut reader = BufReader::new(File::open(input_path)?);
        let mut writer = BufWriter::new(File::create(output_path)?);
        pqfile::decrypt::decrypt_stream(
            privkey_pem,
            &mut reader,
            &mut writer,
            passphrase.as_deref(),
        )
    })
    .map_err(map_err)
}

#[pymodule]
fn _pqfile(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("PqfileError", m.py().get_type::<PqfileError>())?;
    m.add_function(wrap_pyfunction!(keygen, m)?)?;
    m.add_function(wrap_pyfunction!(keygen_hybrid, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_file, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_file, m)?)?;
    Ok(())
}
