//! `bury` and `exhume` (behind the `stego` cargo feature): hides a file
//! inside a cover image's pixel data under a passphrase that keys detection
//! itself.

use std::io::Write;
use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;

use crate::io_util::{ensure_overwrite_allowed, write_private_file, AtomicOutput};
use crate::json_util::{json_object, kv_str};
use crate::prompts::{prompt_new_passphrase, prompt_passphrase};

pub(crate) fn run_bury(
    image: &Path,
    file: &Path,
    output: PathBuf,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let output_is_png = output
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("png"));
    if !output_is_png {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bury output must be a .png file (LSB embedding requires a lossless format)",
        )));
    }
    ensure_overwrite_allowed(&output, false, force)?;

    let cover = std::fs::read(image)?;
    // The payload is nominally key material; treat it like read_keyfile does.
    let payload = zeroize::Zeroizing::new(std::fs::read(file)?);
    let passphrase = prompt_new_passphrase()?;
    let stego_png = pqfile::stego::bury(&cover, &payload, &passphrase)?;
    let mut out = AtomicOutput::new(&output)?;
    out.write_all(&stego_png)?;
    out.commit()?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
                kv_str("bytes_hidden", &payload.len().to_string()),
            ])
        );
    } else {
        println!("Buried {} bytes in {}", payload.len(), output.display());
    }
    Ok(())
}

pub(crate) fn run_exhume(
    image: &Path,
    output: PathBuf,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    ensure_overwrite_allowed(&output, false, force)?;

    let stego_png = std::fs::read(image)?;
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let payload = zeroize::Zeroizing::new(pqfile::stego::exhume(&stego_png, &passphrase)?);
    // Atomic + owner-only: the recovered payload is typically a private key.
    write_private_file(&output, &payload)?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
                kv_str("bytes_recovered", &payload.len().to_string()),
            ])
        );
    } else {
        println!("Recovered {} bytes to {}", payload.len(), output.display());
    }
    Ok(())
}
