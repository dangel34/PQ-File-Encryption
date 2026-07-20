//! Interactive (no-args) mode: a guided prompt flow for encrypt/decrypt/keygen,
//! triggered only when `pqfile` is run with no arguments. Delegates to the
//! same run_* functions the normal subcommand dispatch uses, so behavior
//! (defaults, validation, error messages) stays identical; this layer only
//! gathers the inputs.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;

use crate::commands::decrypt::run_decrypt;
use crate::commands::encrypt::{run_encrypt, EncryptOpts};
use crate::commands::keygen::run_keygen;

fn prompt_line(label: &str) -> Result<String, PqfileError> {
    print!("{label}");
    io::stdout().flush().map_err(PqfileError::Io)?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(PqfileError::Io)?;
    Ok(buf.trim().to_string())
}

fn prompt_line_default(label: &str, default: &str) -> Result<String, PqfileError> {
    let s = prompt_line(&format!("{label} [{default}]: "))?;
    Ok(if s.is_empty() { default.to_string() } else { s })
}

fn prompt_required(label: &str) -> Result<String, PqfileError> {
    let s = prompt_line(label)?;
    if s.is_empty() {
        return Err(PqfileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a value is required",
        )));
    }
    Ok(s)
}

fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool, PqfileError> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    let s = prompt_line(&format!("{label} [{hint}]: "))?;
    Ok(match s.to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default_yes,
    })
}

/// Prompts to overwrite `path` only if it already exists; returns `false` (no
/// prompt) otherwise. Mirrors the `--force` flag's meaning for the run_* calls
/// below.
fn prompt_overwrite_if_exists(path: &str) -> Result<bool, PqfileError> {
    if path.is_empty() || path == "-" || !Path::new(path).exists() {
        return Ok(false);
    }
    prompt_yes_no(&format!("{path} already exists. Overwrite?"), false)
}

pub(crate) fn run_interactive() -> Result<(), PqfileError> {
    println!("pqfile interactive mode (no arguments given).\n");
    println!("What would you like to do?");
    println!("  1) Encrypt a file");
    println!("  2) Decrypt a file");
    println!("  3) Generate a new key pair");
    match prompt_required("Enter a number [1-3]: ")?.as_str() {
        "1" => interactive_encrypt(),
        "2" => interactive_decrypt(),
        "3" => interactive_keygen(),
        other => Err(PqfileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unrecognized choice '{other}'; expected 1, 2, or 3"),
        ))),
    }
}

fn interactive_encrypt() -> Result<(), PqfileError> {
    let input = prompt_required("Path to the file to encrypt: ")?;

    println!("Encrypt using:");
    println!("  1) A recipient's public key");
    println!("  2) A passphrase (no key pair needed)");
    let passphrase_only = prompt_line_default("Enter a number [1-2]", "1")? == "2";

    let mut recipients = Vec::new();
    if !passphrase_only {
        recipients.push(prompt_required(
            "Path to the recipient's pubkey.pem, or a pqf1… recipient string: ",
        )?);
    }

    let default_output = format!("{input}.pqf");
    let output = prompt_line_default("Output path", &default_output)?;
    let force = prompt_overwrite_if_exists(&output)?;

    run_encrypt(
        recipients,
        None,
        None,
        passphrase_only,
        None,
        false,
        input,
        Some(output),
        false,
        EncryptOpts {
            chunk_size: 0,
            compress: false,
            compress_level: 3,
            parallel: false,
            pipeline: false,
            mmap: false,
            anonymous_recipients: false,
            pad_recipients: false,
            force,
            json: false,
            kdf_mem: 65536,
            kdf_time: 3,
            keyfile: None,
            fido2: None,
            pad: false,
            stealth: false,
        },
    )
}

fn interactive_decrypt() -> Result<(), PqfileError> {
    let input = prompt_required("Path to the .pqf file to decrypt: ")?;

    println!("Decrypt using:");
    println!("  1) A private key");
    println!("  2) A passphrase (v10 passphrase-only files)");
    let passphrase_v10 = prompt_line_default("Enter a number [1-2]", "1")? == "2";

    let key = if passphrase_v10 {
        None
    } else {
        Some(PathBuf::from(prompt_required(
            "Path to your privkey.pem: ",
        )?))
    };

    let default_output = Path::new(&input)
        .with_extension("")
        .to_string_lossy()
        .into_owned();
    let output = prompt_line_default("Output path", &default_output)?;
    let force = prompt_overwrite_if_exists(&output)?;

    run_decrypt(
        key,
        passphrase_v10,
        None,
        None,
        false,
        65536,
        3,
        input,
        Some(output),
        false,
        force,
        false,
        false,
        None,
        false,
    )
}

fn interactive_keygen() -> Result<(), PqfileError> {
    let out = PathBuf::from(prompt_line_default(
        "Directory to write the key pair to",
        "./keys",
    )?);
    std::fs::create_dir_all(&out)?;

    let level: u16 = prompt_line_default("ML-KEM security level (512, 768, or 1024)", "768")?
        .parse()
        .map_err(|_| {
            PqfileError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "level must be 512, 768, or 1024",
            ))
        })?;
    let hybrid = prompt_yes_no(
        "Use hybrid X25519+ML-KEM-768 (classical + post-quantum)?",
        false,
    )?;
    let passphrase = prompt_yes_no("Protect the private key with a passphrase?", true)?;

    let force = if out.join("pubkey.pem").exists() || out.join("privkey.pem").exists() {
        prompt_yes_no(
            "Key files already exist in that directory. Overwrite?",
            false,
        )?
    } else {
        false
    };

    run_keygen(
        out, force, level, hybrid, passphrase, false, None, None, false, false,
    )
}
