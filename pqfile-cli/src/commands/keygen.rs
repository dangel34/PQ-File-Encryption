//! `keygen`, `fingerprint`, `import-key`, and (behind the `fido2` feature)
//! `fido2-enroll`: commands that create or describe a key pair rather than
//! operate on file contents.

use std::path::PathBuf;

use pqfile::error::PqfileError;
use pqfile::keygen;

#[cfg(feature = "fido2")]
use crate::io_util::ensure_overwrite_allowed;
use crate::io_util::write_private_file;
use crate::json_util::{json_object, kv_str};
use crate::prompts::{prompt_new_passphrase, prompt_passphrase};

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_keygen(
    out: PathBuf,
    force: bool,
    level: u16,
    hybrid: bool,
    passphrase: bool,
    hardware: bool,
    label: Option<String>,
    expiry: Option<String>,
    qr: bool,
    json: bool,
) -> Result<(), PqfileError> {
    if hardware && passphrase {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--hardware and --passphrase are mutually exclusive",
        )));
    }
    if hardware && expiry.is_some() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--hardware and --expiry are mutually exclusive (hardware key stubs have no PEM header)",
        )));
    }
    // Validate expiry format (YYYY-MM-DD).
    if let Some(ref date) = expiry {
        let parts: Vec<&str> = date.splitn(4, '-').collect();
        let valid = parts.len() == 3
            && parts[0].len() == 4
            && parts[1].len() == 2
            && parts[2].len() == 2
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
        if !valid {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--expiry must be in YYYY-MM-DD format, got {date:?}"),
            )));
        }
    }
    let fp = if hardware {
        let lbl = label.ok_or_else(|| {
            PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--hardware requires --label <LABEL>",
            ))
        })?;
        keygen::keygen_hardware(&out, force, level, hybrid, &lbl)?
    } else {
        let pp = if passphrase {
            let p = prompt_new_passphrase()?;
            if !json && keygen::passphrase_strength(p.as_str()) <= 2 {
                eprintln!("Warning: passphrase is weak. Use 12+ characters with mixed case, digits, and symbols.");
            }
            Some(p)
        } else {
            None
        };
        let fp = keygen::keygen(
            &out,
            force,
            level,
            pp.as_deref().map(|z| z.as_str()),
            hybrid,
        )?;
        // Prepend expiry comment to both PEM files if requested.
        if let Some(ref date) = expiry {
            let pub_path = out.join("pubkey.pem");
            let priv_path = out.join("privkey.pem");
            let pub_pem = std::fs::read_to_string(&pub_path)?;
            let priv_pem = std::fs::read_to_string(&priv_path)?;
            std::fs::write(
                &pub_path,
                format!("# Expires: {date}\n{pub_pem}").as_bytes(),
            )?;
            write_private_file(
                &priv_path,
                format!("# Expires: {date}\n{priv_pem}").as_bytes(),
            )?;
        }
        fp
    };
    // Compute the Bech32 recipient string from the written public key.
    let pub_pem_for_rs = std::fs::read_to_string(out.join("pubkey.pem")).unwrap_or_default();
    let recipient_str =
        pqfile::recipient_string::encode_pubkey(&pub_pem_for_rs).unwrap_or_default();

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("pubkey_path", &out.join("pubkey.pem").to_string_lossy()),
                kv_str("privkey_path", &out.join("privkey.pem").to_string_lossy()),
                kv_str("fingerprint", &fp),
                kv_str("storage", if hardware { "hardware" } else { "disk" }),
                kv_str("expiry", expiry.as_deref().unwrap_or("")),
                kv_str("recipient_string", &recipient_str),
            ])
        );
    } else {
        if hardware {
            println!("Hardware-backed keys written to {}", out.display());
            println!("(Seed stored in OS credential store; no seed bytes on disk)");
        } else {
            println!("Keys written to {}", out.display());
        }
        println!("Public key fingerprint: {fp}");
        if !recipient_str.is_empty() {
            println!("Recipient string:       {recipient_str}");
        }
        if let Some(ref date) = expiry {
            println!("Expiry: {date}");
        }
    }
    if qr && !recipient_str.is_empty() {
        print_recipient_qr(&recipient_str, json);
    }
    Ok(())
}

/// Renders a `pqf1…` recipient string as a terminal QR code.
///
/// The string is uppercased first: Bech32m is case-insensitive and the QR
/// alphanumeric mode (uppercase-only charset) packs ~45% more characters per
/// version than byte mode, keeping the code as scannable as possible. In
/// `--json` mode the QR goes to stderr so stdout stays machine-readable.
pub(crate) fn print_recipient_qr(recipient_str: &str, json: bool) {
    match qrcode::QrCode::new(recipient_str.to_ascii_uppercase().as_bytes()) {
        Ok(code) => {
            let rendered = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            if json {
                eprintln!("{rendered}");
            } else {
                println!("{rendered}");
            }
        }
        Err(e) => eprintln!("warning: could not render QR code: {e}"),
    }
}

#[cfg(feature = "fido2")]
pub(crate) fn run_fido2_enroll(
    output: PathBuf,
    force: bool,
    pin: bool,
    json: bool,
) -> Result<(), PqfileError> {
    ensure_overwrite_allowed(&output, false, force)?;
    let pin_value = if pin {
        Some(zeroize::Zeroizing::new(
            rpassword::prompt_password("Enter FIDO2 PIN: ").map_err(PqfileError::Io)?,
        ))
    } else {
        None
    };
    println!("Touch the security key to create the enrollment credential...");
    crate::fido2::enroll(&output, pin_value.as_deref().map(|z| z.as_str()))?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
            ])
        );
    } else {
        println!("FIDO2 enrollment written to {}", output.display());
        println!(
            "Use --fido2 {} with encrypt/decrypt/check --passphrase.",
            output.display()
        );
    }
    Ok(())
}

// ── import-key ────────────────────────────────────────────────────────────

pub(crate) fn run_import_key(
    from: PathBuf,
    out: PathBuf,
    force: bool,
    use_passphrase: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let ssh_pem = std::fs::read_to_string(&from)?;
    let passphrase = if use_passphrase {
        Some(prompt_passphrase("Enter passphrase for new key: ")?)
    } else {
        None
    };

    // Check for existing output files.
    let pub_path = out.join("pubkey.pem");
    let priv_path = out.join("privkey.pem");
    if !force && (pub_path.exists() || priv_path.exists()) {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "pubkey.pem or privkey.pem already exists; use --force to overwrite",
        )));
    }

    let (pub_pem, priv_pem) =
        keygen::import_key_from_ssh(&ssh_pem, passphrase.as_ref().map(|z| z.as_str()))?;
    let fp = keygen::fingerprint_pem(&pub_pem);
    std::fs::create_dir_all(&out)?;
    std::fs::write(&pub_path, pub_pem.as_bytes())?;
    write_private_file(&priv_path, priv_pem.as_bytes())?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("from", &from.to_string_lossy()),
                kv_str("out", &out.to_string_lossy()),
                kv_str("fingerprint", &fp),
                kv_str(
                    "warning",
                    "derived key is not interoperable with the source tool"
                ),
            ])
        );
    } else {
        println!("Imported:     {}", from.display());
        println!("Saved:        {}", out.display());
        println!("Fingerprint:  {fp}");
        println!(
            "Note:         derived key is not interoperable with SSH. One-way migration only."
        );
    }
    Ok(())
}

// ── fingerprint ───────────────────────────────────────────────────────────────

pub(crate) fn run_fingerprint(key: &str, qr: bool, json: bool) -> Result<(), PqfileError> {
    let pub_pem = if pqfile::recipient_string::is_recipient_string(key) {
        pqfile::recipient_string::decode_pubkey(key)?
    } else {
        std::fs::read_to_string(key)?
    };

    let fp = keygen::fingerprint_pem(&pub_pem);
    let recipient_str = pqfile::recipient_string::encode_pubkey(&pub_pem).unwrap_or_default();

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("fingerprint", &fp),
                kv_str("recipient_string", &recipient_str),
            ])
        );
    } else {
        println!("Fingerprint:      {fp}");
        if !recipient_str.is_empty() {
            println!("Recipient string: {recipient_str}");
        }
    }
    if qr && !recipient_str.is_empty() {
        print_recipient_qr(&recipient_str, json);
    }
    Ok(())
}
