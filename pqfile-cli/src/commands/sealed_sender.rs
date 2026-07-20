//! `identity-keygen`, `seal`, `unseal`: deniable sender authentication over a
//! static X25519 identity key pair, distinct from encryption/signing keys.

use std::io::{self, Write};
use std::path::PathBuf;

use pqfile::error::PqfileError;
use pqfile::{format, keygen, sealed_sender};

use crate::commands::cert::resolve_single_recipient;
use crate::io_util::{
    emit_decrypt_verified_status, open_reader, resolve_decrypt_out_path,
    resolve_pqf_sibling_out_path, AtomicOutput, CliOutput,
};
use crate::json_util::{json_object, kv_str};
use crate::prompts::{maybe_prompt_passphrase, prompt_new_passphrase};

pub(crate) fn run_identity_keygen(
    out: PathBuf,
    force: bool,
    use_passphrase: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let pp = if use_passphrase {
        let p = prompt_new_passphrase()?;
        if !json && keygen::passphrase_strength(p.as_str()) <= 2 {
            eprintln!("Warning: passphrase is weak. Use 12+ characters with mixed case, digits, and symbols.");
        }
        Some(p)
    } else {
        None
    };
    let r = sealed_sender::identity_keygen(&out, force, pp.as_deref().map(|z| z.as_str()))?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str(
                    "pk_path",
                    &out.join("identity_pubkey.pem").to_string_lossy()
                ),
                kv_str(
                    "sk_path",
                    &out.join("identity_privkey.pem").to_string_lossy()
                ),
                kv_str("fingerprint", &r.pk_fingerprint),
            ])
        );
    } else {
        println!("Identity keys written to {}", out.display());
        println!("Identity key fingerprint: {}", r.pk_fingerprint);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_seal(
    key: PathBuf,
    recipient_identity: PathBuf,
    recipient: PathBuf,
    ca_key: Option<PathBuf>,
    revocations: Option<PathBuf>,
    input: PathBuf,
    output: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let sk_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&sk_pem, "Enter passphrase for identity key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let recipient_identity_pk_pem = std::fs::read_to_string(&recipient_identity)?;
    let pem = std::fs::read_to_string(&recipient)?;
    let pubkey_pem = resolve_single_recipient(
        pem,
        &recipient,
        ca_key.as_deref(),
        revocations.as_deref(),
        pqfile::cert::cert_use::ENCRYPT,
    )?;

    let input_len = std::fs::metadata(&input)?.len();
    let out_path = resolve_pqf_sibling_out_path(&input, output, force)?;

    let mut file = std::io::BufReader::new(std::fs::File::open(&input)?);
    let mut writer = AtomicOutput::new(&out_path)?;
    sealed_sender::seal(
        &sk_pem,
        pp_str,
        &recipient_identity_pk_pem,
        &pubkey_pem,
        &mut file,
        input_len,
        &mut writer,
        format::CHUNK_SIZE,
    )?;
    writer.commit()?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("input", &input.to_string_lossy()),
                kv_str("output", &out_path.to_string_lossy()),
            ])
        );
    } else {
        println!("Sealed: {}", out_path.display());
    }
    Ok(())
}

pub(crate) fn run_unseal(
    key: PathBuf,
    identity_key: PathBuf,
    sender_identity: PathBuf,
    input: String,
    output: Option<String>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let identity_sk_pem = std::fs::read_to_string(&identity_key)?;
    let identity_pp =
        maybe_prompt_passphrase(&identity_sk_pem, "Enter passphrase for identity key: ")?;
    let identity_pp_str = identity_pp.as_deref().map(|z| z.as_str());
    let sender_identity_pk_pem = std::fs::read_to_string(&sender_identity)?;

    let (to_stdout, out_path) = resolve_decrypt_out_path(&input, output.as_deref(), force)?;
    let reader = open_reader(&input)?;

    // unseal_bytes always buffers internally and only returns plaintext once the
    // deniable-authentication tag verifies, so there is no write-before-verify
    // hazard here to guard against with streaming output.
    let plaintext = sealed_sender::unseal_bytes(
        &privkey_pem,
        pp_str,
        &identity_sk_pem,
        identity_pp_str,
        &sender_identity_pk_pem,
        reader,
    )?;

    if to_stdout {
        io::stdout()
            .write_all(&plaintext)
            .map_err(PqfileError::Io)?;
    } else {
        let mut writer = CliOutput::new(false, &out_path)?;
        writer.write_all(&plaintext).map_err(PqfileError::Io)?;
        writer.commit()?;
    }

    emit_decrypt_verified_status(
        json,
        to_stdout,
        &out_path,
        "authentication",
        "valid",
        "Sender authenticated.",
    )
}
