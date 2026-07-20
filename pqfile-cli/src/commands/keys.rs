//! `revoke`, `rekey`, `add-recipient`, `repassphrase`: commands that operate
//! on an existing key or rewrite a `.pqf` file's header without touching the
//! payload ciphertext.

use std::io;
use std::path::PathBuf;

use pqfile::error::PqfileError;
use pqfile::{add_recipient, rekey, repassphrase, revoke};

use crate::io_util::{emit_json_ok, open_reader, resolve_in_place_out_path, CliOutput};
use crate::json_util::{json_object, kv_raw, kv_str};
use crate::prompts::{maybe_prompt_passphrase, prompt_new_passphrase, prompt_passphrase};

pub(crate) fn run_revoke(key: PathBuf, reason: &str, json: bool) -> Result<(), PqfileError> {
    let fp = revoke::revoke_key(&key, reason)?;
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("fingerprint", &fp),
                kv_str(
                    "revoked_path",
                    &revoke::revoked_path_for(&key).to_string_lossy()
                ),
            ])
        );
    } else {
        println!("Key revoked: {fp}");
        println!(
            "Sidecar written to {}",
            revoke::revoked_path_for(&key).display()
        );
    }
    Ok(())
}

pub(crate) fn run_rekey(
    key: PathBuf,
    recipient: PathBuf,
    input: String,
    output: Option<String>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    let (to_stdout, out_path) = resolve_in_place_out_path(&input, output.as_deref(), force)?;

    let mut reader = open_reader(&input)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    rekey::rekey_stream(&privkey_pem, &pubkey_pem, &mut *reader, &mut writer, pp_str)?;
    writer.commit()?;

    emit_json_ok(json, to_stdout, &out_path)?;
    Ok(())
}

pub(crate) fn run_add_recipient(
    key: PathBuf,
    recipient: PathBuf,
    input: String,
    output: Option<String>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    let (to_stdout, out_path) = resolve_in_place_out_path(&input, output.as_deref(), force)?;

    let mut reader = open_reader(&input)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    let info = add_recipient::add_recipient_stream(
        &privkey_pem,
        &pubkey_pem,
        &mut *reader,
        &mut writer,
        pp_str,
    )?;
    writer.commit()?;

    if json {
        let target: &mut dyn io::Write = if to_stdout {
            &mut io::stderr()
        } else {
            &mut io::stdout()
        };
        let lossy = out_path.to_string_lossy();
        let out_val: &str = if to_stdout { "-" } else { &lossy };
        writeln!(
            target,
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", out_val),
                kv_raw("recipient_count", &info.recipient_count.to_string()),
            ])
        )?;
    } else if !to_stdout {
        eprintln!(
            "Recipient added. File now has {} recipient(s).",
            info.recipient_count
        );
    }
    Ok(())
}

pub(crate) fn run_repassphrase(
    key: PathBuf,
    from_legacy: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let old_pp = prompt_passphrase("Enter current passphrase: ")?;
    let new_pp = prompt_new_passphrase()?;
    repassphrase::repassphrase_file(&key, old_pp.as_str(), new_pp.as_str(), from_legacy)?;
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("key", &key.to_string_lossy()),
                kv_str(
                    "note",
                    if from_legacy {
                        "migrated from legacy p=1 to p=4"
                    } else {
                        "passphrase updated (p=4)"
                    }
                ),
            ])
        );
    } else if from_legacy {
        println!("Key migrated to Argon2id p=4: {}", key.display());
    } else {
        println!("Passphrase updated: {}", key.display());
    }
    Ok(())
}
