//! `revoke`, `rekey`, `rotate`, `add-recipient`, `repassphrase`: commands
//! that operate on an existing key or rewrite a `.pqf` file's header without
//! touching the payload ciphertext.

use std::io;
use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;
use pqfile::{add_recipient, rekey, repassphrase, revoke};

use crate::io_util::{
    emit_json_ok, open_reader, resolve_in_place_out_path, AtomicOutput, CliOutput,
};
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

/// Batch-rekeys every `.pqf` file under a directory tree to a new recipient,
/// each rewritten in place via the existing zero-copy `rekey::rekey_stream`.
/// Distinct from `archive --recursive` (which packs a tree into one
/// `.pqfa`); this rotates keys across many already-independent `.pqf` files.
/// No new crypto, no format change - a thin batch wrapper around `rekey`.
pub(crate) fn run_rotate(
    old_key: PathBuf,
    new_recipient: PathBuf,
    input: String,
    recursive: bool,
    json: bool,
) -> Result<(), PqfileError> {
    if !recursive {
        return Err(PqfileError::Io(io::Error::other(
            "rotate requires --recursive (rewrites every .pqf file under the directory); \
             use `pqfile rekey` to rotate a single file",
        )));
    }
    let dir = PathBuf::from(&input);
    if !dir.is_dir() {
        return Err(PqfileError::Io(io::Error::other(format!(
            "'{input}' is not a directory (--recursive requires a directory path)"
        ))));
    }

    let privkey_pem = std::fs::read_to_string(&old_key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for old private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pubkey_pem = std::fs::read_to_string(&new_recipient)?;
    revoke::check_not_revoked(&new_recipient, &pubkey_pem)?;

    let mut all_files: Vec<PathBuf> = Vec::new();
    collect_all_files(&dir, &mut all_files)?;
    let (pqf_files, skipped): (Vec<PathBuf>, Vec<PathBuf>) = all_files
        .into_iter()
        .partition(|p| p.extension().is_some_and(|e| e == "pqf"));

    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut json_entries: Vec<String> = Vec::new();

    for file_path in &pqf_files {
        let path_str = file_path.to_string_lossy();
        match rotate_one_file(&privkey_pem, &pubkey_pem, file_path, pp_str) {
            Ok(()) => {
                succeeded += 1;
                if json {
                    json_entries.push(json_object(&[
                        kv_str("file", &path_str),
                        kv_str("status", "ok"),
                    ]));
                } else {
                    println!("ok: {path_str}");
                }
            }
            Err(e) => {
                failed += 1;
                if json {
                    json_entries.push(json_object(&[
                        kv_str("file", &path_str),
                        kv_str("status", "failed"),
                        kv_raw("code", &e.code().to_string()),
                        kv_str("message", &e.to_string()),
                    ]));
                } else {
                    eprintln!("failed: {path_str}: {e}");
                }
            }
        }
    }
    if json {
        for file_path in &skipped {
            json_entries.push(json_object(&[
                kv_str("file", &file_path.to_string_lossy()),
                kv_str("status", "skipped-non-pqf"),
            ]));
        }
        println!("[{}]", json_entries.join(","));
    } else {
        eprintln!(
            "rotate: {succeeded} succeeded, {failed} failed, {} skipped (non-.pqf)",
            skipped.len()
        );
    }

    if failed == 0 {
        Ok(())
    } else {
        Err(PqfileError::Io(io::Error::other(format!(
            "{failed} of {} .pqf file(s) failed to rotate",
            pqf_files.len()
        ))))
    }
}

/// Rekeys one `.pqf` file to the new recipient in place: writes to a
/// temporary file next to it, then atomically renames over the original.
/// Mirrors what the single-file `rekey` command does, minus the `-o`/stdout
/// option - a batch rotate over many files has nowhere else sensible to put
/// each output.
fn rotate_one_file(
    old_privkey_pem: &str,
    new_pubkey_pem: &str,
    file_path: &Path,
    passphrase: Option<&str>,
) -> Result<(), PqfileError> {
    let mut reader = io::BufReader::new(std::fs::File::open(file_path)?);
    let mut writer = AtomicOutput::new(file_path)?;
    rekey::rekey_stream(
        old_privkey_pem,
        new_pubkey_pem,
        &mut reader,
        &mut writer,
        passphrase,
    )?;
    writer.commit()?;
    Ok(())
}

/// Recursively collects every regular file under `dir` (skipping symlinks,
/// which `read_dir`'s file type reports as neither a file nor a directory -
/// matching `encrypt --recursive`'s own `collect_files`), sorted for
/// determinism. The caller splits the result into `.pqf` and non-`.pqf`.
fn collect_all_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), PqfileError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_all_files(&path, files)?;
        } else if ft.is_file() {
            files.push(path);
        }
    }
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
