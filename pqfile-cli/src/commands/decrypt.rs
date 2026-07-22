//! `decrypt` and `check`: recipient-key, passphrase (v10), stealth, and
//! time-locked (v11) decryption, plus `tlock round` (round-number lookup).

use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pqfile::decrypt;
use pqfile::error::PqfileError;
use pqfile::seek_decrypt::SeekableDecryptor;

use crate::config::load_config;
use crate::io_util::{
    derive_fido2_secret, emit_json_ok, open_reader, peek_original_size, read_keyfile,
    resolve_decrypt_out_path, CliOutput, PARALLEL_BATCH_SIZE,
};
use crate::json_util::{json_object, kv_raw, kv_str};
use crate::prompts::{maybe_prompt_passphrase, prompt_passphrase};

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_decrypt(
    key: Option<PathBuf>,
    passphrase_v10: bool,
    keyfile: Option<PathBuf>,
    fido2: Option<PathBuf>,
    no_config: bool,
    max_kdf_mem: u32,
    max_kdf_time: u32,
    input: String,
    output: Option<String>,
    parallel: bool,
    force: bool,
    stealth: bool,
    tlock: bool,
    tlock_url: Option<String>,
    resume: bool,
    fec: bool,
    #[cfg(feature = "audit")] audit_log: Option<PathBuf>,
    #[cfg(feature = "audit")] audit_key: Option<PathBuf>,
    #[cfg(feature = "audit")] audit_recipient: Option<String>,
    json: bool,
) -> Result<(), PqfileError> {
    if resume {
        if tlock {
            return Err(PqfileError::Io(io::Error::other(
                "--resume is not supported with --tlock",
            )));
        }
        return run_decrypt_resumable(key, no_config, &input, output.as_deref(), json);
    }
    // Merge config-file defaults for --audit-log/--audit-key/--audit-recipient
    // once, here, before any of the branches below - each of tlock/stealth/
    // passphrase/key-based only ever executes one path per invocation
    // (mutually exclusive, unlike encrypt's --recursive), so there is no
    // repeated-passphrase-prompt concern that would need special-casing.
    #[cfg(feature = "audit")]
    let (audit_log, audit_key, audit_recipient) = {
        let cfg = load_config(no_config)?;
        (
            audit_log.or(cfg.audit_log),
            audit_key.or(cfg.audit_key),
            audit_recipient.or(cfg.audit_recipient),
        )
    };
    let (to_stdout, out_path) = resolve_decrypt_out_path(&input, output.as_deref(), force)?;
    let reader = open_reader(&input)?;
    let mut reader = maybe_wrap_fec(reader, fec, &input)?;

    if tlock {
        let result = run_decrypt_tlock(
            tlock_url.as_deref(),
            &mut *reader,
            &input,
            to_stdout,
            &out_path,
            json,
        );
        #[cfg(feature = "audit")]
        if result.is_ok() {
            log_decrypt_event(&audit_log, &audit_key, &audit_recipient, &input, "tlock")?;
        }
        return result;
    }

    if stealth {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        let mut writer = CliOutput::new(to_stdout, &out_path)?;
        // decrypt_stream_stealth truncates any Padmé padding tail internally,
        // so no TruncatingWriter wrapping is needed here (unlike the normal
        // path below, there is no header to peek anyway).
        decrypt::decrypt_stream_stealth(&privkey_pem, &mut *reader, &mut writer, pp_str)?;
        writer.commit()?;
        #[cfg(feature = "audit")]
        log_decrypt_event(
            &audit_log,
            &audit_key,
            &audit_recipient,
            &input,
            &pqfile::keygen::fingerprint_pem(&privkey_pem),
        )?;
        emit_json_ok(json, to_stdout, &out_path)?;
        return Ok(());
    }

    // Cap decrypted output at the header's declared original_size, silently
    // dropping any Padmé padding tail. A no-op for every file that wasn't
    // padded (they already decrypt to exactly original_size bytes) or whose
    // size couldn't be peeked (0 disables truncation) - no --pad flag needed
    // at decrypt time.
    let mut writer = pqfile::padding::TruncatingWriter::new(
        CliOutput::new(to_stdout, &out_path)?,
        peek_original_size(&input),
    );

    #[cfg(feature = "audit")]
    #[allow(unused_assignments)]
    let mut key_fingerprint = String::from("passphrase");
    if passphrase_v10 {
        let pp = prompt_passphrase("Enter passphrase: ")?;
        if let Some(ref kf_path) = keyfile {
            let kf = read_keyfile(kf_path)?;
            decrypt::decrypt_stream_passphrase_keyfile_with_limits(
                pp.as_str(),
                &kf,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut writer,
            )?;
        } else if let Some(ref fido2_path) = fido2 {
            let hmac_secret = derive_fido2_secret(fido2_path)?;
            decrypt::decrypt_stream_passphrase_fido2_with_limits(
                pp.as_str(),
                &hmac_secret,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut writer,
            )?;
        } else {
            decrypt::decrypt_stream_passphrase_with_limits(
                pp.as_str(),
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut writer,
            )?;
        }
    } else {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        if parallel {
            decrypt::decrypt_stream_parallel(
                &privkey_pem,
                &mut *reader,
                &mut writer,
                pp_str,
                PARALLEL_BATCH_SIZE,
            )?;
        } else {
            decrypt::decrypt_stream(&privkey_pem, &mut *reader, &mut writer, pp_str)?;
        }
        #[cfg(feature = "audit")]
        {
            key_fingerprint = pqfile::keygen::fingerprint_pem(&privkey_pem);
        }
    }
    let mut writer = writer.into_inner();
    writer.commit()?;
    #[cfg(feature = "audit")]
    log_decrypt_event(
        &audit_log,
        &audit_key,
        &audit_recipient,
        &input,
        &key_fingerprint,
    )?;

    emit_json_ok(json, to_stdout, &out_path)?;
    Ok(())
}

/// `decrypt --resume`: v3/v5 (single-recipient, chunked) files only. Unlike
/// `encrypt --resume`, no checkpoint sidecar is needed - the ciphertext
/// doesn't change between attempts and `-k` supplies the private key every
/// time, so an existing partial output's own length is enough to know how
/// far decryption already got. The last whole chunk apparently present is
/// always redone rather than trusted (harmless and idempotent), since a
/// plain byte-length check can't distinguish "this chunk finished writing"
/// from "the file happens to be a multiple of chunk_size for some other
/// reason" the way `encrypt --resume`'s explicit tag-verification step can.
fn run_decrypt_resumable(
    key: Option<PathBuf>,
    no_config: bool,
    input: &str,
    output: Option<&str>,
    json: bool,
) -> Result<(), PqfileError> {
    if input == "-" {
        return Err(PqfileError::Io(io::Error::other(
            "--resume requires a real input file, not stdin",
        )));
    }
    let out = output.unwrap_or("");
    if out == "-" {
        return Err(PqfileError::Io(io::Error::other(
            "--resume requires a real output file, not stdout",
        )));
    }
    let out_path: PathBuf = if out.is_empty() {
        PathBuf::from(input).with_extension("")
    } else {
        PathBuf::from(out)
    };

    let key_path = resolve_key_path(key, no_config)?;
    let privkey_pem = std::fs::read_to_string(&key_path)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());

    let ct_file = std::fs::File::open(input)?;
    let mut sd = SeekableDecryptor::open(ct_file, &privkey_pem, pp_str)?;
    let chunk_size = sd.chunk_size() as u64;
    let num_chunks = sd.num_chunks();

    let already_bytes = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    let safe_chunks =
        (already_bytes / chunk_size).min(u64::from(num_chunks.saturating_sub(1))) as u32;
    let keep_bytes = u64::from(safe_chunks) * chunk_size;

    let mut out_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&out_path)?;
    out_file.set_len(keep_bytes).map_err(PqfileError::Io)?;
    out_file
        .seek(SeekFrom::Start(keep_bytes))
        .map_err(PqfileError::Io)?;

    for idx in safe_chunks..num_chunks {
        let pt = sd.read_chunk(idx)?;
        out_file.write_all(&pt).map_err(PqfileError::Io)?;
    }
    out_file.flush().map_err(PqfileError::Io)?;

    emit_json_ok(json, false, &out_path)?;
    Ok(())
}

/// Wraps `reader` in a [`pqfile::fec::FecRepairReader`] when `--fec` was
/// passed, transparently repairing bit rot using the `<input>.fec` sidecar
/// before any decrypt/check path sees the bytes. Requires a real input file
/// (not stdin) and the sidecar to actually exist.
#[cfg(feature = "fec")]
fn maybe_wrap_fec(
    reader: Box<dyn io::Read>,
    fec: bool,
    input: &str,
) -> Result<Box<dyn io::Read>, PqfileError> {
    if !fec {
        return Ok(reader);
    }
    if input == "-" {
        return Err(PqfileError::Io(io::Error::other(
            "--fec is not supported with stdin input",
        )));
    }
    let mut fec_path = std::ffi::OsString::from(input);
    fec_path.push(".fec");
    let parity = std::fs::File::open(&fec_path).map_err(|e| {
        PqfileError::Io(io::Error::other(format!(
            "--fec sidecar not found or unreadable ({}): {e}",
            Path::new(&fec_path).display()
        )))
    })?;
    Ok(Box::new(pqfile::fec::FecRepairReader::new(reader, parity)?))
}

#[cfg(not(feature = "fec"))]
fn maybe_wrap_fec(
    reader: Box<dyn io::Read>,
    _fec: bool,
    _input: &str,
) -> Result<Box<dyn io::Read>, PqfileError> {
    Ok(reader)
}

/// After a successful decrypt, if `--audit-log` (or its config-file
/// default) is set, appends a signed+encrypted audit record for this event.
/// The fingerprinted file is the *ciphertext* input, not the recovered
/// plaintext - the artifact of record for a decrypt event is which
/// encrypted file was opened, mirroring what `encrypt` logs (the produced
/// ciphertext, never the plaintext) so nothing plaintext-derived ever
/// enters the log. Not supported with stdin input, since there is no file
/// to fingerprint.
#[cfg(feature = "audit")]
fn log_decrypt_event(
    audit_log: &Option<PathBuf>,
    audit_key: &Option<PathBuf>,
    audit_recipient: &Option<String>,
    input: &str,
    key_fingerprint: &str,
) -> Result<(), PqfileError> {
    let Some(target) = crate::commands::audit::AuditTarget::resolve(
        audit_log.clone(),
        audit_key.clone(),
        audit_recipient.clone(),
        &crate::config::CliConfig::default(),
    )?
    else {
        return Ok(());
    };
    if input == "-" {
        return Err(PqfileError::Io(io::Error::other(
            "--audit-log is not supported with stdin input",
        )));
    }
    let fingerprint = crate::commands::audit::fingerprint_file(Path::new(input))?;
    target.append("decrypt", fingerprint, key_fingerprint)
}

/// Always present regardless of the `tlock` feature so `run_decrypt`/`run_check`
/// don't need their own `#[cfg]` branch: without the feature, `tlock` is
/// always `false` (the CLI flag doesn't exist to set it), so this is provably
/// unreachable in that build, but still has to type-check. Mirrors
/// `derive_fido2_secret`'s pattern.
#[allow(clippy::too_many_arguments)]
fn run_decrypt_tlock(
    #[cfg_attr(not(feature = "tlock"), allow(unused_variables))] relay_url: Option<&str>,
    #[cfg_attr(not(feature = "tlock"), allow(unused_variables))] reader: &mut dyn io::Read,
    input: &str,
    to_stdout: bool,
    out_path: &Path,
    json: bool,
) -> Result<(), PqfileError> {
    #[cfg(feature = "tlock")]
    {
        if !json {
            eprintln!(
                "Fetching drand beacon signature{}...",
                relay_url.map(|u| format!(" from {u}")).unwrap_or_default()
            );
        }
        let mut writer = pqfile::padding::TruncatingWriter::new(
            CliOutput::new(to_stdout, out_path)?,
            peek_original_size(input),
        );
        pqfile::tlock::decrypt_stream_tlock(relay_url, reader, &mut writer)?;
        let mut writer = writer.into_inner();
        writer.commit()?;
        emit_json_ok(json, to_stdout, out_path)?;
        Ok(())
    }
    #[cfg(not(feature = "tlock"))]
    {
        let _ = (input, to_stdout, out_path, json);
        unreachable!("tlock feature disabled; --tlock CLI flag does not exist without it")
    }
}

/// `Write` sink that discards everything but remembers how many bytes passed through.
struct CountingSink(u64);

impl io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Resolves the private key path for decrypt/check: the explicit `-k` flag
/// wins, then the config file's `key` entry.
fn resolve_key_path(key: Option<PathBuf>, no_config: bool) -> Result<PathBuf, PqfileError> {
    if let Some(k) = key {
        return Ok(k);
    }
    if let Some(k) = load_config(no_config)?.key {
        return Ok(k);
    }
    Err(PqfileError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "provide -k <PRIVKEY>, use --passphrase for v10 passphrase-only files, \
         or set a default `key` in the config file",
    )))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_check(
    key: Option<PathBuf>,
    passphrase_v10: bool,
    keyfile: Option<PathBuf>,
    fido2: Option<PathBuf>,
    no_config: bool,
    max_kdf_mem: u32,
    max_kdf_time: u32,
    input: String,
    parallel: bool,
    stealth: bool,
    tlock: bool,
    tlock_url: Option<String>,
    fec: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let reader = open_reader(&input)?;
    let mut reader = maybe_wrap_fec(reader, fec, &input)?;

    if tlock {
        return run_check_tlock(tlock_url.as_deref(), &mut *reader, &input, json);
    }

    if stealth {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        let mut sink = CountingSink(0);
        // decrypt_stream_stealth truncates internally, so sink.0 is already
        // the true (unpadded) plaintext byte count.
        decrypt::decrypt_stream_stealth(&privkey_pem, &mut *reader, &mut sink, pp_str)?;
        let count = sink.0;
        if json {
            println!(
                "{}",
                json_object(&[
                    kv_str("status", "ok"),
                    kv_str("input", &input),
                    kv_raw("plaintext_bytes", &count.to_string()),
                ])
            );
        } else {
            println!(
                "OK: {input} authenticated ({count} plaintext byte{})",
                if count == 1 { "" } else { "s" }
            );
        }
        return Ok(());
    }

    // Cap the reported count at the header's declared original_size, so a
    // padded file's plaintext_bytes reflects the true size, not the padded
    // physical length. No-op for non-padded files; see peek_original_size.
    let mut sink =
        pqfile::padding::TruncatingWriter::new(CountingSink(0), peek_original_size(&input));

    if passphrase_v10 {
        let pp = prompt_passphrase("Enter passphrase: ")?;
        if let Some(ref kf_path) = keyfile {
            let kf = read_keyfile(kf_path)?;
            decrypt::decrypt_stream_passphrase_keyfile_with_limits(
                pp.as_str(),
                &kf,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut sink,
            )?;
        } else if let Some(ref fido2_path) = fido2 {
            let hmac_secret = derive_fido2_secret(fido2_path)?;
            decrypt::decrypt_stream_passphrase_fido2_with_limits(
                pp.as_str(),
                &hmac_secret,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut sink,
            )?;
        } else {
            decrypt::decrypt_stream_passphrase_with_limits(
                pp.as_str(),
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut sink,
            )?;
        }
    } else {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        if parallel {
            decrypt::decrypt_stream_parallel(
                &privkey_pem,
                &mut *reader,
                &mut sink,
                pp_str,
                PARALLEL_BATCH_SIZE,
            )?;
        } else {
            decrypt::decrypt_stream(&privkey_pem, &mut *reader, &mut sink, pp_str)?;
        }
    }
    let count = sink.into_inner().0;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("input", &input),
                kv_raw("plaintext_bytes", &count.to_string()),
            ])
        );
    } else {
        println!(
            "OK: {input} authenticated ({count} plaintext byte{})",
            if count == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

/// Always present regardless of the `tlock` feature; mirrors
/// `run_decrypt_tlock`/`derive_fido2_secret`'s uniform-call-site pattern.
fn run_check_tlock(
    #[cfg_attr(not(feature = "tlock"), allow(unused_variables))] relay_url: Option<&str>,
    #[cfg_attr(not(feature = "tlock"), allow(unused_variables))] reader: &mut dyn io::Read,
    input: &str,
    json: bool,
) -> Result<(), PqfileError> {
    #[cfg(feature = "tlock")]
    {
        if !json {
            eprintln!(
                "Fetching drand beacon signature{}...",
                relay_url.map(|u| format!(" from {u}")).unwrap_or_default()
            );
        }
        let mut sink =
            pqfile::padding::TruncatingWriter::new(CountingSink(0), peek_original_size(input));
        pqfile::tlock::decrypt_stream_tlock(relay_url, reader, &mut sink)?;
        let count = sink.into_inner().0;
        if json {
            println!(
                "{}",
                json_object(&[
                    kv_str("status", "ok"),
                    kv_str("input", input),
                    kv_raw("plaintext_bytes", &count.to_string()),
                ])
            );
        } else {
            println!(
                "OK: {input} authenticated ({count} plaintext byte{})",
                if count == 1 { "" } else { "s" }
            );
        }
        Ok(())
    }
    #[cfg(not(feature = "tlock"))]
    {
        let _ = (input, json);
        unreachable!("tlock feature disabled; --tlock CLI flag does not exist without it")
    }
}

/// `pqfile tlock round <WHEN>`: resolves a human time expression to a drand
/// round number for `encrypt --tlock-round`. Fetches only the chain's public
/// parameters (genesis time, period), never a round's own beacon.
#[cfg(feature = "tlock")]
pub(crate) fn run_tlock_round(
    when: &str,
    relay: Option<String>,
    json: bool,
) -> Result<(), PqfileError> {
    let round = pqfile::tlock::round_for_target_time(when, None, relay.as_deref())?;
    if json {
        println!(
            "{}",
            json_object(&[kv_str("status", "ok"), kv_raw("round", &round.to_string())])
        );
    } else {
        println!("{round}");
    }
    Ok(())
}
