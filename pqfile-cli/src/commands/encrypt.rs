//! `encrypt`: recipient-key, passphrase (v10), and time-locked (v11) file
//! encryption, plus the `--recursive` directory-tree variant.

use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;
use pqfile::writer::PqfWriter;
use pqfile::{encrypt, format, revoke};

use crate::commands::cert::resolve_cert_with_ca;
use crate::config::load_config;
use crate::io_util::{
    derive_fido2_secret, emit_json_ok, ensure_overwrite_allowed, open_reader, read_keyfile,
    write_private_file, AtomicOutput, CliOutput, PARALLEL_BATCH_SIZE,
};
use crate::json_util::{json_object, kv_raw, kv_str};
use crate::prompts::prompt_new_passphrase;

/// Checkpoint sidecar update cadence for `encrypt --resume`: bounds redo-on-
/// crash to at most this many bytes of re-encryption, without fsyncing the
/// (potentially huge) output file after every single small chunk.
const RESUME_CHECKPOINT_INTERVAL_BYTES: u64 = 64 * 1024 * 1024;

/// Wraps a plaintext reader with Padmé length padding when requested,
/// otherwise passes it through unchanged. A single concrete type keeps the
/// two call sites (`run_encrypt_single`, `run_encrypt_passphrase`) from
/// needing separate padded/unpadded code paths.
enum MaybePadded<'a> {
    Plain(&'a mut dyn io::Read),
    Padded(pqfile::padding::PadmeReader<&'a mut dyn io::Read>),
}

impl<'a> MaybePadded<'a> {
    fn new(
        reader: &'a mut dyn io::Read,
        pad: bool,
        original_size: u64,
    ) -> Result<Self, PqfileError> {
        if !pad {
            return Ok(MaybePadded::Plain(reader));
        }
        if original_size == 0 {
            return Err(PqfileError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--pad requires a known, non-zero input size; not supported when reading \
                 from stdin or for empty files",
            )));
        }
        Ok(MaybePadded::Padded(pqfile::padding::PadmeReader::new(
            reader,
            original_size,
        )))
    }
}

impl io::Read for MaybePadded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MaybePadded::Plain(r) => r.read(buf),
            MaybePadded::Padded(r) => r.read(buf),
        }
    }
}

#[derive(Clone)]
pub(crate) struct EncryptOpts {
    pub(crate) chunk_size: usize,
    pub(crate) compress: bool,
    pub(crate) compress_level: i32,
    pub(crate) parallel: bool,
    pub(crate) pipeline: bool,
    pub(crate) mmap: bool,
    pub(crate) anonymous_recipients: bool,
    pub(crate) pad_recipients: bool,
    pub(crate) force: bool,
    pub(crate) json: bool,
    pub(crate) kdf_mem: u32,
    pub(crate) kdf_time: u32,
    pub(crate) keyfile: Option<PathBuf>,
    /// Always present regardless of the `fido2` feature so downstream logic
    /// (`run_encrypt_passphrase`) stays uniform; without the feature the CLI
    /// arg simply doesn't exist, so this is always `None` in that build.
    pub(crate) fido2: Option<PathBuf>,
    pub(crate) pad: bool,
    pub(crate) stealth: bool,
    pub(crate) resume: bool,
    pub(crate) fec: bool,
    #[cfg_attr(not(feature = "audit"), allow(dead_code))]
    pub(crate) audit_log: Option<PathBuf>,
    #[cfg_attr(not(feature = "audit"), allow(dead_code))]
    pub(crate) audit_key: Option<PathBuf>,
    #[cfg_attr(not(feature = "audit"), allow(dead_code))]
    pub(crate) audit_recipient: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_encrypt(
    mut recipients: Vec<String>,
    ca_key: Option<PathBuf>,
    revocations: Option<PathBuf>,
    passphrase_only: bool,
    tlock_round: Option<u64>,
    no_config: bool,
    input: String,
    output: Option<String>,
    recursive: bool,
    #[allow(unused_mut)] mut opts: EncryptOpts,
) -> Result<(), PqfileError> {
    // Load the config file once, here, before any dispatch branch - so every
    // path below (tlock, passphrase, recursive, single) sees the same
    // already-resolved defaults and none of them need their own config lookup.
    let cfg = load_config(no_config)?;
    #[cfg(feature = "audit")]
    {
        if opts.audit_log.is_none() {
            opts.audit_log = cfg.audit_log.clone();
        }
        if opts.audit_key.is_none() {
            opts.audit_key = cfg.audit_key.clone();
        }
        if opts.audit_recipient.is_none() {
            opts.audit_recipient = cfg.audit_recipient.clone();
        }
    }
    if let Some(round) = tlock_round {
        if recursive {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--tlock-round and --recursive cannot be combined",
            )));
        }
        if opts.stealth {
            return Err(PqfileError::Io(std::io::Error::other(
                "--stealth is not supported with --tlock-round",
            )));
        }
        if opts.resume {
            return Err(PqfileError::Io(std::io::Error::other(
                "--resume is not supported with --tlock-round",
            )));
        }
        return run_encrypt_tlock(round, &input, output.as_deref(), opts);
    }
    if passphrase_only {
        if recursive {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--passphrase and --recursive cannot be combined",
            )));
        }
        if opts.stealth {
            return Err(PqfileError::Io(std::io::Error::other(
                "--stealth is not supported with --passphrase",
            )));
        }
        let pp = prompt_new_passphrase()?;
        return run_encrypt_passphrase(pp.as_str(), &input, output.as_deref(), opts);
    }
    if recipients.is_empty() {
        if let Some(r) = cfg.recipient.clone() {
            recipients.push(r);
        }
    }
    if !cfg.groups.is_empty() {
        recipients = expand_recipient_groups(recipients, &cfg.groups);
    }
    if recipients.is_empty() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "provide at least one -r recipient, use --passphrase for passphrase-only encryption, \
             or set a default `recipient` in the config file",
        )));
    }
    if opts.chunk_size > 268_435_456 {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("--chunk-size must be ≤ 268435456, got {}", opts.chunk_size),
        )));
    }
    if opts.compress && (opts.compress_level < 1 || opts.compress_level > 22) {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "--compress-level must be between 1 and 22, got {}",
                opts.compress_level
            ),
        )));
    }
    // Resolve the CA verifying key and revocation list (if given) once for the
    // whole batch rather than once per certificate recipient below - the
    // revocation list's signature check in particular is real work that
    // would otherwise scale with recipient count (up to 256).
    let ca_vk_pem: Option<String> = ca_key.as_deref().map(std::fs::read_to_string).transpose()?;
    let revocation_list: Option<pqfile::cert::RevocationList> = match (&ca_vk_pem, &revocations) {
        (Some(ca_vk_pem), Some(revocations)) => {
            let list_pem = std::fs::read_to_string(revocations)?;
            Some(pqfile::cert::verify_revocation_list(ca_vk_pem, &list_pem)?)
        }
        _ => None,
    };

    // Load and validate recipient public keys. Each recipient can be a path to a
    // pubkey.pem file, a certificate PEM (produced by `issue-cert`), or a
    // `pqf1…` Bech32 recipient string.
    let pubkey_pems: Vec<String> = recipients
        .iter()
        .map(|r| {
            if pqfile::recipient_string::is_recipient_string(r) {
                // Bech32 recipient string: decode directly; no revocation check possible.
                pqfile::recipient_string::decode_pubkey(r)
            } else {
                // File path: read PEM and check for revocation.
                let p = std::path::Path::new(r);
                let pem = std::fs::read_to_string(p)?;
                match resolve_cert_with_ca(
                    &pem,
                    p,
                    ca_vk_pem.as_deref(),
                    revocation_list.as_ref(),
                    pqfile::cert::cert_use::ENCRYPT,
                )? {
                    Some(subject_pem) => Ok(subject_pem),
                    None => {
                        revoke::check_not_revoked(p, &pem)?;
                        Ok(pem)
                    }
                }
            }
        })
        .collect::<Result<_, _>>()?;
    if recursive {
        if opts.pad {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --recursive",
            )));
        }
        if opts.stealth {
            return Err(PqfileError::Io(std::io::Error::other(
                "--stealth is not supported with --recursive",
            )));
        }
        if pubkey_pems.len() != 1 {
            return Err(PqfileError::Io(std::io::Error::other(
                "--recursive supports only one recipient",
            )));
        }
        run_encrypt_recursive(&pubkey_pems[0], &input, opts)
    } else {
        if opts.stealth {
            if pubkey_pems.len() != 1 {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth supports only one recipient",
                )));
            }
            if opts.mmap {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --mmap",
                )));
            }
            if opts.pipeline {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --pipeline",
                )));
            }
            if opts.compress {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --compress",
                )));
            }
            if opts.parallel {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --parallel",
                )));
            }
            if opts.anonymous_recipients || opts.pad_recipients {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --anonymous-recipients or --pad-recipients \
                     (stealth mode is already single-recipient and reveals nothing about key type)",
                )));
            }
            if opts.chunk_size != 0 && opts.chunk_size != format::CHUNK_SIZE {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth always uses the default chunk size; --chunk-size is not supported",
                )));
            }
            return run_encrypt_stealth(&pubkey_pems[0], &input, output.as_deref(), opts);
        }
        run_encrypt_single(&pubkey_pems, &input, output.as_deref(), opts)
    }
}

/// Expands any `-r` value that names a configured `[groups]` entry (see
/// `pqfile-cli/src/config.rs`) into that group's member list, in place.
/// Values that don't match a group name pass through unchanged - bech32
/// recipient strings and pubkey/cert file paths are not expected to collide
/// with a group name in practice. Group membership is not resolved
/// recursively: a member that itself names another group is passed through
/// literally rather than expanded again, so cycles can't occur.
fn expand_recipient_groups(
    recipients: Vec<String>,
    groups: &std::collections::HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(recipients.len());
    for r in recipients {
        match groups.get(&r) {
            Some(members) => out.extend(members.iter().cloned()),
            None => out.push(r),
        }
    }
    out
}

/// Resolves the plaintext size and output destination shared by the encrypt
/// commands: default output is `<input>.pqf`; `-` (or stdin input with no
/// `-o`) means stdout. Also enforces the overwrite guard.
fn resolve_encrypt_output(
    input: &str,
    output: Option<&str>,
    force: bool,
) -> Result<(u64, bool, PathBuf), PqfileError> {
    let original_size: u64 = if input != "-" {
        std::fs::metadata(input).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let out = output.unwrap_or_else(|| if input == "-" { "-" } else { "" });
    let to_stdout = out == "-" || (out.is_empty() && input == "-");
    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        let mut s = std::ffi::OsString::from(input);
        s.push(".pqf");
        PathBuf::from(s)
    } else {
        PathBuf::from(out)
    };

    ensure_overwrite_allowed(&out_path, to_stdout, force)?;
    Ok((original_size, to_stdout, out_path))
}

/// After a successful encrypt, if `--fec` was requested, writes a Reed-
/// Solomon parity sidecar (`<out_path>.fec`) as a post-pass over the
/// finished output file - see `pqfile::fec`'s module docs for why this is a
/// separate sidecar rather than anything embedded in the `.pqf` file
/// itself. Not supported when the payload went to stdout, since there is no
/// file to read back afterward.
#[cfg(feature = "fec")]
fn write_fec_sidecar_if_requested(
    fec: bool,
    to_stdout: bool,
    out_path: &Path,
) -> Result<(), PqfileError> {
    if !fec {
        return Ok(());
    }
    if to_stdout {
        return Err(PqfileError::Io(io::Error::other(
            "--fec is not supported with stdout output",
        )));
    }
    let mut f = std::fs::File::open(out_path)?;
    let sidecar = pqfile::fec::generate_sidecar(&mut f)?;
    let mut fec_path = out_path.as_os_str().to_owned();
    fec_path.push(".fec");
    std::fs::write(fec_path, sidecar)?;
    Ok(())
}

#[cfg(not(feature = "fec"))]
fn write_fec_sidecar_if_requested(
    _fec: bool,
    _to_stdout: bool,
    _out_path: &Path,
) -> Result<(), PqfileError> {
    Ok(())
}

/// After a successful encrypt, if `--audit-log` (or its config-file
/// default) is set, appends a signed+encrypted audit record for this event.
/// `key_fingerprint` is whatever identifies the key involved: the
/// recipient's own fingerprint for key-pair modes, or a fixed placeholder
/// string for passphrase/time-locked modes, which have no recipient key
/// pair to fingerprint at all. Not supported when the payload went to
/// stdout (no file to fingerprint afterward) - the `--recursive` case is
/// excluded at the clap level instead (see `audit_log`'s help text) since
/// resolving a fresh operator key/passphrase per file in a batch is a
/// worse UX than just disallowing the combination for now.
#[cfg(feature = "audit")]
fn log_encrypt_event(
    opts: &EncryptOpts,
    to_stdout: bool,
    out_path: &Path,
    key_fingerprint: &str,
) -> Result<(), PqfileError> {
    let Some(target) = crate::commands::audit::AuditTarget::resolve(
        opts.audit_log.clone(),
        opts.audit_key.clone(),
        opts.audit_recipient.clone(),
        &crate::config::CliConfig::default(),
    )?
    else {
        return Ok(());
    };
    if to_stdout {
        return Err(PqfileError::Io(io::Error::other(
            "--audit-log is not supported with stdout output",
        )));
    }
    let fingerprint = crate::commands::audit::fingerprint_file(out_path)?;
    target.append("encrypt", fingerprint, key_fingerprint)
}

#[cfg(not(feature = "audit"))]
fn log_encrypt_event(
    _opts: &EncryptOpts,
    _to_stdout: bool,
    _out_path: &Path,
    _key_fingerprint: &str,
) -> Result<(), PqfileError> {
    Ok(())
}

fn run_encrypt_stealth(
    pubkey_pem: &str,
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    let (original_size, to_stdout, out_path) = resolve_encrypt_output(input, output, opts.force)?;
    let mut raw_reader = open_reader(input)?;
    let mut reader = MaybePadded::new(&mut *raw_reader, opts.pad, original_size)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    encrypt::encrypt_stream_stealth(pubkey_pem, original_size, &mut reader, &mut writer)?;
    writer.commit()?;
    write_fec_sidecar_if_requested(opts.fec, to_stdout, &out_path)?;
    log_encrypt_event(
        &opts,
        to_stdout,
        &out_path,
        &pqfile::keygen::fingerprint_pem(pubkey_pem),
    )?;

    emit_json_ok(opts.json, to_stdout, &out_path)?;
    Ok(())
}

fn run_encrypt_passphrase(
    passphrase: &str,
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    let (original_size, to_stdout, out_path) = resolve_encrypt_output(input, output, opts.force)?;
    let mut raw_reader = open_reader(input)?;
    let mut reader = MaybePadded::new(&mut *raw_reader, opts.pad, original_size)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    // p=4 matches the library default; --kdf-mem / --kdf-time only tune m and t.
    if let Some(ref kf_path) = opts.keyfile {
        let keyfile = read_keyfile(kf_path)?;
        encrypt::encrypt_stream_passphrase_keyfile_with_params(
            passphrase,
            &keyfile,
            opts.kdf_mem,
            opts.kdf_time,
            4,
            original_size,
            &mut reader,
            &mut writer,
        )?;
    } else if let Some(ref fido2_path) = opts.fido2 {
        let hmac_secret = derive_fido2_secret(fido2_path)?;
        encrypt::encrypt_stream_passphrase_fido2_with_params(
            passphrase,
            &hmac_secret,
            opts.kdf_mem,
            opts.kdf_time,
            4,
            original_size,
            &mut reader,
            &mut writer,
        )?;
    } else {
        encrypt::encrypt_stream_passphrase_with_params(
            passphrase,
            opts.kdf_mem,
            opts.kdf_time,
            4,
            original_size,
            &mut reader,
            &mut writer,
        )?;
    }
    writer.commit()?;
    write_fec_sidecar_if_requested(opts.fec, to_stdout, &out_path)?;
    // Passphrase mode has no recipient key pair to fingerprint at all.
    log_encrypt_event(&opts, to_stdout, &out_path, "passphrase")?;

    emit_json_ok(opts.json, to_stdout, &out_path)?;
    Ok(())
}

/// Always present regardless of the `tlock` feature so `run_encrypt` doesn't
/// need its own `#[cfg]` branch: without the feature, `tlock_round` is always
/// `None` (the CLI flag doesn't exist to set it), so this is provably
/// unreachable in that build, but still has to type-check. Mirrors
/// `derive_fido2_secret`'s pattern.
fn run_encrypt_tlock(
    #[cfg_attr(not(feature = "tlock"), allow(unused_variables))] round: u64,
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    #[cfg(feature = "tlock")]
    {
        let (original_size, to_stdout, out_path) =
            resolve_encrypt_output(input, output, opts.force)?;
        let mut raw_reader = open_reader(input)?;
        let mut reader = MaybePadded::new(&mut *raw_reader, opts.pad, original_size)?;
        let mut writer = CliOutput::new(to_stdout, &out_path)?;
        pqfile::tlock::encrypt_stream_tlock(round, None, original_size, &mut reader, &mut writer)?;
        writer.commit()?;
        write_fec_sidecar_if_requested(opts.fec, to_stdout, &out_path)?;
        // Time-locked mode has no recipient key pair to fingerprint at all.
        log_encrypt_event(&opts, to_stdout, &out_path, &format!("tlock-round-{round}"))?;

        emit_json_ok(opts.json, to_stdout, &out_path)?;
        Ok(())
    }
    #[cfg(not(feature = "tlock"))]
    {
        let _ = (input, output, opts);
        unreachable!("tlock feature disabled; --tlock-round CLI flag does not exist without it")
    }
}

fn run_encrypt_single(
    pubkey_pems: &[String],
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    if opts.resume {
        return run_encrypt_resumable(pubkey_pems, input, output, opts);
    }
    let (original_size, to_stdout, out_path) = resolve_encrypt_output(input, output, opts.force)?;

    if opts.pad {
        if opts.mmap {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --mmap",
            )));
        }
        if opts.pipeline {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --pipeline",
            )));
        }
        if opts.compress {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --compress (compression would shrink the \
                 padding back down, defeating it)",
            )));
        }
    }

    // --mmap: native only, single recipient, no compress, file input only.
    #[cfg(not(target_arch = "wasm32"))]
    if opts.mmap && pubkey_pems.len() == 1 && !opts.compress && input != "-" {
        let chunk_size = if opts.chunk_size == 0 {
            format::adaptive_chunk_size(original_size)
        } else {
            opts.chunk_size
        };
        let mut writer = CliOutput::new(to_stdout, &out_path)?;
        encrypt::encrypt_mmap(
            &pubkey_pems[0],
            std::path::Path::new(input),
            chunk_size,
            &mut writer,
        )?;
        writer.commit()?;
        write_fec_sidecar_if_requested(opts.fec, to_stdout, &out_path)?;
        log_encrypt_event(
            &opts,
            to_stdout,
            &out_path,
            &pqfile::keygen::fingerprint_pem(&pubkey_pems[0]),
        )?;
        emit_json_ok(opts.json, to_stdout, &out_path)?;
        return Ok(());
    }

    // --pipeline: use a file reader that is 'static + Send (not possible with dyn Read).
    // Only available for file inputs (not stdin) since stdin can't be moved to a thread.
    if opts.pipeline && pubkey_pems.len() == 1 && !opts.compress && input != "-" {
        let chunk_size = if opts.chunk_size == 0 {
            format::adaptive_chunk_size(original_size)
        } else {
            opts.chunk_size
        };
        let file_reader = BufReader::new(std::fs::File::open(input)?);
        let mut writer = CliOutput::new(to_stdout, &out_path)?;
        encrypt::encrypt_stream_pipelined(
            &pubkey_pems[0],
            original_size,
            chunk_size,
            file_reader,
            &mut writer,
        )?;
        writer.commit()?;
        write_fec_sidecar_if_requested(opts.fec, to_stdout, &out_path)?;
        log_encrypt_event(
            &opts,
            to_stdout,
            &out_path,
            &pqfile::keygen::fingerprint_pem(&pubkey_pems[0]),
        )?;
        emit_json_ok(opts.json, to_stdout, &out_path)?;
        return Ok(());
    }

    let mut raw_reader = open_reader(input)?;
    let mut reader = MaybePadded::new(&mut *raw_reader, opts.pad, original_size)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    perform_encrypt(pubkey_pems, original_size, &opts, &mut reader, &mut writer)?;
    writer.commit()?;
    write_fec_sidecar_if_requested(opts.fec, to_stdout, &out_path)?;
    // Multi-recipient encrypts log the first recipient's fingerprint only -
    // a documented simplification, not an attempt to represent every slot.
    log_encrypt_event(
        &opts,
        to_stdout,
        &out_path,
        &pqfile::keygen::fingerprint_pem(&pubkey_pems[0]),
    )?;

    emit_json_ok(opts.json, to_stdout, &out_path)?;
    Ok(())
}

/// `<output>.pqfck` - the resume checkpoint sidecar path for `out_path`.
fn resume_checkpoint_path(out_path: &Path) -> PathBuf {
    let mut s = out_path.as_os_str().to_owned();
    s.push(".pqfck");
    PathBuf::from(s)
}

/// Reads exactly `buf.len()` bytes or however many remain before EOF,
/// whichever is shorter - unlike a single `Read::read` call, which may
/// return fewer bytes than requested even mid-stream. `pqfile` has its own
/// private copy of this (`pqfile::io_util::fill_or_eof`, shared by
/// `fec`/`audit`) - not reused here since it isn't part of `pqfile`'s public
/// API and this crate has no other reason to depend on either feature.
fn fill_or_eof(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// `encrypt --resume`: single-recipient only, real file input/output only
/// (see docs/ROADMAP.md, "Resumable/checkpointed encryption"). If
/// `<output>.pqfck` already exists, verifies it against both the partial
/// output and the source file, then continues; otherwise starts a fresh
/// encryption and begins writing checkpoints as it goes. The checkpoint is
/// deleted on successful completion.
fn run_encrypt_resumable(
    pubkey_pems: &[String],
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    if pubkey_pems.len() != 1 {
        return Err(PqfileError::Io(io::Error::other(
            "--resume supports only one recipient",
        )));
    }
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
        let mut s = std::ffi::OsString::from(input);
        s.push(".pqf");
        PathBuf::from(s)
    } else {
        PathBuf::from(out)
    };
    let ck_path = resume_checkpoint_path(&out_path);

    let (mut writer, mut hasher, chunk_size, prefix_len) = if ck_path.exists() {
        let ck_bytes = std::fs::read(&ck_path)?;
        let checkpoint = pqfile::resume::ResumeCheckpoint::from_bytes(&ck_bytes)?;

        let header = {
            let mut header_file = std::fs::File::open(&out_path)?;
            pqfile::resume::read_stream_header_for_resume(&mut header_file)?
        };
        let chunk_size = header.chunk_size() as usize;
        let prefix_len = checkpoint.committed_chunks() as u64 * chunk_size as u64;

        // Verify the source file's already-consumed prefix still matches what
        // the checkpoint recorded, reading it once and leaving the cursor
        // positioned exactly at prefix_len for the main loop below to
        // continue from. A short read (source now shorter than the prefix)
        // is itself evidence the source changed.
        let mut src = std::fs::File::open(input)?;
        let mut hasher = blake3::Hasher::new();
        let mut remaining = prefix_len;
        let mut buf = vec![0u8; chunk_size.max(1)];
        while remaining > 0 {
            let take = remaining.min(buf.len() as u64) as usize;
            let n = fill_or_eof(&mut src, &mut buf[..take])?;
            if n < take {
                return Err(PqfileError::ResumeSourceChanged);
            }
            hasher.update(&buf[..take]);
            remaining -= take as u64;
        }
        if *hasher.finalize().as_bytes() != checkpoint.prefix_hash() {
            return Err(PqfileError::ResumeSourceChanged);
        }
        drop(src);

        let out_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&out_path)?;
        let writer = PqfWriter::resume(out_file, &header, &checkpoint)?;
        (writer, hasher, chunk_size, prefix_len)
    } else {
        ensure_overwrite_allowed(&out_path, false, opts.force)?;
        let original_size = std::fs::metadata(input).map(|m| m.len()).unwrap_or(0);
        let chunk_size = if opts.chunk_size == 0 {
            format::adaptive_chunk_size(original_size)
        } else {
            opts.chunk_size
        };
        let out_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)?;
        let writer = PqfWriter::new(out_file, &pubkey_pems[0], original_size, chunk_size)?;
        (writer, blake3::Hasher::new(), chunk_size, 0u64)
    };

    let mut src = std::fs::File::open(input)?;
    src.seek(SeekFrom::Start(prefix_len))
        .map_err(PqfileError::Io)?;

    let mut buf = vec![0u8; chunk_size];
    let mut bytes_since_checkpoint: u64 = 0;
    loop {
        let n = fill_or_eof(&mut src, &mut buf).map_err(PqfileError::Io)?;
        if n == 0 {
            break;
        }
        io::Write::write_all(&mut writer, &buf[..n]).map_err(PqfileError::Io)?;
        hasher.update(&buf[..n]);
        if n == chunk_size {
            bytes_since_checkpoint += n as u64;
            if bytes_since_checkpoint >= RESUME_CHECKPOINT_INTERVAL_BYTES {
                writer.sync_data().map_err(PqfileError::Io)?;
                let ck = writer.checkpoint(*hasher.finalize().as_bytes());
                write_private_file(&ck_path, &ck.to_bytes()).map_err(PqfileError::Io)?;
                bytes_since_checkpoint = 0;
            }
        }
    }
    writer.finish()?;
    // Best-effort: the encryption itself already succeeded: losing the
    // checkpoint at this point just means a leftover file to clean up
    // manually, not a correctness problem.
    let _ = std::fs::remove_file(&ck_path);
    write_fec_sidecar_if_requested(opts.fec, false, &out_path)?;
    log_encrypt_event(
        &opts,
        false,
        &out_path,
        &pqfile::keygen::fingerprint_pem(&pubkey_pems[0]),
    )?;

    emit_json_ok(opts.json, false, &out_path)?;
    Ok(())
}

fn perform_encrypt(
    pubkey_pems: &[String],
    original_size: u64,
    opts: &EncryptOpts,
    reader: &mut dyn io::Read,
    writer: &mut dyn io::Write,
) -> Result<(), PqfileError> {
    if pubkey_pems.len() == 1 {
        // Resolve adaptive chunk size (0 = auto) for single-recipient paths.
        let chunk_size = if opts.chunk_size == 0 {
            format::adaptive_chunk_size(original_size)
        } else {
            opts.chunk_size
        };
        if opts.compress {
            encrypt::encrypt_stream_compressed(
                &pubkey_pems[0],
                original_size,
                chunk_size,
                opts.compress_level,
                reader,
                writer,
            )
        } else if opts.parallel {
            encrypt::encrypt_stream_parallel(
                &pubkey_pems[0],
                original_size,
                chunk_size,
                PARALLEL_BATCH_SIZE,
                reader,
                writer,
            )
        } else {
            encrypt::encrypt_stream(&pubkey_pems[0], original_size, chunk_size, reader, writer)
        }
    } else {
        // Multi-recipient always uses CHUNK_SIZE internally.
        // 0 (auto) is allowed; any other explicit non-default value is rejected.
        if opts.chunk_size != 0 && opts.chunk_size != format::CHUNK_SIZE {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--chunk-size is not supported with multiple recipients",
            )));
        }
        if opts.compress {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--compress is not supported with multiple recipients",
            )));
        }
        if opts.parallel {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--parallel is not supported with multiple recipients",
            )));
        }
        let refs: Vec<&str> = pubkey_pems.iter().map(|s| s.as_str()).collect();
        if opts.pad_recipients {
            encrypt::encrypt_stream_multi_anon_padded(&refs, original_size, reader, writer)
        } else if opts.anonymous_recipients {
            encrypt::encrypt_stream_multi_anon(&refs, original_size, reader, writer)
        } else {
            encrypt::encrypt_stream_multi(&refs, original_size, reader, writer)
        }
    }
}

fn run_encrypt_recursive(
    pubkey_pem: &str,
    input: &str,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    let dir = PathBuf::from(input);
    if !dir.is_dir() {
        return Err(PqfileError::Io(std::io::Error::other(format!(
            "'{input}' is not a directory (--recursive requires a directory path)"
        ))));
    }

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(&dir, &mut files)?;

    let mut any_error = false;
    let mut json_entries: Vec<String> = Vec::new();

    for file_path in &files {
        let out_path = {
            let mut s = file_path.as_os_str().to_owned();
            s.push(".pqf");
            PathBuf::from(s)
        };
        let result = encrypt_one_file(pubkey_pem, file_path, &out_path, &opts);
        let path_str = file_path.to_string_lossy();
        let out_str = out_path.to_string_lossy();
        match result {
            Ok(()) => {
                if opts.json {
                    json_entries.push(json_object(&[
                        kv_str("file", &path_str),
                        kv_str("status", "ok"),
                        kv_str("output", &out_str),
                    ]));
                } else {
                    println!("ok: {path_str}");
                }
            }
            Err(e) => {
                any_error = true;
                if opts.json {
                    json_entries.push(json_object(&[
                        kv_str("file", &path_str),
                        kv_str("status", "error"),
                        kv_raw("code", &e.code().to_string()),
                        kv_str("message", &e.to_string()),
                    ]));
                } else {
                    eprintln!("error: {path_str}: {e}");
                }
            }
        }
    }

    if opts.json {
        println!("[{}]", json_entries.join(","));
    }

    if any_error {
        Err(PqfileError::Io(std::io::Error::other(
            "one or more files failed to encrypt",
        )))
    } else {
        Ok(())
    }
}

fn encrypt_one_file(
    pubkey_pem: &str,
    file_path: &Path,
    out_path: &Path,
    opts: &EncryptOpts,
) -> Result<(), PqfileError> {
    let size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    let chunk_size = if opts.chunk_size == 0 {
        format::adaptive_chunk_size(size)
    } else {
        opts.chunk_size
    };
    ensure_overwrite_allowed(out_path, false, opts.force)?;
    let mut reader = BufReader::new(std::fs::File::open(file_path)?);
    let mut writer = AtomicOutput::new(out_path)?;
    let result = if opts.compress {
        encrypt::encrypt_stream_compressed(
            pubkey_pem,
            size,
            chunk_size,
            opts.compress_level,
            &mut reader,
            &mut writer,
        )
    } else {
        encrypt::encrypt_stream(pubkey_pem, size, chunk_size, &mut reader, &mut writer)
    };
    result?;
    writer.commit()?;
    Ok(())
}

/// Recursively collects all non-.pqf files under `dir`, sorted for determinism.
fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), PqfileError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(&path, files)?;
        } else if ft.is_file() && path.extension().is_none_or(|e| e != "pqf") {
            files.push(path);
        }
    }
    Ok(())
}
