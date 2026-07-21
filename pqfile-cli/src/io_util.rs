//! Shared I/O plumbing used across most command modules: stdin/stdout
//! handling, atomic private-file writes, output-path resolution, and the
//! `--json` "ok" status line.

use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;
use pqfile::inspect::{inspect_stream, PqfHeaderInfo};

use crate::json_util::{json_object, kv_str};

/// Batch size for `--parallel` chunk processing, shared by encrypt and decrypt.
pub(crate) const PARALLEL_BATCH_SIZE: usize = 8;

/// Returns `OutputExists` when `path` already exists and neither `--force` nor stdout
/// output was requested. Call this with the resolved destination before creating the
/// output writer so an existing file is never clobbered silently. `to_stdout` outputs
/// are always allowed (there is no file to overwrite).
pub(crate) fn ensure_overwrite_allowed(
    path: &Path,
    to_stdout: bool,
    force: bool,
) -> Result<(), PqfileError> {
    if !to_stdout && !force && path.exists() {
        return Err(PqfileError::OutputExists(path.to_path_buf()));
    }
    Ok(())
}

/// Prints the `{"status":"ok","output":...}` line emitted by every command in
/// `--json` mode. Goes to stderr when the payload itself went to stdout.
pub(crate) fn emit_json_ok(
    json: bool,
    to_stdout: bool,
    out_path: &Path,
) -> Result<(), PqfileError> {
    if !json {
        return Ok(());
    }
    let lossy = out_path.to_string_lossy();
    let out_val: &str = if to_stdout { "-" } else { &lossy };
    let target: &mut dyn io::Write = if to_stdout {
        &mut io::stderr()
    } else {
        &mut io::stdout()
    };
    writeln!(
        target,
        "{}",
        json_object(&[kv_str("status", "ok"), kv_str("output", out_val)])
    )?;
    Ok(())
}

/// Prints the final status line for a decrypt-with-verification command
/// (signdecrypt, unseal) that may write plaintext to stdout or to a file: a
/// JSON object (to stderr when the plaintext itself went to stdout, so the
/// two never interleave) or a human-readable "`<verb>` Decrypted to: `<path>`"
/// line. `status_key`/`status_val` name the extra JSON field describing what
/// was verified (e.g. `"signature"`/`"valid"`, `"authentication"`/`"valid"`).
pub(crate) fn emit_decrypt_verified_status(
    json: bool,
    to_stdout: bool,
    out_path: &Path,
    status_key: &str,
    status_val: &str,
    human_verb: &str,
) -> Result<(), PqfileError> {
    if json {
        let out_val = if to_stdout {
            "-"
        } else {
            &out_path.to_string_lossy()
        };
        let target: &mut dyn io::Write = if to_stdout {
            &mut io::stderr()
        } else {
            &mut io::stdout()
        };
        writeln!(
            target,
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", out_val),
                kv_str(status_key, status_val)
            ])
        )?;
    } else {
        println!(
            "{human_verb} Decrypted to: {}",
            if to_stdout {
                "-".to_owned()
            } else {
                out_path.to_string_lossy().into_owned()
            }
        );
    }
    Ok(())
}

/// Derives the `--fido2` second-factor secret, uniformly regardless of
/// whether this build has the `fido2` feature. `opts.fido2` /
/// `run_decrypt`'s and `run_check`'s `fido2` parameter are always `None`
/// without the feature (the CLI arg doesn't exist to set them), so the
/// `not(feature = "fido2")` arm below is provably unreachable in that build,
/// but still has to type-check.
pub(crate) fn derive_fido2_secret(
    enrollment_path: &Path,
) -> Result<zeroize::Zeroizing<[u8; 32]>, PqfileError> {
    #[cfg(feature = "fido2")]
    {
        crate::fido2::derive_secret(enrollment_path)
    }
    #[cfg(not(feature = "fido2"))]
    {
        let _ = enrollment_path;
        unreachable!("fido2 feature disabled; --fido2 CLI flag does not exist without it")
    }
}

pub(crate) fn open_reader(input: &str) -> Result<Box<dyn io::Read>, PqfileError> {
    if input == "-" {
        Ok(Box::new(io::stdin()))
    } else {
        Ok(Box::new(BufReader::new(std::fs::File::open(input)?)))
    }
}

/// Peeks a `.pqf` file's header to read its declared `original_size`, without
/// affecting the real decrypt call that follows (this opens its own,
/// independent file handle and reads only the header). Returns 0 - the
/// existing "unknown length, don't truncate" convention - for stdin input, or
/// if the header can't be read (missing file, bad magic, unsupported
/// version); the real decrypt call surfaces the accurate error in that case.
pub(crate) fn peek_original_size(input: &str) -> u64 {
    if input == "-" {
        return 0;
    }
    let Ok(file) = std::fs::File::open(input) else {
        return 0;
    };
    let mut reader = BufReader::new(file);
    match inspect_stream(&mut reader) {
        Ok(PqfHeaderInfo::Single { original_size, .. })
        | Ok(PqfHeaderInfo::Multi { original_size, .. })
        | Ok(PqfHeaderInfo::AnonMulti { original_size, .. })
        | Ok(PqfHeaderInfo::AnonMultiV8 { original_size, .. })
        | Ok(PqfHeaderInfo::Passphrase { original_size, .. }) => original_size,
        #[cfg(feature = "tlock")]
        Ok(PqfHeaderInfo::TimeLocked { original_size, .. }) => original_size,
        _ => 0,
    }
}

/// Reads a --keyfile for v10 second-factor mode. The bytes act as key material,
/// so they are zeroized on drop and an empty file is rejected up front.
pub(crate) fn read_keyfile(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, PqfileError> {
    let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
    if bytes.is_empty() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "keyfile '{}' is empty; a keyfile must contain at least one byte",
                path.display()
            ),
        )));
    }
    Ok(bytes)
}

/// Writes `contents` to `path` atomically (via [`AtomicOutput`]), restricting
/// the file to its owner - mode 0600 on Unix, an owner-only ACL on Windows -
/// *before* any secret bytes land in it, so the restriction travels with the
/// temp file through the rename and there is never a window where the target
/// holds key material at the process umask. Private key material written
/// directly by the CLI (not through the `pqfile` library's own key-writing
/// functions, which enforce the same restriction) should go through this
/// helper rather than `std::fs::write` directly.
pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut out = AtomicOutput::new(path)?;
    restrict_to_owner(&out.tmp, out.writer.get_ref())?;
    out.write_all(contents)?;
    out.commit()
}

#[cfg(unix)]
fn restrict_to_owner(_tmp: &Path, file: &std::fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn restrict_to_owner(tmp: &Path, _file: &std::fs::File) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    // Strip all inherited ACEs and leave a single ACE granting full control to
    // OWNER RIGHTS (well-known SID S-1-3-4, resolves to whoever owns the file):
    // the closest Windows equivalent of chmod 0600. icacls ships with every
    // supported Windows version; CREATE_NO_WINDOW stops a console flash.
    // Mirrors `pqfile`'s internal fsutil helper, which is not public API.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let status = std::process::Command::new("icacls")
        .arg(tmp)
        .args(["/inheritance:r", "/grant:r", "*S-1-3-4:F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "icacls exited with {status} while restricting '{}' to owner-only access",
            tmp.display()
        )))
    }
}

#[cfg(not(any(unix, windows)))]
fn restrict_to_owner(_tmp: &Path, _file: &std::fs::File) -> io::Result<()> {
    Ok(())
}

/// Buffered writer that writes to a temp file in the same directory as `target`
/// and atomically renames it to `target` when `commit()` is called.
/// If dropped without committing, the temp file is deleted.
pub(crate) struct AtomicOutput {
    writer: BufWriter<std::fs::File>,
    tmp: PathBuf,
    target: PathBuf,
    committed: bool,
}

impl AtomicOutput {
    pub(crate) fn new(target: &Path) -> io::Result<Self> {
        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut tmp_name = target.file_name().unwrap_or_default().to_owned();
        tmp_name.push(format!(".{pid}-{ts}.tmp"));
        let tmp = target.with_file_name(tmp_name);
        // create_new (O_EXCL) rather than create(): refuse to follow a pre-existing
        // file or symlink at the temp path instead of silently truncating it.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        Ok(Self {
            writer: BufWriter::new(f),
            tmp,
            target: target.to_path_buf(),
            committed: false,
        })
    }

    pub(crate) fn commit(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        std::fs::rename(&self.tmp, &self.target)?;
        // On Unix, fsync the parent directory so the rename (directory-entry update)
        // is durable. Without this a crash between rename and the next directory flush
        // can leave the target path absent on some filesystems. Windows manages
        // directory durability internally and does not support opening directories
        // as regular file descriptors for fsync, so skip it there.
        #[cfg(unix)]
        if let Some(parent) = self.target.parent() {
            let dir = std::fs::File::open(parent)?;
            dir.sync_all()?;
        }
        self.committed = true;
        Ok(())
    }
}

impl io::Write for AtomicOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Output target that is either stdout (no commit needed) or an `AtomicOutput` file.
pub(crate) enum CliOutput {
    Stdout(io::Stdout),
    File(AtomicOutput),
}

impl CliOutput {
    pub(crate) fn new(to_stdout: bool, path: &Path) -> Result<Self, PqfileError> {
        if to_stdout {
            Ok(CliOutput::Stdout(io::stdout()))
        } else {
            Ok(CliOutput::File(AtomicOutput::new(path)?))
        }
    }

    pub(crate) fn commit(&mut self) -> io::Result<()> {
        match self {
            CliOutput::Stdout(_) => Ok(()),
            CliOutput::File(ao) => ao.commit(),
        }
    }
}

impl io::Write for CliOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            CliOutput::Stdout(s) => s.write(buf),
            CliOutput::File(ao) => ao.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            CliOutput::Stdout(s) => s.flush(),
            CliOutput::File(ao) => ao.flush(),
        }
    }
}

/// Computes the output path (or a stdout sentinel) for a decrypt-shaped
/// command: `output` may be `-` (stdout), empty (defaults to `input` with
/// its extension stripped), or an explicit path; `input` may itself be `-`
/// (stdin), which also defaults to stdout when `output` is unset. Also runs
/// the overwrite check. Returns `(to_stdout, out_path)`.
pub(crate) fn resolve_decrypt_out_path(
    input: &str,
    output: Option<&str>,
    force: bool,
) -> Result<(bool, PathBuf), PqfileError> {
    let out = output.unwrap_or("");
    let to_stdout = out == "-" || (out.is_empty() && input == "-");
    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        PathBuf::from(input).with_extension("")
    } else {
        PathBuf::from(out)
    };
    ensure_overwrite_allowed(&out_path, to_stdout, force)?;
    Ok((to_stdout, out_path))
}

/// Resolves the output path for an in-place-rewrite command (rekey,
/// add-recipient): defaults to overwriting `input`, or honors an explicit
/// `-o` (including `-` for stdout). An output that resolves back to `input`
/// is always allowed to already exist - that's the whole point of the
/// in-place default; only a *different* existing path is guarded by `force`.
pub(crate) fn resolve_in_place_out_path(
    input: &str,
    output: Option<&str>,
    force: bool,
) -> Result<(bool, PathBuf), PqfileError> {
    let out = output.unwrap_or("");
    let to_stdout = out == "-" || (out.is_empty() && input == "-");
    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        PathBuf::from(input)
    } else {
        PathBuf::from(out)
    };
    if out_path.as_path() != Path::new(input) {
        ensure_overwrite_allowed(&out_path, to_stdout, force)?;
    }
    Ok((to_stdout, out_path))
}

/// Resolves the output path for an "encrypt a sibling `.pqf` file" command
/// (signcrypt, seal): defaults to `<input>.pqf` next to the input, or honors
/// an explicit `-o`. Shared by `run_signcrypt` and `run_seal`.
pub(crate) fn resolve_pqf_sibling_out_path(
    input: &Path,
    output: Option<PathBuf>,
    force: bool,
) -> Result<PathBuf, PqfileError> {
    let out_path = output.unwrap_or_else(|| {
        let mut s = input.as_os_str().to_owned();
        s.push(".pqf");
        PathBuf::from(s)
    });
    ensure_overwrite_allowed(&out_path, false, force)?;
    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── write_private_file: atomic, owner-only, replaceable ──────────────────

    #[test]
    fn write_private_file_roundtrip_and_replace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        write_private_file(&path, b"top secret").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"top secret");
        // Replacing an existing file must work (rename-over on every platform)
        // and must not leave the temp file behind.
        write_private_file(&path, b"rotated").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"rotated");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        write_private_file(&path, b"top secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn write_private_file_restricts_acl_to_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        write_private_file(&path, b"top secret").unwrap();
        // The ACL set on the temp file must survive the rename: a single
        // OWNER-RIGHTS ACE, no inherited entries. Each ACE in icacls output
        // carries a ":(...)" suffix, so counting those is locale-independent.
        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&out.stdout).to_string();
        let ace_count = listing.matches(":(").count();
        assert_eq!(ace_count, 1, "expected exactly one ACE, got: {listing}");
    }
}
