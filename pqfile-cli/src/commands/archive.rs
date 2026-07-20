//! `archive` and `extract`: pack multiple files into a single encrypted PQFA
//! container and unpack it again.

use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;
use pqfile::{archive, revoke};

use crate::io_util::{ensure_overwrite_allowed, open_reader, AtomicOutput};
use crate::json_util::{json_object, json_str, kv_raw, kv_str};
use crate::prompts::maybe_prompt_passphrase;

fn bad_archive_input(msg: String) -> PqfileError {
    PqfileError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

/// Recursively collects every file under `dir` for `archive --recursive`,
/// sorted for determinism. Unlike [`collect_files`] (encrypt --recursive,
/// which skips what it can't use), archiving is a fidelity operation: symlinks
/// and special files (devices, FIFOs, sockets) cannot be represented in a PQFA
/// archive, so encountering one is an error rather than a silent omission.
fn collect_archive_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), PqfileError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        // read_dir file_type does not follow symlinks, so a symlink reports
        // is_symlink() here even when its target is a file or directory.
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            return Err(bad_archive_input(format!(
                "'{}' is a symlink; archives store regular files only",
                path.display()
            )));
        } else if ft.is_dir() {
            collect_archive_files(&path, files)?;
        } else if ft.is_file() {
            files.push(path);
        } else {
            return Err(bad_archive_input(format!(
                "'{}' is not a regular file (device, FIFO, or socket)",
                path.display()
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_archive(
    recipient: PathBuf,
    output: PathBuf,
    files: Vec<PathBuf>,
    base: Option<PathBuf>,
    recursive: bool,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    ensure_overwrite_allowed(&output, false, force)?;
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    // Names an entry from its on-disk path: --base strips a leading prefix;
    // otherwise `prefix` (the walked root's directory name) or the bare
    // filename is used. Archive paths always use forward slashes.
    let entry_name = |path: &Path, prefix: Option<&Path>| -> String {
        if let Some(ref b) = base {
            path.strip_prefix(b)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
        } else if let Some(root) = prefix {
            let rel = path.strip_prefix(root).unwrap_or(path);
            match root.file_name() {
                Some(n) => {
                    format!("{}/{}", n.to_string_lossy(), rel.to_string_lossy()).replace('\\', "/")
                }
                None => rel.to_string_lossy().replace('\\', "/"),
            }
        } else {
            path.file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .to_string()
        }
    };

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    for f in &files {
        let meta = std::fs::symlink_metadata(f)?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(bad_archive_input(format!(
                "'{}' is a symlink; archives store regular files only",
                f.display()
            )));
        }
        if ft.is_dir() {
            if !recursive {
                return Err(bad_archive_input(format!(
                    "'{}' is a directory; pass --recursive to archive a directory tree",
                    f.display()
                )));
            }
            let mut walked: Vec<PathBuf> = Vec::new();
            collect_archive_files(f, &mut walked)?;
            for path in walked {
                let name = entry_name(&path, Some(f));
                entries.push((name, path));
            }
        } else if ft.is_file() {
            entries.push((entry_name(f, None), f.clone()));
        } else {
            return Err(bad_archive_input(format!(
                "'{}' is not a regular file (device, FIFO, or socket)",
                f.display()
            )));
        }
    }

    if entries.is_empty() {
        return Err(bad_archive_input(
            "no files found to archive (directory tree is empty)".to_string(),
        ));
    }

    // Reject duplicate entry names, including case-insensitive collisions:
    // extraction on a case-insensitive filesystem (Windows, macOS default)
    // would silently overwrite one entry with the other.
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, _) in &entries {
        if let Some(prev) = seen.insert(name.to_lowercase(), name.clone()) {
            return Err(bad_archive_input(if prev == *name {
                format!("duplicate archive entry name '{name}'")
            } else {
                format!(
                    "archive entry names '{prev}' and '{name}' collide on \
                     case-insensitive filesystems"
                )
            }));
        }
    }

    let mut writer = AtomicOutput::new(&output)?;
    archive::create(&pubkey_pem, &entries, &mut writer)?;
    writer.commit()?;

    if json {
        let names: Vec<String> = entries.iter().map(|(n, _)| json_str(n)).collect();
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
                kv_raw("entry_count", &entries.len().to_string()),
                format!("\"entries\":[{}]", names.join(",")),
            ])
        );
    } else {
        println!("Archive written to {}", output.display());
        for (name, _) in &entries {
            println!("  + {name}");
        }
    }
    Ok(())
}

pub(crate) fn run_extract(
    input: String,
    key: PathBuf,
    out: PathBuf,
    list_only: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let reader = open_reader(&input)?;

    if list_only {
        let manifest = archive::list(&privkey_pem, reader, pp_str)?;
        if json {
            let entries: Vec<String> = manifest
                .iter()
                .map(|e| {
                    json_object(&[
                        kv_str("path", &e.path),
                        kv_raw("size", &e.file_size.to_string()),
                    ])
                })
                .collect();
            println!(
                "{}",
                json_object(&[
                    kv_str("status", "ok"),
                    format!("\"entries\":[{}]", entries.join(",")),
                ])
            );
        } else {
            for e in &manifest {
                println!("{:>12}  {}", e.file_size, e.path);
            }
        }
        return Ok(());
    }

    std::fs::create_dir_all(&out)?;
    let paths = archive::extract(&privkey_pem, reader, &out, pp_str)?;

    if json {
        let path_strs: Vec<String> = paths
            .iter()
            .map(|p| json_str(&p.to_string_lossy()))
            .collect();
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_raw("extracted", &paths.len().to_string()),
                format!("\"files\":[{}]", path_strs.join(",")),
            ])
        );
    } else {
        for p in &paths {
            println!("  extracted: {}", p.display());
        }
    }
    Ok(())
}
