//! Internal filesystem helpers shared by every code path that writes private
//! key or Shamir share material to disk.

use std::path::{Path, PathBuf};

/// Writes `contents` to `path` atomically: a uniquely-named temporary file is
/// created *already restricted* to its owner (mode 0600 on Unix; an
/// owner-only ACL on Windows, applied before any secret byte is written),
/// filled, flushed, and `fsync`ed, then renamed into place. Private key
/// material and Shamir shares should always go through this helper rather
/// than `std::fs::write` directly.
///
/// This closes two gaps a plain "write, then chmod" sequence leaves open:
/// - **No permissive window.** The temporary file is created with its final
///   restricted permissions in the same syscall that creates it (Unix), or
///   has them applied while still empty (Windows) - contents are never
///   written to a file another local principal could read.
/// - **No stale-descriptor exposure on overwrite.** Replacing an existing
///   `path` is a `rename`, not an in-place write: a file descriptor another
///   process opened against the old `path` before the rename keeps pointing
///   at the old (now-unlinked) inode and its old contents, never observing
///   the new secret.
pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let tmp_path = sibling_temp_path(path)?;
    let write_result = (|| -> std::io::Result<()> {
        let mut f = create_restricted(&tmp_path)?;
        f.write_all(contents)?;
        f.sync_all()
    })();

    match write_result {
        Ok(()) => {
            std::fs::rename(&tmp_path, path)?;
            fsync_parent_dir(path);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Picks a randomly-named sibling of `path` (same directory, so the later
/// `rename` is always same-filesystem and therefore atomic) that does not
/// already exist. 16 bytes of CSPRNG output makes a collision with a
/// concurrent writer's temp file astronomically unlikely without needing a
/// retry loop.
fn sibling_temp_path(path: &Path) -> std::io::Result<PathBuf> {
    let mut suffix = [0u8; 16];
    getrandom::fill(&mut suffix)
        .map_err(|e| std::io::Error::other(format!("failed to generate temp filename: {e}")))?;
    let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!(".{hex}.tmp"));
    Ok(path.with_file_name(name))
}

#[cfg(unix)]
fn fsync_parent_dir(path: &Path) {
    // Best-effort: without this, a rename can still be reordered before the
    // parent directory entry itself is durable after a crash. Failure here
    // (e.g. a filesystem that doesn't support directory fsync) is not a
    // reason to fail the write - the file itself was already fsync'd above.
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) {}

/// Creates `path` for writing with its final owner-only permissions already
/// in place - never a plain-permissions file that gets restricted afterward.
#[cfg(unix)]
fn create_restricted(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(windows)]
fn create_restricted(path: &Path) -> std::io::Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // The file is empty at this point, so there is nothing sensitive for a
    // permissive ACL to expose in the brief window before this call returns.
    restrict_to_owner(path)?;
    Ok(f)
}

#[cfg(not(any(unix, windows)))]
fn create_restricted(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(windows)]
fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;
    // Strip all inherited ACEs and leave a single ACE granting full control to
    // OWNER RIGHTS (well-known SID S-1-3-4, resolves to whoever owns the file):
    // the closest Windows equivalent of chmod 0600. icacls ships with every
    // supported Windows version. CREATE_NO_WINDOW stops a console window from
    // flashing when this runs from the desktop GUI.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", "*S-1-3-4:F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "icacls exited with {status} while restricting '{}' to owner-only access",
            path.display()
        )))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_private_file_sets_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        write_private_file(&path, b"top secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn write_private_file_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        write_private_file(&path, b"top secret").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("secret.pem")]);
    }

    #[test]
    fn forced_overwrite_does_not_publish_secret_through_old_inode() {
        use std::io::{Read, Seek, SeekFrom};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");

        std::fs::write(&path, b"old placeholder").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Models another local principal having opened the permissive inode
        // before rotation - a descriptor an in-place write would let observe
        // the replacement contents through, but a rename cannot.
        let mut observer = std::fs::File::open(&path).unwrap();

        write_private_file(&path, b"replacement secret content").unwrap();

        observer.seek(SeekFrom::Start(0)).unwrap();
        let mut observed = String::new();
        observer.read_to_string(&mut observed).unwrap();
        assert_eq!(observed, "old placeholder");

        // The new file, reached by path, is both correct and now restricted.
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement secret content");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn write_private_file_restricts_acl_to_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        write_private_file(&path, b"top secret").unwrap();

        // The owner must still be able to read and replace the file.
        assert_eq!(std::fs::read(&path).unwrap(), b"top secret");
        write_private_file(&path, b"rotated").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"rotated");

        // The ACL must be reduced to a single ACE (OWNER RIGHTS); inherited
        // entries (Users/Authenticated Users groups) must be gone. Each ACE in
        // icacls output carries a ":(...)" permission suffix, so counting those
        // is locale-independent.
        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&out.stdout).to_string();
        let ace_count = listing.matches(":(").count();
        assert_eq!(ace_count, 1, "expected exactly one ACE, got: {listing}");
    }

    #[test]
    fn write_private_file_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.pem");
        write_private_file(&path, b"top secret").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("secret.pem")]);
    }
}
