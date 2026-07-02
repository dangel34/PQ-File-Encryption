//! Internal filesystem helpers shared by every code path that writes private
//! key or Shamir share material to disk.

use std::path::Path;

/// Writes `contents` to `path`, then restricts the file to its owner: mode
/// 0600 on Unix, an owner-only ACL on Windows. Private key material and Shamir
/// shares should always go through this helper rather than `std::fs::write`
/// directly, since a plain `fs::write` creates new files at the process umask
/// (typically world-readable) or with inherited, often permissive, ACLs.
pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    restrict_to_owner(path)
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
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

#[cfg(not(any(unix, windows)))]
fn restrict_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
}
