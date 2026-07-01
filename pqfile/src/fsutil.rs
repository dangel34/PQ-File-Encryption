//! Internal filesystem helpers shared by every code path that writes private
//! key or Shamir share material to disk.

use std::path::Path;

/// Writes `contents` to `path`, then (on Unix) restricts the file to owner
/// read/write only. Private key material and Shamir shares should always go
/// through this helper rather than `std::fs::write` directly, since a plain
/// `fs::write` creates new files at the process umask (typically world-readable).
pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    restrict_to_owner(path)
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
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
