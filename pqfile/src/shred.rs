/// Secure file deletion: overwrite with zeros then remove.
///
/// This provides a best-effort wipe of the original plaintext after encryption.
/// The overwrite is flushed to the OS via `sync_all()`, making it effective on
/// spinning-disk and NVMe drives where the OS controls block placement.
///
/// **Limitation on SSDs and copy-on-write filesystems (APFS, Btrfs, ZFS):**
/// the OS or drive firmware may remap writes to new blocks, leaving old data
/// intact in unallocated space.  Full-disk encryption (e.g. BitLocker, FileVault)
/// is the correct defense on those platforms.  `--shred` remains useful on
/// rotational media and as a UI signal of intent.
use std::fs::{self, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

/// Overwrites `path` with zeros and then deletes it.
///
/// Returns an error if the file cannot be opened, written, synced, or deleted.
pub fn shred_file(path: &Path) -> io::Result<()> {
    let len = fs::metadata(path)?.len();

    if len > 0 {
        let mut f = OpenOptions::new().write(true).open(path)?;
        f.seek(SeekFrom::Start(0))?;

        // Write zeros in 64 KiB chunks so peak memory is bounded.
        const BUF_SIZE: usize = 65536;
        let buf = vec![0u8; BUF_SIZE];
        let mut remaining = len as usize;
        while remaining > 0 {
            let n = remaining.min(BUF_SIZE);
            f.write_all(&buf[..n])?;
            remaining -= n;
        }
        f.sync_all()?;
    }

    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn shred_removes_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"secret data").unwrap();
        // keep() prevents auto-deletion on drop so shred_file can open and delete it.
        let (_, path) = tmp.keep().unwrap();
        shred_file(&path).unwrap();
        assert!(!path.exists(), "file must be removed after shredding");
    }

    #[test]
    fn shred_empty_file_succeeds() {
        let tmp = NamedTempFile::new().unwrap();
        let (_, path) = tmp.keep().unwrap();
        shred_file(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn shred_nonexistent_file_returns_error() {
        let result = shred_file(Path::new("/nonexistent/path/to/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn shred_large_file_succeeds() {
        let mut tmp = NamedTempFile::new().unwrap();
        // Write 200 KiB (larger than one shred buffer) to exercise the chunk loop.
        tmp.write_all(&vec![0xABu8; 200 * 1024]).unwrap();
        let (_, path) = tmp.keep().unwrap();
        shred_file(&path).unwrap();
        assert!(!path.exists());
    }
}
