//! Atomic file-write helper.
//!
//! pqfile's own `encrypt_stream`/`decrypt_stream` functions are
//! output-agnostic - they take any `&mut dyn Write` and never touch the
//! filesystem themselves. A caller who chooses a plain file as that
//! destination (the CLI, or any of the language bindings that expose an
//! `encrypt_file`/`decrypt_file` convenience function) is responsible for
//! not leaving a truncated or partially-written result at that path if the
//! operation fails partway through - `encrypt_stream`/`decrypt_stream`
//! stream their output as they go, so a plain `File::create` plus direct
//! writes leaves whatever was written so far in place on error, including,
//! for decryption, an authenticated-so-far plaintext prefix of a file that
//! did not authenticate as a whole. [`AtomicFileWriter`](crate::atomic_output::AtomicFileWriter)
//! closes that gap.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Buffered writer that writes to a uniquely-named temporary file in the same
/// directory as `target`, and only atomically renames it into place once
/// [`commit`](Self::commit) is called.
///
/// If dropped without committing - because the operation writing through it
/// (e.g. [`crate::decrypt::decrypt_stream`]) returned an error - the
/// temporary file is deleted and `target` is left exactly as it was before:
/// never truncated up front, and never left holding a partial or
/// unauthenticated result.
///
/// ```no_run
/// use pqfile::atomic_output::AtomicFileWriter;
/// # let (privkey_pem, ciphertext) = (String::new(), Vec::<u8>::new());
/// let mut out = AtomicFileWriter::new("/tmp/plaintext.bin".as_ref())?;
/// pqfile::decrypt::decrypt_stream(&privkey_pem, &mut ciphertext.as_slice(), &mut out, None)?;
/// out.commit()?;
/// # Ok::<_, pqfile::error::PqfileError>(())
/// ```
pub struct AtomicFileWriter {
    writer: BufWriter<File>,
    tmp: PathBuf,
    target: PathBuf,
    committed: bool,
}

impl AtomicFileWriter {
    /// Creates a temporary file next to `target`, ready to be written through
    /// this writer's `Write` implementation and then either
    /// [`commit`](Self::commit)ted or dropped to discard.
    pub fn new(target: &Path) -> io::Result<Self> {
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|e| io::Error::other(format!("failed to generate temp filename: {e}")))?;
        let hex: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let mut tmp_name = target.file_name().unwrap_or_default().to_owned();
        tmp_name.push(format!(".{hex}.tmp"));
        let tmp = target.with_file_name(tmp_name);
        // create_new (O_EXCL): refuse to follow a pre-existing file or
        // symlink at the temp path instead of silently writing through it.
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

    /// Flushes and `fsync`s the temporary file, then atomically renames it to
    /// `target`. On Unix, also `fsync`s the parent directory afterward so the
    /// rename (a directory-entry update) is itself durable against a crash.
    ///
    /// Call this only after the writer has received a complete, successful
    /// result - any error from the operation writing through this type
    /// should instead just drop it, which discards the temporary file.
    pub fn commit(mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        std::fs::rename(&self.tmp, &self.target)?;
        #[cfg(unix)]
        {
            if let Some(parent) = self.target.parent().filter(|p| !p.as_os_str().is_empty()) {
                let dir = std::fs::File::open(parent)?;
                dir.sync_all()?;
            }
        }
        self.committed = true;
        Ok(())
    }
}

impl Write for AtomicFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl Drop for AtomicFileWriter {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_renames_temp_file_into_place() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");
        let mut w = AtomicFileWriter::new(&target).unwrap();
        w.write_all(b"hello").unwrap();
        w.commit().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    }

    #[test]
    fn drop_without_commit_leaves_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");
        std::fs::write(&target, b"original").unwrap();
        {
            let mut w = AtomicFileWriter::new(&target).unwrap();
            w.write_all(b"partial write that never completes").unwrap();
            // Dropped here without calling commit() - simulates the
            // operation writing through `w` returning an error.
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn drop_without_commit_leaves_no_temp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");
        {
            let mut w = AtomicFileWriter::new(&target).unwrap();
            w.write_all(b"partial").unwrap();
        }
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(entries.is_empty());
    }

    #[test]
    fn commit_does_not_truncate_target_before_success() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.bin");
        std::fs::write(&target, b"original, must survive until commit").unwrap();
        let mut w = AtomicFileWriter::new(&target).unwrap();
        w.write_all(b"new content").unwrap();
        // Before commit() is called, `target` must be completely unaffected.
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"original, must survive until commit"
        );
        w.commit().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new content");
    }
}
