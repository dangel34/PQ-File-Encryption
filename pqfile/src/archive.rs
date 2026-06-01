use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use crate::encrypt;
use crate::error::PqfileError;
use crate::format::CHUNK_SIZE;
use crate::reader::PqfReader;

// Inner plaintext payload magic + version.
const PQFA_MAGIC: &[u8; 4] = b"PQFA";
const PQFA_VERSION: u8 = 1;

// Entry manifest header per file:
//   path_len: u16 LE
//   path:     [u8; path_len]  (UTF-8)
//   size:     u64 LE
//   mtime:    i64 LE          (Unix seconds, 0 if unavailable)
//   mode:     u32 LE          (Unix permissions, 0 on Windows)

/// Metadata for a single file in the archive.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    /// Relative path stored in the archive.
    pub path: String,
    /// Uncompressed size of the file in bytes.
    pub file_size: u64,
    /// Last-modification time as Unix seconds; 0 if unavailable.
    pub mtime_secs: i64,
    /// Unix permission bits; 0 on Windows.
    pub mode: u32,
}

/// Create an encrypted archive from a list of `(path_in_archive, source_path)` pairs.
///
/// Writes a standard `.pqf` stream to `writer` whose plaintext payload begins with
/// a `PQFA` header and manifest, followed by concatenated file contents.
#[must_use = "archive creation result must be checked for errors"]
pub fn create(
    pubkey_pem: &str,
    entries: &[(String, PathBuf)],
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    // Collect metadata
    let mut manifest: Vec<ArchiveEntry> = Vec::with_capacity(entries.len());
    let mut total_size: u64 = 0;

    for (archive_path, src) in entries {
        let meta = std::fs::metadata(src)?;
        let file_size = meta.len();
        let mtime_secs = mtime_unix(&meta);
        let mode = unix_mode(&meta);
        let path_bytes = archive_path.as_bytes();
        if path_bytes.len() > u16::MAX as usize {
            return Err(bad_arg("archive entry path too long (> 65535 bytes)"));
        }
        manifest.push(ArchiveEntry {
            path: archive_path.clone(),
            file_size,
            mtime_secs,
            mode,
        });
        total_size += file_size;
    }

    // Serialize the manifest header
    let header_bytes = serialize_manifest(&manifest)?;
    let combined_size = header_bytes.len() as u64 + total_size;

    // Build a chain: header bytes → file 1 → file 2 → …
    let header_reader = Cursor::new(header_bytes);
    let mut chain: Box<dyn Read> = Box::new(header_reader);
    for (_, src) in entries {
        let f = std::fs::File::open(src)?;
        chain = Box::new(chain.chain(io::BufReader::new(f)));
    }

    encrypt::encrypt_stream(pubkey_pem, combined_size, CHUNK_SIZE, &mut chain, writer)
}

/// Extract a `.pqf` archive into `out_dir`, creating subdirectories as needed.
///
/// Authentication of each chunk happens before any bytes are written to disk.
#[must_use = "extracted file paths must be used"]
pub fn extract<R: Read>(
    privkey_pem: &str,
    reader: R,
    out_dir: &Path,
    passphrase: Option<&str>,
) -> Result<Vec<PathBuf>, PqfileError> {
    let mut pqf = PqfReader::new(reader, privkey_pem, passphrase)?;

    // Read and verify PQFA header
    let manifest = read_manifest(&mut pqf)?;

    // Extract each entry
    let mut written = Vec::with_capacity(manifest.len());
    let mut buf = vec![0u8; CHUNK_SIZE];

    for entry in &manifest {
        let dest = safe_dest(out_dir, &entry.path)?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out_file = std::fs::File::create(&dest)?;
        let mut remaining = entry.file_size;
        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = pqf.read(&mut buf[..to_read]).map_err(PqfileError::Io)?;
            if n == 0 {
                return Err(PqfileError::DecryptionFailure);
            }
            out_file.write_all(&buf[..n]).map_err(PqfileError::Io)?;
            remaining -= n as u64;
        }
        written.push(dest);
    }

    Ok(written)
}

/// List the archive manifest without decrypting file contents.
#[must_use = "archive manifest must be used"]
pub fn list<R: Read>(
    privkey_pem: &str,
    reader: R,
    passphrase: Option<&str>,
) -> Result<Vec<ArchiveEntry>, PqfileError> {
    let mut pqf = PqfReader::new(reader, privkey_pem, passphrase)?;
    read_manifest(&mut pqf)
}

/// Decrypt an archive and return all file contents in memory as `(path, data)` pairs.
///
/// Equivalent to [`extract`] but writes into `Vec<u8>` buffers rather than to disk.
/// Useful when no filesystem is available (e.g., WASM builds).
#[must_use = "extracted data must be used"]
pub fn extract_to_memory<R: Read>(
    privkey_pem: &str,
    reader: R,
    passphrase: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>, PqfileError> {
    let mut pqf = PqfReader::new(reader, privkey_pem, passphrase)?;
    let manifest = read_manifest(&mut pqf)?;
    let mut result = Vec::with_capacity(manifest.len());
    let mut buf = vec![0u8; CHUNK_SIZE];
    // Cap pre-allocation hint to 64 MiB per entry so a crafted (but AEAD-valid)
    // archive cannot force an OOM via a large file_size field before any bytes arrive.
    const MAX_PREALLOC: u64 = 64 * 1024 * 1024;
    for entry in &manifest {
        let mut data = Vec::with_capacity(entry.file_size.min(MAX_PREALLOC) as usize);
        let mut remaining = entry.file_size;
        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = pqf.read(&mut buf[..to_read]).map_err(PqfileError::Io)?;
            if n == 0 {
                return Err(PqfileError::DecryptionFailure);
            }
            data.extend_from_slice(&buf[..n]);
            remaining -= n as u64;
        }
        result.push((entry.path.clone(), data));
    }
    Ok(result)
}

/// Create an archive from in-memory file data as `(path_in_archive, data)` pairs.
///
/// Unlike [`create`], this variant does not require files to exist on disk and
/// works on all platforms including WASM.
#[must_use = "archive creation result must be checked for errors"]
pub fn create_from_memory(
    pubkey_pem: &str,
    entries: &[(String, Vec<u8>)],
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let manifest: Vec<ArchiveEntry> = entries
        .iter()
        .map(|(path, data)| ArchiveEntry {
            path: path.clone(),
            file_size: data.len() as u64,
            mtime_secs: 0,
            mode: 0,
        })
        .collect();

    let header_bytes = serialize_manifest(&manifest)?;
    let total_size =
        header_bytes.len() as u64 + entries.iter().map(|(_, d)| d.len() as u64).sum::<u64>();

    let mut chain: Box<dyn Read> = Box::new(Cursor::new(header_bytes));
    for (_, data) in entries {
        chain = Box::new(chain.chain(Cursor::new(data.clone())));
    }

    crate::encrypt::encrypt_stream(pubkey_pem, total_size, CHUNK_SIZE, &mut chain, writer)
}

// ── Manifest serialization ────────────────────────────────────────────────────

fn serialize_manifest(entries: &[ArchiveEntry]) -> Result<Vec<u8>, PqfileError> {
    let mut out = Vec::new();
    out.extend_from_slice(PQFA_MAGIC);
    out.push(PQFA_VERSION);
    let count = entries.len() as u32;
    out.extend_from_slice(&count.to_le_bytes());
    for e in entries {
        let path_bytes = e.path.as_bytes();
        out.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(path_bytes);
        out.extend_from_slice(&e.file_size.to_le_bytes());
        out.extend_from_slice(&e.mtime_secs.to_le_bytes());
        out.extend_from_slice(&e.mode.to_le_bytes());
    }
    Ok(out)
}

fn read_manifest<R: Read>(reader: &mut R) -> Result<Vec<ArchiveEntry>, PqfileError> {
    // Magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).map_err(io_err)?;
    if &magic != PQFA_MAGIC {
        return Err(PqfileError::InvalidPem(
            "not a pqfile archive (missing PQFA magic)".into(),
        ));
    }
    // Version
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver).map_err(io_err)?;
    if ver[0] != PQFA_VERSION {
        return Err(PqfileError::UnsupportedVersion(ver[0]));
    }
    // Entry count
    let mut count_bytes = [0u8; 4];
    reader.read_exact(&mut count_bytes).map_err(io_err)?;
    let count = u32::from_le_bytes(count_bytes) as usize;
    const MAX_ARCHIVE_ENTRIES: usize = 65536;
    if count > MAX_ARCHIVE_ENTRIES {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("archive entry count {count} exceeds maximum ({MAX_ARCHIVE_ENTRIES})"),
        )));
    }

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let mut pl = [0u8; 2];
        reader.read_exact(&mut pl).map_err(io_err)?;
        let path_len = u16::from_le_bytes(pl) as usize;
        let mut path_bytes = vec![0u8; path_len];
        reader.read_exact(&mut path_bytes).map_err(io_err)?;
        let path = String::from_utf8(path_bytes)
            .map_err(|_| PqfileError::InvalidPem("archive path is not valid UTF-8".into()))?;

        let mut size_bytes = [0u8; 8];
        reader.read_exact(&mut size_bytes).map_err(io_err)?;
        let file_size = u64::from_le_bytes(size_bytes);

        let mut mtime_bytes = [0u8; 8];
        reader.read_exact(&mut mtime_bytes).map_err(io_err)?;
        let mtime_secs = i64::from_le_bytes(mtime_bytes);

        let mut mode_bytes = [0u8; 4];
        reader.read_exact(&mut mode_bytes).map_err(io_err)?;
        let mode = u32::from_le_bytes(mode_bytes);

        entries.push(ArchiveEntry {
            path,
            file_size,
            mtime_secs,
            mode,
        });
    }
    Ok(entries)
}

// ── Path safety ───────────────────────────────────────────────────────────────

/// Resolve `archive_path` inside `base`, rejecting path traversal attempts.
fn safe_dest(base: &Path, archive_path: &str) -> Result<PathBuf, PqfileError> {
    // Strip leading slashes and reject ".." components
    let mut dest = base.to_path_buf();
    for component in Path::new(archive_path).components() {
        match component {
            std::path::Component::Normal(c) => dest.push(c),
            std::path::Component::CurDir => {}
            _ => {
                return Err(bad_arg(&format!(
                    "archive entry '{archive_path}' contains unsafe path component"
                )))
            }
        }
    }
    Ok(dest)
}

// ── Platform helpers ──────────────────────────────────────────────────────────

#[cfg(unix)]
fn mtime_unix(meta: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    meta.mtime()
}

#[cfg(not(unix))]
fn mtime_unix(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode()
}

#[cfg(not(unix))]
fn unix_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

fn bad_arg(msg: &str) -> PqfileError {
    PqfileError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

fn io_err(e: io::Error) -> PqfileError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        PqfileError::DecryptionFailure
    } else {
        PqfileError::Io(e)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;
    use tempfile::tempdir;

    fn make_entries(dir: &Path, files: &[(&str, &[u8])]) -> Vec<(String, PathBuf)> {
        files
            .iter()
            .map(|(name, data)| {
                let p = dir.join(name);
                std::fs::write(&p, data).unwrap();
                (name.to_string(), p)
            })
            .collect()
    }

    #[test]
    fn archive_roundtrip_single_file() {
        let tmp = tempdir().unwrap();
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let entries = make_entries(tmp.path(), &[("hello.txt", b"hello world")]);

        let mut archive_bytes = Vec::new();
        create(&pub_pem, &entries, &mut archive_bytes).unwrap();

        let out_dir = tempdir().unwrap();
        let paths = extract(&priv_pem, archive_bytes.as_slice(), out_dir.path(), None).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"hello world");
    }

    #[test]
    fn archive_roundtrip_multiple_files() {
        let tmp = tempdir().unwrap();
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let files: Vec<(&str, &[u8])> = vec![
            ("a.txt", b"file a content"),
            ("b.bin", &[0xDE, 0xAD, 0xBE, 0xEF]),
            ("c.txt", b"another file"),
        ];
        let entries = make_entries(tmp.path(), &files);

        let mut archive_bytes = Vec::new();
        create(&pub_pem, &entries, &mut archive_bytes).unwrap();

        let out_dir = tempdir().unwrap();
        let paths = extract(&priv_pem, archive_bytes.as_slice(), out_dir.path(), None).unwrap();
        assert_eq!(paths.len(), 3);
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"file a content");
        assert_eq!(std::fs::read(&paths[1]).unwrap(), &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(std::fs::read(&paths[2]).unwrap(), b"another file");
    }

    #[test]
    fn archive_empty_file() {
        let tmp = tempdir().unwrap();
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let entries = make_entries(tmp.path(), &[("empty.dat", b"")]);

        let mut archive_bytes = Vec::new();
        create(&pub_pem, &entries, &mut archive_bytes).unwrap();

        let out_dir = tempdir().unwrap();
        let paths = extract(&priv_pem, archive_bytes.as_slice(), out_dir.path(), None).unwrap();
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"");
    }

    #[test]
    fn archive_list_without_extracting() {
        let tmp = tempdir().unwrap();
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let entries = make_entries(tmp.path(), &[("foo.txt", b"foo"), ("bar.txt", b"bar")]);

        let mut archive_bytes = Vec::new();
        create(&pub_pem, &entries, &mut archive_bytes).unwrap();

        let manifest = list(&priv_pem, archive_bytes.as_slice(), None).unwrap();
        assert_eq!(manifest.len(), 2);
        assert_eq!(manifest[0].path, "foo.txt");
        assert_eq!(manifest[0].file_size, 3);
        assert_eq!(manifest[1].path, "bar.txt");
    }

    #[test]
    fn archive_subdirectory_entries() {
        let tmp = tempdir().unwrap();
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        std::fs::create_dir(tmp.path().join("sub")).unwrap();
        let src = tmp.path().join("sub").join("nested.txt");
        std::fs::write(&src, b"nested content").unwrap();
        let entries = vec![("sub/nested.txt".to_string(), src)];

        let mut archive_bytes = Vec::new();
        create(&pub_pem, &entries, &mut archive_bytes).unwrap();

        let out_dir = tempdir().unwrap();
        let paths = extract(&priv_pem, archive_bytes.as_slice(), out_dir.path(), None).unwrap();
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"nested content");
        assert!(paths[0].ends_with("sub/nested.txt") || paths[0].ends_with("sub\\nested.txt"));
    }

    #[test]
    fn archive_path_traversal_rejected() {
        let tmp = tempdir().unwrap();
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let src = tmp.path().join("evil.txt");
        std::fs::write(&src, b"evil").unwrap();
        let entries = vec![("../outside.txt".to_string(), src)];

        let mut archive_bytes = Vec::new();
        create(&pub_pem, &entries, &mut archive_bytes).unwrap();

        let out_dir = tempdir().unwrap();
        let result = extract(&priv_pem, archive_bytes.as_slice(), out_dir.path(), None);
        assert!(result.is_err(), "path traversal should be rejected");
    }

    #[test]
    fn archive_large_file_multi_chunk() {
        let tmp = tempdir().unwrap();
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let big: Vec<u8> = (0u8..=255).cycle().take(CHUNK_SIZE * 3 + 7).collect();
        let entries = make_entries(tmp.path(), &[("big.bin", &big)]);

        let mut archive_bytes = Vec::new();
        create(&pub_pem, &entries, &mut archive_bytes).unwrap();

        let out_dir = tempdir().unwrap();
        let paths = extract(&priv_pem, archive_bytes.as_slice(), out_dir.path(), None).unwrap();
        assert_eq!(std::fs::read(&paths[0]).unwrap(), big);
    }
}
