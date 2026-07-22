//! Checkpointed resume support for interrupted single-recipient encryption.
//!
//! An interrupted `encrypt` of a very large file otherwise has to restart
//! from byte zero. [`ResumeCheckpoint`] is a small, serializable snapshot of
//! an in-progress [`crate::writer::PqfWriter`]'s state - the committed chunk
//! count, a BLAKE3 hash of the plaintext already consumed, and the session
//! key itself - that lets [`crate::writer::PqfWriter::resume`] pick up
//! exactly where a prior run left off.
//!
//! Scoped to single-recipient `v3`/`v5` (chunked) files only, the same
//! precedent [`crate::seek_decrypt::SeekableDecryptor`] set. Multi-recipient,
//! compressed, passphrase, stealth, and time-locked formats are out of scope
//! for this first cut - see `docs/ROADMAP.md`, "Resumable/checkpointed
//! encryption for very large files".
//!
//! **This is not a new wire format.** A resumed file is byte-identical to
//! one written in a single uninterrupted pass - same header, chunks, and
//! tags. No `format.rs` change, no version bump, no new compat vector.
//!
//! **Security note**: the checkpoint holds the raw session key in the
//! clear - there is no recipient private key available mid-encrypt to
//! protect it with, since the whole point is resuming without repeating the
//! KEM encapsulation. This is a real, if bounded, new risk: whoever can read
//! the checkpoint file can decrypt whatever has already been written, no
//! recipient private key required. Callers MUST persist [`ResumeCheckpoint`]
//! bytes to a file with owner-only permissions (mirroring how every other
//! key-material file in this crate is written) and delete it immediately on
//! successful completion. The residual exposure is bounded by "attacker
//! already has local read access to your working directory" - the same
//! threat model the unencrypted source file itself is already exposed to -
//! but it is real and should be stated to users, not glossed over.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit, Tag},
    ChaCha20Poly1305, Key,
};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{
    chunk_nonce, commitment_for_stream, make_chunk_aad, version_layout, PqfHeader, BASE_NONCE_LEN,
    NONCE_LEN, VERSION_V3, VERSION_V5,
};
use crate::secret::LockedSecret;

/// AEAD tag length in bytes (ChaCha20-Poly1305, fixed).
pub(crate) const TAG_LEN: usize = 16;

const CHECKPOINT_MAGIC: &[u8; 4] = b"PQCK";
const CHECKPOINT_VERSION: u8 = 1;
/// `MAGIC(4) | VERSION(1) | COMMITTED_CHUNKS(4 LE) | PREFIX_HASH(32) | SESSION_KEY(32)`.
const CHECKPOINT_LEN: usize = 4 + 1 + 4 + 32 + 32;

/// A serializable snapshot of an in-progress [`crate::writer::PqfWriter`]'s
/// state. See the module docs for the security handling this requires.
pub struct ResumeCheckpoint {
    session_key: LockedSecret<32>,
    committed_chunks: u32,
    prefix_hash: [u8; 32],
}

impl ResumeCheckpoint {
    pub(crate) fn new(
        session_key: &[u8; 32],
        committed_chunks: u32,
        prefix_hash: [u8; 32],
    ) -> Self {
        let mut key = LockedSecret::<32>::zeroed();
        key.as_mut().copy_from_slice(session_key);
        Self {
            session_key: key,
            committed_chunks,
            prefix_hash,
        }
    }

    /// Number of complete chunks already committed to the output file.
    #[must_use]
    pub fn committed_chunks(&self) -> u32 {
        self.committed_chunks
    }

    /// BLAKE3 hash of the plaintext prefix already consumed
    /// (`committed_chunks * chunk_size` bytes). Compare against a fresh hash
    /// of the source file's own prefix before resuming - a mismatch means the
    /// source changed since the interrupted run.
    #[must_use]
    pub fn prefix_hash(&self) -> [u8; 32] {
        self.prefix_hash
    }

    pub(crate) fn session_key_bytes(&self) -> &[u8; 32] {
        &self.session_key
    }

    /// Serializes to a fixed-layout byte buffer suitable for writing to an
    /// owner-only sidecar file. See the module docs: these bytes are as
    /// sensitive as the recipient's private key while the checkpoint exists.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(CHECKPOINT_LEN));
        out.extend_from_slice(CHECKPOINT_MAGIC);
        out.push(CHECKPOINT_VERSION);
        out.extend_from_slice(&self.committed_chunks.to_le_bytes());
        out.extend_from_slice(&self.prefix_hash);
        out.extend_from_slice(self.session_key.as_ref());
        out
    }

    /// Parses bytes written by [`ResumeCheckpoint::to_bytes`].
    ///
    /// Returns [`PqfileError::ResumeCheckpointInvalid`] on malformed input
    /// (wrong length, magic, or checkpoint version) rather than panicking -
    /// a checkpoint file is untrusted input like any other file on disk.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqfileError> {
        if bytes.len() != CHECKPOINT_LEN {
            return Err(PqfileError::ResumeCheckpointInvalid(format!(
                "expected a {CHECKPOINT_LEN}-byte checkpoint, got {}",
                bytes.len()
            )));
        }
        if bytes[..4] != *CHECKPOINT_MAGIC {
            return Err(PqfileError::ResumeCheckpointInvalid(
                "not a pqfile resume checkpoint (bad magic)".to_string(),
            ));
        }
        if bytes[4] != CHECKPOINT_VERSION {
            return Err(PqfileError::ResumeCheckpointInvalid(format!(
                "unsupported checkpoint version {}",
                bytes[4]
            )));
        }
        let committed_chunks =
            u32::from_le_bytes(bytes[5..9].try_into().expect("slice is exactly 4 bytes"));
        let prefix_hash: [u8; 32] = bytes[9..41].try_into().expect("slice is exactly 32 bytes");
        let mut session_key = LockedSecret::<32>::zeroed();
        session_key.as_mut().copy_from_slice(&bytes[41..73]);
        Ok(Self {
            session_key,
            committed_chunks,
            prefix_hash,
        })
    }
}

/// The subset of a v3/v5 `.pqf` header's fields needed to resume encryption,
/// without exposing the crate-internal [`PqfHeader`] type.
pub struct ResumeHeaderInfo {
    version: u8,
    nonce: [u8; NONCE_LEN],
    original_size: u64,
    chunk_size: u32,
    compression_algo: u8,
    header_len: u64,
}

impl ResumeHeaderInfo {
    /// Chunk size this stream was written with (16 bytes larger on disk per
    /// chunk, for the AEAD tag).
    #[must_use]
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Serialized header length in bytes; chunk data starts at this offset.
    #[must_use]
    pub fn header_len(&self) -> u64 {
        self.header_len
    }

    /// The header's `original_size` field (informational; see
    /// [`crate::seek_decrypt::SeekableDecryptor::header_original_size`] for
    /// the Padmé-padding caveat, which applies identically here).
    #[must_use]
    pub fn original_size(&self) -> u64 {
        self.original_size
    }
}

/// Reads a v3/v5 header from `r` - typically the start of an existing,
/// partially-written output file - for use with
/// [`crate::writer::PqfWriter::resume`].
///
/// Returns `UnsupportedVersion` for any other format: resume is scoped to
/// single-recipient chunked files only (see the module docs).
pub fn read_stream_header_for_resume<R: Read + ?Sized>(
    r: &mut R,
) -> Result<ResumeHeaderInfo, PqfileError> {
    let header = PqfHeader::read(r)?;
    let layout = version_layout(header.version);
    if layout != VERSION_V3 && layout != VERSION_V5 {
        return Err(PqfileError::UnsupportedVersion(header.version));
    }
    let header_len = header.header_len() as u64;
    Ok(ResumeHeaderInfo {
        version: header.version,
        nonce: header.nonce,
        original_size: header.original_size,
        chunk_size: header.chunk_size,
        compression_algo: header.compression_algo,
        header_len,
    })
}

/// Recomputes the key commitment for a resumed stream from the checkpoint's
/// session key and the partial output file's own header fields.
pub(crate) fn commitment_for_resume(
    checkpoint: &ResumeCheckpoint,
    header: &ResumeHeaderInfo,
) -> [u8; 32] {
    commitment_for_stream(
        checkpoint.session_key_bytes(),
        header.version,
        &header.nonce,
        header.original_size,
        header.chunk_size,
        header.compression_algo,
    )
}

pub(crate) fn base_nonce_for_resume(header: &ResumeHeaderInfo) -> [u8; BASE_NONCE_LEN] {
    header.nonce[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN; field type guarantees 12 bytes")
}

/// Validates a checkpoint against the partial output file it describes,
/// truncating away any torn trailing write from a mid-chunk crash.
///
/// Three checks, in order: the output file must be at least as long as the
/// checkpoint implies (otherwise data the checkpoint claims is committed
/// isn't actually on disk - a corrupt or foreign checkpoint); the last
/// committed chunk's AEAD tag must verify under the checkpoint's session key
/// (catches a stale, tampered, or bit-rotted checkpoint/output pairing
/// before any more time is spent); then the file is truncated to the exact
/// expected length, discarding anything written after the last checkpoint
/// (a torn trailing chunk from a crash mid-write, or - harmlessly - a
/// successfully-completed final chunk whose checkpoint cleanup never ran,
/// which simply gets re-produced identically once encryption resumes).
///
/// Returns the reconstructed cipher, key commitment, and base nonce, ready
/// for [`crate::writer::PqfWriter::resume`].
///
/// Takes a concrete [`File`] rather than a generic `Read + Write + Seek`
/// because truncation (discarding a torn trailing write) has no portable
/// meaning outside a real file - consistent with `--resume` being an
/// inherently file-based CLI feature, like `encrypt_mmap`'s native-only scope.
pub(crate) fn verify_and_truncate(
    output: &mut File,
    header: &ResumeHeaderInfo,
    checkpoint: &ResumeCheckpoint,
) -> Result<(ChaCha20Poly1305, [u8; 32], [u8; BASE_NONCE_LEN]), PqfileError> {
    let committed = checkpoint.committed_chunks();
    let chunk_on_disk = header.chunk_size as u64 + TAG_LEN as u64;
    let expected_len = header
        .header_len()
        .checked_add(u64::from(committed).saturating_mul(chunk_on_disk))
        .ok_or_else(|| PqfileError::ResumeCheckpointInvalid("length overflow".to_string()))?;

    let actual_len = output.seek(SeekFrom::End(0)).map_err(PqfileError::Io)?;
    if actual_len < expected_len {
        return Err(PqfileError::ResumeCheckpointInvalid(format!(
            "output file ({actual_len} bytes) is shorter than the checkpoint implies ({expected_len} bytes)"
        )));
    }

    let key_commitment = commitment_for_resume(checkpoint, header);
    let base_nonce = base_nonce_for_resume(header);
    let key: &Key = checkpoint
        .session_key_bytes()
        .as_slice()
        .try_into()
        .expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);

    if committed > 0 {
        let last_index = committed - 1;
        let offset = header.header_len() + u64::from(last_index) * chunk_on_disk;
        output
            .seek(SeekFrom::Start(offset))
            .map_err(PqfileError::Io)?;
        let mut buf = Zeroizing::new(vec![0u8; chunk_on_disk as usize]);
        output.read_exact(&mut buf).map_err(PqfileError::Io)?;

        let pt_len = header.chunk_size as usize;
        let tag: Tag<ChaCha20Poly1305> = buf[pt_len..]
            .try_into()
            .expect("chunk_on_disk - chunk_size == TAG_LEN");
        let cn = chunk_nonce(&base_nonce, last_index);
        let (aad_buf, aad_len) = make_chunk_aad(last_index, false, &key_commitment);
        cipher
            .decrypt_inout_detached(
                cn.as_slice().try_into().expect("12-byte nonce"),
                &aad_buf[..aad_len],
                (&mut buf[..pt_len]).into(),
                &tag,
            )
            .map_err(|_| {
                PqfileError::ResumeCheckpointInvalid(
                    "last committed chunk failed to authenticate under the checkpoint's session key"
                        .to_string(),
                )
            })?;
    }

    output.set_len(expected_len).map_err(PqfileError::Io)?;
    output
        .seek(SeekFrom::Start(expected_len))
        .map_err(PqfileError::Io)?;

    Ok((cipher, key_commitment, base_nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::decrypt_stream;
    use crate::keygen::keygen_bytes;
    use crate::writer::PqfWriter;
    use std::fs::OpenOptions;
    use std::io::Write as IoWrite;

    const CHUNK: usize = 64;

    fn open_rw(path: &std::path::Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap()
    }

    fn open_existing(path: &std::path::Path) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }

    #[test]
    fn checkpoint_bytes_roundtrip() {
        let session_key = [7u8; 32];
        let checkpoint = ResumeCheckpoint::new(&session_key, 3, [9u8; 32]);
        let bytes = checkpoint.to_bytes();
        let parsed = ResumeCheckpoint::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.committed_chunks(), 3);
        assert_eq!(parsed.prefix_hash(), [9u8; 32]);
        assert_eq!(parsed.session_key_bytes(), &session_key);
    }

    /// `ResumeCheckpoint`/`ResumeHeaderInfo`/`PqfWriter` deliberately do not
    /// implement `Debug` (the first two hold raw session-key material), so
    /// these helpers assert on the `Err` variant without formatting the `Ok`
    /// side, unlike a plain `.unwrap_err()`.
    fn assert_err<T>(result: Result<T, PqfileError>, check: impl Fn(&PqfileError) -> bool) {
        match result {
            Ok(_) => panic!("expected an error, got Ok"),
            Err(e) => assert!(check(&e), "unexpected error variant"),
        }
    }

    #[test]
    fn checkpoint_from_bytes_rejects_bad_length() {
        assert_err(ResumeCheckpoint::from_bytes(&[0u8; 10]), |e| {
            matches!(e, PqfileError::ResumeCheckpointInvalid(_))
        });
    }

    #[test]
    fn checkpoint_from_bytes_rejects_bad_magic() {
        let session_key = [1u8; 32];
        let mut bytes = ResumeCheckpoint::new(&session_key, 0, [0u8; 32])
            .to_bytes()
            .to_vec();
        bytes[0] = !bytes[0];
        assert_err(ResumeCheckpoint::from_bytes(&bytes), |e| {
            matches!(e, PqfileError::ResumeCheckpointInvalid(_))
        });
    }

    #[test]
    fn checkpoint_from_bytes_rejects_bad_version() {
        let session_key = [1u8; 32];
        let mut bytes = ResumeCheckpoint::new(&session_key, 0, [0u8; 32])
            .to_bytes()
            .to_vec();
        bytes[4] = 0xFF;
        assert_err(ResumeCheckpoint::from_bytes(&bytes), |e| {
            matches!(e, PqfileError::ResumeCheckpointInvalid(_))
        });
    }

    #[test]
    fn read_stream_header_for_resume_rejects_multi_recipient() {
        use crate::encrypt::encrypt_stream_multi;
        let (pub1, _) = keygen_bytes(768, None).unwrap();
        let plaintext = b"not resumable";
        let mut enc = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str()],
            plaintext.len() as u64,
            &mut &plaintext[..],
            &mut enc,
        )
        .unwrap();
        assert_err(read_stream_header_for_resume(&mut enc.as_slice()), |e| {
            matches!(e, PqfileError::UnsupportedVersion(_))
        });
    }

    /// Encrypts `plaintext` into `path` via `PqfWriter`, checkpointing after
    /// every full chunk, but stops after `stop_after_chunks` chunks and
    /// `mem::forget`s the writer instead of calling `finish` - simulating a
    /// process crash (whose destructors never run), not a graceful drop
    /// (which would trip the writer's debug-mode "forgot finish()" panic).
    /// Returns the last checkpoint taken.
    fn encrypt_partial(
        path: &std::path::Path,
        pub_pem: &str,
        plaintext: &[u8],
        stop_after_chunks: usize,
    ) -> ResumeCheckpoint {
        let file = open_rw(path);
        let mut writer = PqfWriter::new(file, pub_pem, plaintext.len() as u64, CHUNK).unwrap();
        let mut hasher = blake3::Hasher::new();
        let mut checkpoint = writer.checkpoint(*hasher.finalize().as_bytes());
        for (i, chunk) in plaintext.chunks(CHUNK).enumerate() {
            if i >= stop_after_chunks || chunk.len() < CHUNK {
                break;
            }
            writer.write_all(chunk).unwrap();
            hasher.update(chunk);
            checkpoint = writer.checkpoint(*hasher.finalize().as_bytes());
        }
        std::mem::forget(writer);
        checkpoint
    }

    /// Resumes from `checkpoint`, verifying the source prefix hash exactly as
    /// a real caller (the CLI) must, then writes the rest of `plaintext` and
    /// finishes.
    fn resume_and_finish(path: &std::path::Path, plaintext: &[u8], checkpoint: &ResumeCheckpoint) {
        let prefix_len = checkpoint.committed_chunks() as usize * CHUNK;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&plaintext[..prefix_len]);
        assert_eq!(
            *hasher.finalize().as_bytes(),
            checkpoint.prefix_hash(),
            "source prefix must match the checkpoint before resuming"
        );

        let mut header_file = open_existing(path);
        let header = read_stream_header_for_resume(&mut header_file).unwrap();
        drop(header_file);

        let file = open_existing(path);
        let mut writer = PqfWriter::resume(file, &header, checkpoint).unwrap();
        writer.write_all(&plaintext[prefix_len..]).unwrap();
        writer.finish().unwrap();
    }

    #[test]
    fn resume_roundtrip_matches_uninterrupted_plaintext() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 5 + 17).collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pqf");

        let checkpoint = encrypt_partial(&path, &pub_pem, &plaintext, 2);
        assert_eq!(checkpoint.committed_chunks(), 2);
        resume_and_finish(&path, &plaintext, &checkpoint);

        let ct = std::fs::read(&path).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn resume_roundtrip_with_zero_committed_chunks() {
        // --resume with no prior progress at all (checkpoint taken immediately
        // after PqfWriter::new, before any chunk is written) must still work.
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 3 + 5).collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pqf");

        let checkpoint = encrypt_partial(&path, &pub_pem, &plaintext, 0);
        assert_eq!(checkpoint.committed_chunks(), 0);
        resume_and_finish(&path, &plaintext, &checkpoint);

        let ct = std::fs::read(&path).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn resume_truncates_torn_trailing_write() {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 4 + 9).collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pqf");

        let checkpoint = encrypt_partial(&path, &pub_pem, &plaintext, 2);
        // Simulate a crash mid-write of the third chunk: append a handful of
        // garbage bytes past the last good checkpoint.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[0xAAu8; 10]).unwrap();
        }

        resume_and_finish(&path, &plaintext, &checkpoint);

        let ct = std::fs::read(&path).unwrap();
        let mut out = Vec::new();
        decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn resume_rejects_wrong_session_key() {
        let (pub_pem, _priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 3).collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pqf");

        let checkpoint = encrypt_partial(&path, &pub_pem, &plaintext, 2);
        let wrong = ResumeCheckpoint::new(
            &[0xFFu8; 32],
            checkpoint.committed_chunks(),
            checkpoint.prefix_hash(),
        );

        let mut header_file = open_existing(&path);
        let header = read_stream_header_for_resume(&mut header_file).unwrap();
        drop(header_file);
        let file = open_existing(&path);
        assert_err(PqfWriter::resume(file, &header, &wrong), |e| {
            matches!(e, PqfileError::ResumeCheckpointInvalid(_))
        });
    }

    #[test]
    fn resume_rejects_output_shorter_than_checkpoint_implies() {
        let (pub_pem, _priv_pem) = keygen_bytes(768, None).unwrap();
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 3).collect();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pqf");

        let real_checkpoint = encrypt_partial(&path, &pub_pem, &plaintext, 2);
        // Claim more committed chunks than actually exist on disk.
        let inflated = ResumeCheckpoint::new(
            real_checkpoint.session_key_bytes(),
            real_checkpoint.committed_chunks() + 10,
            real_checkpoint.prefix_hash(),
        );

        let mut header_file = open_existing(&path);
        let header = read_stream_header_for_resume(&mut header_file).unwrap();
        drop(header_file);
        let file = open_existing(&path);
        assert_err(PqfWriter::resume(file, &header, &inflated), |e| {
            matches!(e, PqfileError::ResumeCheckpointInvalid(_))
        });
    }
}
