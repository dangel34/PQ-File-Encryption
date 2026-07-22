//! Integration tests for `encrypt --resume` / `decrypt --resume`.
//!
//! Simulating an actual process crash mid-write from an integration test
//! (kill the compiled binary at an exact byte offset) isn't practical, so
//! the "interrupted" half of each round-trip test is constructed directly
//! against the `pqfile` library - the same technique
//! `pqfile/src/resume.rs`'s own unit tests use (`PqfWriter::new` plus
//! `mem::forget` to skip `finish()`, mirroring a crash's destructors never
//! running). What's actually under test is the second half: whether the
//! *compiled CLI binary*, given that interrupted state, correctly resumes
//! and finishes it - the same thing a real crash-then-rerun would exercise.

use std::fs;
use std::io::Write as IoWrite;
use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pqfile")
}

const CHUNK: usize = 64;

/// Encrypts `plaintext` into `out_path` via `PqfWriter`, checkpointing after
/// every full chunk, but stops after `stop_after_chunks` and `mem::forget`s
/// the writer - simulating a crash, not a graceful shutdown. Writes the
/// resulting checkpoint to `<out_path>.pqfck` exactly as the CLI's own
/// `encrypt --resume` would have, so the CLI binary can pick it up.
fn write_interrupted_encrypt(
    out_path: &std::path::Path,
    pub_pem: &str,
    plaintext: &[u8],
    stop_after_chunks: usize,
) {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_path)
        .unwrap();
    let mut writer =
        pqfile::writer::PqfWriter::new(file, pub_pem, plaintext.len() as u64, CHUNK).unwrap();
    let mut hasher = blake3::Hasher::new();
    let mut checkpoint = writer.checkpoint(*hasher.finalize().as_bytes());
    for (i, chunk) in plaintext.chunks(CHUNK).enumerate() {
        if i >= stop_after_chunks || chunk.len() < CHUNK {
            break;
        }
        std::io::Write::write_all(&mut writer, chunk).unwrap();
        hasher.update(chunk);
        checkpoint = writer.checkpoint(*hasher.finalize().as_bytes());
    }
    std::mem::forget(writer);

    let mut ck_path = out_path.as_os_str().to_owned();
    ck_path.push(".pqfck");
    fs::write(ck_path, checkpoint.to_bytes().as_slice()).unwrap();
}

#[test]
fn encrypt_resume_fresh_start_completes_and_cleans_up_checkpoint() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("secret.txt");
    let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 3 + 11).collect();
    fs::write(&input, &plaintext).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");
    let out = dir.join("secret.txt.pqf");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "--resume",
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "fresh --resume encrypt failed");

    let mut ck_path = out.as_os_str().to_owned();
    ck_path.push(".pqfck");
    assert!(
        !std::path::Path::new(&ck_path).exists(),
        "checkpoint should be deleted after a successful --resume run"
    );

    let recovered = dir.join("recovered.txt");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt failed");
    assert_eq!(fs::read(&recovered).unwrap(), plaintext);
}

#[test]
fn encrypt_resume_continues_an_interrupted_run() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(768, None).unwrap();
    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");
    fs::write(&pubkey, &pub_pem).unwrap();
    fs::write(&privkey, &priv_pem).unwrap();

    let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 6 + 23).collect();
    let input = dir.join("secret.txt");
    fs::write(&input, &plaintext).unwrap();

    let out = dir.join("secret.txt.pqf");
    write_interrupted_encrypt(&out, &pub_pem, &plaintext, 3);
    assert!(out.exists(), "partial output should exist before resuming");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "--resume",
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "resuming an interrupted encrypt failed");

    let mut ck_path = out.as_os_str().to_owned();
    ck_path.push(".pqfck");
    assert!(
        !std::path::Path::new(&ck_path).exists(),
        "checkpoint should be deleted after a successful resume"
    );

    let recovered = dir.join("recovered.txt");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt of resumed file failed");
    assert_eq!(
        fs::read(&recovered).unwrap(),
        plaintext,
        "resumed file must decrypt to the exact original plaintext"
    );
}

#[test]
fn encrypt_resume_rejects_changed_source() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let (pub_pem, _priv_pem) = pqfile::keygen::keygen_bytes(768, None).unwrap();
    let pubkey = dir.join("pubkey.pem");
    fs::write(&pubkey, &pub_pem).unwrap();

    let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 5).collect();
    let input = dir.join("secret.txt");
    fs::write(&input, &plaintext).unwrap();

    let out = dir.join("secret.txt.pqf");
    write_interrupted_encrypt(&out, &pub_pem, &plaintext, 2);

    // Flip a byte inside the already-committed prefix (first two chunks).
    let mut tampered = plaintext.clone();
    tampered[5] ^= 0xFF;
    fs::write(&input, &tampered).unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "--resume",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "resume must refuse when the source file changed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("changed") || stderr.contains("resume"),
        "expected a source-changed error, got: {stderr}"
    );

    // The checkpoint and partial output must be left alone for the user to
    // inspect/retry, not silently deleted or corrupted.
    let mut ck_path = out.as_os_str().to_owned();
    ck_path.push(".pqfck");
    assert!(
        std::path::Path::new(&ck_path).exists(),
        "checkpoint should survive a rejected resume attempt"
    );
}

#[test]
fn decrypt_resume_continues_a_partial_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let plaintext: Vec<u8> = (0u8..=255).cycle().take(CHUNK * 4 + 7).collect();
    let input = dir.join("secret.txt");
    fs::write(&input, &plaintext).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");

    let pqf = dir.join("secret.pqf");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "-o",
            pqf.to_str().unwrap(),
            "--chunk-size",
            &CHUNK.to_string(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    // Simulate a decrypt interrupted after two whole chunks: write exactly
    // that much of the correct plaintext to the output path (no checkpoint
    // needed on the decrypt side - see run_decrypt_resumable's doc comment).
    let recovered = dir.join("recovered.txt");
    let mut partial = std::fs::File::create(&recovered).unwrap();
    partial.write_all(&plaintext[..CHUNK * 2]).unwrap();
    drop(partial);

    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--resume",
            pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt --resume failed");
    assert_eq!(fs::read(&recovered).unwrap(), plaintext);
}
