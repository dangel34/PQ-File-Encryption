//! Integration tests for `encrypt --fec` / `decrypt --fec` / `check --fec`.
#![cfg(feature = "fec")]

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pqfile")
}

#[test]
fn fec_roundtrip_with_no_corruption() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"forward error correction roundtrip test payload";
    let input = dir.join("secret.txt");
    fs::write(&input, original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");
    let pqf = dir.join("secret.txt.pqf");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "--fec",
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt --fec failed");

    let fec_sidecar = dir.join("secret.txt.pqf.fec");
    assert!(fec_sidecar.exists(), ".fec sidecar not written");

    let recovered = dir.join("recovered.txt");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--fec",
            pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt --fec failed");
    assert_eq!(fs::read(&recovered).unwrap(), original);
}

#[test]
fn fec_repairs_bounded_corruption_on_decrypt() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original: Vec<u8> = (0u8..=255).cycle().take(2000).collect();
    let input = dir.join("secret.bin");
    fs::write(&input, &original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");
    let pqf = dir.join("secret.bin.pqf");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "--fec",
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt --fec failed");

    // Corrupt a handful of bytes inside the ciphertext (within the
    // correctable bound of 4 bytes per 128-byte block) - simulating bit rot,
    // not tampering: scattered across different blocks so each stays
    // individually correctable.
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pqf)
            .unwrap();
        for offset in [5u64, 140, 300] {
            f.seek(SeekFrom::Start(offset)).unwrap();
            let mut byte = [0u8; 1];
            f.read_exact(&mut byte).unwrap();
            byte[0] ^= 0xFF;
            f.seek(SeekFrom::Start(offset)).unwrap();
            f.write_all(&byte).unwrap();
        }
    }

    // Without --fec, the corrupted file must fail to decrypt.
    let recovered_fail = dir.join("should_fail.txt");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            recovered_fail.to_str().unwrap(),
            pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "decrypt without --fec should fail on corrupted ciphertext"
    );

    // With --fec, the same file must repair and decrypt correctly.
    let recovered = dir.join("recovered.bin");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--fec",
            pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt --fec should repair and succeed");
    assert_eq!(fs::read(&recovered).unwrap(), original);
}

#[test]
fn check_fec_repairs_bounded_corruption() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
    let input = dir.join("secret.bin");
    fs::write(&input, &original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");
    let pqf = dir.join("secret.bin.pqf");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "--fec",
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt --fec failed");

    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pqf)
            .unwrap();
        f.seek(SeekFrom::Start(20)).unwrap();
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        f.seek(SeekFrom::Start(20)).unwrap();
        f.write_all(&byte).unwrap();
    }

    let status = std::process::Command::new(bin())
        .args([
            "check",
            "-k",
            privkey.to_str().unwrap(),
            "--fec",
            pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "check --fec should repair and succeed");
}

#[test]
fn encrypt_fec_rejects_stdout_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"data").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let output = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "--fec",
            "-o",
            "-",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "--fec with stdout output must be rejected"
    );
}

#[test]
fn decrypt_fec_requires_sidecar_to_exist() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"no fec sidecar here").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");
    let pqf = dir.join("secret.txt.pqf");

    // Encrypt WITHOUT --fec, so no sidecar exists.
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    let recovered = dir.join("recovered.txt");
    let output = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--fec",
            pqf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "decrypt --fec must fail loudly when the sidecar is missing"
    );
}
