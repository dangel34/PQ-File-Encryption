use std::fs;
use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pqfile")
}

#[test]
fn roundtrip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"quantum-resistant roundtrip test payload";
    let input = dir.join("secret.txt");
    fs::write(&input, original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let status = std::process::Command::new(bin())
        .args(["encrypt", "-r", pubkey.to_str().unwrap(), input.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    let pqf = dir.join("secret.txt.pqf");
    assert!(pqf.exists(), ".pqf output not found");

    let privkey = dir.join("privkey.pem");
    let status = std::process::Command::new(bin())
        .args(["decrypt", "-k", privkey.to_str().unwrap(), pqf.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt failed");

    let got = fs::read(dir.join("secret.txt")).unwrap();
    assert_eq!(got, original, "decrypted bytes do not match original");
}

#[test]
fn roundtrip_custom_output_paths() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("plain.txt");
    fs::write(&input, b"custom output path test").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let pqf = dir.join("encrypted.pqf");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r", pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
            "-o", pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt with -o failed");
    assert!(pqf.exists(), "custom .pqf not found");

    let privkey = dir.join("privkey.pem");
    let recovered = dir.join("recovered.txt");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k", privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
            "-o", recovered.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt with -o failed");
    assert_eq!(fs::read(&recovered).unwrap(), b"custom output path test");
}

#[test]
fn keygen_refuses_overwrite_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "first keygen failed");

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success(), "second keygen should have failed without --force");
}

#[test]
fn keygen_force_overwrites_existing_keys() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "first keygen failed");

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--force"])
        .status()
        .unwrap();
    assert!(status.success(), "keygen --force failed");
}
