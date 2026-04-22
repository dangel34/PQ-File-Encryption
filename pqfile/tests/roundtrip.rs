use std::fs;
use tempfile::TempDir;

#[test]
fn roundtrip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"quantum-resistant roundtrip test payload";
    let input = dir.join("secret.txt");
    fs::write(&input, original).unwrap();

    let bin = env!("CARGO_BIN_EXE_pqfile");

    let status = std::process::Command::new(bin)
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let status = std::process::Command::new(bin)
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    let pqf = dir.join("secret.txt.pqf");
    assert!(pqf.exists(), ".pqf output not found");

    let privkey = dir.join("privkey.pem");
    let status = std::process::Command::new(bin)
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt failed");

    let decrypted = dir.join("secret.txt");
    let got = fs::read(&decrypted).unwrap();
    assert_eq!(got, original, "decrypted bytes do not match original");
}
