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
        .args(["encrypt", "-r", pubkey.to_str().unwrap(), input.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    let pqf = dir.join("secret.txt.pqf");
    assert!(pqf.exists(), ".pqf output not found");

    let privkey = dir.join("privkey.pem");
    let status = std::process::Command::new(bin)
        .args(["decrypt", "-k", privkey.to_str().unwrap(), pqf.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt failed");

    let got = fs::read(dir.join("secret.txt")).unwrap();
    assert_eq!(got, original, "decrypted bytes do not match original");
}

#[test]
fn tamper_detection() {
    use pqfile::{decrypt, encrypt, keygen};

    let original = b"tamper detection test payload";

    let (pub_pem, priv_pem) = keygen::keygen_bytes().unwrap();
    let mut pqf = encrypt::encrypt_bytes(&pub_pem, original).unwrap();

    // Flip a byte in the middle of the payload (past the 1110-byte header).
    let tamper_pos = pqf.len() / 2;
    pqf[tamper_pos] ^= 0xff;

    let result = decrypt::decrypt_bytes(&priv_pem, &pqf);
    assert!(
        result.is_err(),
        "decrypt should have rejected a tampered ciphertext"
    );
}

#[test]
fn tamper_header_detected() {
    use pqfile::{decrypt, encrypt, keygen};

    let original = b"header tamper test payload";

    let (pub_pem, priv_pem) = keygen::keygen_bytes().unwrap();
    let mut pqf = encrypt::encrypt_bytes(&pub_pem, original).unwrap();

    // Flip a byte in the header (byte 100 is inside the KEM ciphertext field).
    pqf[100] ^= 0x01;

    let result = decrypt::decrypt_bytes(&priv_pem, &pqf);
    assert!(
        result.is_err(),
        "decrypt should have rejected a tampered header"
    );
}
