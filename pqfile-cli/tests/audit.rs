//! Integration tests for `--audit-log` / `audit-verify`.
#![cfg(feature = "audit")]

use std::fs;
use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pqfile")
}

struct Keys {
    dir: TempDir,
    pubkey: std::path::PathBuf,
    privkey: std::path::PathBuf,
    sign_pubkey: std::path::PathBuf,
    sign_privkey: std::path::PathBuf,
}

fn setup_keys() -> Keys {
    let dir = TempDir::new().unwrap();
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");
    let status = std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "sign-keygen failed");

    let pubkey = dir.path().join("pubkey.pem");
    let privkey = dir.path().join("privkey.pem");
    let sign_pubkey = dir.path().join("sign_pubkey.pem");
    let sign_privkey = dir.path().join("sign_privkey.pem");
    Keys {
        dir,
        pubkey,
        privkey,
        sign_pubkey,
        sign_privkey,
    }
}

#[test]
fn encrypt_writes_audit_log_and_verify_succeeds() {
    let keys = setup_keys();
    let dir = keys.dir.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"audited payload").unwrap();
    let audit_log = dir.join("audit.log");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            keys.pubkey.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--audit-key",
            keys.sign_privkey.to_str().unwrap(),
            "--audit-recipient",
            keys.pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt --audit-log failed");
    assert!(audit_log.exists(), "audit log was not written");
    assert!(
        dir.join("audit.log.chainhash").exists(),
        "chain-tip sidecar was not written"
    );

    let status = std::process::Command::new(bin())
        .args([
            "audit-verify",
            "--auditor-key",
            keys.privkey.to_str().unwrap(),
            "--operator-key",
            keys.sign_pubkey.to_str().unwrap(),
            audit_log.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "audit-verify should succeed on an intact log"
    );
}

#[test]
fn encrypt_then_decrypt_chain_both_verify() {
    let keys = setup_keys();
    let dir = keys.dir.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"chained events").unwrap();
    let audit_log = dir.join("audit.log");

    let audit_args = [
        "--audit-log".to_string(),
        audit_log.to_str().unwrap().to_string(),
        "--audit-key".to_string(),
        keys.sign_privkey.to_str().unwrap().to_string(),
        "--audit-recipient".to_string(),
        keys.pubkey.to_str().unwrap().to_string(),
    ];

    let mut encrypt_args = vec![
        "encrypt".to_string(),
        "-r".to_string(),
        keys.pubkey.to_str().unwrap().to_string(),
    ];
    encrypt_args.extend(audit_args.iter().cloned());
    encrypt_args.push(input.to_str().unwrap().to_string());
    let status = std::process::Command::new(bin())
        .args(&encrypt_args)
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    let pqf = dir.join("secret.txt.pqf");
    let recovered = dir.join("recovered.txt");
    let mut decrypt_args = vec![
        "decrypt".to_string(),
        "-k".to_string(),
        keys.privkey.to_str().unwrap().to_string(),
        "-o".to_string(),
        recovered.to_str().unwrap().to_string(),
    ];
    decrypt_args.extend(audit_args.iter().cloned());
    decrypt_args.push(pqf.to_str().unwrap().to_string());
    let status = std::process::Command::new(bin())
        .args(&decrypt_args)
        .status()
        .unwrap();
    assert!(status.success(), "decrypt failed");
    assert_eq!(fs::read(&recovered).unwrap(), b"chained events");

    let output = std::process::Command::new(bin())
        .args([
            "audit-verify",
            "--auditor-key",
            keys.privkey.to_str().unwrap(),
            "--operator-key",
            keys.sign_pubkey.to_str().unwrap(),
            audit_log.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "audit-verify should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2 records"),
        "expected 2 records, got: {stdout}"
    );
    assert!(stdout.contains("encrypt"));
    assert!(stdout.contains("decrypt"));
}

#[test]
fn audit_verify_detects_truncated_log() {
    let keys = setup_keys();
    let dir = keys.dir.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"payload").unwrap();
    let audit_log = dir.join("audit.log");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            keys.pubkey.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--audit-key",
            keys.sign_privkey.to_str().unwrap(),
            "--audit-recipient",
            keys.pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    // Corrupt the log after the fact - truncate it mid-entry.
    let mut bytes = fs::read(&audit_log).unwrap();
    bytes.truncate(bytes.len() / 2);
    fs::write(&audit_log, &bytes).unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "audit-verify",
            "--auditor-key",
            keys.privkey.to_str().unwrap(),
            "--operator-key",
            keys.sign_pubkey.to_str().unwrap(),
            audit_log.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "audit-verify must reject a truncated/corrupted log"
    );
}

#[test]
fn audit_verify_detects_wrong_operator_key() {
    let keys = setup_keys();
    let dir = keys.dir.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"payload").unwrap();
    let audit_log = dir.join("audit.log");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            keys.pubkey.to_str().unwrap(),
            "--audit-log",
            audit_log.to_str().unwrap(),
            "--audit-key",
            keys.sign_privkey.to_str().unwrap(),
            "--audit-recipient",
            keys.pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    // A different signer's verifying key must not validate this log.
    let other_dir = TempDir::new().unwrap();
    let status = std::process::Command::new(bin())
        .args(["sign-keygen", "--out", other_dir.path().to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let other_vk = other_dir.path().join("sign_pubkey.pem");

    let output = std::process::Command::new(bin())
        .args([
            "audit-verify",
            "--auditor-key",
            keys.privkey.to_str().unwrap(),
            "--operator-key",
            other_vk.to_str().unwrap(),
            audit_log.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "audit-verify must reject the wrong operator verifying key"
    );
}

#[test]
fn audit_verify_expect_tip_catches_trailing_deletion() {
    let keys = setup_keys();
    let dir = keys.dir.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"payload").unwrap();
    let audit_log = dir.join("audit.log");

    let encrypt_once = || {
        let status = std::process::Command::new(bin())
            .args([
                "encrypt",
                "-r",
                keys.pubkey.to_str().unwrap(),
                "--audit-log",
                audit_log.to_str().unwrap(),
                "--audit-key",
                keys.sign_privkey.to_str().unwrap(),
                "--audit-recipient",
                keys.pubkey.to_str().unwrap(),
                "-o",
                dir.join("out.pqf").to_str().unwrap(),
                "--force",
                input.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "encrypt failed");
    };

    // First entry only - remember exactly how many bytes that is on disk.
    encrypt_once();
    let len_after_first_entry = fs::metadata(&audit_log).unwrap().len();

    // Second entry appended - this is the one a malicious/careless deletion
    // will later strip back off, and its tip is what --expect-tip should
    // have caught the deletion against.
    encrypt_once();
    let verify_two = std::process::Command::new(bin())
        .args([
            "audit-verify",
            "--auditor-key",
            keys.privkey.to_str().unwrap(),
            "--operator-key",
            keys.sign_pubkey.to_str().unwrap(),
            audit_log.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(verify_two.status.success());
    let stdout_two = String::from_utf8_lossy(&verify_two.stdout);
    let tip_two = stdout_two
        .lines()
        .find_map(|l| l.strip_prefix("tip: "))
        .and_then(|rest| rest.split_whitespace().next())
        .expect("audit-verify should print a tip: line")
        .to_string();

    // Wholesale-delete the second entry by truncating back to the first
    // entry's exact length - no mid-entry corruption, so the chain itself
    // stays perfectly consistent.
    let mut bytes = fs::read(&audit_log).unwrap();
    bytes.truncate(len_after_first_entry as usize);
    fs::write(&audit_log, &bytes).unwrap();

    // Without an expected tip, the truncation is invisible.
    let verify_no_tip = std::process::Command::new(bin())
        .args([
            "audit-verify",
            "--auditor-key",
            keys.privkey.to_str().unwrap(),
            "--operator-key",
            keys.sign_pubkey.to_str().unwrap(),
            audit_log.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        verify_no_tip.success(),
        "chain check alone must not notice a whole entry deleted off the end"
    );

    // But checking against the tip from before the deletion catches it.
    let verify_with_tip = std::process::Command::new(bin())
        .args([
            "audit-verify",
            "--auditor-key",
            keys.privkey.to_str().unwrap(),
            "--operator-key",
            keys.sign_pubkey.to_str().unwrap(),
            "--expect-tip",
            &tip_two,
            audit_log.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        !verify_with_tip.success(),
        "--expect-tip must catch a trailing entry deleted after it was recorded"
    );
}

#[test]
fn encrypt_rejects_partial_audit_configuration() {
    let keys = setup_keys();
    let dir = keys.dir.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"payload").unwrap();

    // Only --audit-log given, missing --audit-key/--audit-recipient.
    let output = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            keys.pubkey.to_str().unwrap(),
            "--audit-log",
            dir.join("audit.log").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "partially configured --audit-log should be rejected"
    );
}
