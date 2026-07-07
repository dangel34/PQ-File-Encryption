use std::fs;
use std::io::Write;
use std::process::Stdio;
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
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
            // Default output is the original secret.txt, which still exists; --force
            // permits the intended in-place roundtrip overwrite.
            "--force",
        ])
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
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
            "-o",
            pqf.to_str().unwrap(),
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
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
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
    assert!(
        !status.success(),
        "second keygen should have failed without --force"
    );
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

#[test]
fn encrypt_refuses_to_clobber_existing_output_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"do not clobber my .pqf").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    // Pre-create the default output path (secret.txt.pqf) with sentinel content.
    let pqf = dir.join("secret.txt.pqf");
    fs::write(&pqf, b"PRECIOUS EXISTING FILE").unwrap();

    let pubkey = dir.join("pubkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "encrypt must refuse to overwrite an existing .pqf without --force"
    );
    // The sentinel file must be untouched.
    assert_eq!(fs::read(&pqf).unwrap(), b"PRECIOUS EXISTING FILE");

    // With --force the encrypt proceeds and replaces the sentinel.
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
            "--force",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt --force should overwrite");
    assert_eq!(&fs::read(&pqf).unwrap()[..4], b"PQFL");
}

#[test]
fn decrypt_refuses_to_clobber_existing_output_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("note.txt");
    fs::write(&input, b"decrypt overwrite guard").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
            "-o",
            dir.join("note.enc").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    // An unrelated file sits at the decrypt destination and must not be clobbered.
    let dest = dir.join("important.txt");
    fs::write(&dest, b"KEEP ME").unwrap();

    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            dir.join("note.enc").to_str().unwrap(),
            "-o",
            dest.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "decrypt must refuse to overwrite an existing file without --force"
    );
    assert_eq!(fs::read(&dest).unwrap(), b"KEEP ME");

    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            dir.join("note.enc").to_str().unwrap(),
            "-o",
            dest.to_str().unwrap(),
            "--force",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt --force should overwrite");
    assert_eq!(fs::read(&dest).unwrap(), b"decrypt overwrite guard");
}

#[test]
fn inspect_shows_header_fields() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("data.txt");
    fs::write(&input, b"inspect test payload").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "--chunk-size",
            "65536",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    let output = std::process::Command::new(bin())
        .args(["inspect", dir.join("data.txt.pqf").to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "inspect failed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("PQFL"), "missing magic");
    // v3 layout with the authenticated-header bit (0x80) set.
    assert!(stdout.contains("0x83"), "missing version");
    assert!(
        stdout.contains("Auth. header:       yes"),
        "missing auth flag"
    );
    assert!(stdout.contains("768"), "missing KEM variant");
    assert!(stdout.contains("Original file size"), "missing size field");
    assert!(stdout.contains("20 bytes"), "wrong original size");
}

#[test]
fn inspect_fails_on_invalid_file() {
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("bad.pqf");
    fs::write(&bad, b"not a pqf file").unwrap();

    let status = std::process::Command::new(bin())
        .args(["inspect", bad.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success(), "inspect should fail on invalid file");
}

// ── Stdin / stdout pipe support ────────────────────────────────────────────

#[test]
fn roundtrip_stdin_stdout() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"stdin-stdout pipe roundtrip payload";

    // Generate keys.
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");

    // Encrypt: pipe plaintext via stdin ('-'), write .pqf to a file via -o.
    let pqf_path = dir.join("out.pqf");
    let mut enc = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            "-",
            "-o",
            pqf_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    enc.stdin.take().unwrap().write_all(original).unwrap();
    assert!(enc.wait().unwrap().success(), "encrypt from stdin failed");
    assert!(pqf_path.exists(), ".pqf file not written");

    // Decrypt: read .pqf from a file, write plaintext to stdout ('-' via -o).
    let dec = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            pqf_path.to_str().unwrap(),
            "-o",
            "-",
        ])
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    assert!(dec.status.success(), "decrypt to stdout failed");
    assert_eq!(dec.stdout, original, "stdout bytes do not match original");
}

#[test]
fn roundtrip_stdin_to_stdout() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"full stdin-to-stdout pipeline payload";

    // Generate keys.
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let privkey = dir.join("privkey.pem");

    // Encrypt: stdin → stdout (no -o flag; omitting -o when input is '-' writes to stdout).
    let mut enc = std::process::Command::new(bin())
        .args(["encrypt", "-r", pubkey.to_str().unwrap(), "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    enc.stdin.take().unwrap().write_all(original).unwrap();
    let enc_out = enc.wait_with_output().unwrap();
    assert!(enc_out.status.success(), "encrypt stdin-to-stdout failed");
    let pqf_bytes = enc_out.stdout;
    assert!(!pqf_bytes.is_empty(), "no encrypted output");

    // Decrypt: stdin (the .pqf bytes) → stdout.
    let mut dec = std::process::Command::new(bin())
        .args(["decrypt", "-k", privkey.to_str().unwrap(), "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    dec.stdin.take().unwrap().write_all(&pqf_bytes).unwrap();
    let dec_out = dec.wait_with_output().unwrap();
    assert!(dec_out.status.success(), "decrypt stdin-to-stdout failed");
    assert_eq!(
        dec_out.stdout, original,
        "piped bytes do not match original"
    );
}

// ── Shell completions ──────────────────────────────────────────────────────

#[test]
fn completions_bash_exits_success_and_contains_function() {
    let output = std::process::Command::new(bin())
        .args(["completions", "bash"])
        .output()
        .unwrap();
    assert!(output.status.success(), "completions bash should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("_pqfile"),
        "bash completion should define _pqfile function"
    );
    assert!(!stdout.is_empty());
}

#[test]
fn completions_zsh_exits_success() {
    let output = std::process::Command::new(bin())
        .args(["completions", "zsh"])
        .output()
        .unwrap();
    assert!(output.status.success(), "completions zsh should exit 0");
    assert!(!output.stdout.is_empty(), "zsh output should be non-empty");
}

#[test]
fn completions_fish_exits_success() {
    let output = std::process::Command::new(bin())
        .args(["completions", "fish"])
        .output()
        .unwrap();
    assert!(output.status.success(), "completions fish should exit 0");
    assert!(!output.stdout.is_empty(), "fish output should be non-empty");
}

#[test]
fn completions_powershell_exits_success() {
    let output = std::process::Command::new(bin())
        .args(["completions", "powershell"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "completions powershell should exit 0"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("pqfile"),
        "powershell output should reference pqfile"
    );
}

#[test]
fn completions_unknown_shell_exits_failure() {
    let status = std::process::Command::new(bin())
        .args(["completions", "tcsh"])
        .status()
        .unwrap();
    assert!(!status.success(), "unknown shell should exit non-zero");
}

#[test]
fn completions_all_shells_cover_subcommands() {
    // Verify each shell's output mentions the key subcommands.
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output = std::process::Command::new(bin())
            .args(["completions", shell])
            .output()
            .unwrap();
        assert!(output.status.success(), "completions {shell} failed");
        let text = String::from_utf8(output.stdout).unwrap();
        for sub in ["keygen", "encrypt", "decrypt", "inspect", "completions"] {
            assert!(
                text.contains(sub),
                "shell {shell}: completion output missing subcommand '{sub}'"
            );
        }
    }
}

// ── Streaming encryption (v3 format) ──────────────────────────────────────

#[test]
fn roundtrip_large_file_streaming() {
    // 3 full 64 KiB chunks + a partial last chunk to exercise multi-chunk paths.
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let chunk_size: usize = 65536;
    let payload_size = chunk_size * 3 + 1234;
    let original: Vec<u8> = (0..=255u8).cycle().take(payload_size).collect();

    let input = dir.join("large.bin");
    fs::write(&input, &original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let pqf = dir.join("large.bin.pqf");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt of large file failed");
    assert!(pqf.exists(), ".pqf not created");

    let privkey = dir.join("privkey.pem");
    let recovered = dir.join("large.bin.recovered");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt of large file failed");
    assert_eq!(
        fs::read(&recovered).unwrap(),
        original,
        "large file roundtrip mismatch"
    );
}

#[test]
fn inspect_large_file_shows_v3_version() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // 2 MiB: falls in the 1 MiB-256 MiB range → adaptive chunk size = 64 KiB → v3 format.
    let input = dir.join("data.bin");
    fs::write(&input, vec![0u8; 2 * 1024 * 1024]).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let output = std::process::Command::new(bin())
        .args(["inspect", dir.join("data.bin.pqf").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("0x83"),
        "expected v3 (authenticated) version in inspect output"
    );
}

// ── Recursive encryption ───────────────────────────────────────────────────

#[test]
fn recursive_encrypts_all_files_in_tree() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // Keygen.
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    // Create a small directory tree.
    let sub = dir.join("subdir");
    fs::create_dir(&sub).unwrap();
    fs::write(dir.join("a.txt"), b"file a").unwrap();
    fs::write(dir.join("b.txt"), b"file b").unwrap();
    fs::write(sub.join("c.txt"), b"file c").unwrap();

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            "--recursive",
            dir.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "recursive encrypt failed");

    // All three source files should have a .pqf counterpart.
    assert!(dir.join("a.txt.pqf").exists(), "a.txt.pqf missing");
    assert!(dir.join("b.txt.pqf").exists(), "b.txt.pqf missing");
    assert!(sub.join("c.txt.pqf").exists(), "c.txt.pqf missing");

    // Verify one of them decrypts correctly.
    let privkey = dir.join("privkey.pem");
    let recovered = dir.join("a.recovered");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            dir.join("a.txt.pqf").to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt after recursive encrypt failed");
    assert_eq!(fs::read(&recovered).unwrap(), b"file a");
}

#[test]
fn recursive_skips_existing_pqf_files() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    fs::write(dir.join("data.txt"), b"payload").unwrap();
    // Existing .pqf file should not be re-encrypted by --recursive.
    fs::write(dir.join("already.pqf"), b"pre-existing").unwrap();

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            "--recursive",
            dir.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "recursive encrypt failed");

    // The pre-existing .pqf was not re-encrypted (no .pqf.pqf created).
    assert!(
        !dir.join("already.pqf.pqf").exists(),
        ".pqf files should be skipped"
    );
    // The regular file was encrypted.
    assert!(
        dir.join("data.txt.pqf").exists(),
        "data.txt.pqf should exist"
    );
}

#[test]
fn recursive_fails_on_non_directory() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let file = dir.join("plain.txt");
    fs::write(&file, b"not a dir").unwrap();

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            "--recursive",
            file.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success(), "recursive on a file should fail");
}

// ── ML-KEM-1024 roundtrip ─────────────────────────────────────────────────

#[test]
fn roundtrip_1024() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"ML-KEM-1024 end-to-end roundtrip payload";
    let input = dir.join("secret.txt");
    fs::write(&input, original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--level", "1024"])
        .status()
        .unwrap();
    assert!(status.success(), "keygen --level 1024 failed");

    let pubkey = dir.join("pubkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt with 1024 key failed");

    let pqf = dir.join("secret.txt.pqf");
    assert!(pqf.exists(), ".pqf output not found");

    // inspect should report KEM variant 1024
    let output = std::process::Command::new(bin())
        .args(["inspect", pqf.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "inspect failed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("1024"),
        "inspect should show KEM variant 1024"
    );

    let privkey = dir.join("privkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
            // Default output overwrites the original secret.txt in place.
            "--force",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt with 1024 key failed");

    let got = fs::read(dir.join("secret.txt")).unwrap();
    assert_eq!(got, original, "1024 decrypted bytes do not match original");
}

#[test]
fn roundtrip_1024_json_inspect() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("data.txt");
    fs::write(&input, b"1024 json inspect test").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--level", "1024"])
        .status()
        .unwrap();
    assert!(status.success());

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "inspect",
            dir.join("data.txt.pqf").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("not valid JSON");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["kem_variant"], 1024);
}

#[test]
fn decrypt_1024_key_on_768_file_fails() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("data.txt");
    fs::write(&input, b"mismatch test").unwrap();

    // Generate a 768 key pair and encrypt.
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // Generate a 1024 private key and try to decrypt the 768-encrypted file.
    let keys_1024 = dir.join("keys_1024");
    fs::create_dir(&keys_1024).unwrap();
    let status = std::process::Command::new(bin())
        .args([
            "keygen",
            "--out",
            keys_1024.to_str().unwrap(),
            "--level",
            "1024",
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            keys_1024.join("privkey.pem").to_str().unwrap(),
            dir.join("data.txt.pqf").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "decrypting 768 file with 1024 key should fail"
    );
}

// ── JSON output (--json flag) ──────────────────────────────────────────────

#[test]
fn json_keygen_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let output = std::process::Command::new(bin())
        .args(["--json", "keygen", "--out", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "keygen --json failed");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("not valid JSON");
    assert_eq!(v["status"], "ok");
    assert!(v["pubkey_path"].is_string());
    assert!(v["privkey_path"].is_string());
    assert!(v["fingerprint"].is_string());
}

#[test]
fn json_encrypt_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"json test").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "encrypt --json failed");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("not valid JSON");
    assert_eq!(v["status"], "ok");
    assert!(v["output"].as_str().unwrap().ends_with(".pqf"));
}

#[test]
fn json_decrypt_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("msg.txt");
    fs::write(&input, b"decrypt json test").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let pqf = dir.join("msg.txt.pqf");
    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "decrypt",
            "-k",
            dir.join("privkey.pem").to_str().unwrap(),
            pqf.to_str().unwrap(),
            // Default output overwrites the original msg.txt in place.
            "--force",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "decrypt --json failed");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("not valid JSON");
    assert_eq!(v["status"], "ok");
    assert!(v["output"].is_string());
}

#[test]
fn json_inspect_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("data.txt");
    fs::write(&input, b"inspect json test payload").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    // Explicit chunk-size so this small file gets v3 (not adaptive v5).
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "--chunk-size",
            "65536",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "inspect",
            dir.join("data.txt.pqf").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "inspect --json failed");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("not valid JSON");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["magic"], "PQFL");
    assert_eq!(v["version"], "0x83");
    assert_eq!(v["header_authenticated"], true);
    assert_eq!(v["kem_variant"], 768);
    assert_eq!(v["original_size"], 25);
    assert!(v["nonce"].is_string());
}

#[test]
fn json_error_output_goes_to_stderr() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let bad_file = dir.join("nonexistent.pqf");
    let output = std::process::Command::new(bin())
        .args(["--json", "inspect", bad_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "should fail on missing file");

    let stderr = String::from_utf8(output.stderr).unwrap();
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).expect("stderr not valid JSON");
    assert_eq!(v["status"], "error");
    assert!(v["message"].is_string());
    assert!(
        v["code"].is_u64(),
        "JSON error must include a numeric 'code' field"
    );
}

#[test]
fn json_recursive_encrypt_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // Put keys in a separate directory so they aren't collected by --recursive.
    let keys_dir = dir.join("keys");
    fs::create_dir(&keys_dir).unwrap();
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", keys_dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let content_dir = dir.join("content");
    fs::create_dir(&content_dir).unwrap();
    fs::write(content_dir.join("x.txt"), b"x").unwrap();
    fs::write(content_dir.join("y.txt"), b"y").unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "encrypt",
            "-r",
            keys_dir.join("pubkey.pem").to_str().unwrap(),
            "--recursive",
            content_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "json recursive encrypt failed");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let arr: serde_json::Value = serde_json::from_str(stdout.trim()).expect("not valid JSON array");
    assert!(arr.is_array());
    let entries = arr.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    for entry in entries {
        assert_eq!(entry["status"], "ok");
        assert!(entry["output"].as_str().unwrap().ends_with(".pqf"));
    }
}

// ── Hybrid X25519+ML-KEM-768 ──────────────────────────────────────────────

#[test]
fn roundtrip_hybrid() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"hybrid X25519+ML-KEM-768 roundtrip test";
    let input = dir.join("secret.txt");
    fs::write(&input, original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--hybrid"])
        .status()
        .unwrap();
    assert!(status.success(), "hybrid keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt with hybrid key failed");

    let pqf = dir.join("secret.txt.pqf");
    assert!(pqf.exists(), ".pqf output not found");

    let privkey = dir.join("privkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
            // Default output overwrites the original secret.txt in place.
            "--force",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt with hybrid key failed");

    let got = fs::read(dir.join("secret.txt")).unwrap();
    assert_eq!(got, original, "decrypted bytes do not match original");
}

#[test]
fn roundtrip_hybrid_with_passphrase() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"hybrid passphrase roundtrip";
    let input = dir.join("data.bin");
    fs::write(&input, original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--hybrid"])
        .status()
        .unwrap();
    assert!(status.success(), "hybrid keygen failed");

    let pubkey = dir.join("pubkey.pem");
    let enc_cmd = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(enc_cmd.success(), "encrypt failed");

    let pqf = dir.join("data.bin.pqf");
    let privkey = dir.join("privkey.pem");

    // Decrypt without passphrase (plain key) should succeed.
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
            "-o",
            dir.join("out.bin").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt failed");
    assert_eq!(fs::read(dir.join("out.bin")).unwrap(), original);
}

#[test]
fn hybrid_inspect_shows_correct_kem_variant() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    fs::write(dir.join("plain.txt"), b"test").unwrap();

    std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--hybrid"])
        .status()
        .unwrap();

    std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            dir.join("plain.txt").to_str().unwrap(),
        ])
        .status()
        .unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "inspect",
            dir.join("plain.txt.pqf").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["kem_variant"], 0x0301);
    assert_eq!(v["kem_variant_name"], "Hybrid X25519+ML-KEM-768");
}

#[test]
fn hybrid_keygen_refuses_overwrite_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--hybrid"])
        .status()
        .unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap(), "--hybrid"])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "second hybrid keygen without --force should fail"
    );
}

#[test]
fn hybrid_key_cannot_decrypt_non_hybrid_file() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    // Encrypt with regular ML-KEM-768 key.
    std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();

    fs::write(dir.join("plain.txt"), b"regular file").unwrap();
    std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            dir.join("plain.txt").to_str().unwrap(),
        ])
        .status()
        .unwrap();

    // Generate a hybrid key pair (separate dir).
    let hybrid_dir = tmp.path().join("hybrid");
    fs::create_dir(&hybrid_dir).unwrap();
    std::process::Command::new(bin())
        .args(["keygen", "--out", hybrid_dir.to_str().unwrap(), "--hybrid"])
        .status()
        .unwrap();

    // Try to decrypt with the hybrid private key - should fail (KEM variant mismatch).
    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            hybrid_dir.join("privkey.pem").to_str().unwrap(),
            dir.join("plain.txt.pqf").to_str().unwrap(),
            "-o",
            dir.join("out.txt").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "hybrid key should not decrypt non-hybrid file"
    );
}

// ── ML-DSA signing ────────────────────────────────────────────────────────

#[test]
fn sign_keygen_creates_key_files() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let status = std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "sign-keygen failed");
    assert!(
        dir.join("sign_pubkey.pem").exists(),
        "sign_pubkey.pem not found"
    );
    assert!(
        dir.join("sign_privkey.pem").exists(),
        "sign_privkey.pem not found"
    );
}

#[test]
fn slh_dsa_sign_and_verify_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let data_path = dir.join("doc.txt");
    fs::write(&data_path, b"sign me with slh-dsa").unwrap();

    let status = std::process::Command::new(bin())
        .args([
            "sign-keygen",
            "--out",
            dir.to_str().unwrap(),
            "--algorithm",
            "slh-dsa-shake-192f",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "slh sign-keygen failed");

    let sk_pem = fs::read_to_string(dir.join("sign_privkey.pem")).unwrap();
    assert!(sk_pem.contains("SLH-DSA-SHAKE-192F SIGNING KEY"));

    let sk_path = dir.join("sign_privkey.pem");
    let sig_path = dir.join("doc.txt.sig");

    let status = std::process::Command::new(bin())
        .args([
            "sign",
            "-k",
            sk_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "slh sign failed");
    let sig_pem = fs::read_to_string(&sig_path).unwrap();
    assert!(sig_pem.contains("SLH-DSA-SHAKE-192F SIGNATURE"));

    let vk_path = dir.join("sign_pubkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "verify",
            "-k",
            vk_path.to_str().unwrap(),
            "-s",
            sig_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "slh verify failed");
}

#[test]
fn sign_and_verify_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let data_path = dir.join("doc.txt");
    fs::write(&data_path, b"sign me").unwrap();

    let status = std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "sign-keygen failed");

    let sk_path = dir.join("sign_privkey.pem");
    let sig_path = dir.join("doc.txt.sig");

    let status = std::process::Command::new(bin())
        .args([
            "sign",
            "-k",
            sk_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "sign failed");
    assert!(sig_path.exists(), "signature file not found");

    let vk_path = dir.join("sign_pubkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "verify",
            "-k",
            vk_path.to_str().unwrap(),
            "-s",
            sig_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "verify failed");
}

#[test]
fn verify_fails_on_tampered_file() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let data_path = dir.join("doc.txt");
    fs::write(&data_path, b"original content").unwrap();

    std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();

    let sk_path = dir.join("sign_privkey.pem");
    std::process::Command::new(bin())
        .args([
            "sign",
            "-k",
            sk_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    // Tamper with the file after signing
    fs::write(&data_path, b"tampered content").unwrap();

    let vk_path = dir.join("sign_pubkey.pem");
    let sig_path = dir.join("doc.txt.sig");
    let status = std::process::Command::new(bin())
        .args([
            "verify",
            "-k",
            vk_path.to_str().unwrap(),
            "-s",
            sig_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success(), "verify should fail on tampered file");
}

#[test]
fn sign_keygen_refuses_overwrite_without_force() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();

    let status = std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "second sign-keygen without --force should fail"
    );
}

#[test]
fn sign_keygen_force_overwrites() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();

    let status = std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap(), "--force"])
        .status()
        .unwrap();
    assert!(status.success(), "sign-keygen --force should succeed");
}

#[test]
fn sign_with_custom_output_path() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let data_path = dir.join("data.bin");
    fs::write(&data_path, b"binary data").unwrap();

    std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();

    let sk_path = dir.join("sign_privkey.pem");
    let sig_path = dir.join("custom.sig");

    let status = std::process::Command::new(bin())
        .args([
            "sign",
            "-k",
            sk_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
            "-o",
            sig_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "sign with -o failed");
    assert!(sig_path.exists(), "custom sig path not found");
}

#[test]
fn sign_verify_json_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let data_path = dir.join("doc.txt");
    fs::write(&data_path, b"json test").unwrap();

    std::process::Command::new(bin())
        .args(["sign-keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();

    let sk_path = dir.join("sign_privkey.pem");
    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "sign",
            "-k",
            sk_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "json sign failed");
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["status"], "ok");
    assert!(v["signature"].as_str().unwrap().ends_with(".sig"));

    let vk_path = dir.join("sign_pubkey.pem");
    let sig_path = dir.join("doc.txt.sig");
    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "verify",
            "-k",
            vk_path.to_str().unwrap(),
            "-s",
            sig_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "json verify failed");
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["result"], "valid");
}

#[test]
fn sign_keygen_json_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let output = std::process::Command::new(bin())
        .args(["--json", "sign-keygen", "--out", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "json sign-keygen failed");
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["status"], "ok");
    assert!(v["vk_path"].as_str().unwrap().ends_with("sign_pubkey.pem"));
    assert!(v["sk_path"].as_str().unwrap().ends_with("sign_privkey.pem"));
    assert!(!v["fingerprint"].as_str().unwrap().is_empty());
}

// ── Corrupt / truncated input ────────────────────────────────────────────────

#[test]
fn decrypt_truncated_pqf_fails() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let original = b"truncation test payload with enough bytes to produce multiple chunks";
    let input = dir.join("plain.txt");
    fs::write(&input, original).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");

    let pqf = dir.join("plain.txt.pqf");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt failed");

    // Truncate the ciphertext to half its size.
    let full = fs::read(&pqf).unwrap();
    let truncated = dir.join("truncated.pqf");
    fs::write(&truncated, &full[..full.len() / 2]).unwrap();

    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            dir.join("privkey.pem").to_str().unwrap(),
            truncated.to_str().unwrap(),
            "-o",
            dir.join("out.txt").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success(), "decrypt of truncated file should fail");
}

#[test]
fn decrypt_corrupt_pqf_fails() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("plain.txt");
    fs::write(&input, b"corrupt test payload").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let pqf = dir.join("plain.txt.pqf");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // Flip bytes in the payload (after the 7-byte header prefix).
    let mut corrupt = fs::read(&pqf).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    corrupt[last - 1] ^= 0xFF;
    let bad = dir.join("corrupt.pqf");
    fs::write(&bad, &corrupt).unwrap();

    let status = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            dir.join("privkey.pem").to_str().unwrap(),
            bad.to_str().unwrap(),
            "-o",
            dir.join("out.txt").to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(!status.success(), "decrypt of corrupt file should fail");
}

// ── Multiple recipients (v4 format) ──────────────────────────────────────────

#[test]
fn multi_recipient_two_keys_both_can_decrypt() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let plaintext = b"multi-recipient roundtrip";
    let input = dir.join("secret.txt");
    fs::write(&input, plaintext).unwrap();

    // Generate two independent key pairs.
    let dir_a = dir.join("a");
    let dir_b = dir.join("b");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();

    let s = std::process::Command::new(bin())
        .args(["keygen", "--out", dir_a.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(s.success(), "keygen A failed");

    let s = std::process::Command::new(bin())
        .args(["keygen", "--out", dir_b.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(s.success(), "keygen B failed");

    let pqf = dir.join("secret.txt.pqf");
    let s = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir_a.join("pubkey.pem").to_str().unwrap(),
            "-r",
            dir_b.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(s.success(), "multi-recipient encrypt failed");
    assert!(pqf.exists(), ".pqf not created");

    // Recipient A decrypts.
    let out_a = dir.join("dec_a.txt");
    let s = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            dir_a.join("privkey.pem").to_str().unwrap(),
            pqf.to_str().unwrap(),
            "-o",
            out_a.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(s.success(), "decrypt by A failed");
    assert_eq!(fs::read(&out_a).unwrap(), plaintext);

    // Recipient B decrypts.
    let out_b = dir.join("dec_b.txt");
    let s = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            dir_b.join("privkey.pem").to_str().unwrap(),
            pqf.to_str().unwrap(),
            "-o",
            out_b.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(s.success(), "decrypt by B failed");
    assert_eq!(fs::read(&out_b).unwrap(), plaintext);
}

#[test]
fn multi_recipient_wrong_key_fails() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("data.txt");
    fs::write(&input, b"secret").unwrap();

    let dir_a = dir.join("a");
    let dir_c = dir.join("c");
    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_c).unwrap();

    std::process::Command::new(bin())
        .args(["keygen", "--out", dir_a.to_str().unwrap()])
        .status()
        .unwrap();
    std::process::Command::new(bin())
        .args(["keygen", "--out", dir_c.to_str().unwrap()])
        .status()
        .unwrap();

    // Encrypt only for A.
    let pqf = dir.join("data.txt.pqf");
    std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir_a.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();

    // C's key should fail (not a recipient).
    let out = dir.join("out.txt");
    let s = std::process::Command::new(bin())
        .args([
            "decrypt",
            "-k",
            dir_c.join("privkey.pem").to_str().unwrap(),
            pqf.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    // Single-recipient files still use v3 format; wrong key returns UnsupportedKem.
    assert!(!s.success(), "decrypt with wrong key should fail");
}

#[test]
fn multi_recipient_three_keys_all_decrypt() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let plaintext = b"three-way multi-recipient";
    let input = dir.join("file.txt");
    fs::write(&input, plaintext).unwrap();

    let dirs: Vec<_> = (0..3)
        .map(|i| {
            let d = dir.join(format!("k{i}"));
            fs::create_dir_all(&d).unwrap();
            std::process::Command::new(bin())
                .args(["keygen", "--out", d.to_str().unwrap()])
                .status()
                .unwrap();
            d
        })
        .collect();

    let pqf = dir.join("file.txt.pqf");
    let s = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dirs[0].join("pubkey.pem").to_str().unwrap(),
            "-r",
            dirs[1].join("pubkey.pem").to_str().unwrap(),
            "-r",
            dirs[2].join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(s.success(), "3-recipient encrypt failed");

    for (i, d) in dirs.iter().enumerate() {
        let out = dir.join(format!("dec{i}.txt"));
        let s = std::process::Command::new(bin())
            .args([
                "decrypt",
                "-k",
                d.join("privkey.pem").to_str().unwrap(),
                pqf.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(s.success(), "decrypt by key {i} failed");
        assert_eq!(fs::read(&out).unwrap(), plaintext, "mismatch for key {i}");
    }
}

#[test]
fn multi_recipient_mixed_variants() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let plaintext = b"mixed variant multi-recipient";
    let input = dir.join("data.txt");
    fs::write(&input, plaintext).unwrap();

    let dir_768 = dir.join("k768");
    let dir_1024 = dir.join("k1024");
    fs::create_dir_all(&dir_768).unwrap();
    fs::create_dir_all(&dir_1024).unwrap();

    std::process::Command::new(bin())
        .args(["keygen", "--out", dir_768.to_str().unwrap()])
        .status()
        .unwrap();
    std::process::Command::new(bin())
        .args([
            "keygen",
            "--out",
            dir_1024.to_str().unwrap(),
            "--level",
            "1024",
        ])
        .status()
        .unwrap();

    let pqf = dir.join("data.txt.pqf");
    let s = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir_768.join("pubkey.pem").to_str().unwrap(),
            "-r",
            dir_1024.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(s.success(), "mixed-variant encrypt failed");

    for (label, d) in [("768", &dir_768), ("1024", &dir_1024)] {
        let out = dir.join(format!("dec_{label}.txt"));
        let s = std::process::Command::new(bin())
            .args([
                "decrypt",
                "-k",
                d.join("privkey.pem").to_str().unwrap(),
                pqf.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(s.success(), "mixed-variant decrypt ({label}) failed");
        assert_eq!(fs::read(&out).unwrap(), plaintext);
    }
}

#[test]
fn doctor_key_file() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let priv_key = dir.join("privkey.pem");
    let output = std::process::Command::new(bin())
        .args(["--json", "doctor", priv_key.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "doctor should succeed on a valid key"
    );

    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor output must be valid JSON");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["type"], "private_key");
    assert_eq!(v["encrypted"], false);
    assert_eq!(v["hardware"], false);
    assert_eq!(v["legacy_argon2_p1"], false);
}

#[test]
fn doctor_pqf_file() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let input = dir.join("plain.txt");
    fs::write(&input, b"doctor test payload").unwrap();
    let pqf = dir.join("plain.txt.pqf");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            dir.join("pubkey.pem").to_str().unwrap(),
            input.to_str().unwrap(),
            "-o",
            pqf.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    let output = std::process::Command::new(bin())
        .args(["--json", "doctor", pqf.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "doctor should succeed on a valid .pqf"
    );

    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("doctor output must be valid JSON");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["type"], "pqf_ciphertext");
    assert_eq!(v["header_valid"], "true");
    assert!(v["version"].is_string());
}

// ── pqfile check ──────────────────────────────────────────────────────────────

#[test]
fn check_authenticates_without_writing_plaintext() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();

    let input = dir.join("secret.txt");
    fs::write(&input, b"backup validation payload").unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    let pubkey = dir.join("pubkey.pem");
    let status = std::process::Command::new(bin())
        .args([
            "encrypt",
            "-r",
            pubkey.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    // Remove the original so any plaintext write by `check` would be visible.
    fs::remove_file(&input).unwrap();
    let files_before: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();

    let pqf = dir.join("secret.txt.pqf");
    let privkey = dir.join("privkey.pem");
    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "check",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "check failed on a valid file");
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("check output must be valid JSON");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["plaintext_bytes"], 25);

    let files_after: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files_before, files_after, "check must not create any files");

    // Corrupt one ciphertext byte inside the final chunk: check must now fail
    // with the DecryptionFailure JSON code.
    let mut ct = fs::read(&pqf).unwrap();
    let last = ct.len() - 2;
    ct[last] ^= 0x01;
    fs::write(&pqf, &ct).unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "--json",
            "check",
            "-k",
            privkey.to_str().unwrap(),
            pqf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "check must fail on tampered ciphertext"
    );
    let v: serde_json::Value =
        serde_json::from_slice(String::from_utf8(output.stderr).unwrap().trim().as_bytes())
            .expect("check error must be valid JSON");
    assert_eq!(v["status"], "error");
    assert_eq!(v["code"], 7, "tampered chunk must map to DecryptionFailure");
}

// ── Config file defaults ──────────────────────────────────────────────────────

/// Escapes a path for use inside a TOML basic string (backslashes on Windows).
fn toml_escape(p: &std::path::Path) -> String {
    p.to_str().unwrap().replace('\\', "\\\\")
}

#[test]
fn config_file_supplies_default_recipient_and_key() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let cfg_root = dir.join("cfg");
    fs::create_dir_all(cfg_root.join("pqfile")).unwrap();

    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());

    fs::write(
        cfg_root.join("pqfile").join("config.toml"),
        format!(
            "recipient = \"{}\"\nkey = \"{}\"\n",
            toml_escape(&dir.join("pubkey.pem")),
            toml_escape(&dir.join("privkey.pem")),
        ),
    )
    .unwrap();

    let input = dir.join("note.txt");
    fs::write(&input, b"config default test").unwrap();

    // The same variable feeds both platforms' config lookup: %APPDATA% on
    // Windows, $XDG_CONFIG_HOME elsewhere.
    let envs = [
        ("APPDATA", cfg_root.clone()),
        ("XDG_CONFIG_HOME", cfg_root.clone()),
    ];

    // encrypt with no -r: recipient comes from the config.
    let status = std::process::Command::new(bin())
        .envs(envs.iter().map(|(k, v)| (*k, v.clone())))
        .args(["encrypt", input.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "encrypt must pick up config recipient");

    // decrypt with no -k: key comes from the config.
    fs::remove_file(&input).unwrap();
    let pqf = dir.join("note.txt.pqf");
    let status = std::process::Command::new(bin())
        .envs(envs.iter().map(|(k, v)| (*k, v.clone())))
        .args(["decrypt", pqf.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "decrypt must pick up config key");
    assert_eq!(fs::read(&input).unwrap(), b"config default test");

    // --no-config must restore the missing-recipient error.
    let status = std::process::Command::new(bin())
        .envs(envs.iter().map(|(k, v)| (*k, v.clone())))
        .args(["encrypt", "--no-config", input.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(!status.success(), "--no-config must ignore the config file");
}

#[test]
fn malformed_config_is_a_hard_error() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let cfg_root = dir.join("cfg");
    fs::create_dir_all(cfg_root.join("pqfile")).unwrap();
    fs::write(
        cfg_root.join("pqfile").join("config.toml"),
        "recipient = unquoted\n",
    )
    .unwrap();

    let input = dir.join("note.txt");
    fs::write(&input, b"x").unwrap();

    let output = std::process::Command::new(bin())
        .env("APPDATA", &cfg_root)
        .env("XDG_CONFIG_HOME", &cfg_root)
        .args(["encrypt", input.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "malformed config must not be ignored"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("config.toml"),
        "error must name the config file, got: {stderr}"
    );
}

// ── archive --recursive ─────────────────────────────────────────────────────

/// Creates a key pair in `dir` and returns (pubkey, privkey) paths.
fn keygen_in(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let status = std::process::Command::new(bin())
        .args(["keygen", "--out", dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success(), "keygen failed");
    (dir.join("pubkey.pem"), dir.join("privkey.pem"))
}

#[test]
fn archive_recursive_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let (pubkey, privkey) = keygen_in(dir);

    // root/a.txt, root/sub/b.txt, root/sub/c.pqf — unlike encrypt --recursive,
    // archiving must include .pqf files too.
    let root = dir.join("root");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("a.txt"), b"alpha").unwrap();
    fs::write(root.join("sub").join("b.txt"), b"bravo").unwrap();
    fs::write(root.join("sub").join("c.pqf"), b"not actually encrypted").unwrap();

    let archive = dir.join("tree.pqf");
    let status = std::process::Command::new(bin())
        .args([
            "archive",
            "-r",
            pubkey.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            "--recursive",
            root.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "archive --recursive failed");

    let out = dir.join("extracted");
    let status = std::process::Command::new(bin())
        .args([
            "extract",
            "-k",
            privkey.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "extract failed");

    // Entry names keep the walked directory's name as prefix (like tar).
    assert_eq!(fs::read(out.join("root").join("a.txt")).unwrap(), b"alpha");
    assert_eq!(
        fs::read(out.join("root").join("sub").join("b.txt")).unwrap(),
        b"bravo"
    );
    assert_eq!(
        fs::read(out.join("root").join("sub").join("c.pqf")).unwrap(),
        b"not actually encrypted"
    );
}

#[test]
fn archive_directory_without_recursive_fails() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let (pubkey, _) = keygen_in(dir);

    let root = dir.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("a.txt"), b"alpha").unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "archive",
            "-r",
            pubkey.to_str().unwrap(),
            "-o",
            dir.join("tree.pqf").to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "archiving a directory without --recursive must fail"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--recursive"),
        "error must point at --recursive, got: {stderr}"
    );
}

#[test]
fn archive_rejects_case_insensitive_name_collision() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let (pubkey, _) = keygen_in(dir);

    // Same entry name in different case from two directories: extraction on a
    // case-insensitive filesystem would silently overwrite one with the other.
    fs::create_dir_all(dir.join("one")).unwrap();
    fs::create_dir_all(dir.join("two")).unwrap();
    fs::write(dir.join("one").join("Data.txt"), b"1").unwrap();
    fs::write(dir.join("two").join("data.txt"), b"2").unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "archive",
            "-r",
            pubkey.to_str().unwrap(),
            "-o",
            dir.join("dup.pqf").to_str().unwrap(),
            dir.join("one").join("Data.txt").to_str().unwrap(),
            dir.join("two").join("data.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "case-insensitive entry collision must be rejected"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("collide") || stderr.contains("duplicate"),
        "error must explain the collision, got: {stderr}"
    );
}

#[test]
fn archive_recursive_empty_directory_fails() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let (pubkey, _) = keygen_in(dir);

    let root = dir.join("empty");
    fs::create_dir_all(&root).unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "archive",
            "-r",
            pubkey.to_str().unwrap(),
            "-o",
            dir.join("empty.pqf").to_str().unwrap(),
            "--recursive",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "archiving an empty tree must fail rather than write an empty archive"
    );
}

#[cfg(unix)]
#[test]
fn archive_recursive_rejects_symlinks() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let (pubkey, _) = keygen_in(dir);

    let root = dir.join("root");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("real.txt"), b"real").unwrap();
    std::os::unix::fs::symlink(root.join("real.txt"), root.join("link.txt")).unwrap();

    let output = std::process::Command::new(bin())
        .args([
            "archive",
            "-r",
            pubkey.to_str().unwrap(),
            "-o",
            dir.join("sym.pqf").to_str().unwrap(),
            "--recursive",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a symlink inside the tree must be rejected, not silently followed or skipped"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("symlink"),
        "error must name the symlink problem, got: {stderr}"
    );
}
