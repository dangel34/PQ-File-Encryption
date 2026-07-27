<p align="center">
  <img src="pqfile-gui/icon.png" alt="pqfile logo" width="112" height="112">
</p>

<h1 align="center">pqfile: Post-Quantum File Encryption</h1>

<p align="center">
  <a href="https://github.com/dangel34/PQ-File-Encryption/actions/workflows/ci.yml"><img src="https://github.com/dangel34/PQ-File-Encryption/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://crates.io/crates/pqfile"><img src="https://img.shields.io/crates/v/pqfile.svg" alt="crates.io version"></a>
  <a href="https://docs.rs/pqfile"><img src="https://img.shields.io/docsrs/pqfile" alt="docs.rs"></a>
  <a href="https://crates.io/crates/pqfile"><img src="https://img.shields.io/crates/d/pqfile.svg" alt="crates.io downloads"></a>
  <a href="https://github.com/dangel34/PQ-File-Encryption/releases/latest"><img src="https://img.shields.io/github/v/release/dangel34/PQ-File-Encryption" alt="latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/crates/l/pqfile.svg" alt="license"></a>
</p>

A quantum-resistant file encryption tool with a CLI and a cross-platform GUI. It combines post-quantum key encapsulation (ML-KEM, NIST FIPS 203) with ChaCha20-Poly1305 authenticated encryption. Four key types are supported: ML-KEM-512, ML-KEM-768, ML-KEM-1024, and a hybrid X25519+ML-KEM-768 mode. A file can be encrypted to multiple recipients in a single pass, optionally hiding key types and even recipient count from an observer.

Digital signatures use ML-DSA-65 (NIST FIPS 204), with hash-based SLH-DSA-SHAKE-192f (NIST FIPS 205) as an option for long-lived signatures.

**[docs/QUICKSTART.md](docs/QUICKSTART.md)**: build, install, common CLI commands, GUI overview, deploying.

**Service status**: [status.nappi.work/status/pqfile](https://status.nappi.work/status/pqfile)

---

## Background

Classical public-key algorithms such as RSA and ECDH are vulnerable to attacks from sufficiently large quantum computers. ML-KEM (Module-Lattice Key Encapsulation Mechanism), standardized by NIST as FIPS 203, is believed to be secure against both classical and quantum adversaries.

pqfile uses a hybrid approach:

1. **ML-KEM** encapsulates a fresh random session key. Only the holder of the matching private decapsulation key can recover it.
2. **ChaCha20-Poly1305** encrypts the file contents under that session key using the STREAM construction (64 KiB chunks by default). Each chunk is independently authenticated and position-bound so truncation and reordering attacks are detected.

The optional **hybrid mode** (`--hybrid`) adds X25519 Diffie-Hellman to the key exchange so the encryption is secure under either classical _or_ quantum assumptions, whichever holds in the future.

---

## Cryptographic standards

| Component                        | Standard / Specification                                |
|----------------------------------|-----------------------------------------------------------|
| Key encapsulation (standard)      | ML-KEM-512, ML-KEM-768, or ML-KEM-1024, NIST FIPS 203    |
| Key encapsulation (hybrid)        | X25519 + ML-KEM-768, key combined via HKDF-SHA256        |
| Symmetric cipher                  | ChaCha20-Poly1305, RFC 8439                              |
| Session key wrapping (v4/v7/v8/v9)| AES-256-GCM                                              |
| Randomness                        | OS CSPRNG via `getrandom`                                |
| Key derivation (passphrase)       | Argon2id (m=64 MiB, t=3, p=4)                            |
| Key wrapping (passphrase)         | AES-256-GCM                                              |
| Digital signatures                | ML-DSA-65 (FIPS 204); optional SLH-DSA-SHAKE-192f (FIPS 205) |
| Key fingerprints                  | SHA3-256 (first 8 bytes, colon-separated hex)            |
| Threshold key splitting           | Shamir's Secret Sharing over GF(256)                     |
| Hardware-backed key storage       | OS credential store (Windows Credential Manager, macOS Keychain, Linux Secret Service) - unrelated to the FIDO2 hardware token second factor below, which is a physical USB security key |

---

## Project structure

```
PQ-File-Encryption/
├── Cargo.toml                  Workspace manifest
├── deny.toml                   cargo-deny supply-chain policy (licenses, advisories, bans)
├── supply-chain/               cargo-vet audit configuration
├── fuzz/                       cargo-fuzz targets (excluded from the main workspace)
│   └── fuzz_targets/
│       ├── fuzz_header_read.rs     Fuzzes PqfHeader::read on arbitrary bytes
│       ├── fuzz_decrypt_bytes.rs   Fuzzes decrypt_bytes on arbitrary ciphertext
│       └── fuzz_pem_parsing.rs     Fuzzes PEM parsing and fingerprinting
├── oss-fuzz/                   OSS-Fuzz integration (Dockerfile, build.sh, project.yaml)
├── scripts/                    Release tooling (bump-version.ps1, test-local.ps1)
├── pqfile/                     Core crypto library
│   ├── src/
│   │   ├── lib.rs                Public library re-exports
│   │   ├── keygen.rs             Key pair generation and PEM serialization
│   │   ├── keys.rs               Typed key wrappers (PqfPublicKey, PqfPrivateKey, ...)
│   │   ├── encrypt.rs            Encryption pipeline (v2-v9 formats, mmap, pipelined, parallel)
│   │   ├── decrypt.rs            Decryption pipeline (v2-v9 auto-detect, parallel)
│   │   ├── format.rs             .pqf binary file format definitions
│   │   ├── reader.rs             PqfReader<R: Read> streaming decryptor
│   │   ├── writer.rs             PqfWriter<W: Write> streaming encryptor
│   │   ├── async_io.rs           Async encrypt/decrypt/AsyncPqfWriter (tokio, feature "async")
│   │   ├── archive.rs            Encrypted multi-file archive (PQFA format)
│   │   ├── rekey.rs              Re-encryption without payload decryption
│   │   ├── add_recipient.rs      Add a recipient to a multi-recipient file in place
│   │   ├── revoke.rs             Key revocation sidecar (.revoked) support
│   │   ├── shamir.rs             Shamir secret sharing for M-of-N key splitting
│   │   ├── sign.rs               ML-DSA-65 / SLH-DSA-SHAKE-192f signing and verification
│   │   ├── signcrypt.rs          Combined sign-then-encrypt and signdecrypt
│   │   ├── sealed_sender.rs      Deniable sender authentication (identity keys, seal/unseal)
│   │   ├── passphrase.rs         Argon2id wrapping for passphrase-protected keys
│   │   ├── repassphrase.rs       Change or upgrade a private key's passphrase
│   │   ├── inspect.rs            Header inspection without decryption
│   │   ├── shred.rs              Secure file shredding (overwrite then delete)
│   │   ├── progress.rs           Progress-callback reader/writer wrappers
│   │   ├── fsutil.rs             Internal: restrictive-permission private-key file writes
│   │   ├── hardware/             OS credential store-backed private keys
│   │   │   ├── mod.rs, credential_store.rs, stub.rs
│   │   └── error.rs              PqfileError enum
│   ├── tests/                    Compat matrix, property tests, format vectors, WASM smoke tests
│   ├── examples/                 ct_shamir.rs (dudect constant-time benchmark), vector generators
│   └── benches/
│       └── crypto.rs             Criterion benchmarks (encrypt/decrypt at 1 KB/1 MB/100 MB)
├── pqfile-cli/                  CLI binary
│   ├── src/main.rs                Cli/Command argument definitions + dispatch only
│   │   ├── config.rs, json_util.rs, prompts.rs, io_util.rs   Shared helpers
│   │   ├── interactive.rs         No-args guided prompt mode
│   │   └── commands/              One module per subcommand family (encrypt, decrypt,
│   │                               keygen, sign, cert, keys, archive, sealed_sender,
│   │                               shamir, inspect, stego)
│   ├── packaging/                 .deb / .rpm packaging assets (pqfile.spec)
│   └── tests/roundtrip.rs         End-to-end CLI integration tests
├── pqfile-gui/                  Shared GUI logic + WASM web app
│   ├── icon.png                   App icon (512x512)
│   ├── index.html                 Canvas page for trunk/WASM builds
│   └── src/
│       ├── lib.rs                  Entry point, WASM start fn, tests
│       ├── app.rs                  PqfileApp struct, tab routing, sidebar, in-app help text
│       ├── colors.rs, theme.rs     Catppuccin palette + egui theme
│       ├── types.rs                Shared types (Tab, FileInput, Settings, ...)
│       ├── widgets.rs              UI helper functions
│       ├── fido2.rs                CTAP2 enroll/derive (native, feature "fido2")
│       └── tabs/                   Keys, Keygen, Encrypt, Decrypt, Sign, Signcrypt, Sealed Sender, Archive, Shamir, Inspect, Clipboard, Settings, fido2_ui
├── pqfile-desktop/               Native desktop binary
│   ├── build.rs                   Embeds icon/metadata via winres (Windows)
│   ├── packaging/                 Inno Setup installer script, .ico asset
│   └── src/main.rs                Native entry point
├── pqfile-python/               Python bindings (PyO3 + maturin, excluded from the main workspace)
│   ├── src/lib.rs                 Native `_pqfile` extension module
│   ├── python/pqfile/              Pure-Python wrapper package (pathlib support, docstrings)
│   └── tests/test_roundtrip.py    pytest suite
├── pqfile-node/                 Node.js bindings (napi-rs, excluded from the main workspace)
│   ├── src/lib.rs                 Native addon: AsyncTask-wrapped keygen/encrypt/decrypt
│   ├── index.js, index.d.ts       Generated platform-detection loader + TypeScript types
│   └── __test__/roundtrip.test.js Node built-in test-runner suite
└── pqfile-mobile/               Kotlin/Swift bindings (uniffi-rs, excluded from the main workspace)
    ├── src/lib.rs                 #[uniffi::export]-annotated keygen/encrypt/decrypt
    ├── src/bin/uniffi-bindgen.rs  uniffi-bindgen entry point (generates bindings/kotlin, bindings/swift)
    └── tests/roundtrip.rs         Rust-level round-trip tests (no Kotlin/Swift toolchain to test through)
```

The `pqfile` crate is a library. The `pqfile-cli` crate provides the CLI binary. The `pqfile-gui` crate compiles to a `cdylib` for WASM and an `rlib` for the native binary. `pqfile-desktop` is the thin native entry point. This follows the official eframe template pattern.

---

## CLI usage

Running bare `pqfile` with no arguments starts an interactive guided mode that walks through encrypting, decrypting, or generating a key pair with prompts instead of flags. It calls the same code paths as the flag-driven commands below, so behavior and defaults are identical. Any argument (including `--help`) takes the normal CLI path.

### Key generation

```bash
# ML-KEM-768 (default, 128-bit post-quantum security)
pqfile keygen --out ./keys

# ML-KEM-512 (category 1, smaller keys and ciphertexts)
pqfile keygen --out ./keys --level 512

# ML-KEM-1024 (192-bit post-quantum security)
pqfile keygen --out ./keys --level 1024

# Hybrid X25519 + ML-KEM-768 (secure under classical OR quantum assumptions)
pqfile keygen --out ./keys --hybrid

# Any of the above with a passphrase-protected private key
pqfile keygen --out ./keys --passphrase

# Store the private key seed in the OS credential store instead of on disk
pqfile keygen --out ./keys --hardware --label my-pqfile-key

# Also render the pqf1... recipient string as a terminal QR code for scanning
pqfile keygen --out ./keys --qr
```

Key files written: `pubkey.pem` (share freely) and `privkey.pem` (keep secret; written with owner-only permissions on Unix). The fingerprint (SHA3-256, first 8 bytes) is printed at generation time, along with a compact `pqf1…` Bech32m recipient string that can be passed directly to `-r` without distributing a PEM file. `--hardware` stores the seed in Windows Credential Manager / macOS Keychain / Linux Secret Service instead of writing it to `privkey.pem`, and is mutually exclusive with `--passphrase` and `--expiry`. The same `--hardware --label <LABEL>` flags work on `sign-keygen`.

```bash
# Print fingerprint and recipient string for an existing key (accepts PEM path or pqf1… string)
pqfile fingerprint pubkey.pem

# Same, plus a scannable terminal QR code of the recipient string
pqfile fingerprint pubkey.pem --qr

# Use a recipient string directly - no PEM file needed
pqfile encrypt -r pqf1qyxhkc... secret.txt
```

### Import an existing key

```bash
# Derive an ML-KEM-768 key pair from an existing unencrypted OpenSSH ed25519 private key
pqfile import-key --from ~/.ssh/id_ed25519 --out ./keys
```

This is a one-way HKDF derivation with no mathematical relationship back to the original SSH key, and the result is not interoperable with SSH. Decrypt password-protected SSH keys first: `ssh-keygen -p -f <key> -N ""`.

### Encryption

```bash
# Single recipient
pqfile encrypt -r pubkey.pem secret.txt
# Output: secret.txt.pqf

# Custom output path
pqfile encrypt -r pubkey.pem secret.txt -o encrypted.pqf

# Multiple recipients (any one can decrypt)
pqfile encrypt -r alice/pubkey.pem -r bob/pubkey.pem secret.txt

# Recursive directory encryption
pqfile encrypt -r pubkey.pem --recursive /path/to/dir/
# Each file produces <file>.pqf alongside the original; existing .pqf files are skipped

# Compress before encrypting (single recipient only, not available on WASM)
pqfile encrypt -r pubkey.pem --compress --compress-level 3 secret.txt

# Encrypt chunks in parallel using rayon (single recipient, incompatible with --compress)
pqfile encrypt -r pubkey.pem --parallel large_file.bin

# Cap Rayon worker threads for --parallel (global flag; default 0 = all cores)
pqfile --threads 4 encrypt -r pubkey.pem --parallel large_file.bin

# Custom chunk size in bytes (single recipient, produces v5 format)
# Omit --chunk-size to auto-tune: 16 KiB for small files, 64 KiB default, 256 KiB for large files
pqfile encrypt -r pubkey.pem --chunk-size 131072 large_file.bin

# Hide key types (multiple recipients, produces v8 format)
pqfile encrypt -r alice/pubkey.pem -r bob/pubkey.pem --anonymous-recipients secret.txt

# Hide key types AND recipient count (pads slots to next power of two, produces v9 format)
pqfile encrypt -r alice/pubkey.pem -r bob/pubkey.pem --pad-recipients secret.txt

# Overlap I/O and AEAD for large files on spinning disk or network storage
pqfile encrypt -r pubkey.pem --pipeline large_file.bin

# Memory-mapped zero-copy encrypt (native only, best for files >= 100 MiB)
pqfile encrypt -r pubkey.pem --mmap huge_file.bin

# Read from stdin, write to stdout
cat secret.txt | pqfile encrypt -r pubkey.pem - > secret.txt.pqf

# Passphrase-only encryption (v10 format, no key pair required)
pqfile encrypt --passphrase secret.txt

# Stronger Argon2id parameters for v10 (see `pqfile doctor --calibrate` for a
# machine-tuned recommendation; decryptors above the default need --max-kdf-mem)
pqfile encrypt --passphrase --kdf-mem 189440 --kdf-time 3 secret.txt

# Keyfile second factor for v10: decryption requires the passphrase AND this file
pqfile encrypt --passphrase --keyfile usb/token.bin secret.txt

# FIDO2 hardware token second factor for v10 (requires the `fido2` cargo
# feature; see fido2-enroll below). Mutually exclusive with --keyfile.
pqfile encrypt --passphrase --fido2 fido2-enrollment.txt secret.txt

# Pad the plaintext to a coarser length bucket (Padme, <= ~12% overhead) so the
# ciphertext length hides the exact file size; decryption strips it automatically
pqfile encrypt -r pubkey.pem --pad secret.txt

# Stealth mode: output carries no magic bytes, version, or key-type field, so it
# is not identifiable as pqfile ciphertext (single recipient; see FORMAT.md 5.10)
pqfile encrypt -r pubkey.pem --stealth secret.txt

# The two compose: unidentifiable ciphertext with a bucketed length
pqfile encrypt -r pubkey.pem --stealth --pad secret.txt

# Time-locked encryption (v11 format, requires the `tlock` cargo feature):
# nobody, including the sender, can decrypt before the target drand beacon
# round is public. Resolve a human time expression to a round number first.
pqfile tlock round "24h"
pqfile encrypt --tlock-round 30438443 secret.txt
```

Multiple `-r` flags produce a v4 multi-recipient file. Each recipient gets their own encapsulated session key; the file payload is encrypted once. `--anonymous-recipients` upgrades to v8 format, dropping the per-slot KEM variant field so key types are hidden. `--pad-recipients` upgrades to v9 format, which additionally pads the slot count to the next power of two with random dummy entries. `--recursive` requires exactly one recipient. `--compress-level` accepts 1 (fastest) to 22 (best ratio), default 3. `--parallel` uses rayon for concurrent chunk processing and requires a single recipient.

`--pad` requires a known, non-zero input size, so it is incompatible with stdin input, empty files, `--mmap`, `--pipeline`, and `--compress` (compression would shrink the padding back down); it composes with `--parallel` and `--stealth`. `--stealth` supports a single recipient only and is incompatible with `--passphrase`, `--recursive`, and `--mmap`; because the output has no header, the recipient must already know the file is in stealth mode and pass `--stealth` at decrypt time.

An interrupted `encrypt` of a very large file doesn't have to restart from byte zero: `encrypt --resume` (single recipient, real file input/output only) writes a checkpoint sidecar (`<output>.pqfck`) roughly every 64 MiB and continues from it on a later run. The checkpoint holds the session key in the clear - guard it like a private key, and delete it along with the partial output to abandon a resume attempt; it's deleted automatically on success. `decrypt --resume` is the cheaper counterpart: no checkpoint needed, since the existing partial output's own length is enough to know where to continue.

`encrypt --fec` (requires the `fec` build feature) protects against cold-storage bit rot - not tampering, which AEAD authentication already covers regardless of this flag - by writing a Reed-Solomon parity sidecar (`<output>.pqf.fec`) alongside the output, correcting up to roughly 3% random byte corruption per 128-byte block. `decrypt --fec` / `check --fec` repair using that sidecar before the normal authenticated decrypt/check runs; an uncorrectable block is passed through unchanged, so tampering and unrepairable corruption still fail normally. Not supported with stdout/stdin.

`--audit-log <PATH> --audit-key <SIGNING_KEY> --audit-recipient <PUBKEY>` (requires the `audit` build feature; all three or none) appends a signed, encrypted record of the operation to an append-only audit log: signed with your own ML-DSA/SLH-DSA key so a verifier knows it came from you, encrypted to a separate auditor's public key so only they can read it, and hash-chained so deletion or reordering is detectable without the auditor's private key. Falls back to `audit_log`/`audit_key`/`audit_recipient` in the config file; not supported with `--recursive`. Verify a log with `pqfile audit-verify --auditor-key <AUDITOR_PRIVKEY> --operator-key <YOUR_VERIFYING_KEY> <LOG>`.

### Decryption

```bash
# Decrypt to default path (strips .pqf extension)
pqfile decrypt -k privkey.pem secret.txt.pqf

# Custom output path
pqfile decrypt -k privkey.pem secret.txt.pqf -o recovered.txt

# Decrypt chunks in parallel (only effective for v3/v5 chunked-format files)
pqfile decrypt -k privkey.pem large_file.bin.pqf --parallel

# Stdin/stdout pipeline
cat secret.txt.pqf | pqfile decrypt -k privkey.pem - -o -

# Passphrase-only decryption (v10 format)
pqfile decrypt --passphrase secret.txt.pqf

# Cap Argon2 resource usage when decrypting untrusted v10 files
pqfile decrypt --passphrase --max-kdf-mem 32 --max-kdf-time 2 secret.txt.pqf

# v10 file encrypted with a keyfile second factor
pqfile decrypt --passphrase --keyfile usb/token.bin secret.txt.pqf

# v10 file encrypted with a FIDO2 hardware token second factor
pqfile decrypt --passphrase --fido2 fido2-enrollment.txt secret.txt.pqf

# File written with `encrypt --stealth` (magic-free; cannot be auto-detected)
pqfile decrypt -k privkey.pem --stealth secret.txt.pqf

# File written with `encrypt --tlock-round`; fetches the beacon signature over
# the network and fails with a clear error if the round hasn't fired yet
pqfile decrypt --tlock secret.txt.pqf
```

### Time-locked encryption (drand beacon)

**Not a post-quantum guarantee**: the underlying [tlock](https://eprint.iacr.org/2023/189) scheme is BLS12-381 pairing-based (classical), layered on top of pqfile's usual authenticated, chunked payload. Requires building with the `tlock` cargo feature (off by default: pulls in the only network-capable dependencies in the workspace).

```bash
# Resolve a human time expression to a drand round number (fetches only the
# chain's public parameters, never a round's own beacon - safe for future rounds)
pqfile tlock round "24h"        # relative duration
pqfile tlock round "7d"
pqfile tlock round "2026-08-01T00:00:00Z"   # RFC 3339 datetime

# Encrypt: fully offline given a round number. No recipient key or passphrase.
pqfile encrypt --tlock-round 30438443 secret.txt

# Decrypt: fetches the target round's beacon signature (the only network call
# in the pqfile library). Fails cleanly if the round hasn't fired yet.
pqfile decrypt --tlock secret.txt.pqf
pqfile check --tlock secret.txt.pqf
```

Uses the League of Entropy mainnet `quicknet` chain by default; `--tlock-url` overrides the relay for `decrypt`/`check`. See [docs/FORMAT.md](docs/FORMAT.md) §5.12 for the wire format.

### FIDO2 hardware token second factor

**CLI**: requires building `pqfile-cli` with the `fido2` cargo feature (`cargo install pqfile-cli --features fido2`, or `cargo build --features fido2` from source); off by default so a normal build never needs USB HID system libraries (`libudev-dev` on Linux).

```bash
# Enroll a security key once: creates a non-resident CTAP2 credential
# requesting the hmac-secret extension and writes an enrollment file. Not
# sensitive on its own - reproducing the derived secret requires physically
# touching the same token - so it can be backed up like ordinary configuration.
pqfile fido2-enroll -o fido2-enrollment.txt

# If the token requires a PIN for this operation:
pqfile fido2-enroll -o fido2-enrollment.txt --pin
```

**Desktop GUI**: `pqfile-desktop` ships with this built in (no separate feature flag to pass). On the Encrypt or Decrypt tab, switch to Passphrase mode, then pick "FIDO2 token" under Second Factor and click "Enroll New Token…" the first time. Not available in the web (WASM) GUI - there is no browser-compatible USB HID backend, only the native `hidapi`-based one `pqfile-desktop` uses. See "WebAuthn PRF second factor" below for the web build's own equivalent.

Pass the enrollment file to `encrypt --fido2` / `decrypt --fido2` / `check --fido2` in place of `--keyfile`; the two are mutually exclusive. Each operation touches the token (and prompts for its PIN, if enrolled with one).

If the private key is passphrase-protected, the passphrase is prompted interactively. Works with v2 through v10 files (all single-recipient variants) and v4/v7/v8/v9 (multi-recipient).

### WebAuthn PRF second factor (web GUI only, currently disabled in the UI)

The browser-native equivalent of the FIDO2 second factor above, for the web build of `pqfile-gui` (no CTAP2/USB HID access exists in a browser). Uses the WebAuthn `prf` extension (`navigator.credentials` with a passkey) instead of raw CTAP2. No CLI surface (there is no browser in a terminal) and no cargo feature to build with - it's just part of the wasm32 build.

**Status: implemented but disabled in the Second Factor selector** ("Passkey" is greyed out with an explanatory tooltip). The implementation is complete and spec-correct - it matches the reference flow in Yubico's own PRF developer guide exactly, and the v10 format/library side is fully tested - but real-world browser/OS support for evaluating PRF (not just reporting it as present) turned out too inconsistent to enable as of mid-2026, confirmed by hands-on testing rather than assumed from documentation: Bitwarden's browser extension doesn't implement PRF for third-party sites at all (registration succeeds, `prf.enabled` correctly reports false); Windows Hello via Edge registers and reports `prf.enabled: true` but the follow-up secret derivation returns no output; Firefox fails at registration itself with a generic platform error. Revisit once this settles down - the second-factor selector's disabled branch is a one-line flip back to `ui.selectable_value(...)` once it does.

**Local testing note:** WebAuthn's relying-party ID must be a valid *domain string* - a raw IP address like `127.0.0.1` doesn't qualify (unlike for the separate secure-context check, where an IP is fine over plain HTTP on the same machine). If `trunk serve` prints both `http://127.0.0.1:8080/` and `http://localhost:8080/`, use the `localhost` one - `127.0.0.1` fails passkey registration with an "invalid domain" error.

### Check (verify a backup without writing plaintext)

```bash
# Run the full decrypt path into a null sink: every chunk's AEAD tag is verified,
# but no plaintext is written anywhere
pqfile check -k privkey.pem backup.tar.pqf
# OK: backup.tar.pqf authenticated (1048576 plaintext bytes)

# v10 passphrase-only files
pqfile check --passphrase secret.txt.pqf

# Verify chunks in parallel (only effective for v3/v5 chunked-format files)
pqfile check -k privkey.pem --parallel large_backup.tar.pqf

# Files written with `encrypt --stealth` (requires -k)
pqfile check -k privkey.pem --stealth secret.txt.pqf

# Scripting: exit code 0/1 plus structured JSON
pqfile --json check -k privkey.pem backup.tar.pqf
# {"status":"ok","input":"backup.tar.pqf","plaintext_bytes":1048576}
```

Useful for validating backups and testing that a key still decrypts a file, without producing a cleartext copy on disk.

### Rekey

```bash
# Re-wrap the session key under a new recipient key without decrypting the payload
pqfile rekey -k old_privkey.pem -r new_pubkey.pem -o new.pqf old.pqf
```

Decapsulates the session key with the old private key, re-encapsulates it under the new public key, and rewrites only the header. Payload bytes are not decrypted. Useful for key rotation.

### Rotate a whole directory tree

```bash
# Rekey every .pqf file under a directory (recursively) to a new recipient
pqfile rotate --old-key old_privkey.pem --new-key new_pubkey.pem --recursive backups/
```

A batch wrapper around `rekey`: walks the directory, rewrites each `.pqf` file in place, and prints a succeeded/failed/skipped-non-pqf summary. Inherits `rekey`'s own restrictions (v3/v5 input only, default chunk size only), so a file `rekey` can't handle is reported as a failure for that one file rather than aborting the whole batch - the command still exits non-zero if any file failed. Distinct from `archive --recursive`, which packs a tree into one `.pqfa` rather than rotating keys across many already-independent `.pqf` files.

### Revoke

```bash
# Create a revocation sidecar for a public key
pqfile revoke --key pubkey.pem --reason "Key compromised"
# Output: pubkey.pem.revoked

# pqfile encrypt will refuse to use a key that has a .revoked sidecar
```

### Change a key's passphrase

```bash
# Re-encrypt a private key under a new passphrase (prompts for old and new)
pqfile repassphrase -k privkey.pem

# Migrate a key created before pqfile 4.0 (legacy Argon2id p=1) to the current p=4 parameters
pqfile repassphrase -k privkey.pem --from-legacy
```

The key file is only overwritten after re-encryption succeeds; on error the original is untouched.

### Inspect

```bash
pqfile inspect secret.txt.pqf
```

For a single-recipient file (v2/v3):
```
Magic:              PQFL
Version:            0x03
KEM variant:        768 (ML-KEM-768)
Nonce:              3a7b...
Original file size: 2048 bytes
```

For a multi-recipient file (v4):
```
Magic:              PQFL
Version:            0x04 (multi-recipient)
Recipients:         2
  Recipient 0:      768 (ML-KEM-768)
  Recipient 1:      1024 (ML-KEM-1024)
Nonce:              8c2f...
Original file size: 2048 bytes
```

Files written by the current version set the authenticated-header bit (bit 7) on the version byte, so `inspect` shows `0x83` instead of `0x03`, and reports an extra `Auth. header: yes/no` line (`header_authenticated` in `--json` output). See [FORMAT.md section 4.4](docs/FORMAT.md) for what the bit authenticates. Stealth-mode files have no header and cannot be inspected.

### Digital signatures

```bash
# Generate a signing key pair (separate from encryption keys)
pqfile sign-keygen --out ./keys
# Writes: sign_pubkey.pem (1952 bytes), sign_privkey.pem (32-byte seed)

# Sign a file (produces a detached .sig file)
pqfile sign -k sign_privkey.pem document.pdf
# Output: document.pdf.sig

# Custom signature output path
pqfile sign -k sign_privkey.pem document.pdf -o document.sig

# Verify a signature
pqfile verify -k sign_pubkey.pem -s document.pdf.sig document.pdf

# Hash-based signatures for long-lived signing (FIPS 205)
pqfile sign-keygen --out ./keys --algorithm slh-dsa-shake-192f
```

Signatures default to ML-DSA-65 (NIST FIPS 204), 3309 bytes, stored in PEM format. The verifying key (1952 bytes) can be distributed alongside the signed content. `sign-keygen` also accepts `--passphrase` and `--hardware --label <LABEL>`, same as `keygen`.

`--algorithm slh-dsa-shake-192f` selects SLH-DSA-SHAKE-192f (NIST FIPS 205) instead: hash-based signatures resting on much more conservative security assumptions than lattices, at the cost of slower signing and 35664-byte signatures. Same NIST security category (3) as ML-DSA-65; best for very long-lived signatures such as archival or release signing. `sign`, `verify`, `signcrypt`, and `signdecrypt` detect the algorithm from the key automatically - no extra flags.

### Certificates

A minimal PKI layer over signing keys: a CA signing key attests to a subject public/verifying key's label, validity window, and permitted uses, so the certificate can be used in place of a raw key wherever pqfile accepts a recipient or verifying key.

```bash
# Issue a certificate: the CA vouches for a subject key
pqfile issue-cert --ca-key ca_sign_privkey.pem --subject pubkey.pem \
  --label "alice's laptop" --allow-encrypt --valid-days 365 -o alice.cert

# Verify a certificate and print its contents
pqfile verify-cert --ca-key ca_sign_pubkey.pem alice.cert

# Use a certificate directly as an encrypt recipient - no need to extract the key first
pqfile encrypt -r alice.cert --ca-key ca_sign_pubkey.pem document.pdf

# Certificates also work in place of a raw key for verify/signcrypt/signdecrypt
pqfile verify -k signer.cert --ca-key ca_sign_pubkey.pem -s document.pdf.sig document.pdf
```

Certificates do not chain and have no revocation mechanism beyond their own validity window, unless you also maintain a revocation list:

```bash
# Revoke a certificate before its validity window naturally expires
pqfile revoke-cert --ca-key ca_sign_privkey.pem alice.cert --reason "laptop lost" -o revocations.pem

# Revoking a second certificate appends to the same list and re-signs it
pqfile revoke-cert --ca-key ca_sign_privkey.pem bob.cert --existing revocations.pem \
  --reason "key rotated" -o revocations.pem

# Any command that accepts --ca-key for a certificate can also check --revocations
pqfile encrypt -r alice.cert --ca-key ca_sign_pubkey.pem --revocations revocations.pem document.pdf
pqfile verify-cert --ca-key ca_sign_pubkey.pem --revocations revocations.pem alice.cert
```

`--revocations` is optional everywhere it appears (`encrypt`, `verify`, `signcrypt`, `signdecrypt`, `seal`, `verify-cert`) - a certificate is accepted even without a matching entry when it is omitted, the same way `.revoked` sidecar checking for raw keys only happens when the sidecar file exists. There is no way to un-revoke a certificate; issue a new one instead. Full validity-window enforcement, `allowed_use` checks, and revocation list verification all happen before any recipient key is trusted or any signature is accepted.

### Signcrypt

```bash
# Sign and encrypt in one step; the signature is embedded inside the ciphertext
pqfile signcrypt -k sign_privkey.pem -r pubkey.pem document.pdf
# Output: document.pdf.pqf

# Custom output path
pqfile signcrypt -k sign_privkey.pem -r pubkey.pem document.pdf -o signed.pqf

# Decrypt and verify the embedded signature in one step
pqfile signdecrypt -k privkey.pem -v sign_pubkey.pem document.pdf.pqf
```

Unlike `pqfile sign` followed by `pqfile encrypt`, the signature lives inside the AEAD-authenticated payload and cannot be stripped or substituted after encryption. A recipient cannot re-encrypt the plaintext to a third party while preserving the sender's signature. Stdin is not supported as input because two passes over the file are required (one to hash, one to encrypt).

### Sealed sender

```bash
# One-time setup: each party generates a separate identity key pair
# (distinct from their encryption and signing keys)
pqfile identity-keygen --out ./alice-identity
pqfile identity-keygen --out ./bob-identity

# Alice seals a file for Bob: proves to Bob she sent it, without leaving
# evidence anyone else could check
pqfile seal -k alice-identity/identity_privkey.pem \
  --recipient-identity bob-identity/identity_pubkey.pem \
  -r bob-pubkey.pem document.pdf
# Output: document.pdf.pqf

# Bob unseals it: decrypts and verifies the sender in one step
pqfile unseal -k bob-privkey.pem \
  --identity-key bob-identity/identity_privkey.pem \
  -s alice-identity/identity_pubkey.pem document.pdf.pqf
```

Unlike `signcrypt`, which embeds a non-repudiable ML-DSA/SLH-DSA signature, sealed sender proves the sender's identity only to the specific intended recipient. The authentication tag is derived from a static X25519 Diffie-Hellman between the sender's and recipient's identity keys, so computing it requires only one party's private key plus the other's public key - the recipient could have forged an identical tag themselves, and no third party can ever confirm who really sent the file. Useful when the existence of a communication relationship is itself sensitive. `unseal` buffers the plaintext internally and only releases it once the tag verifies; stdin is not supported for `seal` (two passes are required, as with `signcrypt`).

### Steganographic key backup (`stego` cargo feature)

```bash
# Hide a (ideally passphrase-encrypted) private key inside a cover photo.
# Prompts for a passphrase that keys both detection and recovery. The cover
# can be PNG or JPEG; the output is always a lossless PNG, since LSB
# embedding cannot survive a JPEG re-encode.
pqfile bury --image vacation.jpg privkey.pem -o vacation-with-key.png

# Recover it later (prompts for the same passphrase; the recovered file is
# written atomically with owner-only permissions).
pqfile exhume vacation-with-key.png -o recovered-privkey.pem
```

`bury` embeds the file's bytes one bit per color-channel byte into the cover image's pixel data (least-significant-bit steganography). The passphrase keys *detection*, not just recovery: everything embedded after a random salt is encrypted with a keystream derived from the passphrase (Argon2id, then BLAKE3 subkeys for the keystream and a payload MAC), so there is no plaintext magic, length, or checksum an image scanner could look for, and `exhume` with the wrong passphrase fails identically to `exhume` on an ordinary photo. Useful as an offline backup that doesn't look like a key backup, e.g. among ordinary photos on a drive. This is a plausible-deniability mechanism, not a steganalysis-hardened one: bits are placed sequentially rather than scattered, so a dedicated statistical attack on the image's LSB noise could in principle flag that *something* is embedded, even though it cannot confirm or recover *what*. Requires building with `--features stego` (off by default, since it pulls in an image-codec dependency tree a normal build doesn't need).

### Forward error correction for cold storage (`fec` cargo feature)

```bash
# Write a Reed-Solomon parity sidecar alongside the ciphertext.
pqfile encrypt -r pubkey.pem --fec secret.txt
# -> secret.txt.pqf, secret.txt.pqf.fec

# Later, repair bit rot using the sidecar before the normal authenticated decrypt runs.
pqfile decrypt -k privkey.pem --fec secret.txt.pqf
pqfile check -k privkey.pem --fec secret.txt.pqf
```

AEAD authentication is all-or-nothing: a single flipped bit anywhere in a chunk fails that chunk's tag with no way to recover past it - correct behavior against tampering, but also the failure mode for ordinary bit rot on optical media, aging cloud storage, or a flaky transfer. `--fec` adds classical Reed-Solomon BCH error *correction* (not just detection) over fixed 128-byte blocks of the raw ciphertext bytes, 8 ECC bytes each, correcting up to 4 corrupted bytes anywhere in a block without knowing their positions in advance - the same ratio [Picocrypt](https://github.com/Picocrypt/Picocrypt) uses, tolerating roughly 3% corruption before giving up. Parity lives in a separate sidecar file, never inside the `.pqf` file itself, computed as a post-pass with no awareness of `.pqf` structure at all - which is what lets it protect the header too, and apply uniformly to every format version. A block beyond the correctable bound is left untouched rather than erroring, so genuine tampering (or unrepairable corruption) still fails the normal authentication check exactly as it would without this feature - FEC only ever restores exact original bytes or gets out of the way. Not supported with stdin/stdout, since a real sidecar file is needed on both sides. Requires building with `--features fec` (off by default at the library level; on by default in `pqfile-gui`, since it has no platform restriction and no heavy dependency tree).

### Encrypted audit log (`audit` cargo feature)

```bash
# One-time setup: a signing key for you, and a keypair for the auditor.
pqfile sign-keygen --out ./me
pqfile keygen --out ./auditor

# Every encrypt/decrypt appends a signed, encrypted record.
pqfile encrypt -r pubkey.pem --audit-log audit.log \
  --audit-key me_sign_privkey.pem --audit-recipient auditor_pubkey.pem secret.txt
pqfile decrypt -k privkey.pem --audit-log audit.log \
  --audit-key me_sign_privkey.pem --audit-recipient auditor_pubkey.pem secret.txt.pqf

# The auditor verifies the whole log end to end.
pqfile audit-verify --auditor-key auditor_privkey.pem \
  --operator-key me_sign_pubkey.pem audit.log
```

Each event (timestamp, command, a BLAKE3 file fingerprint, a key fingerprint) is signed with your own ML-DSA/SLH-DSA key - so a verifier knows it came from you - then encrypted to a separate auditor's ML-KEM public key, so only the auditor can read what happened. A hash chain links each record to the previous *signed* record, letting anyone holding your verifying key detect silent deletion or reordering without ever needing the auditor's private key. Since you can't decrypt your own log back, a small non-secret `<log>.chainhash` file (just a BLAKE3 hash, not sensitive) tracks the chain's tip between invocations; `audit-verify` doesn't need it at all, since it recomputes the chain from scratch while decrypting. All three of `--audit-log`/`--audit-key`/`--audit-recipient` must be set together (or use the `audit_log`/`audit_key`/`audit_recipient` config-file defaults); not supported with `--recursive`, since resolving a fresh signing-key passphrase per file in a batch would be worse than just disallowing the combination. Scoped to `encrypt`/`decrypt` only. Requires building with `--features audit` (off by default; native-only in `pqfile-gui`, since an append-only log needs real persistent storage the web build's download-only model can't provide).

The chain check alone catches deletion or reordering of any entry that's followed by another one, but not a whole entry deleted off the *end* of the log (a truncated log is still internally consistent up to wherever it stops) - the co-located `<log>.chainhash` file shares the log's own trust boundary, so it can't help here either. Every `audit-verify` run prints a `tip:` line with the log's actual final chain hash; pass it back in as `--expect-tip <HEX>` on your next verification (kept somewhere the operator alone can't also silently rewrite) to additionally catch that case.

### Archive and extract

```bash
# Pack multiple files into a single encrypted archive
pqfile archive -r pubkey.pem file1.txt file2.txt report.pdf -o bundle.pqf

# Strip a directory prefix so entries use relative paths
pqfile archive -r pubkey.pem --base ./project/ ./project/src/main.rs ./project/README.md

# Pack an entire directory tree (entry names keep the directory prefix, like tar)
pqfile archive -r pubkey.pem --recursive ./project -o project.pqf

# List archive contents without extracting
pqfile extract bundle.pqf -k privkey.pem --list

# Extract to a directory (default: current directory)
pqfile extract bundle.pqf -k privkey.pem -o recovered/
```

Archives use the PQFA format: a streaming authenticated payload where the plaintext is a structured entry sequence. Each entry stores the original relative path and file data. All AEAD authentication is verified before any file is written to disk. Path traversal attempts (entries containing `..`) are rejected. `--recursive` rejects symlinks and special files (devices, FIFOs, sockets) during the walk, and entry names that collide — including case-insensitively, which would overwrite each other when extracted on Windows or macOS — are rejected at pack time.

### Threshold key splitting (Shamir)

```bash
# Split a private key into 3 shares, any 2 of which can reconstruct it
pqfile split-key --threshold 2 --shares 3 privkey.pem --out ./shares/
# Writes: shares/share_1.pem, shares/share_2.pem, shares/share_3.pem

# Reconstruct the private key from any 2 of the 3 shares
pqfile reconstruct-key shares/share_1.pem shares/share_3.pem --out ./recovered/
# Writes: recovered/privkey.pem, recovered/pubkey.pem
```

Uses GF(256) Shamir secret sharing over the 64-byte private key seed. Any `threshold` shares reconstruct the key; fewer than `threshold` shares reveal nothing about the seed. Useful for key escrow, disaster recovery, or organizational workflows requiring multi-party approval to access protected data.

### Diagnostics

```bash
# Inspect a private key file (passphrase status, hardware, legacy p=1, revocation)
pqfile doctor privkey.pem

# Inspect a .pqf file (version, KEM info, header sanity, no decryption needed)
pqfile doctor secret.txt.pqf

# JSON output for scripting
pqfile --json doctor privkey.pem

# Benchmark Argon2id on this machine and recommend --kdf-mem / --kdf-time values
# hitting a target wall-clock time (default 250 ms) for v10 passphrase encryption
pqfile doctor --calibrate
pqfile doctor --calibrate --target-ms 500
```

`doctor` and `inspect` also warn (never fail) if a single-recipient file's KEM variant or a key's algorithm is on pqfile's algorithm-distrust list - empty today, since no supported algorithm has been judged untrustworthy yet.

Calibration scales the memory cost first (64 MiB floor — the compiled-in default — up to a 1 GiB ceiling), then the time cost. It never recommends parameters weaker than the defaults: a fast machine gets stronger parameters, a slow machine simply gets the defaults back.

### Config file

Routine commands can drop the `-r`/`-k` flags by setting defaults in a config file — `~/.config/pqfile/config.toml` (`$XDG_CONFIG_HOME` respected) or `%APPDATA%\pqfile\config.toml` on Windows:

```toml
# Default recipient for `encrypt`: a pqf1… string or a pubkey.pem path
recipient = "pqf1abc..."
# Default private key for `decrypt` and `check`
key = "/home/me/.keys/privkey.pem"
# Default --audit-log / --audit-key / --audit-recipient (requires the `audit` build feature; all three or none)
audit_log = "/home/me/.pqfile/audit.log"
audit_key = "/home/me/.keys/sign_privkey.pem"
audit_recipient = "/home/me/.keys/auditor_pubkey.pem"

# Named recipient sets: pass the group name to -r and it expands to every
# member (mixing pqf1… strings and pubkey.pem/certificate paths freely).
[groups]
team-security = ["pqf1aaa...", "pqf1bbb...", "/home/me/.keys/carol_pubkey.pem"]
```

With this in place, `pqfile encrypt notes.txt` and `pqfile decrypt notes.txt.pqf` just work, and `pqfile encrypt -r team-security notes.txt` fans out to every member of the group. Explicit flags always override the config. Pass the global `--no-config` flag to ignore the file entirely (recommended in scripts). A malformed config is a hard error, never silently ignored. Only `key = "value"` pairs, the `[groups]` table (`name = ["value", ...]` string arrays), `#` comments, and `\\`/`\"` escapes are accepted; group expansion is one level deep (a group member that names another group is passed through literally, not expanded further).

### Shell completions

```bash
pqfile completions bash   >> ~/.bash_completion
pqfile completions zsh    > ~/.zfunc/_pqfile
pqfile completions fish   > ~/.config/fish/completions/pqfile.fish
pqfile completions powershell >> $PROFILE
```

### Man page

```bash
pqfile man > /usr/local/share/man/man1/pqfile.1
```

Generates a roff man page covering every subcommand via `clap_mangen`; no cargo feature needed.

### Update check (`update-check` cargo feature)

```bash
pqfile check-update
# A newer version is available: v4.4.0 (you have v4.3.1).
# https://github.com/dangel34/PQ-File-Encryption/releases/tag/v4.4.0

pqfile --json check-update
# {"status":"ok","current_version":"4.3.1","latest_version":"4.4.0","update_available":"true"}
```

Queries the GitHub Releases API and compares the tag against this binary's own version. Never downloads or installs anything - it's a version comparison and a link, nothing more. Requires building with `--features update-check` (off by default, reaching the same `ureq` dependency `tlock` uses - still the only network-capable crate in the workspace - via a second, independent opt-in feature), but is compiled into the published release binaries so a normal download has it; even then it never runs unless invoked explicitly. The desktop GUI has the same check as a "Check for Updates now" button in Settings, alongside an opt-in "Check for updates on startup" toggle (off by default too, so nothing calls home without the user asking first).

### JSON output

Every command accepts a global `--json` flag for machine-readable output:

```bash
pqfile --json keygen --out ./keys
# {"status":"ok","pubkey_path":"./keys/pubkey.pem","privkey_path":"./keys/privkey.pem","fingerprint":"21:f3:b4:..."}

pqfile --json inspect file.pqf
pqfile --json encrypt -r pubkey.pem file.txt
pqfile --json decrypt -k privkey.pem file.txt.pqf
pqfile --json sign -k sign_privkey.pem file.txt
pqfile --json verify -k sign_pubkey.pem -s file.txt.sig file.txt
```

Errors go to stderr as `{"status":"error","code":N,"message":"..."}`. The numeric `code` field maps to `PqfileError` variants; see `docs/ERROR_CODES.md` for the stable code table. Exit code is always 1 on error.

---

## GUI

The desktop GUI (`pqfile-desktop`) and web app (`pqfile-gui`) share the same egui code and expose nearly everything the CLI does, each tab with built-in "?" help text:

- **🗝 Keys**: a persistent registry of key pairs with fingerprints and quick-load buttons for the Encrypt/Decrypt tabs, plus collapsible "Change Passphrase" and "Revoke Key" sections (native only), an "Issue / Verify / Revoke Certificate" panel for the CA certificate workflow, and a "Steganographic Key Backup" panel (Bury/Exhume, `stego` cargo feature, on by default) for hiding a file inside a cover image under a passphrase that keys detection itself
- **🔑 Keygen**: generates ML-KEM-512/768/1024, hybrid X25519+ML-KEM-768, ML-DSA-65, or SLH-DSA-SHAKE-192f signing key pairs, with optional passphrase or hardware-backed (OS credential store) protection, key expiry dates, and OpenSSH ed25519 key import (native only)
- **🔒 Encrypt**: multi-file batch encryption to one or more recipients; 2+ recipients automatically use the anonymous v8 format (toggle "pad recipient count" for v9); optional zstd compression for single-recipient files; checkboxes for Padme length padding, magic-free stealth mode (single recipient), and a Reed-Solomon error-correction sidecar for cold-storage resilience (`fec` cargo feature, on by default); a folder watcher that auto-encrypts new files (native only); drag-and-drop; a **Passphrase** mode (no key pair required, v10 format) with a Second Factor selector - Keyfile (both builds), FIDO2 hardware token (`pqfile-desktop` only), or Passkey/WebAuthn PRF (web build only, currently disabled pending browser support)
- **🔓 Decrypt**: loads any v2-v10 `.pqf` file, prompting for a passphrase only when the key requires one; the same **Passphrase** mode and Second Factor selector as Encrypt for v10 files; a "Stealth mode" checkbox for files encrypted without a header; auto-repairs from a `.fec` sidecar next to the loaded file when present (native only); includes **Rekey** (re-wrap a file for a new recipient without decrypting the payload) and **Add Recipient** (append a recipient to an existing v4/v7/v8 multi-recipient file) sub-tabs
- **✏ Sign** / **🔏 Signcrypt**: sign and verify with ML-DSA-65 or SLH-DSA-SHAKE-192f (algorithm detected from the loaded key, shown inline), plus combined sign-then-encrypt and decrypt-then-verify
- **🕶 Sealed Sender**: generate a separate X25519 identity key pair, then seal (encrypt with deniable sender authentication) and unseal files - proves the sender to the specific recipient without producing evidence a third party could ever check
- **📦 Archive**: pack multiple files into one encrypted `.pqf` container and extract with path-traversal protection
- **🔀 Shamir**: split a private key into M-of-N shares (with QR code export for air-gapped transfer) and reconstruct from shares
- **🔍 Inspect**: header metadata for any `.pqf` file, or a key-file health check (passphrase/hardware status, expiry, legacy Argon2 detection, revocation sidecar), without decrypting
- **📋 Clipboard**: encrypt/decrypt short text snippets without writing to disk, with an optional auto-clear timer
- **⚙ Settings**: theme, default output directory, confirm-before-overwrite, clipboard auto-clear, (native, `audit` cargo feature, off by default) an audit-log section - log path, your signing key, the auditor's public key, and an in-memory-only signing-key passphrase - that engages automatically once all three paths are set, and (native, `update-check` cargo feature) an opt-in "Check for updates on startup" toggle plus a "Check for Updates now" button that works regardless of the toggle

Hardware-backed keys, the folder watcher, SSH key import, passphrase change, and revocation are native-only (not available in the WASM build, which cannot access the OS credential store or filesystem watch APIs). The update check is also native-only, but for a different reason: it has no `ureq` target for wasm32, and a web app is always whatever's currently deployed, so a version check makes no sense there anyway.

---

## Language bindings

All three wrap the same core single-recipient `keygen`/`encrypt`/`decrypt` streaming path and produce/read the same `.pqf` wire format as the CLI/GUI, so files are interchangeable in every direction. None is a Cargo workspace member - all three are excluded from the root `Cargo.toml` (like `fuzz/`) so a plain `cargo build --workspace` never needs Python, Node.js, or Android/iOS toolchains. Multi-recipient encryption, signing, Shamir sharing, and certificates aren't exposed in any of them yet - see `docs/ROADMAP.md`, "Python, Node.js, and mobile bindings", for status.

### Python (`pqfile-python/`)

Built with [PyO3](https://pyo3.rs) / [maturin](https://www.maturin.rs). Published on [PyPI as `pqfile`](https://pypi.org/project/pqfile/) - `pip install pqfile`, prebuilt wheels for Windows/macOS/Linux.

```python
import pqfile

pub_pem, priv_pem = pqfile.keygen()  # or keygen_hybrid(), or keygen(level=512/1024)
ciphertext = pqfile.encrypt_bytes(pub_pem, b"hello, post-quantum world")
pqfile.decrypt_bytes(priv_pem, ciphertext)  # b"hello, post-quantum world"

pqfile.encrypt_file(pub_pem, "report.pdf", "report.pdf.pqf")  # streams; flat memory use
```

See [pqfile-python/README.md](pqfile-python/README.md) for the full API and build instructions.

### Node.js (`pqfile-node/`)

Built with [napi-rs](https://napi.rs). Published on [npm as `@dangel34/pqfile`](https://www.npmjs.com/package/@dangel34/pqfile) - `npm install @dangel34/pqfile` (the unscoped `pqfile` is blocked as too similar to the existing `vfile` package). Every function returns a `Promise` and runs on libuv's worker thread pool rather than blocking Node's event loop. Prebuilt binary currently covers Windows only - see `pqfile-node/README.md` for the macOS/Linux status.

```js
const pqfile = require("@dangel34/pqfile");

const { publicKey, privateKey } = await pqfile.keygen(); // or keygenHybrid(), or keygen(512/1024)
const ciphertext = await pqfile.encryptBytes(publicKey, Buffer.from("hello, post-quantum world"));
await pqfile.decryptBytes(privateKey, ciphertext); // <Buffer ...> "hello, post-quantum world"

await pqfile.encryptFile(publicKey, "report.pdf", "report.pdf.pqf"); // streams; flat memory use
```

See [pqfile-node/README.md](pqfile-node/README.md) for the full API and build instructions.

### Mobile: Kotlin / Swift (`pqfile-mobile/`)

Built with [uniffi-rs](https://mozilla.github.io/uniffi-rs/) (the same tool Firefox uses for its Android/iOS bindings), generating both languages from one Rust interface definition. Every function is synchronous - there's no single async runtime shared by Kotlin coroutines and Swift's `async`/`await`, so callers dispatch off the main thread themselves, same as any other blocking native call.

**The Rust binding layer is built and tested (`cargo test`, 7 passing cases) and `uniffi-bindgen` generates valid Kotlin and Swift source from it; the Android/iOS packaging (cross-compiled `.so`/XCFramework, Gradle/SPM distribution) is not done** - it needs the Android NDK and a macOS/Xcode machine respectively, neither available in this repo's dev environment. See [pqfile-mobile/README.md](pqfile-mobile/README.md) for exactly what's verified versus what's left.

---

## The .pqf file format

There are ten format versions (v2 through v11, the last gated behind the `tlock` cargo feature). The version byte at offset 4 selects the layout. Files written by the current version additionally set bit 7 of the version byte (`VERSION_AUTH_BIT`, so `0x83` = v3 layout with an authenticated header): the chunk-0 key commitment then also binds the header fields that were previously malleable (chunk size, compression algorithm, v10 Argon2id parameters, v11 chain hash/round). Older pqfile versions reject bit-carrying files with `UnsupportedVersion`; files written by pqfile 4.2.4 and earlier remain fully readable. Two features layer on top of these versions without a version bump: stealth mode (no magic, version, or KEM variant field at all) and Padme plaintext-length padding. Byte-level details for all of this live in [docs/FORMAT.md](docs/FORMAT.md) (sections 4.4, 5.10, 5.11, and 5.12).

### v2: single-recipient, whole-file AEAD

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x02
5        2         KEM variant (u16 little-endian): 768, 1024, or 0x0301 (hybrid)
7        CT_LEN    KEM ciphertext (encapsulated session key)
7+CT     12        ChaCha20-Poly1305 nonce
7+CT+12  8         Original plaintext size (u64 little-endian)
────     N+16      Encrypted payload; header used as AEAD additional data
```

### v3: single-recipient, chunked STREAM

Same header as v2 with `version = 0x03`. The payload is split into 64 KiB chunks. Each chunk's nonce is `base_nonce[8] || counter[4]` and its AAD is `"pqfile" || counter[4] || is_last[1]`. The last-chunk flag prevents truncation; the counter prevents reordering.

### v4: multi-recipient, chunked STREAM

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x04
5        2         Recipient count N (u16 little-endian)
─── Per recipient (repeated N times) ───────────────────────────────
         2         KEM variant (u16 little-endian)
         CT_LEN    KEM ciphertext for this recipient
         48        AES-256-GCM wrapped session key (32-byte key + 16-byte tag)
─── Shared tail ────────────────────────────────────────────────────
         12        Base nonce (8 random bytes || 4 zero bytes)
         8         Original plaintext size (u64 little-endian)
─── Payload ────────────────────────────────────────────────────────
         …         Chunked STREAM identical to v3, keyed by the session key
```

A random 32-byte session key K encrypts the payload. Each recipient's `ss` (from their KEM encapsulation) wraps K under `AES-256-GCM(key=ss, nonce=zero)`. The zero nonce is safe because each `ss` is unique per encapsulation. Mixed KEM variants within one file are supported.

### v5: single-recipient, configurable chunk size

Same header as v3 with `version = 0x05`, extended by four bytes immediately after the original-size field:

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x05
5        2         KEM variant (u16 little-endian)
7        CT_LEN    KEM ciphertext
7+CT     12        ChaCha20-Poly1305 nonce
7+CT+12  8         Original plaintext size (u64 little-endian)
7+CT+20  4         Chunk size (u32 little-endian, 1-268435456 bytes)
```

Produced when `--chunk-size` is passed to override the default 64 KiB (or the adaptive default). The chunk size is stored in the header so the decryptor reads it automatically without any extra flag.

### v6: single-recipient, compress-then-encrypt

Same header as v5 with `version = 0x06`, extended by one byte after the chunk-size field:

```
Offset   Length    Field
------   ------    -----
0        ...       Same as v5 through chunk size
7+CT+24  1         Compression algorithm (0x00 = none, 0x01 = zstd)
```

Produced when `--compress` is passed. The plaintext is compressed with zstd before encryption. Decompression is automatic on decrypt after AEAD verification, with output capped at the declared original size to prevent decompression-bomb memory exhaustion. Only supported with a single recipient.

### v7: anonymous multi-recipient

Like v4 but all KEM ciphertext slots are padded to 1568 bytes (the ML-KEM-1024 ciphertext length) and recipient entries are written in randomized order.

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x07
5        2         Recipient count N (u16 little-endian)
--- Per recipient (repeated N times) ----------------------------
         2         KEM variant (u16 little-endian)
         1568      KEM ciphertext padded to 1568 bytes (trailing bytes are zero)
         48        AES-256-GCM wrapped session key (32-byte key + 16-byte tag)
--- Shared tail -------------------------------------------------
         12        Base nonce (8 random bytes || 4 zero bytes)
         8         Original plaintext size (u64 little-endian)
--- Payload -----------------------------------------------------
         ...       Chunked STREAM identical to v4, keyed by the session key
```

The decryptor reads 1568 bytes per entry and truncates to the actual ciphertext length for the declared variant before decapsulation. Entries are shuffled before writing so an observer cannot determine recipient count, order, or key types in use.

### v8: variant-blind anonymous multi-recipient

Like v7 but the per-slot KEM variant field is removed entirely. All entries are a uniform 1616 bytes (1568 KEM ciphertext + 48 wrapped session key). An observer cannot infer the key type from the ciphertext length. This is the format the GUI's Encrypt tab uses automatically once 2 or more recipients are added.

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x08
5        2         Recipient count N (u16 little-endian)
--- Per recipient (repeated N times) ----------------------------
         1568      KEM ciphertext padded to 1568 bytes (no variant field)
         48        AES-256-GCM wrapped session key
--- Shared tail -------------------------------------------------
         12        Base nonce
         8         Original plaintext size (u64 little-endian)
--- Payload -----------------------------------------------------
         ...       Chunked STREAM identical to v4
```

### v9: padded anonymous multi-recipient

Like v8 but the slot count is rounded up to the next power of two (1, 2, 4, 8, ...) by appending random dummy entries. The decryptor tries each slot and skips failures silently. An observer learns only that there are a power-of-two number of slots.

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x09
5        2         Padded slot count N (u16 little-endian, next power of two)
--- Per slot (repeated N times; some are random dummy entries) ---
         1568      KEM ciphertext or random bytes
         48        Wrapped session key or random bytes
--- Shared tail -------------------------------------------------
         12        Base nonce
         8         Original plaintext size (u64 little-endian)
--- Payload -----------------------------------------------------
         ...       Chunked STREAM identical to v8
```

### v10: passphrase-only

No KEM step. The 32-byte session key is derived from a passphrase via Argon2id. Parameters are stored in the header (unlike private-key wrapping, which uses fixed parameters) because the recipient did not choose them.

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x0A
5        16        Salt (random, for Argon2id)
21       4         M_KIB (u32 little-endian; Argon2id memory in kibibytes)
25       4         T_COST (u32 little-endian; Argon2id time cost)
29       4         P_COST (u32 little-endian; Argon2id parallelism)
33       12        Base nonce (bytes 8-11 are 0x00)
45       8         Original plaintext size (u64 little-endian, informational)
--- Payload -----------------------------------------------------
53       ...       Chunked STREAM identical to v3, keyed by Argon2id output
```

**Security note:** M_KIB, T_COST, and P_COST are attacker-controlled fields. Decryptors must cap these before deriving. `decrypt_stream_passphrase` enforces a default ceiling (64 MiB / t=3); `decrypt_stream_passphrase_with_limits` accepts caller-specified ceilings. Exceeding the ceiling returns `PqfileError::KdfLimitExceeded`. The CLI exposes `--max-kdf-mem` and `--max-kdf-time`.

### v11: time-locked (`tlock` cargo feature)

No KEM step and no recipient key pair. The session key is derived from a random 16-byte seed that is itself locked via [tlock](https://eprint.iacr.org/2023/189) identity-based encryption against a target drand beacon round - not a post-quantum guarantee (the underlying scheme is BLS12-381 pairing-based), but layered on top of the same authenticated, chunked payload as every other format.

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x8B (always carries the authenticated-header bit)
5        32        drand chain hash
37       8         Target beacon round (u64 big-endian)
45       4         tlock ciphertext length (u32 little-endian)
49       var       tlock IBE ciphertext (locks the 16-byte seed to the round)
--- Shared tail -------------------------------------------------
         12        Base nonce (bytes 8-11 are 0x00)
         8         Original plaintext size (u64 little-endian, informational)
--- Payload -----------------------------------------------------
         ...       Chunked STREAM identical to v3, keyed by HKDF-SHA256(seed)
```

Defaults to the League of Entropy mainnet `quicknet` chain. Off by default: pulls in the only network-capable dependencies in the workspace (`tlock`, `drand_core`), so a normal build never gains an HTTP stack. See [docs/FORMAT.md](docs/FORMAT.md) §5.12.

### KEM variant field

| Value    | Algorithm               | CT bytes | EK bytes |
|----------|-------------------------|----------|----------|
| `512`    | ML-KEM-512              | 768      | 800      |
| `768`    | ML-KEM-768              | 1088     | 1184     |
| `1024`   | ML-KEM-1024             | 1568     | 1568     |
| `0x0301` | Hybrid X25519+ML-KEM-768| 1120     | 1216     |

See [docs/FORMAT.md](docs/FORMAT.md) for the byte-level specification (also exercised as executable documentation by `pqfile/tests/vectors.rs`).

---

## PEM key formats

### ML-KEM-512

```
-----BEGIN ML-KEM-512 PUBLIC KEY-----          (800 bytes raw)
-----BEGIN ML-KEM-512 PRIVATE KEY-----         (64-byte seed)
-----BEGIN ML-KEM-512 ENCRYPTED PRIVATE KEY--- (16-byte salt || 12-byte nonce || 80-byte AES ciphertext)
```

### ML-KEM-768

```
-----BEGIN ML-KEM-768 PUBLIC KEY-----          (1184 bytes raw)
-----BEGIN ML-KEM-768 PRIVATE KEY-----         (64-byte seed)
-----BEGIN ML-KEM-768 ENCRYPTED PRIVATE KEY--- (16-byte salt || 12-byte nonce || 80-byte AES ciphertext)
```

### ML-KEM-1024

```
-----BEGIN ML-KEM-1024 PUBLIC KEY-----         (1568 bytes raw)
-----BEGIN ML-KEM-1024 PRIVATE KEY-----        (64-byte seed)
-----BEGIN ML-KEM-1024 ENCRYPTED PRIVATE KEY-- (same layout as above)
```

### Hybrid X25519+ML-KEM-768

```
-----BEGIN X25519+ML-KEM-768 PUBLIC KEY-----         (X25519 pubkey 32 || ML-KEM EK 1184 = 1216 bytes)
-----BEGIN X25519+ML-KEM-768 PRIVATE KEY-----        (X25519 scalar 32 || ML-KEM seed 64 = 96 bytes)
-----BEGIN X25519+ML-KEM-768 ENCRYPTED PRIVATE KEY-- (16-byte salt || 12-byte nonce || 112-byte AES ciphertext)
```

### ML-DSA-65 / SLH-DSA-SHAKE-192f (signing only)

```
-----BEGIN ML-DSA-65 VERIFYING KEY-----             (1952 bytes raw)
-----BEGIN ML-DSA-65 SIGNING KEY-----               (32-byte seed)
-----BEGIN ML-DSA-65 SIGNATURE-----                 (3309 bytes raw)
-----BEGIN SLH-DSA-SHAKE-192F VERIFYING KEY-----    (48 bytes: PK.seed || PK.root)
-----BEGIN SLH-DSA-SHAKE-192F SIGNING KEY-----      (72-byte seed triple: SK.seed || SK.prf || PK.seed)
-----BEGIN SLH-DSA-SHAKE-192F SIGNATURE-----        (35664 bytes raw)
```

Signing keys can optionally be passphrase-protected (`pqfile sign-keygen --passphrase`) or hardware-backed (`--hardware --label <LABEL>`), the same as encryption keys. Without either, protect `sign_privkey.pem` with filesystem permissions (written 0600 on Unix by default) or disk encryption.

Passphrase-protected private keys derive their AES-256-GCM wrapping key via Argon2id (m=64 MiB, t=3, p=4, 16-byte random salt). The private key stores only the seed (64 bytes for ML-KEM, 96 bytes for hybrid, 32 bytes for ML-DSA-65, 72 bytes for SLH-DSA); the full key is re-derived on load. Keys encrypted with older p=1 parameters (pre-4.0) can be migrated with `pqfile repassphrase --from-legacy`.

### Certificate and revocation list

```
-----BEGIN PQFILE CERTIFICATE-----                     (self-delimiting body + CA signature)
-----BEGIN PQFILE CERTIFICATE REVOCATION LIST-----      (self-delimiting body + CA signature)
```

Produced by `pqfile issue-cert` / `pqfile revoke-cert` respectively (see [Certificates](#certificates) above). Both wrap an ML-DSA-65 or SLH-DSA-SHAKE-192f signature (whichever algorithm the CA signing key uses) over a self-delimiting body - a certificate's body embeds the subject key's own PEM tag and bytes verbatim, so a verified certificate hands back a ready-to-use PEM without the caller needing to know the key type in advance. A revocation list's body is a sequence of `(cert_id, revoked_at, reason)` entries, where `cert_id` is SHA3-256 of a certificate's signed body - two certificates issued with byte-identical fields share an identifier.

### X25519 sealed-sender identity key

```
-----BEGIN X25519 IDENTITY PUBLIC KEY-----             (32 bytes raw)
-----BEGIN X25519 IDENTITY PRIVATE KEY-----            (32-byte scalar)
-----BEGIN X25519 IDENTITY ENCRYPTED PRIVATE KEY-----  (16-byte salt || 12-byte nonce || 48-byte AES ciphertext)
```

Generated by `pqfile identity-keygen`; consumed only by `pqfile seal`/`pqfile unseal` (see [Sealed sender](#sealed-sender) above). A separate key pair from every other key type on this page - never used for encryption or signing.

### Hardware key reference (stub)

```
-----BEGIN ML-KEM-768 HARDWARE KEY REFERENCE-----   (version byte || backend ID byte || label, UTF-8)
```

A small PEM stub identifying which OS credential store backend holds the actual seed and the label used to look it up. The seed itself never touches disk. One reference tag per key kind (ML-KEM-512/768/1024, hybrid, ML-DSA-65 signing, and SLH-DSA-SHAKE-192f signing).

### Shamir key share

```
-----BEGIN ML-KEM-768 KEY SHARE-----   (version || KEM variant || threshold || total || index || 16-byte pubkey fingerprint || share bytes)
```

Produced by `split-key`; `reconstruct-key` consumes `threshold` or more of these to recover the original private key.

---

## Error handling

All errors are reported to stderr with a descriptive message; exit code is 1. The GUI shows errors inline in red.

| Error variant          | Meaning                                                                   |
|------------------------|---------------------------------------------------------------------------|
| `Io`                   | File system or I/O failure                                                |
| `InvalidMagic`         | File does not start with "PQFL"                                           |
| `UnsupportedVersion`   | Version byte is not a supported value (0x02-0x0A, any of which may also carry the authenticated-header bit, e.g. 0x83; or 0x8B for v11 time-locked files, which always carries that bit, with the `tlock` feature) |
| `UnsupportedKem`       | KEM variant field is not a recognised value                               |
| `KemVariantMismatch`   | Private key KEM variant does not match the variant in the file header     |
| `EncryptionFailure`    | AEAD encryption or nonce generation failed                                |
| `DecryptionFailure`    | Authentication tag mismatch (file tampered or wrong key)                  |
| `InvalidPem`           | PEM file could not be parsed or has an unrecognised tag                   |
| `InvalidKeyLength`     | Decoded key bytes are the wrong length                                    |
| `OutputExists`         | Key file already exists and `--force` was not passed                      |
| `WrongPassphrase`      | Passphrase decryption of private key seed failed                          |
| `PassphraseRequired`   | Encrypted private key loaded but no passphrase supplied                   |
| `PassphraseMismatch`   | New passphrase and confirmation do not match                              |
| `InvalidSignature`     | Signature bytes are malformed                                             |
| `SignatureVerificationFailed` | Signature (ML-DSA-65 or SLH-DSA) does not match the file           |
| `NoMatchingRecipient`  | Multi-recipient file: no recipient entry matched the provided private key |
| `KeyRevoked`           | Key has an active `.revoked` sidecar and was refused for encryption       |
| `CompressionNotSupported` | Compressed (v6) file decrypted by a build without the `zstd` feature   |
| `LegacyKeyFormat`      | Key was encrypted with Argon2id p=1 (pre-4.0); run `repassphrase --from-legacy` |
| `ShareVerificationFailed` | Reconstructed Shamir key fingerprint does not match the share fingerprint |
| `Truncated`            | Stream ended without a final authenticated chunk; file was truncated      |
| `KdfLimitExceeded`     | v10 file's Argon2 parameters exceed the configured ceiling (memory or time cost) |
| `KeyfileRequired`      | v10 file was encrypted with a keyfile second factor; pass `--keyfile <PATH>` |
| `KeyfileNotRequired`   | `--keyfile` was passed but the file was not encrypted with one            |
| `UnsupportedHeaderFlags` | v10 header carries flag bits this build does not understand; upgrade pqfile |
| `Fido2Required`        | v10 file was encrypted with a FIDO2 hardware token second factor; pass `--fido2 <ENROLLMENT_FILE>` |
| `Fido2NotRequired`     | `--fido2` was passed but the file was not encrypted with one              |
| `CertNotValid`         | Certificate signature verified, but the check time falls outside its validity window |
| `CertUseNotPermitted`  | Certificate does not authorize the requested use (encrypt or sign)        |
| `TlockRoundNotReached` | Time-locked (v11) file's target drand round has not fired yet             |
| `TlockBeaconFetchFailed` | Fetching the drand beacon failed for a reason other than "not yet reached" |
| `TlockDecryptionFailed` | Beacon signature was fetched but tlock/AEAD decryption failed            |
| `WebauthnPrfRequired`  | v10 file was encrypted with a WebAuthn `prf` second factor                |
| `WebauthnPrfNotRequired` | A WebAuthn PRF output was supplied but the file uses a different second factor |
| `SealedSenderAuthFailed` | Sealed-sender deniable-authentication tag did not verify                |
| `CertRevoked`          | Certificate appears in a verified revocation list the caller chose to consult |
| `StegoCapacityExceeded` | `bury`'s cover image is too small to hold the payload                    |
| `StegoPayloadNotFound` | `exhume` found no valid embedded payload (wrong passphrase, wrong image, or edited/corrupted since burying) |
| `StegoInvalidImage`    | Cover or stego image could not be decoded/encoded (unsupported or corrupt format) |

The `#[non_exhaustive]` enum may gain new variants in minor releases; match with a wildcard arm. See [docs/ERROR_CODES.md](docs/ERROR_CODES.md) for the stable numeric code each variant maps to in `--json` output.

---

## Testing

```
cargo test --workspace --all-features
```

636 tests across all crates. Run benchmarks with:

```
cargo bench -p pqfile
```

The `async` feature's tests and the `pqfile/tests/wasm_smoke.rs` WASM smoke tests are excluded from a plain `cargo test --workspace`; use `--all-features` for the former and `wasm-pack test --node pqfile --test wasm_smoke` for the latter.

Key integration tests in `pqfile/tests/`:

| Test file | What it covers |
|-----------|----------------|
| `compat.rs` | Decrypts golden ciphertext files committed per format version against a known-good plaintext, catching any decryptor regression immediately |
| `property.rs` | `proptest`-based property tests for invariants that must hold across all inputs, not just hand-picked cases |
| `static_vectors.rs` | Pre-generated key/ciphertext constants proving round-trip decoding for every format version and KEM variant |
| `vectors.rs` | Encrypts a known plaintext and parses the output byte-by-byte against [docs/FORMAT.md](docs/FORMAT.md), acting as executable format documentation |
| `wasm_smoke.rs` | Encrypt/decrypt roundtrip, keygen, and wrong-key rejection compiled and run on the `wasm32` target via `wasm-pack test --node` |

Key integration tests in `pqfile-cli/tests/roundtrip.rs`:

| Test group | What it covers |
|------------|----------------|
| Basic roundtrip | keygen → encrypt → decrypt → byte-for-byte match |
| Custom paths | `-o` flag on encrypt and decrypt |
| Stdin/stdout | full pipe with `-` |
| Force overwrite | `--force` behaviour |
| Inspect | header fields displayed correctly, v3 version byte, invalid file |
| JSON output | all commands emit valid JSON; errors go to stderr |
| Recursive | directory encryption, skip `.pqf`, non-directory error |
| 1024-bit | ML-KEM-1024 encrypt/decrypt roundtrip and inspect |
| ML-DSA | sign-keygen, sign, verify, tamper detection, JSON output |
| SLH-DSA | keygen tags/lengths, sign/verify roundtrip, tampering, passphrase, signcrypt, repassphrase, CLI roundtrip |
| Hybrid | X25519+ML-KEM-768 roundtrip, passphrase, inspect, mismatch error |
| Multi-recipient | 2-key v4 roundtrip, 3-key v4, mixed variants, wrong key rejected |
| Doctor | key-file and `.pqf`-file health checks |
| Truncation / corruption | truncated and bit-flipped ciphertext both correctly rejected |
| Shell completions | bash/zsh/fish/powershell generation, unknown-shell error, subcommand coverage |

Every push and pull request also runs `cargo clippy`, `cargo fmt --check`, `cargo deny check`, `cargo vet check`, and `gitleaks`. A `cargo-mutants` mutation-testing job and a `cargo fuzz` run execute weekly on a schedule (and on manual dispatch) rather than per-push, since both are CPU-intensive (see `.github/workflows/`).

---

## Dependencies

### pqfile (core library)

| Crate            | Version | Purpose                                                       |
|------------------|---------|-----------------------------------------------------------------|
| ml-kem           | 0.3     | ML-KEM-512/768/1024 key encapsulation (FIPS 203)               |
| ml-dsa           | 0.1     | ML-DSA-65 digital signatures (FIPS 204)                        |
| slh-dsa          | 0.2.0-rc | SLH-DSA-SHAKE-192f hash-based signatures (FIPS 205)           |
| chacha20poly1305 | 0.11    | ChaCha20-Poly1305 authenticated encryption                     |
| aes-gcm          | 0.11    | AES-256-GCM (passphrase key wrapping, multi-recipient session key wrapping) |
| x25519-dalek     | 2       | X25519 Diffie-Hellman (hybrid mode)                             |
| hkdf             | 0.13    | HKDF-SHA256 key derivation (hybrid mode)                        |
| sha2             | 0.11    | SHA-256 (HKDF input)                                            |
| sha3             | 0.12    | SHA3-256 (FIPS 202) for key fingerprints and key commitment     |
| getrandom        | 0.4     | OS CSPRNG for nonces and key generation                         |
| zeroize          | 1       | Overwrite secret bytes on drop                                  |
| argon2           | 0.5     | Argon2id KDF for passphrase-protected keys                      |
| pem              | 3       | PEM encoding/decoding for key files                             |
| bech32           | 0.12    | Bech32m encoding/decoding for compact recipient strings (`pqf1…`) |
| rayon            | 1       | Parallel chunk processing (`--parallel`)                        |
| thiserror        | 2       | Custom error type derivation                                    |
| zstd             | 0.13    | Compression for v6 format (`--compress`)                        |
| memmap2          | 0.9     | Memory-mapped I/O for zero-copy encrypt (`--mmap`, native only)  |
| keyring-core     | 1       | Cross-platform OS credential store abstraction (hardware keys, native only) |
| windows-native-keyring-store | 1 | Windows Credential Manager backend (Windows only)         |
| apple-native-keyring-store   | 1 | macOS Keychain backend (macOS only)                       |
| linux-keyutils-keyring-store | 1 | Linux Secret Service backend (Linux only)                 |
| tokio            | 1       | Async runtime backing `async_io` (optional, feature `"async"`)  |
| memsec           | 0.7     | `mlock`/`VirtualLock` for in-flight secrets (`secret.rs`'s `LockedSecret`)  |
| libcrux-ml-kem   | 0.0.10  | Optional F*-verified ML-KEM backend (`kem-libcrux` feature); agrees byte-for-byte with the default RustCrypto `ml-kem` on FIPS 203, proven by a cross-implementation oracle test |

### pqfile-cli (CLI binary, additional to the above)

| Crate            | Version | Purpose                                                       |
|------------------|---------|-----------------------------------------------------------------|
| clap             | 4       | CLI argument parsing                                            |
| clap_complete    | 4       | Shell completion script generation                              |
| rpassword        | 7       | Secure passphrase prompting                                     |

### pqfile-gui / pqfile-desktop (shared GUI logic, WASM lib, and native shell)

| Crate                    | Version | Purpose                                              |
|--------------------------|---------|--------------------------------------------------------|
| eframe                   | 0.35    | egui app framework (native rlib + WASM cdylib)         |
| rfd                      | 0.17    | Native sync and WASM async file dialogs                |
| image                    | 0.25    | PNG decoding for icons and QR codes                     |
| qrcode                   | 0.14    | QR code generation (Shamir share air-gapped transfer)   |
| notify                   | 8       | Filesystem watcher for the Encrypt-tab folder watcher (native only) |
| winres                   | 0.1     | Embeds the app icon/metadata into the Windows binary (`pqfile-desktop` build-dependency) |
| wasm-bindgen             | 0.2     | Rust/WASM bindings (WASM only)                          |
| wasm-bindgen-futures     | 0.4     | Async bridge for WASM (WASM only)                       |
| web-sys                  | 0.3     | Browser DOM APIs for file download (WASM only)          |
| js-sys                   | 0.3     | JavaScript types for WASM (WASM only)                   |
| getrandom                | 0.4     | JS entropy source for WASM crypto (WASM only)            |
| console_error_panic_hook | 0.1     | Routes Rust panics to the browser console (WASM only)   |

All dependency versions and licenses are audited via `cargo deny check` and `cargo vet check`; see `deny.toml` and `supply-chain/`.

---

## Packaging

Every release (`vX.Y.Z` tag) automatically produces `.deb`, `.rpm`, and AppImage packages for Linux, an unsigned `.app`/DMG for macOS, and a Windows installer - see [docs/RELEASING.md](docs/RELEASING.md). **None of these are code-signed or notarized yet**: Windows SmartScreen and macOS Gatekeeper will both warn on first launch (macOS: right-click the app → Open once to bypass Gatekeeper). To build any of them locally instead of waiting for a release:

### Debian / Ubuntu

```
cargo install cargo-deb
cargo deb -p pqfile-cli
```

Produces a `.deb` package installing the binary to `/usr/bin/pqfile`.

### Fedora / RHEL

```
cargo install cargo-generate-rpm
cargo build --release -p pqfile-cli
cargo generate-rpm -p pqfile-cli
```

Pure Rust, no `rpmbuild`/`rpm-build` package needed. A traditional spec-file build also works if you prefer it: `cp target/release/pqfile ~/rpmbuild/BUILD/ && rpmbuild -bb pqfile-cli/packaging/pqfile.spec` (uses `pqfile-cli/packaging/pqfile.spec`, kept in sync with the crate version by `scripts/bump-version.ps1`).

### Linux AppImage

Requires [linuxdeploy](https://github.com/linuxdeploy/linuxdeploy) and its [appimage plugin](https://github.com/linuxdeploy/linuxdeploy-plugin-appimage) on `PATH`, plus `squashfs-tools`:

```
cargo build --release -p pqfile-desktop
linuxdeploy --appdir AppDir \
  --executable target/release/pqfile-desktop \
  --desktop-file pqfile-desktop/packaging/pqfile-desktop.desktop \
  --icon-file pqfile-desktop/assets/icon.png \
  --output appimage
```

### macOS

```
cargo build --release -p pqfile-desktop
mkdir -p pqfile.app/Contents/MacOS pqfile.app/Contents/Resources
cp target/release/pqfile-desktop pqfile.app/Contents/MacOS/
sed "s/@VERSION@/$(grep -m1 -oP '(?<=^version = ")[^"]+' pqfile-desktop/Cargo.toml)/" \
  pqfile-desktop/packaging/Info.plist.template > pqfile.app/Contents/Info.plist
# icon.icns: see the release workflow's "Build .app bundle and DMG" step for
# the sips/iconutil commands that generate one from pqfile-desktop/assets/icon.png
brew install create-dmg
create-dmg --no-code-sign pqfile.dmg pqfile.app/
```

### Windows

Requires [Inno Setup](https://jrsoftware.org/isinfo.php) and `iscc` on `PATH`:

```
cargo build --release -p pqfile-desktop
iscc pqfile-desktop\packaging\setup.iss
```

---

## Security considerations

- **Private keys must be kept confidential.** Anyone with `privkey.pem` (or access to a hardware-backed key's OS credential store entry) can decrypt any file encrypted to the corresponding public key.
- **Public keys can be shared freely.**
- **Each encryption is independent.** A fresh KEM ciphertext, fresh ephemeral X25519 scalar (hybrid mode), and fresh nonce are generated per file using the OS CSPRNG. Nonce reuse under the same symmetric key is structurally impossible.
- **The entire file is authenticated.** For v2, the full header is passed as AEAD additional data, so any header or payload modification fails decryption. For chunked formats (v3 onward), each chunk carries its own AEAD tag plus a position-binding counter and last-chunk flag, so truncation, reordering, and payload swapping are all detected.
- **Whole-file and async decrypt/encrypt paths are memory-bounded.** The v2 (whole-file) decrypt path and the optional `async` feature's encrypt/decrypt functions cap their internal buffering so a stream with an unbounded or oversized tail cannot force unbounded memory allocation.
- **Secret material is zeroized on drop.** The decapsulation key seed, shared secrets, session keys, Shamir shares, and passphrase-derived keys are wrapped in `Zeroizing<T>` from the `zeroize` crate. `x25519-dalek`, `ml-kem`, and `ml-dsa` are compiled with their `zeroize` features enabled. Small, long-lived secrets (session keys, KEM shared secrets, KDF output) additionally live in `mlock`ed (`VirtualLock` on Windows) heap memory via `secret.rs`'s `LockedSecret`, best-effort since unprivileged memory-lock quotas are small by default - a failed lock degrades to plain zeroize-on-drop rather than erroring.
- **Private key and Shamir share files are written with owner-only permissions (0600) on Unix.** Hardware-backed keys never touch disk at all; the seed lives only in the OS credential store, accessed via its byte-native secret API.
- **Multi-recipient security.** In v4/v7/v8/v9 formats, the file payload is encrypted with a single random 32-byte session key. Each recipient's copy of that key is wrapped under their KEM shared secret using AES-256-GCM (zero nonce; safe because the KEM shared secret is fresh and unique per encapsulation). A recipient with a non-matching key cannot distinguish a file addressed to them from one addressed to others; v9 additionally hides the true recipient count behind power-of-two padding.
- **Hybrid mode security.** The combined session key is `HKDF-SHA256(X25519_ss || ML-KEM_ss, info="pqfile-hybrid-v1")`. Security holds if either X25519 or ML-KEM is unbroken, not both.
- **Signing keys can optionally be passphrase-protected or hardware-backed**, the same as encryption keys. Without either, protect `sign_privkey.pem` with filesystem permissions (0600 by default) or disk encryption. Compromise of the signing key allows forged signatures but does not affect encryption key confidentiality.
- **The web GUI operates entirely in WebAssembly inside the browser.** No file data or key material is transmitted over the network, in either the CLI, the desktop GUI, or the WASM web build.
- **Fingerprints are informational.** SHA3-256(pubkey)[0:8] gives 64 bits. Suitable for display and manual comparison; not a cryptographic commitment. Always verify keys through a trusted channel.

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model, security invariants, and the responsible-disclosure process for reporting a vulnerability.
