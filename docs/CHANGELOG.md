# Changelog

All notable changes to pqfile are documented in this file. Versions follow semantic versioning. Breaking changes to the `.pqf` file format or key format always require a major version bump.

---

## [3.2.0] - 2026-05-21

### Added

- Key revocation: `pqfile revoke --key pubkey.pem --reason "..."` creates a `pubkey.pem.revoked` JSON sidecar containing the key fingerprint and reason. `pqfile encrypt` checks for a `.revoked` sidecar alongside each recipient public key and aborts with a clear error if one is found. The sidecar is a plain JSON file checked at encrypt time (not signed; signed revocation is a future roadmap item).
- Compress-then-encrypt (`--compress`, `--compress-level`): `pqfile encrypt --compress -r pubkey.pem file` compresses plaintext with zstd before encryption, producing a v6 `.pqf` file. `--compress-level <1-22>` (default 3) trades speed for ratio. Decompression is automatic on decrypt. Only supported with a single recipient (incompatible with multi-recipient v4 format). Not available in WASM builds (zstd requires C FFI). New format constants: `VERSION_V6 = 0x06`, `COMPRESSION_NONE = 0x00`, `COMPRESSION_ZSTD = 0x01`.
- Rekey without payload re-encryption: `pqfile rekey --key old_privkey.pem --recipient new_pubkey.pem -o out.pqf in.pqf` decapsulates the session key with the old private key, re-encapsulates it under the new public key, and rewrites only the header. Payload ciphertext bytes are streamed through unchanged. Produces a valid v4 `.pqf` file. Supported for v3 and v5 files with the default 64 KiB chunk size.
- `PqfReader<R: Read>`: a streaming decryptor that wraps any `R: Read` source and implements `Read`, yielding decrypted plaintext bytes incrementally. Supports v2, v3, v4, and v5 files. Exposes a `.info()` method returning `PqfInfo` (version, KEM variant, original size, chunk size). Each AEAD chunk is verified before plaintext bytes are yielded; a tampered chunk returns an I/O error. Available as a public library type in `pqfile::reader`.
- GUI compress checkbox (native only): an "compress before encrypting" checkbox on the Encrypt tab, enabled only when a single recipient is selected. A level slider (1-19) appears when compression is active.
- cargo-vet exemptions for `zstd 0.13.3`, `zstd-safe 7.2.4`, and `zstd-sys 2.0.16+zstd.1.5.7`.

---

## [3.1.0] - 2026-05-21

### Added

- ML-KEM-512 support: `pqfile keygen --level 512` generates ML-KEM-512 key pairs (EK 800 bytes, CT 768 bytes, seed 64 bytes). New PEM labels: `ML-KEM-512 PUBLIC KEY`, `ML-KEM-512 PRIVATE KEY`, `ML-KEM-512 ENCRYPTED PRIVATE KEY`. KEM variant value 512 stored as u16 in the file header. Decryption auto-detects from the header. Passphrase protection supported. Completes the full NIST FIPS 203 parameter set (512, 768, 1024).
- ML-KEM-512 level selector in the GUI keygen tab.
- v5 file format with configurable chunk size: `--chunk-size <bytes>` on `pqfile encrypt` stores the chunk size in the v5 header so the decryptor reads it automatically without any user flag. Supported range: 1 to 268,435,456 bytes. Default 64 KiB is unchanged; v3/v4 format is used when no `--chunk-size` flag is given.
- In-place AEAD in the streaming hot path: `encrypt_stream` and `encrypt_stream_multi` now call `encrypt_in_place_detached`, writing ciphertext into the existing plaintext buffer. `decrypt_v3_chunks` calls `decrypt_in_place_detached`, splitting the tag from the end of the chunk buffer. Zero heap allocations per chunk.
- Benchmark regression detection in CI: `cargo bench` results (bencher format) are fed to `benchmark-action/github-action-benchmark`. The baseline is stored on the `gh-pages` branch and updated automatically on pushes to main. PRs receive comment alerts when any benchmark regresses more than 10%.
- OSS-Fuzz integration files in `oss-fuzz/`: `project.yaml`, `Dockerfile`, and `build.sh` for submitting to the google/oss-fuzz project.
- Nightly fuzz CI job (`.github/workflows/fuzz.yml`): runs each libFuzzer target for 120 seconds and uploads crash artifacts on failure.
- `#[must_use]` annotations on all public `encrypt_*` and `decrypt_*` functions to prevent silently discarding results.
- `zeroize` dependency in `pqfile-gui` for secure clearing of passphrase fields on drop.

---

## [3.0.1] - 2026-05-20

### Added

- cargo-vet supply-chain vetting: `supply-chain/config.toml` records explicit safe-to-deploy or safe-to-run audit entries for every dependency in the tree. `cargo vet --locked` runs in CI on every push and PR to main. Any new dependency added without a corresponding exemption or audit entry fails CI.

---

## [3.0.0] - 2026-05-20

Breaking changes: v3 (streaming) and v4 (multi-recipient) file formats introduced. New PEM labels for ML-KEM-1024 and hybrid keys. Files produced by v2.x are still readable; v3.x cannot produce v2 files by default.

### Added

- ML-KEM-1024 support: `pqfile keygen --level 1024` generates ML-KEM-1024 key pairs (EK 1568 bytes, CT 1568 bytes). A u16 `kem_variant` field in the file header distinguishes 768 from 1024. New PEM labels: `ML-KEM-1024 PUBLIC KEY`, `ML-KEM-1024 PRIVATE KEY`, `ML-KEM-1024 ENCRYPTED PRIVATE KEY`. Private key seed remains 64 bytes. All existing 768 files remain decryptable.
- Hybrid X25519 + ML-KEM-768 key exchange: `pqfile keygen --hybrid` generates a combined key pair (KEM variant `0x0301`). Encryption performs X25519 DH and ML-KEM encapsulate independently, then derives the 32-byte session key via `HKDF-SHA256(IKM = x25519_ss || mlkem_ss, info = "pqfile-hybrid-v1")`. A fresh ephemeral X25519 scalar is generated per encryption. `pqfile inspect` shows the friendly variant name.
- ML-DSA-65 digital signatures (NIST FIPS 204): `pqfile sign-keygen --out <dir>` generates a signing key pair (`sign_pubkey.pem` / `sign_privkey.pem`; verifying key is 1952 bytes, signing key stored as 32-byte seed). `pqfile sign -k sign_privkey.pem <file>` produces a detached PEM `.sig` file (3309-byte signature). `pqfile verify -k sign_pubkey.pem -s <file>.sig <file>` verifies. All three commands support `--json`. Signing keys are separate from encryption keys.
- Multi-recipient encryption (v4 format): repeat `-r` to encrypt a single file for N recipients. A random 32-byte session key K encrypts the payload; each recipient's copy of K is wrapped under their KEM shared secret with AES-256-GCM. Mixed key variants (768/1024/hybrid) are supported in a single file. `decrypt_stream` auto-detects v4 and tries each matching-variant recipient entry in order.
- Streaming encryption for large files (v3 format): chunked AEAD using the STREAM construction. Each 64 KiB chunk uses an independent nonce (`base_nonce[8] || counter[4]`) and per-chunk AAD (`"pqfile" || counter || is_last`) preventing truncation and reordering attacks. Peak memory is proportional to chunk size regardless of file size. `encrypt_bytes` / `decrypt_bytes` retained for library consumers (v2 format).
- Batch and recursive directory encryption: `pqfile encrypt -r pubkey.pem --recursive /path/to/dir/` encrypts every file in a directory tree, writing `.pqf` files alongside the originals. `.pqf` files are skipped automatically.
- Structured JSON output: `--json` global flag on all commands. Success emits `{"status":"ok",...}` to stdout; errors go to stderr as `{"status":"error","message":"..."}`. `pqfile inspect --json` includes magic, version, KEM variant, nonce, and original_size.
- Criterion benchmark suite in `pqfile/benches/crypto.rs` covering `encrypt_bytes`, `decrypt_bytes`, `encrypt_stream`, `decrypt_stream`, and `keygen` at 1 KB, 1 MB, and 100 MB. Run with `cargo bench`; HTML reports written to `target/criterion/`.
- GUI key management panel: dedicated "Keys" tab with persistent named key pairs (label, fingerprint, directory path) stored via eframe Storage. Quick-load buttons populate the Encrypt and Decrypt tabs. "Import Key Pair" browses for a folder containing `pubkey.pem` and optionally `privkey.pem`.
- GUI progress indicator: per-file-count progress bar during multi-file batch encrypt; spinner during decrypt. Encrypt and decrypt operations run on a background thread on native builds so the UI stays responsive throughout.

---

## [2.0.5] - 2026-05-19

### Fixed

- Release workflow no longer creates an empty commit when no files have changed during a version bump.
- Corrected the checksum extraction grep command in the release workflow (removed stray space).

### Removed

- Homebrew formula and winget manifest files and all related packaging instructions.

---

## [2.0.4] - 2026-05-19

### Added

- CycloneDX SBOM generation via `cargo-cyclonedx` in the release workflow. Three SBOMs are attached to each release: `sbom-pqfile.cdx.json`, `sbom-pqfile-gui.cdx.json`, `sbom-pqfile-desktop.cdx.json`.
- Cosign keyless signing of release checksums: `checksums.txt` is signed via the sigstore transparency log and the resulting `checksums.txt.bundle` is attached to each GitHub release. Verification requires no pre-distributed key.
- stdin / stdout pipe support: pass `-` as the input file to read from stdin, and omit `-o` to write to stdout. Enables composability: `cat secret.txt | pqfile encrypt -r pubkey.pem - > out.pqf`.

---

## [2.0.3] - 2026-05-18

### Added

- Passphrase-protected private keys: `pqfile keygen --passphrase` derives an AES-256-GCM key from the passphrase using Argon2id (m=64 MiB, t=3, p=1) and encrypts the 64-byte seed before writing the PEM file. The encrypted label is `ML-KEM-768 ENCRYPTED PRIVATE KEY`. Decryption auto-detects the label and prompts for the passphrase. Unencrypted keys remain fully supported.
- Shell completions: `pqfile completions <shell>` prints a ready-to-install script for bash, zsh, fish, PowerShell, or elvish.
- `cargo-deny` for license and advisory scanning in CI: `deny.toml` enforces license policy (MIT, Apache-2.0, BSL-1.0, OFL-1.1), blocks banned crates (openssl-sys), and restricts crate sources to crates.io. Runs on every push and PR to main.
- `gitleaks` secret scanning in CI with a `.gitleaks.toml` allowlist for test passphrases and packaging metadata.

---

## [2.0.2] - 2026-05-16

### Fixed

- Cross-compilation for `x86_64-apple-darwin` now uses `macos-latest` instead of `macos-13`, resolving intermittent runner availability failures.
- Various CI workflow reliability improvements.

### Added

- Integration tests for encryption and decryption error handling paths.

---

## [2.0.1] - 2026-05-08

### Changed

- Updated `ml-kem` dependency from 0.3.0 to 0.3.2.
- Various GitHub Actions workflow version updates.

---

## [2.0.0] - 2026-05-08

Breaking change: the full `.pqf` header is now included as AEAD additional data. Files produced by v1.x are not decryptable by v2.x.

### Added

- Full AEAD authentication of the `.pqf` header: the entire header is passed as AAD on both encrypt and decrypt, so any single-byte modification to the header or payload causes decryption to fail before any plaintext is returned.
- Custom output paths: `-o / --output` flag on both `pqfile encrypt` and `pqfile decrypt`.
- `pqfile keygen --force` to overwrite existing `pubkey.pem` or `privkey.pem` files. Without `--force`, keygen refuses to overwrite.
- SHA3-256 key fingerprint: the first 8 bytes of the SHA3-256 hash of the public key, printed as colon-separated hex by `pqfile keygen` and displayed in the GUI keygen success message.
- GUI drag-and-drop file loading on the Encrypt, Decrypt, and Inspect panels (native and web).
- GUI key fingerprint in the Inspect tab: shows the SHA3-256 fingerprint of the embedded KEM ciphertext so the recipient can confirm which key was used before decrypting.
- GUI multi-file encrypt: "Files to Encrypt" list with a multi-file picker and drag-and-drop support. Each file shows per-row status. "Encrypt All (N)" processes all files sequentially with the same public key.
- GUI confirm-before-overwrite for keygen: mirrors the CLI `--force` flag; the GUI prompts before overwriting an existing key pair when the setting is enabled.
- GUI persistent settings: theme, auto-clear, and confirm-overwrite choices are saved via `eframe` Storage and restored across restarts.
- Dependabot configuration for weekly Cargo and GitHub Actions dependency pull requests.

### Removed

- `pqfile-gui` binary from `pqfile/src/bin/`. The standalone desktop app is now `pqfile-desktop` exclusively.

---

## [1.0.2] - 2026-05-02

### Added

- GitHub Pages auto-deploy workflow (`.github/workflows/pages.yml`): the WASM web GUI is built and published on every push to main.
- `RELEASING.md` covering the end-to-end release process: version bumping, CI monitoring, cosign verification, and post-release smoke-testing.
- SonarQube project configuration and quality badge in README.

---

## [1.0.1] - 2026-04-25

### Added

- Batch file operations: `pqfile encrypt` and `pqfile decrypt` accept multiple input file arguments in a single invocation.
- `pqfile inspect <file.pqf>`: prints the file header (magic bytes, format version, KEM variant, nonce, original file size) without decrypting the payload.
- SHA-256 checksums (`checksums.txt`) generated for all release artifacts and attached to each GitHub release.
- `SECURITY.md` security policy covering vulnerability reporting procedures, response time targets, in-scope areas, and design invariants.
- Additional roundtrip integration tests including `pqfile inspect` output verification.

### Changed

- Release artifact filenames standardized to a consistent `name-target` scheme across all platforms.

---

## [1.0.0] - 2026-04-25

Initial public release.

### Added

- Core CLI with `pqfile encrypt`, `pqfile decrypt`, and `pqfile keygen` subcommands.
- ML-KEM-768 key encapsulation (NIST FIPS 203) and ChaCha20-Poly1305 AEAD symmetric encryption.
- Streaming AEAD construction: the plaintext is processed in 64 KiB chunks. Each chunk uses an independent nonce derived from a random base nonce and a counter, with per-chunk AAD that prevents truncation and reordering attacks.
- Key generation writes `pubkey.pem` and `privkey.pem` to a specified output directory. The 64-byte seed is stored, not the full private key, keeping the PEM file small.
- `pqfile-gui`: an egui/eframe-based GUI with Encrypt, Decrypt, Keygen, Inspect, and Settings tabs. The same codebase compiles to a native desktop application and a WASM web application (via trunk).
- `pqfile-desktop`: a thin Rust binary that hosts `pqfile-gui` as a native window, built separately from the WASM target.
- Workspace structure with three crates: `pqfile` (core library and CLI), `pqfile-gui` (shared GUI code), and `pqfile-desktop` (native binary entrypoint).
- CI workflow (`.github/workflows/ci.yml`): runs the full test suite, `cargo deny`, and `gitleaks` on every push and PR to main.
- Release workflow (`.github/workflows/release.yml`): triggered by a version tag. Builds the CLI and desktop GUI for Linux x86_64, macOS x86_64, macOS arm64, and Windows x86_64. Produces a Windows installer via Inno Setup, a WASM web app archive, and SHA-256 checksums for all artifacts.
- WASM web app build via trunk, deployed to GitHub Pages.
- `NGINX_DEPLOYMENT.md`: production deployment guide for the web GUI on Ubuntu + nginx, covering hardened TLS configuration, security headers (HSTS, CSP, COOP, COEP), rate limiting, OCSP stapling, and anonymized access logging.
- Integration test suite in `pqfile/tests/roundtrip.rs`.
- `rust-toolchain.toml` pinning the Rust toolchain version.
- MIT license.
