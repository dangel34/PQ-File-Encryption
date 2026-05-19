# pqfile Roadmap

This document tracks planned improvements, new features, and security work across future releases. Items are grouped by milestone. Breaking changes to the `.pqf` format or public API always require a major version bump.

---

## v2.x - Incremental improvements (no breaking changes)

### Security

- **Passphrase-protected private keys** ✓ _released_
  `pqfile keygen --passphrase` derives an AES-256-GCM key from the passphrase using Argon2id (m=64 MiB, t=3, p=1) and encrypts the 64-byte seed before writing the PEM file. Decrypt auto-detects the `ML-KEM-768 ENCRYPTED PRIVATE KEY` label and prompts for the passphrase. Unencrypted keys remain fully supported.

- **Key fingerprint display** ✓ _released_
  SHA3-256 fingerprint (first 8 bytes, colon-separated hex) printed by `pqfile keygen` and shown in the GUI Keygen success message.

- **cargo-audit in CI** ✓ _released_
  `cargo audit` runs in `release.yml` before every build, blocking releases with known RustSec advisories in the dependency tree.

- **Signed releases via sigstore/cosign** ✓ _released_
  Automatically sign release binaries and checksums in CI using cosign keyless signing. Publish a `checksums.txt.sig` alongside each GitHub release.

- **cargo-deny** ✓ _released_
  `deny.toml` enforces license policy (MIT, Apache-2.0, BSL-1.0, OFL-1.1, and font licenses from egui), blocks banned crates (openssl-sys), and restricts sources to crates.io. Runs in `.github/workflows/ci.yml` on every push and PR to main.

- **Secret scanning (gitleaks)** ✓ _released_
  `.gitleaks.toml` with an allowlist for test passphrases and packaging metadata. Runs in `.github/workflows/ci.yml` alongside cargo-deny on every push and PR to main.

### CLI

- **Output path flag (`-o / --output`)** ✓ _released_
  `pqfile encrypt … -o /tmp/out.pqf` and `pqfile decrypt … -o recovered.txt`.

- **Stdin / stdout pipe support** ✓ _released_
  Accept `-` as the input file to read from stdin and write to stdout. Enables composability: `cat secret.txt | pqfile encrypt -r pubkey.pem - > out.pqf`.

- **Shell completions** ✓ _released_
  `pqfile completions <shell>` prints a ready-to-install script for bash, zsh, fish, PowerShell, or elvish. Pipe directly into the appropriate location for your shell (see README for one-liners).

- **`pqfile keygen --force` flag** ✓ _released_
  Without `--force`, keygen refuses to overwrite an existing `pubkey.pem` or `privkey.pem`.

### GUI

- **Drag-and-drop file loading** ✓ _released_
  Accept files dropped onto the Encrypt, Decrypt, and Inspect panels in both the native and web builds. `egui` exposes `dropped_files` on `Context`; the web build needs a JS drop-event bridge.

- **Key fingerprint in Inspect tab** ✓ _released_
  SHA3-256 fingerprint of the embedded KEM ciphertext displayed in the Inspect output. Lets the recipient confirm which key was used before attempting decryption.

- **Multi-file encrypt** ✓ _released_
  "Files to Encrypt" list with "+ Add Files…" button (opens a multi-file picker) and drag-and-drop support. Each file shows a per-row status (✓ / error). "Encrypt All (N)" button processes all files sequentially with the same public key. Works on both native and web.

- **GUI keygen: confirm before overwriting existing keys** ✓ _released_
  Native GUI routes through `keygen::keygen()` with `force = !settings.confirm_overwrite`, giving the same protection as the CLI `--force` flag.

- **Persist settings across sessions** ✓ _released_
  Save `Settings` (theme, auto-clear, confirm-overwrite) to disk via `eframe`'s `Storage` API so they survive restarts.

### Packaging & Distribution

- **Automated release workflow** ✓ _released v2.x_
  `.github/workflows/release.yml` triggered by a version tag (`v*`). Builds CLI and desktop GUI binaries for all four platforms, the Windows installer via Inno Setup, the WASM web app, generates `checksums.txt`, and creates a draft GitHub release.

- **SBOM generation** ✓ _released_
  Produce a CycloneDX or SPDX software bill of materials in CI using `cargo-cyclonedx` or `cargo-sbom` and attach it to each release.

---

## v3.0 - Next major release (breaking .pqf format changes)

### Security

- **ML-KEM-1024 support**
  Add a `--level 1024` flag to `pqfile keygen` and `encrypt`. Store the KEM variant in the header (already present as a u16 field). The private key seed stays 64 bytes (unchanged); the encapsulation key grows from 1184 to 1568 bytes and the KEM ciphertext from 1088 to 1568 bytes. Existing v2 files remain readable.

- **Digital signatures with ML-DSA (NIST FIPS 204)**
  Add optional file signing: `pqfile sign` produces a detached `.sig` file; `pqfile verify` checks it. Uses ML-DSA-65 (Dilithium level 3). This is separate from encryption; a sender can sign a file before the recipient encrypts it, proving the file was not substituted in transit.

- **Hybrid classical + post-quantum key exchange**
  Combine X25519 with ML-KEM-768 in a hybrid KEM: the shared secret is `HKDF-SHA256(x25519_ss || mlkem_ss)`. This provides security against both classical and quantum adversaries simultaneously, following NIST guidance on hybrid schemes. Format version bump to `0x03`.

- **Multiple recipients**
  Encrypt a single file to N public keys by including N KEM ciphertexts in the header. Any holder of the matching private key can decrypt. Useful for team shared files. The header becomes variable-length; a recipient count field is added.

### CLI

- **Streaming encryption for large files**
  Replace the current whole-file-in-memory approach with a chunked AEAD stream (e.g. using the `aead-stream` or `age`-style chunk framing). Each 64 KB chunk gets its own nonce derived from a counter, preventing memory exhaustion on multi-gigabyte files.

- **Batch / recursive directory encryption**
  `pqfile encrypt -r pubkey.pem --recursive /path/to/dir/` encrypts every file in a directory tree, writing `.pqf` files alongside originals (or into a mirrored output tree with `--output-dir`).

- **Structured JSON output (`--json`)**
  Machine-readable output mode for all commands. `pqfile inspect --json` emits `{"magic":"PQFL","version":"0x02",...}`. Useful for scripting and tooling integration.

### GUI

- **Progress bar for large files**
  Show a progress indicator during encrypt/decrypt operations once streaming is implemented. Run the operation on a background thread and poll via a channel.

- **Key management panel**
  A dedicated tab to view loaded keys (label, fingerprint, creation date if embedded in a metadata field), import keys from disk, and delete keys from a remembered list.

---

## Future / Long-term

### Library / API surface

- **Stable public Rust API with semver guarantees**
  Publish `pqfile` to crates.io with full semver stability. Expand the public API beyond `encrypt_bytes` / `decrypt_bytes` / `keygen_bytes` to expose typed key structs so downstream crates can work with keys without round-tripping through PEM.

- **C FFI bindings**
  Expose a `pqfile.h` C header via `cbindgen` so the crypto core can be used from C, Python (via `ctypes`/`cffi`), Go (`cgo`), or any language with C interop. Priority use case: embedding encryption in existing applications.

- **Python bindings (PyO3)**
  A thin `pqfile-py` crate wrapping the core with `#[pymodule]`. Publish to PyPI. Enables Python scripts to encrypt/decrypt files without shelling out.

- **npm / WASM package**
  Package the WASM build as an npm module so browser and Node.js applications can call `encrypt`, `decrypt`, and `keygen` directly as JavaScript functions without loading the full egui app.

### Infrastructure

- **Fuzzing with `cargo-fuzz`** ✓ _released_
  Add fuzz targets for `PqfHeader::read`, `decrypt_bytes` (malformed ciphertext), and PEM parsing. Run on OSS-Fuzz or as a nightly CI job. Guards against panics or logic errors on adversarial input. Targets live in `fuzz/fuzz_targets/`; run with `cargo fuzz run fuzz_header_read` etc.

- **Dependabot / Renovate** ✓ _released_
  `.github/dependabot.yml` enables weekly PRs for Cargo and GitHub Actions dependencies.

- **Benchmark suite**
  Add `criterion` benchmarks for encrypt and decrypt at 1 KB, 1 MB, and 100 MB (once streaming exists). Track performance regressions in CI.

- **cargo-vet**
  Adopt `cargo vet` for third-party crate supply-chain vetting. Each dependency gets an explicit audit entry (safe-to-deploy, safe-to-run, or a trusted publisher exemption). Adds ongoing maintenance burden but is standard practice for widely-distributed security tools.

---

## Security considerations that will not change

The following properties are invariants, not roadmap items. Any proposal that weakens them requires explicit justification and a major version bump:

- All cryptographic operations run locally. No data is sent to a server.
- The entire `.pqf` file (header + payload) is authenticated before any plaintext is returned.
- Secret material is zeroized from memory on drop.
- Each encryption produces a fresh KEM ciphertext and a fresh random nonce.
