# pqfile Roadmap

This document tracks planned improvements, new features, and security work across future releases. Items are grouped by milestone. Breaking changes to the `.pqf` format or public API always require a major version bump.

---

## v2.x — Incremental improvements (no breaking changes)

### Security

- **Passphrase-protected private keys**
  Derive an encryption key from a user passphrase using Argon2id and use it to encrypt the raw private key bytes before writing the PEM file. Decryption prompts for the passphrase. This means a stolen `privkey.pem` is useless without the passphrase.

- **Key fingerprint display** ✓ _released_
  SHA3-256 fingerprint (first 8 bytes, colon-separated hex) printed by `pqfile keygen` and shown in the GUI Keygen success message.

- **cargo-audit in CI** ✓ _released_
  `cargo audit` runs in `release.yml` before every build, blocking releases with known RustSec advisories in the dependency tree.

- **Signed releases via sigstore/cosign**
  Automatically sign release binaries and checksums in CI using cosign keyless signing. Publish a `checksums.txt.sig` alongside each GitHub release.

- **cargo-deny**
  Add a `deny.toml` and a CI step using `cargo-deny` to block disallowed licenses, duplicate dependencies, and advisories beyond what `cargo-audit` covers. Complements the existing audit step in `release.yml` with license and supply-chain policy enforcement.

- **Secret scanning (gitleaks)**
  Add a `gitleaks` step to the CI workflow (or as a pre-commit hook) to catch accidentally committed secrets, API keys, or private key material before they reach the remote. Configure a `.gitleaks.toml` allowlist to suppress intentional test fixtures.

### CLI

- **Output path flag (`-o / --output`)** ✓ _released_
  `pqfile encrypt … -o /tmp/out.pqf` and `pqfile decrypt … -o recovered.txt`.

- **Stdin / stdout pipe support**
  Accept `-` as the input file to read from stdin and write to stdout. Enables composability: `cat secret.txt | pqfile encrypt -r pubkey.pem - > out.pqf`.

- **Shell completions**
  Generate completion scripts for bash, zsh, fish, and PowerShell via `clap_complete`. Ship them in the `.deb` and `.rpm` packages and document the one-liner to install them.

- **`pqfile keygen --force` flag** ✓ _released_
  Without `--force`, keygen refuses to overwrite an existing `pubkey.pem` or `privkey.pem`.

### GUI

- **Drag-and-drop file loading**
  Accept files dropped onto the Encrypt, Decrypt, and Inspect panels in both the native and web builds. `egui` exposes `dropped_files` on `Context`; the web build needs a JS drop-event bridge.

- **Key fingerprint in Inspect tab**
  Compute and display the SHA-256 fingerprint of the embedded KEM ciphertext. Lets the recipient confirm which key was used to encrypt a file before attempting decryption.

- **Multi-file encrypt (native only)**
  Allow selecting multiple plaintext files in one Browse dialog and encrypt them sequentially with the same public key. Show a per-file status list.

- **GUI keygen: confirm before overwriting existing keys**
  The native GUI calls `keygen_bytes()` directly and writes keys unconditionally — it bypasses the `--force` check enforced by the CLI. The `confirm_overwrite` setting only protects encrypt/decrypt output, not keygen. Clicking "Generate Key Pair" a second time silently replaces an existing key pair. Should either route through `keygen()` with an overwrite prompt or respect the confirm-overwrite setting.

- **Persist settings across sessions**
  Save `Settings` (theme, auto-clear, confirm-overwrite) to disk via `eframe`'s `Storage` API so they survive restarts.

### Packaging & Distribution

- **Homebrew formula**
  Publish a `homebrew-tap` repository with a formula for `pqfile` (CLI only). Keep it updated by the release workflow.

- **Windows winget manifest**
  Submit a manifest to the `microsoft/winget-pkgs` community repository so users can install via `winget install pqfile`.

- **Automated release workflow** ✓ _released v2.x_
  `.github/workflows/release.yml` triggered by a version tag (`v*`). Builds CLI and desktop GUI binaries for all four platforms, the Windows installer via Inno Setup, the WASM web app, generates `checksums.txt`, and creates a draft GitHub release.

- **SBOM generation**
  Produce a CycloneDX or SPDX software bill of materials in CI using `cargo-cyclonedx` or `cargo-sbom` and attach it to each release.

---

## v3.0 — Next major release (breaking .pqf format changes)

### Security

- **ML-KEM-1024 support**
  Add a `--level 1024` flag to `pqfile keygen` and `encrypt`. Store the KEM variant in the header (already present as a u16 field). The private key seed stays 64 bytes (unchanged); the encapsulation key grows from 1184 to 1568 bytes and the KEM ciphertext from 1088 to 1568 bytes. Existing v2 files remain readable.

- **Digital signatures with ML-DSA (NIST FIPS 204)**
  Add optional file signing: `pqfile sign` produces a detached `.sig` file; `pqfile verify` checks it. Uses ML-DSA-65 (Dilithium level 3). This is separate from encryption — a sender can sign a file before the recipient encrypts it, proving the file was not substituted in transit.

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

- **Fuzzing with `cargo-fuzz`**
  Add fuzz targets for `PqfHeader::read`, `decrypt_bytes` (malformed ciphertext), and PEM parsing. Run on OSS-Fuzz or as a nightly CI job. Guards against panics or logic errors on adversarial input.

- **Dependabot / Renovate**
  Enable automated dependency update PRs for both Cargo dependencies and GitHub Actions. Configure auto-merge for patch-level updates that pass CI.

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
