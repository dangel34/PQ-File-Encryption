# pqfile Roadmap

This document tracks planned improvements, new features, and security work across future releases. Items are grouped by milestone. Breaking changes to the `.pqf` format or public API always require a major version bump.

---

## v2.x - Incremental improvements (no breaking changes)

### Security

- **Passphrase-protected private keys** ✓ _released_
  `pqfile keygen --passphrase` derives an AES-256-GCM key from the passphrase using Argon2id (m=64 MiB, t=3, p=1) and encrypts the 64-byte seed before writing the PEM file. Decrypt auto-detects the `ML-KEM-768 ENCRYPTED PRIVATE KEY` label and prompts for the passphrase. Unencrypted keys remain fully supported.

- **Key fingerprint display** ✓ _released_
  SHA3-256 fingerprint (first 8 bytes, colon-separated hex) printed by `pqfile keygen` and shown in the GUI Keygen success message.

- **Advisory scanning via cargo-deny** ✓ _released_
  `cargo-deny` runs in `ci.yml` on every push and PR to main, checking for known RustSec advisories (equivalent to `cargo audit`) alongside license, ban, and source policy. This replaces a standalone `cargo audit` step that was previously in `release.yml`.

- **Signed releases via sigstore/cosign** ✓ _released_
  Automatically sign release binaries and checksums in CI using cosign keyless signing. Publish a `checksums.txt.sig` alongside each GitHub release.

- **cargo-deny** ✓ _released_
  `deny.toml` enforces license policy (MIT, Apache-2.0, BSL-1.0, OFL-1.1, and font licenses from egui), blocks banned crates (openssl-sys), and restricts sources to crates.io. Runs in `.github/workflows/ci.yml` on every push and PR to main.

- **Secret scanning (gitleaks)** ✓ _released_
  `.gitleaks.toml` with an allowlist for test passphrases and packaging metadata. Runs in `.github/workflows/ci.yml` alongside cargo-deny on every push and PR to main.

### CLI

- **Output path flag (`-o / --output`)** ✓ _released_
  `pqfile encrypt ... -o /tmp/out.pqf` and `pqfile decrypt ... -o recovered.txt`.

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
  "Files to Encrypt" list with "+ Add Files..." button (opens a multi-file picker) and drag-and-drop support. Each file shows a per-row status (✓ / error). "Encrypt All (N)" button processes all files sequentially with the same public key. Works on both native and web.

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

- **ML-KEM-1024 support** ✓ _released_
  `pqfile keygen --level 1024` generates ML-KEM-1024 keys (EK 1568 bytes, CT 1568 bytes). The header `kem_variant` field (u16) distinguishes 768 vs 1024 files. The private key seed remains 64 bytes. Decryption auto-detects the variant from the file header; mismatched keys produce a clear error. New PEM tags: `ML-KEM-1024 PUBLIC KEY`, `ML-KEM-1024 PRIVATE KEY`, `ML-KEM-1024 ENCRYPTED PRIVATE KEY`. All existing v2/v3 768 files remain readable.

- **Digital signatures with ML-DSA (NIST FIPS 204)** ✓ _released_
  `pqfile sign-keygen --out <dir>` generates an ML-DSA-65 key pair (`sign_pubkey.pem` / `sign_privkey.pem`; verifying key is 1952 bytes, signing key stored as 32-byte seed). `pqfile sign -k sign_privkey.pem <file>` produces a detached PEM `.sig` file (3309-byte signature). `pqfile verify -k sign_pubkey.pem -s <file>.sig <file>` verifies the signature. All three commands support `--json`. Signing is separate from encryption; a sender can sign a file before the recipient encrypts it, proving the file was not substituted in transit.

- **Hybrid classical + post-quantum key exchange** ✓ _released_
  `pqfile keygen --hybrid` generates an X25519+ML-KEM-768 hybrid key pair (KEM variant `0x0301`). The public key PEM contains X25519 pubkey (32 bytes) || ML-KEM-768 EK (1184 bytes). Encryption produces a fresh ephemeral X25519 key, runs DH + ML-KEM encapsulate, then derives the 32-byte session key via `HKDF-SHA256(IKM = x25519_ss || mlkem_ss, info = "pqfile-hybrid-v1")`. `pqfile inspect` shows the friendly variant name. Hybrid keys and pure ML-KEM keys cannot decrypt each other's files (KEM variant mismatch error).

- **Multiple recipients** ✓ _released_
  Encrypt a single file to N public keys (v4 format) by repeating `-r` on the CLI. A random 32-byte session key K encrypts the payload; each recipient's KEM shared secret wraps K under AES-256-GCM. Any holder of a matching private key can decrypt. Mixed variants (768/1024/hybrid) are supported in a single file. `decrypt_stream` auto-detects v4 format and tries each matching-variant recipient entry in order.

### CLI

- **Streaming encryption for large files** ✓ _released_
  Chunked AEAD stream using the STREAM construction: each 64 KiB chunk uses an independent nonce (`base_nonce[8] || counter[4]`) and AAD (`"pqfile" || counter || is_last`) that prevents truncation and reordering attacks. Peak memory is proportional to chunk size regardless of file size. Format version bumped to `0x03`. CLI produces v3 by default; `decrypt_stream` reads both v2 and v3. `encrypt_bytes` / `decrypt_bytes` retained for library consumers at v2.

- **Batch / recursive directory encryption** ✓ _released_
  `pqfile encrypt -r pubkey.pem --recursive /path/to/dir/` encrypts every file in a directory tree, writing `.pqf` files alongside originals. `.pqf` files are skipped automatically to prevent double-encryption.

- **Structured JSON output (`--json`)** ✓ _released_
  Machine-readable output mode for all commands via a global `--json` flag. All commands emit `{"status":"ok",...}` on success; errors go to stderr as `{"status":"error","message":"..."}`. `pqfile inspect --json` emits magic, version, KEM variant, nonce, and original_size. Recursive encrypt emits a JSON array with per-file status entries.

### GUI

- **Progress bar for large files** ✓ _released_
  Encrypt and decrypt operations run on a background thread (native). A per-file-count progress bar is shown during multi-file batch encrypt; a spinner is shown during decrypt. The UI stays responsive throughout. WASM keeps the existing synchronous path.

- **Key management panel** ✓ _released_
  Dedicated "Keys" tab. Remembered key pairs (label, fingerprint, directory path) persist across sessions via eframe Storage. Encrypt / Decrypt buttons quick-load keys into the respective tabs. Import Key Pair browses for a folder containing pubkey.pem and optionally privkey.pem. Missing-file warning shown inline.

---

## Future / Long-term

### Security

- **ML-KEM-512 support** ✓ _released_
  `pqfile keygen --level 512` generates an ML-KEM-512 key pair (EK 800 bytes, CT 768 bytes, seed 64 bytes). New PEM tags: `ML-KEM-512 PUBLIC KEY`, `ML-KEM-512 PRIVATE KEY`, `ML-KEM-512 ENCRYPTED PRIVATE KEY`. KEM variant value `512` (u16). Decryption auto-detects from the file header. Passphrase protection supported. Completes FIPS 203 parameter set coverage.

- **Anonymous recipients in v4 format**
  In the current v4 header, the recipient count and each entry's KEM variant are visible in plaintext. An `--anonymous-recipients` flag on `pqfile encrypt` pads all recipient entries to the maximum variant size and randomizes their serialization order before writing the header. An eavesdropper cannot determine the number of recipients or which key types are in use. Adds a v5 format flag byte to signal anonymous mode; the decryptor must try each entry regardless of variant instead of filtering by the key's own variant first.

- **Signcrypt (combined authenticate and encrypt)**
  A `pqfile signcrypt -k sign_privkey.pem -r pubkey.pem <file>` command that signs the plaintext under ML-DSA-65 and embeds the detached signature inside the encrypted payload. `pqfile signdecrypt -k privkey.pem -v sign_pubkey.pem <file.pqf>` decrypts and verifies in one step. Because the signature lives inside the AEAD-authenticated ciphertext it cannot be stripped or substituted after the fact. This prevents "surreptitious forwarding": a recipient cannot re-encrypt the plaintext to a third party while preserving the sender's signature, because re-encryption requires decryption first, which reveals that the sender signed only the original plaintext (not one addressed to a different recipient). Eliminates the need for a separate `.sig` file when the sender identity must be bound to the ciphertext.

- **Key revocation** ✓ _released_
  A `pqfile revoke -k sign_privkey.pem pubkey.pem` command that produces a signed `pubkey.pem.revoked` PEM file containing the key fingerprint, a UTC revocation timestamp, and a free-text reason. `pqfile encrypt` can check for a `.revoked` sidecar file alongside the public key and refuse to encrypt if one is found, with a clear error message. Revocations are signed with the ML-DSA signing key so they cannot be forged or silently discarded without the signing key. Provides a lightweight revocation mechanism for deployments that cannot yet implement a full PKI.

- **Hardware-backed private keys (TPM / PKCS#11)**
  Store the private key seed inside a hardware security module rather than on disk. Opt in with `pqfile keygen --hardware`. Supported backends: Windows TPM2 via the CNG API, macOS Secure Enclave via the Security framework, Linux TPM2 via tpm2-tools, and YubiKey or other PKCS#11 tokens. The PEM private key file is replaced by a hardware key reference (device attestation + slot identifier). The seed is generated inside the hardware and never exported to process memory. Decapsulation calls are proxied to the hardware, so a physical token or OS-level access control is required for every decrypt. Provides strong protection against disk theft, memory forensics, and cold-boot attacks.

- **Threshold decryption (M-of-N)**
  Split a private key seed across N shareholders using Shamir's Secret Sharing (GF(2^8) polynomial interpolation over the 64-byte seed). `pqfile split-key --threshold M --shares N privkey.pem` produces N share PEM files. `pqfile reconstruct-key share1.pem share2.pem ... privkey.pem` reassembles the seed from any M shares. Decryption then proceeds normally. Useful for high-security key escrow, disaster recovery where no single person holds the full key, or organizational workflows requiring M-of-N approval to access protected data.

### CLI / Library

- **Stable public Rust API with semver guarantees**
  Publish `pqfile` to crates.io with full semver stability. Expand the public API beyond `encrypt_bytes` / `decrypt_bytes` / `keygen_bytes` to expose typed key structs so downstream crates can work with keys without round-tripping through PEM.

- **Streaming decryptor type implementing Read** ✓ _released_
  Expose a `PqfReader<R: Read>` type that wraps a source reader and implements `Read`, yielding decrypted plaintext bytes incrementally. Library consumers can pipe the output directly into any `Read`-expecting API (a decompressor, CSV parser, database import stream, or network socket) without buffering the full plaintext in memory first. Each 64 KiB chunk is yielded only after its AEAD tag passes verification; a tampered chunk causes the `Read` call to return an error. This is the primary missing abstraction for embedding pqfile in larger Rust applications.

- **Async I/O support**
  Add `encrypt_stream_async` and `decrypt_stream_async` that accept `AsyncRead + AsyncWrite + Unpin` from `tokio::io`, plus a feature-flagged `futures::io` variant. The chunk loop becomes an `async` block with `.await` on each read and write. Enables non-blocking encryption in async servers and proxies without spawning a dedicated OS thread per operation. The async API is a direct mirror of the sync streaming API; the same format.rs helpers (chunk_nonce, chunk_aad, fill_chunk) are reused with async equivalents.

- **Encrypted archive (multi-file bundle)**
  A `pqfile archive -r pubkey.pem -o bundle.pqf [files...]` command that packs multiple files and directory trees into a single encrypted authenticated archive. Each entry stores the original relative path, file size, modification time, and Unix permissions in a per-entry header, all covered by the same AEAD authentication as the payload. `pqfile extract bundle.pqf -k privkey.pem [-o dir]` restores the original layout. Useful for sending a set of related files as a single auditable package. All authentication happens before any file is written to disk on extraction. The format is a v4 stream where the payload is a structured entry sequence rather than raw file bytes.

- **Re-encryption without payload decryption (rekey)** ✓ _released_
  `pqfile rekey -k old_privkey.pem -r new_pubkey.pem file.pqf` decapsulates the session key using the old private key, re-encapsulates it under the new public key, and rewrites only the file header. The payload ciphertext bytes are streamed through unchanged. The resulting file is a valid `.pqf` decryptable only with the new private key. Useful for key rotation (replace a compromised or expired key without re-reading the plaintext), and for adding a recipient to an already-encrypted file when the original plaintext is no longer available.

- **Compress-then-encrypt (zstd)** ✓ _released_
  An optional `--compress` flag on `pqfile encrypt`. Plaintext is compressed with zstd at the configured level before encryption, reducing ciphertext size for compressible inputs. The compression ratio and original uncompressed size are stored in an extended header field. Decompression happens automatically after AEAD verification on decrypt, before returning plaintext to the caller. This is safe for file encryption: unlike CRIME/BREACH attacks (which exploit a compression oracle over many adaptive requests), compression here is a one-shot transform applied before a fresh random AEAD per file. A `--compress-level` option (1 to 22) trades speed for ratio.

- **C FFI bindings**
  Expose a `pqfile.h` C header via `cbindgen` so the crypto core can be used from C, Python (via `ctypes` / `cffi`), Go (`cgo`), or any language with C interop. Priority use case: embedding encryption in existing applications.

- **Python bindings (PyO3)**
  A thin `pqfile-py` crate wrapping the core with `#[pymodule]`. Publish to PyPI. Enables Python scripts to encrypt/decrypt files without shelling out.

- **npm / WASM package**
  Package the WASM build as an npm module so browser and Node.js applications can call `encrypt`, `decrypt`, and `keygen` directly as JavaScript functions without loading the full egui app.

### Performance

- **Parallel chunk processing with rayon**
  In `encrypt_stream` and `decrypt_stream`, each chunk is processed independently: the per-chunk nonce and AAD are deterministic from the base nonce and the chunk counter, so the order of encryption/decryption does not need to match the order of I/O. A rayon work-stealing thread pool can encrypt or decrypt N chunks concurrently across available cores. A two-phase pipeline reads chunks on the I/O thread while worker threads process previously read chunks, keeping both the disk and CPU busy. Expected throughput improvement is roughly linear with core count up to I/O bandwidth saturation. Gate behind a `--parallel` flag so single-core and memory-constrained environments are unaffected by default.

- **Configurable chunk size** ✓ _released_
  `--chunk-size <bytes>` flag on `pqfile encrypt`. Default 64 KiB (v3 format). Non-default values emit v5 format which stores the chunk size in the header so the decryptor reads it automatically. Supported range: 1–268435456 bytes. Not supported with multiple recipients (v4 format).

- **In-place AEAD to eliminate per-chunk allocation** ✓ _released_
  `encrypt_stream` and `encrypt_stream_multi` now use `encrypt_in_place_detached` (ciphertext written to the existing plaintext buffer; 16-byte tag appended separately). `decrypt_v3_chunks` uses `decrypt_in_place_detached` (tag split from end of chunk buffer). Zero heap allocations per chunk in the streaming hot path.

- **Benchmark regression detection in CI** ✓ _released_
  `.github/workflows/ci.yml` `bench` job runs `cargo bench -p pqfile -- --output-format bencher` and feeds results to `benchmark-action/github-action-benchmark`. Baseline auto-pushed on main; PRs compare against stored baseline and post alert comments if any benchmark regresses more than 10%.

### Infrastructure

- **OSS-Fuzz continuous fuzzing** ✓ _released_
  `oss-fuzz/project.yaml`, `Dockerfile`, and `build.sh` provide the integration files for a google/oss-fuzz PR. Nightly CI fuzz job in `.github/workflows/fuzz.yml` runs each target for 120 seconds with libFuzzer, uploads crash artifacts on failure. To enable continuous OSS-Fuzz coverage, submit a PR to https://github.com/google/oss-fuzz adding the `projects/pqfile/` directory from `oss-fuzz/`.

- **Fuzzing with `cargo-fuzz`** ✓ _released_
  Add fuzz targets for `PqfHeader::read`, `decrypt_bytes` (malformed ciphertext), and PEM parsing. Run on OSS-Fuzz or as a nightly CI job. Guards against panics or logic errors on adversarial input. Targets live in `fuzz/fuzz_targets/`; run with `cargo fuzz run fuzz_header_read` etc.

- **Dependabot / Renovate** ✓ _released_
  `.github/dependabot.yml` enables weekly PRs for Cargo and GitHub Actions dependencies.

- **Benchmark suite** ✓ _released_
  `criterion` benchmarks in `pqfile/benches/crypto.rs` cover `encrypt_bytes`, `decrypt_bytes`, `encrypt_stream`, `decrypt_stream`, and `keygen` at 1 KB, 1 MB, and 100 MB. Run with `cargo bench`. HTML reports written to `target/criterion/`.

- **cargo-vet** ✓ _released_
  `supply-chain/config.toml` records an explicit exemption (safe-to-deploy or safe-to-run) for every dependency in the tree. `cargo vet --locked` runs in `.github/workflows/ci.yml` on every push and PR to main. New dependencies added without a corresponding exemption or audit entry will fail CI.

---

## Security considerations that will not change

The following properties are invariants, not roadmap items. Any proposal that weakens them requires explicit justification and a major version bump:

- All cryptographic operations run locally. No data is sent to a server.
- The entire `.pqf` file (header + payload) is authenticated before any plaintext is returned.
- Secret material is zeroized from memory on drop.
- Each encryption produces a fresh KEM ciphertext and a fresh random nonce.
- In hybrid mode, each encryption also produces a fresh ephemeral X25519 scalar.
