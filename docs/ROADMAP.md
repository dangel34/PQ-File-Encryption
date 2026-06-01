# pqfile Roadmap

This document tracks planned improvements, new features, and security work across future releases. Items are grouped by milestone. Breaking changes to the `.pqf` format or public API always require a major version bump.

---

## v2.x - Incremental improvements (no breaking changes)

### Security

- **Passphrase-protected private keys** ✓ _released_
  `pqfile keygen --passphrase` derives an AES-256-GCM key from the passphrase using Argon2id (m=64 MiB, t=3, p=1) and encrypts the 64-byte seed before writing the PEM file. Decrypt auto-detects the `ML-KEM-768 ENCRYPTED PRIVATE KEY` label and prompts for the passphrase. Unencrypted keys remain fully supported.

- **Key fingerprint display** ✓ _released_
  SHA3-256 fingerprint (first 16 bytes, colon-separated hex) printed by `pqfile keygen` and shown in the GUI Keygen success message.

- **Supply-chain vetting (cargo-deny + cargo-vet)** ✓ _released_
  `cargo-deny` enforces license policy (MIT, Apache-2.0, BSL-1.0, OFL-1.1, and font licenses from egui), blocks banned crates (openssl-sys), and restricts sources to crates.io. `cargo-vet` records an explicit exemption (safe-to-deploy or safe-to-run) for every dependency in the tree. Both tools run in `.github/workflows/ci.yml` on every push and PR to main.

- **Signed releases via sigstore/cosign** ✓ _released_
  Automatically sign release binaries and checksums in CI using cosign keyless signing. Publish a `checksums.txt.sig` alongside each GitHub release.

- **Secret scanning (gitleaks)** ✓ _released_
  `.gitleaks.toml` with an allowlist for test passphrases and packaging metadata. Runs in `.github/workflows/ci.yml` alongside cargo-deny on every push and PR to main.

### CLI

- **Output path flag (`-o / --output`)** ✓ _released_
  `pqfile encrypt ... -o /tmp/out.pqf` and `pqfile decrypt ... -o recovered.txt`.

- **Stdin / stdout pipe support** ✓ _released_
  Accept `-` as the input file to read from stdin and write to stdout. Enables composability: `cat secret.txt | pqfile encrypt -r pubkey.pem - > out.pqf`.

- **Shell completions** ✓ _released_
  `pqfile completions <shell>` prints a ready-to-install script for bash, zsh, fish, PowerShell, or elvish.

- **`pqfile keygen --force` flag** ✓ _released_
  Without `--force`, keygen refuses to overwrite an existing `pubkey.pem` or `privkey.pem`.

### GUI

- **Drag-and-drop file loading** ✓ _released_
  Accept files dropped onto the Encrypt, Decrypt, and Inspect panels in both the native and web builds.

- **Key fingerprint in Inspect tab** ✓ _released_
  SHA3-256 fingerprint displayed in the Inspect output. Lets the recipient confirm which key was used before attempting decryption.

- **Multi-file encrypt** ✓ _released_
  "+ Add Files..." button, drag-and-drop support, per-row status (ok / error), and "Encrypt All (N)" button. Works on native and web.

- **GUI keygen: confirm before overwriting existing keys** ✓ _released_
  Native GUI routes through `keygen::keygen()` with `force = !settings.confirm_overwrite`.

- **Persist settings across sessions** ✓ _released_
  Save `Settings` (theme, auto-clear, confirm-overwrite) to disk via `eframe`'s `Storage` API.

### Packaging and Distribution

- **Automated release workflow** ✓ _released_
  `.github/workflows/release.yml` triggered by a version tag (`v*`). Builds CLI and desktop GUI binaries for all four platforms, the Windows installer via Inno Setup, the WASM web app, generates `checksums.txt`, and creates a draft GitHub release.

- **SBOM generation** ✓ _released_
  CycloneDX software bill of materials generated in CI and attached to each release.

---

## v3.0 - Format and feature expansion (breaking .pqf format changes)

### Security

- **ML-KEM-1024 support** ✓ _released_
  `pqfile keygen --level 1024` generates ML-KEM-1024 keys (EK 1568 bytes, CT 1568 bytes). The header `kem_variant` field (u16) distinguishes variants. Decryption auto-detects the variant from the file header; mismatched keys produce a clear error.

- **Digital signatures with ML-DSA (NIST FIPS 204)** ✓ _released_
  `pqfile sign-keygen --out <dir>` generates an ML-DSA-65 key pair. `pqfile sign -k sign_privkey.pem <file>` produces a detached PEM `.sig` file (3309-byte signature). `pqfile verify` verifies. All commands support `--json`.

- **Hybrid classical + post-quantum key exchange** ✓ _released_
  `pqfile keygen --hybrid` generates an X25519+ML-KEM-768 hybrid key pair (KEM variant `0x0301`). Session key derived via `HKDF-SHA256(IKM = x25519_ss || mlkem_ss, info = "pqfile-hybrid-v1")`.

- **Multiple recipients** ✓ _released_
  Encrypt a single file to N public keys (v4 format) by repeating `-r` on the CLI. A random 32-byte session key K encrypts the payload; each recipient's KEM shared secret wraps K under AES-256-GCM. Mixed variants (768/1024/hybrid) are supported in a single file.

### CLI

- **Streaming encryption for large files** ✓ _released_
  Chunked AEAD stream using the STREAM construction: each 64 KiB chunk uses an independent nonce and AAD that prevents truncation and reordering attacks.

- **Batch / recursive directory encryption** ✓ _released_
  `pqfile encrypt -r pubkey.pem --recursive /path/to/dir/` encrypts every file in a directory tree, writing `.pqf` files alongside originals.

- **Structured JSON output (`--json`)** ✓ _released_
  Machine-readable output mode for all commands. All commands emit `{"status":"ok",...}` on success; errors go to stderr as `{"status":"error","message":"..."}`.

### GUI

- **Progress bar for large files** ✓ _released_
  Encrypt and decrypt operations run on a background thread (native). A per-file-count progress bar is shown during batch encrypt; a spinner is shown during decrypt. The UI stays responsive throughout.

- **Key management panel** ✓ _released_
  Dedicated "Keys" tab. Remembered key pairs (label, fingerprint, directory path) persist across sessions. Encrypt / Decrypt buttons quick-load keys into the respective tabs.

---

## Future / Long-term

### Security

- **ML-KEM-512 support** ✓ _released_
  `pqfile keygen --level 512` generates an ML-KEM-512 key pair. Completes FIPS 203 parameter set coverage (512 / 768 / 1024).

- **Anonymous recipients** ✓ _released_
  `--anonymous-recipients` flag (v7 format) pads all recipient KEM ciphertext entries to the maximum variant size and randomizes their serialization order. An eavesdropper cannot determine the number of recipients or which key types are in use.

- **Signcrypt (combined authenticate and encrypt)** ✓ _released_
  `pqfile signcrypt -k sign_privkey.pem -r pubkey.pem <file>` signs the plaintext under ML-DSA-65 and embeds the detached signature inside the encrypted payload. `pqfile signdecrypt` decrypts and verifies in one step. The signature lives inside the AEAD-authenticated ciphertext and cannot be stripped or substituted after the fact. `signcrypt_bytes` added for non-seekable (in-memory) inputs.

- **Key revocation** ✓ _released_
  `pqfile revoke --key pubkey.pem --reason "..."` writes a `pubkey.pem.revoked` JSON sidecar containing the key fingerprint and reason. `pqfile encrypt` checks for a `.revoked` sidecar and aborts if one is found.

- **Passphrase-protected signing keys** ✓ _released_
  `pqfile sign-keygen --passphrase` encrypts the 32-byte ML-DSA-65 seed using Argon2id + AES-256-GCM. PEM label: `ML-DSA-65 ENCRYPTED SIGNING KEY`. Auto-detected on load.

- **Hardware-backed private keys (TPM / PKCS#11)**
  Store the private key seed inside a hardware security module rather than on disk. Opt in with `pqfile keygen --hardware`. Supported backends: Windows TPM2 via the CNG API, macOS Secure Enclave via the Security framework, Linux TPM2 via tpm2-tools, and YubiKey or other PKCS#11 tokens. The seed is generated inside the hardware and never exported to process memory. Provides strong protection against disk theft, memory forensics, and cold-boot attacks.

- **Threshold decryption (M-of-N)** ✓ _released_
  Split a private key seed across N shareholders using Shamir's Secret Sharing (GF(2^8) polynomial interpolation over the 64-byte seed). `pqfile split-key --threshold M --shares N privkey.pem` produces N share PEM files. `pqfile reconstruct-key` reassembles the seed from any M shares.

### CLI and Library

- **Typed public key API** ✓ _released_
  `pqfile::keys` exposes `PqfPublicKey`, `PqfPrivateKey`, `PqfSigningKey`, and `PqfVerifyingKey` -- typed wrapper structs that parse and validate PEM on construction, cache the KEM variant and fingerprint, and re-expose the PEM string for use with the existing encrypt/decrypt/sign functions. Downstream crates can work with structured key values instead of raw PEM strings.

- **File header inspection API** ✓ _released_
  `pqfile::inspect::inspect_stream` reads and parses a `.pqf` header without decrypting the payload. Returns a typed `PqfHeaderInfo` enum covering all format versions (v2 through v7), exposing version, KEM variant, nonce, original size, chunk size, and per-recipient slot info.

- **Add recipient without re-encryption** ✓ _released_
  `pqfile add-recipient -k existing_privkey.pem -r new_pubkey.pem file.pqf` decapsulates the session key using an existing recipient's private key, re-encapsulates it under the new public key, and appends a new recipient entry to the header without touching the payload ciphertext. Works for v4 and v7 files.

- **Secure file shredding** ✓ _released_
  `pqfile shred <file>` overwrites the file content with random bytes before deleting it, reducing the chance of plaintext recovery via file system forensics. CLI `--shred` flag on encrypt deletes the original after successful encryption.

- **Stable public Rust API with semver guarantees** _(audit complete; v4.0 release remains)_
  The public API surface audit is complete: `#[non_exhaustive]` on all public structs and enums, `#[must_use]` on all fallible functions, internal helpers moved to `pub(crate)`, passphrase parameters standardized to the last position, file-path wrappers removed. A written stability promise (STABILITY.md) and the crates.io 1.0 release are the remaining v4.0 steps.

- **Streaming decryptor type implementing Read** ✓ _released_
  `PqfReader<R: Read>` wraps a source reader and implements `Read`, yielding decrypted plaintext bytes incrementally. Each 64 KiB chunk is yielded only after its AEAD tag passes verification.

- **Async I/O support**
  Add `encrypt_stream_async` and `decrypt_stream_async` that accept `AsyncRead + AsyncWrite + Unpin` from `tokio::io`. Enables non-blocking encryption in async servers and proxies without spawning a dedicated OS thread per operation.

- **Encrypted archive (multi-file bundle)** ✓ _released_
  `pqfile archive -r pubkey.pem -o bundle.pqf [files...]` packs multiple files into a single encrypted authenticated archive (PQFA format). `pqfile extract bundle.pqf -k privkey.pem` restores the original layout. All authentication happens before any file is written to disk on extraction.

- **Re-encryption without payload decryption (rekey)** ✓ _released_
  `pqfile rekey -k old_privkey.pem -r new_pubkey.pem file.pqf` decapsulates the session key using the old private key, re-encapsulates it under the new public key, and rewrites only the file header. The payload ciphertext bytes are streamed through unchanged.

- **Compress-then-encrypt (zstd)** ✓ _released_
  `--compress` flag on `pqfile encrypt`. Plaintext is compressed with zstd before encryption. Decompression happens automatically after AEAD verification on decrypt.

- **C FFI bindings**
  Expose a `pqfile.h` C header via `cbindgen` so the crypto core can be used from C, Python (via `ctypes` / `cffi`), Go (`cgo`), or any language with C interop.

- **Python bindings (PyO3)**
  A thin `pqfile-py` crate wrapping the core with `#[pymodule]`. Publish to PyPI.

- **npm / WASM package**
  Package the WASM build as an npm module so browser and Node.js applications can call `encrypt`, `decrypt`, and `keygen` directly as JavaScript functions without loading the full egui app.

- **Right-click / context-menu integration**
  Add "Encrypt with pqfile" and "Decrypt with pqfile" to the OS file manager without needing a terminal. On Windows a lightweight shell extension or a simple registry entry pointing at the CLI covers Explorer. On macOS a Quick Action in Automator. On Linux a Nautilus script and a KDE Dolphin service menu entry. All crypto stays in the existing CLI process -- purely a discoverability and convenience layer.

- **Browser-native encrypted file vault (OPFS)**
  Extend the web GUI with a persistent encrypted file vault backed by the Web Origin Private File System API. Files are stored as `.pqf` blobs in OPFS and browsable through a file-manager panel. The session key lives in memory only while the vault is unlocked; an idle timeout or tab close locks it automatically. Turns the one-shot encrypt/decrypt page into a self-contained encrypted file manager with no backend or server involvement.

- **Format specification (docs/FORMAT.md)** ✓ _released_
  Byte-level specification of all `.pqf` and `.pqfa` format versions (v2 through v7), covering the exact field layout, sizes, byte order, and invariants for each header and payload structure. Includes reference test vectors for each version and KEM variant combination.

### Performance

- **Parallel chunk processing with rayon** ✓ _released_
  `--parallel` flag on `pqfile encrypt` and `pqfile decrypt`. Chunks are processed concurrently across available cores using a rayon work-stealing thread pool. Not supported with multiple recipients or compression.

- **Configurable chunk size** ✓ _released_
  `--chunk-size <bytes>` flag on `pqfile encrypt`. Default 64 KiB (v3 format). Non-default values emit v5 format which stores the chunk size in the header so the decryptor reads it automatically. Supported range: 1 to 268435456 bytes.

- **In-place AEAD to eliminate per-chunk allocation** ✓ _released_
  `encrypt_stream` uses `encrypt_in_place_detached`; `decrypt_v3_chunks` uses `decrypt_in_place_detached`. Zero heap allocations per chunk in the streaming hot path.

- **Benchmark regression detection in CI** ✓ _released_
  `bench` job in CI runs criterion benchmarks and compares against the stored baseline. PRs that regress any benchmark by more than 10% receive an alert comment.

### Infrastructure

- **OSS-Fuzz continuous fuzzing** ✓ _released_
  `oss-fuzz/project.yaml`, `Dockerfile`, and `build.sh` provide the integration files. Fuzz targets: `fuzz_header_read` (format parsing), `fuzz_decrypt_bytes` (malformed ciphertext), and `fuzz_pem_parsing` (PEM parsing and key type detection). Nightly CI job runs each target for 120 seconds and uploads crash artifacts on failure.

- **Dependabot** ✓ _released_
  `.github/dependabot.yml` enables weekly PRs for Cargo and GitHub Actions dependencies.

- **Benchmark suite** ✓ _released_
  Criterion benchmarks in `pqfile/benches/crypto.rs` cover `encrypt_bytes`, `decrypt_bytes`, `encrypt_stream`, `decrypt_stream`, and `keygen` at 1 KB, 1 MB, and 100 MB.

---

## v4.0 - API stability release (breaking API changes)

The v4.0 release formalizes the stability commitment started in the v3.x audit. All items listed here are breaking changes relative to v3.x and require a major version bump.

- **Formal 1.0 stability promise**
  Publish STABILITY.md documenting the guaranteed stable surface: `pqfile::encrypt`, `pqfile::decrypt`, `pqfile::sign`, `pqfile::keygen`, `pqfile::keys`, `pqfile::inspect`, and `PqfileError`. Any future change to these modules that removes or renames a public item will require a new major version.

- **Argon2id p=4 for passphrase-protected keys**
  Increase the Argon2id parallelism parameter from p=1 to p=4 for passphrase-protected keys. OWASP recommends p=4 with the same m/t values (64 MiB, 3 iterations) to force brute-force attempts to occupy 4x the memory bandwidth. Migration path: a `pqfile repassphrase` command reads with old params and re-encrypts with new. A version byte in the encrypted body distinguishes the two parameter sets.

- **Passphrase parameter position standardized** ✓ _shipped in v3.3.x_
  The `passphrase: Option<&str>` parameter has been moved to the last position across all signing and rekeying functions (`sign_bytes`, `sign_file`, `rekey_stream`, `add_recipient_stream`, `signcrypt`, `signcrypt_bytes`). This is the primary breaking API change from the v3.x surface audit.

- **Remove file-path wrapper functions** ✓ _shipped in v3.3.x_
  The `encrypt::encrypt(pubkey_path, input_path, output_path)` and `decrypt::decrypt(privkey_path, input_path, output_path, passphrase)` convenience wrappers have been removed. Callers open files themselves and pass `Read`/`Write` impls to the streaming API.

---

## New Directions

These are ideas not yet implemented in any pqfile release. Many are uncommon or absent from other file encryption tools.

### Time-locked encryption

Integrate with the drand League of Entropy randomness beacon to support "decrypt after time T" semantics. The file is encrypted using a key derived from a future beacon round output. Before that round fires, the key material does not exist anywhere. The decryptor polls the beacon automatically and decrypts once the round is published, with no trusted server holding a pre-generated key. Useful for sealed bids, embargoed document releases, future-dated disclosures, and dead-man switch archives.

### Deniable encryption

Produce a `.pqf` file that yields two valid, indistinguishable plaintexts: a real one under the primary key and a decoy under a second duress key. Both decrypt without error and leave no detectable marker distinguishing which is real. VeraCrypt offers this for full-disk volumes but no post-quantum file encryptor provides it. The primary design challenge is accommodating two independently valid ML-KEM shared secrets that each map to a distinct AEAD layer, with an outer header that reveals nothing about which layer is authoritative.

### Attribute-based access control policies

Go beyond M-of-N threshold decryption to support Boolean access policies: for example, "decrypt if holder of key A AND key B, OR key C." Each policy node is an encrypted share of the session key. Evaluation is a small tree walk using Shamir recombination at AND nodes and branch selection at OR nodes. Useful for organizational workflows where decryption requires both a department head key and a security officer key, with a fallback escrow key as an alternative.

### Forward-secret file exchange protocol

A stateful protocol built on pqfile that provides forward secrecy for an ongoing file exchange session between two parties. Each exchange ratchets a shared root secret forward using a new ML-KEM encapsulation, so compromise of the current session key does not expose previously exchanged files. Similar in spirit to the Signal Double Ratchet but adapted for file payloads rather than messages. State is stored in a small JSON ratchet file alongside the key pair.

### Zero-knowledge proof of correct encryption

Allow the encryptor to produce a non-interactive proof that a specific plaintext was encrypted for a specific public key, without revealing the plaintext. A verifier can check the proof against the ciphertext without decrypting. Useful for compliance workflows where an auditor must confirm a regulated document was encrypted for the authorized recipient before leaving the sender's system. The proof is a Sigma protocol (commit-challenge-response) over the KEM ciphertext and a plaintext hash commitment.

### Key ceremony tooling

An interactive guided ceremony mode for high-assurance key generation. Multiple participants each contribute entropy (typed input or hardware-generated) combined via SHA3-256 before seeding key generation, so no single participant can bias the result. The ceremony log records each participant's entropy hash, the combined seed hash, and the resulting public key fingerprint. A quorum can verify the log offline. Targeted at organizations generating long-lived escrow or signing keys in an audited environment, analogous to root CA key ceremonies but built into the tool with no external dependencies.

### Encrypted audit log

An append-only log of encryption and decryption events, stored as a chain of signed and encrypted records. Each record contains the timestamp, command, file fingerprint, and key fingerprint, signed with the operator's ML-DSA signing key and encrypted for an auditor public key. The chaining structure makes silent deletion detectable. Useful for compliance-regulated environments (HIPAA, PCI-DSS) that require evidence of who encrypted or decrypted what and when.

---

## Security considerations that will not change

The following properties are invariants, not roadmap items. Any proposal that weakens them requires explicit justification and a major version bump:

- All cryptographic operations run locally. No data is sent to a server.
- The entire `.pqf` file (header + payload) is authenticated before any plaintext is returned.
- Secret material is zeroized from memory on drop.
- Each encryption produces a fresh KEM ciphertext and a fresh random nonce.
- In hybrid mode, each encryption also produces a fresh ephemeral X25519 scalar.
