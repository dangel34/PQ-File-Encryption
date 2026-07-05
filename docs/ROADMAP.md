# pqfile Roadmap

This document tracks planned improvements, new features, and security work across future releases. Breaking changes to the `.pqf` format or public API always require a major version bump.

---

## v4.0.0 through v4.2.x (complete)

All features from v2.x through v4.2.4 are complete. Items from v10-format work onward are merged to `main` but still in the changelog's `[Unreleased]` section, pending the next tagged release. A full history is available in `docs/CHANGELOG.md`. The highlights:

- ML-KEM (512 / 768 / 1024) and hybrid X25519+ML-KEM-768 key encapsulation (FIPS 203)
- ML-DSA-65 digital signatures and signcrypt (FIPS 204)
- Multi-recipient encryption, Shamir M-of-N threshold key splitting, key revocation
- v8 anonymous recipient format (uniform slot size, no per-slot variant field)
- v9 padded-recipient format (slot count rounded to next power of two with random dummy slots)
- Hardware-backed private keys via OS credential store (Windows, macOS, Linux)
- Streaming AEAD with chunk authentication, parallel processing, zstd compression
- `PqfWriter<W: Write>` streaming encryptor, `PqfReader<R: Read>` streaming decryptor
- `AsyncPqfWriter` and async decrypt backed by Tokio (`pqfile` feature `"async"`)
- `encrypt_stream_pipelined` (I/O and AEAD overlap), `encrypt_mmap` (zero-copy mmap)
- Adaptive chunk sizing: auto-tunes to 16 KiB / 64 KiB / 256 KiB based on file size
- Atomic output writes: all CLI file writes use temp-file-then-rename with directory fsync on Unix
- Structured JSON error codes (`docs/ERROR_CODES.md`)
- `pqfile doctor` diagnostic subcommand for key and ciphertext health checks
- Cross-version compatibility matrix in `pqfile/tests/compat/` covering v2-v9
- Property-based tests (`proptest`) and mutation testing CI (`cargo-mutants`)
- Branchless GF(256) arithmetic in Shamir: constant-time `gf_mul` and `gf_inv` via fixed 7-squaring chain
- Key commitment in chunk-0 AAD: SHA3-256(session_key) bound into first AEAD tag
- `PqfileError::Truncated`: distinguishes clean truncation from authentication failure
- Header validation: `original_size` capped at 1 TiB, recipient count capped at 256
- Encrypted archive format (PQFA), rekey, add-recipient, secure file shredding
- Native GUI (egui), CLI, and WASM web app sharing one core library
- Typed key API, `inspect_stream`, formal stability promise in `STABILITY.md`
- Security hardening pass (v4.1.1): timing oracle closed, signdecrypt stdout buffered, Shamir coefficients zeroized, decompression bomb protection, PqfWriter debug-mode drop panic
- GUI: watchfolder, key expiry/renewal, drag-and-drop, recent files, QR codes, clipboard encrypt/decrypt, SSH key import, passphrase strength meter, segmented sub-tabs, scroll indicators
- `passphrase_strength` promoted to public `pqfile::keygen` API; CLI warns on weak passphrases at keygen
- `#[must_use]` on `PqfWriter::finish` and `AsyncPqfWriter::finish`
- Published to crates.io as `pqfile`; supply-chain audited via `cargo vet` and `cargo deny`
- `PqfileError::NoMatchingRecipient` extended with `slots_tried: usize` field for diagnostic context
- `MultiEncryptBuilder` fluent API wrapping all three multi-recipient formats (v4/v8/v9); `.with_progress(cb)` for progress callbacks
- `encrypt_stream_with_progress`, `encrypt_stream_multi_anon_with_progress`, `encrypt_stream_multi_anon_padded_with_progress`, and `decrypt_stream_with_progress` for progress tracking
- Background thread for encrypt/decrypt on desktop (already present since v4.0); per-file byte progress bar wired into desktop GUI
- `PqfileError` source chaining: `Io(#[from] std::io::Error)` already exposes the root via thiserror's `#[from]` (implies `#[source]`); no other wrapping variants hold actual error sources
- WASM CI smoke test: `pqfile/tests/wasm_smoke.rs` with 4 `#[wasm_bindgen_test]` cases; `wasm-test` job added to ci.yml runs via `wasm-pack test --node`
- Chunk boundary property tests at 16 KiB, 64 KiB, 256 KiB tier edges (off-by-one coverage)
- CLI integration tests: truncated ciphertext and bit-flipped ciphertext both correctly rejected
- `--threads N` global CLI flag caps Rayon worker threads for `--parallel` operations; default 0 uses all cores
- Security hardening pass: bounded the previously-unbounded reads in v2 and `async`-feature decrypt/encrypt; private key and Shamir share files now written with 0600 permissions on Unix; Shamir `split_raw` shares zeroized; GUI passphrase clones re-wrapped in `Zeroizing` before use; hardware credential store moved to byte-native secret storage with transparent legacy-format migration; v9 recipient shuffle retry loop bounded to match v8; `AsyncPqfWriter` gained a debug-mode drop guard; CLI atomic output uses `O_EXCL`; `cargo vet` `audit-as-crates-io` policy gap fixed
- **Passphrase-only encryption (v10 format)**: `--passphrase` encrypt/decrypt mode with no ML-KEM step; Argon2id parameters in-header; `KdfLimitExceeded` ceiling; `--max-kdf-mem`/`--max-kdf-time` CLI flags
- **Compact recipient strings (`pqf1…`)**: `pqfile keygen` prints a Bech32m recipient string; `-r` accepts either PEM path or `pqf1…`; `pqfile fingerprint` subcommand
- **`#![deny(unsafe_code)]` at crate root** with narrow `#[allow(unsafe_code)]` on the sanctioned mmap call
- **Archive mtime and permissions restore**: `extract()` restores `mtime_secs` and `mode` from the PQFA manifest per entry
- **`--force` overwrite protection**: all CLI file-writing subcommands refuse to overwrite an existing output unless `--force` is passed (closes the silent-overwrite footgun from the 2026-07-01 audit)
- **`pqfile check`**: authenticates a `.pqf` end-to-end into a null sink without writing plaintext (named `check` rather than the roadmap's `verify` to avoid colliding with the existing signature-verification subcommand)
- **Windows ACL restriction on private key files**: `write_private_file` now strips inherited ACEs and leaves a single OWNER RIGHTS full-control ACE via `icacls`, mirroring the Unix 0600 behavior
- **Argon2id auto-calibration**: `pqfile doctor --calibrate [--target-ms N]` benchmarks the local machine and recommends `--kdf-mem`/`--kdf-time`; `encrypt --passphrase` accepts them via `encrypt_stream_passphrase_with_params`
- **Default recipient config file**: `~/.config/pqfile/config.toml` / `%APPDATA%\pqfile\config.toml` holding `recipient` and `key` defaults; explicit flags win; global `--no-config` opts out
- **Supply-chain hardening in release artifacts**: SLSA build provenance attestations (`actions/attest-build-provenance`) on all release artifacts, binaries built with `cargo auditable`, `cargo-vet` runs on PRs as well as pushes, and CI no longer skips itself on workflow-file changes. (Remaining manual step: mark `cargo-vet`/`cargo-deny`/`test-and-lint` as required status checks in the GitHub branch-protection settings.)
- **Release binary tuning**: workspace `[profile.release]` with thin LTO, one codegen unit, and symbol stripping for smaller, faster native binaries and WASM bundle
- **SLH-DSA-SHAKE-192f signatures (FIPS 205)**: `sign-keygen --algorithm slh-dsa-shake-192f`; hash-based alternative to ML-DSA-65 at the same security category, auto-detected from the key's PEM tag by all sign/verify/signcrypt paths; plaintext, passphrase-encrypted, and hardware-backed key storage; 192f chosen over 192s because 192s signing is ~20× slower for no category gain
- **GUI `<meta>` CSP**: `pqfile-gui/index.html` carries an in-document Content-Security-Policy so the WASM app is protected even when served without the nginx header snippet
- **Keyfile as a second factor for passphrase mode**: `--keyfile <path>` on v10 `encrypt`/`decrypt`/`check` mixes the keyfile's SHA3-256 hash into the Argon2id derivation as the secret (pepper) input; the v10 header gained a flags byte (bit 0 = keyfile required) with unknown-bit rejection, and missing/superfluous keyfiles fail fast with dedicated errors (codes 23/24/25) before the KDF runs
- **Recursive directory packing with symlink/special-file rejection**: `pqfile archive --recursive` walks directory arguments (entry names keep the directory prefix, like tar), rejecting symlinks, devices, FIFOs, and sockets per-path, and rejecting duplicate entry names including case-insensitive collisions for all archives

---

## v4.x - Planned (no breaking format changes)

### Performance

- **Minimal encrypt-only WASM build**
  Split the `pqfile-gui` WASM output into a full build and a stripped variant that includes only the encrypt path (no Argon2 KDF, no zstd, no Shamir, no signing). The smaller build loads faster for web deployments that only need to encrypt. Publish both from the release workflow.

### Key sharing UX

- **Passphrase on recipient strings**
  `pqfile fingerprint` and `pqfile keygen` already emit `pqf1…` strings; consider a `--qr` flag that produces a scannable QR code for the recipient string without requiring the Shamir tab.

### CLI UX

- **Interactive mode with no arguments**
  Running `pqfile` with no subcommand currently prints clap's help text. Add a guided prompt flow instead (pick encrypt/decrypt/keygen, then fill in the missing pieces interactively), matching FerroCrypt's no-args mode. CLI-layer only; no library changes.

### Supply chain

- **Mark `cargo vet` / `cargo deny` / `test-and-lint` as required CI status checks**
  The `cargo vet` policy gap in June 2026 went unnoticed precisely because the job is not required. The code side is done (vet runs on PRs, SLSA provenance and `cargo auditable` ship since the same change); what remains is the GitHub branch-protection setting itself, which must be flipped in the repository settings by an admin.

---

## v5.0 - Next major (breaking format changes)

These items require a new major version because they change the wire format or public API in a backward-incompatible way.

- **Authenticated header across all format versions**
  Today only the legacy v2 whole-file format feeds the header bytes into the AEAD as AAD; the chunked formats (v3+) authenticate a counter, last-chunk flag, and key commitment per chunk (`make_chunk_aad`), but not the header itself. Bind the serialized header into the chunk-0 AAD for every new file written and bump the version byte. Old files remain readable but new files are protected against header tampering (e.g. flipping the compression flag or `kem_variant`) without any opt-in flag.

- **Per-file entry AEAD in archives (PQFA v2)**
  The current `.pqfa` format authenticates the entire archive before any file is extracted, which requires buffering the full ciphertext in memory for in-memory extractions. A PQFA v2 layout gives each file entry its own AEAD tag derived from the session key and the entry index, so individual files can be extracted and verified without loading the whole archive.

- **`PqfileError` refinement**
  Break `DecryptionFailure` into specific variants: `AuthenticationFailure` (tag mismatch), `Truncated` (clean truncation), `UnsupportedVersion` (unknown format version), `RecipientNotFound` (none of the recipient slots matched). This is an API break but gives callers the precision they need for good error messages.

- **Misuse-resistant nonces (nonce-SIV construction)**
  Replace random nonces with synthetic nonces derived from a hash of the session key and plaintext chunk (a simplified SIV mode). With random nonces, a nonce collision is possible if the same key encrypts a very large number of chunks; SIV derivation makes collision probability zero regardless of how many files are encrypted under a given session key. This is a format break because the nonce field changes meaning in the chunk header.

- **Plaintext length padding (Padmé)**
  v9 hides the recipient count and `--stealth` (below) would hide the file type, but the ciphertext length still reveals the plaintext length almost exactly. Pad the plaintext to a Padmé-bounded size (max ~12% overhead, decreasing with file size) before encryption, storing the true length inside the authenticated stream. Complements v9 and stealth mode to close the last major metadata leak.

- **Magic-free output mode**
  Currently all `.pqf` files begin with the four-byte magic `PQFL`, which immediately identifies them as pqfile output to any observer. A `--stealth` flag omits the magic bytes and version header, producing output that is indistinguishable from random bytes. The decryptor uses `--stealth` as a hint to skip magic validation and attempt raw decryption. Useful when revealing that a file is encrypted at all is itself sensitive.

---

## New Directions

These are ideas not yet implemented. All are focused on cryptographic depth or ecosystem reach.

### Sealed sender

Encrypt without revealing the sender's identity in the ciphertext. The sender derives a one-time signing key pair via HKDF from their long-term signing key and the KEM ciphertext, signs the payload with the ephemeral key, and discards it. The recipient can verify authenticity using the sender's long-term verifying key, but no third party observing the ciphertext can link it to the sender. Useful when the existence of a communication relationship is itself sensitive.

### Deniable encryption

Produce a `.pqf` file that yields two valid, indistinguishable plaintexts: a real one under the primary key and a decoy under a duress key. Both decrypt without error and leave no detectable marker distinguishing which is real. VeraCrypt offers this for full-disk volumes but no post-quantum file encryptor provides it. The design challenge is two independently valid ML-KEM shared secrets each mapping to a distinct AEAD layer, with a header that reveals nothing about which layer is authoritative.

### Time-locked encryption

Integrate with the drand League of Entropy randomness beacon to support "decrypt after time T" semantics. The file is encrypted using a key derived from a future beacon round output. Before that round fires, the key material does not exist anywhere. The decryptor polls the beacon and decrypts once the round is published. Useful for sealed bids, embargoed releases, and dead-man switch archives.

### Forward-secret file exchange protocol

A stateful protocol built on pqfile that provides forward secrecy for an ongoing file exchange session between two parties. Each exchange ratchets a shared root secret forward using a new ML-KEM encapsulation, so compromise of the current session key does not expose previously exchanged files. State lives in a small JSON ratchet file alongside the key pair.

### Attribute-based access control policies

Go beyond M-of-N threshold decryption to support Boolean access policies: "decrypt if holder of key A AND key B, OR key C." Each policy node is an encrypted share of the session key. Evaluation is a tree walk using Shamir recombination at AND nodes and branch selection at OR nodes.

### Encrypted audit log

An append-only log of encryption and decryption events stored as a chain of signed and encrypted records. Each record contains the timestamp, command, file fingerprint, and key fingerprint, signed with the operator's ML-DSA key and encrypted for an auditor public key. The chaining structure makes silent deletion detectable.

### Key ceremony tooling

An interactive guided ceremony mode for high-assurance key generation. Multiple participants each contribute entropy combined via SHA3-256 before seeding key generation so no single participant can bias the result. The ceremony log records each participant's entropy hash, the combined seed hash, and the resulting public key fingerprint.

### Signable public key certificates

A lightweight certificate format where a CA signing key (ML-DSA-65) signs a public key (ML-KEM) along with metadata: a label, a validity window, and an allowed-use bitmask (encrypt-only, sign-only, or both). `pqfile issue-cert` creates the certificate; `pqfile verify-cert` checks the chain. `pqfile encrypt` optionally accepts a certificate instead of a raw public key and validates expiry and allowed-use before encapsulating. This is a minimal PKI layer built entirely from the existing primitives with no external dependencies.

### Split ciphertext storage

A mode where the raw ciphertext bytes are split across N output files using a secret sharing scheme (or simpler XOR splitting for K=N), requiring any K files to reconstruct. Different from key splitting: the key stays intact and the payload itself is distributed. Useful for backup scenarios where the ciphertext is spread across cloud providers that are mutually untrusted; no single provider has a usable ciphertext.

### Constant-time test harness extension

`pqfile/examples/ct_shamir.rs` is a standalone `dudect-bencher` binary covering the Shamir GF(256) reconstruction path. Extension to the decryption error path and passphrase-comparison path remains future work.

### Proxy re-encryption

Generate a re-encryption key `rk(A -> B)` from private key A and public key B. A proxy holding only `rk` can transform a ciphertext encrypted for A into one encrypted for B, without ever seeing the plaintext or either private key. Useful for delegated access: a file server can re-encrypt stored files on behalf of a new recipient without the sender needing to re-encrypt manually.

### Shell integration

Right-click "Encrypt with pqfile" on Windows (Explorer context menu via registry entry), macOS (Quick Action via Automator bundle), and Linux (`.desktop` file). The integration invokes the CLI with the last-used recipient key and writes the output alongside the original.

### Web extension / browser integration

A browser extension (Chrome / Firefox) that embeds the existing WASM core and adds an "Encrypt" action to file-attachment dialogs and an "Encrypt text" context menu item. Encryption runs entirely in the browser process; no data is sent to a server.

### Python and Node.js bindings

Expose core `pqfile::encrypt` and `pqfile::decrypt` as a Python wheel (via PyO3) and an npm package (via wasm-bindgen). Allows Python and Node.js scripts to encrypt and decrypt without shelling out to the CLI.

### Native OS installer packaging

Automate production of signed OS-native installers from the release workflow: MSI via WiX (Windows), DMG via create-dmg (macOS), .deb/.rpm via cargo-deb/rpmbuild (already documented manually in the README), and AppImage via appimagetool (Linux, requires `squashfs-tools`). Currently desktop users must build from source or use the WASM web app. Code-signing and macOS notarization are the long pole here, which is why this stays unscheduled rather than in v4.x Planned.

---

## Security invariants

The following properties are invariants, not roadmap items. Any proposal that weakens them requires explicit justification and a major version bump:

- All cryptographic operations run locally. No data is sent to a server.
- The entire `.pqf` file (header + payload) is authenticated before any plaintext is returned.
- Secret material is zeroized from memory on drop.
- Each encryption produces a fresh KEM ciphertext and a fresh random nonce.
- In hybrid mode, each encryption also produces a fresh ephemeral X25519 scalar.
