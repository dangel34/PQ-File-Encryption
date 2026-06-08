# Changelog

All notable changes to pqfile are documented in this file. Versions follow semantic versioning. Breaking changes to the `.pqf` file format or key format always require a major version bump.

---

## [4.2.1] - 2026-06-08

### Performance

- **Pre-compressed WASM assets**: `pqfile-gui` build now runs `wasm-opt` and ships Brotli/gzip pre-compressed assets alongside a service worker for offline support, reducing initial load size.

### Fixes

- **Publish workflow**: corrected `curl` command in `publish.yml` that could misreport HTTP errors during the crates.io idempotency check.

### Dependencies

- `ml-dsa` 0.1.0 → 0.1.1 (bug fixes in the ML-DSA-65 implementation)
- `notify` 7.0.0 → 8.2.0 (filesystem watcher; API-compatible for the watchfolder feature)
- `taiki-e/install-action` CI action 2.81.3 → 2.81.8

---

## [4.2.0] - 2026-06-05

### New features

- **Legal Notices modal**: a scrollable in-app legal page covering what pqfile is, no-warranty and no-liability disclaimers, U.S. export control obligations (EAR / License Exception TSU, 15 CFR 742.15(b)), responsible security disclosure instructions, and a link to the Privacy Policy.
- **Footer links**: the footer now shows "Legal" (opens the Legal Notices modal) and "Privacy" (links to the Privacy Policy) alongside the existing version label.

---

## [4.1.1] - 2026-06-02

### Security

- **`gf_inv` constant-time fix** (`shamir.rs`): The field inversion helper previously used a data-dependent exponentiation loop that ran a variable number of iterations depending on secret share bytes. It has been replaced with a fixed 7-squaring chain (`x^254 = x^128 * x^64 * x^32 * x^16 * x^8 * x^4 * x^2`) that runs identically for all non-zero inputs. `gf_pow` was removed entirely.
- **`find_session_key` timing oracle closed** (`decrypt.rs`): In the v4/v7 multi-recipient path, the function previously returned early on the first successful slot, revealing via timing which slot position matched. It now iterates every same-variant entry and stores the first success, matching the behavior of `find_session_key_v8`.
- **`signdecrypt` CLI stdout path hardened** (`main.rs`): `pqfile signdecrypt` writing to stdout previously streamed plaintext before the ML-DSA signature was verified. The stdout path now buffers into a `Zeroizing<Vec<u8>>` and writes to stdout only after `signdecrypt` returns `Ok(())`. File output paths were already safe via `AtomicOutput`.
- **Shamir polynomial coefficients zeroized** (`shamir.rs`): `coeff_buf` in `split_raw` was a plain `Vec<u8>` holding the random polynomial coefficients used during share generation. It is now wrapped in `Zeroizing`, so the coefficients are overwritten when the split operation returns.
- **Decompression bomb protection** (`decrypt.rs`): v6 (compress-then-encrypt) decompression now feeds the zstd decoder through a new `LimitedWriter` that returns an error if decoded output exceeds `original_size` (or `MAX_ORIGINAL_SIZE` when `original_size` is zero). Previously a crafted file with a tiny compressed payload could expand the decoder output without bound.
- **`PqfReader` streaming plaintext zeroized** (`reader.rs`): The per-chunk plaintext buffer in `ReaderState::Streaming` has been changed from `Vec<u8>` to `Zeroizing<Vec<u8>>`. `zeroize()` is called on the buffer before each reuse, ensuring decrypted bytes are overwritten before the next chunk fills the same allocation.

### Bug fixes

- **`pqfile doctor` legacy key detection** (`main.rs`): `doctor_key` previously used a dummy passphrase when probing whether a key was encrypted with the legacy p=1 Argon2id parameters, so the probe always failed and `legacy_argon2_p1` was always reported as false. It now calls `maybe_prompt_passphrase` to obtain the real passphrase before probing. p=1 keys are now reliably identified.
- **Parallel decrypt `Truncated` error** (`decrypt.rs`): `decrypt_stream_parallel` returned `PqfileError::DecryptionFailure` for streams that ended without a final chunk. It now returns `PqfileError::Truncated` when `is_last && counter > 0`, matching the behavior of the serial path and `PqfReader`.

### Improvements

- **`PqfWriter` drop guard** (`writer.rs`): `PqfWriter::drop` now panics in debug builds (`#[cfg(debug_assertions)]`) when `finish()` was not called, surfacing forgotten finish calls during development. Release builds keep the previous best-effort seal-on-drop behavior.
- **`encrypt_mmap` sequential prefetch hint** (`encrypt.rs`): `mmap.advise(Advice::Sequential)` is now called on Unix after the mapping is created, hinting to the kernel that pages will be read linearly and allowing readahead to reduce page-fault stalls during encryption.
- **`AtomicOutput` directory fsync** (`main.rs`): `AtomicOutput::commit` now opens and fsyncs the parent directory on Unix after the rename, ensuring the directory entry is durable on power loss and not just the file data.
- **`archive::create_from_memory` single buffer** (`archive.rs`): Entry data is now appended to one contiguous `Vec<u8>` instead of cloning each entry into a separate allocation, roughly halving peak memory for multi-file in-memory archives.
- **`json_escape` control character coverage** (`main.rs`): Characters U+0001 through U+001F (other than `\n`, `\r`, `\t`) were previously written unescaped, producing invalid JSON on any control character in an error message or filename. They are now escaped as `\uXXXX`.

---

## [4.1.0] - 2026-06-02

### New features

- **`PqfWriter<W: Write>`**: streaming encryptor in `pqfile::writer`. Buffers plaintext in `write()`, seals the final chunk in `finish()`, and makes a best-effort seal on drop. Completes Read/Write symmetry with `PqfReader`.
- **`AsyncPqfWriter<W: AsyncWrite + Unpin>`**: async streaming encryptor in `pqfile::async_io` (feature `"async"`). Accepts plaintext via `AsyncWrite::write`, seals on `finish()` or `poll_shutdown()`.
- **`encrypt_stream_pipelined`**: overlaps disk reads and AEAD encryption using a bounded two-buffer producer/consumer channel. Eliminates CPU idle time on I/O-bound storage. CLI `--pipeline` flag.
- **`encrypt_mmap`**: zero-copy encrypt via memory-mapped I/O (`memmap2`). Native builds only. CLI `--mmap` flag.
- **`encrypt_stream_multi_anon_padded`**: v9 format. Pads the recipient list to the next power of two with random dummy slots so an observer learns only 1/2/4/8/... slots exist, not the exact count. CLI `--pad-recipients` flag.
- **Adaptive chunk sizing**: `format::adaptive_chunk_size(file_size)` returns 16 KiB for files under 1 MiB, 256 KiB for files over 256 MiB, and 64 KiB otherwise. CLI `--chunk-size 0` (the new default) triggers auto-tune. The chosen size is stored in v5 format.
- **Atomic output writes**: all CLI file writes now use `AtomicOutput` (temp file + rename + fsync). A killed process leaves no partial artifact.
- **Structured JSON error codes**: every JSON error response includes `"code": N`. A 21-entry stable code table is defined in `docs/ERROR_CODES.md`.
- **`pqfile doctor`**: new CLI subcommand. Inspects a PEM key or `.pqf` file and reports passphrase status, hardware/legacy detection, revocation sidecar presence, format version, and header sanity without decryption.
- **`PqfileError::Truncated`**: returned when a streaming decrypt ends without a final chunk (clean truncation rather than corruption). `PqfReader` surfaces it as `io::ErrorKind::UnexpectedEof`.
- **Cross-version compatibility matrix**: golden ciphertext files for all format versions (v2 through v8) committed to `pqfile/tests/compat/`. Eleven roundtrip tests run on every CI push.
- **Property-based tests** (`proptest`): `pqfile/tests/property.rs` covers encrypt/decrypt roundtrip, single-byte tamper detection, and Shamir split/reconstruct invariants.
- **Mutation testing CI**: `.github/workflows/mutants.yml` runs weekly against `decrypt.rs`, `format.rs`, `shamir.rs`, and `passphrase.rs`.

### Security

- **GF(256) constant-time fix** (`shamir.rs`): `gf_mul` previously had a data-dependent branch (`if high != 0 { a ^= 0x1B; }`) that could leak bits of the secret share value `yj` through timing. Both conditionals are now replaced with branchless mask idioms (`a = (a << 1) ^ (0x1B & 0u8.wrapping_sub(a >> 7))`). The loop runs exactly 8 iterations for all inputs. A `dudect` statistical benchmark and a `--features timing-tests` unit test are provided for local verification.
- **Key commitment in chunk-0 AAD**: the first AEAD chunk now includes `SHA3-256("pqfile-session-key-commitment" || session_key)` as additional data, binding each file to the specific session key. Prevents KEM ciphertext substitution and multi-key collision attacks. Static test vectors regenerated.
- **Header validation hardening**: `original_size > 1 TiB` is rejected at parse time. Recipient count cap lowered from 1000 to 256 and extracted as a named module constant.

### Bug fixes

- `PqfReader` now emits `io::ErrorKind::UnexpectedEof` (wrapping `PqfileError::Truncated`) for mid-stream truncation rather than a generic authentication failure.

---

## [4.0.0] - 2026-06-01

### Breaking changes

- **Argon2id p=4**: All new passphrase-protected keys use `p=4` (up from `p=1`). Keys encrypted with p=1 (pre-4.0) return `PqfileError::LegacyKeyFormat` and must be migrated with `pqfile repassphrase --from-legacy` before use.
- **v8 anonymous format**: `--anonymous-recipients` now emits v8, which drops the per-slot `kem_variant` field entirely. All slots are a uniform 1616 bytes. v7 files remain readable but v7 write is removed.
- **`pqfile` library at 4.0.0**: The library crate version now matches the CLI/GUI version sequence. `PqfileError::LegacyKeyFormat` is a new variant introduced in this release.

### New features

- **Hardware-backed private keys**: `pqfile keygen --hardware` and `pqfile sign-keygen --hardware` store the key seed in the OS credential store (Windows Credential Manager, macOS Keychain, Linux Secret Service). The seed never touches disk.
- **`pqfile repassphrase`**: Change or upgrade the passphrase on any key type. Pass `--from-legacy` to migrate a p=1 key to p=4.
- **Async I/O** (`pqfile` feature `"async"`): `encrypt_stream_async` and `decrypt_stream_async` backed by Tokio. Ciphertext format is identical to the synchronous API.
- **STABILITY.md**: Formal 1.0 stability promise for the public API surface.

---

## [3.3.0] - 2026-06-01

### Breaking changes

- **Shamir share format**: The `pubkey_fp` field in each share PEM body grew from 8 bytes to 16 bytes (`SHARE_HEADER_LEN` changed from 14 to 22). Shares produced by v3.1.x or earlier are not compatible and are now rejected with a clear error rather than silently producing incorrect output.
- **signcrypt parameter order**: `sign_passphrase: Option<&str>` moved to the last position in `signcrypt`, `signcrypt_bytes`. Callers that passed positional arguments must update their call sites.
- **Hybrid HKDF salt**: HKDF for the hybrid X25519+ML-KEM-768 key exchange was corrected to use no explicit salt (previously a fixed zero salt was passed incorrectly). Files encrypted with a hybrid key before this fix cannot be decrypted by v3.3.x, and vice versa. Pure ML-KEM files are unaffected.

### Security

- `KemVariantMismatch { key, file }` error added. `decrypt_stream` and `decrypt_bytes` now return this distinct variant when the private key's KEM variant does not match the file header, rather than the generic `UnsupportedKem`. Callers can pattern-match to present a specific diagnostic.
- `UnsupportedKem` is no longer returned for key/file variant mismatches; it is now reserved for genuinely unrecognised KEM variant identifiers in on-disk data.
- Shamir `decode_share_pem` explicitly detects shares produced with the old 8-byte fingerprint layout (v3.1.x and earlier) and returns a clear error instead of producing garbage results.
- Constant-time note: the `gf_mul` loop in GF(256) arithmetic branches on its second argument. In the Lagrange interpolation path, that argument is always a Lagrange coefficient derived from public share indices, so timing does not depend on secret share bytes. This is now documented in the source.
- Shamir `reconstruct_raw` now borrows `y` slices rather than taking owned `Vec<u8>`, eliminating an intermediate non-zeroizing copy of sensitive share material.
- Streaming decrypt_v6 path added: compressed-then-encrypted (v6) files can now be decrypted via `decrypt_stream` without first buffering the entire decompressed payload.
- `signdecrypt` explicitly documents the v6 limitation (PqfReader does not support compressed files) and the write-before-verify hazard.

### API changes

- Constants renamed for clarity: `KEM_VARIANT` -> `KEM_VARIANT_768`, `KEM_CT_LEN` -> `KEM_CT_LEN_768`, `EK_LEN` -> `EK_LEN_768`, `HEADER_LEN` -> `HEADER_LEN_768`.
- `signcrypt_bytes` added: signs and encrypts a `&[u8]` in a single pass without requiring `Seek`.
- `#[non_exhaustive]` applied to `PqfileError`, `SplitResult`, `SignKeygenResult`, `ArchiveEntry`, `PqfHeaderInfo`. Future variants/fields can be added without a semver break.
- `#[must_use]` applied to all fallible public functions.
- Internal types (`PqfHeader`, `PqfHeaderV4`, `PqfHeaderV7`, `RecipientEntryV4`, `RecipientEntryV7`) and the `passphrase` module are now `pub(crate)`.
- All 12 PEM tag constants in `keygen` are now `pub(crate)`.
- CLI and GUI `inspect` commands migrated to `inspect_stream` (typed `PqfHeaderInfo` enum) rather than raw internal format structs.
- File-path wrapper functions `encrypt::encrypt` and `decrypt::decrypt` removed. Callers open files and pass `Read`/`Write` impls to the streaming API directly.

---

## [3.2.0] - 2026-05-28

### Added

- Anonymous recipients (v7 format): `--anonymous-recipients` on `pqfile encrypt` pads all recipient KEM ciphertext slots to 1568 bytes (the ML-KEM-1024 ciphertext length) and writes entries in randomized order. An observer cannot determine the number of recipients or which key variants are in use. Requires multiple `-r` recipients; single-recipient files are unaffected.
- Signcrypt and signdecrypt: `pqfile signcrypt -k sign_privkey.pem -r pubkey.pem <file>` signs the plaintext under ML-DSA-65 and embeds the signature inside the AEAD-authenticated ciphertext. `pqfile signdecrypt -k privkey.pem -v sign_pubkey.pem <file.pqf>` decrypts and verifies in one step. The embedded signature cannot be stripped or substituted after encryption. Stdin is not supported as input because signcrypt requires two passes over the file. Note: `signdecrypt` streams plaintext to the output writer before the ML-DSA signature is verified; callers should write to a `Vec<u8>` and only act on the data after the function returns `Ok(())`.
- Encrypted archive and extract: `pqfile archive -r pubkey.pem [files...] -o bundle.pqf` packs multiple files into a single authenticated archive. `pqfile extract bundle.pqf -k privkey.pem [-o dir] [--list]` restores files or lists contents. Path-traversal entries are rejected on extract. All AEAD authentication is verified before any file is written to disk.
- Threshold key splitting via Shamir secret sharing: `pqfile split-key --threshold M --shares N privkey.pem --out <dir>` splits a private key seed into N shares over GF(256). `pqfile reconstruct-key share_1.pem share_2.pem ... --out <dir>` reassembles the seed from any M shares. Fewer than M shares reveal nothing about the key.
- Parallel chunk processing: `--parallel` flag on `pqfile encrypt` and `pqfile decrypt` uses a rayon work-stealing thread pool to process independent AEAD chunks concurrently. Not supported with multiple recipients or `--compress`.
- Passphrase-protected ML-DSA-65 signing keys: `pqfile sign-keygen --passphrase` encrypts the 32-byte signing seed with AES-256-GCM using an Argon2id-derived key (same parameters as KEM keys: m=64 MiB, t=3, p=1). New PEM label: `ML-DSA-65 ENCRYPTED SIGNING KEY`. `pqfile sign` and `pqfile signcrypt` auto-detect the encrypted label and prompt for the passphrase interactively.
- Key revocation: `pqfile revoke --key pubkey.pem --reason "..."` creates a `pubkey.pem.revoked` JSON sidecar containing the key fingerprint and reason. `pqfile encrypt` checks for a `.revoked` sidecar alongside each recipient public key and aborts with a clear error if one is found. The sidecar is a plain JSON file checked at encrypt time (not signed; signed revocation is a future roadmap item).
- Compress-then-encrypt (`--compress`, `--compress-level`): `pqfile encrypt --compress -r pubkey.pem file` compresses plaintext with zstd before encryption, producing a v6 `.pqf` file. `--compress-level <1-22>` (default 3) trades speed for ratio. Decompression is automatic on decrypt. Only supported with a single recipient (incompatible with multi-recipient v4 format). Not available in WASM builds (zstd requires C FFI). New format constants: `VERSION_V6 = 0x06`, `COMPRESSION_NONE = 0x00`, `COMPRESSION_ZSTD = 0x01`.
- Rekey without payload re-encryption: `pqfile rekey --key old_privkey.pem --recipient new_pubkey.pem -o out.pqf in.pqf` decapsulates the session key with the old private key, re-encapsulates it under the new public key, and rewrites only the header. Payload ciphertext bytes are streamed through unchanged. Produces a valid v4 `.pqf` file. Supported for v3 and v5 files with the default 64 KiB chunk size.
- `PqfReader<R: Read>`: a streaming decryptor that wraps any `R: Read` source and implements `Read`, yielding decrypted plaintext bytes incrementally. Supports v2, v3, v4, and v5 files. Exposes a `.info()` method returning `PqfInfo` (version, KEM variant, original size, chunk size). Each AEAD chunk is verified before plaintext bytes are yielded; a tampered chunk returns an I/O error. Available as a public library type in `pqfile::reader`.
- GUI compress checkbox (native only): an "compress before encrypting" checkbox on the Encrypt tab, enabled only when a single recipient is selected. A level slider (1-19) appears when compression is active.
- cargo-vet exemptions for `zstd 0.13.3`, `zstd-safe 7.2.4`, and `zstd-sys 2.0.16+zstd.1.5.7`.

### Security

- `rekey_stream` now rejects v2 (whole-file AEAD) files with `UnsupportedVersion(0x02)`. Previously v2 files were silently accepted and produced a v4 output file that could never be decrypted because the payload format is incompatible with the v4 streaming chunk layout.
- v5 and v6 `CHUNK_SIZE` fields are validated on decode. Values of zero or greater than 268435456 are rejected with an I/O error. A crafted file with `chunk_size = u32::MAX` previously caused an out-of-memory allocation attempt.
- v4 and v7 recipient counts are capped at 1000 on decode. A crafted file with `COUNT = 65535` previously caused a large allocation before any I/O validation.
- `extract_json_str` in the revocation sidecar reader now includes the colon in the JSON key needle (`"fingerprint":` instead of `"fingerprint"`). The previous form could match a key prefix such as `"fingerprint_extra":` in a crafted sidecar and return the wrong value, potentially allowing revocation to be bypassed without deleting the sidecar file.
- `encrypt_stream_compressed` now streams through a `zstd::stream::read::Encoder` rather than buffering the full compressed payload in a `Vec`. Peak memory for compress-then-encrypt operations is now O(chunk_size) instead of O(file_size).
- Fisher-Yates shuffle in `encrypt_stream_multi_anon` (v7 format) replaced with a rejection-sampling loop that eliminates modulo bias.

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
