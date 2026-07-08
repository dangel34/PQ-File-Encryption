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
- **Authenticated headers (`VERSION_AUTH_BIT`)**: new files set bit 7 of the version byte and bind `chunk_size`, `compression_algo`, and the v10 KDF fields into the chunk-0 key commitment (v3 definition, distinct domain separation), closing the compression-flag-flip gap; the version byte and `kem_variant` stay excluded so zero-copy `rekey`/`add-recipient` still work; old files remain readable and old pqfile versions reject new files with a clean `UnsupportedVersion`. Implemented without new per-layout version bytes, so no v5.0 wire-format redesign was needed (release versioning decision, 4.x vs 5.0, still open since older readers cannot read newly written files)
- **`--qr` on `keygen` and `fingerprint`**: renders the `pqf1…` recipient string as a terminal unicode QR code (uppercased for the denser QR alphanumeric mode; Bech32m is case-insensitive); goes to stderr under `--json`
- **Constant-time harness extension**: `examples/ct_decrypt.rs` (tamper-position classes on the AEAD reject path) and `examples/ct_passphrase.rs` (unrelated vs near-miss wrong passphrase on v10) join `ct_shamir.rs`; all three use the same dudect-style Welch t-test
- **Interactive no-args CLI mode**: running bare `pqfile` (no subcommand, no flags) drops into a guided prompt flow for encrypt/decrypt/keygen instead of clap's usage text; any argument (including `--help`) still takes the normal clap path. CLI-layer only, delegates to the same `run_*` functions as the flag-driven paths so behavior stays identical.
- **Plaintext length padding (Padmé)**: `pqfile::padding::padme_length`/`PadmeReader`/`TruncatingWriter` and `encrypt --pad` round the plaintext length to a coarser bucket (≤ ~12% overhead) before encryption, so ciphertext length no longer reveals the exact plaintext size. The true length still travels in the existing authenticated `original_size` header field; decrypt strips the padding back off by capping output at that field (a no-op for every non-padded file, so no `--pad` flag is needed at decrypt time). Incompatible with stdin input, empty files, `--mmap`, `--pipeline`, and `--compress` (compression would shrink the padding back down). Shipped without a wire-format change - no version bump required.
- **Magic-free stealth mode**: `encrypt --stealth` / `decrypt --stealth` / `check --stealth` (new library functions `encrypt_stream_stealth`/`decrypt_stream_stealth`) omit the `.pqf` magic, version byte, and KEM variant field entirely; wire layout is `KEM_CT || BASE_NONCE(8) || ORIGINAL_SIZE(8) || <chunked ciphertext>`, using the recipient's own key type (known to the decryptor already) instead of a variant field. Single recipient only; composes with `--pad`. There is nothing on the wire to auto-detect, so the caller must already know a file was written in stealth mode. See `docs/FORMAT.md` §6.

---

## v4.x - Planned (no breaking format changes)

Ranked by security value per unit of effort (2026-07-08 ecosystem review): cheap CI and supply-chain wins first, then hardening work, then performance. Item 1 is the only one that requires no code.

### 1. Mark `cargo vet` / `cargo deny` / `test-and-lint` as required CI status checks

The `cargo vet` policy gap in June 2026 went unnoticed precisely because the job is not required. The code side is done (vet runs on PRs, SLSA provenance and `cargo auditable` ship since the same change); what remains is the GitHub branch-protection setting itself, which must be flipped in the repository settings by an admin.

### 2. `cargo-semver-checks` CI job

`STABILITY.md` makes a formal API promise and `pqfile` is published to crates.io, but nothing verifies that promise mechanically. [`cargo-semver-checks`](https://crates.io/crates/cargo-semver-checks) compares the crate's current API against the last published version via rustdoc JSON and flags accidental breaking changes before they ship; it is used by tokio, PyO3, and Cargo itself, and analysis of the top 1000 crates found roughly 1 in 6 has shipped an unintentional semver break. Add it as a job in `ci.yml` and as a pre-publish gate in `publish.yml`, then fold it into the required-checks list from item 1.

Implementation notes: use `obi1kenobi/cargo-semver-checks-action` (pinned by commit SHA like every other action in this repo) or install the tool and run `cargo semver-checks --package pqfile --all-features` so the `async` surface is covered. The baseline is the latest published `pqfile` on crates.io (currently 4.2.4), fetched automatically, so no old-tag checkout is needed. Check the library crate only; `pqfile-cli` and the GUI crates make no API promise (see `STABILITY.md`). In `publish.yml`, the gate belongs before the `cargo publish -p pqfile` step. An intentional break passes as soon as the version is bumped to the next major, so the gate never blocks a planned v5.0.

### 3. Scheduled dependency advisory scan

`cargo deny` checks RustSec advisories, but only on push and PR, so a CVE published against a dependency while the repo is idle goes unnoticed until the next commit. Add a `schedule:` cron trigger (daily or weekly) to the deny job with a notification on failure. The January 2026 `ml-dsa` timing side channel (CVE-2026-22705, patched in 0.1.0-rc.2) is exactly the class of event this catches; pqfile happened to already be on a fixed version, but only by luck of timing.

Implementation notes: a `schedule:` trigger fires every job in its workflow file, so put the cron in a new dedicated workflow (for example `.github/workflows/advisories.yml`) rather than adding it to `ci.yml`. Run `EmbarkStudios/cargo-deny-action` with `command-arguments: "advisories"` only; licenses, bans, and sources cannot change without a commit, so re-checking them nightly is noise. For notification, do not rely on GitHub's default scheduled-failure email (it goes only to the last committer of the workflow file); add an `if: failure()` step with `issues: write` permission that opens or updates a pinned tracking issue via `gh issue`. The existing `deny.toml` ignores (RUSTSEC-2026-0192/0194/0195, all eframe or wayland transitive build-time deps) stay suppressed as intended; the scheduled run keeps the rest of the tree honest between commits.

### 4. `zizmor` workflow audit

The six GitHub Actions workflows pin their actions, but pinning does not catch template injection, credential persistence, over-broad token permissions, or cache-poisoning vectors. [`zizmor`](https://github.com/zizmorcore/zizmor) statically audits workflow files for all of these. Given the supply-chain investment already made (vet, deny, SLSA provenance, auditable builds), auditing the workflows themselves is the consistent next step, and it is a one-job addition.

Implementation notes: one `ci.yml` job running `zizmor .github/workflows/` (install via a pinned release binary or `uvx zizmor`); pass `GH_TOKEN` so the online audits (ref confusion, stale action pins) run too. Findings to expect on first run, worth triaging rather than blanket-silencing: every `actions/checkout` in the repo persists credentials by default (add `persist-credentials: false` except where a later step pushes, like the bench job's gh-pages write); `${{ github.event.release.tag_name }}` is interpolated directly into `run:` blocks in `publish.yml` (template-injection class; route it through an `env:` var); and the self-hosted deploy job in `publish.yml`, which zizmor flags on principle and which is an accepted risk here.

### 5. Compat-matrix vectors for v10, keyfile, stealth, and padding

The frozen-ciphertext matrix in `pqfile/tests/compat/` stops at v9. The v10 passphrase format, the keyfile flags-bit variant, stealth mode, and Padmé padding are all shipped wire behavior with zero committed vectors, so a byte-level regression in any of them would sail past the compat suite that exists precisely to catch that. All four are cheap to freeze: a v10 vector decrypts with a fixed passphrase committed in the test (plus a committed keyfile for the flags-bit variant); a stealth vector needs its private key and known parameters committed alongside, since there is nothing on the wire to auto-detect; a padded vector locks in the decrypt-side `original_size` truncation behavior. Extend `pqfile/examples/gen_compat_vectors.rs` and the matrix test to cover them, and make it policy that any future format addition lands with its vector in the same PR.

### 6. Multithreaded zstd compression

The `zstd` crate's `zstdmt` feature exposes `ZSTD_c_nbWorkers`. Compression currently runs single-threaded even inside the `--parallel` and pipelined paths, making it the likely bottleneck for large compressible inputs. Output stays standard zstd frames, so there is no format impact and decompression is unchanged. One Cargo feature plus one encoder parameter, gated by the existing `--threads` cap.

Implementation notes: the single call site is `encrypt_stream_compressed` (`pqfile/src/encrypt.rs`), which wraps the plaintext reader in `zstd::stream::read::Encoder`; enable the `zstdmt` feature on the existing non-WASM `zstd` dependency and call `Encoder::multithread(n)` before streaming. The worker count is zstd's own internal thread pool, separate from Rayon, so the CLI's global `--threads` cap (which today only sizes the Rayon pool in `pqfile-cli/src/main.rs`) has to reach the encoder as an explicit parameter or via `rayon::current_num_threads()`. The decompression side needs no change, and WASM is unaffected because `zstd` is already a non-wasm32 dependency.

### 7. Memory locking for in-flight secrets

Zeroize-on-drop does not stop a live secret from being swapped to disk or captured in a crash dump. An internal `LockedSecret` wrapper built on [`memsec`](https://crates.io/crates/memsec) (`mlock`/`VirtualLock` plus `mprotect`) would cover the session key, decapsulated KEM shared secrets, Argon2id output, and passphrase buffers while they are alive, complementing the existing `Zeroizing` discipline. Must degrade to plain `Zeroizing` on WASM, where page locking does not exist. [`shush-rs`](https://github.com/Eyob94/shush-rs) and [`secrets`](https://crates.io/crates/secrets) are higher-level alternatives if the raw `memsec` surface proves awkward.

Implementation notes: put the wrapper in a new `pqfile/src/secret.rs`. Concrete coverage targets, in priority order: the per-file session key and the HKDF-combined hybrid secret (`hybrid_hkdf` in `pqfile/src/format.rs`, plus the key material flowing through `encrypt.rs` and `decrypt.rs`), Argon2id output and passphrase bytes (`pqfile/src/passphrase.rs`), and private-key seed bytes while loaded (`pqfile/src/keys.rs`). Treat lock failure as soft: unprivileged `mlock` quotas (`RLIMIT_MEMLOCK`) and the Windows `VirtualLock` working-set quota are small by default, so on failure fall back to plain `Zeroizing` rather than erroring, and use the same fallback unconditionally on wasm32. Do not attempt to lock plaintext or chunk buffers; they are large enough to exhaust the quota immediately and are not long-lived key material.

### 8. Optional formally verified ML-KEM backend (`libcrux-ml-kem`)

Cryspen's [`libcrux-ml-kem`](https://crates.io/crates/libcrux-ml-kem) implements all three ML-KEM variants with code verified in F* (via hax) for panic freedom, correctness, and secret independence, plus AVX2 and NEON backends that outperform the pure-Rust `ml-kem` crate. A feature-gated backend (`kem-libcrux`) behind the existing typed-key API would let users opt into the verified implementation with no wire-format change, and enables a permanent cross-implementation oracle test in CI: encapsulate with one implementation, decapsulate with the other, for every variant. Caveat for honest documentation: independent analysis ([eprint 2026/192](https://eprint.iacr.org/2026/192.pdf)) found only ~58% of the Rust proof surface is actually SMT-checked and the NEON backend is admitted without proofs, so this is defense in depth, not a silver bullet.

Implementation notes: all ML-KEM key handling is already centralized in `pqfile/src/keys.rs`, where private keys are stored as seeds and expanded via `DecapsulationKey*::from_seed`, so the backend switch stays confined to one module behind the typed-key API. The first thing to verify is seed compatibility: both crates implement FIPS 203 `ML-KEM.KeyGen_internal`, so the same 64-byte seed must expand to byte-identical key pairs, but that equivalence is exactly what the oracle test should prove before anything ships. Keep `ml-kem` compiled as a dev-dependency even when the `kem-libcrux` feature is active, so the CI cross-implementation test (encapsulate with one crate, decapsulate with the other, for 512/768/1024 and the hybrid path) always has both sides available.

### 9. Deterministic benchmark gate (`iai-callgrind`)

The criterion-based CI regression check measures wall-clock time on shared runners, which forces loose thresholds to avoid false alarms. [`iai-callgrind`](https://crates.io/crates/iai-callgrind) counts instructions under Valgrind, which is deterministic, allowing the gate to tighten to 1-2% regressions. Keep criterion for local human-readable numbers; the iai job is Linux-only, which is fine for a gate.

Implementation notes: this needs its own bench target (a second `[[bench]]` entry with `harness = false`, for example `pqfile/benches/iai.rs`) alongside the existing criterion `crypto` bench, plus `valgrind` from apt and `iai-callgrind-runner` installed at the exact same version as the `iai-callgrind` library crate (a version mismatch is a hard error, so pin both to one version string). Gate via the built-in regression limits on instruction counts, or by saving a baseline from main and comparing on PRs; do not route it through `github-action-benchmark`, which only parses criterion's bencher output. Bench the AEAD, KEM, Shamir, and header paths; skip or down-parameter the Argon2id benches, since a deliberately memory-hard KDF under callgrind's roughly 20x slowdown would dominate the CI time budget for no signal.

### 10. Profile-guided optimization for release binaries

[`cargo-pgo`](https://github.com/Kobzol/cargo-pgo) automates the instrument / run-workload / rebuild cycle. On top of the existing thin-LTO release profile, 5-15% is typical for hot crypto loops. The workload step (a representative encrypt/decrypt corpus) adds release-pipeline complexity, so do this after item 9 exists and the win can be measured rather than assumed.

Implementation notes: requires the `llvm-tools-preview` toolchain component; the flow is `cargo pgo build`, run the workload against the instrumented binary, then `cargo pgo optimize build`. The workload script should exercise every hot path once: encrypt and decrypt across all KEM variants and both AEAD suites, compression on and off, a v10 passphrase file, and one multi-recipient file. This applies only to the native binaries in `release.yml`; there is no PGO path for the WASM bundle.

### 11. CodeQL scanning

CodeQL's Rust support is generally available since October 2025, including no-build scanning, and is free for public repositories via default setup. It overlaps SonarQube but its taint-tracking query suite is different, and alerts land natively in the GitHub Security tab. Cheap to enable; ranked last only because the marginal finding rate over the existing SonarQube + clippy + fuzzing stack is uncertain.

Implementation notes: prefer the default setup toggle (repository Settings, Code security and analysis) over a committed workflow file; Rust scans with `build-mode: none`, so no build customization is needed. If a workflow file is used instead, it needs `security-events: write` permission and should be added to the zizmor audit scope from item 4.

### Standing guideline: BLAKE3 for new non-format hashing

SHA3-256 stays everywhere it appears in the wire format or key fingerprints (compatibility is binding). But new surfaces that never touch the format, such as a future audit log, `doctor` file hashing, or dedup checks, should prefer [`blake3`](https://crates.io/crates/blake3): roughly 10x faster and internally parallel. Recorded here so SHA3 does not get baked into new features by reflex.

---

## v5.0 - Next major (breaking format changes)

These items require a new major version because they change the wire format or public API in a backward-incompatible way (or, for new KEM/cipher variants, produce files that older readers reject). Ranked.

- **X-Wing as the hybrid KEM (standards alignment)**
  Replace the bespoke X25519+ML-KEM-768 combiner with [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), the IETF CFRG general-purpose PQ/T hybrid KEM, using the RustCrypto [`x-wing`](https://github.com/RustCrypto/KEMs/tree/master/x-wing) crate (built on the same `ml-kem` and `x25519-dalek` pqfile already depends on). X-Wing carries a formal security proof (secure if SHA-3 and either component is secure) and is on an RFC track, which buys interoperability and external review that a homegrown combiner never gets. Technically this could ship additively as a new KEM variant ID in 4.x, but since older readers cannot read the files it belongs with the other compatibility-affecting work. The existing hybrid variant stays readable forever. Code anchors: the current bespoke combiner is `hybrid_hkdf` in `pqfile/src/format.rs` (HKDF-SHA256 over both shared secrets), hybrid keygen lives in `pqfile/src/keygen.rs`, and KEM variant IDs are defined in `format.rs`; X-Wing replaces the combiner and the two-ciphertext slot layout with the crate's single opaque KEM, so the recipient-slot writing and parsing code changes too.

- **Per-file entry AEAD in archives (PQFA v2)**
  The current `.pqfa` format authenticates the entire archive before any file is extracted, which requires buffering the full ciphertext in memory for in-memory extractions. A PQFA v2 layout gives each file entry its own AEAD tag derived from the session key and the entry index, so individual files can be extracted and verified without loading the whole archive. Design notes for when this happens: bind both the entry index and the entry name into each entry's AAD (index prevents undetected reordering, name prevents undetected renames), authenticate the manifest on its own before streaming any entry, and keep the per-entry `mtime_secs`/`mode` restore working from the v1 work. The archive code is isolated in `pqfile/src/archive.rs`.

- **`PqfileError` refinement** *(substantially complete)*
  `Truncated`, `UnsupportedVersion`, and `NoMatchingRecipient { slots_tried }` already exist as distinct variants, and `DecryptionFailure` is now returned only for genuine AEAD tag mismatches (plus deliberate anti-oracle collapsing of malformed-ciphertext cases). The only remaining piece of the original item is renaming `DecryptionFailure` → `AuthenticationFailure`, a pure rename whose API break buys no new information for callers; do it only if a v5.0 major happens for other reasons.

- **Misuse-resistant nonces (nonce-SIV construction)**
  Replace random nonces with synthetic nonces derived from a hash of the session key and plaintext chunk (a simplified SIV mode). With random nonces, a nonce collision is possible if the same key encrypts a very large number of chunks; SIV derivation makes collision probability zero regardless of how many files are encrypted under a given session key. This is a format break because the nonce field changes meaning in the chunk header. Lower priority than it may sound: every file already gets a fresh session key, so the collision scenario this defends against is already negligible in practice.

- **AEGIS as an optional AEAD suite**
  [AEGIS-128L / AEGIS-128X / AEGIS-256](https://github.com/jedisct1/rust-aegis) (CFRG draft `draft-irtf-cfrg-aegis-aead`) is dramatically faster than both AES-GCM and ChaCha20-Poly1305 on CPUs with AES acceleration, natively key-committing (pqfile currently bolts commitment on via the chunk-0 AAD), and has a large nonce space. A new cipher ID in the header means older readers reject the files, hence v5.0. Caveats that keep it below X-Wing: the performant path of the `aegis` crate links C (`libaegis`) via `cc` while the pure-Rust fallback is much slower, the WASM story is weak, and ChaCha20-Poly1305 already saturates most storage I/O, so the practical win is narrower than the benchmark gap suggests.

---

## New Directions

Ideas not yet implemented, focused on cryptographic depth or ecosystem reach. Ordered roughly by value multiplied by implementation readiness as of the 2026-07-08 review; entries near the top have mature building blocks available today, entries near the bottom are research-grade or blocked on external events.

### 1. Time-locked encryption

Integrate with the drand League of Entropy randomness beacon to support "decrypt after time T" semantics. The file is encrypted using a key derived from a future beacon round output. Before that round fires, the key material does not exist anywhere. The decryptor polls the beacon and decrypts once the round is published. Useful for sealed bids, embargoed releases, and dead-man switch archives.

More tractable than originally scoped: [`tlock-rs`](https://github.com/thibmeu/tlock-rs) plus [`drand_core`](https://lib.rs/crates/tlock) already implement the drand identity-based encryption scheme in Rust, so pqfile would wrap the session key (or one recipient slot) in a tlock ciphertext for a target round while the streaming AEAD layer stays untouched. Design caveat that must be documented honestly: drand tlock is BLS-pairing based, so the time-lock layer itself is not post-quantum; frame it as a hybrid time-lock alongside a normal recipient slot rather than a PQ guarantee.

### 2. FIDO2 hmac-secret hardware token keyslot

Derive a decryption secret from a physical security key using the CTAP2 `hmac-secret` extension (YubiKey 4/5, Nitrokey 3, Google Titan v2, and any compliant authenticator). The [`ctap-hid-fido2`](https://crates.io/crates/ctap-hid-fido2) crate implements CTAP 2.0/2.1 over USB HID. Two integration shapes, both cheap given existing plumbing: feed the token-derived secret into the v10 Argon2id derivation as the pepper (exactly the slot the `--keyfile` second factor already occupies, so a `--fido2` flag parallel to `--keyfile` falls out naturally), or make it a full standalone keyslot. Prior art: LUKSbox and `age-plugin-yubikey`. This closes the biggest gap in the current hardware-key story: the OS credential store protects keys at rest on one machine, while a token is portable and phishing-resistant.

### 3. age ecosystem interoperability

age v1.3.0 ships native post-quantum hybrid ML-KEM-768+X25519 recipients, and the [age plugin protocol](https://words.filippo.io/age-plugins/) makes third-party recipient types first-class in every age client (including rage, the Rust implementation). An `age-plugin-pqfile` binary exposing pqfile identities as age recipients would put pqfile keys inside the largest modern file-encryption ecosystem without users switching tools. Independently worth stealing: age's `RecipientWithLabels` anti-downgrade mechanism, where a recipient labeled `postquantum` refuses to be mixed with weaker recipients in one file; pqfile's multi-recipient modes currently have no equivalent policy check when mixing, say, an ML-KEM-1024 slot with an ML-KEM-512 slot.

### 4. FN-DSA (Falcon) signatures

FIPS 206 went to draft approval in August 2025 with the final standard expected late 2026 or early 2027. FN-DSA signatures are ~666 bytes versus ~3.3 KB for ML-DSA-65, a major win for signcrypt overhead and QR-code-sized artifacts. Thomas Pornin's [`rust-fn-dsa`](https://github.com/pornin/rust-fn-dsa) is high quality and tracks the draft. The PEM-tag-based algorithm auto-detection added for SLH-DSA means a third signature algorithm slots into every sign/verify/signcrypt path the same way. Blocked on: the standard finalizing, and the crate stabilizing against the final test vectors. Revisit each quarter.

### 5. Signable public key certificates

A lightweight certificate format where a CA signing key (ML-DSA-65) signs a public key (ML-KEM) along with metadata: a label, a validity window, and an allowed-use bitmask (encrypt-only, sign-only, or both). `pqfile issue-cert` creates the certificate; `pqfile verify-cert` checks the chain. `pqfile encrypt` optionally accepts a certificate instead of a raw public key and validates expiry and allowed-use before encapsulating. This is a minimal PKI layer built entirely from the existing primitives with no external dependencies.

### 6. Sealed sender

Encrypt without revealing the sender's identity in the ciphertext. The sender derives a one-time signing key pair via HKDF from their long-term signing key and the KEM ciphertext, signs the payload with the ephemeral key, and discards it. The recipient can verify authenticity using the sender's long-term verifying key, but no third party observing the ciphertext can link it to the sender. Useful when the existence of a communication relationship is itself sensitive.

### 7. Python and Node.js bindings

Expose core `pqfile::encrypt` and `pqfile::decrypt` as a Python wheel and an npm package. The modern pairing is PyO3 with [`maturin`](https://github.com/PyO3/maturin) for wheel builds across the manylinux/macOS/Windows matrix, and [`napi-rs`](https://napi.rs) for prebuilt native Node addons (faster than the WASM path for server-side use; the existing wasm-bindgen build remains the browser fallback). Allows Python and Node.js scripts to encrypt and decrypt without shelling out to the CLI.

### 8. Shell integration

Right-click "Encrypt with pqfile" on Windows (Explorer context menu via registry entry), macOS (Quick Action via Automator bundle), and Linux (`.desktop` file). The integration invokes the CLI with the last-used recipient key and writes the output alongside the original.

### 9. Native OS installer packaging

Automate production of signed OS-native installers from the release workflow: MSI via WiX (Windows), DMG via create-dmg (macOS), .deb/.rpm via cargo-deb/rpmbuild (already documented manually in the README), and AppImage via appimagetool (Linux, requires `squashfs-tools`). Evaluate [`cargo-dist`](https://opensource.axo.dev/cargo-dist/) first: it generates the entire release matrix (MSI, shell/PowerShell installers, Homebrew tap, checksums) from one config and would replace most of the hand-rolled release.yml artifact logic. Code-signing and macOS notarization are the long pole here, which is why this stays unscheduled rather than in v4.x Planned.

### 10. Encrypted audit log

An append-only log of encryption and decryption events stored as a chain of signed and encrypted records. Each record contains the timestamp, command, file fingerprint, and key fingerprint, signed with the operator's ML-DSA key and encrypted for an auditor public key. The chaining structure makes silent deletion detectable. A natural first user of the BLAKE3 guideline above, since none of the log's hashing touches the wire format.

### 11. Split ciphertext storage

A mode where the raw ciphertext bytes are split across N output files using a secret sharing scheme (or simpler XOR splitting for K=N), requiring any K files to reconstruct. Different from key splitting: the key stays intact and the payload itself is distributed. Useful for backup scenarios where the ciphertext is spread across cloud providers that are mutually untrusted; no single provider has a usable ciphertext.

### 12. Key ceremony tooling

An interactive guided ceremony mode for high-assurance key generation. Multiple participants each contribute entropy combined via SHA3-256 before seeding key generation so no single participant can bias the result. The ceremony log records each participant's entropy hash, the combined seed hash, and the resulting public key fingerprint.

### 13. Attribute-based access control policies

Go beyond M-of-N threshold decryption to support Boolean access policies: "decrypt if holder of key A AND key B, OR key C." Each policy node is an encrypted share of the session key. Evaluation is a tree walk using Shamir recombination at AND nodes and branch selection at OR nodes.

### 14. Web extension / browser integration

A browser extension (Chrome / Firefox) that embeds the existing WASM core and adds an "Encrypt" action to file-attachment dialogs and an "Encrypt text" context menu item. Encryption runs entirely in the browser process; no data is sent to a server.

### 15. Deniable encryption

Produce a `.pqf` file that yields two valid, indistinguishable plaintexts: a real one under the primary key and a decoy under a duress key. Both decrypt without error and leave no detectable marker distinguishing which is real. VeraCrypt offers this for full-disk volumes but no post-quantum file encryptor provides it. The design challenge is two independently valid ML-KEM shared secrets each mapping to a distinct AEAD layer, with a header that reveals nothing about which layer is authoritative.

### 16. Forward-secret file exchange protocol

A stateful protocol built on pqfile that provides forward secrecy for an ongoing file exchange session between two parties. Each exchange ratchets a shared root secret forward using a new ML-KEM encapsulation, so compromise of the current session key does not expose previously exchanged files. State lives in a small JSON ratchet file alongside the key pair.

### 17. Proxy re-encryption

Generate a re-encryption key `rk(A -> B)` from private key A and public key B. A proxy holding only `rk` can transform a ciphertext encrypted for A into one encrypted for B, without ever seeing the plaintext or either private key. Useful for delegated access: a file server can re-encrypt stored files on behalf of a new recipient without the sender needing to re-encrypt manually. Ranked last among the cryptographic items because no practical post-quantum PRE construction with a mature implementation exists; the known lattice-based schemes are research-grade, and falling back to a classical ECC-based PRE would break the project's post-quantum story.

### Constant-time test harness extension *(complete)*

`pqfile/examples/ct_shamir.rs` (Shamir GF(256) reconstruction), `ct_decrypt.rs` (decryption error path: tamper-position timing), and `ct_passphrase.rs` (wrong-passphrase rejection: unrelated vs near-miss guess) are standalone dudect-style Welch t-test binaries. All three require a quiet machine and ≥100 000 samples for a meaningful verdict; they are deliberately not run in CI.

---

## Evaluated and not planned

Considered during the 2026-07-08 ecosystem review and deliberately left off the roadmap, recorded so they are not re-litigated from scratch:

- **Ascon-AEAD128 (NIST SP 800-232)**: standardized in 2025 for constrained devices, but it is slower than ChaCha20-Poly1305 on every platform pqfile targets (desktop, server, WASM), and the Rust crate is unaudited. No fit unless an embedded target appears.
- **Miri / `cargo-careful` CI jobs**: `#![deny(unsafe_code)]` at the crate root leaves almost no first-party unsafe surface (one sanctioned mmap call), and dependency unsafe is better covered by the existing fuzzing plus `cargo vet`. Poor signal per CI minute.
- **io_uring async I/O (`tokio-uring` / `compio`)**: encryption throughput is CPU-bound on the AEAD and KDF paths, not syscall-bound; the Linux-only complexity is not justified by the profile.
- **`memsecurity` / ASCON-encrypted in-RAM secrets**: encrypting secrets in memory with a key that lives in the same address space adds obfuscation, not a security boundary. The `memsec` mlock/mprotect approach (v4.x item 7) addresses the actual threat, which is swap and crash dumps.

---

## Security invariants

The following properties are invariants, not roadmap items. Any proposal that weakens them requires explicit justification and a major version bump:

- All cryptographic operations run locally. No data is sent to a server.
- The entire `.pqf` file (header + payload) is authenticated before any plaintext is returned.
- Secret material is zeroized from memory on drop.
- Each encryption produces a fresh KEM ciphertext and a fresh random nonce.
- In hybrid mode, each encryption also produces a fresh ephemeral X25519 scalar.
