# pqfile Roadmap

This document tracks planned improvements, new features, and security work across future releases. Breaking changes to the `.pqf` format or public API always require a major version bump.

---

## v4.0.0 through v4.3.0 (complete)

All features from v2.x through v4.3.0 are complete. A full history is available in `docs/CHANGELOG.md`. The highlights:

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
- **Compact recipient strings (**`pqf1…`**)**: `pqfile keygen` prints a Bech32m recipient string; `-r` accepts either PEM path or `pqf1…`; `pqfile fingerprint` subcommand
- `#![deny(unsafe_code)]` **at crate root** with narrow `#[allow(unsafe_code)]` on the sanctioned mmap call
- **Archive mtime and permissions restore**: `extract()` restores `mtime_secs` and `mode` from the PQFA manifest per entry
- `--force` **overwrite protection**: all CLI file-writing subcommands refuse to overwrite an existing output unless `--force` is passed (closes the silent-overwrite footgun from the 2026-07-01 audit)
- `pqfile check`: authenticates a `.pqf` end-to-end into a null sink without writing plaintext (named `check` rather than the roadmap's `verify` to avoid colliding with the existing signature-verification subcommand)
- **Windows ACL restriction on private key files**: `write_private_file` now strips inherited ACEs and leaves a single OWNER RIGHTS full-control ACE via `icacls`, mirroring the Unix 0600 behavior
- **Argon2id auto-calibration**: `pqfile doctor --calibrate [--target-ms N]` benchmarks the local machine and recommends `--kdf-mem`/`--kdf-time`; `encrypt --passphrase` accepts them via `encrypt_stream_passphrase_with_params`
- **Default recipient config file**: `~/.config/pqfile/config.toml` / `%APPDATA%\pqfile\config.toml` holding `recipient` and `key` defaults; explicit flags win; global `--no-config` opts out
- **Supply-chain hardening in release artifacts**: SLSA build provenance attestations (`actions/attest-build-provenance`) on all release artifacts, binaries built with `cargo auditable`, `cargo-vet` runs on PRs as well as pushes, and CI no longer skips itself on workflow-file changes. `cargo-vet` and `cargo-semver-checks` are now also required status checks on the "Protect main" ruleset.
- **Release binary tuning**: workspace `[profile.release]` with thin LTO, one codegen unit, and symbol stripping for smaller, faster native binaries and WASM bundle
- **SLH-DSA-SHAKE-192f signatures (FIPS 205)**: `sign-keygen --algorithm slh-dsa-shake-192f`; hash-based alternative to ML-DSA-65 at the same security category, auto-detected from the key's PEM tag by all sign/verify/signcrypt paths; plaintext, passphrase-encrypted, and hardware-backed key storage; 192f chosen over 192s because 192s signing is ~20× slower for no category gain
- **GUI** `<meta>` **CSP**: `pqfile-gui/index.html` carries an in-document Content-Security-Policy so the WASM app is protected even when served without the nginx header snippet
- **Keyfile as a second factor for passphrase mode**: `--keyfile <path>` on v10 `encrypt`/`decrypt`/`check` mixes the keyfile's SHA3-256 hash into the Argon2id derivation as the secret (pepper) input; the v10 header gained a flags byte (bit 0 = keyfile required) with unknown-bit rejection, and missing/superfluous keyfiles fail fast with dedicated errors (codes 23/24/25) before the KDF runs
- **Recursive directory packing with symlink/special-file rejection**: `pqfile archive --recursive` walks directory arguments (entry names keep the directory prefix, like tar), rejecting symlinks, devices, FIFOs, and sockets per-path, and rejecting duplicate entry names including case-insensitive collisions for all archives
- **Authenticated headers (**`VERSION_AUTH_BIT`**)**: new files set bit 7 of the version byte and bind `chunk_size`, `compression_algo`, and the v10 KDF fields into the chunk-0 key commitment (v3 definition, distinct domain separation), closing the compression-flag-flip gap; the version byte and `kem_variant` stay excluded so zero-copy `rekey`/`add-recipient` still work; old files remain readable and old pqfile versions reject new files with a clean `UnsupportedVersion`. Implemented without new per-layout version bytes, so no v5.0 wire-format redesign was needed (release versioning decision, 4.x vs 5.0, still open since older readers cannot read newly written files)
- `--qr` **on** `keygen` **and** `fingerprint`: renders the `pqf1…` recipient string as a terminal unicode QR code (uppercased for the denser QR alphanumeric mode; Bech32m is case-insensitive); goes to stderr under `--json`
- **Constant-time harness extension**: `examples/ct_decrypt.rs` (tamper-position classes on the AEAD reject path) and `examples/ct_passphrase.rs` (unrelated vs near-miss wrong passphrase on v10) join `ct_shamir.rs`; all three use the same dudect-style Welch t-test
- **Interactive no-args CLI mode**: running bare `pqfile` (no subcommand, no flags) drops into a guided prompt flow for encrypt/decrypt/keygen instead of clap's usage text; any argument (including `--help`) still takes the normal clap path. CLI-layer only, delegates to the same `run_`* functions as the flag-driven paths so behavior stays identical.
- **Plaintext length padding (Padmé)**: `pqfile::padding::padme_length`/`PadmeReader`/`TruncatingWriter` and `encrypt --pad` round the plaintext length to a coarser bucket (≤ ~12% overhead) before encryption, so ciphertext length no longer reveals the exact plaintext size. The true length still travels in the existing authenticated `original_size` header field; decrypt strips the padding back off by capping output at that field (a no-op for every non-padded file, so no `--pad` flag is needed at decrypt time). Incompatible with stdin input, empty files, `--mmap`, `--pipeline`, and `--compress` (compression would shrink the padding back down). Shipped without a wire-format change - no version bump required.
- **Magic-free stealth mode**: `encrypt --stealth` / `decrypt --stealth` / `check --stealth` (new library functions `encrypt_stream_stealth`/`decrypt_stream_stealth`) omit the `.pqf` magic, version byte, and KEM variant field entirely; wire layout is `KEM_CT || BASE_NONCE(8) || ORIGINAL_SIZE(8) || <chunked ciphertext>`, using the recipient's own key type (known to the decryptor already) instead of a variant field. Single recipient only; composes with `--pad`. There is nothing on the wire to auto-detect, so the caller must already know a file was written in stealth mode. See `docs/FORMAT.md` §6.
- **Compat-matrix vectors for v10, keyfile, stealth, and padding**: golden ciphertexts committed for all four post-v9 wire behaviors (`v10_passphrase.pqf`, `v10_keyfile.pqf` + keyfile, `stealth_768.pqf` + private key, `padme_768.pqf` + its own 37-byte plaintext that actually pads to 40); the padded vector locks in both that the header's `original_size` is the true length and that capping decrypt output at it recovers the exact input, and the keyfile vector locks in the fail-fast without its second factor. Standing policy: any future format addition lands with its vector in the same PR.
- **`cargo-semver-checks` CI job and pre-publish gate**: `ci.yml` job (with `--release-type minor`, so only breaking changes fail between releases) plus a gate in `publish.yml` before `cargo publish -p pqfile` using default inference against the stamped release version; library crate only, `--all-features` so the async surface is covered
- **Scheduled dependency advisory scan**: `.github/workflows/advisories.yml` runs `cargo deny check advisories` daily at 06:00 UTC and opens or updates a `security`-labeled tracking issue on failure instead of relying on the scheduled-failure email
- **`zizmor` workflow audit**: CI job (pinned `pipx install`, GH_TOKEN for the online audits) plus fixes for every finding: `persist-credentials: false` on all non-pushing checkouts, template-injection vectors (`github.ref_name`, release tag, mutants `extra_flags`, version step outputs) routed through `env:` vars, release-workflow Cargo caches removed entirely (cache poisoning would flow into provenance-attested binaries), and the accepted Trusted-Publishing finding documented in `.github/zizmor.yml`
- **Memory locking for in-flight secrets**: internal `LockedSecret<N>` (`pqfile/src/secret.rs`) holds secrets in `mlock`ed (`VirtualLock` on Windows, plus `MADV_DONTDUMP` on Linux) heap pages via `memsec`, zeroized before unlock on drop; covers session keys, KEM shared secrets, the HKDF hybrid secret, Argon2id output, and the keyfile pepper. Lock failure degrades softly to zeroize-only (small default `RLIMIT_MEMLOCK`/working-set quotas), unconditionally so on wasm32. Deliberately not covered: private-key seeds returned by the public `decrypt_seed*` functions (their `Zeroizing` return type is stable API) and expanded key objects (external `ml-kem`/`x25519-dalek` types); plaintext and chunk buffers are excluded by design, as they would exhaust the lock quota
- **FIDO2 hardware token second factor for v10 (`fido2-enroll`/`--fido2` CLI, desktop GUI)**: mirrors `--keyfile` in the same Argon2id pepper slot (new mutually-exclusive `V10_FLAG_FIDO2` header bit; `PqfileError::Fido2Required`/`Fido2NotRequired`, codes 26/27), but the secret comes from a physical security key's CTAP2 `hmac-secret` extension output instead of a file. New library API: `encrypt_stream_passphrase_fido2[_with_params]`, `decrypt_stream_passphrase_fido2[_with_limits]` - the core library stays free of any USB dependency; it only ever sees the already-derived 32-byte secret. `pqfile fido2-enroll` (CLI) / "Enroll New Token…" (desktop GUI) creates a non-resident CTAP2 credential requesting `hmac-secret` and writes an enrollment file (credential ID + a fresh random salt, not sensitive on its own since reproducing the secret needs the physical token) in the same text format both tools read. All USB HID code (`ctap-hid-fido2`) lives behind an off-by-default `fido2` cargo feature on both `pqfile-cli` and `pqfile-gui` (native target only; `pqfile-desktop` always enables it), so a normal build of either never needs `libudev-dev`/hidraw system packages; not available in the WASM web GUI (no hidapi target for browsers). Dedicated CI coverage compiles and unit-tests both crates' feature on every push without needing real hardware. Non-resident credentials were chosen deliberately over resident ones: no token resident-slot consumption, and every FIDO2 authenticator supports them.
- **v10 passphrase-only encryption in the desktop and web GUI**: previously CLI-only; the Encrypt/Decrypt tabs gained a Public Key / Passphrase mode toggle with the same optional keyfile/FIDO2 second factor as the CLI (FIDO2 desktop-only). Compression and stealth stay hidden in passphrase mode since neither has a library-level passphrase variant; Padmé padding composes with both modes. Batch encryption resolves the second factor (including any FIDO2 hardware touch) once per batch, not once per file.
- **Multithreaded zstd compression**: `encrypt_stream_compressed`'s zstd encoder now runs with the `zstdmt` Cargo feature enabled and sizes its worker count off `rayon::current_num_threads()`, so `encrypt --compress` on large compressible input is no longer single-threaded; still respects the CLI's `--threads` cap since that's what sizes the shared Rayon pool. No wire-format impact (still standard zstd frames); falls back to single-threaded when the pool has 1 thread.
- **CodeQL scanning**: enabled via the repository's default-setup toggle (no committed workflow file, so it needed nothing from this repo's CI files); Rust analysis running with `build-mode: none` alongside the existing SonarQube + clippy + fuzzing stack.
- **Deterministic benchmark gate (`iai-callgrind`)**: `pqfile/benches/iai.rs` benches the KEM (`keygen_bytes`), AEAD (`encrypt_bytes`/`decrypt_bytes` on a 64 KiB payload), header parsing (`inspect_stream`), and Shamir (`split_key`/`reconstruct_key`) paths under Valgrind/Callgrind via `#[library_benchmark]`, with setup functions keeping key generation and ciphertext prep outside the measured region. Gated at +/-5% instruction-count regression via `Callgrind::soft_limits([(EventKind::Ir, 5.0)])`, checked against the previous run's `target/iai/` baseline (restored by the existing `cargo-cache` action, Cargo.lock-keyed with a prefix fallback so it survives most dependency bumps). New `iai-bench` CI job installs `valgrind` from apt and `iai-callgrind-runner` pinned to the exact same version as the `iai-callgrind` dev-dependency (0.16.1 - a mismatch between the two is a hard error). Argon2id stays out of scope, as planned, since a memory-hard KDF under Valgrind's ~20x slowdown would dominate CI time for no signal. The existing criterion `crypto` bench and its wall-clock `bench` job in ci.yml are unchanged and still the source for human-readable local numbers.
- **Optional formally verified ML-KEM backend (`libcrux-ml-kem`, opt-in `kem-libcrux` feature)**: new `pqfile/src/kem_backend.rs` defines a `KemBackend` trait (`ek_from_seed`/`encapsulate`/`decapsulate`, all raw-byte in and out) with two implementors - `MlKemBackend` (RustCrypto `ml-kem`, always compiled, default) and `LibcruxBackend` (Cryspen's F*-verified `libcrux-ml-kem`, behind `kem-libcrux`). Every KEM call site across `encrypt.rs`, `decrypt.rs`, `keygen.rs`, `keys.rs`, and `shamir.rs` (two more files than the original scoping note anticipated) now goes through the trait instead of constructing `ml-kem` typed keys directly; `EkVariant`/`DkVariant` hold raw EK bytes and the 64-byte private seed respectively rather than backend-specific types. Plain random keygen (previously `Kem::generate_keypair()`) was unified onto the same seed-based path as import/hardware/reconstruction after confirming byte-for-byte equivalence: `generate_keypair`'s RNG draws `d` then `z` (32 bytes each) and reaches the same `generate_deterministic(d, z)` that `from_seed` reaches via `seed.split()`. No wire-format change - `pqfile/tests/kem_oracle.rs` already proved interchangeability, and the full compat-matrix vectors in `pqfile/tests/compat/` (golden ciphertexts from the default backend) pass unmodified under `--features kem-libcrux`. One real behavioral gap found and closed along the way: libcrux's raw `TryFrom<&[u8]>` public-key constructor is a length-only check, unlike `ml-kem`'s `EncapsulationKey::new()`, which also performs the FIPS 203 §7.2 "Encapsulation Key Check" (rejects out-of-range decoded coefficients); `LibcruxBackend::encapsulate` now calls a shared `validate_ek` helper that reuses `ml-kem`'s own constructor purely for this check (still always a dependency regardless of the feature) rather than re-implementing the coefficient bit-unpacking, so both backends reject the same malformed keys. New `kem-libcrux-check` CI job (mirrors the existing `fido2-check` pattern) runs clippy and the full `pqfile` test suite with the feature on; a normal build never pulls in the extra dependency tree. Caveat carried over honestly from the original scoping: independent analysis ([eprint 2026/192](https://eprint.iacr.org/2026/192.pdf)) found only ~58% of the Rust proof surface is actually SMT-checked and the NEON backend is admitted without proofs, so this is defense in depth, not a silver bullet.
- **Profile-guided optimization for the CLI release binary**: `release.yml`'s `build` job now does an instrument / train / merge / optimize cycle around `pqfile-cli` specifically, on all four native targets, using raw `-Cprofile-generate`/`-Cprofile-use` `RUSTFLAGS` rather than the `cargo-pgo` tool the original note suggested - `cargo-pgo` always shells out to plain `cargo build` internally (confirmed by reading its source), which is incompatible with the `cargo auditable build` this pipeline already uses to embed SBOM-scannable dependency metadata in shipped binaries; the manual RUSTFLAGS approach is the same official rustc PGO workflow cargo-pgo itself wraps, verified locally to compose cleanly with `cargo auditable` (`cargo audit bin` still finds the embedded dependency data on the optimized binary). New `scripts/pgo_workload.sh` trains on ML-KEM 512/768/1024/hybrid single-recipient roundtrips at two sizes, a multi-recipient roundtrip (exercises the AES-256-GCM session-key-wrap path), and a compressed roundtrip. **Scoped to the CLI only**, not `pqfile-desktop`: a GUI binary has no headless way to be driven in CI to collect profile data. **Does not cover v10 `--passphrase` mode**: `rpassword` reads the controlling terminal device directly rather than stdin, so its prompt can't be scripted headlessly; the KDF that mode alone exercises (Argon2id) is already out of scope for instruction-level tuning per the iai-callgrind bench notes, since it's deliberately memory-hard, so the gap has low practical cost. The whole sequence runs inside a non-fatal wrapper: any failure (missing `llvm-profdata`, a workload error, a cross-compiled target's instrumented binary not being runnable on the build host, ...) falls back to the plain `cargo auditable build` that shipped before this existed, so a PGO-specific break can never fail a release - see the 2026-06-26 release-pipeline breakage for why that bar matters here. No PGO path for `pqfile-desktop` or the WASM bundle.
- **Signable public key certificates**: new `pqfile::cert` module (`issue_cert`/`verify_cert`/`Certificate`/`cert_use`) is a minimal PKI layer over the existing `sign` module - no new cryptographic primitive, just a signed, self-describing wrapper. A CA signing key (ML-DSA-65 or SLH-DSA-SHAKE-192f) signs a subject public key (any pqfile PEM: KEM/hybrid public key or a verifying key) together with a label, a validity window (`not_before`/`not_after`, Unix seconds, both inclusive), and an `allowed_use` bitmask (`ENCRYPT`/`SIGN`, combinable). The subject key's own PEM tag travels inside the signed body, so `verify_cert` hands back a ready-to-use PEM without the caller needing to know the key type in advance; the wire body is fully self-delimiting (no outer length prefix) so parsing and signing operate over the identical byte range. `pqfile issue-cert --ca-key <SK> --subject <PUBKEY|pqf1…> --label <TEXT> --allow-encrypt/--allow-sign [--not-before YYYY-MM-DD] --valid-days <N> -o <FILE>` creates one; `pqfile verify-cert --ca-key <VK> <FILE>` checks the signature and window and prints the label, validity, and allowed use. `pqfile encrypt -r <CERT> --ca-key <VK>` accepts a certificate directly in place of a raw recipient key: it verifies the cert, rejects it if `ENCRYPT` is not in `allowed_use` (new `PqfileError::CertUseNotPermitted`, code 29) or if the check time falls outside the window (new `PqfileError::CertNotValid`, code 28), and otherwise substitutes the embedded subject key transparently. Certificates do not chain and there is no revocation beyond the validity window (re-issue with a shorter window instead); a certified recipient key also skips the `.revoked`-sidecar check that a direct pubkey path gets, since there is no on-disk path to a sidecar for an embedded key. CLI-only for now: `sign`/`verify`/`signcrypt` do not yet accept a certificate in place of a verifying key, and neither GUI has cert support - both are natural follow-ups if this sees use.



---



## v4.x - Planned (no breaking format changes)

All ranked items from the 2026-07-08 ecosystem review (CodeQL, the iai-callgrind gate, the libcrux-ml-kem backend, and PGO) are done and moved to the completed list above, along with 2-5 of an even earlier ranking (cargo-semver-checks, advisory scan, zizmor, compat vectors) and the memory-locking item. Only the standing guideline below remains as an open item in this section.

### Standing guideline: BLAKE3 for new non-format hashing

SHA3-256 stays everywhere it appears in the wire format or key fingerprints (compatibility is binding). But new surfaces that never touch the format, such as a future audit log, `doctor` file hashing, or dedup checks, should prefer `[blake3](https://crates.io/crates/blake3)`: roughly 10x faster and internally parallel. Recorded here so SHA3 does not get baked into new features by reflex.

---



## v5.0 - Next major (breaking format changes)

These items require a new major version because they change the wire format or public API in a backward-incompatible way (or, for new KEM/cipher variants, produce files that older readers reject). Ranked.

- **X-Wing as the hybrid KEM (standards alignment)**
Replace the bespoke X25519+ML-KEM-768 combiner with [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), the IETF CFRG general-purpose PQ/T hybrid KEM, using the RustCrypto `[x-wing](https://github.com/RustCrypto/KEMs/tree/master/x-wing)` crate (built on the same `ml-kem` and `x25519-dalek` pqfile already depends on). X-Wing carries a formal security proof (secure if SHA-3 and either component is secure) and is on an RFC track, which buys interoperability and external review that a homegrown combiner never gets. Technically this could ship additively as a new KEM variant ID in 4.x, but since older readers cannot read the files it belongs with the other compatibility-affecting work. The existing hybrid variant stays readable forever. Code anchors: the current bespoke combiner is `hybrid_hkdf` in `pqfile/src/format.rs` (HKDF-SHA256 over both shared secrets), hybrid keygen lives in `pqfile/src/keygen.rs`, and KEM variant IDs are defined in `format.rs`; X-Wing replaces the combiner and the two-ciphertext slot layout with the crate's single opaque KEM, so the recipient-slot writing and parsing code changes too.
- **Per-file entry AEAD in archives (PQFA v2)**
The current `.pqfa` format authenticates the entire archive before any file is extracted, which requires buffering the full ciphertext in memory for in-memory extractions. A PQFA v2 layout gives each file entry its own AEAD tag derived from the session key and the entry index, so individual files can be extracted and verified without loading the whole archive. Design notes for when this happens: bind both the entry index and the entry name into each entry's AAD (index prevents undetected reordering, name prevents undetected renames), authenticate the manifest on its own before streaming any entry, and keep the per-entry `mtime_secs`/`mode` restore working from the v1 work. The archive code is isolated in `pqfile/src/archive.rs`.
- `PqfileError` **refinement** *(substantially complete)*
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

More tractable than originally scoped: `[tlock-rs](https://github.com/thibmeu/tlock-rs)` plus `[drand_core](https://lib.rs/crates/tlock)` already implement the drand identity-based encryption scheme in Rust, so pqfile would wrap the session key (or one recipient slot) in a tlock ciphertext for a target round while the streaming AEAD layer stays untouched. Design caveat that must be documented honestly: drand tlock is BLS-pairing based, so the time-lock layer itself is not post-quantum; frame it as a hybrid time-lock alongside a normal recipient slot rather than a PQ guarantee.

### 2. age ecosystem interoperability

age v1.3.0 ships native post-quantum hybrid ML-KEM-768+X25519 recipients, and the [age plugin protocol](https://words.filippo.io/age-plugins/) makes third-party recipient types first-class in every age client (including rage, the Rust implementation). An `age-plugin-pqfile` binary exposing pqfile identities as age recipients would put pqfile keys inside the largest modern file-encryption ecosystem without users switching tools. Independently worth stealing: age's `RecipientWithLabels` anti-downgrade mechanism, where a recipient labeled `postquantum` refuses to be mixed with weaker recipients in one file; pqfile's multi-recipient modes currently have no equivalent policy check when mixing, say, an ML-KEM-1024 slot with an ML-KEM-512 slot.

### 3. FN-DSA (Falcon) signatures

FIPS 206 went to draft approval in August 2025 with the final standard expected late 2026 or early 2027. FN-DSA signatures are ~666 bytes versus ~3.3 KB for ML-DSA-65, a major win for signcrypt overhead and QR-code-sized artifacts. Thomas Pornin's `[rust-fn-dsa](https://github.com/pornin/rust-fn-dsa)` is high quality and tracks the draft. The PEM-tag-based algorithm auto-detection added for SLH-DSA means a third signature algorithm slots into every sign/verify/signcrypt path the same way. Blocked on: the standard finalizing, and the crate stabilizing against the final test vectors. Revisit each quarter.

### 4. Sealed sender

Encrypt without revealing the sender's identity in the ciphertext. The sender derives a one-time signing key pair via HKDF from their long-term signing key and the KEM ciphertext, signs the payload with the ephemeral key, and discards it. The recipient can verify authenticity using the sender's long-term verifying key, but no third party observing the ciphertext can link it to the sender. Useful when the existence of a communication relationship is itself sensitive.

### 5. Python and Node.js bindings

Expose core `pqfile::encrypt` and `pqfile::decrypt` as a Python wheel and an npm package. The modern pairing is PyO3 with `[maturin](https://github.com/PyO3/maturin)` for wheel builds across the manylinux/macOS/Windows matrix, and `[napi-rs](https://napi.rs)` for prebuilt native Node addons (faster than the WASM path for server-side use; the existing wasm-bindgen build remains the browser fallback). Allows Python and Node.js scripts to encrypt and decrypt without shelling out to the CLI.

### 6. Shell integration

Right-click "Encrypt with pqfile" on Windows (Explorer context menu via registry entry), macOS (Quick Action via Automator bundle), and Linux (`.desktop` file). The integration invokes the CLI with the last-used recipient key and writes the output alongside the original.

### 7. Native OS installer packaging

Automate production of signed OS-native installers from the release workflow: MSI via WiX (Windows), DMG via create-dmg (macOS), .deb/.rpm via cargo-deb/rpmbuild (already documented manually in the README), and AppImage via appimagetool (Linux, requires `squashfs-tools`). Evaluate `[cargo-dist](https://opensource.axo.dev/cargo-dist/)` first: it generates the entire release matrix (MSI, shell/PowerShell installers, Homebrew tap, checksums) from one config and would replace most of the hand-rolled release.yml artifact logic. Code-signing and macOS notarization are the long pole here, which is why this stays unscheduled rather than in v4.x Planned.

### 8. Encrypted audit log

An append-only log of encryption and decryption events stored as a chain of signed and encrypted records. Each record contains the timestamp, command, file fingerprint, and key fingerprint, signed with the operator's ML-DSA key and encrypted for an auditor public key. The chaining structure makes silent deletion detectable. A natural first user of the BLAKE3 guideline above, since none of the log's hashing touches the wire format.

### 9. Split ciphertext storage

A mode where the raw ciphertext bytes are split across N output files using a secret sharing scheme (or simpler XOR splitting for K=N), requiring any K files to reconstruct. Different from key splitting: the key stays intact and the payload itself is distributed. Useful for backup scenarios where the ciphertext is spread across cloud providers that are mutually untrusted; no single provider has a usable ciphertext.

### 10. Key ceremony tooling

An interactive guided ceremony mode for high-assurance key generation. Multiple participants each contribute entropy combined via SHA3-256 before seeding key generation so no single participant can bias the result. The ceremony log records each participant's entropy hash, the combined seed hash, and the resulting public key fingerprint.

### 11. Attribute-based access control policies

Go beyond M-of-N threshold decryption to support Boolean access policies: "decrypt if holder of key A AND key B, OR key C." Each policy node is an encrypted share of the session key. Evaluation is a tree walk using Shamir recombination at AND nodes and branch selection at OR nodes.

### 12. Web extension / browser integration

A browser extension (Chrome / Firefox) that embeds the existing WASM core and adds an "Encrypt" action to file-attachment dialogs and an "Encrypt text" context menu item. Encryption runs entirely in the browser process; no data is sent to a server.

### 13. Deniable encryption

Produce a `.pqf` file that yields two valid, indistinguishable plaintexts: a real one under the primary key and a decoy under a duress key. Both decrypt without error and leave no detectable marker distinguishing which is real. VeraCrypt offers this for full-disk volumes but no post-quantum file encryptor provides it. The design challenge is two independently valid ML-KEM shared secrets each mapping to a distinct AEAD layer, with a header that reveals nothing about which layer is authoritative.

### 14. Forward-secret file exchange protocol

A stateful protocol built on pqfile that provides forward secrecy for an ongoing file exchange session between two parties. Each exchange ratchets a shared root secret forward using a new ML-KEM encapsulation, so compromise of the current session key does not expose previously exchanged files. State lives in a small JSON ratchet file alongside the key pair.

### 15. Proxy re-encryption

Generate a re-encryption key `rk(A -> B)` from private key A and public key B. A proxy holding only `rk` can transform a ciphertext encrypted for A into one encrypted for B, without ever seeing the plaintext or either private key. Useful for delegated access: a file server can re-encrypt stored files on behalf of a new recipient without the sender needing to re-encrypt manually. Ranked last among the cryptographic items because no practical post-quantum PRE construction with a mature implementation exists; the known lattice-based schemes are research-grade, and falling back to a classical ECC-based PRE would break the project's post-quantum story.

### Constant-time test harness extension *(complete)*

`pqfile/examples/ct_shamir.rs` (Shamir GF(256) reconstruction), `ct_decrypt.rs` (decryption error path: tamper-position timing), and `ct_passphrase.rs` (wrong-passphrase rejection: unrelated vs near-miss guess) are standalone dudect-style Welch t-test binaries. All three require a quiet machine and ≥100 000 samples for a meaningful verdict; they are deliberately not run in CI.

---



## Evaluated and not planned

Considered during the 2026-07-08 ecosystem review and deliberately left off the roadmap, recorded so they are not re-litigated from scratch:

- **Ascon-AEAD128 (NIST SP 800-232)**: standardized in 2025 for constrained devices, but it is slower than ChaCha20-Poly1305 on every platform pqfile targets (desktop, server, WASM), and the Rust crate is unaudited. No fit unless an embedded target appears.
- **Miri /** `cargo-careful` **CI jobs**: `#![deny(unsafe_code)]` at the crate root leaves almost no first-party unsafe surface (one sanctioned mmap call), and dependency unsafe is better covered by the existing fuzzing plus `cargo vet`. Poor signal per CI minute.
- **io_uring async I/O (**`tokio-uring` **/** `compio`**)**: encryption throughput is CPU-bound on the AEAD and KDF paths, not syscall-bound; the Linux-only complexity is not justified by the profile.
- `memsecurity` **/ ASCON-encrypted in-RAM secrets**: encrypting secrets in memory with a key that lives in the same address space adds obfuscation, not a security boundary. The `memsec` mlock approach (shipped 2026-07-08 as `pqfile/src/secret.rs`) addresses the actual threat, which is swap and crash dumps.

---



## Security invariants

The following properties are invariants, not roadmap items. Any proposal that weakens them requires explicit justification and a major version bump:

- All cryptographic operations run locally. No data is sent to a server.
- The entire `.pqf` file (header + payload) is authenticated before any plaintext is returned.
- Secret material is zeroized from memory on drop.
- Each encryption produces a fresh KEM ciphertext and a fresh random nonce.
- In hybrid mode, each encryption also produces a fresh ephemeral X25519 scalar.

