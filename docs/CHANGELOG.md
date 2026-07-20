# Changelog

All notable changes to pqfile are documented in this file. Versions follow semantic versioning. Breaking changes to the `.pqf` file format or key format always require a major version bump.

---

## [Unreleased]

### Code and documentation cleanup

- **`pqfile-cli/src/main.rs` split from 5,370 lines into per-subcommand modules**: it held every subcommand's argument parsing *and* implementation in one file (~90 free functions). `main.rs` now holds only `Cli`/`Command`/`TlockCommand` and the `run()` dispatch match (~1,380 lines, almost entirely clap derive attributes and doc comments); everything else moved into `commands/{keygen,encrypt,decrypt,inspect,sign,cert,keys,archive,sealed_sender,shamir,stego}.rs` (one module per subcommand family) plus five small shared-helper modules at the crate root: `config.rs` (the user config-file loader), `json_util.rs` (the hand-rolled `--json` output helpers), `prompts.rs` (passphrase prompting), `io_util.rs` (stdin/stdout, atomic private-file writes, output-path resolution - the largest shared module, since nearly every subcommand needs some of it), and `interactive.rs` (the no-args guided-prompt mode). Purely mechanical: every moved function kept its body verbatim, gaining only `pub(crate)` where another module now needs to call it. Verified behavior-preserving via the full pre-existing test suite (26 unit + 61 CLI integration tests, unchanged) passing under every feature combination (`fido2`, `tlock`, `stego`, `update-check`, all four together), plus `cargo clippy -D warnings` clean on all of them.
- **`update_check` deduplicated**: the CLI and GUI's independent `update_check.rs` files each defined the same ~50 lines (GitHub Releases API fetch, version parsing/comparison, tests) verbatim. Extracted the shared logic into `pqfile-cli/src/update_check_common.rs`, physically reused by `pqfile-gui` via `#[path = "../../pqfile-cli/src/update_check_common.rs"]` - the same single-source-of-truth convention `fido2_common.rs`/`hex_lines.rs` already use for CLI/GUI-shared code, for the same reason (pqfile-cli is published to crates.io and can't path-depend on an internal workspace crate; pqfile-gui isn't published, so it can safely reach across the workspace). No behavior change.
- **Dead hardware-key-deletion code removed**: `pqfile::hardware`'s `delete_seed`/`dispatch_delete` and `credential_store::CredentialStoreBackend::delete_seed` were `#[allow(dead_code)]`-suppressed with zero callers anywhere in the workspace - a "revoke hardware key" primitive that was built but never wired into any CLI/GUI command and isn't on the roadmap. Removed rather than left as unreachable scaffolding; all three were `pub(crate)`/private, so this is not a public API change.
- **`add_recipient`'s v4/v7 duplication collapsed**: `add_to_v4` and `add_to_v7` were structurally identical (`RecipientEntryV4`/`V7` and `PqfHeaderV4`/`V7` have identical field layouts, kept as distinct types only so the two formats can't be mixed up at compile time). Both now generate from one `macro_rules! add_to_multi` body instead of ~45 hand-duplicated lines; behavior and the existing test suite are unchanged.
- **`run_decrypt` now calls `resolve_decrypt_out_path`** instead of reimplementing its five-line output-path logic inline - the helper already existed and is already used by `run_signdecrypt`/`run_unseal`, but the `decrypt` subcommand itself (the most-used one) had its own hand-copied twin.
- **Windows release binaries were silently shipping without an embedded .exe icon**: `pqfile-desktop/build.rs` pointed `winres` at `assets/icon.ico`, a file that has never existed (only `assets/icon.png` does) - `docs/BUILDING.md` even documented converting one there as a manual step nobody had done. `winres`'s failure path is a `cargo:warning`, not a build error, so this shipped silently in every release. Repointed at `packaging/assets/icon.ico`, which already exists and is git-tracked (it's what the Inno Setup installer uses for its own icon).
- **`--stealth` had no `--help` text on `encrypt`/`decrypt`**: every neighboring flag (including `check`'s own `--stealth`) has a doc comment; these two didn't, so `pqfile encrypt --help`/`pqfile decrypt --help` showed no description for a load-bearing, single-recipient-only flag. Added, mirroring `check`'s wording.
- **`pqfile-cli/packaging/pqfile.spec`'s `%changelog` had accumulated exact-duplicate entries** (`2.0.5-1` four times, `2.0.1-1` and `4.2.3-1` twice) from re-running `scripts/bump-version.ps1` for a version after an earlier attempt had already edited the file but failed a later pre-flight check before committing. Squashed the byte-identical duplicates and made the script's changelog-prepend step idempotent (skips if an entry for the target version already exists) so this can't recur.
- **Stale info fixed**: the GUI About window's crypto card still said Argon2id `p=1` (bumped to `p=4` in a prior release) and `.pqf v3-v6`/`v4` (format versions now run v2-v11, multi-recipient v4/v7-v9); a misplaced `#[allow(clippy::too_many_arguments)]` sat on a 3-argument function in `tabs/encrypt.rs`; the stale `#[allow(dead_code)]` on `shamir.rs`'s `DecodedShare::total` field was removed (it's read in the type's manual `Debug` impl, so the lint was never actually needed); `widgets.rs`'s `toggle_switch`/`reveal_in_explorer` were `pub(crate)` despite only ever being called within `widgets.rs` itself, tightened to private.
- **Documentation drift fixed**: `docs/BUILDING.md`/`docs/QUICKSTART.md` said `cargo build -p pqfile`/`cargo install --path pqfile` to get the CLI binary - `pqfile` is the library crate with no `[[bin]]`; both now say `pqfile-cli`. `pqfile-cli/README.md` claimed the crate "is not published to crates.io", contradicted by `docs/RELEASING.md` and `publish.yml`, which both publish it automatically right after `pqfile`. `docs/SECURITY.md`'s "Local-only operation" claim was stated as an absolute despite the `tlock` and `update-check` features both making explicit, off-by-default network calls - narrowed to name both exceptions. `docs/STABILITY.md`'s stable-surface table omitted the `cert`, `sealed_sender`, and `recipient_string` modules entirely (all shipped, all `pub`). `docs/FORMAT.md`'s constants table omitted `VERSION_TLOCK` (`0x0B`). The three crate READMEs (`pqfile-cli`, `pqfile-gui`, `pqfile-desktop`) didn't mention the `tlock`/`update-check` features where applicable. The root README didn't document the `pqfile man` subcommand, the `kem-libcrux` feature (F*-verified ML-KEM backend), or `secret.rs`'s `mlock`-based `LockedSecret` hardening - all shipped in prior releases; added to the CLI usage section, Dependencies table, and Security considerations respectively, plus the matching `docs/SECURITY.md` memory-safety paragraph.

### Documentation and GUI consistency

- **GUI in-app text audit**: fixed a Signcrypt tab warning that overstated risk - it claimed signdecrypt streams plaintext to the output before signature verification (true of the library's streaming-writer API, `pqfile::signcrypt::signdecrypt`, when called with a raw file/socket writer directly), but the GUI's own `do_signdecrypt` always buffers into an in-memory `Vec` first and only writes to disk after verification succeeds - exactly as safe as Sealed Sender's Unseal flow, whose copy claimed to be the only one doing this. Both tabs' inline and Learn More text now describe the actual GUI behavior. Added several security-relevant notes that previously existed only in a tab's "Learn more" modal, not on the screen where the relevant decision is made: Keygen's passphrase section now states the key-loss consequence inline, Shamir's Reconstruct screen now states upfront that it writes an unencrypted `privkey.pem`, Archive's Extract screen now states its path-traversal rejection guarantee, the Encrypt tab now proactively notes that 2+ recipients switch to the anonymized v8/v9 format and disable Compress/Stealth, and the Clipboard tab now notes that its auto-clear only covers pqfile's own fields, not OS-level clipboard history. Added `sig_algorithm_hint` calls to the Cert tab's CA/subject key rows (previously only Sign/Signcrypt showed the detected algorithm). Aligned every tab's on-screen heading with its "Learn more" modal title, and gave the Stego panel and Cert panel a "Learn more" entry (folded into the Keys tab's modal, since neither is a top-level `Tab`). The Encrypt tab's watchfolder log previously colored entries by sniffing a leading `✔`/`⚠` character out of a plain `String`; it now carries a typed `WatchLogLevel` end to end from the background thread through the channel to the UI.
- **README fixes**: the error-code table had fallen a full feature-cycle behind `docs/ERROR_CODES.md` (22 of 39 variants listed) and still described the version byte range as `0x02-0x0A`, missing v11's `0x8B`; both are now current. Added the v10 Passphrase-mode + Second Factor selector and the Decrypt tab's Add Recipient sub-tab to the GUI feature list (both existed in code and were documented for the CLI, but the GUI bullet list never mentioned them). Clarified that "hardware-backed key storage" (OS credential store) and the FIDO2 hardware token second factor are unrelated mechanisms that happen to share the word "hardware".
- Note for future readers of `pqfile-gui/src/types.rs`'s `tab_from_key`: the `"doctor"` and `"tools"` aliases document a Doctor→Inspect and Tools→Clipboard tab rename that happened before this changelog's earliest GUI-restructure entries; no dated entry records it, so this is the closest thing to one.

### New features

- **Update check (**`check-update` **CLI subcommand, GUI "Check for Updates" button, both behind a new** `update-check` **cargo feature)**: queries the GitHub Releases API (`GET /repos/dangel34/PQ-File-Encryption/releases/latest`) and compares the tag against the running binary's own version, reporting whether a newer release exists. Never downloads or installs anything - it's a version comparison and a link, nothing more. Off by default, reaching the same `ureq` dependency (`rustls` backend, no system OpenSSL needed) `tlock` uses - still the only network-capable crate in the workspace - via a second, independent opt-in feature: a plain `cargo build` stays completely network-free. Even when compiled in, it never runs on its own - the CLI subcommand only runs when invoked explicitly, and the GUI only checks when the user clicks the button or has opted into "Check for updates on startup" (off by default too). The published release binaries (CLI via `release.yml`, desktop GUI via `pqfile-desktop`'s `Cargo.toml`, same mechanism as `fido2`) have the feature compiled in so real downloads can actually use it; the WASM web build does not, since a web app is always whatever's currently deployed. New CLI: `pqfile check-update` (respects `--json`). New GUI: a "Check for Updates now" button and result row in Settings, right below the startup-check toggle; state lives in `PqfileApp::update_check_status`/`update_check_pending`, polled once per frame like the existing FIDO2 enrollment job. No wire-format impact and no new error code: a failed request surfaces as a plain `PqfileError::Io` (the CLI's existing convention for non-cryptographic, non-format errors, e.g. `issue-cert`'s argument validation), not a dedicated variant.
- **Steganographic key backup (`bury`/`exhume`, `stego` cargo feature)**: new `pqfile::stego` module (`bury`, `exhume`, `capacity`) hides a file inside a cover image's pixel data using least-significant-bit embedding, keyed by a passphrase. The passphrase gates *detection*, not just recovery: the embedded message is `SALT(16) || ENC(MAGIC("PQST") || LEN(u32 LE) || MAC(keyed-BLAKE3-32) || PAYLOAD)`, where `ENC` is an XOR with a BLAKE3-XOF keystream derived (via Argon2id at parameters frozen forever for this scheme - m=64 MiB, t=3, p=4, deliberately *not* shared with the passphrase format's tunable defaults, since the image cannot record KDF parameters without embedding recognizable plaintext structure) from the passphrase and the random salt. Nothing embedded is distinguishable from noise without the passphrase, and `exhume` with a wrong passphrase fails identically to `exhume` on an ordinary photo (`StegoPayloadNotFound`, code 38 - the collapse is deliberate, since distinguishing "wrong passphrase" from "nothing here" would leak exactly the signal keyed detection exists to withhold). Still not steganalysis-hardened: bits are placed sequentially, so LSB-noise statistics can flag that *something* is embedded, just never confirm or recover *what*. `bury` accepts a PNG or JPEG cover but always re-encodes the output as a lossless PNG (LSB embedding cannot survive a JPEG re-encode; the CLI rejects a non-`.png` `-o` path with a clear error). Cover decode is bounded (16384px per side, 100 MP total, on top of the `image` crate's 512 MiB decoder-allocation default) so a crafted tiny-file/huge-pixels image cannot balloon memory, and the attacker-controllable recorded length is handled in 64-bit arithmetic so it cannot wrap a 32-bit `usize` (wasm) into a panicking slice range. New CLI subcommands `pqfile bury --image <COVER> <FILE> -o <OUT.png>` / `pqfile exhume <IMAGE> -o <OUT>`, both prompting for the passphrase; `exhume` writes the recovered file (typically a private key) atomically with owner-only permissions via the same helper as every other CLI key-material write, and both treat payload buffers as zeroize-on-drop key material end to end (library framing buffers included). New errors: `StegoCapacityExceeded` (code 37), `StegoPayloadNotFound` (code 38), `StegoInvalidImage` (code 39). Off by default: `stego` pulls in the `image` crate's PNG/JPEG codecs plus `blake3`, a dependency tree a normal `pqfile`/`pqfile-cli` build doesn't need. A new `fuzz_exhume` target (weekly fuzz workflow) drives both arbitrary-bytes robustness and bury/exhume round-trip correctness through `#[cfg(fuzzing)]`-gated entry points that skip the Argon2 stage for throughput. **GUI (desktop + web)**: unlike the native-only FIDO2/keyfile second factors, steganographic backup has no platform restriction, so `pqfile-gui`'s own `stego` feature (forwarding to `pqfile/stego`) is *on* by default - both the desktop app and the `trunk build` web app get a new "Steganographic Key Backup" collapsible panel in the Keys tab (Bury/Exhume sub-tabs, each with passphrase entry) for free, no extra build flags needed. Not a wire-format change - the embedded framing lives entirely inside the cover image's pixel data, never touching `format.rs`, so no `pqfile/tests/compat/` vector was needed. See `docs/ROADMAP.md`, "Steganographic key backup".
- **CLI private-file writes hardened**: the CLI's `write_private_file` helper (used for every key-material file the CLI writes directly, now including `exhume` output) writes atomically via the same temp-file-plus-rename machinery as `AtomicOutput` and restricts the file to its owner *before* any secret bytes land in it - mode 0600 on Unix via the open file handle, an owner-only ACL on Windows via `icacls` (mirroring the `pqfile` library's internal fsutil helper, which the CLI cannot call). Previously it was a plain `fs::write` followed by a Unix-only chmod, leaving a window where the file existed world-readable and no Windows ACL restriction at all.

---

## [4.3.1] - 2026-07-16

### New features

- **Signable public key certificates**: new `pqfile::cert` module (`issue_cert`/`verify_cert`/`Certificate`, plus the `cert_use` bitmask) is a minimal PKI layer over the existing `sign` module. A CA signing key (ML-DSA-65 or SLH-DSA-SHAKE-192f) signs a subject public key (any pqfile PEM - KEM/hybrid public key or a verifying key) together with a label, a validity window (`not_before`/`not_after`, inclusive Unix seconds), and an `allowed_use` bitmask (`cert_use::ENCRYPT` / `cert_use::SIGN`, combinable). The subject key's own PEM tag travels inside the signed body, so a verified certificate hands back a ready-to-use PEM without the caller needing to know the key type in advance. New CLI subcommands: `pqfile issue-cert --ca-key <SK> --subject <PUBKEY|pqf1…> --label <TEXT> --allow-encrypt/--allow-sign [--not-before YYYY-MM-DD] [--valid-days N] -o <FILE>` and `pqfile verify-cert --ca-key <VK> <FILE>`. `pqfile encrypt -r <CERT> --ca-key <VK>` accepts a certificate directly in place of a raw recipient key, verifying it and checking `allowed_use` before encapsulating. New errors `PqfileError::CertNotValid` (code 28, signature verified but outside the validity window) and `PqfileError::CertUseNotPermitted` (code 29, certificate does not authorize the requested use). Certificates do not chain; revocation before the validity window naturally expires is a separate, optional mechanism (see the certificate revocation entry below).
- **Certificate support in** `sign`/`verify`/`signcrypt`/`signdecrypt`: `verify -k`, `signcrypt -r`, and `signdecrypt -v` now accept a certificate PEM in the same slot as a raw key, each paired with a new `--ca-key <CA_VERIFYING_KEY>` flag, enforcing the correct `allowed_use` bit for that slot (`ENCRYPT` for `signcrypt -r`, `SIGN` for `verify -k`/`signdecrypt -v`).
- **GUI certificate support (desktop + web)**: the Keys tab gained an "Issue / Verify Certificate" panel mirroring `issue-cert`/`verify-cert`, available on both native and WASM builds. The Encrypt tab's recipient picker also accepts a certificate file directly (via Browse or drag-and-drop), resolving it against a new CA-verifying-key field before adding it as a recipient. (Later gained a third "Revoke" sub-tab; see the certificate revocation entry below.)
- **Time-locked encryption (v11 format, `tlock` cargo feature)**: `pqfile encrypt --tlock-round <ROUND> file` encrypts so nobody - including the sender - can decrypt before that round's threshold BLS signature is published on the [drand](https://drand.love) beacon (League of Entropy `quicknet` mainnet chain by default). A random 16-byte seed is locked via [tlock](https://eprint.iacr.org/2023/189) identity-based encryption against the target round; the 32-byte session key is HKDF-SHA256-derived from the seed and used for the same chunked, authenticated STREAM payload as every other format. New version byte `0x8B` (always carries `VERSION_AUTH_BIT` - no legacy v11 layout predates it), own key-commitment domain separator binding `chain_hash`/`round`. `pqfile decrypt --tlock` / `check --tlock` fetch the round's beacon signature from a drand HTTP relay - the only network-touching code path in the `pqfile` library - and fail cleanly with `PqfileError::TlockRoundNotReached` (code 30) if the round hasn't fired yet, or `TlockBeaconFetchFailed`/`TlockDecryptionFailed` (codes 31/32) for other fetch or corruption failures; `--tlock-url` overrides the relay. `pqfile tlock round "24h"|"7d"|<RFC3339 date>` resolves a human time expression to a round number, itself network-touching (fetches only the chain's public parameters) but kept separate so `encrypt --tlock-round` stays fully offline given a round number. New library API: `pqfile::tlock::{encrypt_stream_tlock, decrypt_stream_tlock, round_for_target_time, quicknet, TlockChain}`. Off by default: `tlock`/`drand_core` are the only network-capable dependencies in the workspace, gated behind a `tlock` Cargo feature on `pqfile`/`pqfile-cli` so a normal build never gains an HTTP stack. Two upstream `tlock` crate quirks are worked around explicitly: its IBE decrypt silently strips trailing zero bytes from the recovered plaintext (encrypt-side seed generation resamples until the last byte is non-zero) and its `assert_eq!` sanity check panics rather than returns `Err` on a tampered ciphertext (caught via `catch_unwind` at the API boundary so a malformed file can never crash the process). Not a post-quantum guarantee: the underlying tlock scheme is BLS12-381 pairing-based (classical), layered on top of pqfile's existing PQ-secured payload construction. Scoped to pure time-lock in this release - no way to additionally require a recipient's own private key alongside the round; GUI wiring is deferred, matching the FIDO2 feature's native-only precedent. See `docs/FORMAT.md` §5.12.
- **WebAuthn PRF second factor for the web GUI (implemented, disabled in the UI pending browser/OS support)**: closes the gap left by the native-only FIDO2 second factor (USB HID via `ctap-hid-fido2`, unreachable from `wasm32`) - the web build of `pqfile-gui` gains its own v10 second factor, using the WebAuthn `prf` extension (`navigator.credentials` against a passkey) instead of raw CTAP2. New v10 header flag bit (`V10_FLAG_WEBAUTHN_PRF`, mutually exclusive with the existing keyfile/FIDO2 bits - the header's flag-validation check was generalized from a pairwise comparison to `count_ones() <= 1` so it now scales to any number of mutually-exclusive factors), new errors `PqfileError::WebauthnPrfRequired`/`WebauthnPrfNotRequired` (codes 33/34), and new library API `encrypt_stream_passphrase_webauthn_prf[_with_params]` / `decrypt_stream_passphrase_webauthn_prf[_with_limits]`, all in the core `pqfile` crate (no Cargo feature - the same domain-separated-hash-into-Argon2id-pepper mechanism as `--keyfile`/`--fido2`, just fed by a different secret source). On the GUI side: a new wasm32-only `pqfile-gui::webauthn` module talks to `navigator.credentials.create()`/`.get()` via hand-written `#[wasm_bindgen(inline_js = "...")]` glue rather than web-sys's Credential Management bindings, avoiding the `--cfg=web_sys_unstable_apis` opt-in those require anywhere in the build; the Encrypt/Decrypt tabs gain a "Passkey" second-factor option (wasm-only) alongside a "Register Passkey…" flow mirroring the native "Enroll New Token…" one, and the wasm build's encrypt/decrypt queues (previously always synchronous, since every prior second factor resolved in-memory) gained a small pending-state machine to defer starting until the async passkey prompt resolves. Registers a resident (discoverable) credential, matching the W3C PRF explainer's own example - Windows Hello's OS-level WebAuthn API hard-requires a resident credential to expose `hmac-secret`/PRF at all, so the non-resident choice the native FIDO2 second factor uses was tried first and found to silently break PRF on Windows Hello specifically. **The "Passkey" selector button is disabled with an explanatory tooltip rather than removed**: hands-on testing across three browsers found real-world PRF support too inconsistent to ship enabled - Bitwarden's browser extension doesn't implement PRF for third-party sites at all (registration succeeds, `prf.enabled` correctly reports false); Windows Hello via Edge registers and reports `prf.enabled: true` but the subsequent derivation call returns no output; Firefox fails at registration itself with a generic platform error, even with the request pared down to a single ES256 credential parameter. The implementation itself is complete, spec-correct, and fully tested (Rust-side plumbing: flag validation, secret derivation, roundtrip with a fake PRF output, mirroring the existing FIDO2 test pattern); no automated end-to-end browser-passkey coverage exists (no virtual-authenticator harness in this repo), so re-enabling the selector is a one-line change once browser/OS support stabilizes enough to be worth another manual pass. No CLI or native-desktop equivalent (by design - no browser exists there; native already has FIDO2). See `docs/FORMAT.md` §5.9.
- **Sealed sender**: new `pqfile::sealed_sender` module (`identity_keygen[_bytes]`, `seal[_bytes]`, `unseal_bytes`) proves a file's sender to its specific recipient without producing evidence a third party could ever check - unlike `signcrypt`'s non-repudiable ML-DSA/SLH-DSA signature. The mechanism is a static-static X25519 Diffie-Hellman between a new, separate *identity* key pair for the sender and recipient (distinct from their ML-KEM encryption keys and any signing keys): the derived key authenticates a 32-byte SHA3-256 tag over the plaintext, and because computing that tag requires only one party's private key plus the other's public key, the recipient could have forged an identical tag themselves, so verification convinces the recipient but proves nothing to anyone else. New CLI subcommands: `pqfile identity-keygen --out <DIR> [--passphrase]`, `pqfile seal -k <IDENTITY_SK> --recipient-identity <IDENTITY_PK> -r <PUBKEY> <FILE>`, and `pqfile unseal -k <PRIVKEY> --identity-key <IDENTITY_SK> -s <SENDER_IDENTITY_PK> <FILE>`. `seal` is two-pass (hashes the input, then encrypts a `tag ++ plaintext` payload as a standard v3 `.pqf` file to the recipient's normal encryption key), so stdin input is not supported; `unseal_bytes` buffers the full plaintext internally and only returns it once the tag verifies against the claimed sender's identity key (new error `PqfileError::SealedSenderAuthFailed`, code 35) - there is no streaming write-before-verify variant, unlike `signdecrypt`. Identity private keys share the existing passphrase-encryption and `repassphrase` machinery (new PEM tags `X25519 IDENTITY PUBLIC/PRIVATE/ENCRYPTED PRIVATE KEY`). GUI support (desktop + web): a new "Sealed Sender" tab under "More Tools" with Identity Keys / Seal / Unseal sub-tabs, mirroring the existing Signcrypt tab's layout. See `docs/FORMAT.md` §6.6 and §9.
- **Certificate revocation**: closes the scope cut from the original cert module (2026-07-13) - certificates could previously only be invalidated by waiting out their validity window. New `pqfile::cert` API: `revoke_cert`, `verify_revocation_list`, `check_cert_not_revoked`, `cert_id`, plus the `RevocationList`/`RevokedEntry` types. A revocation list is a compact analogue of an X.509 CRL: a CA-signed list of `(cert_id, revoked_at, reason)` entries, where `cert_id` is SHA3-256 of the certificate's own signed body (no serial-number field was added to `Certificate` - two certificates with byte-identical fields already share an id, which is exactly the identification granularity revocation needs). New CLI subcommand `pqfile revoke-cert --ca-key <CA_SIGNING_KEY> <CERT> [--existing <FILE>] [--reason <TEXT>] -o <FILE>`; a new `--revocations <FILE>` flag is accepted everywhere `--ca-key` already resolves a certificate (`encrypt -r`, `verify -k`, `signcrypt -r`, `signdecrypt -v`, `seal -r`, `verify-cert`) and is optional at every one of those call sites - a certificate is accepted even without a matching entry when the flag is omitted, mirroring how `.revoked`-sidecar checking for raw keys only ever happens when the sidecar file exists. New error `PqfileError::CertRevoked` (code 36). `revoke_cert` carries an existing list's entries forward without re-verifying its own signature before re-signing - documented as the same trust boundary `issue_cert` already assumes for its inputs (a CA controls the files on its own machine), not a gap introduced here. GUI support (desktop + web): the Keys tab's certificate panel gained a third "Revoke Certificate" sub-tab, and the Verify Certificate sub-tab plus the Encrypt tab's certificate-recipient resolution both gained an optional revocation-list field. See `docs/FORMAT.md` §6.5.

### CI and supply chain

- **Native OS packages for Linux and macOS**: `release.yml`'s existing per-target `build` job gained new conditional steps that package the already-built (PGO-optimized, `cargo auditable`) binaries rather than rebuilding them - a `.deb` (`cargo-deb`) and `.rpm` (`cargo-generate-rpm`, a pure-Rust generator with no `rpmbuild`/`rpm-build` system package needed) for Linux, a Linux AppImage (`linuxdeploy` + its appimage plugin, run with `--appimage-extract-and-run` since GitHub Actions runners have no FUSE) for the desktop GUI, and a macOS `.app` bundle + DMG (`create-dmg --no-code-sign`, with a multi-resolution `.icns` generated at build time via `sips`/`iconutil` from the existing 512×512 PNG) also for the desktop GUI. New packaging assets: `pqfile-desktop/packaging/pqfile-desktop.desktop`, `pqfile-desktop/packaging/Info.plist.template`. `[package.metadata.deb]`/`[package.metadata.generate-rpm]` in `pqfile-cli/Cargo.toml` already existed before this change and needed no updates - both tools substitute the correct per-target-triple path for the `target/release/...` placeholder automatically. **None of the new packages, nor the pre-existing Windows Inno Setup installer, are code-signed or notarized** - that's explicitly out of scope for this change (needs a paid Windows code-signing certificate and an Apple Developer Program membership, both cost/account decisions left to the project owner); Windows SmartScreen and macOS Gatekeeper will both warn on first launch until that's addressed separately. cargo-dist was evaluated first, per `docs/ROADMAP.md`'s existing note, and turned out not to fit: it doesn't build DMG, `.deb`, `.rpm`, or AppImage at all (macOS support is explicitly out of scope upstream, axodotdev/cargo-dist#24) - point tools were used instead, added as new steps in the existing job rather than replacing any of the PGO/SLSA/cosign/SBOM machinery already in the pipeline.

---

## [4.3.0] - 2026-07-11

### New features

- **Interactive no-args CLI mode**: running bare `pqfile` with no arguments at all drops into a guided prompt flow (encrypt / decrypt / generate a key pair) instead of clap's usage text. Any argument, including a bare `--help`, still takes the normal flag-driven path. The prompts collect the same inputs the flags would and call the identical `run_encrypt`/`run_decrypt`/`run_keygen` functions underneath, so behavior, defaults, and error messages are unchanged from the flag-driven CLI. Also fixes a debug-build-only stack overflow: clap's derive-generated argument-parser construction for this CLI's size is a deep (but finite) call chain that doesn't fit Windows' default 1 MiB main-thread stack once inlining is disabled; `main()` now runs on a spawned thread with a 16 MiB stack (release builds were never affected — optimization collapses the chain via inlining).
- **Plaintext length padding (`encrypt --pad`, Padmé)**: pads the plaintext to a coarser length bucket (≤ ~12% overhead) before encryption, so the ciphertext length no longer reveals the exact plaintext size. Not a wire-format change: the true length still travels in the existing `original_size` header field (already authenticated via the chunk-0 key commitment); `decrypt`/`check` cap their output at that field automatically for every file, which is a no-op unless the file was actually padded — no `--pad` flag is needed at decrypt time. Incompatible with stdin input, empty files, `--mmap`, `--pipeline`, and `--compress` (compression would shrink the padding back down, defeating it); composes with `--parallel` and `--stealth`. New public library API: `pqfile::padding::{padme_length, PadmeReader, TruncatingWriter}`.
- **`inspect`/`doctor` support v10 (passphrase-only) files**: `inspect_stream` gained a `PqfHeaderInfo::Passphrase` variant exposing the Argon2id parameters, keyfile-required flag, nonce, and original size; previously a v10 file returned `UnsupportedVersion` from `inspect`. Added while wiring `--pad`'s decrypt-side truncation, which needed to peek `original_size` for every format including v10.
- **Magic-free stealth mode (`encrypt --stealth` / `decrypt --stealth` / `check --stealth`)**: new library functions `encrypt_stream_stealth`/`decrypt_stream_stealth` omit the `.pqf` magic, version byte, and KEM variant field entirely, producing output that doesn't identify itself as pqfile ciphertext (or as any particular key type) to an observer. Wire layout: `KEM_CT || BASE_NONCE(8) || ORIGINAL_SIZE(8) || <chunked ciphertext>` — the KEM ciphertext length comes from the *decrypting* private key's own variant rather than a stored field, so there's nothing to leak and nothing to auto-detect; the caller must already know a file is in stealth mode. Single recipient only; composes with `--pad`, and `decrypt_stream_stealth` strips any Padmé padding automatically (no prior callers to keep compatible, since the function is new). Documented in `docs/FORMAT.md` §5.10-5.11. New test suite `pqfile/tests/stealth.rs` covers all KEM variants, hybrid, tamper rejection, wrong-key rejection, and padding composition.
- **`--qr` on `keygen` and `fingerprint`**: renders the `pqf1…` recipient string as a scannable terminal QR code (unicode half-blocks). The string is uppercased first so the QR alphanumeric mode packs ~45% more characters per version — Bech32m is case-insensitive, and both `is_recipient_string` and `decode_pubkey` accept the uppercase form a scanner app produces. Under `--json` the QR goes to stderr so stdout stays machine-readable. New CLI dependency: `qrcode` (unicode renderer only, no image/svg features; already in the workspace via the GUI).
- **Constant-time harness extension**: two new standalone dudect-style binaries join `examples/ct_shamir.rs` — `examples/ct_decrypt.rs` verifies that rejecting a tampered ciphertext takes the same time regardless of which tag byte was corrupted, and `examples/ct_passphrase.rs` verifies that a v10 wrong-passphrase rejection takes the same time for an unrelated guess as for a near-miss sharing all but one character with the real passphrase (minimum Argon2id parameters keep per-sample cost sub-millisecond). Same Welch t-test scaffolding and |t| < 4.5 criterion as `ct_shamir.rs`; both PASS on initial runs.
- **Authenticated headers (`VERSION_AUTH_BIT`, `0x80`)**: every newly written `.pqf` file now sets bit 7 of the version byte (`0x83`/`0x84`/`0x85`/`0x86`/`0x88`/`0x89`/`0x8A`) and computes the chunk-0 key commitment with a v3 definition that additionally binds the header fields whose tampering was not previously self-healing: `chunk_size` (v5/v6), `compression_algo` (v6 — flipping zstd→none used to deliver compressed bytes as "plaintext" with every AEAD tag passing), and the v10 Argon2id salt/parameters/flags. Stripping or adding the bit also fails authentication (distinct domain-separation contexts). The version byte and `kem_variant` stay outside the commitment by design — both change during zero-copy `rekey` (v3→v4), and tampering with them is self-healing — so `rekey` and `add-recipient` remain zero-copy and preserve the bit. All files written by pqfile ≤ 4.2.4 remain readable (legacy v2 commitment); older pqfile versions reject the new files with `UnsupportedVersion`, the intended upgrade signal. `inspect`/`doctor` report an "Auth. header: yes/no" line (JSON: `header_authenticated`). New public API: `format::VERSION_AUTH_BIT`, `format::version_layout`, `format::is_header_authenticated`. Wire layouts are byte-identical apart from the version byte; documented in FORMAT.md §4.4. New test suite `pqfile/tests/auth_header.rs` covers the tamper and downgrade cases.

- **SLH-DSA-SHAKE-192f signatures (FIPS 205)**: `pqfile sign-keygen --algorithm slh-dsa-shake-192f` generates a hash-based signing key pair as a conservative alternative to ML-DSA-65 for long-lived signatures (same NIST security category 3; slower signing; 35664-byte signatures vs 3309). `sign`, `verify`, `signcrypt`, `signdecrypt`, and `repassphrase` auto-detect the algorithm from the key's PEM tag - no flag needed beyond keygen. Supports plaintext, passphrase-encrypted (new 116-byte body), and hardware-backed (OS credential store) key storage; the private key is stored as the 72-byte FIPS 205 seed triple and the full key is deterministically recomputed on load, revalidating `PK.root` every time. New PEM labels: `SLH-DSA-SHAKE-192F VERIFYING KEY` / `SIGNING KEY` / `ENCRYPTED SIGNING KEY` / `SIGNATURE` / `HARDWARE SIGNING KEY REFERENCE`. New library API: `sign::SigAlgorithm` plus `_with_algorithm` variants of the four sign-keygen functions; `PqfSigningKey`/`PqfVerifyingKey` gain `.algorithm()`. GUI: the Keygen tab gains an SLH-DSA-SHAKE-192f option; the Sign, Verify, Signcrypt, and Signdecrypt tabs show a detected-algorithm hint under any loaded signing/verifying key; Doctor reports SLH-DSA keys correctly; tab headings, Settings note, About panel, and help modals updated to cover both algorithms. The 192f parameter set was chosen over 192s deliberately: signing is interactive in the CLI/GUI and 192s signing is ~20× slower at the same security category, while the larger signature is irrelevant for file encryption. Uses the RustCrypto `slh-dsa` crate (0.2.0-rc.5, sharing the workspace's sha2 0.11 line).
- **Passphrase-only encryption (v10 format)**: `pqfile encrypt --passphrase secret.txt` derives the session key directly from a passphrase via Argon2id, with no ML-KEM step. New format version `0x0A`: `MAGIC | 0x0A | SALT(16) | ARGON2_PARAMS(12: m_kib/t/p as u32 LE) | FLAGS(1) | NONCE(12) | ORIGINAL_SIZE(8)` followed by standard STREAM chunks. Argon2 parameters travel in the header so the decryptor does not need a fixed parameter set. `--passphrase` is mutually exclusive with `-r`/`-k`. New library entry points: `encrypt_stream_passphrase`, `decrypt_stream_passphrase`, and `decrypt_stream_passphrase_with_limits`. `PqfileError::KdfLimitExceeded` (JSON error code 22) is returned when the file's Argon2 parameters exceed configurable ceilings (default: 64 MiB / t=3); CLI flags `--max-kdf-mem` / `--max-kdf-time` let callers tighten the ceiling. *(Note: the `FLAGS` byte was added while v10 was still unreleased; v10 files written by untagged main-branch builds prior to the keyfile feature use the old 52-byte header and must be re-encrypted.)*
- **Keyfile second factor for passphrase mode (`--keyfile`)**: `pqfile encrypt --passphrase --keyfile usb/secret.bin file.txt` mixes the SHA3-256 hash of an arbitrary non-empty file into the v10 Argon2id derivation as the secret (pepper) input, so decryption requires both the passphrase (something you know) and the identical keyfile bytes (something you have). `decrypt`/`check` take the same `--keyfile` flag. The v10 header's new `FLAGS` byte records keyfile use (bit 0): decrypting a keyfile-protected file without one fails fast with `KeyfileRequired` (JSON error code 23) before the KDF runs, and passing `--keyfile` for a file that never used one fails with `KeyfileNotRequired` (code 24) instead of an opaque tag mismatch. Unknown flag bits are rejected with `UnsupportedHeaderFlags` (code 25) so future v10 features cannot be silently misdecrypted; clearing the flag bit in transit cannot bypass the second factor, since the keyfile hash is baked into the session key. New library entry points: `encrypt_stream_passphrase_keyfile[_with_params]`, `decrypt_stream_passphrase_keyfile[_with_limits]`.
- **Recursive directory archiving (`pqfile archive --recursive`)**: directory arguments are now walked recursively, with entry names keeping the directory name as a prefix (like tar); `--base` still overrides naming. The walk rejects symlinks and special files (devices, FIFOs, sockets) with a per-path error rather than silently skipping or following them, and `.pqf` files are included (unlike `encrypt --recursive`, archiving is a fidelity operation). Entry names that collide — including case-insensitive collisions, which would silently overwrite each other when extracted on Windows or macOS — are rejected at pack time for all archives, recursive or not. Passing a directory without `--recursive` now fails with a clear pointer to the flag instead of an open-error.
- **Compact recipient strings (`pqf1…`)**: `pqfile keygen` now prints a Bech32m recipient string alongside the fingerprint. Pass a `pqf1…` string directly to `-r` without needing to distribute a PEM file. New `pqfile fingerprint <path-or-string>` subcommand prints the fingerprint and recipient string for either form. New library functions: `pqfile::recipient_string::encode_pubkey`, `decode_pubkey`, `is_recipient_string`.
- **`pqfile check`**: authenticates a `.pqf` file end-to-end without writing any plaintext. Runs the full decrypt path (every chunk AEAD tag, key commitment, KDF-ceiling check for v10) into a counting null sink and reports `plaintext_bytes` on success. Same `-k` / `--passphrase` / `--max-kdf-mem` / `--max-kdf-time` interface as `decrypt`. Useful for validating backups and testing keys without producing a cleartext copy.
- **Argon2id auto-calibration (`pqfile doctor --calibrate`)**: benchmarks Argon2id on the local machine and recommends `--kdf-mem` / `--kdf-time` values whose measured wall-clock cost hits a target (default 250 ms, `--target-ms 50..=10000`). Scales memory cost first (64 MiB floor = compiled-in default, 1 GiB ceiling), then time cost (t ≤ 16); never recommends parameters weaker than the defaults. New library API: `pqfile::calibrate(target_ms)` returning `CalibrationResult` (native only). Companion flags `encrypt --passphrase --kdf-mem <KIB> --kdf-time <ITERS>` feed the recommendation into v10 encryption via the new `encrypt_stream_passphrase_with_params` library entry point; files above the default ceiling need `--max-kdf-mem` / `--max-kdf-time` raised at decryption time (stated in the calibrate output).
- **User config file with default recipient and key**: `~/.config/pqfile/config.toml` (`$XDG_CONFIG_HOME` respected; `%APPDATA%\pqfile\config.toml` on Windows) can hold `recipient = "pqf1… or pubkey.pem path"` and `key = "privkey.pem path"`. `encrypt` with no `-r` and `decrypt`/`check` with no `-k` fall back to it; explicit flags always win; the global `--no-config` flag opts out for scripting. Parsed with a strict built-in TOML-subset reader (`key = "value"`, `#` comments, `\\`/`\"` escapes) - no new dependencies; a malformed config is a hard error, never silently ignored.
- **FIDO2 hardware token second factor for v10 (CLI `fido2-enroll`/`--fido2`, desktop GUI)**: an alternative to `--keyfile` that derives the Argon2id pepper from a physical security key instead of a file, using the CTAP2 `hmac-secret` extension. `pqfile fido2-enroll -o <FILE> [--pin]` (CLI) or the "Enroll New Token…" button (desktop GUI, either tab's Second Factor card) creates a non-resident credential requesting the extension and writes an enrollment file (credential ID plus a fresh random salt); the file is not sensitive on its own, since reproducing the derived secret requires physically touching the same token. `encrypt`/`decrypt`/`check --passphrase --fido2 <FILE>` then mix that secret in exactly like `--keyfile` (the two are mutually exclusive - a new v10 header bit, `V10_FLAG_FIDO2`, records which one, if either, a file needs). New library API: `encrypt_stream_passphrase_fido2[_with_params]`, `decrypt_stream_passphrase_fido2[_with_limits]`; new errors `PqfileError::Fido2Required`/`Fido2NotRequired` (JSON codes 26/27), mirroring the keyfile ones. The core `pqfile` library has no USB dependency - it only ever receives the already-derived 32-byte secret; all CTAP2/HID code (`ctap-hid-fido2`) lives behind a new `fido2` Cargo feature on `pqfile-cli` (off by default) and `pqfile-gui` (native target only; `pqfile-desktop` always enables it, since it's the one native GUI build), so a normal build of either never needs `libudev-dev`/hidraw system packages. Not available in the web (WASM) GUI - no hidapi target exists for browsers. Dedicated CI coverage compiles, lints, and unit-tests both crates' `fido2` feature on every push, without requiring real hardware.
- **v10 passphrase-only encryption in the desktop and web GUI**: the Encrypt and Decrypt tabs gain a Public Key / Passphrase mode toggle; Passphrase mode needs no key pair (v10 format) and offers the same optional second factor as the CLI (None / Keyfile / FIDO2, the last desktop-only per above). Compression and stealth mode stay public-key-only (no passphrase variant exists at the library level) and are hidden accordingly; Padmé padding composes with either mode, matching the CLI. Multi-file batch encryption reuses one passphrase (and, for FIDO2, one hardware touch) across every file in the batch rather than re-deriving per file.

### Hardening

- **`#![deny(unsafe_code)]` at crate root** (`pqfile/src/lib.rs`): the attribute rejects any new `unsafe` block at compile time. The single sanctioned exception (mmap in `encrypt.rs`) carries a narrow `#[allow(unsafe_code)]` at the call site.
- **Memory locking for in-flight secrets** (new `pqfile/src/secret.rs`, new dependency `memsec`): the internal `LockedSecret<N>` wrapper holds key material in heap pages locked with `mlock` (`VirtualLock` on Windows; Linux additionally gets `MADV_DONTDUMP`) for as long as the secret is alive, and zeroizes before releasing the lock on drop. Beyond swap and crash-dump protection, the stable heap address also eliminates the unzeroized stack copies that by-value moves of `Zeroizing<[u8; N]>` left behind. Converted flows: per-file session keys (single-, multi-, and anonymous-recipient, encrypt and decrypt sides), KEM shared secrets from encapsulation and decapsulation, the HKDF-combined hybrid secret, Argon2id output for both v10 files and encrypted-key PEMs, and the v10 keyfile pepper. Lock failure is soft by design (default `RLIMIT_MEMLOCK` and Windows working-set quotas are small): on failure, and always on wasm32, behavior degrades to the previous zeroize-on-drop semantics. Not converted: the public `decrypt_seed*` functions keep their stable `Zeroizing` return type, expanded key objects are external crate types, and plaintext/chunk buffers are excluded deliberately (they would exhaust the lock quota and are not long-lived key material). The two raw `mlock`/`munlock` calls in `secret.rs` join mmap as the crate's only sanctioned `#[allow(unsafe_code)]` sites.

### CI and supply chain

- **Compat vectors for v10, keyfile, stealth, and Padmé padding** (`pqfile/tests/compat/`, `tests/compat.rs`, `examples/gen_compat_vectors.rs`): the frozen-ciphertext matrix previously stopped at v9, leaving four shipped wire behaviors with no committed vectors. New golden files: `v10_passphrase.pqf` (fixed passphrase, low-cost Argon2id params committed in the test), `v10_keyfile.pqf` + `v10_keyfile.bin` (flags-bit variant; also locks in that decrypting without the keyfile fails fast), `stealth_768.pqf` + private key (nothing on the wire to auto-detect, so the key is the vector's required side channel), and `padme_768.pqf` + `padme_plaintext.bin` (37 bytes padding to 40; locks in that the header's `original_size` is the true length and that capping decrypt output at it recovers the exact input). Policy going forward: any format addition lands with its vector in the same PR.
- **`cargo-semver-checks` CI job and pre-publish gate** (`ci.yml`, `publish.yml`): verifies the `STABILITY.md` API promise mechanically against the latest published `pqfile` on crates.io. The CI job runs with `--release-type minor` (fails only on breaking changes, since the version is bumped only at release time); the publish gate runs with default inference against the stamped release version before `cargo publish`, and is skipped when the version is already on crates.io so re-runs stay idempotent.
- **Scheduled dependency advisory scan** (new `.github/workflows/advisories.yml`): daily `cargo deny check advisories` run, so a RustSec advisory published while the repo is idle is caught within a day instead of at the next commit. On failure it opens (or comments on) a `security`-labeled tracking issue rather than relying on GitHub's scheduled-failure email, which goes only to the workflow file's last committer.
- **`zizmor` workflow audit job plus fixes for everything it found** (`ci.yml` + all workflows): new CI job audits the workflow files for template injection, credential persistence, and cache poisoning. Findings fixed rather than silenced: `persist-credentials: false` on every checkout except the bench job's (which pushes gh-pages; annotated ignore), attacker-influencable values (`github.ref_name`, release tag, workflow-dispatch `extra_flags`, version outputs) routed through `env:` vars instead of `${{ }}` interpolation into `run:` scripts, and the two Cargo caches removed from `release.yml` so a poisoned cache entry can never flow into shipped, provenance-attested release binaries. The one accepted finding (crates.io Trusted Publishing as a replacement for `CARGO_REGISTRY_TOKEN`) is documented in the new `.github/zizmor.yml`.
- **`libcrux-ml-kem` cross-implementation oracle test** (new `pqfile/tests/kem_oracle.rs`; `libcrux-ml-kem` added as a non-wasm32 dev-dependency only): proves, rather than assumes, that the RustCrypto `ml-kem` crate pqfile actually ships and Cryspen's formally verified `libcrux-ml-kem` agree on FIPS 203 byte-for-byte, for all three parameter sets (512/768/1024; the hybrid X25519+ML-KEM-768 variant reuses the plain 768 code path, so it needs no separate case). Checks: the same 64-byte seed derives the same public key in both crates (`KeyGen_internal`), the same `(ek, m)` produces a byte-identical ciphertext and shared secret in both (`Encaps_internal`, using `ml-kem`'s `encapsulate_deterministic`), and each crate correctly decapsulates the other's ciphertext. This is the prerequisite the roadmap called out before offering `libcrux-ml-kem` as an optional production backend; the actual `kem-libcrux` feature and backend swap (a larger change touching every KEM call site in `encrypt.rs`/`decrypt.rs`/`keygen.rs`) is deliberately scoped out for now and remains on the roadmap.

### Performance

- **Multithreaded zstd compression** (`encrypt_stream_compressed`, new `zstd` feature `zstdmt`): the zstd encoder now sizes its own internal worker pool off `rayon::current_num_threads()`, so `encrypt --compress` on a large compressible input is no longer single-threaded. This is zstd's own thread pool, separate from Rayon's, but reads the same count so it still respects the CLI's `--threads` cap; falls back to single-threaded compression when that count is 1. Output remains standard zstd frames - no format change, decompression unaffected.

### Improvements

- **Archive mtime and permissions restore on extract** (`archive.rs`): `extract()` now calls `File::set_times` and (Unix-only) `set_permissions` per entry, restoring the original modification time and permission bits captured in the PQFA manifest. New test `archive_extract_restores_mtime` confirms behavior.

### Dependencies

- `memsec` 0.7 added (non-WASM only, `use_os` feature only): provides the `mlock`/`munlock` primitives for `LockedSecret`. Its Windows backend pins the legacy `windows-sys` 0.45 / `windows-targets` 0.42.2 stack (inert link-stub crates, Windows-only, exempted in `supply-chain/config.toml`).
- `ctap-hid-fido2` 3.5 (plus `getrandom`) added to `pqfile-cli` and `pqfile-gui` (native target only), both optional behind each crate's own `fido2` feature: CTAP2 USB HID for the FIDO2 second factor. Pulls in `hidapi`, `ring`, `x509-parser`, and their transitive trees (37 new crates); all exempted in `supply-chain/config.toml`. Not a dependency of the `pqfile` library, of a default `pqfile-cli` build, or of the WASM web GUI; `pqfile-desktop` enables `pqfile-gui`'s `fido2` feature unconditionally, so its release/CI builds need `libudev-dev` on Linux.
- `bech32` 0.9 → 0.12: migrated `recipient_string.rs` to the new API. A custom `PqfChecksum` type (Bech32m polynomial, `CODE_LENGTH = usize::MAX`) bypasses the built-in 1023-character cap that ML-KEM-768 public keys (~1900 characters) exceed.
- `aes-gcm` 0.10 → 0.11, `chacha20poly1305` 0.10 → 0.11 (pulls in aead 0.6, hybrid-array 0.4.12): migrated all call sites from `AeadInPlace` to `AeadInOut` (`encrypt_inout_detached` / `decrypt_inout_detached`). Tag extraction migrated from `Tag::clone_from_slice` to `try_into()`.
- `deny.toml`: temporarily ignore RUSTSEC-2026-0194 / RUSTSEC-2026-0195 (quick-xml < 0.41 DoS advisories). quick-xml is reachable only through the Linux GUI stack - wayland-scanner uses it at build time on bundled protocol XML, and zbus_xml parses local D-Bus introspection XML - so no attacker-controlled input reaches it in pqfile. The parents (wayland-scanner 0.31.10, zbus_xml 5.1.1) are at their latest releases and still require quick-xml ^0.39; the ignores carry a TODO to drop them once upstream moves to >= 0.41.

### Security

- **Bounded reads in v2 and `async`-feature decrypt/encrypt paths** (`decrypt.rs`, `async_io.rs`): `decrypt_v2_payload` and the `async` feature's `encrypt_stream_async`/`decrypt_stream_async` called `read_to_end` with no cap, so a stream with an unbounded tail could force unbounded memory allocation before any size check ran. All three now cap the read with `.take(MAX_ORIGINAL_SIZE + ...)`, matching the existing bound already used in `decapsulate_stream_init`.
- **Private key and Shamir share files written 0600 on Unix** (new `fsutil.rs`; `keygen.rs`, `sign.rs`, `shamir.rs`, `repassphrase.rs`, `pqfile-cli/src/main.rs`): these files were previously created with the process umask (typically world-readable). A new `write_private_file` helper writes the file and then restricts it to owner read/write only.
- **Shamir `split_raw` shares zeroized** (`shamir.rs`): the random polynomial coefficients were already wrapped in `Zeroizing` (v4.1.1), but the output shares themselves (genuine secret material, since any `threshold` of them reconstruct the key) were returned as plain `Vec<u8>`. They are now `Zeroizing<Vec<u8>>`.
- **GUI passphrase clones zeroized** (`pqfile-gui/src/tabs/*.rs`): 11 call sites cloned a passphrase out of its `Zeroizing<String>` field into a bare `String` before passing it to a library call. Each clone is now re-wrapped in `Zeroizing`.
- **Hardware credential store uses byte-native secret storage** (`hardware/credential_store.rs`): the seed was hex-encoded and stored via the credential store's string `set_password`/`get_password` API, adding unnecessary non-zeroized copies along the way. It now uses the byte-native `set_secret`/`get_secret` API directly. `load_seed` transparently detects and decodes seeds stored by older pqfile versions in the legacy hex format, so existing hardware keys keep working after upgrading.
- **v9 recipient shuffle retry loop bounded** (`encrypt.rs`): `encrypt_stream_multi_anon_padded`'s Fisher-Yates shuffle used an unbounded rejection-sampling loop; the sibling v8 function (`encrypt_stream_multi_anon`) already bounds this at 1000 retries per position to guard against a malfunctioning entropy source. Both now share the same bound.
- **`cargo vet` policy gap fixed** (`supply-chain/config.toml`): added the missing `policy.*.audit-as-crates-io` entries for `pqfile` and `pqfile-cli`, which are published to crates.io under the same versions as the workspace's local path dependencies. `cargo vet check` was failing on this ever since, unnoticed because `cargo-vet` is not a required CI status check.

### Improvements

- **`AsyncPqfWriter` drop guard** (`async_io.rs`): added the same debug-mode drop panic that `PqfWriter` already has, so dropping an `AsyncPqfWriter` without calling `finish()`/`shutdown()` is caught during development instead of silently discarding the buffered plaintext.
- **CLI atomic output uses `O_EXCL`** (`main.rs`): `AtomicOutput::new` created its temp file with `File::create` (truncate-if-exists); it now uses `create_new`, refusing to follow a pre-existing file or symlink at the temp path.
- **`DecodedShare` Debug redaction** (`shamir.rs`): `Zeroizing<Vec<u8>>`'s `Debug` impl forwards to the inner type's, so the derived `Debug` on `DecodedShare` would have printed raw share bytes if ever logged. It now has a hand-written `Debug` impl that redacts the share field.

---

## [4.2.4] - 2026-06-26

### Fixes

- **Release workflow version-consistency check**: the check for `pqfile-gui`'s `APP_VERSION` grepped for a literal string that no longer exists (`APP_VERSION` now reads `env!("CARGO_PKG_VERSION")`), so every tag push since that refactor failed the `check-versions` job before any artifacts were built. Removed the now-redundant check from `release.yml` and `scripts/bump-version.ps1`.
- **WASM build**: `decrypt.rs` referenced `PathBuf` in a `#[cfg(target_arch = "wasm32")]` branch, but the import was gated to `#[cfg(not(target_arch = "wasm32"))]`, which would have failed the `pqfile-gui` WASM build.
- **QR code modal**: removed automatic clipboard copy when opening a QR code. Viewing a Shamir secret-share's QR silently placed the raw key-share plaintext on the shared OS clipboard with no auto-clear, undermining the air-gapped-transfer purpose of the feature. Copying is now only via the explicit "Copy" button.
- `eframe`/`egui` 0.34 → 0.35 compile fixes: `Panel`/`CentralPanel::show_inside` renamed to `show`; `eframe::Storage` gained a required `remove_string` method.

### Dependencies

- `eframe` / `egui` 0.34 → 0.35
- Routine patch-level `cargo update` across the workspace and `fuzz/`
- GitHub Actions: `actions/cache` v5.0.5 → v6.0.0, `taiki-e/install-action` v2.82.2 → v2.82.4, `dtolnay/rust-toolchain`'s `stable` pin refreshed to the current branch head

---

## [4.2.3] - 2026-06-08

### New features

- **`--threads N` global CLI flag**: caps the Rayon worker thread count for `--parallel` encrypt and decrypt operations. Default 0 uses all available cores. Useful when pqfile runs alongside other workloads on a shared machine.

### Fixes

- **WASM loading screen no longer goes blank**: the loading spinner previously hid itself as soon as the canvas was sized (before WASM was instantiated), leaving a blank screen for several seconds. It now stays visible until Rust signals readiness after the first egui frame renders.

### Performance

- **Brotli pre-compression**: release builds now ship `.wasm.br` and `.js.br` alongside `.wasm.gz`. With `brotli_static on` in nginx, browsers receive brotli-compressed assets (15-20% smaller than gzip), reducing initial load time.

---

## [4.2.2] - 2026-06-08

### New features

- **`MultiEncryptBuilder`**: fluent builder API in `pqfile::encrypt` wrapping all three multi-recipient formats (Standard v4, Anonymous v8, Padded v9). Chain `.anonymous()`, `.padded()`, and `.with_progress(cb)` before calling `.encrypt(reader, writer)`.
- **Progress callbacks**: `encrypt_stream_with_progress`, `encrypt_stream_multi_anon_with_progress`, `encrypt_stream_multi_anon_padded_with_progress`, and `decrypt_stream_with_progress` report `(bytes_done, total)` via a callback on each chunk. `total` is 0 when the size is not known in advance.
- **Per-file byte progress bar in desktop GUI**: the encrypt and decrypt tabs now show a second progress bar tracking bytes processed for the current file. The decrypt bar is animated and indeterminate (with a MiB counter) because the original size is not available until after decryption completes.
- **WASM CI smoke test**: `pqfile/tests/wasm_smoke.rs` adds four `#[wasm_bindgen_test]` cases (encrypt/decrypt roundtrip, keygen at 512 and 1024, wrong-key rejection). A `wasm-test` job in `ci.yml` runs them via `wasm-pack test --node` on every push and pull request.
- **`--threads N` global CLI flag**: caps the Rayon worker thread count for `--parallel` encrypt and decrypt operations. Useful when pqfile runs alongside other workloads and should not consume all cores. Default 0 uses all available cores (previous behavior unchanged).

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
