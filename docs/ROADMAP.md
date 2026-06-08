# pqfile Roadmap

This document tracks planned improvements, new features, and security work across future releases. Breaking changes to the `.pqf` format or public API always require a major version bump.

---

## v4.0.0 through v4.1.1 (fully released)

All features from v2.x through v4.1.1 are complete and shipped. A full history is available in `docs/CHANGELOG.md`. The highlights:

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
- `pqfile doctor` diagnostic subcommand for key and ciphertext health checks (legacy p=1 detection fixed in v4.1.1)
- Cross-version compatibility matrix in `pqfile/tests/compat/` covering v2-v8
- Property-based tests (`proptest`) and mutation testing CI (`cargo-mutants`)
- Branchless GF(256) arithmetic in Shamir: constant-time `gf_mul` (v4.1.0) and constant-time `gf_inv` via fixed 7-squaring chain (v4.1.1)
- Key commitment in chunk-0 AAD: SHA3-256(session_key) bound into first AEAD tag
- `PqfileError::Truncated`: distinguishes clean truncation from authentication failure; parallel decrypt path matches serial behavior (v4.1.1)
- Header validation: `original_size` capped at 1 TiB, recipient count capped at 256
- Encrypted archive format (PQFA), rekey, add-recipient, secure file shredding
- Native GUI (egui), CLI, and WASM web app sharing one core library; zero compiler warnings across all three targets
- Typed key API, `inspect_stream`, formal stability promise in `STABILITY.md`
- Security hardening pass (v4.1.1): `find_session_key` timing oracle closed, `signdecrypt` CLI stdout buffered before ML-DSA verification, Shamir polynomial coefficients and `PqfReader` streaming plaintext both wrapped in `Zeroizing`, decompression bomb protection for v6 files via `LimitedWriter`, `PqfWriter` drop panics in debug builds when `finish()` not called
- Published to crates.io as `pqfile = "4.0.0"`; v4.1.x patch series complete

---

## v4.x - Depth and hardening (no breaking format changes)

### Security

- ~~**Authenticated header (nonce + size binding)**~~  **DONE (v4.x)**
  The `nonce` and `original_size` fields are now bound into the session-key commitment: `compute_key_commitment` hashes `session_key || nonce || original_size` (domain separator `"pqfile-session-key-commitment-v2"`), so any tampering with those header fields causes chunk-0's AEAD tag to fail. The KEM ciphertext and recipient slots are excluded because wrong-CT → wrong-ss already covers that attack vector, and excluding them preserves zero-copy operations (`add_recipient`, `rekey`): both operations preserve the session key, nonce, and original_size. This is a breaking wire change for existing files - they must be re-encrypted; static and compat test vectors were regenerated.
  > **Note:** Full binding of every header byte (including KEM ciphertexts and recipient slots) is reserved for v5.0 with a version bump, where `add_recipient` and `rekey` can be updated to re-tag chunk-0.

- ~~**Key commitment check**~~  **DONE (v4.x)**
  The first AEAD chunk now includes a 32-byte SHA3-256 commitment to the session key in its Additional Authenticated Data (`"pqfile" || 0u32_be || is_last || key_commitment`). This binds each file to the specific session key that encrypted it, preventing KEM ciphertext substitution attacks and "invisible salamander" multi-key collisions where a crafted ciphertext authenticates under two distinct ChaCha20 keys. Implementation note: the commitment is placed in chunk AAD (not stored per-recipient-slot as originally planned), and uses SHA3-256 (not BLAKE3). Header bytes are excluded so `add_recipient` and `rekey` remain valid without re-encrypting payload chunks. This is a breaking wire-format change; static test vectors were regenerated accordingly.

- ~~**Full constant-time audit**~~  **DONE (v4.1.0 / v4.1.1)**
  Both GF(256) arithmetic primitives used in Lagrange interpolation are now branchless. `gf_mul` had data-dependent branching on the `a` (secret) argument; both conditionals were replaced with mask idioms (`0u8.wrapping_sub(bit)`) in v4.1.0. `gf_inv` previously computed `x^254` via a data-dependent exponentiation loop; it was replaced in v4.1.1 with a fixed 7-squaring chain that runs identically for all non-zero inputs. A standalone `dudect` benchmark (`pqfile/examples/ct_shamir.rs`) and a `--features timing-tests` unit test cover both primitives. The passphrase and key-comparison paths were reviewed and found to rely on constant-time primitives from the `aes-gcm` and `argon2` crates.

- ~~**Security hardening pass**~~  **DONE (v4.1.1)**
  Twelve findings from a pre-publish security audit were addressed. Critical: `pqfile doctor` legacy key detection now prompts for the actual passphrase before probing, so p=1 keys are reliably identified; `signdecrypt` CLI stdout path buffers into `Zeroizing<Vec<u8>>` so plaintext only reaches stdout after ML-DSA verification succeeds. High: `find_session_key` (v4/v7) now iterates all same-variant entries without early return, closing a timing oracle that revealed which slot matched; Shamir polynomial coefficients (`coeff_buf`) wrapped in `Zeroizing` so random coefficients are overwritten after splitting; v6 (compressed) decompression capped via `LimitedWriter` at `original_size` to prevent decompression bomb attacks; `PqfReader` per-chunk plaintext buffer changed to `Zeroizing<Vec<u8>>` with explicit `zeroize()` before each reuse; parallel decrypt now returns `PqfileError::Truncated` for truncated streams, matching the serial path. Additional: `PqfWriter::drop` panics in debug builds when `finish()` was not called; `encrypt_mmap` calls `madvise(Sequential)` on Unix; `AtomicOutput::commit` fsyncs the parent directory on Unix after rename; `json_escape` escapes all control characters 0x00-0x1F.

- ~~**Recipient count padding (v9 format)**~~  **DONE (v4.1.0)**
  `encrypt_stream_multi_anon_padded` pads the slot count to the next power of two with random dummy entries before shuffling. Version byte `0x09`. The decryptor handles v9 identically to v8. CLI flag `--pad-recipients`. Three format vector tests added.

### Library

- ~~**`PqfWriter<W: Write>` streaming encryptor**~~  **DONE (v4.1.0)**
  Implemented in `pqfile::writer`. Buffers plaintext into chunks and encrypts on write. `finish()` seals the final partial chunk and returns the inner writer. Drop attempts a best-effort seal. Nine tests including interop with `PqfReader`.

- ~~**`PqfWriter` async counterpart**~~  **DONE (v4.1.0)**
  `AsyncPqfWriter<W: AsyncWrite + Unpin>` in `pqfile::async_io`. Buffers plaintext in `poll_write`, seals on `finish()` or `poll_shutdown()` via a Buffering/Flushing/Done state machine. Six tokio tests.

- ~~**Partial truncation detection in streaming decrypt**~~  **DONE (v4.1.0)**
  `PqfileError::Truncated` returned when `is_last && counter > 0` (at least one chunk succeeded before the stream ended unexpectedly). `PqfReader` surfaces it as `io::ErrorKind::UnexpectedEof` wrapping `PqfileError::Truncated`.

### Testing

- ~~**Property-based testing with proptest**~~  **DONE (v4.1.0)**
  `pqfile/tests/property.rs` with five proptest tests: encrypt/decrypt roundtrip for arbitrary lengths, single-byte flip always fails auth, Shamir split/reconstruct recovers the original key, and insufficient shares do not recover it.

- ~~**Mutation testing with cargo-mutants**~~  **DONE (v4.1.0)**
  `.github/workflows/mutants.yml` runs weekly and on manual dispatch, scoped to `decrypt.rs`, `format.rs`, `shamir.rs`, `passphrase.rs`. Any surviving mutant in those paths requires a new test.

- ~~**Cross-version compatibility matrix**~~  **DONE (v4.1.0)**
  Golden ciphertext files for v2 through v8 (all format variants) committed to `pqfile/tests/compat/`. Eleven roundtrip tests in `pqfile/tests/compat.rs` run on every CI push via `cargo test --workspace`.

### Performance

- ~~**`PqfWriter` zero-copy path with memory-mapped I/O**~~  **DONE (v4.1.0)**
  `encrypt_mmap(pubkey_pem, path, chunk_size, writer)` in `pqfile::encrypt` (native only, `memmap2 = "0.9"`). CLI `--mmap` flag for single-recipient file inputs. Three tests. The intermediate read buffer is eliminated; kernel pages map directly into the AEAD path.

- ~~**Adaptive chunk sizing**~~  **DONE (v4.1.0)**
  `format::adaptive_chunk_size(file_size) -> usize` returns 16 KiB for files under 1 MiB, 256 KiB for files over 256 MiB, and 64 KiB otherwise. CLI `--chunk-size 0` (the new default) triggers auto-tune. The chosen size is stored in v5 format.

- ~~**Chunk pipeline (I/O and AEAD overlap)**~~  **DONE (v4.1.0)**
  `encrypt_stream_pipelined<R: Read + Send + 'static>` uses a bounded `mpsc::sync_channel(2)` to read ahead one full chunk while the current chunk is being encrypted. CLI `--pipeline` flag (file inputs only; stdin unsupported). Four tests.

### Robustness

- ~~**Atomic output writes**~~  **DONE (v4.1.0)**
  `AtomicOutput` struct writes to a temp file in the same directory and renames on `commit()` (with `sync_all()` before rename). All seven CLI file-write paths now go through `AtomicOutput` or `CliOutput` (which wraps stdout or `AtomicOutput`). A killed process leaves no partial artifact.

- ~~**Input header validation hardening**~~  **DONE (v4.1.0)**
  `MAX_RECIPIENTS = 256` and `MAX_ORIGINAL_SIZE = 1 TiB` added as module-level constants in `format.rs`. `read_nonce_and_size` rejects `original_size > MAX_ORIGINAL_SIZE` with a clear I/O error. The three inline `MAX_RECIPIENTS = 1000` guards were replaced with the new constant.

- ~~**`pqfile doctor` diagnostic command**~~  **DONE (v4.1.0)**
  `pqfile doctor <file>` inspects a PEM key or `.pqf` ciphertext. For keys: reports encrypted/hardware/legacy-p1 status and optionally checks the revocation sidecar. For `.pqf` files: reports version, KEM info, original size, and header validity without decrypting. JSON output supported. Two CLI integration tests.

- ~~**Structured error codes in JSON output**~~  **DONE (v4.1.0)**
  All JSON error responses now include `"code": N`. `docs/ERROR_CODES.md` defines a 21-entry stable code table treated as part of the public API. The CLI integration test for JSON error output was updated to assert the `code` field is present.

### GUI

**UX polish**

- ~~**Pre-flight validation**~~  **DONE**
  All action buttons are disabled with an inline hint when requirements are unmet (Encrypt: "Add at least one recipient key and one file to continue.", Decrypt: "Load a private key and add at least one .pqf file to continue."). Validation is proactive, not post-hoc.

- ~~**Output path preview**~~  **DONE**
  The Encrypt tab now shows the derived output path (first file + output directory setting + `.pqf`) as a grey subtext line under the action button before it is clicked, along with "…and N more" when multiple files are selected.

- ~~**Batch operation summary**~~  **DONE**
  After a multi-file encrypt or decrypt run a one-line summary ("3 files encrypted successfully." / "2 succeeded, 1 failed.") appears below the progress bar. Individual per-file results remain visible in the list.

- ~~**Copy-to-clipboard on fingerprints**~~  **DONE**
  The Keys tab now shows a small `⎘` clipboard button beside each key fingerprint. Clicking it calls `ctx.copy_text()`.

- ~~**Clear-all on file and recipient lists**~~  **DONE**
  "Clear all" buttons added to the Encrypt recipients header, Encrypt files header, and Decrypt files header (Archive and Shamir already had them). Buttons appear only when the list is non-empty and no job is running.

- ~~**Scroll indicators on long lists**~~  **DONE**
  The Encrypt recipients list, Encrypt files list, Decrypt files list, Shamir shares list, and Archive files list are now wrapped in a `ScrollArea::vertical().max_height(154.0)`. When content overflows a mesh-gradient fade (transparent → card background colour) is painted at the bottom using `egui::Shape::mesh`. The helper `scrollable_list()` in `widgets.rs` handles this for all lists.

- ~~**Eye icon for passphrase visibility toggle**~~  **DONE**
  The ●/○ toggle was replaced with `"👁 show"` / `"hide"` text labels, with tooltip text "Show passphrase" / "Hide passphrase". The button is sized to fit.

- ~~**Sub-tab segmented controls**~~  **DONE**
  Sign (Key Generation / Sign File / Verify Signature), Signcrypt (Sign + Encrypt / Decrypt + Verify), Archive (Create / Extract), and Shamir (Split Key / Reconstruct Key) all now show a pill-style segmented control (`seg_tabs` widget in `widgets.rs`) that switches between their two or three modes. Only the active mode is rendered.

- ~~**Compression tooltip when grayed out**~~  **DONE**
  The "Compress before encrypting" label now shows a hover tooltip explaining the restriction when multiple recipients are selected: "Compression is disabled for multi-recipient files because content length leaks information about the plaintext across independently keyed slots."

- ~~**Tools tab section grouping**~~  **DONE**
  Each utility (Repassphrase, Revoke, Rekey) already has its own `section_label` + `card()` scope.

**Features**

- ~~**Key label propagation to recipient slots**~~  **DONE**
  `apply_load_pub` in the Keys tab now uses `self.keys[i].label` (the human-readable name) instead of `pubkey.pem` as the recipient display name when loading a key into the Encrypt tab.

- ~~**`pqfile doctor` in the Inspect tab**~~  **DONE**
  The Inspect tab now accepts both `.pqf` and `.pem` files. For `.pqf` files it shows the existing header info plus "Header validity: OK". For `.pem` key files it shows type, variant, passphrase-protected status, hardware-backed status, and usage tips (passphrase upgrade path, revocation hint). The section label was updated from "FILE" to "FILE OR KEY".

- ~~**Drag-and-drop from Keys tab into recipient slots**~~  **DONE**
  Each key entry row in the Keys panel is wrapped in `ui.dnd_drag_source(id, Arc<KeyDragPayload>, ...)`. The Encrypt recipients card has a `dnd_drop_zone` that accepts a dropped `KeyDragPayload` and adds the key's label + PEM to the recipient list. The Decrypt private key section has a `dnd_drop_zone` that loads the private key path. `KeyDragPayload { label, pub_pem, priv_path }` is defined in `types.rs`.

- ~~**Recent files list**~~  **DONE**
  The last 5 encrypt source files and decrypt `.pqf` files are tracked per operation and persisted to `AppStorage` via `save_recent`/`load_recent`. When the respective file list is empty a "Recent:" row of click-to-load filename buttons appears in the list card (native only).

- ~~**Passphrase strength meter during key generation**~~  **DONE**
  The Keygen tab now shows a narrow colour bar (red / amber / green) below the passphrase field when the passphrase is non-empty, scored on length (≥8 / ≥12 / ≥16) and character diversity (lower, upper, digit, symbol). Label: "Weak" / "Fair" / "Strong". Feedback only; no minimum enforced.

- ~~**Inline WASM file size guard**~~  **DONE**
  `tick_encrypt_wasm` now checks `data.len() > u32::MAX` before starting encryption and sets `OpStatus::Err("File too large for browser (N GiB). Use the desktop app (limit: 4 GiB).")` instead of panicking.

- ~~**Clipboard encrypt / decrypt**~~  **DONE**
  A "Clipboard Encrypt / Decrypt" section in the Tools tab lets users type or paste short plaintext, choose a recipient public key, click "Encrypt & Copy" to encrypt and write the PEM-wrapped ciphertext to the clipboard. The reverse path pastes the ciphertext, loads a private key, and decrypts back into the text area. Uses a `-----BEGIN PQFILE CIPHERTEXT-----` PEM wrapper via the `pem = "3"` crate dependency.

- ~~**QR code export for public keys and Shamir shares**~~  **DONE**
  A "📷 Show QR code" button appears on the Keygen tab after successful key generation (native) and "📷 QR share N" buttons appear after a Shamir split. Clicking generates a QR code via `qrcode = "0.14"`, loads it as an egui texture, and shows a modal window with the image and a "Close" button. `PqfileApp::open_qr()` / `show_qr_window()` in `app.rs` handle the generation and modal lifecycle. `qr_modal: Option<QrModal>` is stored on the app state.

**Import**

- ~~**Import from SSH ed25519 keys**~~  **DONE (SSH ed25519 only)**
  `pqfile import-key --from <ssh-key.pem> --out <dir> [--passphrase] [--force]` parses an unencrypted OpenSSH ed25519 private key, expands the 32-byte seed to 64 bytes via HKDF-SHA256 (info `"pqfile-import-from-ssh-ed25519"`), and calls `keygen_bytes_from_seed` to produce an ML-KEM-768 key pair. The GUI adds an "Import SSH key…" button to the Keygen tab. The new library functions `keygen_bytes_from_seed` and `import_key_from_ssh` are in `pqfile::keygen`. Manual OpenSSH binary format parser in `extract_ssh_ed25519_seed` / `ssh_read_u32` / `ssh_read_string`. 5 new library tests. Import from age and minisign remains future work.

**Automation**

- ~~**Watchfolder / auto-encrypt mode**~~  **DONE**
  A "Watch Folder (Auto-Encrypt)" section in the Encrypt tab shows a folder path input, a Browse button, a start/stop toggle, and a scrollable activity log. When active, a background thread uses `notify = "8"` (`recommended_watcher`) to receive `Create` events from the OS and encrypts each new non-`.pqf` file for the currently loaded recipients using `encrypt_stream` or `encrypt_stream_multi_anon`. Results (✓ success / ✗ error / ⚠ skipped) stream into `watch_log` and are rendered in a scrollable card. The watcher stops cleanly via an `AtomicBool` stop flag. `WatchHandle { log_rx, stop_flag }` held in app state. Shred-after-encrypt remains an option for a future iteration.

- ~~**Key expiry and renewal workflow**~~  **DONE**
  An optional `# Expires: YYYY-MM-DD` comment line is prepended to both PEM files at key generation time (new "Expiry" section in the Keygen tab, applies to native and WASM). The Keys tab reads the comment and shows a colour badge: green (>30 days), amber (≤30 days), red (expired). A "↺ Renew" button appears on expired/near-expiry entries and switches to the Keygen tab pre-filled with the key's label. The Inspect tab's doctor output also displays the expiry with days remaining. Utility functions `read_pem_expiry` and `expiry_days_remaining` live in `types.rs` and use exact Gregorian JDN arithmetic.

---

## v5.0 - Next major (breaking format changes)

These items require a new major version because they change the wire format or public API in a backward-incompatible way.

- **Authenticated header across all format versions**
  Roll the header-AAD binding (from the v4.x hardening work above) into every new file written, and bump the version byte. Old files remain readable but new files are protected against header tampering without any opt-in flag.

- **Per-file entry AEAD in archives (PQFA v2)**
  The current `.pqfa` format authenticates the entire archive before any file is extracted, which requires buffering the full ciphertext in memory for in-memory extractions. A PQFA v2 layout gives each file entry its own AEAD tag derived from the session key and the entry index, so individual files can be extracted and verified without loading the whole archive.

- **`PqfileError` refinement**
  Break `DecryptionFailure` into specific variants: `AuthenticationFailure` (tag mismatch), `Truncated` (clean truncation), `UnsupportedVersion` (unknown format version), `RecipientNotFound` (none of the recipient slots matched). This is an API break but gives callers the precision they need for good error messages.

- **Misuse-resistant nonces (nonce-SIV construction)**
  Replace random nonces with synthetic nonces derived from a hash of the session key and plaintext chunk (a simplified SIV mode). With random nonces, a nonce collision is possible if the same key encrypts a very large number of chunks; SIV derivation makes collision probability zero regardless of how many files are encrypted under a given session key. This is a format break because the nonce field changes meaning in the chunk header.

- **Magic-free output mode**
  Currently all `.pqf` files begin with the four-byte magic `PQFL`, which immediately identifies them as pqfile output to any observer. A `--stealth` flag omits the magic bytes and version header, producing output that is indistinguishable from random bytes. The decryptor uses `--stealth` as a hint to skip magic validation and attempt raw decryption. Useful when revealing that a file is encrypted at all is itself sensitive.

---

## New Directions

These are ideas not yet implemented. All are focused on cryptographic depth rather than ecosystem expansion.

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

A mode where the raw ciphertext bytes are split across N output files using a secret sharing scheme (or simpler XOR splitting for K=N), requiring any K files to reconstruct. Different from key splitting: the key stays intact and the payload itself is distributed. Useful for backup scenarios where the ciphertext is spread across cloud providers that are mutually untrusted -- no single provider has a usable ciphertext.

### Timing consistency test harness

~~Implemented in v4.1.0 / v4.1.1.~~ `pqfile/examples/ct_shamir.rs` is a standalone `dudect-bencher` binary covering the Shamir GF(256) reconstruction path, including both `gf_mul` and the `gf_inv` 7-squaring chain added in v4.1.1. `cargo test --features timing-tests` runs a fast sanity check that measures the mean timing for two secret classes and asserts the relative difference stays under 10%. Full rigorous `dudect` analysis requires a quiet machine (`cargo run --example ct_shamir -p pqfile`). Extension to the decryption error path and passphrase path remains future work.

### Proxy re-encryption

Generate a re-encryption key `rk(A -> B)` from private key A and public key B. A proxy holding only `rk` can transform a ciphertext encrypted for A into one encrypted for B, without ever seeing the plaintext or either private key. Useful for delegated access: a file server can re-encrypt stored files on behalf of a new recipient without the sender needing to re-encrypt manually. The construction uses a KEM-based proxy scheme: `rk = HKDF(dkA, ekB)` combined with a blinding factor so the proxy cannot decapsulate either the original or the transformed ciphertext on its own.

### Shell integration

Right-click → "Encrypt with pqfile" on Windows (Explorer context menu via registry entry pointing to the CLI binary), macOS (Quick Action via an Automator `.workflow` bundle or `LaunchServices` registration), and Linux (`.desktop` file with a broad `MimeType=*` registration). The integration invokes the CLI with the last-used recipient key and writes the output alongside the original. On Windows this requires a small registry shim under `HKCU\Software\Classes\*\shell\`; no COM server is needed if the CLI handles its own argument quoting. High discoverability impact: users encounter the feature in their normal file workflow rather than needing to open the GUI.

### Web extension / browser integration

A browser extension (Chrome / Firefox) that embeds the existing WASM core and adds an "Encrypt" action to file-attachment dialogs and an "Encrypt text" context menu item for any selected text on a web page. Encryption runs entirely in the browser process via the WASM module - no data is sent to a server. The extension's key store persists to `browser.storage.local`, itself encrypted under a passphrase at rest. This is differentiated from existing tools: no other post-quantum file encryptor offers browser-native encryption that operates on arbitrary page content without a round-trip to a backend.

---

## Security invariants

The following properties are invariants, not roadmap items. Any proposal that weakens them requires explicit justification and a major version bump:

- All cryptographic operations run locally. No data is sent to a server.
- The entire `.pqf` file (header + payload) is authenticated before any plaintext is returned.
- Secret material is zeroized from memory on drop.
- Each encryption produces a fresh KEM ciphertext and a fresh random nonce.
- In hybrid mode, each encryption also produces a fresh ephemeral X25519 scalar.
