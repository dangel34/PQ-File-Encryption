# Changelog

All notable changes to pqfile are documented here.
Releases follow [Semantic Versioning](https://semver.org).
The `.pqf` format version (`VERSION` in `format.rs`) is separate from the crate version — it only increments when the on-disk format changes in a way that breaks existing `.pqf` files.

---

## [1.0.0] — 2026-04-25

Initial public release.

### Cryptography

- ML-KEM-768 (NIST FIPS 203) key encapsulation — generates a fresh 32-byte shared secret per file.
- ChaCha20-Poly1305 (RFC 8439) authenticated symmetric encryption using that shared secret.
- STREAM AEAD construction (`StreamBE32`) over 64 KB chunks — each chunk carries a 16-byte authentication tag, providing integrity and preventing truncation or reordering attacks.
- All header bytes (magic, version, KEM variant, KEM ciphertext, nonce, original size) are bound as AEAD additional data (AAD). Any modification to any byte of the file — header or payload — causes decryption to fail before any plaintext is produced.
- Fresh random nonce and KEM ciphertext for every encryption. Nonce reuse under the same key is structurally impossible because the symmetric key itself is freshly derived per file.

### Key management

- ML-KEM-768 key pair generation, serialized to PEM files (`pubkey.pem`, `privkey.pem`).
- Private key files are written with mode `0600` (owner read/write only) on Unix systems.
- Public key fingerprint (truncated SHA-256 hex) printed after keygen.
- Secret bytes (decapsulation key, shared secret, decrypted file contents in the GUI) are zeroed in memory on drop via the `zeroize` crate.

### CLI (`pqfile`)

- `keygen --out <DIR>` — generate a new key pair.
- `encrypt -r <PUBKEY> <INPUT>…` — encrypt one or more files; each output is `<input>.pqf`.
- `decrypt -k <PRIVKEY> <INPUT>…` — decrypt one or more `.pqf` files; output has `.pqf` stripped.
- `inspect <FILE>` — print header fields (magic, version, KEM variant, nonce, original size) without decrypting.
- Atomic writes: all output is first written to a `.tmp` file and renamed on success. A partial or failed output is never left behind.
- Status line printed per file for multi-file operations.

### Desktop GUI (`pqfile-desktop`)

- Four-tab egui interface: Keygen, Encrypt, Decrypt, Inspect.
- Native file dialogs via `rfd`.
- Settings tab with in-app self-updater: checks the GitHub Releases API, downloads the platform-specific binary, verifies its SHA-256 checksum against `checksums.sha256`, and performs an atomic replacement of the running executable.
- Identical feature set on Linux, macOS, and Windows.

### Web GUI (WASM)

- Same four-tab interface compiled to WebAssembly via `trunk`.
- All cryptographic operations run entirely in the browser — no file data or key material is transmitted to any server.
- File input via drag-and-drop or file picker; output is downloaded via the browser download mechanism.
- Deployed automatically to GitHub Pages on every version tag.

### File format

- Magic: `PQFL`
- Format version: `0x03`
- Header size: 1110 bytes fixed.
- Payload: 64 KB STREAM AEAD chunks, each with a 16-byte Poly1305 tag.

### CI / Release automation

- CI runs `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` on every push and pull request.
- Release workflow builds CLI binaries for Linux, macOS, and Windows; desktop GUI binaries for the same three platforms; and the WASM web app — all triggered by a `v*` tag push.
- Release assets use platform-specific names (`pqfile-linux-x86_64`, `pqfile-macos-x86_64`, etc.).
- `checksums.sha256` published alongside binaries for independent verification.
- GitHub Pages deployed automatically on every release.

---

<!-- New releases go above this line, oldest at the bottom. -->
<!-- Format: ## [X.Y.Z] — YYYY-MM-DD -->
