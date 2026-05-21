# pqfile - Post-Quantum File Encryption

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=dangel34_PQ-File-Encryption&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dangel34_PQ-File-Encryption)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=dangel34_PQ-File-Encryption&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=dangel34_PQ-File-Encryption)

A quantum-resistant file encryption tool with a CLI and a cross-platform GUI. It combines post-quantum key encapsulation (ML-KEM, NIST FIPS 203) with ChaCha20-Poly1305 authenticated encryption. Three key types are supported: ML-KEM-768, ML-KEM-1024, and a hybrid X25519+ML-KEM-768 mode. A file can be encrypted to multiple recipients in a single pass.

Digital signatures use ML-DSA-65 (NIST FIPS 204).

**[QUICKSTART.md](QUICKSTART.md)**: build, install, common CLI commands, GUI overview, deploying.

---

## Background

Classical public-key algorithms such as RSA and ECDH are vulnerable to attacks from sufficiently large quantum computers. ML-KEM (Module-Lattice Key Encapsulation Mechanism), standardized by NIST as FIPS 203, is believed to be secure against both classical and quantum adversaries.

pqfile uses a hybrid approach:

1. **ML-KEM** encapsulates a fresh random session key. Only the holder of the matching private decapsulation key can recover it.
2. **ChaCha20-Poly1305** encrypts the file contents under that session key using the STREAM construction (64 KiB chunks). Each chunk is independently authenticated and position-bound so truncation and reordering attacks are detected.

The optional **hybrid mode** (`--hybrid`) adds X25519 Diffie-Hellman to the key exchange so the encryption is secure under either classical _or_ quantum assumptions, whichever holds in the future.

---

## Cryptographic standards

| Component                        | Standard / Specification                                |
|----------------------------------|---------------------------------------------------------|
| Key encapsulation (standard)     | ML-KEM-768 or ML-KEM-1024, NIST FIPS 203               |
| Key encapsulation (hybrid)       | X25519 + ML-KEM-768, key combined via HKDF-SHA256       |
| Symmetric cipher                 | ChaCha20-Poly1305, RFC 8439                             |
| Session key wrapping (v4)        | AES-256-GCM                                             |
| Randomness                       | OS CSPRNG via `getrandom`                               |
| Key derivation (passphrase)      | Argon2id (m=64 MiB, t=3, p=1)                          |
| Key wrapping (passphrase)        | AES-256-GCM                                             |
| Digital signatures               | ML-DSA-65, NIST FIPS 204                                |
| Key fingerprints                 | SHA3-256 (first 8 bytes, colon-separated hex)           |

---

## Project structure

```
PQ-File-Encryption/
├── Cargo.toml              Workspace manifest
├── fuzz/                   cargo-fuzz targets (excluded from main workspace)
│   └── fuzz_targets/
│       ├── fuzz_header_read.rs    Fuzzes PqfHeader::read on arbitrary bytes
│       ├── fuzz_decrypt_bytes.rs  Fuzzes decrypt_bytes on arbitrary ciphertext
│       └── fuzz_pem_parsing.rs    Fuzzes PEM parsing and fingerprinting
├── pqfile/                 CLI tool and crypto library
│   ├── src/
│   │   ├── main.rs         CLI entry point (clap subcommands, stdin/stdout support)
│   │   ├── lib.rs          Public library re-exports
│   │   ├── keygen.rs       Key pair generation and PEM serialization
│   │   ├── encrypt.rs      Hybrid encryption pipeline (v2/v3/v4 formats)
│   │   ├── decrypt.rs      Hybrid decryption pipeline (v2/v3/v4 auto-detect)
│   │   ├── format.rs       .pqf binary file format definitions
│   │   ├── passphrase.rs   Argon2id wrapping for passphrase-protected keys
│   │   ├── sign.rs         ML-DSA-65 signing and verification
│   │   └── error.rs        PqfileError enum
│   ├── benches/
│   │   └── crypto.rs       Criterion benchmarks (encrypt/decrypt at 1 KB/1 MB/100 MB)
│   └── tests/
│       └── roundtrip.rs    End-to-end CLI integration tests (45 tests)
├── pqfile-gui/             Shared GUI logic + WASM web app
│   ├── index.html          Canvas page for trunk/WASM builds
│   └── src/
│       ├── lib.rs          Entry point, WASM start fn, tests
│       ├── app.rs          PqfileApp struct and frame impl
│       ├── colors.rs       Catppuccin palette constants
│       ├── theme.rs        egui theme application
│       ├── types.rs        Shared types (Tab, FileInput, Settings…)
│       ├── widgets.rs      UI helper functions
│       └── tabs/
│           ├── keygen.rs, encrypt.rs, decrypt.rs, inspect.rs, settings.rs, keys.rs
└── pqfile-desktop/         Native desktop binary
    └── src/
        └── main.rs         Native entry point (~18 lines)
```

The `pqfile` crate is both a library and a CLI binary. The `pqfile-gui` crate compiles to a `cdylib` for WASM and an `rlib` for the native binary. `pqfile-desktop` is the thin native entry point. This follows the official eframe template pattern.

---

## CLI usage

### Key generation

```bash
# ML-KEM-768 (default, 128-bit post-quantum security)
pqfile keygen --out ./keys

# ML-KEM-1024 (192-bit post-quantum security)
pqfile keygen --out ./keys --level 1024

# Hybrid X25519 + ML-KEM-768 (secure under classical OR quantum assumptions)
pqfile keygen --out ./keys --hybrid

# Any of the above with a passphrase-protected private key
pqfile keygen --out ./keys --passphrase
```

Key files written: `pubkey.pem` (share freely) and `privkey.pem` (keep secret). The fingerprint (SHA3-256, first 8 bytes) is printed at generation time.

### Encryption

```bash
# Single recipient
pqfile encrypt -r pubkey.pem secret.txt
# Output: secret.txt.pqf

# Custom output path
pqfile encrypt -r pubkey.pem secret.txt -o encrypted.pqf

# Multiple recipients - any one of them can decrypt
pqfile encrypt -r alice/pubkey.pem -r bob/pubkey.pem secret.txt

# Recursive directory encryption
pqfile encrypt -r pubkey.pem --recursive /path/to/dir/
# Each file → <file>.pqf alongside the original; existing .pqf files are skipped

# Read from stdin, write to stdout
cat secret.txt | pqfile encrypt -r pubkey.pem - > secret.txt.pqf
```

Multiple `-r` flags produce a v4 multi-recipient file. Each recipient gets their own encapsulated session key; the file payload is encrypted once. `--recursive` requires exactly one recipient.

### Decryption

```bash
# Decrypt to default path (strips .pqf extension)
pqfile decrypt -k privkey.pem secret.txt.pqf

# Custom output path
pqfile decrypt -k privkey.pem secret.txt.pqf -o recovered.txt

# Stdin/stdout pipeline
cat secret.txt.pqf | pqfile decrypt -k privkey.pem - -o -
```

If the private key is passphrase-protected, the passphrase is prompted interactively. Works with v2, v3 (streamed), and v4 (multi-recipient) files.

### Inspect

```bash
pqfile inspect secret.txt.pqf
```

For a single-recipient file (v2/v3):
```
Magic:              PQFL
Version:            0x03
KEM variant:        768 (ML-KEM-768)
Nonce:              3a7b...
Original file size: 2048 bytes
```

For a multi-recipient file (v4):
```
Magic:              PQFL
Version:            0x04 (multi-recipient)
Recipients:         2
  Recipient 0:      768 (ML-KEM-768)
  Recipient 1:      1024 (ML-KEM-1024)
Nonce:              8c2f...
Original file size: 2048 bytes
```

### Digital signatures

```bash
# Generate a signing key pair (separate from encryption keys)
pqfile sign-keygen --out ./keys
# Writes: sign_pubkey.pem (1952 bytes), sign_privkey.pem (32-byte seed)

# Sign a file (produces a detached .sig file)
pqfile sign -k sign_privkey.pem document.pdf
# Output: document.pdf.sig

# Custom signature output path
pqfile sign -k sign_privkey.pem document.pdf -o document.sig

# Verify a signature
pqfile verify -k sign_pubkey.pem -s document.pdf.sig document.pdf
```

Signatures are ML-DSA-65 (NIST FIPS 204), 3309 bytes, stored in PEM format. The verifying key (1952 bytes) can be distributed alongside the signed content.

### Shell completions

```bash
pqfile completions bash   >> ~/.bash_completion
pqfile completions zsh    > ~/.zfunc/_pqfile
pqfile completions fish   > ~/.config/fish/completions/pqfile.fish
pqfile completions powershell >> $PROFILE
```

### JSON output

Every command accepts a global `--json` flag for machine-readable output:

```bash
pqfile --json keygen --out ./keys
# {"status":"ok","pubkey_path":"./keys/pubkey.pem","privkey_path":"./keys/privkey.pem","fingerprint":"21:f3:b4:..."}

pqfile --json inspect file.pqf
pqfile --json encrypt -r pubkey.pem file.txt
pqfile --json decrypt -k privkey.pem file.txt.pqf
pqfile --json sign -k sign_privkey.pem file.txt
pqfile --json verify -k sign_pubkey.pem -s file.txt.sig file.txt
```

Errors go to stderr as `{"status":"error","message":"..."}`. Exit code is always 1 on error.

---

## GUI

The desktop GUI (`pqfile-desktop`) and web app (`pqfile-gui`) share the same egui code and support:

- **Keygen tab**: generates key pairs (ML-KEM-768, ML-KEM-1024, or Hybrid), with optional passphrase protection
- **Encrypt tab**: multi-recipient list, multi-file batch encrypt with per-file status and progress bar
- **Decrypt tab**: loads any v2/v3/v4 `.pqf` file; shows passphrase field only when needed
- **Inspect tab**: displays header metadata for v2/v3/v4 `.pqf` files without decrypting
- **Keys tab**: persistent key-pair registry with fingerprints and quick-load buttons
- **Settings tab**: theme, auto-clear, confirm-overwrite preferences

> The GUI keygen always produces ML-KEM-768 keys. Use the CLI for `--level 1024`, `--hybrid`, or multi-recipient encryption.

---

## The .pqf file format

There are four format versions. The version byte at offset 4 selects the layout.

### v2: single-recipient, whole-file AEAD

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x02
5        2         KEM variant (u16 little-endian): 768, 1024, or 0x0301 (hybrid)
7        CT_LEN    KEM ciphertext (encapsulated session key)
7+CT     12        ChaCha20-Poly1305 nonce
7+CT+12  8         Original plaintext size (u64 little-endian)
────     N+16      Encrypted payload; header used as AEAD additional data
```

### v3: single-recipient, chunked STREAM

Same header as v2 with `version = 0x03`. The payload is split into 64 KiB chunks. Each chunk's nonce is `base_nonce[8] || counter[4]` and its AAD is `"pqfile" || counter[4] || is_last[1]`. The last-chunk flag prevents truncation; the counter prevents reordering.

### v4: multi-recipient, chunked STREAM

```
Offset   Length    Field
------   ------    -----
0        4         Magic: "PQFL"
4        1         Version: 0x04
5        2         Recipient count N (u16 little-endian)
─── Per recipient (repeated N times) ───────────────────────────────
         2         KEM variant (u16 little-endian)
         CT_LEN    KEM ciphertext for this recipient
         48        AES-256-GCM wrapped session key (32-byte key + 16-byte tag)
─── Shared tail ────────────────────────────────────────────────────
         12        Base nonce (8 random bytes || 4 zero bytes)
         8         Original plaintext size (u64 little-endian)
─── Payload ────────────────────────────────────────────────────────
         …         Chunked STREAM identical to v3, keyed by the session key
```

A random 32-byte session key K encrypts the payload. Each recipient's `ss` (from their KEM encapsulation) wraps K under `AES-256-GCM(key=ss, nonce=zero)`. The zero nonce is safe because each `ss` is unique per encapsulation. Mixed KEM variants within one file are supported.

### KEM variant field

| Value    | Algorithm               | CT bytes | EK bytes |
|----------|-------------------------|----------|----------|
| `768`    | ML-KEM-768              | 1088     | 1184     |
| `1024`   | ML-KEM-1024             | 1568     | 1568     |
| `0x0301` | Hybrid X25519+ML-KEM-768| 1120     | 1216     |

---

## PEM key formats

### ML-KEM-768

```
-----BEGIN ML-KEM-768 PUBLIC KEY-----          (1184 bytes raw)
-----BEGIN ML-KEM-768 PRIVATE KEY-----         (64-byte seed)
-----BEGIN ML-KEM-768 ENCRYPTED PRIVATE KEY--- (16-byte salt || 12-byte nonce || 80-byte AES ciphertext)
```

### ML-KEM-1024

```
-----BEGIN ML-KEM-1024 PUBLIC KEY-----         (1568 bytes raw)
-----BEGIN ML-KEM-1024 PRIVATE KEY-----        (64-byte seed)
-----BEGIN ML-KEM-1024 ENCRYPTED PRIVATE KEY-- (same layout as above)
```

### Hybrid X25519+ML-KEM-768

```
-----BEGIN X25519+ML-KEM-768 PUBLIC KEY-----         (X25519 pubkey 32 || ML-KEM EK 1184 = 1216 bytes)
-----BEGIN X25519+ML-KEM-768 PRIVATE KEY-----        (X25519 scalar 32 || ML-KEM seed 64 = 96 bytes)
-----BEGIN X25519+ML-KEM-768 ENCRYPTED PRIVATE KEY-- (16-byte salt || 12-byte nonce || 112-byte AES ciphertext)
```

### ML-DSA-65 (signing only)

```
-----BEGIN ML-DSA-65 VERIFYING KEY-----  (1952 bytes raw)
-----BEGIN ML-DSA-65 SIGNING KEY-----    (32-byte seed)
-----BEGIN ML-DSA-65 SIGNATURE-----      (3309 bytes raw)
```

Signing keys are not passphrase-protected. Protect `sign_privkey.pem` with filesystem permissions or store it on encrypted storage.

Passphrase-protected private keys derive their AES-256-GCM wrapping key via Argon2id (m=64 MiB, t=3, p=1, 16-byte random salt). The private key stores only the seed (64 bytes for ML-KEM, 96 bytes for hybrid); the full decapsulation key is re-derived on load.

---

## Error handling

All errors are reported to stderr with a descriptive message; exit code is 1. The GUI shows errors inline in red.

| Error variant          | Meaning                                                                   |
|------------------------|---------------------------------------------------------------------------|
| `Io`                   | File system or I/O failure                                                |
| `InvalidMagic`         | File does not start with "PQFL"                                           |
| `UnsupportedVersion`   | Version byte is not 0x02, 0x03, or 0x04                                   |
| `UnsupportedKem`       | KEM variant field is not a recognised value                               |
| `EncryptionFailure`    | AEAD encryption or nonce generation failed                                |
| `DecryptionFailure`    | Authentication tag mismatch (file tampered or wrong key)                  |
| `InvalidPem`           | PEM file could not be parsed or has an unrecognised tag                   |
| `InvalidKeyLength`     | Decoded key bytes are the wrong length                                    |
| `OutputExists`         | Key file already exists and `--force` was not passed                      |
| `WrongPassphrase`      | Passphrase decryption of private key seed failed                          |
| `PassphraseRequired`   | Encrypted private key loaded but no passphrase supplied                   |
| `PassphraseMismatch`   | New passphrase and confirmation do not match                              |
| `InvalidSignature`     | Signature bytes are malformed                                             |
| `SignatureVerificationFailed` | ML-DSA-65 signature does not match the file                        |
| `NoMatchingRecipient`  | v4 file: no recipient entry matched the provided private key              |

---

## Testing

```
cargo test --workspace
```

171 tests across all crates (63 unit + 63 unit-in-main + 45 integration). Run benchmarks with:

```
cargo bench -p pqfile
```

Key integration tests in `pqfile/tests/roundtrip.rs`:

| Test group | What it covers |
|------------|----------------|
| Basic roundtrip | keygen → encrypt → decrypt → byte-for-byte match |
| Custom paths | `-o` flag on encrypt and decrypt |
| Stdin/stdout | full pipe with `-` |
| Force overwrite | `--force` behaviour |
| Inspect | header fields displayed correctly, v3 version byte, invalid file |
| JSON output | all commands emit valid JSON; errors go to stderr |
| Recursive | directory encryption, skip `.pqf`, non-directory error |
| 1024-bit | ML-KEM-1024 encrypt/decrypt roundtrip and inspect |
| ML-DSA | sign-keygen, sign, verify, tamper detection, JSON output |
| Hybrid | X25519+ML-KEM-768 roundtrip, passphrase, inspect, mismatch error |
| Multi-recipient | 2-key v4 roundtrip, 3-key v4, mixed variants, wrong key rejected |

---

## Dependencies

### pqfile (CLI and library)

| Crate            | Version | Purpose                                                       |
|------------------|---------|---------------------------------------------------------------|
| ml-kem           | 0.3     | ML-KEM-768/1024 key encapsulation (FIPS 203)                  |
| ml-dsa           | 0.1     | ML-DSA-65 digital signatures (FIPS 204)                       |
| chacha20poly1305 | 0.10    | ChaCha20-Poly1305 authenticated encryption                    |
| aes-gcm          | 0.10    | AES-256-GCM (passphrase key wrapping, v4 session key wrapping)|
| x25519-dalek     | 2       | X25519 Diffie-Hellman (hybrid mode)                           |
| hkdf             | 0.12    | HKDF-SHA256 key derivation (hybrid mode)                      |
| sha2             | 0.10    | SHA-256 (HKDF input)                                          |
| getrandom        | 0.4     | OS CSPRNG for nonces and key generation                       |
| zeroize          | 1       | Overwrite secret bytes on drop                                |
| argon2           | 0.5     | Argon2id KDF for passphrase-protected keys                    |
| pem              | 3       | PEM encoding/decoding for key files                           |
| sha3             | 0.12    | SHA3-256 (FIPS 202) for key fingerprints                      |
| clap             | 4       | CLI argument parsing                                          |
| clap_complete    | 4       | Shell completion script generation                            |
| thiserror        | 2       | Custom error type derivation                                  |
| rpassword        | 7       | Secure passphrase prompting                                   |

### pqfile-gui (shared GUI logic and WASM lib)

| Crate                    | Version | Purpose                                              |
|--------------------------|---------|------------------------------------------------------|
| eframe                   | 0.34    | egui app framework (native rlib + WASM cdylib)       |
| rfd                      | 0.17    | Native sync and WASM async file dialogs              |
| wasm-bindgen             | 0.2     | Rust/WASM bindings (WASM only)                       |
| wasm-bindgen-futures     | 0.4     | Async bridge for WASM (WASM only)                    |
| web-sys                  | 0.3     | Browser DOM APIs for file download (WASM only)       |
| js-sys                   | 0.3     | JavaScript types for WASM (WASM only)                |
| getrandom                | 0.4     | JS entropy source for WASM crypto (WASM only)        |
| console_error_panic_hook | 0.1     | Routes Rust panics to the browser console (WASM only)|

---

## Packaging

### Debian / Ubuntu

```
cargo install cargo-deb
cargo deb -p pqfile
```

Produces a `.deb` package installing the binary to `/usr/bin/pqfile`.

### Fedora / RHEL

```
cargo build --release -p pqfile
cp target/release/pqfile ~/rpmbuild/BUILD/
rpmbuild -bb pqfile/packaging/pqfile.spec
```

---

## Security considerations

- **Private keys must be kept confidential.** Anyone with `privkey.pem` can decrypt any file encrypted to the corresponding public key.
- **Public keys can be shared freely.**
- **Each encryption is independent.** A fresh KEM ciphertext, fresh ephemeral X25519 scalar (hybrid mode), and fresh nonce are generated per file. Nonce reuse under the same symmetric key is structurally impossible.
- **The entire file is authenticated.** For v2, the 1115-byte header is AEAD additional data so any header or payload modification fails decryption. For v3/v4, each 64 KiB chunk carries its own AEAD tag plus a position-binding counter so truncation, reordering, and payload swapping are all detected.
- **Secret material is zeroized on drop.** The decapsulation key seed, shared secrets, session keys, and passphrase-derived keys are wrapped in `Zeroizing<T>` from the `zeroize` crate. `x25519-dalek` and `ml-kem` are compiled with their `zeroize` features enabled.
- **Multi-recipient security.** In v4 format, the file payload is encrypted with a single random 32-byte session key. Each recipient's copy of that key is wrapped under their KEM shared secret using AES-256-GCM (zero nonce; safe because the KEM shared secret is fresh and unique per encapsulation). A recipient with a non-matching key cannot distinguish a file addressed to them from one addressed to others.
- **Hybrid mode security.** The combined session key is `HKDF-SHA256(X25519_ss || ML-KEM_ss, info="pqfile-hybrid-v1")`. Security holds if either X25519 or ML-KEM is unbroken, not both.
- **Signing keys are not passphrase-protected.** Protect `sign_privkey.pem` with filesystem permissions or disk encryption. Compromise of the signing key allows forged signatures but does not affect encryption key confidentiality.
- **The web GUI operates entirely in WebAssembly inside the browser.** No file data or key material is transmitted over the network.
- **Fingerprints are informational.** SHA3-256(pubkey)[0:8] gives 64 bits. Suitable for display and manual comparison; not a cryptographic commitment. Always verify keys through a trusted channel.
