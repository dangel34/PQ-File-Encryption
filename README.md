# pqfile

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=dangel34_PQ-File-Encryption&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dangel34_PQ-File-Encryption)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=dangel34_PQ-File-Encryption&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=dangel34_PQ-File-Encryption)

A quantum-resistant file encryption tool with a command-line interface and a cross-platform GUI. It uses hybrid encryption combining ML-KEM-768 key encapsulation (NIST FIPS 203) with ChaCha20-Poly1305 authenticated symmetric encryption.

Encrypted files can only be decrypted by the holder of the private decapsulation key, and any tampering with an encrypted file is detected before decryption produces output.

**[QUICKSTART.md](QUICKSTART.md)** - build, install, common CLI commands, GUI overview, deploying.

---

## Background

Classical public-key algorithms such as RSA and ECDH are vulnerable to attacks from sufficiently large quantum computers. ML-KEM (Module-Lattice-based Key Encapsulation Mechanism), standardized by NIST as FIPS 203, is a post-quantum algorithm believed to be secure against both classical and quantum adversaries.

pqfile uses a hybrid approach:

1. **ML-KEM-768** encapsulates a fresh 32-byte shared secret. The encapsulation produces a ciphertext that only the private key holder can unwrap, replacing the role that RSA or ECDH would normally play.

2. **ChaCha20-Poly1305** uses that shared secret as a symmetric key to encrypt the actual file contents. Together they provide authenticated encryption: decryption fails with an explicit error if the ciphertext has been modified.

Because the symmetric key is freshly generated for each file and encapsulated with ML-KEM, no classical asymmetric operation ever touches the file contents directly.

---

## Cryptographic standards

| Component           | Standard / Specification     |
|---------------------|------------------------------|
| Key encapsulation   | ML-KEM-768, NIST FIPS 203    |
| Symmetric cipher    | ChaCha20-Poly1305, RFC 8439  |
| Randomness          | OS CSPRNG via OsRng          |
| Key derivation      | Argon2id (passphrase-protected keys) |
| Key wrapping        | AES-256-GCM (passphrase-protected keys) |
| Key serialization   | Custom PEM labels            |

---

## Project structure

```
PQ-File-Encryption/
├── Cargo.toml              Workspace manifest
├── Formula/
│   └── pqfile.rb           Homebrew formula (copy to homebrew-pqfile tap)
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
│   │   ├── encrypt.rs      Hybrid encryption pipeline
│   │   ├── decrypt.rs      Hybrid decryption pipeline
│   │   ├── format.rs       .pqf binary file format
│   │   ├── passphrase.rs   Argon2id wrapping for passphrase-protected keys
│   │   └── error.rs        PqfileError enum
│   ├── tests/
│   │   └── roundtrip.rs    End-to-end CLI integration tests (12 tests)
│   └── packaging/
│       ├── Cargo.deb.toml  Debian package metadata
│       └── pqfile.spec     RPM spec for Fedora/RHEL
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
│           ├── keygen.rs, encrypt.rs, decrypt.rs, inspect.rs, settings.rs
└── pqfile-desktop/         Native desktop binary
    └── src/
        └── main.rs         Native entry point (~18 lines)
```

The `pqfile` crate is both a library (exposing `encrypt_bytes`, `decrypt_bytes`, `keygen_bytes`) and a CLI binary. The `pqfile-gui` crate is a lib-only crate: it compiles to a `cdylib` for WASM deployment and an `rlib` for the native binary. The `pqfile-desktop` crate contains only the entry point and links against `pqfile-gui`. This follows the official eframe template pattern and avoids build artifact conflicts between lib and binary targets.

---

## The .pqf file format

Every encrypted file begins with a fixed-length header followed by the encrypted payload.

```
Offset   Length    Field
------   ------    -----
0        4         Magic bytes: ASCII "PQFL"
4        1         Version: 0x02
5        2         KEM variant: 768 as little-endian u16
7        1088      ML-KEM-768 KEM ciphertext (encapsulated shared secret)
1095     12        ChaCha20-Poly1305 nonce
1107     8         Original plaintext size as little-endian u64
1115     N+16      Encrypted payload (N bytes ciphertext + 16-byte Poly1305 tag)
```

The KEM ciphertext field is 1088 bytes, the exact ciphertext size specified by FIPS 203 for ML-KEM-768 (k=3, du=10, dv=4).

The entire 1115-byte header (bytes 0-1114) is passed as AEAD additional data (AAD) during encryption. The Poly1305 tag therefore covers both the ciphertext payload and the header, so any modification to any header field is detected and causes decryption to fail. The original file size field is informational; it is displayed by `pqfile inspect` but not used for truncation.

---

## PEM key format

Keys are stored in standard PEM framing with custom type labels:

```
-----BEGIN ML-KEM-768 PUBLIC KEY-----
<base64-encoded encapsulation key, 1184 bytes raw>
-----END ML-KEM-768 PUBLIC KEY-----
```

```
-----BEGIN ML-KEM-768 PRIVATE KEY-----
<base64-encoded decapsulation key seed, 64 bytes raw>
-----END ML-KEM-768 PRIVATE KEY-----
```

When generated with `--passphrase`, the private key uses an encrypted body:

```
-----BEGIN ML-KEM-768 ENCRYPTED PRIVATE KEY-----
<base64-encoded: 16-byte Argon2id salt || 12-byte AES-GCM nonce || 80-byte AES-256-GCM ciphertext>
-----END ML-KEM-768 ENCRYPTED PRIVATE KEY-----
```

The 80-byte ciphertext is the 64-byte seed encrypted under a 256-bit key derived from the passphrase via Argon2id (m=64 MiB, t=3, p=1), plus the 16-byte AES-GCM authentication tag.

The private key stores the 64-byte seed (§3.3 of FIPS 203) rather than the 2400-byte expanded form. The decapsulation key is re-derived on load, which keeps key files small and avoids storing redundant data.

| Key type               | Raw size (bytes) |
|------------------------|-----------------|
| Encapsulation key      | 1184            |
| Decapsulation key seed | 64              |
| KEM ciphertext         | 1088            |
| Shared secret          | 32              |

---

## Error handling

All errors are reported to stderr with a descriptive message. The process exits with code 1 on any error. The GUI displays errors in red text inline.

| Error variant       | Meaning                                                              |
|---------------------|----------------------------------------------------------------------|
| `Io`                | Any file system or I/O failure                                       |
| `InvalidMagic`      | File does not start with the bytes "PQFL"                            |
| `UnsupportedVersion`| Version byte is not 0x02                                            |
| `UnsupportedKem`    | KEM variant field is not 768                                         |
| `EncryptionFailure` | ChaCha20-Poly1305 encryption failed (e.g. nonce generation error)    |
| `DecryptionFailure` | ChaCha20-Poly1305 authentication tag mismatch                        |
| `InvalidPem`        | PEM file could not be parsed                                         |
| `InvalidKeyLength`  | Decoded key bytes are the wrong length                               |
| `OutputExists`      | Key file already exists and `--force` was not passed                 |
| `WrongPassphrase`      | Passphrase decryption of private key seed failed                  |
| `PassphraseRequired`   | Encrypted private key loaded but no passphrase supplied           |
| `PassphraseMismatch`   | New passphrase and confirmation do not match (keygen `--passphrase`) |

---

## Testing

```
cargo test --workspace
```

84 tests across all crates. The integration tests in `pqfile/tests/roundtrip.rs` cover the CLI binary end-to-end:

| Test | What it verifies |
|------|-----------------|
| `roundtrip` | keygen → encrypt → decrypt → byte-for-byte match (also exercises stdin/stdout path via file args) |
| `roundtrip_custom_output_paths` | `-o` flag on both encrypt and decrypt |
| `keygen_refuses_overwrite_without_force` | second keygen exits non-zero without `--force` |
| `keygen_force_overwrites_existing_keys` | `--force` succeeds on second keygen |
| `inspect_shows_header_fields` | `pqfile inspect` prints correct magic, version, KEM variant, size |
| `inspect_fails_on_invalid_file` | inspect exits non-zero on a file with invalid magic bytes |
| `completions_*` (6 tests) | shell completion scripts generate without error for all supported shells |

---

## Dependencies

### pqfile (CLI and library)

| Crate            | Version | Purpose                                          |
|------------------|---------|--------------------------------------------------|
| ml-kem           | 0.3     | ML-KEM-768 key encapsulation (FIPS 203)          |
| chacha20poly1305 | 0.10    | ChaCha20-Poly1305 authenticated encryption       |
| getrandom        | 0.4     | OS CSPRNG for nonce generation                   |
| zeroize          | 1       | Overwrite secret bytes in memory on drop         |
| pem              | 3       | PEM encoding and decoding for key files          |
| clap             | 4       | Command-line argument parsing with derive macros |
| thiserror        | 2       | Ergonomic custom error type derivation           |
| sha3             | 0.12    | SHA3-256 (FIPS 202) for public key fingerprints  |
| argon2           | 0.5     | Argon2id KDF for passphrase-protected keys       |
| aes-gcm          | 0.10    | AES-256-GCM wrapping of the private key seed     |
| rpassword        | 7       | Secure passphrase prompting in the CLI           |

### pqfile-gui (shared GUI logic and WASM lib)

| Crate                    | Version | Purpose                                        |
|--------------------------|---------|------------------------------------------------|
| eframe                   | 0.34    | egui app framework (native via rlib, WASM via cdylib) |
| rfd                      | 0.17    | Native sync and WASM async file dialogs        |
| wasm-bindgen             | 0.2     | Rust/WASM bindings (WASM only)                 |
| wasm-bindgen-futures     | 0.4     | Async bridge for WASM (WASM only)              |
| web-sys                  | 0.3     | Browser DOM APIs for file download (WASM only) |
| js-sys                   | 0.3     | JavaScript types for WASM (WASM only)          |
| getrandom                | 0.4     | JS entropy source for WASM crypto (WASM only)  |
| console_error_panic_hook | 0.1     | Routes Rust panics to the browser console (WASM only) |

### pqfile-desktop (native binary)

| Crate      | Version | Purpose                               |
|------------|---------|---------------------------------------|
| pqfile-gui | local   | Shared GUI app logic (linked as rlib) |
| eframe     | 0.34    | Native window creation and event loop |

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

- The private key (`privkey.pem`) must be kept confidential. Anyone who obtains it can decrypt any file encrypted to the corresponding public key.
- The public key (`pubkey.pem`) can be shared freely.
- Each encryption operation generates a fresh KEM ciphertext and a fresh random nonce. Reuse of a nonce under the same key would break ChaCha20-Poly1305 confidentiality, but this cannot happen here because the symmetric key itself is freshly derived per file.
- The entire `.pqf` file is authenticated. The 1115-byte header is passed as AEAD additional data (AAD), so the Poly1305 tag covers both the header and the ciphertext. Any modification to any byte (header or payload) is detected before decryption produces output.
- Secret material (the decapsulation key bytes and the shared secret) is overwritten with zeros when the relevant variables go out of scope, using the `zeroize` crate.
- The web GUI performs all cryptographic operations in WebAssembly inside the browser. No file data or key material is transmitted over the network.
