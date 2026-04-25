# pqfile

A quantum-resistant file encryption tool with a command-line interface and a cross-platform GUI. It uses hybrid encryption combining ML-KEM-768 key encapsulation (NIST FIPS 203) with ChaCha20-Poly1305 authenticated symmetric encryption.

Encrypted files can only be decrypted by the holder of the private decapsulation key, and any tampering with an encrypted file is detected before decryption produces output.

---

## Background

Classical public-key cryptography algorithms such as RSA and ECDH are vulnerable to attacks from sufficiently large quantum computers. ML-KEM (Module-Lattice-based Key Encapsulation Mechanism), standardized by NIST as FIPS 203, is a post-quantum algorithm that is believed to be secure against both classical and quantum adversaries.

pqfile uses a hybrid approach:

1. **ML-KEM-768** encapsulates a fresh 32-byte shared secret. The encapsulation produces a ciphertext that only the private key holder can unwrap. This step replaces the role that RSA or ECDH would normally play.

2. **ChaCha20-Poly1305** uses that shared secret as a symmetric key to encrypt the actual file contents. ChaCha20 is a stream cipher and Poly1305 is a message authentication code. Together they provide authenticated encryption: decryption fails with an explicit error if the ciphertext has been modified.

Because the symmetric key is freshly generated for each file and encapsulated with ML-KEM, no classical asymmetric operation ever touches the file contents directly.

---

## Cryptographic standards

| Component           | Standard / Specification     |
|---------------------|------------------------------|
| Key encapsulation   | ML-KEM-768, NIST FIPS 203    |
| Symmetric cipher    | ChaCha20-Poly1305, RFC 8439  |
| Randomness          | OS CSPRNG via OsRng          |
| Key serialization   | Custom PEM labels            |

---

## Project structure

```
PQ-File-Encryption/
├── Cargo.toml              Workspace manifest
├── pqfile/                 CLI tool and crypto library
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs         CLI entry point (clap subcommands)
│   │   ├── lib.rs          Public library re-exports
│   │   ├── keygen.rs       Key pair generation and PEM serialization
│   │   ├── encrypt.rs      Hybrid encryption pipeline
│   │   ├── decrypt.rs      Hybrid decryption pipeline
│   │   ├── format.rs       .pqf binary file format
│   │   └── error.rs        PqfileError enum
│   ├── tests/
│   │   └── roundtrip.rs    End-to-end integration test
│   └── packaging/
│       ├── Cargo.deb.toml  Debian package metadata
│       └── pqfile.spec     RPM spec for Fedora/RHEL
├── pqfile-gui/             Shared GUI logic + WASM web app
│   ├── Cargo.toml          crate-type = ["cdylib", "rlib"]
│   ├── index.html          Canvas page for trunk/WASM builds
│   └── src/
│       └── lib.rs          App logic and WASM entry point
└── pqfile-desktop/         Native desktop binary
    ├── Cargo.toml          Depends on pqfile-gui and eframe
    └── src/
        └── main.rs         Native entry point (12 lines)
```

The `pqfile` crate is both a library (exposing `encrypt_bytes`, `decrypt_bytes`, `keygen_bytes`) and a CLI binary. The `pqfile-gui` crate is a lib-only crate: it compiles to a `cdylib` for WASM deployment and an `rlib` for the native binary to link against. The `pqfile-desktop` crate is the native binary; it contains only the entry point and links against `pqfile-gui`. This separation follows the official eframe template pattern and avoids build artifact conflicts between the lib and binary targets.

---

## Building from source

Requires Rust 1.74 or later. All commands are run from the repository root unless noted.

```
git clone <repo>
cd PQ-File-Encryption
```

### CLI only

```
cargo build --release -p pqfile
```

Binary is at `target/release/pqfile`. To install to your Cargo bin directory:

```
cargo install --path pqfile
```

### Native GUI

```
cargo build --release --bin pqfile-desktop
```

Binary is at `target/release/pqfile-desktop`. Run it directly:

```
./target/release/pqfile-desktop
```

### Web GUI

Install [trunk](https://trunkrs.dev), the WASM bundler for Rust:

```
cargo install trunk
```

Add the WASM target if you do not already have it:

```
rustup target add wasm32-unknown-unknown
```

Build the web app from inside the `pqfile-gui` directory:

```
cd pqfile-gui
trunk build --release
```

The output is written to `pqfile-gui/dist/`. Serve that folder with any static file host.

---

## CLI usage

### Generate a key pair

```
pqfile keygen --out /path/to/keys/
```

Writes `pubkey.pem` and `privkey.pem` to the given directory. The directory must already exist. Share `pubkey.pem` with anyone who needs to send you encrypted files. Keep `privkey.pem` private.

### Encrypt a file

```
pqfile encrypt -r /path/to/keys/pubkey.pem secret.txt
```

Produces `secret.txt.pqf` alongside the original file. The original is not removed. The output path is always the input path with `.pqf` appended.

### Decrypt a file

```
pqfile decrypt -k /path/to/keys/privkey.pem secret.txt.pqf
```

Produces `secret.txt` (the `.pqf` extension is stripped). If the file has been tampered with, the command exits with an authentication tag mismatch error and writes no output.

### Inspect a .pqf file

```
pqfile inspect secret.txt.pqf
```

Parses and prints the header fields without decrypting the payload. Useful for verifying the format, checking the nonce, or confirming the original file size.

```
Magic:              PQFL
Version:            0x03
KEM variant:        768
Header size:        1110 bytes
Nonce:              a3f09c12de87b6
Original file size: 2048 bytes
```

---

## GUI usage

The GUI has four tabs and works identically on native and web, except that the web version downloads output files to your browser downloads folder instead of writing them to disk.

### Keygen tab

- **Native:** Click Browse to choose an output directory, then click Generate Key Pair. `pubkey.pem` and `privkey.pem` are written to that directory.
- **Web:** Click Generate Key Pair. The browser downloads `pubkey.pem` and `privkey.pem` immediately.

### Encrypt tab

1. Click Browse next to **Public key (.pem)** and select the recipient's `pubkey.pem`.
2. Click Browse next to **Input file** and select the file to encrypt.
3. Click Encrypt.
   - Native: `{filename}.pqf` is saved alongside the input file.
   - Web: `{filename}.pqf` is downloaded.

### Decrypt tab

1. Click Browse next to **Private key (.pem)** and select your `privkey.pem`.
2. Click Browse next to **Input file (.pqf)** and select the encrypted file.
3. Click Decrypt.
   - Native: the decrypted file is saved alongside the `.pqf` file (extension stripped).
   - Web: the decrypted file is downloaded.
   - If the file has been tampered with, an authentication failure error is shown and no output is produced.

### Inspect tab

1. Click Browse and select a `.pqf` file.
2. Click Inspect.

The header fields (magic, version, KEM variant, nonce, original size) are displayed without decrypting the payload.

---

## Running the web GUI locally

### Development server (recommended)

`trunk serve` builds the app and serves it with live reload on every file change:

```
cd pqfile-gui
trunk serve
```

Open `http://localhost:8080` in your browser.

### Serving a pre-built dist/

If you have already run `trunk build --release`, you can serve the output directly:

```
# Python (no install required)
cd pqfile-gui/dist
python -m http.server 8080
```

> The server must send the `application/wasm` MIME type for `.wasm` files or the browser will refuse to load the app. Python's `http.server` and `trunk serve` both handle this correctly.

---

## Deploying the web GUI

After running `trunk build --release` inside `pqfile-gui/`, the `dist/` folder contains everything needed for a static deployment.

### GitHub Pages

```
# From pqfile-gui/
trunk build --release --public-url /your-repo-name/
```

Push the `dist/` folder to the `gh-pages` branch, or configure Pages to serve from it.

### Cloudflare Pages / Netlify / Vercel

Point the build output directory to `pqfile-gui/dist/`. Set the build command to:

```
cargo install trunk && rustup target add wasm32-unknown-unknown && trunk build --release
```

### Nginx or Apache

Copy the contents of `dist/` to your web root:

```
cp -r pqfile-gui/dist/* /var/www/html/
```

> All cryptographic operations run entirely in the browser via WebAssembly. No file data is sent to any server.

---

## The .pqf file format

Every encrypted file begins with a fixed-length header followed by the encrypted payload.

```
Offset   Length    Field
------   ------    -----
0        4         Magic bytes: ASCII "PQFL"
4        1         Version: 0x03
5        2         KEM variant: 768 as little-endian u16
7        1088      ML-KEM-768 KEM ciphertext (encapsulated shared secret)
1095     7         STREAM nonce (StreamBE32 base nonce for ChaCha20-Poly1305)
1102     8         Original plaintext size as little-endian u64
1110     chunks    STREAM-AEAD payload: 64 KB chunks, each chunk+16-byte tag
```

The KEM ciphertext field is 1088 bytes because that is the exact ciphertext size specified by FIPS 203 for the ML-KEM-768 parameter set (k=3, du=10, dv=4).

The payload uses the STREAM AEAD construction (`aead::stream::StreamBE32`) over 64 KB chunks. Each chunk is encrypted independently using a per-block nonce derived from the 8-byte stream nonce and a 4-byte big-endian counter, then authenticated with a 16-byte Poly1305 tag. The original file size field allows pre-allocation; the authentication tags provide integrity and prevent truncation or reordering attacks.

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
<base64-encoded decapsulation key, 2400 bytes raw>
-----END ML-KEM-768 PRIVATE KEY-----
```

Raw sizes from FIPS 203 Section 7:

| Key type          | Raw size (bytes) |
|-------------------|-----------------|
| Encapsulation key | 1184            |
| Decapsulation key | 2400            |
| KEM ciphertext    | 1088            |
| Shared secret     | 32              |

---

## Testing

Run the full test suite from the repository root:

```
cargo test
```

The integration test in `pqfile/tests/roundtrip.rs` performs a complete end-to-end cycle:

1. Creates a temporary directory.
2. Writes a known byte string to a file.
3. Runs `pqfile keygen` to generate a fresh key pair.
4. Runs `pqfile encrypt` to produce a `.pqf` file.
5. Runs `pqfile decrypt` to recover the plaintext.
6. Asserts that the recovered bytes are identical to the original.

---

## Error handling

All errors are reported to stderr with a descriptive message. The process exits with code 1 on any error. The GUI displays errors in red text inline.

| Error variant       | Meaning                                               |
|---------------------|-------------------------------------------------------|
| Io                  | Any file system or I/O failure                        |
| InvalidMagic        | File does not start with the bytes "PQFL"             |
| UnsupportedVersion  | Version byte is not 0x03                              |
| UnsupportedKem      | KEM variant field is not 768                          |
| KemEncapsulation    | ML-KEM encapsulation failed                           |
| KemDecapsulation    | ML-KEM decapsulation failed                           |
| DecryptionFailure   | ChaCha20-Poly1305 authentication tag mismatch         |
| InvalidPem          | PEM file could not be parsed                          |
| InvalidKeyLength    | Decoded key bytes are the wrong length                |

---

## Dependencies

### pqfile (CLI and library)

| Crate            | Version | Purpose                                          |
|------------------|---------|--------------------------------------------------|
| ml-kem           | 0.2     | ML-KEM-768 key encapsulation (FIPS 203)          |
| chacha20poly1305 | 0.10    | ChaCha20-Poly1305 authenticated encryption       |
| aead             | 0.5     | STREAM AEAD construction (stream feature)        |
| sha2             | 0.10    | SHA-256 for public key fingerprints              |
| rand             | 0.8     | OsRng and RngCore for secure randomness          |
| rand_core        | 0.6     | CryptoRngCore trait used by ml-kem               |
| zeroize          | 1       | Overwrite secret bytes in memory on drop         |
| pem              | 3       | PEM encoding and decoding for key files          |
| clap             | 4       | Command-line argument parsing with derive macros |
| thiserror        | 1       | Ergonomic custom error type derivation           |

### pqfile-gui (shared GUI logic and WASM lib)

| Crate                | Version | Purpose                                        |
|----------------------|---------|------------------------------------------------|
| eframe               | 0.29    | egui app framework (native via rlib, WASM via cdylib) |
| rfd                  | 0.14    | Native sync and WASM async file dialogs        |
| ureq                 | 2       | HTTP client for update checks (native only)    |
| wasm-bindgen         | 0.2     | Rust/WASM bindings (WASM only)                 |
| wasm-bindgen-futures | 0.4     | Async bridge for WASM (WASM only)              |
| web-sys              | 0.3     | Browser DOM APIs for file download (WASM only) |
| js-sys               | 0.3     | JavaScript types for WASM (WASM only)          |
| getrandom            | 0.2     | JS entropy source for WASM crypto (WASM only)  |

### pqfile-desktop (native binary)

| Crate      | Version | Purpose                                  |
|------------|---------|------------------------------------------|
| pqfile-gui | local   | Shared GUI app logic (linked as rlib)    |
| eframe     | 0.29    | Native window creation and event loop    |

---

## Packaging

### Debian / Ubuntu

```
cargo install cargo-deb
cargo deb -p pqfile
```

Produces a `.deb` package installing the binary to `/usr/bin/pqfile`.

### Fedora / RHEL

The RPM spec file is at `pqfile/packaging/pqfile.spec`. To build an RPM:

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
- The STREAM AEAD construction authenticates both the payload chunks and all header fields. The serialized header is passed as additional data (AAD) to every STREAM chunk call. Any modification to any byte of the file — header or payload — will cause authentication to fail before any plaintext is produced.
- Secret material (the decapsulation key bytes and the shared secret) is overwritten with zeros when the relevant variables go out of scope using the `zeroize` crate.
- The web GUI performs all cryptographic operations in WebAssembly inside the browser. No file data or key material is transmitted over the network.
