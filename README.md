# pqfile

A command-line tool for quantum-resistant file encryption and decryption. It uses hybrid encryption combining ML-KEM-768 key encapsulation (NIST FIPS 203) with ChaCha20-Poly1305 authenticated symmetric encryption.

The tool is designed so that encrypted files can only be decrypted by the holder of the private decapsulation key, and so that any tampering with an encrypted file is detected before decryption produces output.

---

## Background

Classical public-key cryptography algorithms such as RSA and ECDH are vulnerable to attacks from sufficiently large quantum computers. ML-KEM (Module-Lattice-based Key Encapsulation Mechanism), standardized by NIST as FIPS 203, is a post-quantum algorithm that is believed to be secure against both classical and quantum adversaries.

pqfile uses a hybrid approach:

1. **ML-KEM-768** is used to encapsulate a fresh 32-byte shared secret. The encapsulation produces a ciphertext that only the private key holder can unwrap. This step replaces the role that RSA or ECDH would normally play.

2. **ChaCha20-Poly1305** uses that shared secret as a symmetric key to encrypt the actual file contents. ChaCha20 is a stream cipher and Poly1305 is a message authentication code. Together they provide authenticated encryption: decryption fails with an explicit error if the ciphertext has been modified.

Because the symmetric key is freshly generated for each file and encapsulated with ML-KEM, no classical asymmetric operation ever touches the file contents directly.

---

## Cryptographic standards

| Component           | Standard / Specification          |
|---------------------|-----------------------------------|
| Key encapsulation   | ML-KEM-768, NIST FIPS 203         |
| Symmetric cipher    | ChaCha20-Poly1305, RFC 8439       |
| Randomness          | OS CSPRNG via OsRng               |
| Key serialization   | Custom PEM labels (see below)     |

---

## Project structure

```
pqfile/
+-- Cargo.toml          Package manifest and packaging metadata
+-- src/
|   +-- main.rs         CLI entry point; defines subcommands with clap
|   +-- keygen.rs       Key pair generation and PEM serialization
|   +-- encrypt.rs      Hybrid encryption pipeline
|   +-- decrypt.rs      Hybrid decryption pipeline
|   +-- format.rs       .pqf binary file format definition
|   +-- error.rs        PqfileError enum
+-- tests/
|   +-- roundtrip.rs    Integration test: keygen, encrypt, decrypt, verify
+-- packaging/
    +-- Cargo.deb.toml  Debian package metadata reference
    +-- pqfile.spec     RPM spec file for Fedora/RHEL
```

### src/main.rs

Parses command-line arguments using clap v4 with the derive macro. Defines four subcommands and dispatches to the corresponding module function. Errors are printed to stderr and the process exits with code 1.

### src/format.rs

Defines the `.pqf` binary file format and provides `PqfHeader::write` and `PqfHeader::read` for structured I/O. All multi-byte integers are little-endian.

### src/keygen.rs

Calls `MlKem768::generate` with the OS CSPRNG, serializes both keys with the `pem` crate using custom PEM labels, and writes them to disk. The private key byte buffer is wrapped in `Zeroizing<Vec<u8>>` so it is overwritten with zeros when it goes out of scope.

### src/encrypt.rs

Reads the recipient public key from PEM, reconstructs the `EncapsulationKey` type, calls `encapsulate` to obtain a KEM ciphertext and a 32-byte shared secret, generates a fresh random 12-byte nonce, encrypts the file with ChaCha20-Poly1305 (which appends a 16-byte authentication tag), and writes the `.pqf` output file. The shared secret is copied into a `Zeroizing<[u8; 32]>` for its lifetime.

### src/decrypt.rs

Reads the private key from PEM, reconstructs the `DecapsulationKey` type, parses the `.pqf` header, calls `decapsulate` with the stored KEM ciphertext to recover the shared secret, and calls `ChaCha20Poly1305::decrypt`. If the authentication tag does not match, decryption returns `PqfileError::DecryptionFailure` and no output file is written.

### src/error.rs

Defines `PqfileError` using the `thiserror` crate. All library errors that cross a module boundary are converted into this type.

---

## The .pqf file format

Every encrypted file begins with a fixed-length header followed by the encrypted payload.

```
Offset   Length    Field
------   ------    -----
0        4         Magic bytes: ASCII "PQFL"
4        1         Version: 0x01
5        2         KEM variant: 768 as little-endian u16
7        1088      ML-KEM-768 KEM ciphertext (encapsulated shared secret)
1095     12        ChaCha20-Poly1305 nonce
1107     8         Original plaintext size as little-endian u64
1115     N+16      Encrypted payload (N bytes ciphertext + 16-byte Poly1305 tag)
```

The KEM ciphertext field is 1088 bytes because that is the exact ciphertext size specified by FIPS 203 for the ML-KEM-768 parameter set (k=3, du=10, dv=4).

The Poly1305 tag is appended directly to the ciphertext by the `chacha20poly1305` crate. The original file size field allows a reader to verify or pre-allocate before decryption, though it is not used for truncation since the authentication tag provides integrity.

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

The raw sizes come from FIPS 203 Section 7:

| Key type          | Raw size (bytes) |
|-------------------|-----------------|
| Encapsulation key | 1184            |
| Decapsulation key | 2400            |
| KEM ciphertext    | 1088            |
| Shared secret     | 32              |

---

## Installation

Requires Rust 1.74 or later.

```
git clone <repo>
cd pqfile
cargo build --release
# binary is at target/release/pqfile
```

To install to your local Cargo bin directory:

```
cargo install --path .
```

---

## Usage

### Generate a key pair

```
pqfile keygen --out /path/to/keys/
```

Writes `pubkey.pem` and `privkey.pem` to the given directory. The directory must already exist. Anyone who should be able to send you encrypted files needs access to `pubkey.pem`. Keep `privkey.pem` private.

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

Example output:

```
Magic:              PQFL
Version:            0x01
KEM variant:        768
Nonce:              a3f09c12de87b64c01e5a920
Original file size: 2048 bytes
```

---

## Error handling

All errors are reported to stderr with a descriptive message. The process exits with code 1 on any error. The following error conditions are defined:

| Error variant       | Meaning                                               |
|---------------------|-------------------------------------------------------|
| Io                  | Any file system or I/O failure                        |
| InvalidMagic        | File does not start with the bytes "PQFL"             |
| UnsupportedVersion  | Version byte is not 0x01                              |
| UnsupportedKem      | KEM variant field is not 768                          |
| KemEncapsulation    | ML-KEM encapsulation failed                           |
| KemDecapsulation    | ML-KEM decapsulation failed                           |
| DecryptionFailure   | ChaCha20-Poly1305 authentication tag mismatch         |
| InvalidPem          | PEM file could not be parsed                          |
| InvalidKeyLength    | Decoded key bytes are the wrong length                |

---

## Dependencies

| Crate              | Version | Purpose                                         |
|--------------------|---------|-------------------------------------------------|
| ml-kem             | 0.2     | ML-KEM-768 key encapsulation (FIPS 203)         |
| chacha20poly1305   | 0.10    | ChaCha20-Poly1305 authenticated encryption      |
| rand               | 0.8     | OsRng and RngCore for secure randomness         |
| rand_core          | 0.6     | CryptoRngCore trait used by ml-kem              |
| zeroize            | 1       | Overwrite secret bytes in memory on drop        |
| pem                | 3       | PEM encoding and decoding for key files         |
| clap               | 4       | Command-line argument parsing with derive macros|
| thiserror          | 1       | Ergonomic custom error type derivation          |

Development dependency: `tempfile` (3) for temporary directories in integration tests.

---

## Testing

```
cargo test
```

The integration test in `tests/roundtrip.rs` performs a complete end-to-end cycle:

1. Creates a temporary directory.
2. Writes a known byte string to a file.
3. Runs `pqfile keygen` to generate a fresh key pair.
4. Runs `pqfile encrypt` to produce a `.pqf` file.
5. Runs `pqfile decrypt` to recover the plaintext.
6. Asserts that the recovered bytes are identical to the original.

The test uses `env!("CARGO_BIN_EXE_pqfile")` to locate the compiled binary, so Cargo builds it automatically before running the test suite.

---

## Packaging

### Debian / Ubuntu

The `[package.metadata.deb]` section in `Cargo.toml` is read by `cargo-deb`:

```
cargo install cargo-deb
cargo deb
```

Produces a `.deb` package installing the binary to `/usr/bin/pqfile`.

### Fedora / RHEL

The RPM spec file is at `packaging/pqfile.spec`. To build an RPM:

```
cargo build --release
cp target/release/pqfile ~/rpmbuild/BUILD/
rpmbuild -bb packaging/pqfile.spec
```

---

## Security considerations

- The private key (`privkey.pem`) must be kept confidential. Anyone who obtains it can decrypt any file encrypted to the corresponding public key.
- The public key (`pubkey.pem`) can be shared freely.
- Each encryption operation generates a fresh KEM ciphertext and a fresh random nonce. Reuse of a nonce under the same key would break ChaCha20-Poly1305 confidentiality, but this cannot happen here because the symmetric key itself is freshly derived per file.
- The Poly1305 authentication tag guarantees that any modification to the ciphertext or header payload will be detected. The header fields before the payload (magic, version, KEM variant, KEM ciphertext, nonce, size) are not covered by the authentication tag; they are structural and validated by the format parser before decryption begins.
- Secret material (the decapsulation key bytes in memory, and the shared secret) is overwritten with zeros when the relevant variables go out of scope using the `zeroize` crate.
