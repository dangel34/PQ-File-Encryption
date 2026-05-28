# pqfile Format Specification

This document is the authoritative byte-level description of all `.pqf` file format versions (v2 through v7). All multi-byte integers are little-endian unless stated otherwise.

---

## 1. Constants

| Symbol | Value | Meaning |
|--------|-------|---------|
| MAGIC | `50 51 46 4C` (`PQFL`) | File magic (4 bytes) |
| VERSION_V2 | `0x02` | Whole-file AEAD |
| VERSION_V3 | `0x03` | 64 KiB chunked STREAM |
| VERSION_V4 | `0x04` | Multi-recipient |
| VERSION_V5 | `0x05` | Chunked STREAM, configurable chunk size |
| VERSION_V6 | `0x06` | Compress-then-encrypt |
| VERSION_V7 | `0x07` | Anonymous multi-recipient |
| CHUNK_SIZE | 65536 | Default chunk size (bytes) |
| BASE_NONCE_LEN | 8 | Random base-nonce bytes stored in header |
| NONCE_LEN | 12 | Full per-chunk nonce length (base + counter) |
| WRAPPED_KEY_LEN | 48 | AES-256-GCM wrapped session key (32-byte key + 16-byte tag) |
| PADDED_CT_LEN | 1568 | v7 per-slot ciphertext slot width (= ML-KEM-1024 CT length) |

---

## 2. KEM Variants

| Value (u16 LE) | Algorithm | Public key (EK) | Private seed | KEM CT |
|----------------|-----------|-----------------|--------------|--------|
| `0x0200` (512) | ML-KEM-512 (FIPS 203) | 800 bytes | 64 bytes | 768 bytes |
| `0x0300` (768) | ML-KEM-768 (FIPS 203) | 1184 bytes | 64 bytes | 1088 bytes |
| `0x0400` (1024) | ML-KEM-1024 (FIPS 203) | 1568 bytes | 64 bytes | 1568 bytes |
| `0x0103` (0x0301) | Hybrid X25519 + ML-KEM-768 | 1216 bytes (32 + 1184) | 96 bytes (32 + 64) | 1120 bytes (32 + 1088) |

The Hybrid variant stores an X25519 ephemeral public key (32 bytes) concatenated with the ML-KEM-768 ciphertext (1088 bytes) as its KEM ciphertext. The shared secret is `HKDF-SHA256(X25519_ss || ML-KEM-768_ss, info = "pqfile-hybrid-v1")`.

---

## 3. Symmetric Cipher

All versions use **ChaCha20-Poly1305** (RFC 8439) for payload authentication and encryption. The 32-byte key is the KEM shared secret (or a session key derived from it for v4/v7).

For multi-recipient formats (v4, v7) the 32-byte session key K is wrapped per-recipient under **AES-256-GCM** using the per-recipient KEM shared secret as the wrapping key, with a 12-byte all-zero nonce. A fixed zero nonce is safe because the AES-256-GCM key is a fresh, single-use KEM shared secret that is never reused.

```
WRAPPED_KEY = AES-256-GCM(
    key    = KEM_shared_secret (32 bytes),
    nonce  = 00 00 00 00 00 00 00 00 00 00 00 00,
    plain  = session_key K (32 bytes),
    aad    = (empty)
)
// 32 + 16 = 48 bytes
```

---

## 4. STREAM Chunk Construction (v3, v4, v5, v6, v7)

The payload is split into chunks of at most `chunk_size` bytes (default 65536). Each chunk is authenticated independently. The last chunk is explicitly flagged to prevent truncation attacks.

### 4.1 Per-chunk nonce

The header stores a 12-byte `BASE_NONCE` field, but only the first 8 bytes are filled with cryptographically random data. The last 4 bytes are always zero in the serialized header. The per-chunk nonce is:

```
chunk_nonce(counter) = BASE_NONCE[0..8] || counter.to_be_bytes()
```

`counter` is a 32-bit unsigned integer starting at zero and incremented by one for each chunk.

### 4.2 Per-chunk AAD

```
chunk_aad(counter, is_last) =
    b"pqfile"        (6 bytes, ASCII)
    counter         (4 bytes, big-endian u32)
    is_last         (1 byte: 0x01 for final chunk, 0x00 otherwise)
// 11 bytes total
```

### 4.3 Chunk ciphertext

```
chunk_ciphertext = ChaCha20-Poly1305-encrypt(
    key   = session_key K,
    nonce = chunk_nonce(counter),
    aad   = chunk_aad(counter, is_last),
    plain = plaintext_chunk (up to chunk_size bytes)
)
// output = plaintext_chunk || 16-byte Poly1305 tag
```

For an empty file, one zero-byte chunk is emitted (just the 16-byte tag).

---

## 5. Version Layouts

### 5.1 v2 - Whole-file AEAD

```
Offset  Len   Field
0       4     MAGIC ("PQFL")
4       1     VERSION (0x02)
5       2     KEM_VARIANT (u16 LE)
7       var   KEM_CT (length = ct_len[KEM_VARIANT])
7+ct    12    NONCE (12 random bytes)
19+ct   8     ORIGINAL_SIZE (u64 LE, informational)
27+ct   var   CIPHERTEXT
```

`CIPHERTEXT` is the entire plaintext encrypted as a single ChaCha20-Poly1305 message:

```
ciphertext = ChaCha20-Poly1305-encrypt(
    key   = KEM_shared_secret,
    nonce = NONCE (12 bytes),
    aad   = header bytes (bytes 0 through 27+ct-1),
    plain = plaintext
)
```

Output length: plaintext_len + 16 bytes.

**Header sizes for v2 (bytes before CIPHERTEXT):**

| Variant | ct_len | Header size |
|---------|--------|-------------|
| ML-KEM-512 | 768 | 795 |
| ML-KEM-768 | 1088 | 1115 |
| ML-KEM-1024 | 1568 | 1595 |
| Hybrid 768 | 1120 | 1147 |

---

### 5.2 v3 - 64 KiB chunked STREAM

Same header layout as v2, but VERSION is `0x03` and the payload is STREAM chunks using the default 64 KiB chunk size.

```
Offset  Len   Field
0       4     MAGIC
4       1     VERSION (0x03)
5       2     KEM_VARIANT
7       var   KEM_CT
7+ct    12    BASE_NONCE (only first 8 bytes are random; bytes 8-11 are 0x00)
19+ct   8     ORIGINAL_SIZE
27+ct   var   STREAM chunks (see Section 4)
```

v3 is always emitted when `chunk_size == 65536`. The BASE_NONCE bytes 8-11 in the header are zeroes and are ignored at read time.

---

### 5.3 v5 - Configurable chunk size

Extends v3 with an explicit 4-byte chunk size field. Emitted only when `chunk_size != 65536`.

```
Offset  Len   Field
0       4     MAGIC
4       1     VERSION (0x05)
5       2     KEM_VARIANT
7       var   KEM_CT
7+ct    12    BASE_NONCE
19+ct   8     ORIGINAL_SIZE
27+ct   4     CHUNK_SIZE (u32 LE; must be in range 1..=268435456)
31+ct   var   STREAM chunks
```

---

### 5.4 v6 - Compress-then-encrypt

Extends v5 with a compression algorithm byte. The plaintext is compressed before being split into chunks.

```
Offset  Len   Field
0       4     MAGIC
4       1     VERSION (0x06)
5       2     KEM_VARIANT
7       var   KEM_CT
7+ct    12    BASE_NONCE
19+ct   8     ORIGINAL_SIZE (uncompressed plaintext size)
27+ct   4     CHUNK_SIZE
31+ct   1     COMPRESSION_ALGO (0x00=none, 0x01=zstd)
32+ct   var   STREAM chunks (of compressed data)
```

COMPRESSION_ALGO values:

| Value | Algorithm |
|-------|-----------|
| 0x00 | None (passthrough, same as v5) |
| 0x01 | zstd (RFC 8878) |

---

### 5.5 v4 - Multi-recipient

Uses a random 32-byte session key K. Each recipient slot contains a KEM ciphertext and a wrapped copy of K.

```
Offset  Len   Field
0       4     MAGIC
4       1     VERSION (0x04)
5       2     COUNT (u16 LE; number of recipient entries)
7       var   RECIPIENT ENTRIES (COUNT entries, variable size)
7+N*E   12    BASE_NONCE
19+N*E  8     ORIGINAL_SIZE
27+N*E  var   STREAM chunks (chunk_size = 65536; no chunk-size field)
```

Each recipient entry (variable width):

```
Len   Field
2     KEM_VARIANT (u16 LE)
var   KEM_CT (length = ct_len[KEM_VARIANT])
48    WRAPPED_KEY (AES-256-GCM wrapped session key K)
```

Entry size per variant:

| Variant | ct_len | Entry size |
|---------|--------|------------|
| ML-KEM-512 | 768 | 818 |
| ML-KEM-768 | 1088 | 1138 |
| ML-KEM-1024 | 1568 | 1618 |
| Hybrid 768 | 1120 | 1170 |

v4 always uses `chunk_size = 65536`. Configurable chunk size is not supported in v4.

Decoders MUST reject files with COUNT greater than 1000. The limit protects against crafted files that trigger large allocations before any I/O validation.

---

### 5.6 v7 - Anonymous multi-recipient

Identical to v4 except:
1. All KEM ciphertexts are zero-padded to a uniform PADDED_CT_LEN = 1568 bytes.
2. Recipient entries are written in a randomly shuffled order.

```
Offset  Len         Field
0       4           MAGIC
4       1           VERSION (0x07)
5       2           COUNT (u16 LE)
7       var         RECIPIENT ENTRIES (COUNT x 1618 bytes each)
7+N*E   12          BASE_NONCE
19+N*E  8           ORIGINAL_SIZE
27+N*E  var         STREAM chunks (chunk_size = 65536)
```

Each recipient entry (fixed 1618 bytes):

```
Len   Field
2     KEM_VARIANT (u16 LE; indicates which variant's CT occupies the real bytes)
1568  PADDED_CT (actual KEM CT zero-padded on the right to 1568 bytes)
48    WRAPPED_KEY
```

Decryptors read all 1568 bytes per slot, truncate to `ct_len[KEM_VARIANT]`, and try decapsulation. Entries that do not match the decryptor's key variant are skipped without error.

Decoders MUST reject files with COUNT greater than 1000 (same limit as v4).

---

## 6. Key File Formats (PEM)

Private and public keys are stored as PEM (RFC 7468) files. The PEM label determines the key type and protection status.

### 6.1 KEM keys

| PEM Label | Contents |
|-----------|----------|
| `ML-KEM-512 PUBLIC KEY` | 800-byte ML-KEM-512 encapsulation key |
| `ML-KEM-768 PUBLIC KEY` | 1184-byte ML-KEM-768 encapsulation key |
| `ML-KEM-1024 PUBLIC KEY` | 1568-byte ML-KEM-1024 encapsulation key |
| `X25519+ML-KEM-768 PUBLIC KEY` | 1216-byte hybrid public key (32 + 1184) |
| `ML-KEM-512 PRIVATE KEY` | 64-byte ML-KEM-512 decapsulation seed (plaintext) |
| `ML-KEM-768 PRIVATE KEY` | 64-byte ML-KEM-768 decapsulation seed (plaintext) |
| `ML-KEM-1024 PRIVATE KEY` | 64-byte ML-KEM-1024 decapsulation seed (plaintext) |
| `X25519+ML-KEM-768 PRIVATE KEY` | 96-byte hybrid seed: X25519 scalar (32) || ML-KEM-768 seed (64) |
| `ML-KEM-512 ENCRYPTED PRIVATE KEY` | 108-byte encrypted body (see Section 7) |
| `ML-KEM-768 ENCRYPTED PRIVATE KEY` | 108-byte encrypted body |
| `ML-KEM-1024 ENCRYPTED PRIVATE KEY` | 108-byte encrypted body |
| `X25519+ML-KEM-768 ENCRYPTED PRIVATE KEY` | 140-byte encrypted body (see Section 7) |

### 6.2 ML-DSA-65 signing keys

| PEM Label | Contents |
|-----------|----------|
| `ML-DSA-65 VERIFYING KEY` | 1952-byte verifying key |
| `ML-DSA-65 SIGNING KEY` | 32-byte signing seed (plaintext) |
| `ML-DSA-65 ENCRYPTED SIGNING KEY` | 76-byte encrypted body (see Section 7) |

### 6.3 Shamir key shares

| PEM Label | Contents |
|-----------|----------|
| `ML-KEM-512 KEY SHARE` | Shamir GF(256) share of a 64-byte ML-KEM-512 seed |
| `ML-KEM-768 KEY SHARE` | Shamir GF(256) share of a 64-byte ML-KEM-768 seed |
| `ML-KEM-1024 KEY SHARE` | Shamir GF(256) share of a 64-byte ML-KEM-1024 seed |
| `X25519+ML-KEM-768 KEY SHARE` | Shamir GF(256) share of a 96-byte hybrid seed |

Share body layout (inside each PEM block):

```
Offset  Len  Field
0       1    VERSION (0x01)
1       2    KEM_VARIANT (u16 big-endian)
3       1    THRESHOLD (minimum shares required)
4       1    TOTAL (total shares produced)
5       1    X (1-indexed share index)
6       8    PUBKEY_FP (first 8 bytes of SHA3-256 of the derived public key)
14      var  Y (GF(256) share bytes; length equals seed length for the variant)
```

---

## 7. Passphrase-Protected Private Key Format

All encrypted private key PEM bodies share the same layout, differing only in the plaintext seed length.

```
Offset  Len   Field
0       16    SALT (random, for Argon2id)
16      12    NONCE (random, for AES-256-GCM)
28      var   CIPHERTEXT (seed + 16-byte GCM tag)
```

| Key type | Seed length | Body length (total) |
|----------|-------------|---------------------|
| ML-KEM-512/768/1024 | 64 bytes | 108 bytes |
| Hybrid X25519+ML-KEM-768 | 96 bytes | 140 bytes |
| ML-DSA-65 signing | 32 bytes | 76 bytes |

KDF: **Argon2id** (RFC 9106), parameters m=65536 (64 MiB), t=3, p=1, output=32 bytes.

Encryption: **AES-256-GCM** with the 32-byte KDF output as key and a 12-byte random nonce. AAD is empty.

---

## 8. Signcrypt Layout

A signcrypted file is a standard v3 `.pqf` file whose plaintext payload is:

```
[ML-DSA-65 signature: 3309 bytes][original plaintext: N bytes]
```

The signature covers `SHA3-256(original_plaintext)`, not the raw bytes, enabling streaming. The signature is inside the AEAD ciphertext so it cannot be stripped or reordered.

`ORIGINAL_SIZE` in the header stores `3309 + N`.

---

## 9. Encrypted Archive Format (PQFA)

An encrypted archive is a standard v3 `.pqf` file. Its decrypted plaintext consists of two sections: a manifest header followed by all file data concatenated in manifest order.

### 9.1 Manifest header

```
Offset  Len  Field
0       4    PQFA_MAGIC ("PQFA")
4       1    PQFA_VERSION (0x01)
5       8    COUNT (u32 LE; number of entries; max 65536)
9       var  ENTRY METADATA (COUNT entries)
```

Each entry metadata record:

```
Len    Field
2      PATH_LEN (u16 LE; byte length of the path string; max 65535)
var    PATH (UTF-8, PATH_LEN bytes; no null terminator, no leading slash, no `..` components)
8      FILE_SIZE (u64 LE; byte length of this file's data)
8      MTIME_SECS (i64 LE; last-modified time as Unix seconds; 0 if unavailable)
4      MODE (u32 LE; Unix permission bits; 0 on Windows)
```

### 9.2 Data section

Immediately after the manifest, file data is written in the same order as the metadata entries:

```
FILE_SIZE[0] bytes  (data for entry 0)
FILE_SIZE[1] bytes  (data for entry 1)
...
FILE_SIZE[N-1] bytes  (data for entry N-1)
```

There is no per-file delimiter; the reader uses `FILE_SIZE` from the manifest to know exactly how many bytes to consume for each entry.

### 9.3 Path validation on extract

Decoders MUST reject archive entries whose path:
- is absolute (starts with `/` or a drive letter on Windows),
- contains a `..` path component, or
- contains null bytes.

Decoders MUST reject archives with COUNT greater than 65536.

---

## 10. Compliance Notes

- An implementation MUST accept v2 through v7 on read.
- An implementation MAY refuse to write any deprecated version.
- A decryptor for v4/v7 MUST iterate all recipient entries before returning `NoMatchingRecipient`; it MUST NOT short-circuit on a failed decapsulation for the correct variant.
- A v7 decryptor MUST treat entry order as meaningless and MUST NOT assume any mapping between position and identity.
- `ORIGINAL_SIZE` is informational. Decryptors MUST NOT pre-allocate `ORIGINAL_SIZE` bytes without bounds checking, as the field is attacker-controlled.
- Chunk counter overflow at `u32::MAX` is treated as an encryption error; files larger than approximately 256 TiB at the default 64 KiB chunk size are unsupported.
- Decoders MUST reject v5/v6 files where `CHUNK_SIZE` is 0 or greater than 268435456 (256 MiB). A crafted value of `u32::MAX` would cause a multi-gigabyte allocation before any data is read.
- Decoders MUST reject v4/v7 files where `COUNT` is greater than 1000. A crafted maximum value of 65535 would cause a large header allocation before any AEAD verification.
- `rekey` MUST NOT accept v2 files as input. v2 uses a single whole-file AEAD whose payload format is incompatible with the v4 STREAM chunk layout that rekey produces. A v2 file rekeyed to v4 format cannot be decrypted.
