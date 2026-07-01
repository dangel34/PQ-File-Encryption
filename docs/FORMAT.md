# pqfile Format Specification

This document is the authoritative byte-level description of all `.pqf` file format versions (v2 through v10). All multi-byte integers are little-endian unless stated otherwise.

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
| VERSION_V8 | `0x08` | Variant-blind anonymous multi-recipient |
| VERSION_V9 | `0x09` | Padded anonymous multi-recipient |
| VERSION_V10 | `0x0A` | Passphrase-only (no KEM) |
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

## 4. STREAM Chunk Construction (v3–v10)

The payload is split into chunks of at most `chunk_size` bytes (default 65536). Each chunk is authenticated independently. The last chunk is explicitly flagged to prevent truncation attacks. Applies to v3 through v10 (v10 always uses the default 65536 chunk size).

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

Decoders MUST reject files with COUNT greater than 256. The limit protects against crafted files that trigger large allocations before any I/O validation.

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

Decoders MUST reject files with COUNT greater than 256 (same limit as v4).

---

### 5.7 v8 - Variant-blind anonymous multi-recipient

Supersedes v7 for `--anonymous-recipients` in pqfile 4.0+. v7 files remain
readable; new anonymous files are always v8.

The key difference from v7: the per-slot `KEM_VARIANT` field is **removed entirely**.
Every slot is a uniform 1616 bytes. An observer learns only the recipient count;
no information about key types is exposed.

```
Offset  Len         Field
0       4           MAGIC
4       1           VERSION (0x08)
5       2           COUNT (u16 LE)
7       var         RECIPIENT ENTRIES (COUNT x 1616 bytes each)
7+N*E   12          BASE_NONCE
19+N*E  8           ORIGINAL_SIZE
27+N*E  var         STREAM chunks (chunk_size = 65536)
```

Each recipient entry (fixed 1616 bytes):

```
Len   Field
1568  PADDED_CT (actual KEM CT zero-padded on the right to 1568 bytes)
48    WRAPPED_KEY
```

Note: the `KEM_VARIANT` field present in v7 is absent in v8. The decryptor
determines which prefix of the padded CT to use based on its own private
key's variant (e.g. 1088 bytes for ML-KEM-768).

**Decryption algorithm:**

For each slot in the header:
1. Extract the first `ct_len[dk.variant()]` bytes from PADDED_CT as the
   candidate ciphertext.
2. Attempt ML-KEM decapsulation. ML-KEM always produces a shared secret
   value; on a wrong slot the resulting shared secret is pseudorandom
   (implicit rejection per FIPS 203).
3. Attempt AES-256-GCM unwrap of WRAPPED_KEY using the derived shared secret.
4. If the AEAD tag verifies: the session key is recovered and decryption
   proceeds. A false positive is computationally infeasible (probability
   approximately 1 over 2^128).
5. Otherwise: continue to the next slot.
6. If no slot matches: return `NoMatchingRecipient`.

Decoders MUST reject files with COUNT greater than 256 (same limit as v4/v7).

---

### 5.8 v9 - Padded anonymous multi-recipient

Supersedes v8 when `--pad-recipients` is used. The slot count is rounded up to the next power of two (1, 2, 4, 8, ...) by appending random dummy entries. An observer learns only the padded slot count, not the true recipient count.

```
Offset  Len         Field
0       4           MAGIC
4       1           VERSION (0x09)
5       2           COUNT (u16 LE; padded to next power of two ≥ actual recipient count)
7       var         RECIPIENT SLOTS (COUNT x 1616 bytes each)
7+N*E   12          BASE_NONCE
19+N*E  8           ORIGINAL_SIZE
27+N*E  var         STREAM chunks (chunk_size = 65536)
```

Each slot is identical to v8 (1568-byte padded CT + 48-byte wrapped key). Dummy slots contain random bytes in both fields.

**Decryption algorithm:** identical to v8; try every slot, skip AEAD failures silently, return `NoMatchingRecipient` only if all slots fail.

Decoders MUST reject files with COUNT greater than 256 (same limit as v4/v7/v8).

---

### 5.9 v10 - Passphrase-only

No KEM step. The 32-byte session key is derived from a passphrase via Argon2id. Argon2 parameters are stored in the header because the sender chose them; the recipient cannot assume fixed parameters.

```
Offset  Len   Field
0       4     MAGIC
4       1     VERSION (0x0A)
5       16    SALT (random, for Argon2id)
21      4     M_KIB (u32 LE; Argon2id memory cost in kibibytes)
25      4     T_COST (u32 LE; Argon2id time cost / iterations)
29      4     P_COST (u32 LE; Argon2id parallelism lanes)
33      12    BASE_NONCE (first 8 bytes random; bytes 8-11 are 0x00)
45      8     ORIGINAL_SIZE (u64 LE; informational)
53      var   STREAM chunks (chunk_size = 65536; identical to v3)
```

KDF:
```
session_key = Argon2id(
    password = passphrase bytes (UTF-8),
    salt     = SALT (16 bytes),
    m_cost   = M_KIB,
    t_cost   = T_COST,
    p_cost   = P_COST,
    output   = 32 bytes
)
```

The 32-byte output is used directly as the ChaCha20-Poly1305 session key for the STREAM payload.

**Security note:** M_KIB, T_COST, and P_COST are attacker-controlled. Decryptors MUST enforce a ceiling before calling the KDF. Exceeding the ceiling returns `PqfileError::KdfLimitExceeded`. The default ceiling matches the encrypt-side default: 64 MiB / t=3.

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

Share body layout (inside each PEM block, current format introduced in v3.2.x):

```
Offset  Len  Field
0       1    VERSION (0x01)
1       2    KEM_VARIANT (u16 big-endian)
3       1    THRESHOLD (minimum shares required)
4       1    TOTAL (total shares produced)
5       1    X (1-indexed share index)
6       16   PUBKEY_FP (first 16 bytes of SHA3-256 of the derived public key)
22      var  Y (GF(256) share bytes; length equals seed length for the variant)
```

**Format version break (v3.2.x):** Prior to v3.2.x, PUBKEY_FP was 8 bytes and Y started at offset 14 (SHARE_HEADER_LEN = 14). Shares from v3.1.x and earlier are rejected with a clear error when decoded by v3.2.x or later. Implementors supporting old shares must handle both layouts by checking body length against the variant's expected seed length.

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

KDF: **Argon2id** (RFC 9106), parameters m=65536 (64 MiB), t=3, p=4, output=32 bytes.

**Legacy parameters (pre-4.0):** Keys created before v4.0 used p=1. These are detected at load time and rejected with `PqfileError::LegacyKeyFormat`; run `pqfile repassphrase --from-legacy` to migrate.

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

## 10. Bech32 Recipient Strings

Public keys may be distributed as a compact, human-readable Bech32m string instead of a PEM file. This is purely a key-transport encoding; it has no effect on the `.pqf` wire format.

**Encoding:**
```
pqf1<bech32m-data-characters>
```

The human-readable part (HRP) is `pqf`. The payload encodes:

```
Offset  Len   Field
0       2     KEM_VARIANT (u16 little-endian; same values as Section 2)
2       var   RAW_KEY_BYTES (encapsulation key; length per variant in Section 2)
```

**Checksum:** Bech32m polynomial (BIP350) with `CODE_LENGTH = usize::MAX`. The standard Bech32m limit of 1023 characters is lifted because ML-KEM-768 encapsulation keys encode to approximately 1900 characters.

**Produced by:** `pqfile keygen` (printed after the fingerprint line); `pqfile fingerprint <path-or-string>`.

**Consumed by:** `-r` flag on `pqfile encrypt` (accepts either a PEM file path or a `pqf1…` string); `pqfile fingerprint`.

---

## 11. Compliance Notes

- An implementation MUST accept v2 through v10 on read.
- An implementation MAY refuse to write any deprecated version.
- A decryptor for v4/v7 MUST iterate all recipient entries before returning `NoMatchingRecipient`; it MUST NOT short-circuit on a failed decapsulation for the correct variant.
- A v7/v8/v9 decryptor MUST treat entry order as meaningless and MUST NOT assume any mapping between position and identity.
- `ORIGINAL_SIZE` is informational. Decryptors MUST NOT pre-allocate `ORIGINAL_SIZE` bytes without bounds checking, as the field is attacker-controlled.
- Chunk counter overflow at `u32::MAX` is treated as an encryption error; files larger than approximately 256 TiB at the default 64 KiB chunk size are unsupported.
- Decoders MUST reject v5/v6 files where `CHUNK_SIZE` is 0 or greater than 268435456 (256 MiB). A crafted value of `u32::MAX` would cause a multi-gigabyte allocation before any data is read.
- Decoders MUST reject v4/v7/v8/v9 files where `COUNT` is greater than 256. A crafted maximum value of 65535 would cause a large header allocation before any AEAD verification.
- Decoders MUST enforce a ceiling on v10 `M_KIB`, `T_COST`, and `P_COST` before calling the KDF. These fields are attacker-controlled; exceeding the ceiling MUST return an error rather than attempting derivation.
- `rekey` MUST NOT accept v2 files as input. v2 uses a single whole-file AEAD whose payload format is incompatible with the v4 STREAM chunk layout that rekey produces. A v2 file rekeyed to v4 format cannot be decrypted.
