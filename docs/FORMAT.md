# pqfile Format Specification

This document is the authoritative byte-level description of all `.pqf` file format versions (v2 through v10), plus the stealth mode (§5.10) and Padmé padding (§5.11) that layer on top without a version bump. All multi-byte integers are little-endian unless stated otherwise.

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
| VERSION_AUTH_BIT | `0x80` | Authenticated-header flag bit, OR-ed onto the version byte (e.g. `0x83` = v3 layout + authenticated header). See §4.4. |
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

## 4. STREAM Chunk Construction (v3-v10)

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
    key_commitment  (32 bytes, chunk 0 only — see §4.4)
// 43 bytes for chunk 0, 11 bytes for all later chunks
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

### 4.4 Chunk-0 key commitment and the authenticated-header bit

The first chunk's AAD carries a 32-byte SHA3-256 **key commitment** binding the
chunk-0 tag to the session key and the stable header fields. Which preimage is
used depends on `VERSION_AUTH_BIT` in the version byte:

**Legacy files (bit clear, written by pqfile ≤ 4.2.4):**

```
key_commitment = SHA3-256(
    b"pqfile-session-key-commitment-v2"
    || session_key (32 bytes)
    || BASE_NONCE  (12 bytes as stored in the header)
    || ORIGINAL_SIZE (8 bytes, little-endian)
)
```

**Authenticated-header files (bit set, e.g. version byte `0x83`/`0x84`/…/`0x8A`):**

```
key_commitment = SHA3-256(
    b"pqfile-session-key-commitment-v3"
    || session_key      (32 bytes)
    || chunk_size       (4 bytes LE; CHUNK_SIZE for layouts without the field)
    || compression_algo (1 byte; 0x00 for layouts without the field)
    || kdf_fields       (29 bytes: v10 SALT || M || T || P || FLAGS; all zero
                         for every layout other than v10)
    || BASE_NONCE       (12 bytes)
    || ORIGINAL_SIZE    (8 bytes LE)
)
```

The v3 commitment binds every header field whose tampering is not already
self-healing. Flipping `compression_algo`, `chunk_size`, the v10 Argon2id
parameters/flags, or the auth bit itself makes chunk-0 authentication fail (the
two definitions use different domain-separation contexts, so the bit cannot be
stripped or added). The version byte and `kem_variant` are deliberately
**excluded** from the preimage: both change during zero-copy `rekey`
(v3 → v4) while the payload is preserved, and tampering with either is
self-healing — a structural misparse or wrong shared secret that ends in a tag
failure. Recipient-slot contents are likewise excluded so `add-recipient` and
`rekey` can rewrite headers without touching the payload.

There is no `0x82`: v2 already authenticates its entire header as the
whole-file AAD, so the bit is rejected on the v2 layout. pqfile ≤ 4.2.4
rejects any bit-carrying version byte with `UnsupportedVersion` — the intended
"upgrade to read this file" signal. Files written by older versions remain
readable.

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
33      1     FLAGS (bit 0 = keyfile required, bit 1 = FIDO2 token required,
                       bit 2 = WebAuthn PRF required [at most one of the
                       three may be set]; bits 3-7 reserved, MUST be 0)
34      12    BASE_NONCE (first 8 bytes random; bytes 8-11 are 0x00)
46      8     ORIGINAL_SIZE (u64 LE; informational)
54      var   STREAM chunks (chunk_size = 65536; identical to v3)
```

KDF:
```
session_key = Argon2id(
    password = passphrase bytes (UTF-8),
    salt     = SALT (16 bytes),
    secret   = SHA3-256("pqfile-keyfile-v1" || keyfile bytes)         -- only if FLAGS bit 0 set
             | SHA3-256("pqfile-fido2-v1" || hmac-secret output)      -- only if FLAGS bit 1 set
             | SHA3-256("pqfile-webauthn-prf-v1" || PRF output)       -- only if FLAGS bit 2 set
    m_cost   = M_KIB,
    t_cost   = T_COST,
    p_cost   = P_COST,
    output   = 32 bytes
)
```

The 32-byte output is used directly as the ChaCha20-Poly1305 session key for the STREAM payload.

**Keyfile second factor (FLAGS bit 0):** when set, the SHA3-256 hash of a caller-supplied keyfile (any non-empty byte string) is passed as the Argon2id *secret* (pepper) input, so deriving the session key requires both the passphrase and the identical keyfile bytes. A decryptor without a keyfile MUST fail with `PqfileError::KeyfileRequired` before running the KDF; a decryptor given a keyfile for a file whose bit is clear MUST fail with `PqfileError::KeyfileNotRequired`. The flag is not independently authenticated, but tampering with it cannot bypass the second factor: the keyfile hash is baked into the session key, so a cleared bit only produces an authentication failure.

**FIDO2 token second factor (FLAGS bit 1):** the same pepper slot as the keyfile second factor, sourced from a hardware security key instead of a file. The secret is the domain-separated SHA3-256 hash of the 32-byte output of the CTAP2 `hmac-secret` extension, presented by a token holding the credential enrolled by `pqfile fido2-enroll` (credential ID and salt recorded in a separate, non-sensitive enrollment file - reproducing the output requires physically touching the same token). Mutually exclusive with bits 0 and 2: a header with more than one of the three bits set is rejected as unsupported. Missing/superfluous-token failures mirror the keyfile case: `PqfileError::Fido2Required` / `PqfileError::Fido2NotRequired`, and tampering with the bit is likewise self-defeating since the derived secret is baked into the session key.

**WebAuthn PRF second factor (FLAGS bit 2):** the browser-native equivalent of the FIDO2 second factor above, for the WASM web GUI (which has no CTAP2/USB HID access). The same pepper slot, sourced from the WebAuthn `prf` extension instead of CTAP2 `hmac-secret`: the secret is the domain-separated SHA3-256 hash of the 32-byte value returned by `PublicKeyCredential.getClientExtensionResults().prf.results.first`, evaluated against a credential ID and salt recorded in a separate, non-sensitive enrollment file (analogous in shape to the FIDO2 one, but produced by `navigator.credentials.create`/`.get()` in the browser rather than CTAP2). Registers a *resident* (discoverable) credential (`residentKey: "required"`), unlike the FIDO2 second factor's non-resident choice - Windows Hello's OS-level WebAuthn API hard-requires a resident credential before it will expose `hmac-secret`/PRF at all, so a non-resident credential silently breaks PRF there. Still passes the credential ID via `allowCredentials` at derive time rather than relying on full passwordless discovery, for consistency with the enrollment-file-based flow every other second factor uses. Mutually exclusive with bits 0 and 1. Missing/superfluous-passkey failures mirror the keyfile/FIDO2 cases: `PqfileError::WebauthnPrfRequired` / `PqfileError::WebauthnPrfNotRequired`. Not a post-quantum concern either way: this only changes which secret feeds the same classical Argon2id pepper slot, not the payload's PQ security.

**Unknown flag bits:** decoders MUST reject a header with any reserved bit set, or with more than one of bits 0-2 set (`PqfileError::UnsupportedHeaderFlags`), rather than ignore it, so files written by future versions with different derivation semantics are never silently misdecrypted.

**Security note:** M_KIB, T_COST, and P_COST are attacker-controlled. Decryptors MUST enforce a ceiling before calling the KDF. Exceeding the ceiling returns `PqfileError::KdfLimitExceeded`. The default ceiling matches the encrypt-side default: 64 MiB / t=3.

---

### 5.10 Stealth mode - no magic, no version, no KEM variant field

`encrypt_stream_stealth` / `decrypt_stream_stealth` (`pqfile::encrypt` / `pqfile::decrypt`) produce output with **no header at all** in the sense used by every other version above: no `PQFL` magic, no version byte, and no KEM variant field. The point is that the ciphertext is not identifiable as pqfile output (or as any particular key type) to an observer without the private key.

```
Offset  Len   Field
0       ct    KEM_CT (length implied by the recipient's own KEM variant)
ct      8     BASE_NONCE (random)
ct+8    8     ORIGINAL_SIZE (u64 LE; informational, authenticated - see below)
ct+16   var   STREAM chunks (chunk_size = 65536, no compression; identical construction to v3)
```

Single recipient only. `ct` (the KEM ciphertext length) is not stored anywhere on the wire - the decryptor already knows it, because `ct_len` is determined entirely by the *private key's own* KEM variant (`ct_len_for_variant(dk.kem_variant())`). A wrong-variant or unrelated key simply reads the wrong number of bytes and fails decapsulation or chunk-0 authentication, the same failure shape as any other corrupt input.

**Key commitment:** identical to the `VERSION_AUTH_BIT` v3 definition (`commitment_for_stream` with `chunk_size = CHUNK_SIZE`, `compression_algo = COMPRESSION_NONE`), even though no version byte travels on the wire to select it - both sides derive the same commitment because both sides use the same hardcoded chunk_size/compression_algo constants.

**Decrypt-side truncation:** `decrypt_stream_stealth` unconditionally caps its output at the parsed `ORIGINAL_SIZE` (via `pqfile::padding::TruncatingWriter`), unlike the non-stealth decrypt paths where this is left to the caller. There is no legacy caller whose behavior this could change, since the function is new, and it means [Padmé padding](#padding) composes with stealth mode with no extra steps at decrypt time.

**Residual leakage:** the KEM ciphertext (and, in hybrid mode, the X25519 ephemeral public key) and the nonce are computationally indistinguishable from random bytes. `ORIGINAL_SIZE` is not - small files leave high-order zero bytes visible in that field. Pair with `PadmeReader` (encrypt-side, real length still passed to `encrypt_stream_stealth` so `ORIGINAL_SIZE` stays accurate) if the plaintext length is also sensitive.

<a id="padding"></a>
### 5.11 Plaintext length padding (Padmé)

Padmé padding (`pqfile::padding::padme_length`/`PadmeReader`/`TruncatingWriter`) is **not a wire-format change** - every version above already has an `ORIGINAL_SIZE` field meaning "true plaintext length," and that field is already bound into the chunk-0 key commitment. Padding works entirely by:

1. **Encrypt side:** wrap the plaintext reader in `PadmeReader::new(reader, real_len)`, which emits `real_len` real bytes followed by `padme_length(real_len) - real_len` zero bytes before EOF. Pass `real_len` (not the padded length) as `original_size` to the encrypt function unchanged - the header keeps recording the true size; only the physical byte count of the chunked payload grows.
2. **Decrypt side:** wrap the output writer in `TruncatingWriter::new(writer, original_size)`, capping forwarded bytes at the header's (authenticated) `original_size` and silently dropping the padding tail. Because non-padded files already decrypt to exactly `original_size` bytes, this is a no-op unless the file was actually padded - callers do not need to know in advance.

`padme_length(len)` rounds `len` up to a bucket whose low-order bits are masked to zero (the number of masked bits grows with `len`'s own bit-length), bounding overhead to roughly 1/2^k for a length k bits short of a power of two - in practice at most ~12% for real file sizes.

---

### 5.12 v11 - Time-locked (`tlock` feature)

No KEM step and no recipient key pair at all. The session key is derived from a random 16-byte seed that is itself protected by [tlock](https://eprint.iacr.org/2023/189) identity-based encryption (IBE) against a target [drand](https://drand.love) beacon round: nobody, including the sender, can reconstruct the seed until that round's threshold BLS signature is published. `pqfile::tlock::encrypt_stream_tlock` / `decrypt_stream_tlock` (off by default; `tlock` Cargo feature on `pqfile`/`pqfile-cli`).

```
Offset  Len   Field
0       4     MAGIC
4       1     VERSION (0x8B; always carries the VERSION_AUTH_BIT, 0x80, set -
                        there is no legacy v11 layout predating it)
5       32    CHAIN_HASH (identifies the drand chain the ROUND is relative to)
37      8     ROUND (u64 BE; target beacon round)
45      4     TLOCK_CT_LEN (u32 LE)
49      var   TLOCK_CT (tlock IBE ciphertext: U (48 or 96 bytes, whichever
                        group is opposite the chain's public key) || V (16
                        bytes) || W (16 bytes))
49+L    12    BASE_NONCE (first 8 bytes random; bytes 8-11 are 0x00)
61+L    8     ORIGINAL_SIZE (u64 LE; informational)
69+L    var   STREAM chunks (chunk_size = 65536; identical to v3)
```

Session key derivation:
```
seed        = 16 random bytes, resampled until the last byte is non-zero
                (see "tlock quirk" below)
TLOCK_CT    = tlock::encrypt(seed, chain_public_key, ROUND)
session_key = HKDF-SHA256(ikm = seed, info = "pqfile-tlock-v1", 32 bytes)
```

Decryption fetches the beacon signature for `ROUND` from a drand HTTP relay (the only network-touching step in the `pqfile` library), uses it as the IBE "private key" to recover `seed` via `tlock::decrypt(TLOCK_CT, signature)`, then re-derives `session_key` identically. Decrypting before `ROUND` has fired returns `PqfileError::TlockRoundNotReached`; the underlying beacon fetch is otherwise indistinguishable in shape from a normal decrypt failure path.

**Default chain:** the League of Entropy mainnet `quicknet` chain (3-second rounds, unchained BLS12-381 with the RFC 9380 hash-to-curve scheme). `CHAIN_HASH` records which chain a file targets so a decryptor knows which relay/public key to use; it is public information, not sensitive, and is bound into the key commitment (below) so tampering with it is caught rather than silently causing a decrypt against the wrong chain.

**tlock quirk:** the reference `tlock` crate silently strips trailing zero bytes from its recovered 16-byte plaintext. As long as the seed's last byte is non-zero, no truncation occurs regardless of earlier bytes, so the encoder resamples (~1/256 chance per attempt) rather than accepting a seed whose last byte is `0x00`.

**Key commitment:** own domain separator (`"pqfile-tlock-key-commitment-v1"`, distinct from the v2/v3 stream commitments and from v10's), always computed as SHA3-256 of `CTX || session_key || CHAIN_HASH || ROUND || BASE_NONCE || ORIGINAL_SIZE` - unlike v10, there is no legacy v11 layout predating `VERSION_AUTH_BIT` to stay compatible with, so there is only one commitment definition.

**Not a post-quantum guarantee:** drand's tlock scheme is BLS12-381 pairing-based (classical), layered on top of pqfile's usual chunked, authenticated AEAD payload exactly like every other format - only the session-key derivation differs.

**Scope (v1):** pure time-lock only; there is no way to additionally require a recipient's own private key alongside the round (see `docs/ROADMAP.md`). `encrypt_stream_tlock` is fully offline given a round number; resolving a human time expression ("in 24h", an RFC 3339 date) to a round number is a separate, explicitly network-touching convenience (`pqfile::tlock::round_for_target_time`, `pqfile tlock round` CLI subcommand) that never fetches the round's own beacon.

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

### 6.2 Signing keys

| PEM Label | Contents |
|-----------|----------|
| `ML-DSA-65 VERIFYING KEY` | 1952-byte verifying key |
| `ML-DSA-65 SIGNING KEY` | 32-byte signing seed (plaintext) |
| `ML-DSA-65 ENCRYPTED SIGNING KEY` | 76-byte encrypted body (see Section 7) |
| `SLH-DSA-SHAKE-192F VERIFYING KEY` | 48-byte verifying key (PK.seed ‖ PK.root) |
| `SLH-DSA-SHAKE-192F SIGNING KEY` | 72-byte seed triple (SK.seed ‖ SK.prf ‖ PK.seed, plaintext) |
| `SLH-DSA-SHAKE-192F ENCRYPTED SIGNING KEY` | 116-byte encrypted body (see Section 7) |

The SLH-DSA private key is stored as the FIPS 205 seed triple rather than the
expanded 96-byte key; the full signing key (including PK.root) is deterministically
recomputed from the triple on every load via `slh_keygen_internal` (Algorithm 18).
Detached SLH-DSA signatures use the `SLH-DSA-SHAKE-192F SIGNATURE` PEM label
(35664-byte body).

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

### 6.4 Certificates

| PEM Label | Contents |
|-----------|----------|
| `PQFILE CERTIFICATE` | CA-signed attestation of a subject public/verifying key (see below) |

A certificate binds a subject key to a label, a validity window, and an allowed-use
bitmask, signed by a CA signing key (ML-DSA-65 or SLH-DSA-SHAKE-192f, via the `sign`
module - see 6.2). Certificates do not chain and carry no revocation mechanism beyond
the validity window. Body layout (self-delimiting: every variable-length field carries
its own length prefix, so the signed range is exactly `body`, with `SIG_LEN`/`SIG`
appended afterward):

```
Offset  Len   Field
0       4     MAGIC ("PQFC")
4       1     VERSION (0x01)
5       8     NOT_BEFORE (Unix seconds, LE, inclusive)
13      8     NOT_AFTER (Unix seconds, LE, inclusive)
21      1     ALLOWED_USE (bit 0 = ENCRYPT, bit 1 = SIGN)
22      2     LABEL_LEN (LE, ≤ 256)
24      var   LABEL (UTF-8)
...     1     SUBJECT_TAG_LEN (≤ 64)
...     var   SUBJECT_TAG (the subject key's own PEM tag, e.g. "ML-KEM-768 PUBLIC KEY")
...     4     SUBJECT_KEY_LEN (LE, ≤ 16384)
...     var   SUBJECT_KEY (the subject key's raw PEM body bytes)
...     4     SIG_LEN (LE)
...     var   SIG (CA signature over everything from MAGIC through SUBJECT_KEY)
```

The subject key's PEM tag travels inside the signed body, so a verified certificate
hands back a ready-to-use, self-describing PEM (`SUBJECT_TAG` + `SUBJECT_KEY`) without
the caller needing to know the key type in advance - any current or future pqfile
public key type can be certified without a format change here.

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
| SLH-DSA-SHAKE-192f signing | 72 bytes | 116 bytes |

KDF: **Argon2id** (RFC 9106), parameters m=65536 (64 MiB), t=3, p=4, output=32 bytes.

**Legacy parameters (pre-4.0):** Keys created before v4.0 used p=1. These are detected at load time and rejected with `PqfileError::LegacyKeyFormat`; run `pqfile repassphrase --from-legacy` to migrate.

Encryption: **AES-256-GCM** with the 32-byte KDF output as key and a 12-byte random nonce. AAD is empty.

---

## 8. Signcrypt Layout

A signcrypted file is a standard v3 `.pqf` file whose plaintext payload is:

```
[signature: SIG_LEN bytes][original plaintext: N bytes]
```

`SIG_LEN` is fixed per signature algorithm and is implied by the signing/verifying key pair - no algorithm identifier travels in the file:

| Algorithm | SIG_LEN |
|-----------|---------|
| ML-DSA-65 (FIPS 204) | 3309 |
| SLH-DSA-SHAKE-192f (FIPS 205) | 35664 |

The decryptor derives `SIG_LEN` from the PEM tag of the verifying key supplied to `signdecrypt`. Supplying a key of the wrong algorithm causes signature verification to fail.

The signature covers `SHA3-256(original_plaintext)`, not the raw bytes, enabling streaming. The signature is inside the AEAD ciphertext so it cannot be stripped or reordered.

`ORIGINAL_SIZE` in the header stores `SIG_LEN + N`.

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
