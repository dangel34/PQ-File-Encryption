# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 4.x     | Yes       |
| 3.x     | No        |
| 2.x     | No        |
| 1.x     | No        |
| < 1.0   | No        |

Only the latest 4.x release receives security patches. Upgrade to the latest tag before reporting.

---

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Use the private security advisory feature on GitHub:

> https://github.com/dangel34/PQ-File-Encryption/security/advisories/new

Include as much of the following as you can:

- A clear description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept (safe to share privately)
- The version(s) and platform(s) affected
- Any suggested remediation or root cause

You will receive an acknowledgement within **48 hours**. Patches are targeted within:

| Severity | Target patch window |
|----------|---------------------|
| Critical / High | 7 days |
| Medium | 30 days |
| Low | 90 days |

We will coordinate the disclosure timeline with you and credit you in the release notes unless you prefer to stay anonymous.

---

## Scope

### In scope

| Area | Example |
|------|---------|
| Cryptographic correctness | Errors in the ML-KEM, ML-DSA, ChaCha20-Poly1305, or key derivation implementation |
| Authentication bypass | Any code path that returns plaintext without passing AEAD verification |
| Key material exposure | Private key seed or shared secret leaked to disk, logs, or memory beyond the zeroize-on-drop boundary |
| File format parsing | Panics, incorrect behaviour, or silent data corruption on malformed `.pqf` input |
| Nonce reuse | Any path that could produce two encryptions under the same (key, nonce) pair |
| Signature forgery | Any path that produces a valid ML-DSA-65 or SLH-DSA-SHAKE-192f signature without the signing key |
| WASM sandbox | Cross-origin data exposure or unintended network requests from the web GUI |

### Out of scope

- Vulnerabilities in third-party Cargo dependencies (report those to the upstream crate maintainers)
- Attacks that require physical access to the machine or an already-compromised OS
- Brute-force attacks against the ML-KEM-768 parameter set (security category 3 is a design constraint, not a flaw)
- Social engineering

---

## Security design

pqfile is built on the following invariants. Any proposal that weakens them is treated as a breaking change and requires a major version bump.

**Post-quantum confidentiality**
Key encapsulation uses ML-KEM (NIST FIPS 203). Three key types are supported: ML-KEM-768 (security category 3), ML-KEM-1024 (security category 5), and a hybrid X25519+ML-KEM-768 mode. All three are believed to be secure against both classical and quantum adversaries. The hybrid mode additionally provides classical security guarantees from X25519 Diffie-Hellman, so encryption is secure under either classical or quantum assumptions, whichever holds in the future.

**KEM variant error reporting**
If a private key's KEM variant (512, 768, 1024, or hybrid) does not match the variant recorded in the file header, `decrypt_stream` returns `PqfileError::KemVariantMismatch { key, file }` with both variant identifiers. This is a distinct error from `UnsupportedKem`, which is returned only when an entirely unrecognised variant identifier appears in on-disk data. Callers can pattern-match to present a precise diagnostic.

**Authenticated encryption**
Symmetric encryption uses ChaCha20-Poly1305 (RFC 8439). For v2 (whole-file) format, the entire `.pqf` header is passed as AEAD additional data so any single-byte modification to the header or payload fails decryption before plaintext is returned. For v3 and later (streaming) formats, the payload is split into chunks; each chunk carries its own AEAD tag. The per-chunk AAD contains a position counter and an end-of-stream flag, so truncation and reordering attacks are detected.

**Key commitment and authenticated headers**
The first chunk's AAD additionally carries a 32-byte SHA3-256 key commitment binding the chunk-0 tag to the session key, base nonce, and original size, so a ciphertext cannot be crafted to decrypt successfully under two different keys. Files written by the current version set `VERSION_AUTH_BIT` (bit 7 of the version byte) and use a v3 commitment definition that also binds the header fields whose tampering was not previously self-healing: the chunk size (v5/v6), the compression algorithm byte (v6), and the v10 Argon2id salt, parameters, and flags. Stripping or adding the bit also fails authentication, since the two definitions use distinct domain-separation contexts. The version byte and KEM variant field are deliberately excluded: both change during zero-copy `rekey`, and tampering with either is self-healing (a structural misparse or wrong shared secret ending in a tag failure). See FORMAT.md section 4.4 for the exact preimages.

**Fresh randomness per file**
A new ML-KEM encapsulation and a new random base nonce are generated independently for every encryption operation using the OS CSPRNG (`getrandom`). In hybrid mode, a fresh ephemeral X25519 scalar is also generated per encryption. Nonce reuse is structurally impossible under normal usage.

**Bounded memory for whole-file and async decrypt/encrypt paths**
`decrypt_v2_payload` (used by the v2 whole-file format) and the `async` feature's `encrypt_stream_async`/`decrypt_stream_async` cap their internal `read_to_end` calls at `MAX_ORIGINAL_SIZE` (plus a small fixed slack for framing overhead), so a stream with an unbounded or oversized tail cannot force unbounded memory allocation before any size check runs. The chunked v3/v4/v5 streaming paths read one bounded chunk at a time and were never affected.

**Digital signatures**
Signing uses ML-DSA-65 (NIST FIPS 204) by default, with SLH-DSA-SHAKE-192f (NIST FIPS 205) as a hash-based option resting on more conservative assumptions for long-lived signatures. Both sit at NIST security category 3, and the algorithm is bound to the key's PEM tag, so a key can never be used under the wrong algorithm. Signing keys are separate from encryption keys. Passphrase protection is supported for signing keys using the same Argon2id + AES-256-GCM scheme as KEM keys. Signatures are detached PEM files. Verification rejects signatures from any key other than the one used to sign.

**Signcrypt write-before-verify design**
`signdecrypt` is a streaming operation: it writes decrypted plaintext bytes to the output writer as it goes, and verifies the ML-DSA sender signature only after the full stream has been processed. Each chunk is AEAD-authenticated before output, so the plaintext content is integrity-protected throughout. However, the sender's *identity* is not confirmed until `signdecrypt` returns `Ok(())`. Callers MUST write to a `Vec<u8>` (or equivalent retractable buffer) and only act on the data after the call succeeds. Writing directly to a file or socket before the return value is checked means data from an unverified sender may already be on disk or on the wire.

`signcrypt` and `signdecrypt` do not support v6 (compress-then-encrypt) files; that format combination is not produced by any pqfile code path.

**Passphrase parameter position**
All functions that accept an optional passphrase take it as the last parameter (`sign_passphrase: Option<&str>` in `signcrypt`/`signcrypt_bytes`, `passphrase: Option<&str>` in `signdecrypt`, `rekey_stream`, `add_recipient_stream`). This is a stable API invariant enforced since v3.3.x.

**Memory safety**
Private key seeds, shared secrets, session keys, and passphrase-derived keys are wrapped in `Zeroizing` from the `zeroize` crate, which overwrites the memory before deallocation. The `ml-kem`, `ml-dsa`, and `x25519-dalek` crates are compiled with their `zeroize` features enabled. Small, long-lived secrets (session keys, KEM shared secrets, KDF output) are additionally held in `mlock`ed heap memory (`VirtualLock` on Windows, plus `MADV_DONTDUMP` on Linux) via `secret.rs`'s `LockedSecret`, so they cannot be swapped to disk or included in a crash dump while alive; locking is best-effort (unprivileged `RLIMIT_MEMLOCK`/working-set quotas are small by default, and there is no page locking on `wasm32`), degrading to plain zeroize-on-drop rather than erroring when it fails. Plaintext and chunk buffers are deliberately excluded from locking - they are large enough to exhaust the lock quota immediately and are not long-lived key material. Shamir `reconstruct_raw` borrows `y` slices from the caller's `Zeroizing<Vec<u8>>` rather than cloning, so intermediate share bytes are not left in unzeroized heap allocations. The random polynomial coefficients generated during Shamir share splitting (`coeff_buf` in `split_raw`) are also wrapped in `Zeroizing` and overwritten when the split operation returns, and so are the output shares themselves. The per-chunk plaintext buffer inside `PqfReader` uses `Zeroizing<Vec<u8>>` and is explicitly zeroed before each reuse, so decrypted plaintext bytes do not outlive the chunk that produced them. GUI code that clones a passphrase out of a `Zeroizing<String>` field before passing it to a library call re-wraps the clone in `Zeroizing` rather than leaving it as a plain `String`.

**File permissions and hardware-backed key storage**
Private key files and Shamir share files are written with owner-only permissions (`0600`) on Unix via a dedicated `write_private_file` helper, rather than inheriting the process umask. Hardware-backed key seeds are stored in the OS credential store (Windows Credential Manager, macOS Keychain, or Linux Secret Service) via its byte-native secret API rather than as a hex-encoded string, avoiding an extra non-zeroized intermediate copy; seeds written by older pqfile versions in the legacy hex format are still read correctly.

**Shamir GF(256) constant-time status**
Both GF(256) arithmetic primitives used in Lagrange interpolation are branchless. `gf_mul` uses mask idioms (`0u8.wrapping_sub(bit)`) so execution time does not depend on either argument; the loop runs exactly 8 iterations for all inputs. `gf_inv` is implemented as a fixed 7-squaring chain computing `x^254` with no conditional branches and no early exit; execution time is identical for all non-zero inputs. A standalone `dudect` statistical benchmark (`cargo run --example ct_shamir -p pqfile`) and a fast sanity test (`cargo test --features timing-tests`) are provided to verify both functions locally.

**Constant-time rejection harnesses**
Two further dudect-style harnesses cover the decrypt paths. `cargo run --release --example ct_decrypt -p pqfile` verifies that rejecting a tampered ciphertext takes the same time regardless of which tag byte was corrupted. `cargo run --release --example ct_passphrase -p pqfile` verifies that a v10 wrong-passphrase rejection takes the same time for an unrelated guess as for a near-miss differing from the real passphrase by a single character. Both use the same Welch t-test scaffolding and |t| < 4.5 pass criterion as `ct_shamir`.

**Metadata protection**
Several optional modes reduce what a ciphertext reveals beyond its contents. `--anonymous-recipients` (v8) hides recipient key types; `--pad-recipients` (v9) additionally hides the recipient count. `encrypt --pad` applies Padme padding so the ciphertext length reveals only a coarse bucket (at most ~12% overhead) rather than the exact plaintext size; decryption strips it automatically using the authenticated original-size field. `encrypt --stealth` omits the magic bytes, version byte, and KEM variant field entirely, so the output does not identify itself as pqfile ciphertext or as any particular key type; the KEM ciphertext, nonce, and payload are computationally indistinguishable from random bytes, with the caveat that the 8-byte original-size field is visibly non-random for small files (pair with `--pad` when the length itself is sensitive).

**Multi-recipient security**
In v4 format, a random 32-byte session key K encrypts the file payload. Each recipient's copy of K is wrapped under their KEM shared secret using AES-256-GCM with a zero nonce. The zero nonce is safe because each KEM shared secret is fresh and unique per encapsulation. A recipient with a non-matching key cannot distinguish a file addressed to them from one addressed to others.

**API stability and forward compatibility**
All public error, result, and info types carry `#[non_exhaustive]`. Code that matches on `PqfileError`, `PqfHeaderInfo`, or similar types with `..` will continue to compile when new variants are added in future releases. All fallible public functions carry `#[must_use]` to prevent silently discarding error results.

**Local-only operation**
All cryptographic operations run on the user's device. No file data, key material, or metadata is transmitted over a network in either the CLI or the GUI (including the WASM web build), with two narrow, off-by-default, explicitly-invoked exceptions: the `tlock` feature's `decrypt`/`check --tlock` fetch a drand beacon signature (never file data or key material - only a public, round-indexed signature) to unlock a time-locked file, and the `update-check` feature's `check-update` / "Check for Updates" queries the GitHub Releases API to compare version strings. Neither ever runs unless invoked explicitly (a CLI flag/subcommand, or a GUI button/opt-in toggle), and neither is compiled in by default.
