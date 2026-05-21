# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 3.x     | Yes       |
| 2.x     | No        |
| 1.x     | No        |
| < 1.0   | No        |

Only the latest 3.x release receives security patches. Upgrade to the latest tag before reporting.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private security advisory feature:

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
| Signature forgery | Any path that produces a valid ML-DSA-65 signature without the signing key |
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

**Authenticated encryption**
Symmetric encryption uses ChaCha20-Poly1305 (RFC 8439). For v2 (whole-file) format, the entire `.pqf` header is passed as AEAD additional data so any single-byte modification to the header or payload fails decryption before plaintext is returned. For v3 and v4 (streaming) formats, the payload is split into 64 KiB chunks; each chunk carries its own AEAD tag. The per-chunk AAD contains a position counter and an end-of-stream flag, so truncation and reordering attacks are detected.

**Fresh randomness per file**
A new ML-KEM encapsulation and a new random base nonce are generated independently for every encryption operation using the OS CSPRNG (`getrandom`). In hybrid mode, a fresh ephemeral X25519 scalar is also generated per encryption. Nonce reuse is structurally impossible under normal usage.

**Digital signatures**
Signing uses ML-DSA-65 (NIST FIPS 204). Signing keys are separate from encryption keys and are not passphrase-protected. Signatures are detached PEM files. Verification rejects signatures from any key other than the one used to sign.

**Memory safety**
Private key seeds, shared secrets, session keys, and passphrase-derived keys are wrapped in `Zeroizing` from the `zeroize` crate, which overwrites the memory before deallocation. The `ml-kem`, `ml-dsa`, and `x25519-dalek` crates are compiled with their `zeroize` features enabled.

**Multi-recipient security**
In v4 format, a random 32-byte session key K encrypts the file payload. Each recipient's copy of K is wrapped under their KEM shared secret using AES-256-GCM with a zero nonce. The zero nonce is safe because each KEM shared secret is fresh and unique per encapsulation. A recipient with a non-matching key cannot distinguish a file addressed to them from one addressed to others.

**Local-only operation**
All cryptographic operations run on the user's device. No file data, key material, or metadata is transmitted over a network in either the CLI or the GUI (including the WASM web build).
