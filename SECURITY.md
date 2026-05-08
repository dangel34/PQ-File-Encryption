# Security Policy

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | Yes                |
| 1.x     | No                 |
| < 1.0   | No                 |

Only the latest 2.x release receives security patches. Upgrade to the latest tag before reporting.

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
| Cryptographic correctness | Errors in the ML-KEM, ChaCha20-Poly1305, or key derivation implementation |
| Authentication bypass | Any code path that returns plaintext without passing AEAD verification |
| Key material exposure | Private key seed or shared secret leaked to disk, logs, or memory beyond the zeroize-on-drop boundary |
| File format parsing | Panics, incorrect behaviour, or silent data corruption on malformed `.pqf` input |
| Nonce reuse | Any path that could produce two encryptions under the same (key, nonce) pair |
| WASM sandbox | Cross-origin data exposure or unintended network requests from the web GUI |

### Out of scope

- Vulnerabilities in third-party Cargo dependencies — report those to the upstream crate maintainers
- Attacks that require physical access to the machine or an already-compromised OS
- Brute-force attacks against the ML-KEM-768 parameter set (security category 3 is a design constraint, not a flaw)
- Social engineering

---

## Security design

pqfile is built on the following invariants. Any proposal that weakens them is treated as a breaking change and requires a major version bump.

**Post-quantum confidentiality**
Key encapsulation uses ML-KEM-768 (NIST FIPS 203, security category 3). This parameter set is believed to be secure against both classical and quantum adversaries.

**Authenticated encryption**
Symmetric encryption uses ChaCha20-Poly1305 (RFC 8439). The entire 1115-byte `.pqf` header — magic, version, KEM variant, KEM ciphertext, nonce, and original file size — is passed as AEAD additional data. The Poly1305 tag therefore authenticates both the header and the payload. Any single-byte modification to any part of the file causes decryption to fail before plaintext is returned.

**Fresh randomness per file**
A new ML-KEM encapsulation and a new 96-bit nonce are generated independently for every encryption operation using the OS CSPRNG (`getrandom`). Nonce reuse is structurally impossible under normal usage.

**Memory safety**
The private key seed (64 bytes) and the derived shared secret (32 bytes) are wrapped in `Zeroizing` from the `zeroize` crate, which overwrites the memory before deallocation.

**Local-only operation**
All cryptographic operations run on the user's device. No file data, key material, or metadata is transmitted over a network in either the CLI or the GUI (including the WASM web build).
