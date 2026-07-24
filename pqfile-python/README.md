# pqfile (Python bindings)

Python bindings for [`pqfile`](https://github.com/dangel34/PQ-File-Encryption), a
quantum-resistant file encryption library: ML-KEM (512/768/1024) and hybrid
X25519+ML-KEM-768 key encapsulation with ChaCha20-Poly1305 authenticated
encryption. Built with [PyO3](https://pyo3.rs) and packaged with
[maturin](https://www.maturin.rs); the crypto itself lives entirely in the
`pqfile` Rust crate, not in this binding layer.

## Install (from source, until wheels are published)

```sh
pip install maturin
cd pqfile-python
maturin develop --release
```

## Quick start

```python
import pqfile

# Generate a key pair
pub_pem, priv_pem = pqfile.keygen()  # level=768 by default; also 512, 1024

# Encrypt / decrypt in memory
ciphertext = pqfile.encrypt_bytes(pub_pem, b"hello, post-quantum world")
plaintext = pqfile.decrypt_bytes(priv_pem, ciphertext)
assert plaintext == b"hello, post-quantum world"

# Encrypt / decrypt files directly (streams; flat memory use regardless of size)
pqfile.encrypt_file(pub_pem, "report.pdf", "report.pdf.pqf")
pqfile.decrypt_file(priv_pem, "report.pdf.pqf", "report.pdf")
```

A passphrase-protected private key:

```python
pub_pem, priv_pem = pqfile.keygen(passphrase="correct horse battery staple")
plaintext = pqfile.decrypt_bytes(priv_pem, ciphertext, passphrase="correct horse battery staple")
```

Hybrid X25519 + ML-KEM-768 (defense in depth against a future ML-KEM break):

```python
pub_pem, priv_pem = pqfile.keygen_hybrid()
```

## Errors

All failures raise `pqfile.PqfileError`, a subclass of `Exception`, with a
human-readable message and the stable numeric error code from
[`docs/ERROR_CODES.md`](../docs/ERROR_CODES.md) appended, e.g.
`decryption failure: authentication tag mismatch (code 7)`.

## Scope

This wraps `pqfile::encrypt`/`pqfile::decrypt`'s single-recipient streaming
path only (`keygen`/`encrypt_bytes`/`decrypt_bytes`/`encrypt_file`/`decrypt_file`).
Multi-recipient encryption, signing/`signcrypt`, Shamir sharing, certificates,
and the other CLI features are not yet exposed here - see
`docs/ROADMAP.md`, "Python, Node.js, and mobile bindings", for status.

## Compatibility

Produces and reads the same `.pqf` v3/v5 wire format as the `pqfile` CLI and
GUI (see `docs/FORMAT.md`), so files are interchangeable in both directions.

## CI and publishing

`ci.yml`'s `bindings-python` job builds this crate and runs the pytest suite
on every push/PR. `publish-python.yml` is scaffolding for the actual PyPI
release - it builds wheels for Linux (manylinux, via `PyO3/maturin-action`'s
bundled Docker image)/Windows/macOS (x86_64 and aarch64) plus an sdist, and
would publish them to PyPI on a GitHub Release being published. It has never
actually run: publishing uses PyPI Trusted Publishing (OIDC) rather than a
stored token, which needs a one-time "pending publisher" registered on PyPI
first (pypi.org -> your account -> Publishing -> Add a new pending
publisher) - project name `pqfile`, owner `dangel34`, repository
`PQ-File-Encryption`, workflow `publish-python.yml`, environment `release`.
Until that's registered, the publish job's `id-token: write` permission has
nothing to authenticate against and the upload step fails.
