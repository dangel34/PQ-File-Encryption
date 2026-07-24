"""Quantum-resistant file encryption (ML-KEM, hybrid X25519+ML-KEM-768).

Thin, pythonic wrapper around the native `pqfile._pqfile` extension module,
which in turn binds the `pqfile` Rust crate (the same core used by the
pqfile CLI and GUI). See the pqfile-python README for a quick start and
docs/FORMAT.md in the main repository for the on-disk format.

Example:
    >>> import pqfile
    >>> pub_pem, priv_pem = pqfile.keygen()
    >>> ciphertext = pqfile.encrypt_bytes(pub_pem, b"hello, post-quantum world")
    >>> pqfile.decrypt_bytes(priv_pem, ciphertext)
    b'hello, post-quantum world'
"""

from __future__ import annotations

import os
from typing import Optional, Union

from ._pqfile import (
    PqfileError,
    decrypt_bytes,
    encrypt_bytes,
    keygen,
    keygen_hybrid,
)
from ._pqfile import decrypt_file as _decrypt_file
from ._pqfile import encrypt_file as _encrypt_file

__all__ = [
    "PqfileError",
    "keygen",
    "keygen_hybrid",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_file",
    "decrypt_file",
]

StrPath = Union[str, "os.PathLike[str]"]


def encrypt_file(pubkey_pem: str, input_path: StrPath, output_path: StrPath) -> None:
    """Encrypts the file at `input_path` to `output_path` for `pubkey_pem`.

    Streams from disk to disk, so memory use stays flat regardless of file
    size (unlike `encrypt_bytes`, which loads the whole plaintext into RAM).
    """
    _encrypt_file(pubkey_pem, os.fspath(input_path), os.fspath(output_path))


def decrypt_file(
    privkey_pem: str,
    input_path: StrPath,
    output_path: StrPath,
    passphrase: Optional[str] = None,
) -> None:
    """Decrypts the `.pqf` file at `input_path` to `output_path`.

    Streams from disk to disk, so memory use stays flat regardless of file
    size (unlike `decrypt_bytes`, which loads the whole plaintext into RAM).
    """
    _decrypt_file(privkey_pem, os.fspath(input_path), os.fspath(output_path), passphrase)
