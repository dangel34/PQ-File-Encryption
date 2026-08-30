import pytest

import pqfile


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_bytes_roundtrip(level):
    pub_pem, priv_pem = pqfile.keygen(level=level)
    plaintext = b"hello, post-quantum world" * 100
    ciphertext = pqfile.encrypt_bytes(pub_pem, plaintext)
    assert ciphertext != plaintext
    assert pqfile.decrypt_bytes(priv_pem, ciphertext) == plaintext


def test_hybrid_roundtrip():
    pub_pem, priv_pem = pqfile.keygen_hybrid()
    plaintext = b"hybrid X25519 + ML-KEM-768"
    ciphertext = pqfile.encrypt_bytes(pub_pem, plaintext)
    assert pqfile.decrypt_bytes(priv_pem, ciphertext) == plaintext


def test_passphrase_protected_key():
    passphrase = "correct horse battery staple"
    pub_pem, priv_pem = pqfile.keygen(passphrase=passphrase)
    ciphertext = pqfile.encrypt_bytes(pub_pem, b"secret")

    assert pqfile.decrypt_bytes(priv_pem, ciphertext, passphrase=passphrase) == b"secret"

    with pytest.raises(pqfile.PqfileError):
        pqfile.decrypt_bytes(priv_pem, ciphertext, passphrase="wrong passphrase")

    with pytest.raises(pqfile.PqfileError):
        pqfile.decrypt_bytes(priv_pem, ciphertext)


def test_empty_plaintext_roundtrip():
    pub_pem, priv_pem = pqfile.keygen()
    ciphertext = pqfile.encrypt_bytes(pub_pem, b"")
    assert pqfile.decrypt_bytes(priv_pem, ciphertext) == b""


def test_wrong_key_fails():
    pub_pem_a, _ = pqfile.keygen()
    _, priv_pem_b = pqfile.keygen()
    ciphertext = pqfile.encrypt_bytes(pub_pem_a, b"for A, not B")
    with pytest.raises(pqfile.PqfileError):
        pqfile.decrypt_bytes(priv_pem_b, ciphertext)


def test_file_roundtrip(tmp_path):
    pub_pem, priv_pem = pqfile.keygen()
    plaintext = b"streamed to disk" * 10_000

    src = tmp_path / "input.bin"
    encrypted = tmp_path / "input.bin.pqf"
    decrypted = tmp_path / "output.bin"
    src.write_bytes(plaintext)

    pqfile.encrypt_file(pub_pem, src, encrypted)
    assert encrypted.read_bytes() != plaintext

    pqfile.decrypt_file(priv_pem, encrypted, decrypted)
    assert decrypted.read_bytes() == plaintext


def test_invalid_pem_raises():
    with pytest.raises(pqfile.PqfileError):
        pqfile.encrypt_bytes("not a pem", b"data")


def test_decrypt_file_is_atomic_on_failure(tmp_path):
    """A decrypt_file call that fails partway through (here, a tampered
    final byte breaking the last chunk's AEAD tag) must not leave an
    authenticated-so-far plaintext prefix at the destination, and must not
    touch a pre-existing file at that path either."""
    pub_pem, priv_pem = pqfile.keygen()
    # Multiple chunks, so a tampered final chunk leaves earlier chunks
    # already authenticated and written before the failure.
    plaintext = b"streamed to disk, multiple chunks worth" * 10_000

    src = tmp_path / "input.bin"
    encrypted = tmp_path / "input.bin.pqf"
    output = tmp_path / "output.bin"
    src.write_bytes(plaintext)
    output.write_bytes(b"pre-existing destination")

    pqfile.encrypt_file(pub_pem, src, encrypted)

    damaged = bytearray(encrypted.read_bytes())
    damaged[-1] ^= 1
    encrypted.write_bytes(damaged)

    with pytest.raises(pqfile.PqfileError):
        pqfile.decrypt_file(priv_pem, encrypted, output)

    assert output.read_bytes() == b"pre-existing destination"
    # No leftover temp file either: src, ciphertext, and destination only.
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [src.name, encrypted.name, output.name]
    )
