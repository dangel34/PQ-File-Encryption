//! Quantum-resistant file encryption library.
//!
//! pqfile provides authenticated, post-quantum file encryption using NIST-standardised
//! algorithms. All format versions are stable on disk and documented in `docs/FORMAT.md`.
//!
//! # Algorithms
//!
//! - **Key encapsulation**: ML-KEM-512, ML-KEM-768 (default), ML-KEM-1024 (NIST FIPS 203)
//! - **Hybrid mode**: X25519 + ML-KEM-768 via HKDF-SHA256
//! - **Symmetric cipher**: ChaCha20-Poly1305 (RFC 8439)
//! - **Session key wrapping**: AES-256-GCM (multi-recipient modes)
//! - **Signatures**: ML-DSA-65 (NIST FIPS 204)
//! - **Passphrase protection**: Argon2id (m=64 MiB, t=3, p=1) + AES-256-GCM
//!
//! # Quick start
//!
//! ```no_run
//! use pqfile::{keygen, encrypt, decrypt};
//!
//! // Generate a key pair
//! let (pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();
//!
//! // Encrypt
//! let plaintext = b"hello, post-quantum world";
//! let ciphertext = encrypt::encrypt_bytes(&pub_pem, plaintext).unwrap();
//!
//! // Decrypt
//! let recovered = decrypt::decrypt_bytes(&priv_pem, &ciphertext, None).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! # Streaming
//!
//! For large files, use the streaming API to avoid loading the entire file into memory:
//!
//! ```no_run
//! use pqfile::{keygen, encrypt, decrypt};
//! use std::io::Cursor;
//!
//! let (pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();
//! let plaintext = b"streaming data";
//!
//! let mut ct = Vec::new();
//! encrypt::encrypt_stream(&pub_pem, plaintext.len() as u64, pqfile::format::CHUNK_SIZE,
//!     &mut Cursor::new(plaintext), &mut ct).unwrap();
//!
//! let mut out = Vec::new();
//! decrypt::decrypt_stream(&priv_pem, &mut ct.as_slice(), &mut out, None).unwrap();
//! assert_eq!(out, plaintext);
//! ```
//!
//! # Stability
//!
//! The public API is not yet stabilised for 1.0. Breaking changes between minor versions
//! are possible until a stable 1.0 release is announced. See the roadmap.

#![warn(missing_docs)]

// ── Public modules ─────────────────────────────────────────────────────────

/// Encrypted multi-file archive support (PQFA format).
pub mod archive;

/// Decryption: all format versions v2 through v7, all KEM variants.
pub mod decrypt;

/// Encryption: single-recipient, multi-recipient, compressed, and parallel modes.
pub mod encrypt;

/// Error types.
pub mod error;

/// On-disk format constants and header structs.
pub mod format;

/// Key generation: ML-KEM (512/768/1024), hybrid X25519+ML-KEM-768.
pub mod keygen;

/// Passphrase-based key protection (Argon2id + AES-256-GCM).
pub mod passphrase;

/// Streaming decryptor: `PqfReader<R>` implements `std::io::Read`.
pub mod reader;

/// Rekey: transfer a v3/v5 file to a new recipient without re-encrypting.
pub mod rekey;

/// Key revocation: create and check `.revoked` sidecar files.
pub mod revoke;

/// Shamir secret sharing: split and reconstruct private keys (M-of-N).
pub mod shamir;

/// ML-DSA-65 signing key generation, signing, and verification.
pub mod sign;

/// Signcrypt: sign-then-encrypt and decrypt-then-verify in a single step.
pub mod signcrypt;
