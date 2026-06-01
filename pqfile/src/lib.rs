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
//! - **Passphrase protection**: Argon2id (m=64 MiB, t=3, p=4) + AES-256-GCM
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
//! # Crate layout
//!
//! Items re-exported to the crate root (`pqfile::PqfileError`, `pqfile::CHUNK_SIZE`,
//! `pqfile::PqfReader`, `pqfile::PqfInfo`, `pqfile::inspect_stream`, `pqfile::PqfHeaderInfo`,
//! `pqfile::RecipientInfo`, and the typed key wrappers) are the stable, high-level surface.
//!
//! Operation functions (`encrypt_stream`, `decrypt_stream`, `signcrypt`, etc.) are always
//! addressed via their module path — e.g. `pqfile::encrypt::encrypt_stream`.
//!
//! The typed wrappers in `pqfile::keys` (`PqfPublicKey`, `PqfPrivateKey`, `PqfSigningKey`,
//! `PqfVerifyingKey`) are the recommended way to pass keys; they validate eagerly on
//! construction. Raw `&str` PEM parameters on operation functions are the lower-level
//! alternative when a typed wrapper is not convenient.
//!
//! # Stability
//!
//! The public API is **stable at 1.0**. Items in the modules listed in `STABILITY.md`
//! will not be removed or renamed before a 2.0 release. New items and new
//! `#[non_exhaustive]` variants may be added in minor (1.x) releases without
//! a major version bump. See `STABILITY.md` for the full policy.

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

pub(crate) mod passphrase;

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

/// Add a recipient to an existing multi-recipient file without re-encrypting.
pub mod add_recipient;

/// File header inspection without decryption.
pub mod inspect;

/// Typed key wrapper structs (`PqfPublicKey`, `PqfPrivateKey`, `PqfSigningKey`, `PqfVerifyingKey`).
pub mod keys;

/// Secure file shredding: overwrite then delete.
pub mod shred;

/// Passphrase upgrade: change or migrate the passphrase on any encrypted private key.
pub mod repassphrase;

/// Hardware-backed private key support: OS credential store, future PKCS#11.
pub mod hardware;

/// Async encrypt / decrypt streaming via `tokio::io` (requires the `async` feature).
#[cfg(feature = "async")]
pub mod async_io;

// ── Crate-root re-exports ──────────────────────────────────────────────────

pub use error::PqfileError;
pub use format::CHUNK_SIZE;
pub use inspect::{inspect_stream, PqfHeaderInfo, RecipientInfo};
pub use keys::{PqfPrivateKey, PqfPublicKey, PqfSigningKey, PqfVerifyingKey};
pub use reader::{PqfInfo, PqfReader};
