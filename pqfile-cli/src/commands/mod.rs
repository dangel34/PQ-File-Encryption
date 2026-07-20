//! One module per CLI subcommand family. `main.rs` holds only argument
//! parsing (`Cli`/`Command`/`TlockCommand`) and dispatch; every subcommand's
//! actual logic lives here.

pub(crate) mod archive;
pub(crate) mod cert;
pub(crate) mod decrypt;
pub(crate) mod encrypt;
pub(crate) mod inspect;
pub(crate) mod keygen;
pub(crate) mod keys;
pub(crate) mod sealed_sender;
pub(crate) mod shamir;
pub(crate) mod sign;
#[cfg(feature = "stego")]
pub(crate) mod stego;
