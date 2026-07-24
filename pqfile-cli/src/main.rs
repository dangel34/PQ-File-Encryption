use std::io;
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use rayon::ThreadPoolBuilder;

use pqfile::error::PqfileError;

mod commands;
mod config;
#[cfg(feature = "fido2")]
mod fido2;
#[cfg(feature = "fido2")]
mod hex_lines;
mod interactive;
mod io_util;
mod json_util;
mod prompts;
#[cfg(feature = "update-check")]
mod update_check;
#[cfg(feature = "update-check")]
mod update_check_common;

use commands::archive::{run_archive, run_extract};
#[cfg(feature = "audit")]
use commands::audit::run_audit_verify;
use commands::cert::{run_issue_cert, run_revoke_cert, run_verify_cert};
#[cfg(feature = "tlock")]
use commands::decrypt::run_tlock_round;
use commands::decrypt::{run_check, run_decrypt};
use commands::encrypt::{run_encrypt, EncryptOpts};
use commands::inspect::{inspect, run_calibrate, run_doctor};
#[cfg(feature = "fido2")]
use commands::keygen::run_fido2_enroll;
use commands::keygen::{run_fingerprint, run_import_key, run_keygen};
use commands::keys::{run_add_recipient, run_rekey, run_repassphrase, run_revoke, run_rotate};
use commands::sealed_sender::{run_identity_keygen, run_seal, run_unseal};
use commands::shamir::{run_reconstruct_key, run_split_key};
use commands::sign::{
    run_sign, run_sign_keygen, run_signcrypt, run_signdecrypt, run_verify, SigAlgorithmArg,
};
#[cfg(feature = "stego")]
use commands::stego::{run_bury, run_exhume};
use interactive::run_interactive;
use json_util::json_error_from;
#[cfg(feature = "update-check")]
use update_check::run_check_update;

#[derive(Parser)]
#[command(
    name = "pqfile",
    version,
    about = "Quantum-resistant file encryption for the post-quantum era. Encrypt any file with a public key. Only the matching private key can decrypt it."
)]
struct Cli {
    /// Emit machine-readable JSON to stdout (errors go to stderr as JSON).
    #[arg(long, global = true)]
    json: bool,

    /// Maximum Rayon worker threads for --parallel operations (0 = all cores).
    #[arg(long, global = true, value_name = "N", default_value_t = 0)]
    threads: usize,

    /// Ignore the user config file (~/.config/pqfile/config.toml, or
    /// %APPDATA%\pqfile\config.toml on Windows). Recommended for scripts.
    #[arg(long, global = true, default_value_t = false)]
    no_config: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new ML-KEM (or hybrid X25519+ML-KEM) key pair.
    Keygen {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Overwrite existing key files without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Protect the private key with a passphrase (prompted interactively).
        /// Cannot be combined with --hardware.
        #[arg(long, default_value_t = false)]
        passphrase: bool,
        /// KEM security level: 512 (ML-KEM-512), 768 (ML-KEM-768, default), or 1024 (ML-KEM-1024).
        #[arg(long, value_name = "LEVEL", default_value_t = 768u16)]
        level: u16,
        /// Generate a Hybrid X25519+ML-KEM-768 key pair for combined classical+PQ security.
        #[arg(long, default_value_t = false)]
        hybrid: bool,
        /// Store the private key in the OS credential store (hardware-backed).
        /// The seed never touches disk; only a reference stub is written.
        #[arg(long, default_value_t = false)]
        hardware: bool,
        /// Human-readable label for the hardware key (required with --hardware).
        #[arg(long, value_name = "LABEL")]
        label: Option<String>,
        /// Embed an expiry date comment in the PEM files (format: YYYY-MM-DD).
        /// Purely informational; pqfile checks and displays expiry but does not
        /// enforce it cryptographically. Cannot be combined with --hardware.
        #[arg(long, value_name = "DATE")]
        expiry: Option<String>,
        /// Print the recipient string as a scannable QR code (terminal unicode).
        /// ML-KEM-1024 and hybrid keys produce dense codes; a larger terminal
        /// font or screenshot-zoom may be needed to scan them.
        #[arg(long, default_value_t = false)]
        qr: bool,
    },
    /// Encrypt a file to one or more recipients, or with a passphrase (v10).
    Encrypt {
        /// Recipient public key(s): a path to a pubkey.pem file, or a `pqf1…` recipient string.
        /// Repeat -r for multiple recipients (v4 format). Mutually exclusive with --passphrase.
        #[arg(short = 'r', value_name = "PUBKEY", action = clap::ArgAction::Append, conflicts_with = "passphrase_only")]
        recipients: Vec<String>,
        /// CA verifying key to check any certificate passed via -r against.
        /// Required only when one or more -r arguments is a certificate PEM
        /// (produced by `issue-cert`) rather than a raw public key.
        #[arg(long, value_name = "CA_VERIFYING_KEY")]
        ca_key: Option<PathBuf>,
        /// CA-signed revocation list to check any certificate passed via -r against.
        /// Optional; -r certificates are accepted even without a matching entry when omitted.
        #[arg(long, value_name = "FILE")]
        revocations: Option<PathBuf>,
        /// Encrypt without a key pair: derive the session key directly from a passphrase (v10 format).
        /// The passphrase is prompted interactively. Mutually exclusive with -r.
        #[arg(
            long = "passphrase",
            default_value_t = false,
            conflicts_with = "recipients"
        )]
        passphrase_only: bool,
        /// Input file to encrypt, or '-' to read from stdin.
        input: String,
        /// Write encrypted output to this path, or '-' for stdout.
        /// Defaults to <input>.pqf. Ignored in --recursive mode.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Encrypt every file in a directory tree. INPUT must be a directory.
        /// Each file is written alongside the original as `<file>.pqf`.
        #[arg(long, default_value_t = false)]
        recursive: bool,
        /// Chunk size in bytes for streaming encryption (default: 0 = auto-tune).
        /// 0 = pick automatically: 16 KiB for files <1 MiB, 256 KiB for files >256 MiB, 64 KiB otherwise.
        /// Any non-zero value is used directly and produces v5 format if it differs from 65536.
        /// Must be in the range 1..=268435456. Not supported with multiple recipients.
        #[arg(long, value_name = "BYTES", default_value_t = 0)]
        chunk_size: usize,
        /// Compress plaintext with zstd before encrypting (produces v6 format). Not supported on WASM.
        #[arg(long, default_value_t = false)]
        compress: bool,
        /// zstd compression level (1=fastest, 22=best). Only used with --compress.
        #[arg(long, value_name = "LEVEL", default_value_t = 3)]
        compress_level: i32,
        /// Encrypt chunks in parallel using rayon. Not supported with multiple recipients or --compress.
        #[arg(long, default_value_t = false)]
        parallel: bool,
        /// Overlap disk reads and AEAD encryption using a two-buffer pipeline.
        /// Best for I/O-bound storage (spinning disk, NFS). Incompatible with --parallel.
        #[arg(long, default_value_t = false)]
        pipeline: bool,
        /// Map the source file into memory (mmap) instead of reading through a buffer.
        /// Can improve throughput for files ≥100 MiB on systems with fast page cache.
        /// Native builds only; ignored on WASM. Incompatible with --parallel and --compress.
        #[arg(long, default_value_t = false)]
        mmap: bool,
        /// Hide recipient identities in multi-recipient files (v8 format): all KEM ciphertexts are
        /// padded to a uniform size and recipient entries are written in random order.
        /// Requires multiple -r recipients; has no effect with a single recipient.
        #[arg(long, default_value_t = false)]
        anonymous_recipients: bool,
        /// Pad the recipient list to the next power of two with random dummy slots (v9 format).
        /// Combined with --anonymous-recipients to hide both key type and exact recipient count.
        /// Requires multiple -r recipients.
        #[arg(long, default_value_t = false)]
        pad_recipients: bool,
        /// Argon2id memory cost (KiB) for --passphrase (v10) encryption (default: 65536 = 64 MiB).
        /// Run `pqfile doctor --calibrate` for a machine-tuned recommendation. Values above the
        /// default produce files that need --max-kdf-mem raised at decryption time.
        #[arg(long, value_name = "KIB", default_value_t = 65536u32, requires = "passphrase_only",
              value_parser = clap::value_parser!(u32).range(65536..=4_194_304))]
        kdf_mem: u32,
        /// Argon2id time cost (iterations) for --passphrase (v10) encryption (default: 3).
        /// Values above the default produce files that need --max-kdf-time raised at decryption time.
        #[arg(long, value_name = "ITERS", default_value_t = 3u32, requires = "passphrase_only",
              value_parser = clap::value_parser!(u32).range(3..=64))]
        kdf_time: u32,
        /// Mix this file into the --passphrase (v10) key derivation as a second factor.
        /// Decryption then requires both the passphrase and the same keyfile
        /// (`decrypt --passphrase --keyfile <PATH>`). Any non-empty file works; guard it
        /// like a private key.
        #[arg(long, value_name = "PATH", requires = "passphrase_only")]
        keyfile: Option<PathBuf>,
        /// Mix a FIDO2 hardware token's hmac-secret output into the --passphrase
        /// (v10) key derivation as a second factor, instead of --keyfile (the two
        /// are mutually exclusive). Pass the enrollment file created by
        /// `pqfile fido2-enroll`.
        #[cfg(feature = "fido2")]
        #[arg(
            long,
            value_name = "ENROLLMENT_FILE",
            requires = "passphrase_only",
            conflicts_with = "keyfile"
        )]
        fido2: Option<PathBuf>,
        /// Pad the plaintext length to a Padmé bucket before encrypting, so the
        /// ciphertext length no longer reveals the exact plaintext size (only a
        /// coarser range; overhead is at most ~12%). The true size still travels
        /// in the authenticated header, so decryption strips the padding back off
        /// automatically - no flag needed at decrypt time. Requires a known,
        /// non-zero input size, so it is incompatible with stdin input, empty
        /// files, --mmap, --pipeline, and --compress (compression would shrink
        /// the padding back down, defeating it).
        #[arg(long, default_value_t = false)]
        pad: bool,
        /// Produce magic-free, unidentifiable ciphertext carrying no header at
        /// all (single recipient only); the recipient must already know to
        /// pass --stealth at decrypt time. See FORMAT.md 5.10.
        #[arg(long, default_value_t = false)]
        stealth: bool,
        /// Time-lock this file to a drand beacon round instead of a recipient key
        /// or passphrase: nobody (including the sender) can decrypt it before
        /// this round's threshold signature is published. Get a round number
        /// from `pqfile tlock round`. Uses the League of Entropy mainnet
        /// `quicknet` chain. Mutually exclusive with -r and --passphrase.
        #[cfg(feature = "tlock")]
        #[arg(
            long,
            value_name = "ROUND",
            conflicts_with_all = ["recipients", "passphrase_only"]
        )]
        tlock_round: Option<u64>,
        /// Resume an interrupted encryption instead of restarting from byte
        /// zero, using a checkpoint sidecar (`<output>.pqfck`) written every
        /// ~64 MiB of progress. If no checkpoint exists yet, starts a fresh
        /// encryption and begins writing one; on success the checkpoint is
        /// deleted. Single recipient only; INPUT and -o must both be real
        /// files (not `-`). The checkpoint holds the session key in the
        /// clear (there is no recipient private key available mid-encrypt
        /// to protect it with) - guard it like a private key, and delete it
        /// along with the partial output to abandon a resume attempt.
        #[arg(
            long,
            default_value_t = false,
            conflicts_with_all = ["recursive", "passphrase_only", "compress", "parallel", "pipeline", "mmap", "stealth"]
        )]
        resume: bool,
        /// Write a Reed-Solomon forward-error-correction sidecar
        /// (`<output>.pqf.fec`) alongside the output, protecting against bit
        /// rot on cold storage (corrects up to ~3% random byte corruption
        /// per block; no help against deliberate tampering, which the
        /// existing AEAD authentication already covers). Applies uniformly
        /// to any format this produces; not supported with stdout output or
        /// `--recursive` (each recursive output would need its own sidecar,
        /// not yet wired).
        #[cfg(feature = "fec")]
        #[arg(long, default_value_t = false, conflicts_with = "recursive")]
        fec: bool,
        /// Append a signed, encrypted record of this operation to an audit
        /// log. Falls back to the config file's `audit_log` default when
        /// omitted. Must be set together with --audit-key and
        /// --audit-recipient (all three, or none). Not supported with
        /// --recursive: each file would re-prompt for the signing key's
        /// passphrase, since a fresh operator key is resolved per event.
        #[cfg(feature = "audit")]
        #[arg(long, value_name = "PATH", conflicts_with = "recursive")]
        audit_log: Option<PathBuf>,
        /// Your own signing key (ML-DSA or SLH-DSA), used to sign each
        /// audit record so a verifier can tell it came from you. Falls back
        /// to the config file's `audit_key` default.
        #[cfg(feature = "audit")]
        #[arg(long, value_name = "SIGNING_KEY", conflicts_with = "recursive")]
        audit_key: Option<PathBuf>,
        /// The auditor's ML-KEM public key (or `pqf1…` recipient string);
        /// each record is encrypted to this key, so only the auditor can
        /// read the log's contents. Falls back to the config file's
        /// `audit_recipient` default.
        #[cfg(feature = "audit")]
        #[arg(long, value_name = "PUBKEY", conflicts_with = "recursive")]
        audit_recipient: Option<String>,
    },
    /// Decrypt a file produced by `encrypt`.
    Decrypt {
        /// Private key file for decryption. Required unless --passphrase is set (v10 files).
        #[arg(short = 'k', value_name = "PRIVKEY", conflicts_with = "passphrase_v10")]
        key: Option<PathBuf>,
        /// Encrypted .pqf file to decrypt, or '-' to read from stdin.
        input: String,
        /// Write decrypted output to this path, or '-' for stdout. Defaults to stripping .pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Decrypt chunks in parallel using rayon (only effective for v3/v5 format files).
        #[arg(long, default_value_t = false)]
        parallel: bool,
        /// Decrypt a v10 passphrase-only file. The passphrase is prompted interactively.
        /// Mutually exclusive with -k.
        #[arg(long = "passphrase", default_value_t = false, conflicts_with = "key")]
        passphrase_v10: bool,
        /// Maximum Argon2id memory cost (KiB) accepted from a v10 file header (default: 65536 = 64 MiB).
        /// Files whose m parameter exceeds this are rejected before the KDF runs.
        #[arg(long, value_name = "KIB", default_value_t = 65536u32)]
        max_kdf_mem: u32,
        /// Maximum Argon2id time cost (iterations) accepted from a v10 file header (default: 3).
        #[arg(long, value_name = "ITERS", default_value_t = 3u32)]
        max_kdf_time: u32,
        /// Keyfile used as a second factor at encryption time (v10 --passphrase files
        /// encrypted with `encrypt --keyfile`). Must be the identical file content.
        #[arg(long, value_name = "PATH", requires = "passphrase_v10")]
        keyfile: Option<PathBuf>,
        /// Enrollment file (from `pqfile fido2-enroll`) for a v10 file encrypted
        /// with `encrypt --fido2`. Mutually exclusive with --keyfile.
        #[cfg(feature = "fido2")]
        #[arg(
            long,
            value_name = "ENROLLMENT_FILE",
            requires = "passphrase_v10",
            conflicts_with = "keyfile"
        )]
        fido2: Option<PathBuf>,
        /// Decrypt a file written with `encrypt --stealth`. Requires -k;
        /// mutually exclusive with --passphrase.
        #[arg(long, default_value_t = false)]
        stealth: bool,
        /// Decrypt a file written with `encrypt --tlock-round`. Fetches the
        /// target round's beacon signature over the network. No -k or
        /// --passphrase needed; mutually exclusive with both.
        #[cfg(feature = "tlock")]
        #[arg(long, default_value_t = false, conflicts_with_all = ["key", "passphrase_v10", "stealth"])]
        tlock: bool,
        /// drand HTTP relay to fetch the beacon from (default: the chain's own
        /// default relay, resolved from the file header).
        #[cfg(feature = "tlock")]
        #[arg(long, value_name = "URL", requires = "tlock")]
        tlock_url: Option<String>,
        /// Resume an interrupted decryption instead of restarting from byte
        /// zero: an existing partial output is truncated to its last whole
        /// authenticated chunk and decryption continues from there via
        /// random-access reads into the (unchanged) ciphertext. No separate
        /// checkpoint file is needed - unlike `encrypt --resume`, there is no
        /// secret this side has to persist, since the ciphertext doesn't
        /// change between attempts and -k already supplies the private key
        /// every time. Requires -k; INPUT and -o must both be real files
        /// (not `-`); only for v3/v5 (single-recipient, chunked) files.
        #[arg(
            long,
            default_value_t = false,
            conflicts_with_all = ["passphrase_v10", "stealth", "parallel"]
        )]
        resume: bool,
        /// Repair bit rot using a Reed-Solomon sidecar written by
        /// `encrypt --fec` (`<input>.fec`), before running the normal
        /// authenticated decrypt. An uncorrectable block is passed through
        /// unchanged, so decryption still fails normally in that case - this
        /// only ever helps, never weakens authentication. Requires the
        /// sidecar to exist; not supported with stdin input or `--resume`
        /// (resume needs random-access reads, which the repair pass doesn't
        /// support).
        #[cfg(feature = "fec")]
        #[arg(long, default_value_t = false, conflicts_with = "resume")]
        fec: bool,
        /// Append a signed, encrypted record of this operation to an audit
        /// log. See `encrypt --audit-log`'s help for the full explanation;
        /// must be set together with --audit-key and --audit-recipient.
        #[cfg(feature = "audit")]
        #[arg(long, value_name = "PATH")]
        audit_log: Option<PathBuf>,
        /// Your own signing key (ML-DSA or SLH-DSA), used to sign each
        /// audit record.
        #[cfg(feature = "audit")]
        #[arg(long, value_name = "SIGNING_KEY")]
        audit_key: Option<PathBuf>,
        /// The auditor's ML-KEM public key (or `pqf1…` recipient string).
        #[cfg(feature = "audit")]
        #[arg(long, value_name = "PUBKEY")]
        audit_recipient: Option<String>,
    },
    /// Verify that a .pqf file authenticates end-to-end without writing any plaintext.
    ///
    /// Runs the full decryption path into a null sink: every chunk's AEAD tag (and,
    /// for v10 files, the KDF parameter ceiling) is checked exactly as in a real
    /// decrypt, but no plaintext is written anywhere. Useful for validating backups
    /// and testing keys without producing a cleartext copy.
    Check {
        /// Private key file for decryption. Required unless --passphrase is set (v10 files).
        #[arg(short = 'k', value_name = "PRIVKEY", conflicts_with = "passphrase_v10")]
        key: Option<PathBuf>,
        /// Encrypted .pqf file to check, or '-' to read from stdin.
        input: String,
        /// Check chunks in parallel using rayon (only effective for v3/v5 format files).
        #[arg(long, default_value_t = false)]
        parallel: bool,
        /// Check a v10 passphrase-only file. The passphrase is prompted interactively.
        /// Mutually exclusive with -k.
        #[arg(long = "passphrase", default_value_t = false, conflicts_with = "key")]
        passphrase_v10: bool,
        /// Maximum Argon2id memory cost (KiB) accepted from a v10 file header (default: 65536 = 64 MiB).
        #[arg(long, value_name = "KIB", default_value_t = 65536u32)]
        max_kdf_mem: u32,
        /// Maximum Argon2id time cost (iterations) accepted from a v10 file header (default: 3).
        #[arg(long, value_name = "ITERS", default_value_t = 3u32)]
        max_kdf_time: u32,
        /// Keyfile used as a second factor at encryption time (v10 --passphrase files
        /// encrypted with `encrypt --keyfile`). Must be the identical file content.
        #[arg(long, value_name = "PATH", requires = "passphrase_v10")]
        keyfile: Option<PathBuf>,
        /// Enrollment file (from `pqfile fido2-enroll`) for a v10 file encrypted
        /// with `encrypt --fido2`. Mutually exclusive with --keyfile.
        #[cfg(feature = "fido2")]
        #[arg(
            long,
            value_name = "ENROLLMENT_FILE",
            requires = "passphrase_v10",
            conflicts_with = "keyfile"
        )]
        fido2: Option<PathBuf>,
        /// Check a file written with `encrypt --stealth`. Requires -k; mutually
        /// exclusive with --passphrase.
        #[arg(long, default_value_t = false, conflicts_with = "passphrase_v10")]
        stealth: bool,
        /// Check a file written with `encrypt --tlock-round`. Fetches the
        /// target round's beacon signature over the network. No -k or
        /// --passphrase needed; mutually exclusive with both.
        #[cfg(feature = "tlock")]
        #[arg(long, default_value_t = false, conflicts_with_all = ["key", "passphrase_v10", "stealth"])]
        tlock: bool,
        /// drand HTTP relay to fetch the beacon from (default: the chain's own
        /// default relay, resolved from the file header).
        #[cfg(feature = "tlock")]
        #[arg(long, value_name = "URL", requires = "tlock")]
        tlock_url: Option<String>,
        /// Repair bit rot using a Reed-Solomon sidecar written by
        /// `encrypt --fec` (`<input>.fec`), before running the normal
        /// authenticated check. An uncorrectable block is passed through
        /// unchanged, so the check still fails normally in that case.
        /// Requires the sidecar to exist; not supported with stdin input.
        #[cfg(feature = "fec")]
        #[arg(long, default_value_t = false)]
        fec: bool,
    },
    /// Print a .pqf file's header fields (version, KEM variant, recipient count)
    /// without decrypting the payload.
    Inspect {
        /// Encrypted .pqf file to inspect.
        input: PathBuf,
    },
    /// Verify an `--audit-log`: decrypts every record with the auditor's
    /// private key, checks each one's signature against the operator's
    /// verifying key, and checks the hash chain end to end. Reports which
    /// record (if any) failed and why - a broken chain means an entry was
    /// deleted, reordered, or forged without the operator's signing key.
    ///
    /// The chain check alone cannot detect entries deleted off the *end* of
    /// the log (a truncated log is still internally consistent up to
    /// wherever it stops) - only `--expect-tip`, compared against a tip
    /// saved from a prior run, catches that. Every run prints a `tip:` line
    /// with the log's actual final chain hash to save for next time.
    #[cfg(feature = "audit")]
    #[command(name = "audit-verify")]
    AuditVerify {
        /// The audit log file written by `encrypt --audit-log` / `decrypt --audit-log`.
        log: PathBuf,
        /// The auditor's private key (decrypts each record).
        #[arg(long, value_name = "PRIVKEY")]
        auditor_key: PathBuf,
        /// The operator's verifying key (checks each record's signature).
        #[arg(long, value_name = "VERIFYING_KEY")]
        operator_key: PathBuf,
        /// The log's expected final chain hash (the `tip:` line from a
        /// previous `audit-verify` run), 64 hex characters. Without this,
        /// entries silently deleted from the end of the log go undetected.
        #[arg(long, value_name = "HEX")]
        expect_tip: Option<String>,
    },
    /// Enroll a FIDO2 hardware security key as a v10 second factor.
    ///
    /// Creates a non-resident CTAP2 credential on the attached authenticator
    /// requesting the hmac-secret extension, and writes an enrollment file
    /// recording the credential ID and a fresh random salt. Pass that file to
    /// `encrypt --fido2` / `decrypt --fido2` / `check --fido2` in place of
    /// `--keyfile`. The enrollment file is not sensitive on its own:
    /// reproducing the derived secret requires physically touching the same
    /// token, so it is fine to store or back up like ordinary configuration.
    #[cfg(feature = "fido2")]
    #[command(name = "fido2-enroll")]
    Fido2Enroll {
        /// Path to write the enrollment file.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: PathBuf,
        /// Overwrite an existing enrollment file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// This token requires a PIN; prompt for it now and record that
        /// `--fido2` must prompt for one too when deriving the secret later.
        #[arg(long, default_value_t = false)]
        pin: bool,
    },
    /// Time-locked encryption helpers (drand beacon).
    #[cfg(feature = "tlock")]
    Tlock {
        #[command(subcommand)]
        action: TlockCommand,
    },
    /// Print a shell completion script to stdout.
    ///
    /// Examples:
    ///   pqfile completions bash   >> ~/.bash_completion
    ///   pqfile completions zsh    > ~/.zfunc/_pqfile
    ///   pqfile completions fish   > ~/.config/fish/completions/pqfile.fish
    ///   pqfile completions powershell >> $PROFILE
    Completions {
        /// Target shell (bash, zsh, fish, powershell, elvish).
        shell: Shell,
    },
    /// Print a roff man page for `pqfile` (and every subcommand) to stdout.
    ///
    /// Example: pqfile man > /usr/local/share/man/man1/pqfile.1
    Man,
    /// Generate a signing key pair (ML-DSA-65 by default, or SLH-DSA-SHAKE-192f).
    #[command(name = "sign-keygen")]
    SignKeygen {
        /// Directory to write sign_pubkey.pem and sign_privkey.pem.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Overwrite existing key files without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Protect the signing private key with a passphrase (prompted interactively).
        /// Cannot be combined with --hardware.
        #[arg(long, default_value_t = false)]
        passphrase: bool,
        /// Store the signing key in the OS credential store (hardware-backed).
        #[arg(long, default_value_t = false)]
        hardware: bool,
        /// Human-readable label for the hardware key (required with --hardware).
        #[arg(long, value_name = "LABEL")]
        label: Option<String>,
        /// Signature algorithm. SLH-DSA is hash-based: slower signing and larger
        /// signatures (35 KB vs 3.3 KB), but rests on more conservative security
        /// assumptions; suited to long-lived signatures.
        #[arg(long, value_enum, default_value_t = SigAlgorithmArg::MlDsa65)]
        algorithm: SigAlgorithmArg,
    },
    /// Sign a file with a signing key, producing a detached .sig file.
    ///
    /// The signature algorithm (ML-DSA-65 or SLH-DSA-SHAKE-192f) is taken from
    /// the key itself.
    Sign {
        /// Path to sign_privkey.pem (signing key).
        #[arg(short = 'k', value_name = "SIGNING_KEY")]
        key: PathBuf,
        /// File to sign.
        input: PathBuf,
        /// Output path for the detached signature (defaults to <input>.sig).
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Verify a detached signature against a file.
    ///
    /// The signature algorithm (ML-DSA-65 or SLH-DSA-SHAKE-192f) is taken from
    /// the verifying key itself.
    Verify {
        /// Path to sign_pubkey.pem (verifying key), or a certificate PEM
        /// produced by `issue-cert` (requires --ca-key).
        #[arg(short = 'k', value_name = "VERIFYING_KEY")]
        key: PathBuf,
        /// CA verifying key to check -k against, if -k is a certificate PEM.
        #[arg(long, value_name = "CA_VERIFYING_KEY")]
        ca_key: Option<PathBuf>,
        /// CA-signed revocation list to check a -k certificate against. Optional.
        #[arg(long, value_name = "FILE")]
        revocations: Option<PathBuf>,
        /// Detached signature file (.sig).
        #[arg(short = 's', value_name = "SIG")]
        sig: PathBuf,
        /// File whose signature is being verified.
        input: PathBuf,
    },
    /// Mark a public key as revoked, creating a .revoked sidecar file.
    ///
    /// Any subsequent `encrypt` using that public key file path will fail.
    Revoke {
        /// Path to the public key file to revoke (pubkey.pem).
        #[arg(short = 'k', value_name = "PUBKEY")]
        key: PathBuf,
        /// Human-readable reason for revocation.
        #[arg(long, value_name = "TEXT", default_value = "")]
        reason: String,
    },
    /// Rekey a v3/v5 encrypted file to a new recipient without re-encrypting the payload.
    ///
    /// Reads the file encrypted to the old key and produces a v4 file decryptable by the new key.
    /// Only works for files using the default chunk size (65536 bytes).
    Rekey {
        /// Old private key used to decrypt the existing file.
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        /// New recipient public key.
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        /// Encrypted .pqf file to rekey, or '-' to read from stdin.
        input: String,
        /// Output path for the rekeyed file, or '-' for stdout. Defaults to overwriting the input.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Overwrite an existing output file without prompting. Note: the default output path
        /// is the input file itself, so rekey overwrites the input in place unless -o is given.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Batch-rekey every .pqf file under a directory tree to a new recipient.
    ///
    /// A thin wrapper around `rekey`: walks the tree and rewrites each v3/v5
    /// .pqf file in place, in the same default-chunk-size restriction rekey
    /// itself has. Distinct from `archive --recursive`, which packs a tree
    /// into one .pqfa rather than rotating keys across many independent
    /// .pqf files. Non-.pqf files are left untouched; a .pqf file rekey
    /// cannot handle (e.g. multi-recipient v4/v7-v9, v6 compressed, v10
    /// passphrase-only, a non-default chunk size) is reported as failed
    /// rather than silently skipped.
    Rotate {
        /// Old private key used to decrypt each existing file.
        #[arg(long, value_name = "PRIVKEY")]
        old_key: PathBuf,
        /// New recipient public key.
        #[arg(long, value_name = "PUBKEY")]
        new_key: PathBuf,
        /// Directory to walk. Every .pqf file found (recursively) is rewritten in place.
        input: String,
        /// Required to confirm rewriting every .pqf file under the directory.
        #[arg(long, default_value_t = false)]
        recursive: bool,
    },
    /// Add a recipient to an existing v4/v7/v8 multi-recipient file without
    /// re-encrypting the payload (zero-copy).
    ///
    /// Requires one existing recipient's private key to recover the session key.
    /// For v7/v8 (anonymous) files, the new entry is appended at the end, which
    /// reveals its position to an observer comparing the file before and after;
    /// re-encrypt with --anonymous-recipients to restore full shuffle anonymity.
    #[command(name = "add-recipient")]
    AddRecipient {
        /// Private key of an existing recipient, used to recover the session key.
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        /// New recipient's public key to add.
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        /// Encrypted .pqf file to add a recipient to, or '-' to read from stdin.
        input: String,
        /// Output path for the updated file, or '-' for stdout. Defaults to overwriting the input.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Overwrite an existing output file without prompting. Note: the default output path
        /// is the input file itself, so add-recipient overwrites the input in place unless -o
        /// is given.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Pack multiple files into a single encrypted archive (.pqf).
    ///
    /// Files are listed in their archive path order. Use --base to strip a leading
    /// directory prefix from each path (archive paths are then relative to --base).
    Archive {
        /// Recipient public key.
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        /// Output archive file (default: archive.pqf).
        #[arg(short = 'o', long, value_name = "FILE", default_value = "archive.pqf")]
        output: PathBuf,
        /// Files to include. Each becomes a top-level entry using its filename.
        /// With --recursive, directories are allowed and archived as a tree.
        #[arg(value_name = "FILE", required = true)]
        files: Vec<PathBuf>,
        /// Strip this prefix from each file path when computing the archive entry name.
        #[arg(long, value_name = "DIR")]
        base: Option<PathBuf>,
        /// Recurse into directories listed as FILE arguments. Entry names keep the
        /// directory name as a prefix (like tar). Symlinks and special files
        /// (devices, FIFOs, sockets) inside the tree are rejected, as are entry
        /// names that collide case-insensitively.
        #[arg(long, default_value_t = false)]
        recursive: bool,
        /// Overwrite an existing archive file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Extract a pqfile archive created with `archive`.
    Extract {
        /// Encrypted archive file (.pqf).
        input: String,
        /// Private decryption key.
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        /// Directory to extract into (default: current directory).
        #[arg(short = 'o', long, value_name = "DIR", default_value = ".")]
        out: PathBuf,
        /// List archive contents without extracting.
        #[arg(long, default_value_t = false)]
        list: bool,
    },
    /// Sign and encrypt a file in one step.
    ///
    /// The ML-DSA-65 signature is embedded inside the encrypted payload so it cannot
    /// be stripped. Use `signdecrypt` to decrypt and verify the sender in one step.
    ///
    /// Note: requires two passes over the input file (to hash then encrypt), so stdin
    /// is not supported as input.
    Signcrypt {
        /// ML-DSA-65 signing key (sign_privkey.pem).
        #[arg(short = 'k', value_name = "SIGNING_KEY")]
        key: PathBuf,
        /// Recipient public key (pubkey.pem), or a certificate PEM produced
        /// by `issue-cert` (requires --ca-key).
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        /// CA verifying key to check -r against, if -r is a certificate PEM.
        #[arg(long, value_name = "CA_VERIFYING_KEY")]
        ca_key: Option<PathBuf>,
        /// CA-signed revocation list to check a -r certificate against. Optional.
        #[arg(long, value_name = "FILE")]
        revocations: Option<PathBuf>,
        /// File to sign and encrypt.
        input: PathBuf,
        /// Output path. Defaults to <input>.pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Decrypt and verify a signcrypted file.
    ///
    /// Decrypts the file and verifies the embedded ML-DSA-65 signature. Plaintext is
    /// written as it is decrypted (streaming); if signature verification fails at the
    /// end, the output should be discarded.
    Signdecrypt {
        /// Private decryption key (privkey.pem).
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        /// Sender's ML-DSA-65 verifying key (sign_pubkey.pem), or a
        /// certificate PEM produced by `issue-cert` (requires --ca-key).
        #[arg(short = 'v', value_name = "VERIFYING_KEY")]
        verifying_key: PathBuf,
        /// CA verifying key to check -v against, if -v is a certificate PEM.
        #[arg(long, value_name = "CA_VERIFYING_KEY")]
        ca_key: Option<PathBuf>,
        /// CA-signed revocation list to check a -v certificate against. Optional.
        #[arg(long, value_name = "FILE")]
        revocations: Option<PathBuf>,
        /// Signcrypted .pqf file to decrypt, or '-' to read from stdin.
        input: String,
        /// Output path. Defaults to stripping .pqf from input.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Generate an X25519 identity key pair for sealed-sender authentication.
    ///
    /// Separate from encryption (`keygen`) and signing (`sign-keygen`) keys: identity
    /// keys exist only to authenticate `seal`/`unseal` to their intended counterparty.
    #[command(name = "identity-keygen")]
    IdentityKeygen {
        /// Directory to write identity_pubkey.pem and identity_privkey.pem.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Overwrite existing key files without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Protect the identity private key with a passphrase (prompted interactively).
        #[arg(long, default_value_t = false)]
        passphrase: bool,
    },
    /// Encrypt a file with deniable sender authentication ("sealed sender").
    ///
    /// Unlike `signcrypt`, which embeds a non-repudiable signature, this proves the
    /// sender's identity only to the specific recipient: the authentication tag is
    /// derived from a static X25519 Diffie-Hellman between the sender's and
    /// recipient's identity keys, so the recipient cannot prove to a third party
    /// who sent the file (they could have forged the same tag themselves).
    ///
    /// Note: requires two passes over the input file (to hash then encrypt), so stdin
    /// is not supported as input.
    Seal {
        /// Sender's identity private key (identity_privkey.pem).
        #[arg(short = 'k', value_name = "IDENTITY_KEY")]
        key: PathBuf,
        /// Recipient's identity public key (identity_pubkey.pem).
        #[arg(long, value_name = "IDENTITY_PUBKEY")]
        recipient_identity: PathBuf,
        /// Recipient's encryption public key (pubkey.pem), or a certificate PEM
        /// produced by `issue-cert` (requires --ca-key).
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        /// CA verifying key to check -r against, if -r is a certificate PEM.
        #[arg(long, value_name = "CA_VERIFYING_KEY")]
        ca_key: Option<PathBuf>,
        /// CA-signed revocation list to check a -r certificate against. Optional.
        #[arg(long, value_name = "FILE")]
        revocations: Option<PathBuf>,
        /// File to seal and encrypt.
        input: PathBuf,
        /// Output path. Defaults to <input>.pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Decrypt and verify a sealed-sender file.
    ///
    /// Decrypts the file and verifies the deniable authentication tag against the
    /// claimed sender's identity key. Unlike `signdecrypt`, plaintext is only
    /// released once verification succeeds (buffered internally).
    Unseal {
        /// Recipient's decryption private key (privkey.pem).
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        /// Recipient's own identity private key (identity_privkey.pem).
        #[arg(long, value_name = "IDENTITY_KEY")]
        identity_key: PathBuf,
        /// Sender's identity public key (identity_pubkey.pem).
        #[arg(short = 's', value_name = "SENDER_IDENTITY_PUBKEY")]
        sender_identity: PathBuf,
        /// Sealed-sender .pqf file to decrypt, or '-' to read from stdin.
        input: String,
        /// Output path. Defaults to stripping .pqf from input.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Split a private key into M-of-N Shamir shares.
    ///
    /// Any `threshold` shares can reconstruct the private key; fewer reveal nothing.
    /// Writes share_1.pem ... share_N.pem into --out (or the directory of the key file).
    #[command(name = "split-key")]
    SplitKey {
        /// Private key to split (privkey.pem or a passphrase-protected variant).
        #[arg(value_name = "PRIVKEY")]
        key: PathBuf,
        /// Minimum shares required to reconstruct (>= 2).
        #[arg(long, value_name = "N")]
        threshold: u8,
        /// Total number of shares to produce (>= threshold).
        #[arg(long, value_name = "N")]
        shares: u8,
        /// Directory to write share files. Defaults to the directory of the key file.
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
        /// Overwrite existing share files without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Change or upgrade the passphrase on any encrypted private key.
    ///
    /// Reads the key with the old passphrase and re-encrypts it with the new one
    /// using the current Argon2id parameters (p=4).
    ///
    /// Use --from-legacy when migrating a key created with pqfile < 4.0 (Argon2id p=1).
    /// Without --from-legacy, passing a legacy key returns an error directing you to add it.
    #[command(name = "repassphrase")]
    Repassphrase {
        /// Path to the encrypted private key file to update.
        #[arg(short = 'k', value_name = "KEY")]
        key: PathBuf,
        /// Read the key using legacy Argon2id p=1 parameters (pqfile < 4.0 keys).
        /// Required when migrating old keys; causes an error if set on a p=4 key.
        #[arg(long, default_value_t = false)]
        from_legacy: bool,
    },

    /// Reconstruct a private key from M-of-N Shamir shares.
    ///
    /// Provide at least `threshold` share files produced by `split-key`.
    /// Writes privkey.pem and pubkey.pem to --out (or current directory).
    #[command(name = "reconstruct-key")]
    ReconstructKey {
        /// Share PEM files (share_1.pem, share_3.pem, ...). At least `threshold` required.
        #[arg(value_name = "SHARE", required = true)]
        shares: Vec<PathBuf>,
        /// Directory to write the reconstructed privkey.pem and pubkey.pem.
        #[arg(long, value_name = "DIR", default_value = ".")]
        out: PathBuf,
        /// Overwrite existing key files without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Inspect a key file or .pqf file and report a structured health summary.
    ///
    /// For key files: reports passphrase protection status, legacy Argon2id
    /// parameter detection (p=1 vs p=4), hardware stub validity, and revocation
    /// sidecar presence.
    ///
    /// For .pqf files: reports the format version, KEM variant(s), and whether
    /// the header passes sanity checks, without decrypting the payload.
    Doctor {
        /// Path to a private key file (.pem) or an encrypted file (.pqf) to inspect.
        /// Not used with --calibrate.
        #[arg(value_name = "FILE", required_unless_present = "calibrate")]
        file: Option<PathBuf>,
        /// Companion public key path for revocation sidecar check (key files only).
        /// If omitted, the sidecar check is skipped.
        #[arg(long, value_name = "PUBKEY", conflicts_with = "calibrate")]
        pubkey: Option<PathBuf>,
        /// Benchmark Argon2id on this machine and recommend --kdf-mem / --kdf-time
        /// values for `encrypt --passphrase` (v10) that hit the target wall-clock time.
        #[arg(long, default_value_t = false)]
        calibrate: bool,
        /// Target wall-clock time for --calibrate, in milliseconds.
        #[arg(long, value_name = "MS", default_value_t = 250, requires = "calibrate",
              value_parser = clap::value_parser!(u64).range(50..=10_000))]
        target_ms: u64,
    },

    /// Check whether a newer pqfile release is available.
    ///
    /// Queries the GitHub Releases API and compares the latest tag against
    /// this binary's own version. Never downloads or installs anything -
    /// only reports the comparison. Requires the `update-check` feature
    /// (not part of a plain `cargo build`, but included in the published
    /// release binaries).
    #[cfg(feature = "update-check")]
    CheckUpdate,

    /// Print the fingerprint and Bech32 recipient string for a public key.
    ///
    /// Accepts either a path to a pubkey.pem file, or a `pqf1…` recipient string directly.
    Fingerprint {
        /// Public key: path to pubkey.pem or a `pqf1…` recipient string.
        key: String,
        /// Print the recipient string as a scannable QR code (terminal unicode).
        #[arg(long, default_value_t = false)]
        qr: bool,
    },

    /// Import an existing key and derive an ML-KEM-768 key pair from it (one-way migration).
    ImportKey {
        /// Source key file.  Currently only unencrypted OpenSSH ed25519 private keys
        /// (`-----BEGIN OPENSSH PRIVATE KEY-----`) are supported.  Passphrase-protected
        /// SSH keys must be decrypted first (`ssh-keygen -p -f <key> -N ""`).
        #[arg(long, value_name = "FILE")]
        from: PathBuf,
        /// Output directory for pubkey.pem and privkey.pem.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Overwrite existing key files without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Protect the output private key with a passphrase (prompted interactively).
        #[arg(long, default_value_t = false)]
        passphrase: bool,
    },

    /// Issue a certificate: a CA signing key attests to a subject public key's
    /// label, validity window, and permitted uses.
    ///
    /// The subject key can be an ML-KEM/hybrid public key (--allow-encrypt), a
    /// signature verifying key (--allow-sign), or both flags together for a key
    /// that serves both roles. `encrypt -r` accepts the resulting certificate
    /// directly in place of a raw public key when given the matching `--ca-key`.
    #[command(name = "issue-cert")]
    IssueCert {
        /// CA signing key: the certificate is signed with this key.
        #[arg(long, value_name = "CA_SIGNING_KEY")]
        ca_key: PathBuf,
        /// Subject public key to certify: a path to a public/verifying key PEM,
        /// or a `pqf1…` recipient string.
        #[arg(long, value_name = "SUBJECT_KEY")]
        subject: String,
        /// Human-readable label for the subject (free text).
        #[arg(long)]
        label: String,
        /// Validity window start (YYYY-MM-DD, UTC). Defaults to today.
        #[arg(long, value_name = "DATE")]
        not_before: Option<String>,
        /// Validity window length in days, starting at --not-before.
        #[arg(long, value_name = "DAYS", default_value_t = 365u32)]
        valid_days: u32,
        /// Permit the certified key to be used as an encryption recipient.
        #[arg(long, default_value_t = false)]
        allow_encrypt: bool,
        /// Permit the certified key to be used to verify signatures.
        #[arg(long, default_value_t = false)]
        allow_sign: bool,
        /// Output path for the certificate PEM.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: PathBuf,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Verify a certificate against a CA verifying key and print its contents.
    #[command(name = "verify-cert")]
    VerifyCert {
        /// CA verifying key (issuer's public key).
        #[arg(long, value_name = "CA_VERIFYING_KEY")]
        ca_key: PathBuf,
        /// CA-signed revocation list to check the certificate against. Optional.
        #[arg(long, value_name = "FILE")]
        revocations: Option<PathBuf>,
        /// Certificate file to verify.
        cert: PathBuf,
    },

    /// Revoke a certificate before its validity window naturally expires.
    ///
    /// Appends the certificate to a CA-signed revocation list (a compact analogue of
    /// an X.509 CRL) and re-signs the whole list. There is no way to un-revoke a
    /// certificate; issue a new one instead.
    #[command(name = "revoke-cert")]
    RevokeCert {
        /// CA signing key: the same key used to `issue-cert`.
        #[arg(long, value_name = "CA_SIGNING_KEY")]
        ca_key: PathBuf,
        /// Certificate to revoke.
        cert: PathBuf,
        /// Existing revocation list to append to. Starts a fresh list if omitted.
        #[arg(long, value_name = "FILE")]
        existing: Option<PathBuf>,
        /// Human-readable reason (free text).
        #[arg(long, value_name = "TEXT", default_value = "")]
        reason: String,
        /// Output path for the updated revocation list.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: PathBuf,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Hide a file inside a cover image's pixel data (steganographic backup).
    ///
    /// Prompts for a passphrase; the passphrase keys detection itself, so without
    /// it nothing in the image reveals that a payload is present, let alone what
    /// it is. Intended for backing up a (ideally also passphrase-encrypted)
    /// private key PEM somewhere that doesn't look like a key backup, e.g. among
    /// ordinary photos. A statistical LSB-noise analysis can still flag the image
    /// as carrying *something*; the passphrase only prevents confirming or
    /// recovering *what*.
    #[cfg(feature = "stego")]
    Bury {
        /// Cover image (PNG or JPEG).
        #[arg(long, value_name = "IMAGE")]
        image: PathBuf,
        /// File to hide inside the cover image.
        file: PathBuf,
        /// Output path for the resulting image. Must end in `.png`: LSB embedding
        /// only survives a lossless re-encode, so the output is always a PNG
        /// regardless of the cover image's original format.
        #[arg(short = 'o', long, value_name = "FILE.png")]
        output: PathBuf,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },

    /// Recover a file previously hidden with `bury`.
    ///
    /// Prompts for the passphrase used at bury time. A wrong passphrase is
    /// indistinguishable from an image that holds no payload at all - that is
    /// the point of keying detection. The recovered file is written atomically
    /// with owner-only permissions, since it is typically private key material.
    #[cfg(feature = "stego")]
    Exhume {
        /// Image previously produced by `bury`.
        image: PathBuf,
        /// Output path for the recovered file.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: PathBuf,
        /// Overwrite an existing output file without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[cfg(feature = "tlock")]
#[derive(Subcommand)]
enum TlockCommand {
    /// Resolve a human time expression to a drand round number, for use with
    /// `encrypt --tlock-round`. Fetches the chain's public parameters over the
    /// network (never the round's own beacon, which may not exist yet).
    Round {
        /// An absolute round number ("123"), a relative duration ("24h", "30m",
        /// "90s", "7d"), or an RFC 3339 datetime.
        when: String,
        /// drand HTTP relay to query (default: the quicknet chain's own relay).
        #[arg(long, value_name = "URL")]
        relay: Option<String>,
    },
}

fn main() {
    // clap's derive-generated argument-parser construction for this many
    // subcommands/flags is a deep (but finite) call chain once inlining is
    // disabled (debug builds). Windows' default 1MB main-thread stack isn't
    // enough for that depth - `cargo build --release` never hits this - so
    // run everything on a spawned thread with a larger stack instead of
    // directly on the OS-provided main thread. This is a standard, portable
    // workaround (not platform-specific linker flags) and has no effect on
    // program behavior.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(run_main)
        .expect("failed to spawn main worker thread")
        .join()
        .expect("main worker thread panicked");
}

fn run_main() {
    // Bare invocation (no arguments at all) drops into a guided prompt flow
    // instead of clap's usage/help text. Any argument, including a bare
    // `--help` or `--json`, takes the normal clap path below.
    if std::env::args().count() <= 1 {
        if let Err(e) = run_interactive() {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let cli = Cli::parse();
    let json = cli.json;
    if let Err(e) = run(cli) {
        if json {
            eprintln!("{}", json_error_from(&e));
        } else {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), PqfileError> {
    let json = cli.json;
    let no_config = cli.no_config;
    if cli.threads > 0 {
        ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
            .map_err(|e| PqfileError::Io(io::Error::other(e)))?;
    }
    match cli.command {
        Command::Keygen {
            out,
            force,
            passphrase,
            level,
            hybrid,
            hardware,
            qr,
            label,
            expiry,
        } => run_keygen(
            out, force, level, hybrid, passphrase, hardware, label, expiry, qr, json,
        ),
        Command::Encrypt {
            recipients,
            ca_key,
            revocations,
            input,
            output,
            force,
            recursive,
            chunk_size,
            compress,
            compress_level,
            parallel,
            pipeline,
            mmap,
            anonymous_recipients,
            pad_recipients,
            passphrase_only,
            kdf_mem,
            kdf_time,
            keyfile,
            #[cfg(feature = "fido2")]
            fido2,
            pad,
            stealth,
            #[cfg(feature = "tlock")]
            tlock_round,
            resume,
            #[cfg(feature = "fec")]
            fec,
            #[cfg(feature = "audit")]
            audit_log,
            #[cfg(feature = "audit")]
            audit_key,
            #[cfg(feature = "audit")]
            audit_recipient,
        } => run_encrypt(
            recipients,
            ca_key,
            revocations,
            passphrase_only,
            #[cfg(feature = "tlock")]
            tlock_round,
            #[cfg(not(feature = "tlock"))]
            None,
            no_config,
            input,
            output,
            recursive,
            EncryptOpts {
                chunk_size,
                compress,
                compress_level,
                parallel,
                pipeline,
                mmap,
                anonymous_recipients,
                pad_recipients,
                force,
                json,
                kdf_mem,
                kdf_time,
                keyfile,
                #[cfg(feature = "fido2")]
                fido2,
                #[cfg(not(feature = "fido2"))]
                fido2: None,
                pad,
                stealth,
                resume,
                #[cfg(feature = "fec")]
                fec,
                #[cfg(not(feature = "fec"))]
                fec: false,
                #[cfg(feature = "audit")]
                audit_log,
                #[cfg(not(feature = "audit"))]
                audit_log: None,
                #[cfg(feature = "audit")]
                audit_key,
                #[cfg(not(feature = "audit"))]
                audit_key: None,
                #[cfg(feature = "audit")]
                audit_recipient,
                #[cfg(not(feature = "audit"))]
                audit_recipient: None,
            },
        ),
        Command::Decrypt {
            key,
            input,
            output,
            force,
            parallel,
            passphrase_v10,
            max_kdf_mem,
            max_kdf_time,
            keyfile,
            #[cfg(feature = "fido2")]
            fido2,
            stealth,
            #[cfg(feature = "tlock")]
            tlock,
            #[cfg(feature = "tlock")]
            tlock_url,
            resume,
            #[cfg(feature = "fec")]
            fec,
            #[cfg(feature = "audit")]
            audit_log,
            #[cfg(feature = "audit")]
            audit_key,
            #[cfg(feature = "audit")]
            audit_recipient,
        } => run_decrypt(
            key,
            passphrase_v10,
            keyfile,
            #[cfg(feature = "fido2")]
            fido2,
            #[cfg(not(feature = "fido2"))]
            None,
            no_config,
            max_kdf_mem,
            max_kdf_time,
            input,
            output,
            parallel,
            force,
            stealth,
            #[cfg(feature = "tlock")]
            tlock,
            #[cfg(not(feature = "tlock"))]
            false,
            #[cfg(feature = "tlock")]
            tlock_url,
            #[cfg(not(feature = "tlock"))]
            None,
            resume,
            #[cfg(feature = "fec")]
            fec,
            #[cfg(not(feature = "fec"))]
            false,
            #[cfg(feature = "audit")]
            audit_log,
            #[cfg(feature = "audit")]
            audit_key,
            #[cfg(feature = "audit")]
            audit_recipient,
            json,
        ),
        Command::Check {
            key,
            input,
            parallel,
            passphrase_v10,
            max_kdf_mem,
            max_kdf_time,
            keyfile,
            #[cfg(feature = "fido2")]
            fido2,
            stealth,
            #[cfg(feature = "tlock")]
            tlock,
            #[cfg(feature = "tlock")]
            tlock_url,
            #[cfg(feature = "fec")]
            fec,
        } => run_check(
            key,
            passphrase_v10,
            keyfile,
            #[cfg(feature = "fido2")]
            fido2,
            #[cfg(not(feature = "fido2"))]
            None,
            no_config,
            max_kdf_mem,
            max_kdf_time,
            input,
            parallel,
            stealth,
            #[cfg(feature = "tlock")]
            tlock,
            #[cfg(not(feature = "tlock"))]
            false,
            #[cfg(feature = "tlock")]
            tlock_url,
            #[cfg(not(feature = "tlock"))]
            None,
            #[cfg(feature = "fec")]
            fec,
            #[cfg(not(feature = "fec"))]
            false,
            json,
        ),
        Command::Inspect { input } => inspect(input.as_path(), json),
        #[cfg(feature = "audit")]
        Command::AuditVerify {
            log,
            auditor_key,
            operator_key,
            expect_tip,
        } => run_audit_verify(
            &log,
            &auditor_key,
            &operator_key,
            expect_tip.as_deref(),
            json,
        ),
        #[cfg(feature = "fido2")]
        Command::Fido2Enroll { output, force, pin } => run_fido2_enroll(output, force, pin, json),
        #[cfg(feature = "tlock")]
        Command::Tlock { action } => match action {
            TlockCommand::Round { when, relay } => run_tlock_round(&when, relay, json),
        },
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "pqfile", &mut io::stdout());
            Ok(())
        }
        Command::Man => {
            let man = clap_mangen::Man::new(Cli::command());
            man.render(&mut io::stdout()).map_err(PqfileError::Io)?;
            Ok(())
        }
        Command::SignKeygen {
            out,
            force,
            passphrase,
            hardware,
            label,
            algorithm,
        } => run_sign_keygen(out, force, passphrase, hardware, label, algorithm, json),
        Command::Sign { key, input, output } => run_sign(key, input, output, json),
        Command::Verify {
            key,
            ca_key,
            revocations,
            sig,
            input,
        } => run_verify(key, ca_key, revocations, sig, input, json),
        Command::Revoke { key, reason } => run_revoke(key, &reason, json),
        Command::Rekey {
            key,
            recipient,
            input,
            output,
            force,
        } => run_rekey(key, recipient, input, output, force, json),
        Command::Rotate {
            old_key,
            new_key,
            input,
            recursive,
        } => run_rotate(old_key, new_key, input, recursive, json),
        Command::AddRecipient {
            key,
            recipient,
            input,
            output,
            force,
        } => run_add_recipient(key, recipient, input, output, force, json),
        Command::Archive {
            recipient,
            output,
            files,
            base,
            recursive,
            force,
        } => run_archive(recipient, output, files, base, recursive, force, json),
        Command::Extract {
            input,
            key,
            out,
            list,
        } => run_extract(input, key, out, list, json),
        Command::Signcrypt {
            key,
            recipient,
            ca_key,
            revocations,
            input,
            output,
            force,
        } => run_signcrypt(
            key,
            recipient,
            ca_key,
            revocations,
            input,
            output,
            force,
            json,
        ),
        Command::Signdecrypt {
            key,
            verifying_key,
            ca_key,
            revocations,
            input,
            output,
            force,
        } => run_signdecrypt(
            key,
            verifying_key,
            ca_key,
            revocations,
            input,
            output,
            force,
            json,
        ),
        Command::IdentityKeygen {
            out,
            force,
            passphrase,
        } => run_identity_keygen(out, force, passphrase, json),
        Command::Seal {
            key,
            recipient_identity,
            recipient,
            ca_key,
            revocations,
            input,
            output,
            force,
        } => run_seal(
            key,
            recipient_identity,
            recipient,
            ca_key,
            revocations,
            input,
            output,
            force,
            json,
        ),
        Command::Unseal {
            key,
            identity_key,
            sender_identity,
            input,
            output,
            force,
        } => run_unseal(
            key,
            identity_key,
            sender_identity,
            input,
            output,
            force,
            json,
        ),
        Command::SplitKey {
            key,
            threshold,
            shares,
            out,
            force,
        } => run_split_key(key, threshold, shares, out, force, json),
        Command::ReconstructKey { shares, out, force } => {
            run_reconstruct_key(shares, out, force, json)
        }
        Command::Repassphrase { key, from_legacy } => run_repassphrase(key, from_legacy, json),
        Command::Doctor {
            file,
            pubkey,
            calibrate,
            target_ms,
        } => {
            if calibrate {
                run_calibrate(target_ms, json)
            } else {
                // required_unless_present = "calibrate" guarantees Some here.
                run_doctor(
                    file.expect("clap enforces FILE without --calibrate"),
                    pubkey,
                    json,
                )
            }
        }
        Command::ImportKey {
            from,
            out,
            force,
            passphrase,
        } => run_import_key(from, out, force, passphrase, json),
        #[cfg(feature = "update-check")]
        Command::CheckUpdate => run_check_update(json),
        Command::Fingerprint { key, qr } => run_fingerprint(&key, qr, json),
        Command::IssueCert {
            ca_key,
            subject,
            label,
            not_before,
            valid_days,
            allow_encrypt,
            allow_sign,
            output,
            force,
        } => run_issue_cert(
            ca_key,
            &subject,
            &label,
            not_before,
            valid_days,
            allow_encrypt,
            allow_sign,
            output,
            force,
            json,
        ),
        Command::VerifyCert {
            ca_key,
            revocations,
            cert,
        } => run_verify_cert(ca_key, revocations, cert, json),
        Command::RevokeCert {
            ca_key,
            cert,
            existing,
            reason,
            output,
            force,
        } => run_revoke_cert(ca_key, cert, existing, &reason, output, force, json),
        #[cfg(feature = "stego")]
        Command::Bury {
            image,
            file,
            output,
            force,
        } => run_bury(&image, &file, output, force, json),
        #[cfg(feature = "stego")]
        Command::Exhume {
            image,
            output,
            force,
        } => run_exhume(&image, output, force, json),
    }
}
