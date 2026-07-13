use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use rayon::ThreadPoolBuilder;

use pqfile::error::PqfileError;
use pqfile::inspect::{inspect_stream, PqfHeaderInfo, RecipientInfo};
use pqfile::{
    archive, decrypt, encrypt, format, keygen, rekey, repassphrase, revoke, shamir, sign, signcrypt,
};

#[cfg(feature = "fido2")]
mod fido2;

#[derive(Parser)]
#[command(
    name = "pqfile",
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
        /// Each file is written alongside the original as <file>.pqf.
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
        #[arg(long, default_value_t = false)]
        stealth: bool,
    },
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
        #[arg(long, default_value_t = false)]
        stealth: bool,
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
    },
    Inspect {
        input: PathBuf,
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
        /// Path to sign_pubkey.pem (verifying key).
        #[arg(short = 'k', value_name = "VERIFYING_KEY")]
        key: PathBuf,
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
        /// Recipient public key (pubkey.pem).
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
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
        /// Sender's ML-DSA-65 verifying key (sign_pubkey.pem).
        #[arg(short = 'v', value_name = "VERIFYING_KEY")]
        verifying_key: PathBuf,
        /// Signcrypted .pqf file to decrypt, or '-' to read from stdin.
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
        /// Certificate file to verify.
        cert: PathBuf,
    },
}

const PARALLEL_BATCH_SIZE: usize = 8;

/// Wraps a plaintext reader with Padmé length padding when requested,
/// otherwise passes it through unchanged. A single concrete type keeps the
/// two call sites (`run_encrypt_single`, `run_encrypt_passphrase`) from
/// needing separate padded/unpadded code paths.
enum MaybePadded<'a> {
    Plain(&'a mut dyn io::Read),
    Padded(pqfile::padding::PadmeReader<&'a mut dyn io::Read>),
}

impl<'a> MaybePadded<'a> {
    fn new(
        reader: &'a mut dyn io::Read,
        pad: bool,
        original_size: u64,
    ) -> Result<Self, PqfileError> {
        if !pad {
            return Ok(MaybePadded::Plain(reader));
        }
        if original_size == 0 {
            return Err(PqfileError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--pad requires a known, non-zero input size; not supported when reading \
                 from stdin or for empty files",
            )));
        }
        Ok(MaybePadded::Padded(pqfile::padding::PadmeReader::new(
            reader,
            original_size,
        )))
    }
}

impl io::Read for MaybePadded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MaybePadded::Plain(r) => r.read(buf),
            MaybePadded::Padded(r) => r.read(buf),
        }
    }
}

#[derive(Clone)]
struct EncryptOpts {
    chunk_size: usize,
    compress: bool,
    compress_level: i32,
    parallel: bool,
    pipeline: bool,
    mmap: bool,
    anonymous_recipients: bool,
    pad_recipients: bool,
    force: bool,
    json: bool,
    kdf_mem: u32,
    kdf_time: u32,
    keyfile: Option<PathBuf>,
    /// Always present regardless of the `fido2` feature so downstream logic
    /// (`run_encrypt_passphrase`) stays uniform; without the feature the CLI
    /// arg simply doesn't exist, so this is always `None` in that build.
    fido2: Option<PathBuf>,
    pad: bool,
    stealth: bool,
}

/// Optional user defaults loaded from the config file. Explicit flags always win;
/// the config is only consulted when the corresponding flag is absent, and never
/// when `--no-config` is passed.
#[derive(Default)]
struct CliConfig {
    /// Default recipient for `encrypt`: a `pqf1…` string or a pubkey.pem path.
    recipient: Option<String>,
    /// Default private key path for `decrypt` / `check`.
    key: Option<PathBuf>,
}

/// Platform config file location: `%APPDATA%\pqfile\config.toml` on Windows,
/// `$XDG_CONFIG_HOME/pqfile/config.toml` (falling back to `~/.config/...`) elsewhere.
fn config_path() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("pqfile").join("config.toml"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|base| base.join("pqfile").join("config.toml"))
    }
}

/// Loads the config file, treating a missing file as empty defaults but a
/// malformed file as a hard error — silently ignoring a typo would make the
/// command behave differently than the user configured.
fn load_config(no_config: bool) -> Result<CliConfig, PqfileError> {
    if no_config {
        return Ok(CliConfig::default());
    }
    let Some(path) = config_path() else {
        return Ok(CliConfig::default());
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CliConfig::default()),
        Err(e) => return Err(PqfileError::Io(e)),
    };
    parse_config_toml(&text).map_err(|msg| {
        PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: {msg}", path.display()),
        ))
    })
}

/// Parses the strict TOML subset the config file uses: `key = "value"` pairs,
/// blank lines, and `#` comments. Only basic strings with `\\` and `\"` escapes
/// are accepted; unknown keys are ignored for forward compatibility.
fn parse_config_toml(text: &str) -> Result<CliConfig, String> {
    let mut cfg = CliConfig::default();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {}: expected `key = \"value\"`", idx + 1));
        };
        let val =
            parse_toml_basic_string(v.trim()).map_err(|e| format!("line {}: {e}", idx + 1))?;
        match k.trim() {
            "recipient" => cfg.recipient = Some(val),
            "key" => cfg.key = Some(PathBuf::from(val)),
            _ => {}
        }
    }
    Ok(cfg)
}

fn parse_toml_basic_string(v: &str) -> Result<String, String> {
    let rest = v
        .strip_prefix('"')
        .ok_or("value must be a double-quoted string")?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let tail = chars.as_str().trim_start();
                if tail.is_empty() || tail.starts_with('#') {
                    return Ok(out);
                }
                return Err("unexpected content after closing quote".to_owned());
            }
            '\\' => match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => return Err(format!("unsupported escape `\\{other}`")),
                None => return Err("dangling escape at end of string".to_owned()),
            },
            other => out.push(other),
        }
    }
    Err("unterminated string".to_owned())
}

/// Returns `OutputExists` when `path` already exists and neither `--force` nor stdout
/// output was requested. Call this with the resolved destination before creating the
/// output writer so an existing file is never clobbered silently. `to_stdout` outputs
/// are always allowed (there is no file to overwrite).
fn ensure_overwrite_allowed(path: &Path, to_stdout: bool, force: bool) -> Result<(), PqfileError> {
    if !to_stdout && !force && path.exists() {
        return Err(PqfileError::OutputExists(path.to_path_buf()));
    }
    Ok(())
}

/// Current wall-clock time as Unix seconds, for certificate validity checks.
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses a `YYYY-MM-DD` date (UTC, midnight) into Unix seconds.
fn parse_ymd_to_unix(date: &str) -> Result<u64, PqfileError> {
    let bad = || {
        PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("date must be in YYYY-MM-DD format, got {date:?}"),
        ))
    };
    let parts: Vec<&str> = date.splitn(4, '-').collect();
    if parts.len() != 3
        || parts[0].len() != 4
        || parts[1].len() != 2
        || parts[2].len() != 2
        || !parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
    {
        return Err(bad());
    }
    let y: i64 = parts[0].parse().map_err(|_| bad())?;
    let m: i64 = parts[1].parse().map_err(|_| bad())?;
    let d: i64 = parts[2].parse().map_err(|_| bad())?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(bad());
    }
    let days = days_from_civil(y, m, d);
    let epoch_days = days_from_civil(1970, 1, 1);
    let secs = (days - epoch_days) * 86_400;
    u64::try_from(secs).map_err(|_| bad())
}

/// Formats Unix seconds as a `YYYY-MM-DD` date (UTC).
fn format_unix_date(secs: u64) -> String {
    let days = (secs / 86_400) as i64 + days_from_civil(1970, 1, 1);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant's `days_from_civil`: proleptic Gregorian calendar date to
/// days since 1970-01-01 (correct for any year, including leap years).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`]: days since 1970-01-01 to a civil date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
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

// ── Interactive (no-args) mode ─────────────────────────────────────────────
//
// A guided prompt flow for encrypt/decrypt/keygen, triggered only when
// `pqfile` is run with no arguments. Delegates to the same run_* functions
// the normal subcommand dispatch uses, so behavior (defaults, validation,
// error messages) stays identical; this layer only gathers the inputs.

fn prompt_line(label: &str) -> Result<String, PqfileError> {
    print!("{label}");
    io::stdout().flush().map_err(PqfileError::Io)?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).map_err(PqfileError::Io)?;
    Ok(buf.trim().to_string())
}

fn prompt_line_default(label: &str, default: &str) -> Result<String, PqfileError> {
    let s = prompt_line(&format!("{label} [{default}]: "))?;
    Ok(if s.is_empty() { default.to_string() } else { s })
}

fn prompt_required(label: &str) -> Result<String, PqfileError> {
    let s = prompt_line(label)?;
    if s.is_empty() {
        return Err(PqfileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a value is required",
        )));
    }
    Ok(s)
}

fn prompt_yes_no(label: &str, default_yes: bool) -> Result<bool, PqfileError> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    let s = prompt_line(&format!("{label} [{hint}]: "))?;
    Ok(match s.to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default_yes,
    })
}

/// Prompts to overwrite `path` only if it already exists; returns `false` (no
/// prompt) otherwise. Mirrors the `--force` flag's meaning for the run_* calls
/// below.
fn prompt_overwrite_if_exists(path: &str) -> Result<bool, PqfileError> {
    if path.is_empty() || path == "-" || !Path::new(path).exists() {
        return Ok(false);
    }
    prompt_yes_no(&format!("{path} already exists. Overwrite?"), false)
}

fn run_interactive() -> Result<(), PqfileError> {
    println!("pqfile interactive mode (no arguments given).\n");
    println!("What would you like to do?");
    println!("  1) Encrypt a file");
    println!("  2) Decrypt a file");
    println!("  3) Generate a new key pair");
    match prompt_required("Enter a number [1-3]: ")?.as_str() {
        "1" => interactive_encrypt(),
        "2" => interactive_decrypt(),
        "3" => interactive_keygen(),
        other => Err(PqfileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unrecognized choice '{other}'; expected 1, 2, or 3"),
        ))),
    }
}

fn interactive_encrypt() -> Result<(), PqfileError> {
    let input = prompt_required("Path to the file to encrypt: ")?;

    println!("Encrypt using:");
    println!("  1) A recipient's public key");
    println!("  2) A passphrase (no key pair needed)");
    let passphrase_only = prompt_line_default("Enter a number [1-2]", "1")? == "2";

    let mut recipients = Vec::new();
    if !passphrase_only {
        recipients.push(prompt_required(
            "Path to the recipient's pubkey.pem, or a pqf1… recipient string: ",
        )?);
    }

    let default_output = format!("{input}.pqf");
    let output = prompt_line_default("Output path", &default_output)?;
    let force = prompt_overwrite_if_exists(&output)?;

    run_encrypt(
        recipients,
        None,
        passphrase_only,
        false,
        input,
        Some(output),
        false,
        EncryptOpts {
            chunk_size: 0,
            compress: false,
            compress_level: 3,
            parallel: false,
            pipeline: false,
            mmap: false,
            anonymous_recipients: false,
            pad_recipients: false,
            force,
            json: false,
            kdf_mem: 65536,
            kdf_time: 3,
            keyfile: None,
            fido2: None,
            pad: false,
            stealth: false,
        },
    )
}

fn interactive_decrypt() -> Result<(), PqfileError> {
    let input = prompt_required("Path to the .pqf file to decrypt: ")?;

    println!("Decrypt using:");
    println!("  1) A private key");
    println!("  2) A passphrase (v10 passphrase-only files)");
    let passphrase_v10 = prompt_line_default("Enter a number [1-2]", "1")? == "2";

    let key = if passphrase_v10 {
        None
    } else {
        Some(PathBuf::from(prompt_required(
            "Path to your privkey.pem: ",
        )?))
    };

    let default_output = Path::new(&input)
        .with_extension("")
        .to_string_lossy()
        .into_owned();
    let output = prompt_line_default("Output path", &default_output)?;
    let force = prompt_overwrite_if_exists(&output)?;

    run_decrypt(
        key,
        passphrase_v10,
        None,
        None,
        false,
        65536,
        3,
        input,
        Some(output),
        false,
        force,
        false,
        false,
    )
}

fn interactive_keygen() -> Result<(), PqfileError> {
    let out = PathBuf::from(prompt_line_default(
        "Directory to write the key pair to",
        "./keys",
    )?);
    std::fs::create_dir_all(&out)?;

    let level: u16 = prompt_line_default("ML-KEM security level (512, 768, or 1024)", "768")?
        .parse()
        .map_err(|_| {
            PqfileError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "level must be 512, 768, or 1024",
            ))
        })?;
    let hybrid = prompt_yes_no(
        "Use hybrid X25519+ML-KEM-768 (classical + post-quantum)?",
        false,
    )?;
    let passphrase = prompt_yes_no("Protect the private key with a passphrase?", true)?;

    let force = if out.join("pubkey.pem").exists() || out.join("privkey.pem").exists() {
        prompt_yes_no(
            "Key files already exist in that directory. Overwrite?",
            false,
        )?
    } else {
        false
    };

    run_keygen(
        out, force, level, hybrid, passphrase, false, None, None, false, false,
    )
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
        } => run_encrypt(
            recipients,
            ca_key,
            passphrase_only,
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
            json,
        ),
        Command::Check {
            key,
            input,
            passphrase_v10,
            max_kdf_mem,
            max_kdf_time,
            keyfile,
            #[cfg(feature = "fido2")]
            fido2,
            stealth,
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
            stealth,
            json,
        ),
        Command::Inspect { input } => inspect(input.as_path(), json),
        #[cfg(feature = "fido2")]
        Command::Fido2Enroll { output, force, pin } => run_fido2_enroll(output, force, pin, json),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "pqfile", &mut io::stdout());
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
        Command::Verify { key, sig, input } => run_verify(key, sig, input, json),
        Command::Revoke { key, reason } => run_revoke(key, &reason, json),
        Command::Rekey {
            key,
            recipient,
            input,
            output,
            force,
        } => run_rekey(key, recipient, input, output, force, json),
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
            input,
            output,
            force,
        } => run_signcrypt(key, recipient, input, output, force, json),
        Command::Signdecrypt {
            key,
            verifying_key,
            input,
            output,
            force,
        } => run_signdecrypt(key, verifying_key, input, output, force, json),
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
        Command::VerifyCert { ca_key, cert } => run_verify_cert(ca_key, cert, json),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_keygen(
    out: PathBuf,
    force: bool,
    level: u16,
    hybrid: bool,
    passphrase: bool,
    hardware: bool,
    label: Option<String>,
    expiry: Option<String>,
    qr: bool,
    json: bool,
) -> Result<(), PqfileError> {
    if hardware && passphrase {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--hardware and --passphrase are mutually exclusive",
        )));
    }
    if hardware && expiry.is_some() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--hardware and --expiry are mutually exclusive (hardware key stubs have no PEM header)",
        )));
    }
    // Validate expiry format (YYYY-MM-DD).
    if let Some(ref date) = expiry {
        let parts: Vec<&str> = date.splitn(4, '-').collect();
        let valid = parts.len() == 3
            && parts[0].len() == 4
            && parts[1].len() == 2
            && parts[2].len() == 2
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()));
        if !valid {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("--expiry must be in YYYY-MM-DD format, got {date:?}"),
            )));
        }
    }
    let fp = if hardware {
        let lbl = label.ok_or_else(|| {
            PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--hardware requires --label <LABEL>",
            ))
        })?;
        keygen::keygen_hardware(&out, force, level, hybrid, &lbl)?
    } else {
        let pp = if passphrase {
            let p = prompt_new_passphrase()?;
            if !json && keygen::passphrase_strength(p.as_str()) <= 2 {
                eprintln!("Warning: passphrase is weak. Use 12+ characters with mixed case, digits, and symbols.");
            }
            Some(p)
        } else {
            None
        };
        let fp = keygen::keygen(
            &out,
            force,
            level,
            pp.as_deref().map(|z| z.as_str()),
            hybrid,
        )?;
        // Prepend expiry comment to both PEM files if requested.
        if let Some(ref date) = expiry {
            let pub_path = out.join("pubkey.pem");
            let priv_path = out.join("privkey.pem");
            let pub_pem = std::fs::read_to_string(&pub_path)?;
            let priv_pem = std::fs::read_to_string(&priv_path)?;
            std::fs::write(
                &pub_path,
                format!("# Expires: {date}\n{pub_pem}").as_bytes(),
            )?;
            write_private_file(
                &priv_path,
                format!("# Expires: {date}\n{priv_pem}").as_bytes(),
            )?;
        }
        fp
    };
    // Compute the Bech32 recipient string from the written public key.
    let pub_pem_for_rs = std::fs::read_to_string(out.join("pubkey.pem")).unwrap_or_default();
    let recipient_str =
        pqfile::recipient_string::encode_pubkey(&pub_pem_for_rs).unwrap_or_default();

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("pubkey_path", &out.join("pubkey.pem").to_string_lossy()),
                kv_str("privkey_path", &out.join("privkey.pem").to_string_lossy()),
                kv_str("fingerprint", &fp),
                kv_str("storage", if hardware { "hardware" } else { "disk" }),
                kv_str("expiry", expiry.as_deref().unwrap_or("")),
                kv_str("recipient_string", &recipient_str),
            ])
        );
    } else {
        if hardware {
            println!("Hardware-backed keys written to {}", out.display());
            println!("(Seed stored in OS credential store; no seed bytes on disk)");
        } else {
            println!("Keys written to {}", out.display());
        }
        println!("Public key fingerprint: {fp}");
        if !recipient_str.is_empty() {
            println!("Recipient string:       {recipient_str}");
        }
        if let Some(ref date) = expiry {
            println!("Expiry: {date}");
        }
    }
    if qr && !recipient_str.is_empty() {
        print_recipient_qr(&recipient_str, json);
    }
    Ok(())
}

/// Renders a `pqf1…` recipient string as a terminal QR code.
///
/// The string is uppercased first: Bech32m is case-insensitive and the QR
/// alphanumeric mode (uppercase-only charset) packs ~45% more characters per
/// version than byte mode, keeping the code as scannable as possible. In
/// `--json` mode the QR goes to stderr so stdout stays machine-readable.
fn print_recipient_qr(recipient_str: &str, json: bool) {
    match qrcode::QrCode::new(recipient_str.to_ascii_uppercase().as_bytes()) {
        Ok(code) => {
            let rendered = code
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            if json {
                eprintln!("{rendered}");
            } else {
                println!("{rendered}");
            }
        }
        Err(e) => eprintln!("warning: could not render QR code: {e}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_encrypt(
    mut recipients: Vec<String>,
    ca_key: Option<PathBuf>,
    passphrase_only: bool,
    no_config: bool,
    input: String,
    output: Option<String>,
    recursive: bool,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    if passphrase_only {
        if recursive {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--passphrase and --recursive cannot be combined",
            )));
        }
        if opts.stealth {
            return Err(PqfileError::Io(std::io::Error::other(
                "--stealth is not supported with --passphrase",
            )));
        }
        let pp = prompt_new_passphrase()?;
        return run_encrypt_passphrase(pp.as_str(), &input, output.as_deref(), opts);
    }
    if recipients.is_empty() {
        if let Some(r) = load_config(no_config)?.recipient {
            recipients.push(r);
        }
    }
    if recipients.is_empty() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "provide at least one -r recipient, use --passphrase for passphrase-only encryption, \
             or set a default `recipient` in the config file",
        )));
    }
    if opts.chunk_size > 268_435_456 {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("--chunk-size must be ≤ 268435456, got {}", opts.chunk_size),
        )));
    }
    if opts.compress && (opts.compress_level < 1 || opts.compress_level > 22) {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "--compress-level must be between 1 and 22, got {}",
                opts.compress_level
            ),
        )));
    }
    // Load and validate recipient public keys. Each recipient can be a path to a
    // pubkey.pem file, a certificate PEM (produced by `issue-cert`), or a
    // `pqf1…` Bech32 recipient string.
    let now = current_unix_secs();
    let pubkey_pems: Vec<String> = recipients
        .iter()
        .map(|r| {
            if pqfile::recipient_string::is_recipient_string(r) {
                // Bech32 recipient string: decode directly; no revocation check possible.
                pqfile::recipient_string::decode_pubkey(r)
            } else {
                // File path: read PEM and check for revocation.
                let p = std::path::Path::new(r);
                let pem = std::fs::read_to_string(p)?;
                if pqfile::cert::is_certificate(&pem) {
                    let ca_key = ca_key.as_ref().ok_or_else(|| {
                        PqfileError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "-r {r} is a certificate; pass --ca-key <CA_VERIFYING_KEY> to verify it"
                            ),
                        ))
                    })?;
                    let ca_vk_pem = std::fs::read_to_string(ca_key)?;
                    let cert = pqfile::cert::verify_cert(&ca_vk_pem, &pem, now)?;
                    if !cert.permits(pqfile::cert::cert_use::ENCRYPT) {
                        return Err(PqfileError::CertUseNotPermitted {
                            required: pqfile::cert::cert_use::ENCRYPT,
                            allowed: cert.allowed_use,
                        });
                    }
                    Ok(cert.subject_pem)
                } else {
                    revoke::check_not_revoked(p, &pem)?;
                    Ok(pem)
                }
            }
        })
        .collect::<Result<_, _>>()?;
    if recursive {
        if opts.pad {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --recursive",
            )));
        }
        if opts.stealth {
            return Err(PqfileError::Io(std::io::Error::other(
                "--stealth is not supported with --recursive",
            )));
        }
        if pubkey_pems.len() != 1 {
            return Err(PqfileError::Io(std::io::Error::other(
                "--recursive supports only one recipient",
            )));
        }
        run_encrypt_recursive(&pubkey_pems[0], &input, opts)
    } else {
        if opts.stealth {
            if pubkey_pems.len() != 1 {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth supports only one recipient",
                )));
            }
            if opts.mmap {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --mmap",
                )));
            }
            if opts.pipeline {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --pipeline",
                )));
            }
            if opts.compress {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --compress",
                )));
            }
            if opts.parallel {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --parallel",
                )));
            }
            if opts.anonymous_recipients || opts.pad_recipients {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth is not supported with --anonymous-recipients or --pad-recipients \
                     (stealth mode is already single-recipient and reveals nothing about key type)",
                )));
            }
            if opts.chunk_size != 0 && opts.chunk_size != format::CHUNK_SIZE {
                return Err(PqfileError::Io(std::io::Error::other(
                    "--stealth always uses the default chunk size; --chunk-size is not supported",
                )));
            }
            return run_encrypt_stealth(&pubkey_pems[0], &input, output.as_deref(), opts);
        }
        run_encrypt_single(&pubkey_pems, &input, output.as_deref(), opts)
    }
}

/// Prints the `{"status":"ok","output":...}` line emitted by every command in
/// `--json` mode. Goes to stderr when the payload itself went to stdout.
fn emit_json_ok(json: bool, to_stdout: bool, out_path: &Path) -> Result<(), PqfileError> {
    if !json {
        return Ok(());
    }
    let lossy = out_path.to_string_lossy();
    let out_val: &str = if to_stdout { "-" } else { &lossy };
    let target: &mut dyn io::Write = if to_stdout {
        &mut io::stderr()
    } else {
        &mut io::stdout()
    };
    writeln!(
        target,
        "{}",
        json_object(&[kv_str("status", "ok"), kv_str("output", out_val)])
    )?;
    Ok(())
}

/// Resolves the plaintext size and output destination shared by the encrypt
/// commands: default output is `<input>.pqf`; `-` (or stdin input with no
/// `-o`) means stdout. Also enforces the overwrite guard.
fn resolve_encrypt_output(
    input: &str,
    output: Option<&str>,
    force: bool,
) -> Result<(u64, bool, PathBuf), PqfileError> {
    let original_size: u64 = if input != "-" {
        std::fs::metadata(input).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };

    let out = output.unwrap_or_else(|| if input == "-" { "-" } else { "" });
    let to_stdout = out == "-" || (out.is_empty() && input == "-");
    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        let mut s = std::ffi::OsString::from(input);
        s.push(".pqf");
        PathBuf::from(s)
    } else {
        PathBuf::from(out)
    };

    ensure_overwrite_allowed(&out_path, to_stdout, force)?;
    Ok((original_size, to_stdout, out_path))
}

fn run_encrypt_stealth(
    pubkey_pem: &str,
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    let (original_size, to_stdout, out_path) = resolve_encrypt_output(input, output, opts.force)?;
    let mut raw_reader = open_reader(input)?;
    let mut reader = MaybePadded::new(&mut *raw_reader, opts.pad, original_size)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    encrypt::encrypt_stream_stealth(pubkey_pem, original_size, &mut reader, &mut writer)?;
    writer.commit()?;

    emit_json_ok(opts.json, to_stdout, &out_path)?;
    Ok(())
}

fn run_encrypt_passphrase(
    passphrase: &str,
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    let (original_size, to_stdout, out_path) = resolve_encrypt_output(input, output, opts.force)?;
    let mut raw_reader = open_reader(input)?;
    let mut reader = MaybePadded::new(&mut *raw_reader, opts.pad, original_size)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    // p=4 matches the library default; --kdf-mem / --kdf-time only tune m and t.
    if let Some(ref kf_path) = opts.keyfile {
        let keyfile = read_keyfile(kf_path)?;
        encrypt::encrypt_stream_passphrase_keyfile_with_params(
            passphrase,
            &keyfile,
            opts.kdf_mem,
            opts.kdf_time,
            4,
            original_size,
            &mut reader,
            &mut writer,
        )?;
    } else if let Some(ref fido2_path) = opts.fido2 {
        let hmac_secret = derive_fido2_secret(fido2_path)?;
        encrypt::encrypt_stream_passphrase_fido2_with_params(
            passphrase,
            &hmac_secret,
            opts.kdf_mem,
            opts.kdf_time,
            4,
            original_size,
            &mut reader,
            &mut writer,
        )?;
    } else {
        encrypt::encrypt_stream_passphrase_with_params(
            passphrase,
            opts.kdf_mem,
            opts.kdf_time,
            4,
            original_size,
            &mut reader,
            &mut writer,
        )?;
    }
    writer.commit()?;

    emit_json_ok(opts.json, to_stdout, &out_path)?;
    Ok(())
}

fn run_encrypt_single(
    pubkey_pems: &[String],
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    let (original_size, to_stdout, out_path) = resolve_encrypt_output(input, output, opts.force)?;

    if opts.pad {
        if opts.mmap {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --mmap",
            )));
        }
        if opts.pipeline {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --pipeline",
            )));
        }
        if opts.compress {
            return Err(PqfileError::Io(std::io::Error::other(
                "--pad is not supported with --compress (compression would shrink the \
                 padding back down, defeating it)",
            )));
        }
    }

    // --mmap: native only, single recipient, no compress, file input only.
    #[cfg(not(target_arch = "wasm32"))]
    if opts.mmap && pubkey_pems.len() == 1 && !opts.compress && input != "-" {
        let chunk_size = if opts.chunk_size == 0 {
            format::adaptive_chunk_size(original_size)
        } else {
            opts.chunk_size
        };
        let mut writer = CliOutput::new(to_stdout, &out_path)?;
        encrypt::encrypt_mmap(
            &pubkey_pems[0],
            std::path::Path::new(input),
            chunk_size,
            &mut writer,
        )?;
        writer.commit()?;
        emit_json_ok(opts.json, to_stdout, &out_path)?;
        return Ok(());
    }

    // --pipeline: use a file reader that is 'static + Send (not possible with dyn Read).
    // Only available for file inputs (not stdin) since stdin can't be moved to a thread.
    if opts.pipeline && pubkey_pems.len() == 1 && !opts.compress && input != "-" {
        let chunk_size = if opts.chunk_size == 0 {
            format::adaptive_chunk_size(original_size)
        } else {
            opts.chunk_size
        };
        let file_reader = BufReader::new(std::fs::File::open(input)?);
        let mut writer = CliOutput::new(to_stdout, &out_path)?;
        encrypt::encrypt_stream_pipelined(
            &pubkey_pems[0],
            original_size,
            chunk_size,
            file_reader,
            &mut writer,
        )?;
        writer.commit()?;
        emit_json_ok(opts.json, to_stdout, &out_path)?;
        return Ok(());
    }

    let mut raw_reader = open_reader(input)?;
    let mut reader = MaybePadded::new(&mut *raw_reader, opts.pad, original_size)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    perform_encrypt(pubkey_pems, original_size, &opts, &mut reader, &mut writer)?;
    writer.commit()?;

    emit_json_ok(opts.json, to_stdout, &out_path)?;
    Ok(())
}

fn perform_encrypt(
    pubkey_pems: &[String],
    original_size: u64,
    opts: &EncryptOpts,
    reader: &mut dyn io::Read,
    writer: &mut dyn io::Write,
) -> Result<(), PqfileError> {
    if pubkey_pems.len() == 1 {
        // Resolve adaptive chunk size (0 = auto) for single-recipient paths.
        let chunk_size = if opts.chunk_size == 0 {
            format::adaptive_chunk_size(original_size)
        } else {
            opts.chunk_size
        };
        if opts.compress {
            encrypt::encrypt_stream_compressed(
                &pubkey_pems[0],
                original_size,
                chunk_size,
                opts.compress_level,
                reader,
                writer,
            )
        } else if opts.parallel {
            encrypt::encrypt_stream_parallel(
                &pubkey_pems[0],
                original_size,
                chunk_size,
                PARALLEL_BATCH_SIZE,
                reader,
                writer,
            )
        } else {
            encrypt::encrypt_stream(&pubkey_pems[0], original_size, chunk_size, reader, writer)
        }
    } else {
        // Multi-recipient always uses CHUNK_SIZE internally.
        // 0 (auto) is allowed; any other explicit non-default value is rejected.
        if opts.chunk_size != 0 && opts.chunk_size != format::CHUNK_SIZE {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--chunk-size is not supported with multiple recipients",
            )));
        }
        if opts.compress {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--compress is not supported with multiple recipients",
            )));
        }
        if opts.parallel {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--parallel is not supported with multiple recipients",
            )));
        }
        let refs: Vec<&str> = pubkey_pems.iter().map(|s| s.as_str()).collect();
        if opts.pad_recipients {
            encrypt::encrypt_stream_multi_anon_padded(&refs, original_size, reader, writer)
        } else if opts.anonymous_recipients {
            encrypt::encrypt_stream_multi_anon(&refs, original_size, reader, writer)
        } else {
            encrypt::encrypt_stream_multi(&refs, original_size, reader, writer)
        }
    }
}

fn run_encrypt_recursive(
    pubkey_pem: &str,
    input: &str,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    let dir = PathBuf::from(input);
    if !dir.is_dir() {
        return Err(PqfileError::Io(std::io::Error::other(format!(
            "'{input}' is not a directory (--recursive requires a directory path)"
        ))));
    }

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(&dir, &mut files)?;

    let mut any_error = false;
    let mut json_entries: Vec<String> = Vec::new();

    for file_path in &files {
        let out_path = {
            let mut s = file_path.as_os_str().to_owned();
            s.push(".pqf");
            PathBuf::from(s)
        };
        let result = encrypt_one_file(pubkey_pem, file_path, &out_path, &opts);
        let path_str = file_path.to_string_lossy();
        let out_str = out_path.to_string_lossy();
        match result {
            Ok(()) => {
                if opts.json {
                    json_entries.push(json_object(&[
                        kv_str("file", &path_str),
                        kv_str("status", "ok"),
                        kv_str("output", &out_str),
                    ]));
                } else {
                    println!("ok: {path_str}");
                }
            }
            Err(e) => {
                any_error = true;
                if opts.json {
                    json_entries.push(json_object(&[
                        kv_str("file", &path_str),
                        kv_str("status", "error"),
                        kv_raw("code", &e.code().to_string()),
                        kv_str("message", &e.to_string()),
                    ]));
                } else {
                    eprintln!("error: {path_str}: {e}");
                }
            }
        }
    }

    if opts.json {
        println!("[{}]", json_entries.join(","));
    }

    if any_error {
        Err(PqfileError::Io(std::io::Error::other(
            "one or more files failed to encrypt",
        )))
    } else {
        Ok(())
    }
}

fn encrypt_one_file(
    pubkey_pem: &str,
    file_path: &Path,
    out_path: &Path,
    opts: &EncryptOpts,
) -> Result<(), PqfileError> {
    let size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    let chunk_size = if opts.chunk_size == 0 {
        format::adaptive_chunk_size(size)
    } else {
        opts.chunk_size
    };
    ensure_overwrite_allowed(out_path, false, opts.force)?;
    let mut reader = BufReader::new(std::fs::File::open(file_path)?);
    let mut writer = AtomicOutput::new(out_path)?;
    let result = if opts.compress {
        encrypt::encrypt_stream_compressed(
            pubkey_pem,
            size,
            chunk_size,
            opts.compress_level,
            &mut reader,
            &mut writer,
        )
    } else {
        encrypt::encrypt_stream(pubkey_pem, size, chunk_size, &mut reader, &mut writer)
    };
    result?;
    writer.commit()?;
    Ok(())
}

/// Recursively collects all non-.pqf files under `dir`, sorted for determinism.
fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), PqfileError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files(&path, files)?;
        } else if ft.is_file() && path.extension().is_none_or(|e| e != "pqf") {
            files.push(path);
        }
    }
    Ok(())
}

fn bad_archive_input(msg: String) -> PqfileError {
    PqfileError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

/// Recursively collects every file under `dir` for `archive --recursive`,
/// sorted for determinism. Unlike [`collect_files`] (encrypt --recursive,
/// which skips what it can't use), archiving is a fidelity operation: symlinks
/// and special files (devices, FIFOs, sockets) cannot be represented in a PQFA
/// archive, so encountering one is an error rather than a silent omission.
fn collect_archive_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), PqfileError> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.path());
    for entry in entries {
        let path = entry.path();
        // read_dir file_type does not follow symlinks, so a symlink reports
        // is_symlink() here even when its target is a file or directory.
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            return Err(bad_archive_input(format!(
                "'{}' is a symlink; archives store regular files only",
                path.display()
            )));
        } else if ft.is_dir() {
            collect_archive_files(&path, files)?;
        } else if ft.is_file() {
            files.push(path);
        } else {
            return Err(bad_archive_input(format!(
                "'{}' is not a regular file (device, FIFO, or socket)",
                path.display()
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_decrypt(
    key: Option<PathBuf>,
    passphrase_v10: bool,
    keyfile: Option<PathBuf>,
    fido2: Option<PathBuf>,
    no_config: bool,
    max_kdf_mem: u32,
    max_kdf_time: u32,
    input: String,
    output: Option<String>,
    parallel: bool,
    force: bool,
    stealth: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let out = output.as_deref().unwrap_or("");
    let to_stdout = out == "-" || (out.is_empty() && input == "-");
    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        PathBuf::from(&input).with_extension("")
    } else {
        PathBuf::from(out)
    };

    ensure_overwrite_allowed(&out_path, to_stdout, force)?;
    let mut reader = open_reader(&input)?;

    if stealth {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        let mut writer = CliOutput::new(to_stdout, &out_path)?;
        // decrypt_stream_stealth truncates any Padmé padding tail internally,
        // so no TruncatingWriter wrapping is needed here (unlike the normal
        // path below, there is no header to peek anyway).
        decrypt::decrypt_stream_stealth(&privkey_pem, &mut *reader, &mut writer, pp_str)?;
        writer.commit()?;
        emit_json_ok(json, to_stdout, &out_path)?;
        return Ok(());
    }

    // Cap decrypted output at the header's declared original_size, silently
    // dropping any Padmé padding tail. A no-op for every file that wasn't
    // padded (they already decrypt to exactly original_size bytes) or whose
    // size couldn't be peeked (0 disables truncation) - no --pad flag needed
    // at decrypt time.
    let mut writer = pqfile::padding::TruncatingWriter::new(
        CliOutput::new(to_stdout, &out_path)?,
        peek_original_size(&input),
    );

    if passphrase_v10 {
        let pp = prompt_passphrase("Enter passphrase: ")?;
        if let Some(ref kf_path) = keyfile {
            let kf = read_keyfile(kf_path)?;
            decrypt::decrypt_stream_passphrase_keyfile_with_limits(
                pp.as_str(),
                &kf,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut writer,
            )?;
        } else if let Some(ref fido2_path) = fido2 {
            let hmac_secret = derive_fido2_secret(fido2_path)?;
            decrypt::decrypt_stream_passphrase_fido2_with_limits(
                pp.as_str(),
                &hmac_secret,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut writer,
            )?;
        } else {
            decrypt::decrypt_stream_passphrase_with_limits(
                pp.as_str(),
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut writer,
            )?;
        }
    } else {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        if parallel {
            decrypt::decrypt_stream_parallel(
                &privkey_pem,
                &mut *reader,
                &mut writer,
                pp_str,
                PARALLEL_BATCH_SIZE,
            )?;
        } else {
            decrypt::decrypt_stream(&privkey_pem, &mut *reader, &mut writer, pp_str)?;
        }
    }
    let mut writer = writer.into_inner();
    writer.commit()?;

    emit_json_ok(json, to_stdout, &out_path)?;
    Ok(())
}

/// Derives the `--fido2` second-factor secret, uniformly regardless of
/// whether this build has the `fido2` feature. `opts.fido2` /
/// `run_decrypt`'s and `run_check`'s `fido2` parameter are always `None`
/// without the feature (the CLI arg doesn't exist to set them), so the
/// `not(feature = "fido2")` arm below is provably unreachable in that build,
/// but still has to type-check.
fn derive_fido2_secret(
    enrollment_path: &Path,
) -> Result<zeroize::Zeroizing<[u8; 32]>, PqfileError> {
    #[cfg(feature = "fido2")]
    {
        fido2::derive_secret(enrollment_path)
    }
    #[cfg(not(feature = "fido2"))]
    {
        let _ = enrollment_path;
        unreachable!("fido2 feature disabled; --fido2 CLI flag does not exist without it")
    }
}

/// `Write` sink that discards everything but remembers how many bytes passed through.
struct CountingSink(u64);

impl io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Resolves the private key path for decrypt/check: the explicit `-k` flag
/// wins, then the config file's `key` entry.
fn resolve_key_path(key: Option<PathBuf>, no_config: bool) -> Result<PathBuf, PqfileError> {
    if let Some(k) = key {
        return Ok(k);
    }
    if let Some(k) = load_config(no_config)?.key {
        return Ok(k);
    }
    Err(PqfileError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "provide -k <PRIVKEY>, use --passphrase for v10 passphrase-only files, \
         or set a default `key` in the config file",
    )))
}

#[allow(clippy::too_many_arguments)]
fn run_check(
    key: Option<PathBuf>,
    passphrase_v10: bool,
    keyfile: Option<PathBuf>,
    fido2: Option<PathBuf>,
    no_config: bool,
    max_kdf_mem: u32,
    max_kdf_time: u32,
    input: String,
    stealth: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let mut reader = open_reader(&input)?;

    if stealth {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        let mut sink = CountingSink(0);
        // decrypt_stream_stealth truncates internally, so sink.0 is already
        // the true (unpadded) plaintext byte count.
        decrypt::decrypt_stream_stealth(&privkey_pem, &mut *reader, &mut sink, pp_str)?;
        let count = sink.0;
        if json {
            println!(
                "{}",
                json_object(&[
                    kv_str("status", "ok"),
                    kv_str("input", &input),
                    kv_raw("plaintext_bytes", &count.to_string()),
                ])
            );
        } else {
            println!(
                "OK: {input} authenticated ({count} plaintext byte{})",
                if count == 1 { "" } else { "s" }
            );
        }
        return Ok(());
    }

    // Cap the reported count at the header's declared original_size, so a
    // padded file's plaintext_bytes reflects the true size, not the padded
    // physical length. No-op for non-padded files; see peek_original_size.
    let mut sink =
        pqfile::padding::TruncatingWriter::new(CountingSink(0), peek_original_size(&input));

    if passphrase_v10 {
        let pp = prompt_passphrase("Enter passphrase: ")?;
        if let Some(ref kf_path) = keyfile {
            let kf = read_keyfile(kf_path)?;
            decrypt::decrypt_stream_passphrase_keyfile_with_limits(
                pp.as_str(),
                &kf,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut sink,
            )?;
        } else if let Some(ref fido2_path) = fido2 {
            let hmac_secret = derive_fido2_secret(fido2_path)?;
            decrypt::decrypt_stream_passphrase_fido2_with_limits(
                pp.as_str(),
                &hmac_secret,
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut sink,
            )?;
        } else {
            decrypt::decrypt_stream_passphrase_with_limits(
                pp.as_str(),
                max_kdf_mem,
                max_kdf_time,
                &mut *reader,
                &mut sink,
            )?;
        }
    } else {
        let key_path = resolve_key_path(key, no_config)?;
        let privkey_pem = std::fs::read_to_string(&key_path)?;
        let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        decrypt::decrypt_stream(&privkey_pem, &mut *reader, &mut sink, pp_str)?;
    }
    let count = sink.into_inner().0;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("input", &input),
                kv_raw("plaintext_bytes", &count.to_string()),
            ])
        );
    } else {
        println!(
            "OK: {input} authenticated ({count} plaintext byte{})",
            if count == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

#[cfg(feature = "fido2")]
fn run_fido2_enroll(
    output: PathBuf,
    force: bool,
    pin: bool,
    json: bool,
) -> Result<(), PqfileError> {
    ensure_overwrite_allowed(&output, false, force)?;
    let pin_value = if pin {
        Some(zeroize::Zeroizing::new(
            rpassword::prompt_password("Enter FIDO2 PIN: ").map_err(PqfileError::Io)?,
        ))
    } else {
        None
    };
    println!("Touch the security key to create the enrollment credential...");
    fido2::enroll(&output, pin_value.as_deref().map(|z| z.as_str()))?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
            ])
        );
    } else {
        println!("FIDO2 enrollment written to {}", output.display());
        println!(
            "Use --fido2 {} with encrypt/decrypt/check --passphrase.",
            output.display()
        );
    }
    Ok(())
}

fn open_reader(input: &str) -> Result<Box<dyn io::Read>, PqfileError> {
    if input == "-" {
        Ok(Box::new(io::stdin()))
    } else {
        Ok(Box::new(BufReader::new(std::fs::File::open(input)?)))
    }
}

/// Peeks a `.pqf` file's header to read its declared `original_size`, without
/// affecting the real decrypt call that follows (this opens its own,
/// independent file handle and reads only the header). Returns 0 - the
/// existing "unknown length, don't truncate" convention - for stdin input, or
/// if the header can't be read (missing file, bad magic, unsupported
/// version); the real decrypt call surfaces the accurate error in that case.
fn peek_original_size(input: &str) -> u64 {
    if input == "-" {
        return 0;
    }
    let Ok(file) = std::fs::File::open(input) else {
        return 0;
    };
    let mut reader = BufReader::new(file);
    match inspect_stream(&mut reader) {
        Ok(PqfHeaderInfo::Single { original_size, .. })
        | Ok(PqfHeaderInfo::Multi { original_size, .. })
        | Ok(PqfHeaderInfo::AnonMulti { original_size, .. })
        | Ok(PqfHeaderInfo::AnonMultiV8 { original_size, .. })
        | Ok(PqfHeaderInfo::Passphrase { original_size, .. }) => original_size,
        _ => 0,
    }
}

/// Reads a --keyfile for v10 second-factor mode. The bytes act as key material,
/// so they are zeroized on drop and an empty file is rejected up front.
fn read_keyfile(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>, PqfileError> {
    let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
    if bytes.is_empty() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "keyfile '{}' is empty; a keyfile must contain at least one byte",
                path.display()
            ),
        )));
    }
    Ok(bytes)
}

/// Writes `contents` to `path`, then (on Unix) restricts the file to owner
/// read/write only. Private key material written directly by the CLI (not
/// through the `pqfile` library's own key-writing functions) should go
/// through this helper rather than `std::fs::write` directly.
fn write_private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Buffered writer that writes to a temp file in the same directory as `target`
/// and atomically renames it to `target` when `commit()` is called.
/// If dropped without committing, the temp file is deleted.
struct AtomicOutput {
    writer: BufWriter<std::fs::File>,
    tmp: PathBuf,
    target: PathBuf,
    committed: bool,
}

impl AtomicOutput {
    fn new(target: &Path) -> io::Result<Self> {
        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let mut tmp_name = target.file_name().unwrap_or_default().to_owned();
        tmp_name.push(format!(".{pid}-{ts}.tmp"));
        let tmp = target.with_file_name(tmp_name);
        // create_new (O_EXCL) rather than create(): refuse to follow a pre-existing
        // file or symlink at the temp path instead of silently truncating it.
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        Ok(Self {
            writer: BufWriter::new(f),
            tmp,
            target: target.to_path_buf(),
            committed: false,
        })
    }

    fn commit(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        std::fs::rename(&self.tmp, &self.target)?;
        // On Unix, fsync the parent directory so the rename (directory-entry update)
        // is durable. Without this a crash between rename and the next directory flush
        // can leave the target path absent on some filesystems. Windows manages
        // directory durability internally and does not support opening directories
        // as regular file descriptors for fsync, so skip it there.
        #[cfg(unix)]
        if let Some(parent) = self.target.parent() {
            let dir = std::fs::File::open(parent)?;
            dir.sync_all()?;
        }
        self.committed = true;
        Ok(())
    }
}

impl io::Write for AtomicOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Output target that is either stdout (no commit needed) or an `AtomicOutput` file.
enum CliOutput {
    Stdout(io::Stdout),
    File(AtomicOutput),
}

impl CliOutput {
    fn new(to_stdout: bool, path: &Path) -> Result<Self, PqfileError> {
        if to_stdout {
            Ok(CliOutput::Stdout(io::stdout()))
        } else {
            Ok(CliOutput::File(AtomicOutput::new(path)?))
        }
    }

    fn commit(&mut self) -> io::Result<()> {
        match self {
            CliOutput::Stdout(_) => Ok(()),
            CliOutput::File(ao) => ao.commit(),
        }
    }
}

impl io::Write for CliOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            CliOutput::Stdout(s) => s.write(buf),
            CliOutput::File(ao) => ao.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            CliOutput::Stdout(s) => s.flush(),
            CliOutput::File(ao) => ao.flush(),
        }
    }
}

/// Prompts for a passphrase if `pem_str` is an encrypted (non-hardware) private key.
/// Returns `None` for plaintext keys and hardware stubs; hardware backends
/// handle their own authentication inside the OS credential store.
fn maybe_prompt_passphrase(
    pem_str: &str,
    prompt: &str,
) -> Result<Option<zeroize::Zeroizing<String>>, PqfileError> {
    if keygen::is_hardware_key(pem_str) {
        Ok(None)
    } else if keygen::is_encrypted_key(pem_str)
        || pqfile::keys::PqfSigningKey::from_pem(pem_str)
            .map(|k| k.is_encrypted())
            .unwrap_or(false)
    {
        Ok(Some(prompt_passphrase(prompt)?))
    } else {
        Ok(None)
    }
}

fn prompt_new_passphrase() -> Result<zeroize::Zeroizing<String>, PqfileError> {
    let pp = zeroize::Zeroizing::new(
        rpassword::prompt_password("Enter passphrase: ").map_err(PqfileError::Io)?,
    );
    let confirm = zeroize::Zeroizing::new(
        rpassword::prompt_password("Confirm passphrase: ").map_err(PqfileError::Io)?,
    );
    if *pp != *confirm {
        return Err(PqfileError::PassphraseMismatch);
    }
    Ok(pp)
}

fn prompt_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>, PqfileError> {
    Ok(zeroize::Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(PqfileError::Io)?,
    ))
}

fn kem_variant_name(variant: u16) -> &'static str {
    match variant {
        512 => "ML-KEM-512",
        768 => "ML-KEM-768",
        1024 => "ML-KEM-1024",
        0x0301 => "Hybrid X25519+ML-KEM-768",
        _ => "unknown",
    }
}

fn inspect(input: &Path, json: bool) -> Result<(), PqfileError> {
    let mut file = std::fs::File::open(input)?;
    // Peek the raw version byte: the Multi/AnonMulti inspect variants do not carry
    // it, but the display should show the on-disk byte (which may include the
    // authenticated-header bit). Errors are ignored here; inspect_stream below
    // reports the canonical error for short or malformed files.
    let mut preamble = [0u8; 5];
    let raw_version = match std::io::Read::read_exact(&mut file, &mut preamble) {
        Ok(()) => preamble[4],
        Err(_) => 0,
    };
    std::io::Seek::rewind(&mut file)?;
    let mut reader = BufReader::new(file);
    let info = inspect_stream(&mut reader)?;
    let authenticated = format::is_header_authenticated(raw_version);
    let auth_str = if authenticated { "yes" } else { "no" };
    let auth_json = if authenticated { "true" } else { "false" };
    match &info {
        PqfHeaderInfo::Single {
            version,
            kem_variant,
            nonce,
            original_size,
            chunk_size,
            compression_algo,
        } => {
            let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let variant_name = kem_variant_name(*kem_variant);
            let layout = format::version_layout(*version);
            let has_chunk_size = layout == format::VERSION_V5 || layout == format::VERSION_V6;
            let compression_name = match compression_algo {
                v if *v == format::COMPRESSION_NONE => "none",
                v if *v == format::COMPRESSION_ZSTD => "zstd",
                _ => "unknown",
            };
            if json {
                let mut fields = vec![
                    kv_str("status", "ok"),
                    kv_str("magic", "PQFL"),
                    kv_str("version", &format!("{version:#04x}")),
                    kv_raw("header_authenticated", auth_json),
                    kv_raw("kem_variant", &format!("{kem_variant}")),
                    kv_str("kem_variant_name", variant_name),
                    kv_str("nonce", &nonce_hex),
                    kv_raw("original_size", &format!("{original_size}")),
                ];
                if has_chunk_size {
                    fields.push(kv_raw("chunk_size", &format!("{chunk_size}")));
                }
                if layout == format::VERSION_V6 {
                    fields.push(kv_str("compression", compression_name));
                }
                println!("{}", json_object(&fields));
            } else {
                println!("Magic:              PQFL");
                println!("Version:            {version:#04x}");
                println!("Auth. header:       {auth_str}");
                println!("KEM variant:        {kem_variant} ({variant_name})");
                println!("Nonce:              {nonce_hex}");
                println!("Original file size: {original_size} bytes");
                if has_chunk_size {
                    println!("Chunk size:         {chunk_size} bytes");
                }
                if layout == format::VERSION_V6 {
                    println!("Compression:        {compression_name}");
                }
            }
        }
        PqfHeaderInfo::Multi {
            recipients,
            nonce,
            original_size,
        } => print_multi_header(
            &format!("{raw_version:#04x}"),
            &format!("{raw_version:#04x} (multi-recipient)"),
            authenticated,
            nonce,
            *original_size,
            recipients,
            None,
            "",
            &|i, v, name| println!("  Recipient {i}:      {v} ({name})"),
            json,
        ),
        PqfHeaderInfo::AnonMulti {
            recipients,
            nonce,
            original_size,
        } => print_multi_header(
            &format!("{raw_version:#04x}"),
            &format!("{raw_version:#04x} (anonymous multi-recipient, legacy)"),
            authenticated,
            nonce,
            *original_size,
            recipients,
            Some("anonymous-recipients"),
            " (order shuffled)",
            &|i, v, name| println!("  Slot {i}:           {v} ({name})"),
            json,
        ),
        PqfHeaderInfo::AnonMultiV8 {
            version,
            slot_count,
            nonce,
            original_size,
        } => {
            let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let version_hex = format!("{version:#04x}");
            let is_v9 = format::version_layout(*version) == pqfile::format::VERSION_V9;
            let mode_label = if is_v9 {
                "anonymous-recipients-v9-padded"
            } else {
                "anonymous-recipients-v8"
            };
            let version_display = if is_v9 {
                format!("{version_hex} (padded anonymous multi-recipient)")
            } else {
                format!("{version_hex} (variant-blind anonymous multi-recipient)")
            };
            if json {
                println!(
                    "{}",
                    json_object(&[
                        kv_str("status", "ok"),
                        kv_str("magic", "PQFL"),
                        kv_str("version", &version_hex),
                        kv_raw("header_authenticated", auth_json),
                        kv_str("mode", mode_label),
                        kv_raw("slot_count", &slot_count.to_string()),
                        kv_str("nonce", &nonce_hex),
                        kv_raw("original_size", &original_size.to_string()),
                    ])
                );
            } else {
                println!("Magic:              PQFL");
                println!("Version:            {version_display}");
                println!("Auth. header:       {auth_str}");
                println!("Slots:              {slot_count} (key types hidden)");
                println!("Nonce:              {nonce_hex}");
                println!("Original file size: {original_size} bytes");
            }
        }
        PqfHeaderInfo::Passphrase {
            version,
            m_kib,
            t_cost,
            p_cost,
            flags,
            nonce,
            original_size,
        } => {
            let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let keyfile_required = flags & 0x01 != 0;
            if json {
                println!(
                    "{}",
                    json_object(&[
                        kv_str("status", "ok"),
                        kv_str("magic", "PQFL"),
                        kv_str("version", &format!("{version:#04x}")),
                        kv_raw("header_authenticated", auth_json),
                        kv_str("mode", "passphrase"),
                        kv_raw("kdf_mem_kib", &m_kib.to_string()),
                        kv_raw("kdf_time", &t_cost.to_string()),
                        kv_raw("kdf_parallelism", &p_cost.to_string()),
                        kv_raw(
                            "keyfile_required",
                            if keyfile_required { "true" } else { "false" },
                        ),
                        kv_str("nonce", &nonce_hex),
                        kv_raw("original_size", &original_size.to_string()),
                    ])
                );
            } else {
                println!("Magic:              PQFL");
                println!("Version:            {version:#04x} (passphrase-only)");
                println!("Auth. header:       {auth_str}");
                println!("Argon2id:           m={m_kib} KiB, t={t_cost}, p={p_cost}");
                println!(
                    "Keyfile required:   {}",
                    if keyfile_required { "yes" } else { "no" }
                );
                println!("Nonce:              {nonce_hex}");
                println!("Original file size: {original_size} bytes");
            }
        }
        _ => return Err(PqfileError::UnsupportedVersion(0)),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_multi_header(
    version_num: &str,
    version_label: &str,
    authenticated: bool,
    nonce: &[u8; 12],
    original_size: u64,
    recipients: &[RecipientInfo],
    mode_json: Option<&str>,
    count_suffix: &str,
    row_fmt: &dyn Fn(usize, u16, &str),
    json: bool,
) {
    let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    if json {
        let recipients_json: Vec<String> = recipients
            .iter()
            .map(|r| {
                let name = kem_variant_name(r.kem_variant);
                json_object(&[
                    kv_raw("kem_variant", &r.kem_variant.to_string()),
                    kv_str("kem_variant_name", name),
                ])
            })
            .collect();
        let mut fields = vec![
            kv_str("status", "ok"),
            kv_str("magic", "PQFL"),
            kv_str("version", version_num),
            kv_raw(
                "header_authenticated",
                if authenticated { "true" } else { "false" },
            ),
        ];
        if let Some(m) = mode_json {
            fields.push(kv_str("mode", m));
        }
        fields.extend([
            kv_raw("recipient_count", &recipients.len().to_string()),
            format!("\"recipients\":[{}]", recipients_json.join(",")),
            kv_str("nonce", &nonce_hex),
            kv_raw("original_size", &original_size.to_string()),
        ]);
        println!("{}", json_object(&fields));
    } else {
        println!("Magic:              PQFL");
        println!("Version:            {version_label}");
        println!(
            "Auth. header:       {}",
            if authenticated { "yes" } else { "no" }
        );
        println!("Recipients:         {}{count_suffix}", recipients.len());
        for (i, r) in recipients.iter().enumerate() {
            let name = kem_variant_name(r.kem_variant);
            row_fmt(i, r.kem_variant, name);
        }
        println!("Nonce:              {nonce_hex}");
        println!("Original file size: {original_size} bytes");
    }
}

/// CLI-facing signature algorithm choice for `sign-keygen`.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SigAlgorithmArg {
    /// ML-DSA-65 (FIPS 204): lattice-based, fast, 3.3 KB signatures.
    #[value(name = "ml-dsa-65")]
    MlDsa65,
    /// SLH-DSA-SHAKE-192f (FIPS 205): hash-based, conservative assumptions,
    /// slower signing, 35 KB signatures.
    #[value(name = "slh-dsa-shake-192f")]
    SlhDsaShake192f,
}

impl From<SigAlgorithmArg> for sign::SigAlgorithm {
    fn from(a: SigAlgorithmArg) -> Self {
        match a {
            SigAlgorithmArg::MlDsa65 => sign::SigAlgorithm::MlDsa65,
            SigAlgorithmArg::SlhDsaShake192f => sign::SigAlgorithm::SlhDsaShake192f,
        }
    }
}

fn run_sign_keygen(
    out: PathBuf,
    force: bool,
    use_passphrase: bool,
    hardware: bool,
    label: Option<String>,
    algorithm: SigAlgorithmArg,
    json: bool,
) -> Result<(), PqfileError> {
    if hardware && use_passphrase {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--hardware and --passphrase are mutually exclusive",
        )));
    }
    let alg: sign::SigAlgorithm = algorithm.into();
    let r = if hardware {
        let lbl = label.ok_or_else(|| {
            PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--hardware requires --label <LABEL>",
            ))
        })?;
        sign::sign_keygen_hardware_with_algorithm(&out, force, &lbl, alg)?
    } else {
        let pp = if use_passphrase {
            let p = prompt_new_passphrase()?;
            if !json && keygen::passphrase_strength(p.as_str()) <= 2 {
                eprintln!("Warning: passphrase is weak. Use 12+ characters with mixed case, digits, and symbols.");
            }
            Some(p)
        } else {
            None
        };
        sign::sign_keygen_with_algorithm(&out, force, pp.as_deref().map(|z| z.as_str()), alg)?
    };
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("vk_path", &out.join("sign_pubkey.pem").to_string_lossy()),
                kv_str("sk_path", &out.join("sign_privkey.pem").to_string_lossy()),
                kv_str("fingerprint", &r.vk_fingerprint),
                kv_str("algorithm", alg.name()),
                kv_str("storage", if hardware { "hardware" } else { "disk" }),
            ])
        );
    } else {
        if hardware {
            println!("Hardware-backed signing keys written to {}", out.display());
        } else {
            println!("Signing keys written to {}", out.display());
        }
        println!("Algorithm: {}", alg.name());
        println!("Verifying key fingerprint: {}", r.vk_fingerprint);
    }
    Ok(())
}

fn run_sign(
    key: PathBuf,
    input: PathBuf,
    output: Option<PathBuf>,
    json: bool,
) -> Result<(), PqfileError> {
    let sk_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&sk_pem, "Enter passphrase for signing key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let sig_path = output.unwrap_or_else(|| sign::default_sig_path(&input));
    sign::sign_file(&sk_pem, &input, &sig_path, pp_str)?;
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("input", &input.to_string_lossy()),
                kv_str("signature", &sig_path.to_string_lossy()),
            ])
        );
    } else {
        println!("Signature written to {}", sig_path.display());
    }
    Ok(())
}

fn run_verify(key: PathBuf, sig: PathBuf, input: PathBuf, json: bool) -> Result<(), PqfileError> {
    let vk_pem = std::fs::read_to_string(&key)?;
    sign::verify_file(&vk_pem, &input, &sig)?;
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("input", &input.to_string_lossy()),
                kv_str("signature", &sig.to_string_lossy()),
                kv_str("result", "valid"),
            ])
        );
    } else {
        println!("Signature is valid.");
    }
    Ok(())
}

fn run_revoke(key: PathBuf, reason: &str, json: bool) -> Result<(), PqfileError> {
    let fp = revoke::revoke_key(&key, reason)?;
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("fingerprint", &fp),
                kv_str(
                    "revoked_path",
                    &revoke::revoked_path_for(&key).to_string_lossy()
                ),
            ])
        );
    } else {
        println!("Key revoked: {fp}");
        println!(
            "Sidecar written to {}",
            revoke::revoked_path_for(&key).display()
        );
    }
    Ok(())
}

fn run_rekey(
    key: PathBuf,
    recipient: PathBuf,
    input: String,
    output: Option<String>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    let out = output.as_deref().unwrap_or("");
    let to_stdout = out == "-" || (out.is_empty() && input == "-");

    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        PathBuf::from(&input)
    } else {
        PathBuf::from(out)
    };

    // Rekey defaults to rewriting the input file in place, so an existing output that
    // equals the input is expected and always allowed. Only guard an explicit -o that
    // points at a *different* existing file.
    if out_path.as_path() != Path::new(&input) {
        ensure_overwrite_allowed(&out_path, to_stdout, force)?;
    }

    let mut reader = open_reader(&input)?;
    let mut writer = CliOutput::new(to_stdout, &out_path)?;
    rekey::rekey_stream(&privkey_pem, &pubkey_pem, &mut *reader, &mut writer, pp_str)?;
    writer.commit()?;

    emit_json_ok(json, to_stdout, &out_path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_archive(
    recipient: PathBuf,
    output: PathBuf,
    files: Vec<PathBuf>,
    base: Option<PathBuf>,
    recursive: bool,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    ensure_overwrite_allowed(&output, false, force)?;
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    // Names an entry from its on-disk path: --base strips a leading prefix;
    // otherwise `prefix` (the walked root's directory name) or the bare
    // filename is used. Archive paths always use forward slashes.
    let entry_name = |path: &Path, prefix: Option<&Path>| -> String {
        if let Some(ref b) = base {
            path.strip_prefix(b)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/")
        } else if let Some(root) = prefix {
            let rel = path.strip_prefix(root).unwrap_or(path);
            match root.file_name() {
                Some(n) => {
                    format!("{}/{}", n.to_string_lossy(), rel.to_string_lossy()).replace('\\', "/")
                }
                None => rel.to_string_lossy().replace('\\', "/"),
            }
        } else {
            path.file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy()
                .to_string()
        }
    };

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    for f in &files {
        let meta = std::fs::symlink_metadata(f)?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(bad_archive_input(format!(
                "'{}' is a symlink; archives store regular files only",
                f.display()
            )));
        }
        if ft.is_dir() {
            if !recursive {
                return Err(bad_archive_input(format!(
                    "'{}' is a directory; pass --recursive to archive a directory tree",
                    f.display()
                )));
            }
            let mut walked: Vec<PathBuf> = Vec::new();
            collect_archive_files(f, &mut walked)?;
            for path in walked {
                let name = entry_name(&path, Some(f));
                entries.push((name, path));
            }
        } else if ft.is_file() {
            entries.push((entry_name(f, None), f.clone()));
        } else {
            return Err(bad_archive_input(format!(
                "'{}' is not a regular file (device, FIFO, or socket)",
                f.display()
            )));
        }
    }

    if entries.is_empty() {
        return Err(bad_archive_input(
            "no files found to archive (directory tree is empty)".to_string(),
        ));
    }

    // Reject duplicate entry names, including case-insensitive collisions:
    // extraction on a case-insensitive filesystem (Windows, macOS default)
    // would silently overwrite one entry with the other.
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (name, _) in &entries {
        if let Some(prev) = seen.insert(name.to_lowercase(), name.clone()) {
            return Err(bad_archive_input(if prev == *name {
                format!("duplicate archive entry name '{name}'")
            } else {
                format!(
                    "archive entry names '{prev}' and '{name}' collide on \
                     case-insensitive filesystems"
                )
            }));
        }
    }

    let mut writer = AtomicOutput::new(&output)?;
    archive::create(&pubkey_pem, &entries, &mut writer)?;
    writer.commit()?;

    if json {
        let names: Vec<String> = entries.iter().map(|(n, _)| json_str(n)).collect();
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
                kv_raw("entry_count", &entries.len().to_string()),
                format!("\"entries\":[{}]", names.join(",")),
            ])
        );
    } else {
        println!("Archive written to {}", output.display());
        for (name, _) in &entries {
            println!("  + {name}");
        }
    }
    Ok(())
}

fn run_extract(
    input: String,
    key: PathBuf,
    out: PathBuf,
    list_only: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let reader = open_reader(&input)?;

    if list_only {
        let manifest = archive::list(&privkey_pem, reader, pp_str)?;
        if json {
            let entries: Vec<String> = manifest
                .iter()
                .map(|e| {
                    json_object(&[
                        kv_str("path", &e.path),
                        kv_raw("size", &e.file_size.to_string()),
                    ])
                })
                .collect();
            println!(
                "{}",
                json_object(&[
                    kv_str("status", "ok"),
                    format!("\"entries\":[{}]", entries.join(",")),
                ])
            );
        } else {
            for e in &manifest {
                println!("{:>12}  {}", e.file_size, e.path);
            }
        }
        return Ok(());
    }

    std::fs::create_dir_all(&out)?;
    let paths = archive::extract(&privkey_pem, reader, &out, pp_str)?;

    if json {
        let path_strs: Vec<String> = paths
            .iter()
            .map(|p| json_str(&p.to_string_lossy()))
            .collect();
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_raw("extracted", &paths.len().to_string()),
                format!("\"files\":[{}]", path_strs.join(",")),
            ])
        );
    } else {
        for p in &paths {
            println!("  extracted: {}", p.display());
        }
    }
    Ok(())
}

fn run_signcrypt(
    key: PathBuf,
    recipient: PathBuf,
    input: PathBuf,
    output: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let sk_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&sk_pem, "Enter passphrase for signing key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    let input_len = std::fs::metadata(&input)?.len();
    let out_path = output.unwrap_or_else(|| {
        let mut s = input.as_os_str().to_owned();
        s.push(".pqf");
        PathBuf::from(s)
    });
    ensure_overwrite_allowed(&out_path, false, force)?;

    let mut file = std::io::BufReader::new(std::fs::File::open(&input)?);
    let mut writer = AtomicOutput::new(&out_path)?;
    signcrypt::signcrypt(
        &sk_pem,
        &pubkey_pem,
        &mut file,
        input_len,
        &mut writer,
        format::CHUNK_SIZE,
        pp_str,
    )?;
    writer.commit()?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("input", &input.to_string_lossy()),
                kv_str("output", &out_path.to_string_lossy()),
            ])
        );
    } else {
        println!("Signcrypted: {}", out_path.display());
    }
    Ok(())
}

fn run_signdecrypt(
    key: PathBuf,
    verifying_key: PathBuf,
    input: String,
    output: Option<String>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let vk_pem = std::fs::read_to_string(&verifying_key)?;

    let out = output.as_deref().unwrap_or("");
    let to_stdout = out == "-" || (out.is_empty() && input == "-");
    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        PathBuf::from(&input).with_extension("")
    } else {
        PathBuf::from(out)
    };

    ensure_overwrite_allowed(&out_path, to_stdout, force)?;
    let reader = open_reader(&input)?;

    if to_stdout {
        // Buffer the entire plaintext before writing to stdout so that the ML-DSA
        // signature can be fully verified before any bytes reach the consumer.
        // The AtomicOutput approach used for file output cannot retract bytes already
        // written to stdout, so buffering is the only safe option here.
        let mut buf = zeroize::Zeroizing::new(Vec::new());
        signcrypt::signdecrypt(&privkey_pem, &vk_pem, reader, &mut *buf, pp_str)?;
        // Signature verified; now safe to emit.
        io::stdout().write_all(&buf).map_err(PqfileError::Io)?;
    } else {
        let mut writer = CliOutput::new(false, &out_path)?;
        signcrypt::signdecrypt(&privkey_pem, &vk_pem, reader, &mut writer, pp_str)?;
        writer.commit()?;
    }

    if json {
        let out_val = if to_stdout {
            "-"
        } else {
            &out_path.to_string_lossy()
        };
        let target: &mut dyn io::Write = if to_stdout {
            &mut io::stderr()
        } else {
            &mut io::stdout()
        };
        writeln!(
            target,
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", out_val),
                kv_str("signature", "valid")
            ])
        )?;
    } else {
        println!(
            "Signature valid. Decrypted to: {}",
            if to_stdout {
                "-".to_owned()
            } else {
                out_path.to_string_lossy().into_owned()
            }
        );
    }
    Ok(())
}

fn run_split_key(
    key: PathBuf,
    threshold: u8,
    shares: u8,
    out: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let result = shamir::split_key(&privkey_pem, threshold, shares, pp_str)?;
    let out_dir = out.unwrap_or_else(|| {
        key.parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf()
    });
    let paths = shamir::write_shares(&result.share_pems, &out_dir, force)?;
    if json {
        let path_strs: Vec<String> = paths
            .iter()
            .map(|p| json_str(&p.to_string_lossy()))
            .collect();
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("fingerprint", &result.pubkey_fingerprint),
                kv_raw("threshold", &threshold.to_string()),
                kv_raw("total", &shares.to_string()),
                format!("\"shares\":[{}]", path_strs.join(",")),
            ])
        );
    } else {
        println!(
            "Key split into {} shares (threshold: {})",
            result.total, result.threshold
        );
        println!("Public key fingerprint: {}", result.pubkey_fingerprint);
        for p in &paths {
            println!("  Written: {}", p.display());
        }
    }
    Ok(())
}

fn run_reconstruct_key(
    shares: Vec<PathBuf>,
    out: PathBuf,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let share_pems: Vec<String> = shares
        .iter()
        .map(std::fs::read_to_string)
        .collect::<Result<_, _>>()?;
    let refs: Vec<&str> = share_pems.iter().map(|s| s.as_str()).collect();
    let (priv_pem, pub_pem) = shamir::reconstruct_key(&refs)?;

    let priv_path = out.join("privkey.pem");
    let pub_path = out.join("pubkey.pem");
    for p in [&priv_path, &pub_path] {
        if !force && p.exists() {
            return Err(PqfileError::OutputExists(p.clone()));
        }
    }
    write_private_file(&priv_path, priv_pem.as_bytes())?;
    std::fs::write(&pub_path, pub_pem.as_bytes())?;

    let fp = keygen::fingerprint_pem(&pub_pem);
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("privkey_path", &priv_path.to_string_lossy()),
                kv_str("pubkey_path", &pub_path.to_string_lossy()),
                kv_str("fingerprint", &fp),
            ])
        );
    } else {
        println!("Key reconstructed successfully.");
        println!("Public key fingerprint: {fp}");
        println!("  Written: {}", priv_path.display());
        println!("  Written: {}", pub_path.display());
    }
    Ok(())
}

fn run_repassphrase(key: PathBuf, from_legacy: bool, json: bool) -> Result<(), PqfileError> {
    let old_pp = prompt_passphrase("Enter current passphrase: ")?;
    let new_pp = prompt_new_passphrase()?;
    repassphrase::repassphrase_file(&key, old_pp.as_str(), new_pp.as_str(), from_legacy)?;
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("key", &key.to_string_lossy()),
                kv_str(
                    "note",
                    if from_legacy {
                        "migrated from legacy p=1 to p=4"
                    } else {
                        "passphrase updated (p=4)"
                    }
                ),
            ])
        );
    } else if from_legacy {
        println!("Key migrated to Argon2id p=4: {}", key.display());
    } else {
        println!("Passphrase updated: {}", key.display());
    }
    Ok(())
}

fn run_calibrate(target_ms: u64, json: bool) -> Result<(), PqfileError> {
    if !json {
        println!("Benchmarking Argon2id (target: {target_ms} ms per derivation)...");
    }
    let r = pqfile::calibrate(target_ms)?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_raw("target_ms", &target_ms.to_string()),
                kv_raw("m_kib", &r.m_kib.to_string()),
                kv_raw("t_cost", &r.t_cost.to_string()),
                kv_raw("p_cost", &r.p_cost.to_string()),
                kv_raw("measured_ms", &r.measured_ms.to_string()),
                kv_raw("default_ms", &r.default_ms.to_string()),
            ])
        );
        return Ok(());
    }

    println!();
    println!(
        "  Compiled-in defaults (m=64 MiB, t=3, p=4) take ~{} ms on this machine.",
        r.default_ms
    );
    println!(
        "  Recommended: m={} MiB, t={}, p={}  (~{} ms measured)",
        r.m_kib / 1024,
        r.t_cost,
        r.p_cost,
        r.measured_ms
    );
    println!();
    if r.m_kib == 65536 && r.t_cost == 3 {
        println!("  The defaults already meet the target; no flags needed.");
    } else {
        println!("  Use with passphrase-only (v10) encryption:");
        println!(
            "    pqfile encrypt --passphrase --kdf-mem {} --kdf-time {} <FILE>",
            r.m_kib, r.t_cost
        );
        println!();
        println!("  Note: decrypting such files on another machine requires raising the");
        println!(
            "  decryption ceiling: pqfile decrypt --passphrase --max-kdf-mem {} --max-kdf-time {} <FILE>",
            r.m_kib, r.t_cost
        );
    }
    Ok(())
}

fn run_doctor(file: PathBuf, pubkey: Option<PathBuf>, json: bool) -> Result<(), PqfileError> {
    let content = std::fs::read(&file)?;

    // Detect file type: try reading as UTF-8 PEM first (key file), otherwise .pqf.
    let is_pem = content.starts_with(b"-----BEGIN");
    let is_pqf = content.starts_with(b"PQFL");

    if is_pem {
        doctor_key(&file, &content, pubkey.as_deref(), json)
    } else if is_pqf {
        doctor_pqf(&file, &content, json)
    } else {
        Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file is neither a PEM key nor a PQFL ciphertext",
        )))
    }
}

fn doctor_key(
    file: &Path,
    content: &[u8],
    pubkey_path: Option<&Path>,
    json: bool,
) -> Result<(), PqfileError> {
    let pem_str = std::str::from_utf8(content)
        .map_err(|e| PqfileError::InvalidPem(format!("non-UTF-8 PEM file: {e}")))?;

    let is_encrypted = keygen::is_encrypted_key(pem_str);
    let is_hardware = keygen::is_hardware_key(pem_str);

    // Detect legacy Argon2id p=1 format by probing with the real passphrase.
    //
    // LegacyKeyFormat is returned by decrypt_seed only when the key successfully
    // decrypts with p=1 parameters but not p=4.  An empty probe passphrase
    // would never authenticate a real key, so we must prompt for the actual
    // passphrase.  We pass the truncated stub `b"PQFL"` as the ciphertext
    // input so the probe terminates immediately after key derivation: on p=4
    // keys the file-magic read exhausts the input and returns Io(UnexpectedEof);
    // on p=1 keys LegacyKeyFormat is returned before any file I/O occurs.
    let is_legacy = if is_encrypted && !is_hardware {
        let pp =
            maybe_prompt_passphrase(pem_str, "Enter passphrase (for legacy Argon2 detection): ")?;
        let pp_str = pp.as_deref().map(|z| z.as_str());
        matches!(
            pqfile::decrypt::decrypt_stream(
                pem_str,
                &mut b"PQFL".as_slice(),
                &mut Vec::new(),
                pp_str,
            ),
            Err(PqfileError::LegacyKeyFormat)
        )
    } else {
        false
    };

    // Revocation sidecar check.
    let revocation_status = if let Some(pk_path) = pubkey_path {
        if let Ok(pk_pem) = std::fs::read_to_string(pk_path) {
            match revoke::check_not_revoked(pk_path, &pk_pem) {
                Ok(()) => "not_revoked",
                Err(PqfileError::KeyRevoked { .. }) => "revoked",
                Err(_) => "check_failed",
            }
        } else {
            "pubkey_not_found"
        }
    } else {
        "not_checked"
    };

    // Hardware stub validity.
    let hw_valid = if is_hardware {
        // Try to list credentials; a valid stub will have a credential store entry.
        // We use fingerprint from PEM tag as a best-effort indicator.
        "stub_present"
    } else {
        "n/a"
    };

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("file", &file.to_string_lossy()),
                kv_str("type", "private_key"),
                kv_raw("encrypted", &is_encrypted.to_string()),
                kv_raw("hardware", &is_hardware.to_string()),
                kv_raw("legacy_argon2_p1", &is_legacy.to_string()),
                kv_str("revocation", revocation_status),
                kv_str("hardware_stub", hw_valid),
            ])
        );
    } else {
        println!("File:              {}", file.display());
        println!("Type:              private key");
        println!("Encrypted:         {is_encrypted}");
        println!("Hardware-backed:   {is_hardware}");
        println!(
            "Legacy Argon2 p=1: {is_legacy}{}",
            if is_legacy {
                "; run: pqfile repassphrase --from-legacy --key <path>"
            } else {
                ""
            }
        );
        println!("Revocation:        {revocation_status}");
        if is_hardware {
            println!("Hardware stub:     {hw_valid}");
        }
    }
    Ok(())
}

fn doctor_pqf(file: &Path, content: &[u8], json: bool) -> Result<(), PqfileError> {
    let mut buf = content;
    let info = inspect_stream(&mut buf)?;

    let (version_str, kem_info_str, original_size) = match &info {
        PqfHeaderInfo::Single {
            version,
            kem_variant,
            original_size,
            ..
        } => {
            let v = format!("{version:#04x}");
            let k = kem_variant_name(*kem_variant).to_string();
            (v, k, *original_size)
        }
        PqfHeaderInfo::Multi {
            recipients,
            original_size,
            ..
        } => {
            let v = format!("{:#04x}", content.get(4).copied().unwrap_or(0));
            let k = format!("{} recipients", recipients.len());
            (v, k, *original_size)
        }
        PqfHeaderInfo::AnonMulti {
            recipients,
            original_size,
            ..
        } => {
            let v = format!("{:#04x}", content.get(4).copied().unwrap_or(0));
            let k = format!("{} slots (anon)", recipients.len());
            (v, k, *original_size)
        }
        PqfHeaderInfo::AnonMultiV8 {
            version,
            slot_count,
            original_size,
            ..
        } => {
            let v = format!("{version:#04x}");
            let label = if format::version_layout(*version) == pqfile::format::VERSION_V9 {
                "anon v9 padded"
            } else {
                "anon v8"
            };
            let k = format!("{slot_count} slots ({label})");
            (v, k, *original_size)
        }
        PqfHeaderInfo::Passphrase {
            version,
            m_kib,
            t_cost,
            original_size,
            ..
        } => {
            let v = format!("{version:#04x}");
            let k = format!("passphrase (m={m_kib} KiB, t={t_cost})");
            (v, k, *original_size)
        }
        _ => ("unknown".to_string(), "unknown".to_string(), 0u64),
    };

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("file", &file.to_string_lossy()),
                kv_str("type", "pqf_ciphertext"),
                kv_str("version", &version_str),
                kv_str("kem_info", &kem_info_str),
                kv_raw("original_size", &original_size.to_string()),
                kv_str("header_valid", "true"),
            ])
        );
    } else {
        println!("File:         {}", file.display());
        println!("Type:         .pqf ciphertext");
        println!("Version:      {version_str}");
        println!("KEM info:     {kem_info_str}");
        println!("Orig size:    {original_size} bytes");
        println!("Header:       valid");
    }
    Ok(())
}

// ── import-key ────────────────────────────────────────────────────────────

fn run_import_key(
    from: PathBuf,
    out: PathBuf,
    force: bool,
    use_passphrase: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let ssh_pem = std::fs::read_to_string(&from)?;
    let passphrase = if use_passphrase {
        Some(prompt_passphrase("Enter passphrase for new key: ")?)
    } else {
        None
    };

    // Check for existing output files.
    let pub_path = out.join("pubkey.pem");
    let priv_path = out.join("privkey.pem");
    if !force && (pub_path.exists() || priv_path.exists()) {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "pubkey.pem or privkey.pem already exists; use --force to overwrite",
        )));
    }

    let (pub_pem, priv_pem) =
        keygen::import_key_from_ssh(&ssh_pem, passphrase.as_ref().map(|z| z.as_str()))?;
    let fp = keygen::fingerprint_pem(&pub_pem);
    std::fs::create_dir_all(&out)?;
    std::fs::write(&pub_path, pub_pem.as_bytes())?;
    write_private_file(&priv_path, priv_pem.as_bytes())?;

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("from", &from.to_string_lossy()),
                kv_str("out", &out.to_string_lossy()),
                kv_str("fingerprint", &fp),
                kv_str(
                    "warning",
                    "derived key is not interoperable with the source tool"
                ),
            ])
        );
    } else {
        println!("Imported:     {}", from.display());
        println!("Saved:        {}", out.display());
        println!("Fingerprint:  {fp}");
        println!(
            "Note:         derived key is not interoperable with SSH. One-way migration only."
        );
    }
    Ok(())
}

// ── JSON helpers ──────────────────────────────────────────────────────────

fn json_escape(s: &str) -> String {
    // RFC 8259 §7: all characters in U+0000 to U+001F must be escaped.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Other ASCII control characters: emit \uXXXX escape.
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

fn kv_str(key: &str, val: &str) -> String {
    format!("{}:{}", json_str(key), json_str(val))
}

fn kv_raw(key: &str, raw: &str) -> String {
    format!("{}:{raw}", json_str(key))
}

fn json_object(pairs: &[String]) -> String {
    format!("{{{}}}", pairs.join(","))
}

/// Returns the stable numeric code for a `PqfileError`.
/// These codes are part of the public API; see `docs/ERROR_CODES.md`.
fn json_error_from(e: &PqfileError) -> String {
    json_object(&[
        kv_str("status", "error"),
        kv_raw("code", &e.code().to_string()),
        kv_str("message", &e.to_string()),
    ])
}

// ── fingerprint ───────────────────────────────────────────────────────────────

fn run_fingerprint(key: &str, qr: bool, json: bool) -> Result<(), PqfileError> {
    let pub_pem = if pqfile::recipient_string::is_recipient_string(key) {
        pqfile::recipient_string::decode_pubkey(key)?
    } else {
        std::fs::read_to_string(key)?
    };

    let fp = keygen::fingerprint_pem(&pub_pem);
    let recipient_str = pqfile::recipient_string::encode_pubkey(&pub_pem).unwrap_or_default();

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("fingerprint", &fp),
                kv_str("recipient_string", &recipient_str),
            ])
        );
    } else {
        println!("Fingerprint:      {fp}");
        if !recipient_str.is_empty() {
            println!("Recipient string: {recipient_str}");
        }
    }
    if qr && !recipient_str.is_empty() {
        print_recipient_qr(&recipient_str, json);
    }
    Ok(())
}

// ── certificates ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn run_issue_cert(
    ca_key: PathBuf,
    subject: &str,
    label: &str,
    not_before: Option<String>,
    valid_days: u32,
    allow_encrypt: bool,
    allow_sign: bool,
    output: PathBuf,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    if !allow_encrypt && !allow_sign {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "issue-cert requires at least one of --allow-encrypt or --allow-sign",
        )));
    }
    ensure_overwrite_allowed(&output, false, force)?;

    let ca_sk_pem = std::fs::read_to_string(&ca_key)?;
    let pp = maybe_prompt_passphrase(&ca_sk_pem, "Enter passphrase for CA signing key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());

    let subject_pem = if pqfile::recipient_string::is_recipient_string(subject) {
        pqfile::recipient_string::decode_pubkey(subject)?
    } else {
        std::fs::read_to_string(subject)?
    };

    let not_before_secs = match not_before {
        Some(ref date) => parse_ymd_to_unix(date)?,
        None => current_unix_secs(),
    };
    let not_after_secs = not_before_secs + u64::from(valid_days) * 86_400;

    let mut allowed_use = 0u8;
    if allow_encrypt {
        allowed_use |= pqfile::cert::cert_use::ENCRYPT;
    }
    if allow_sign {
        allowed_use |= pqfile::cert::cert_use::SIGN;
    }

    let cert_pem = pqfile::cert::issue_cert(
        &ca_sk_pem,
        pp_str,
        &subject_pem,
        label,
        not_before_secs,
        not_after_secs,
        allowed_use,
    )?;
    std::fs::write(&output, &cert_pem)?;

    let subject_fp = keygen::fingerprint_pem(&subject_pem);
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
                kv_str("label", label),
                kv_str("subject_fingerprint", &subject_fp),
                kv_str("not_before", &format_unix_date(not_before_secs)),
                kv_str("not_after", &format_unix_date(not_after_secs)),
                kv_str(
                    "allow_encrypt",
                    if allow_encrypt { "true" } else { "false" }
                ),
                kv_str("allow_sign", if allow_sign { "true" } else { "false" }),
            ])
        );
    } else {
        println!("Certificate written to {}", output.display());
        println!("Label:               {label}");
        println!("Subject fingerprint: {subject_fp}");
        println!(
            "Validity:            {} .. {}",
            format_unix_date(not_before_secs),
            format_unix_date(not_after_secs)
        );
        println!(
            "Allowed use:         {}{}",
            if allow_encrypt { "encrypt " } else { "" },
            if allow_sign { "sign" } else { "" }
        );
    }
    Ok(())
}

fn run_verify_cert(ca_key: PathBuf, cert: PathBuf, json: bool) -> Result<(), PqfileError> {
    let ca_vk_pem = std::fs::read_to_string(&ca_key)?;
    let cert_pem = std::fs::read_to_string(&cert)?;
    let now = current_unix_secs();
    let parsed = pqfile::cert::verify_cert(&ca_vk_pem, &cert_pem, now)?;
    let subject_fp = keygen::fingerprint_pem(&parsed.subject_pem);
    let allow_encrypt = parsed.permits(pqfile::cert::cert_use::ENCRYPT);
    let allow_sign = parsed.permits(pqfile::cert::cert_use::SIGN);

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("result", "valid"),
                kv_str("label", &parsed.label),
                kv_str("subject_fingerprint", &subject_fp),
                kv_str("not_before", &format_unix_date(parsed.not_before)),
                kv_str("not_after", &format_unix_date(parsed.not_after)),
                kv_str(
                    "allow_encrypt",
                    if allow_encrypt { "true" } else { "false" }
                ),
                kv_str("allow_sign", if allow_sign { "true" } else { "false" }),
            ])
        );
    } else {
        println!("Certificate is valid.");
        println!("Label:               {}", parsed.label);
        println!("Subject fingerprint: {subject_fp}");
        println!(
            "Validity:            {} .. {}",
            format_unix_date(parsed.not_before),
            format_unix_date(parsed.not_after)
        );
        println!(
            "Allowed use:         {}{}",
            if allow_encrypt { "encrypt " } else { "" },
            if allow_sign { "sign" } else { "" }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fix #14: json_escape must handle all RFC 8259 control characters ──────

    #[test]
    fn json_escape_standard_escapes() {
        assert_eq!(json_escape("\""), "\\\"");
        assert_eq!(json_escape("\\"), "\\\\");
        assert_eq!(json_escape("\n"), "\\n");
        assert_eq!(json_escape("\r"), "\\r");
        assert_eq!(json_escape("\t"), "\\t");
    }

    #[test]
    fn json_escape_control_characters() {
        // NUL (0x00) and other low control characters must be \uXXXX-escaped.
        assert_eq!(json_escape("\x00"), "\\u0000");
        assert_eq!(json_escape("\x01"), "\\u0001");
        assert_eq!(json_escape("\x1f"), "\\u001f");
        // 0x20 (space) is NOT a control character and must pass through verbatim.
        assert_eq!(json_escape(" "), " ");
    }

    #[test]
    fn json_escape_mixed_string() {
        let s = "path\x00with\nnewline";
        let escaped = json_escape(s);
        // Must not contain raw NUL or raw newline.
        assert!(!escaped.contains('\x00'));
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("\\u0000"));
        assert!(escaped.contains("\\n"));
    }

    #[test]
    fn json_escape_printable_passthrough() {
        let s = "hello/world-OK_123";
        assert_eq!(json_escape(s), s);
    }

    // ── date helpers (issue-cert / verify-cert) ────────────────────────────

    #[test]
    fn parse_ymd_known_epoch_values() {
        assert_eq!(parse_ymd_to_unix("1970-01-01").unwrap(), 0);
        assert_eq!(parse_ymd_to_unix("1970-01-02").unwrap(), 86_400);
        // 2024-01-01 00:00:00 UTC.
        assert_eq!(parse_ymd_to_unix("2024-01-01").unwrap(), 1_704_067_200);
    }

    #[test]
    fn format_unix_date_roundtrips_parse() {
        for date in ["1970-01-01", "2000-02-29", "2024-01-01", "2099-12-31"] {
            let secs = parse_ymd_to_unix(date).unwrap();
            assert_eq!(format_unix_date(secs), date);
        }
    }

    #[test]
    fn parse_ymd_rejects_malformed_input() {
        assert!(parse_ymd_to_unix("2024-1-1").is_err());
        assert!(parse_ymd_to_unix("not-a-date").is_err());
        assert!(parse_ymd_to_unix("2024-13-01").is_err());
        assert!(parse_ymd_to_unix("2024-01-32").is_err());
    }

    #[test]
    fn days_from_civil_handles_leap_years() {
        // 2020 and 2000 are leap years; 1900 and 2100 (proleptic) are not.
        assert_eq!(
            days_from_civil(2020, 2, 29) + 1,
            days_from_civil(2020, 3, 1)
        );
        assert_eq!(
            days_from_civil(2000, 2, 29) + 1,
            days_from_civil(2000, 3, 1)
        );
        assert_eq!(
            days_from_civil(1900, 2, 28) + 1,
            days_from_civil(1900, 3, 1)
        );
    }

    #[test]
    fn config_toml_parses_recipient_and_key() {
        let cfg = parse_config_toml(
            "# defaults\n\
             recipient = \"pqf1abcdef\"  # trailing comment\n\
             \n\
             key = \"C:\\\\keys\\\\privkey.pem\"\n\
             future_knob = \"ignored\"\n",
        )
        .unwrap();
        assert_eq!(cfg.recipient.as_deref(), Some("pqf1abcdef"));
        assert_eq!(cfg.key.as_deref(), Some(Path::new("C:\\keys\\privkey.pem")));
    }

    #[test]
    fn config_toml_rejects_malformed_lines() {
        assert!(parse_config_toml("recipient = unquoted").is_err());
        assert!(parse_config_toml("just some words").is_err());
        assert!(parse_config_toml("key = \"unterminated").is_err());
        assert!(parse_config_toml("key = \"bad escape \\n\"").is_err());
        assert!(parse_config_toml("key = \"trailing\" junk").is_err());
    }
}
