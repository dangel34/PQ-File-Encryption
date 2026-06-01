use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use pqfile::error::PqfileError;
use pqfile::inspect::{inspect_stream, PqfHeaderInfo, RecipientInfo};
use pqfile::{archive, decrypt, encrypt, format, keygen, rekey, revoke, shamir, sign, signcrypt};

#[derive(Parser)]
#[command(
    name = "pqfile",
    about = "Quantum-resistant file encryption for the post-quantum era. Encrypt any file with a public key. Only the matching private key can decrypt it."
)]
struct Cli {
    /// Emit machine-readable JSON to stdout (errors go to stderr as JSON).
    #[arg(long, global = true)]
    json: bool,

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
        #[arg(long, default_value_t = false)]
        passphrase: bool,
        /// KEM security level: 512 (ML-KEM-512), 768 (ML-KEM-768, default), or 1024 (ML-KEM-1024).
        #[arg(long, value_name = "LEVEL", default_value_t = 768u16)]
        level: u16,
        /// Generate a Hybrid X25519+ML-KEM-768 key pair for combined classical+PQ security.
        #[arg(long, default_value_t = false)]
        hybrid: bool,
    },
    Encrypt {
        /// Recipient public key(s). Repeat -r for multiple recipients (v4 format).
        #[arg(short = 'r', value_name = "PUBKEY", action = clap::ArgAction::Append, required = true)]
        recipients: Vec<PathBuf>,
        /// Input file to encrypt, or '-' to read from stdin.
        input: String,
        /// Write encrypted output to this path, or '-' for stdout.
        /// Defaults to <input>.pqf. Ignored in --recursive mode.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Encrypt every file in a directory tree. INPUT must be a directory.
        /// Each file is written alongside the original as <file>.pqf.
        #[arg(long, default_value_t = false)]
        recursive: bool,
        /// Chunk size in bytes for streaming encryption (default: 65536).
        /// Values other than the default produce v5 format files with the chunk size stored in the header.
        /// Must be in the range 1..=268435456. Not supported with multiple recipients.
        #[arg(long, value_name = "BYTES", default_value_t = format::CHUNK_SIZE)]
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
        /// Hide recipient identities in multi-recipient files (v7 format): all KEM ciphertexts are
        /// padded to a uniform size and recipient entries are written in random order.
        /// Requires multiple -r recipients; has no effect with a single recipient.
        #[arg(long, default_value_t = false)]
        anonymous_recipients: bool,
    },
    Decrypt {
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        /// Encrypted .pqf file to decrypt, or '-' to read from stdin.
        input: String,
        /// Write decrypted output to this path, or '-' for stdout. Defaults to stripping .pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
        /// Decrypt chunks in parallel using rayon (only effective for v3/v5 format files).
        #[arg(long, default_value_t = false)]
        parallel: bool,
    },
    Inspect {
        input: PathBuf,
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
    /// Generate an ML-DSA-65 signing key pair.
    #[command(name = "sign-keygen")]
    SignKeygen {
        /// Directory to write sign_pubkey.pem and sign_privkey.pem.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Overwrite existing key files without prompting.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Protect the signing private key with a passphrase (prompted interactively).
        #[arg(long, default_value_t = false)]
        passphrase: bool,
    },
    /// Sign a file with an ML-DSA-65 signing key, producing a detached .sig file.
    Sign {
        /// Path to sign_privkey.pem (ML-DSA-65 signing key).
        #[arg(short = 'k', value_name = "SIGNING_KEY")]
        key: PathBuf,
        /// File to sign.
        input: PathBuf,
        /// Output path for the detached signature (defaults to <input>.sig).
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Verify a detached ML-DSA-65 signature against a file.
    Verify {
        /// Path to sign_pubkey.pem (ML-DSA-65 verifying key).
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
        #[arg(value_name = "FILE", required = true)]
        files: Vec<PathBuf>,
        /// Strip this prefix from each file path when computing the archive entry name.
        #[arg(long, value_name = "DIR")]
        base: Option<PathBuf>,
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
}

const PARALLEL_BATCH_SIZE: usize = 8;

#[derive(Clone, Copy)]
struct EncryptOpts {
    chunk_size: usize,
    compress: bool,
    compress_level: i32,
    parallel: bool,
    anonymous_recipients: bool,
    json: bool,
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    if let Err(e) = run(cli) {
        if json {
            eprintln!("{}", json_error(&e.to_string()));
        } else {
            eprintln!("error: {e}");
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), PqfileError> {
    let json = cli.json;
    match cli.command {
        Command::Keygen {
            out,
            force,
            passphrase,
            level,
            hybrid,
        } => run_keygen(out, force, level, hybrid, passphrase, json),
        Command::Encrypt {
            recipients,
            input,
            output,
            recursive,
            chunk_size,
            compress,
            compress_level,
            parallel,
            anonymous_recipients,
        } => run_encrypt(
            recipients,
            input,
            output,
            recursive,
            EncryptOpts {
                chunk_size,
                compress,
                compress_level,
                parallel,
                anonymous_recipients,
                json,
            },
        ),
        Command::Decrypt {
            key,
            input,
            output,
            parallel,
        } => run_decrypt(key, input, output, parallel, json),
        Command::Inspect { input } => inspect(input.as_path(), json),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "pqfile", &mut io::stdout());
            Ok(())
        }
        Command::SignKeygen {
            out,
            force,
            passphrase,
        } => run_sign_keygen(out, force, passphrase, json),
        Command::Sign { key, input, output } => run_sign(key, input, output, json),
        Command::Verify { key, sig, input } => run_verify(key, sig, input, json),
        Command::Revoke { key, reason } => run_revoke(key, &reason, json),
        Command::Rekey {
            key,
            recipient,
            input,
            output,
        } => run_rekey(key, recipient, input, output, json),
        Command::Archive {
            recipient,
            output,
            files,
            base,
        } => run_archive(recipient, output, files, base, json),
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
        } => run_signcrypt(key, recipient, input, output, json),
        Command::Signdecrypt {
            key,
            verifying_key,
            input,
            output,
        } => run_signdecrypt(key, verifying_key, input, output, json),
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
    }
}

fn run_keygen(
    out: PathBuf,
    force: bool,
    level: u16,
    hybrid: bool,
    passphrase: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let pp = if passphrase {
        Some(prompt_new_passphrase()?)
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
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("pubkey_path", &out.join("pubkey.pem").to_string_lossy()),
                kv_str("privkey_path", &out.join("privkey.pem").to_string_lossy()),
                kv_str("fingerprint", &fp),
            ])
        );
    } else {
        println!("Keys written to {}", out.display());
        println!("Public key fingerprint: {fp}");
    }
    Ok(())
}

fn run_encrypt(
    recipients: Vec<PathBuf>,
    input: String,
    output: Option<String>,
    recursive: bool,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
    if opts.chunk_size == 0 || opts.chunk_size > 268_435_456 {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "--chunk-size must be between 1 and 268435456, got {}",
                opts.chunk_size
            ),
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
    // Check revocation for all recipient key files before encrypting.
    let pubkey_pems: Vec<String> = recipients
        .iter()
        .map(|p| {
            let pem = std::fs::read_to_string(p)?;
            revoke::check_not_revoked(p, &pem)?;
            Ok::<_, PqfileError>(pem)
        })
        .collect::<Result<_, _>>()?;
    if recursive {
        if pubkey_pems.len() != 1 {
            return Err(PqfileError::Io(std::io::Error::other(
                "--recursive supports only one recipient",
            )));
        }
        run_encrypt_recursive(&pubkey_pems[0], &input, opts)
    } else {
        run_encrypt_single(&pubkey_pems, &input, output.as_deref(), opts)
    }
}

fn run_encrypt_single(
    pubkey_pems: &[String],
    input: &str,
    output: Option<&str>,
    opts: EncryptOpts,
) -> Result<(), PqfileError> {
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

    let mut reader = open_reader(input)?;
    let mut writer = open_writer(to_stdout, &out_path)?;
    perform_encrypt(
        pubkey_pems,
        original_size,
        &opts,
        &mut *reader,
        &mut *writer,
    )?;

    if opts.json {
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
            json_object(&[kv_str("status", "ok"), kv_str("output", out_val)])
        )?;
    }
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
        if opts.compress {
            encrypt::encrypt_stream_compressed(
                &pubkey_pems[0],
                original_size,
                opts.chunk_size,
                opts.compress_level,
                reader,
                writer,
            )
        } else if opts.parallel {
            encrypt::encrypt_stream_parallel(
                &pubkey_pems[0],
                original_size,
                opts.chunk_size,
                PARALLEL_BATCH_SIZE,
                reader,
                writer,
            )
        } else {
            encrypt::encrypt_stream(
                &pubkey_pems[0],
                original_size,
                opts.chunk_size,
                reader,
                writer,
            )
        }
    } else {
        if opts.chunk_size != format::CHUNK_SIZE {
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
        if opts.anonymous_recipients {
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
    let mut reader = BufReader::new(std::fs::File::open(file_path)?);
    let mut writer = BufWriter::new(std::fs::File::create(out_path)?);
    if opts.compress {
        encrypt::encrypt_stream_compressed(
            pubkey_pem,
            size,
            opts.chunk_size,
            opts.compress_level,
            &mut reader,
            &mut writer,
        )
    } else {
        encrypt::encrypt_stream(pubkey_pem, size, opts.chunk_size, &mut reader, &mut writer)
    }
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

fn run_decrypt(
    key: PathBuf,
    input: String,
    output: Option<String>,
    parallel: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = if keygen::is_encrypted_key(&privkey_pem) {
        Some(prompt_passphrase("Enter passphrase for private key: ")?)
    } else {
        None
    };
    let pp_str = pp.as_deref().map(|z| z.as_str());

    let out = output.as_deref().unwrap_or("");
    let to_stdout = out == "-" || (out.is_empty() && input == "-");

    let out_path: PathBuf = if to_stdout {
        PathBuf::new()
    } else if out.is_empty() {
        PathBuf::from(&input).with_extension("")
    } else {
        PathBuf::from(out)
    };

    let mut reader = open_reader(&input)?;
    let mut writer = open_writer(to_stdout, &out_path)?;
    if parallel {
        decrypt::decrypt_stream_parallel(
            &privkey_pem,
            &mut *reader,
            &mut *writer,
            pp_str,
            PARALLEL_BATCH_SIZE,
        )?;
    } else {
        decrypt::decrypt_stream(&privkey_pem, &mut *reader, &mut *writer, pp_str)?;
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
            json_object(&[kv_str("status", "ok"), kv_str("output", out_val)])
        )?;
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

fn open_writer(to_stdout: bool, path: &Path) -> Result<Box<dyn io::Write>, PqfileError> {
    if to_stdout {
        Ok(Box::new(io::stdout()))
    } else {
        Ok(Box::new(BufWriter::new(std::fs::File::create(path)?)))
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
    let file = std::fs::File::open(input)?;
    let mut reader = BufReader::new(file);
    let info = inspect_stream(&mut reader)?;
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
            let has_chunk_size = *version == format::VERSION_V5 || *version == format::VERSION_V6;
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
                    kv_raw("kem_variant", &format!("{kem_variant}")),
                    kv_str("kem_variant_name", variant_name),
                    kv_str("nonce", &nonce_hex),
                    kv_raw("original_size", &format!("{original_size}")),
                ];
                if has_chunk_size {
                    fields.push(kv_raw("chunk_size", &format!("{chunk_size}")));
                }
                if *version == format::VERSION_V6 {
                    fields.push(kv_str("compression", compression_name));
                }
                println!("{}", json_object(&fields));
            } else {
                println!("Magic:              PQFL");
                println!("Version:            {version:#04x}");
                println!("KEM variant:        {kem_variant} ({variant_name})");
                println!("Nonce:              {nonce_hex}");
                println!("Original file size: {original_size} bytes");
                if has_chunk_size {
                    println!("Chunk size:         {chunk_size} bytes");
                }
                if *version == format::VERSION_V6 {
                    println!("Compression:        {compression_name}");
                }
            }
        }
        PqfHeaderInfo::Multi {
            recipients,
            nonce,
            original_size,
        } => print_multi_header(
            "0x04",
            "0x04 (multi-recipient)",
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
            "0x07",
            "0x07 (anonymous multi-recipient)",
            nonce,
            *original_size,
            recipients,
            Some("anonymous-recipients"),
            " (order shuffled)",
            &|i, v, name| println!("  Slot {i}:           {v} ({name})"),
            json,
        ),
        _ => return Err(PqfileError::UnsupportedVersion(0)),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn print_multi_header(
    version_num: &str,
    version_label: &str,
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
        println!("Recipients:         {}{count_suffix}", recipients.len());
        for (i, r) in recipients.iter().enumerate() {
            let name = kem_variant_name(r.kem_variant);
            row_fmt(i, r.kem_variant, name);
        }
        println!("Nonce:              {nonce_hex}");
        println!("Original file size: {original_size} bytes");
    }
}

fn run_sign_keygen(
    out: PathBuf,
    force: bool,
    use_passphrase: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let pp = if use_passphrase {
        Some(prompt_new_passphrase()?)
    } else {
        None
    };
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let r = sign::sign_keygen(&out, force, pp_str)?;
    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("vk_path", &out.join("sign_pubkey.pem").to_string_lossy()),
                kv_str("sk_path", &out.join("sign_privkey.pem").to_string_lossy()),
                kv_str("fingerprint", &r.vk_fingerprint),
            ])
        );
    } else {
        println!("Signing keys written to {}", out.display());
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
    let pp = if pqfile::keys::PqfSigningKey::from_pem(&sk_pem)
        .map(|k| k.is_encrypted())
        .unwrap_or(false)
    {
        Some(prompt_passphrase("Enter passphrase for signing key: ")?)
    } else {
        None
    };
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
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = if keygen::is_encrypted_key(&privkey_pem) {
        Some(prompt_passphrase("Enter passphrase for private key: ")?)
    } else {
        None
    };
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

    let mut reader = open_reader(&input)?;
    let mut writer = open_writer(to_stdout, &out_path)?;
    rekey::rekey_stream(
        &privkey_pem,
        &pubkey_pem,
        &mut *reader,
        &mut *writer,
        pp_str,
    )?;

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
            json_object(&[kv_str("status", "ok"), kv_str("output", out_val)])
        )?;
    }
    Ok(())
}

fn run_archive(
    recipient: PathBuf,
    output: PathBuf,
    files: Vec<PathBuf>,
    base: Option<PathBuf>,
    json: bool,
) -> Result<(), PqfileError> {
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    let entries: Result<Vec<(String, PathBuf)>, PqfileError> = files
        .iter()
        .map(|f| {
            let archive_name = if let Some(ref b) = base {
                f.strip_prefix(b)
                    .unwrap_or(f.as_path())
                    .to_string_lossy()
                    .replace('\\', "/")
            } else {
                f.file_name()
                    .unwrap_or(f.as_os_str())
                    .to_string_lossy()
                    .to_string()
            };
            Ok((archive_name, f.clone()))
        })
        .collect();
    let entries = entries?;

    let mut writer = BufWriter::new(std::fs::File::create(&output)?);
    archive::create(&pubkey_pem, &entries, &mut writer)?;

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
    let pp = if keygen::is_encrypted_key(&privkey_pem) {
        Some(prompt_passphrase("Enter passphrase for private key: ")?)
    } else {
        None
    };
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
    json: bool,
) -> Result<(), PqfileError> {
    let sk_pem = std::fs::read_to_string(&key)?;
    let pp = if pqfile::keys::PqfSigningKey::from_pem(&sk_pem)
        .map(|k| k.is_encrypted())
        .unwrap_or(false)
    {
        Some(prompt_passphrase("Enter passphrase for signing key: ")?)
    } else {
        None
    };
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pubkey_pem = std::fs::read_to_string(&recipient)?;
    revoke::check_not_revoked(&recipient, &pubkey_pem)?;

    let input_len = std::fs::metadata(&input)?.len();
    let out_path = output.unwrap_or_else(|| {
        let mut s = input.as_os_str().to_owned();
        s.push(".pqf");
        PathBuf::from(s)
    });

    let mut file = std::io::BufReader::new(std::fs::File::open(&input)?);
    let mut writer = BufWriter::new(std::fs::File::create(&out_path)?);
    signcrypt::signcrypt(
        &sk_pem,
        &pubkey_pem,
        &mut file,
        input_len,
        &mut writer,
        format::CHUNK_SIZE,
        pp_str,
    )?;

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
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = if keygen::is_encrypted_key(&privkey_pem) {
        Some(prompt_passphrase("Enter passphrase for private key: ")?)
    } else {
        None
    };
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

    let reader = open_reader(&input)?;
    let mut writer = open_writer(to_stdout, &out_path)?;
    signcrypt::signdecrypt(&privkey_pem, &vk_pem, reader, &mut *writer, pp_str)?;

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
    let pp = if keygen::is_encrypted_key(&privkey_pem) {
        Some(prompt_passphrase("Enter passphrase for private key: ")?)
    } else {
        None
    };
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
    std::fs::write(&priv_path, priv_pem.as_bytes())?;
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

// ── JSON helpers ──────────────────────────────────────────────────────────

fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c => vec![c],
        })
        .collect()
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

fn json_error(msg: &str) -> String {
    json_object(&[kv_str("status", "error"), kv_str("message", msg)])
}
