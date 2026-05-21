mod decrypt;
mod encrypt;
mod error;
mod format;
mod keygen;
mod passphrase;
mod sign;

use std::io::{self, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use error::PqfileError;

#[derive(Parser)]
#[command(name = "pqfile", about = "Quantum-resistant file encryption (ML-KEM-768 + ChaCha20-Poly1305)")]
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
        /// Must be in the range 64..=268435456. Not supported with multiple recipients.
        #[arg(long, value_name = "BYTES", default_value_t = format::CHUNK_SIZE)]
        chunk_size: usize,
    },
    Decrypt {
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        /// Encrypted .pqf file to decrypt, or '-' to read from stdin.
        input: String,
        /// Write decrypted output to this path, or '-' for stdout. Defaults to stripping .pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
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
        Command::Keygen { out, force, passphrase, level, hybrid } => run_keygen(out, force, level, hybrid, passphrase, json),
        Command::Encrypt { recipients, input, output, recursive, chunk_size } => {
            run_encrypt(recipients, input, output, recursive, chunk_size, json)
        }
        Command::Decrypt { key, input, output } => run_decrypt(key, input, output, json),
        Command::Inspect { input } => inspect(input.as_path(), json),
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "pqfile", &mut io::stdout());
            Ok(())
        }
        Command::SignKeygen { out, force } => run_sign_keygen(out, force, json),
        Command::Sign { key, input, output } => run_sign(key, input, output, json),
        Command::Verify { key, sig, input } => run_verify(key, sig, input, json),
    }
}

fn run_keygen(out: PathBuf, force: bool, level: u16, hybrid: bool, passphrase: bool, json: bool) -> Result<(), PqfileError> {
    let pp = if passphrase { Some(prompt_new_passphrase()?) } else { None };
    let fp = keygen::keygen(&out, force, level, pp.as_deref().map(|z| z.as_str()), hybrid)?;
    if json {
        println!("{}", json_object(&[
            kv_str("status", "ok"),
            kv_str("pubkey_path", &out.join("pubkey.pem").to_string_lossy()),
            kv_str("privkey_path", &out.join("privkey.pem").to_string_lossy()),
            kv_str("fingerprint", &fp),
        ]));
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
    chunk_size: usize,
    json: bool,
) -> Result<(), PqfileError> {
    if chunk_size == 0 || chunk_size > 268_435_456 {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("--chunk-size must be between 1 and 268435456, got {chunk_size}"),
        )));
    }
    let pubkey_pems: Vec<String> = recipients.iter()
        .map(|p| std::fs::read_to_string(p))
        .collect::<Result<_, _>>()?;
    if recursive {
        if pubkey_pems.len() != 1 {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "--recursive supports only one recipient",
            )));
        }
        run_encrypt_recursive(&pubkey_pems[0], &input, chunk_size, json)
    } else {
        run_encrypt_single(&pubkey_pems, &input, output.as_deref(), chunk_size, json)
    }
}

fn run_encrypt_single(
    pubkey_pems: &[String],
    input: &str,
    output: Option<&str>,
    chunk_size: usize,
    json: bool,
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
    if pubkey_pems.len() == 1 {
        encrypt::encrypt_stream(&pubkey_pems[0], original_size, chunk_size, &mut *reader, &mut *writer)?;
    } else {
        if chunk_size != format::CHUNK_SIZE {
            return Err(PqfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--chunk-size is not supported with multiple recipients",
            )));
        }
        let refs: Vec<&str> = pubkey_pems.iter().map(|s| s.as_str()).collect();
        encrypt::encrypt_stream_multi(&refs, original_size, &mut *reader, &mut *writer)?;
    }

    if json {
        let out_val = if to_stdout { "-" } else { &out_path.to_string_lossy() };
        let target: &mut dyn io::Write = if to_stdout { &mut io::stderr() } else { &mut io::stdout() };
        writeln!(target, "{}", json_object(&[kv_str("status", "ok"), kv_str("output", out_val)]))?;
    }
    Ok(())
}

fn run_encrypt_recursive(pubkey_pem: &str, input: &str, chunk_size: usize, json: bool) -> Result<(), PqfileError> {
    let dir = PathBuf::from(input);
    if !dir.is_dir() {
        return Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("'{input}' is not a directory (--recursive requires a directory path)"),
        )));
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
        let size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
        let result: Result<(), PqfileError> = (|| {
            let mut reader = BufReader::new(std::fs::File::open(file_path)?);
            let mut writer = BufWriter::new(std::fs::File::create(&out_path)?);
            encrypt::encrypt_stream(pubkey_pem, size, chunk_size, &mut reader, &mut writer)
        })();

        let path_str = file_path.to_string_lossy();
        let out_str = out_path.to_string_lossy();
        match result {
            Ok(()) => {
                if json {
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
                if json {
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

    if json {
        println!("[{}]", json_entries.join(","));
    }

    if any_error {
        Err(PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "one or more files failed to encrypt",
        )))
    } else {
        Ok(())
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
        } else if ft.is_file() && path.extension().map_or(true, |e| e != "pqf") {
            files.push(path);
        }
    }
    Ok(())
}

fn run_decrypt(key: PathBuf, input: String, output: Option<String>, json: bool) -> Result<(), PqfileError> {
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
    decrypt::decrypt_stream(&privkey_pem, &mut *reader, &mut *writer, pp_str)?;

    if json {
        let out_val = if to_stdout { "-" } else { &out_path.to_string_lossy() };
        let target: &mut dyn io::Write = if to_stdout { &mut io::stderr() } else { &mut io::stdout() };
        writeln!(target, "{}", json_object(&[kv_str("status", "ok"), kv_str("output", out_val)]))?;
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
        rpassword::prompt_password("Enter passphrase: ").map_err(PqfileError::Io)?
    );
    let confirm = zeroize::Zeroizing::new(
        rpassword::prompt_password("Confirm passphrase: ").map_err(PqfileError::Io)?
    );
    if *pp != *confirm {
        return Err(PqfileError::PassphraseMismatch);
    }
    Ok(pp)
}

fn prompt_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>, PqfileError> {
    Ok(zeroize::Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(PqfileError::Io)?
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
    let version = format::PqfHeader::read_magic_version(&mut reader)?;

    match version {
        format::VERSION | format::VERSION_V3 => {
            let header = format::PqfHeader::read_body(&mut reader, version)?;
            let nonce_hex: String = header.nonce.iter().map(|b| format!("{b:02x}")).collect();
            let variant_name = kem_variant_name(header.kem_variant);
            if json {
                println!("{}", json_object(&[
                    kv_str("status", "ok"),
                    kv_str("magic", "PQFL"),
                    kv_str("version", &format!("{:#04x}", header.version)),
                    kv_raw("kem_variant", &format!("{}", header.kem_variant)),
                    kv_str("kem_variant_name", variant_name),
                    kv_str("nonce", &nonce_hex),
                    kv_raw("original_size", &format!("{}", header.original_size)),
                ]));
            } else {
                println!("Magic:              PQFL");
                println!("Version:            {:#04x}", header.version);
                println!("KEM variant:        {} ({})", header.kem_variant, variant_name);
                println!("Nonce:              {nonce_hex}");
                println!("Original file size: {} bytes", header.original_size);
            }
            Ok(())
        }
        format::VERSION_V4 => {
            let header = format::PqfHeaderV4::read_body(&mut reader)?;
            let nonce_hex: String = header.nonce.iter().map(|b| format!("{b:02x}")).collect();
            if json {
                let recipients_json: Vec<String> = header.recipients.iter().map(|r| {
                    json_object(&[
                        kv_raw("kem_variant", &r.kem_variant.to_string()),
                        kv_str("kem_variant_name", kem_variant_name(r.kem_variant)),
                    ])
                }).collect();
                println!("{}", json_object(&[
                    kv_str("status", "ok"),
                    kv_str("magic", "PQFL"),
                    kv_str("version", "0x04"),
                    kv_raw("recipient_count", &header.recipients.len().to_string()),
                    format!("\"recipients\":[{}]", recipients_json.join(",")),
                    kv_str("nonce", &nonce_hex),
                    kv_raw("original_size", &header.original_size.to_string()),
                ]));
            } else {
                println!("Magic:              PQFL");
                println!("Version:            0x04 (multi-recipient)");
                println!("Recipients:         {}", header.recipients.len());
                for (i, r) in header.recipients.iter().enumerate() {
                    println!("  Recipient {i}:      {} ({})", r.kem_variant, kem_variant_name(r.kem_variant));
                }
                println!("Nonce:              {nonce_hex}");
                println!("Original file size: {} bytes", header.original_size);
            }
            Ok(())
        }
        v => Err(PqfileError::UnsupportedVersion(v)),
    }
}

fn run_sign_keygen(out: PathBuf, force: bool, json: bool) -> Result<(), PqfileError> {
    let r = sign::sign_keygen(&out, force)?;
    if json {
        println!("{}", json_object(&[
            kv_str("status", "ok"),
            kv_str("vk_path", &out.join("sign_pubkey.pem").to_string_lossy()),
            kv_str("sk_path", &out.join("sign_privkey.pem").to_string_lossy()),
            kv_str("fingerprint", &r.vk_fingerprint),
        ]));
    } else {
        println!("Signing keys written to {}", out.display());
        println!("Verifying key fingerprint: {}", r.vk_fingerprint);
    }
    Ok(())
}

fn run_sign(key: PathBuf, input: PathBuf, output: Option<PathBuf>, json: bool) -> Result<(), PqfileError> {
    let sk_pem = std::fs::read_to_string(&key)?;
    let sig_path = output.unwrap_or_else(|| sign::default_sig_path(&input));
    sign::sign_file(&sk_pem, &input, &sig_path)?;
    if json {
        println!("{}", json_object(&[
            kv_str("status", "ok"),
            kv_str("input", &input.to_string_lossy()),
            kv_str("signature", &sig_path.to_string_lossy()),
        ]));
    } else {
        println!("Signature written to {}", sig_path.display());
    }
    Ok(())
}

fn run_verify(key: PathBuf, sig: PathBuf, input: PathBuf, json: bool) -> Result<(), PqfileError> {
    let vk_pem = std::fs::read_to_string(&key)?;
    sign::verify_file(&vk_pem, &input, &sig)?;
    if json {
        println!("{}", json_object(&[
            kv_str("status", "ok"),
            kv_str("input", &input.to_string_lossy()),
            kv_str("signature", &sig.to_string_lossy()),
            kv_str("result", "valid"),
        ]));
    } else {
        println!("Signature is valid.");
    }
    Ok(())
}

// ── JSON helpers ──────────────────────────────────────────────────────────

fn json_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"'  => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c    => vec![c],
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
