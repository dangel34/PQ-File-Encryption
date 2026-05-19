mod decrypt;
mod encrypt;
mod error;
mod format;
mod keygen;
mod passphrase;

use std::io::{self, Read, Write};
use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use error::PqfileError;

#[derive(Parser)]
#[command(name = "pqfile", about = "Quantum-resistant file encryption (ML-KEM-768 + ChaCha20-Poly1305)")]
struct Cli {
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
    },
    Encrypt {
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        /// Input file to encrypt, or '-' to read from stdin.
        input: String,
        /// Write encrypted output to this path, or '-' for stdout. Defaults to <input>.pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<String>,
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
}

fn run() -> Result<(), PqfileError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { out, force, passphrase } => {
            let pp = if passphrase {
                Some(prompt_new_passphrase()?)
            } else {
                None
            };
            let fp = keygen::keygen(&out, force, pp.as_deref().map(|z| z.as_str()))?;
            println!("Keys written to {}", out.display());
            println!("Public key fingerprint: {fp}");
            Ok(())
        }
        Command::Encrypt { recipient, input, output } => {
            let pubkey_pem = std::fs::read_to_string(&recipient)?;
            let plaintext = read_input(&input)?;
            let ciphertext = encrypt::encrypt_bytes(&pubkey_pem, &plaintext)?;
            let out = output.as_deref().unwrap_or_else(|| {
                if input == "-" { "-" } else { "" } // resolved below
            });
            if out == "-" || (out.is_empty() && input == "-") {
                io::stdout().write_all(&ciphertext)?;
            } else {
                let path: PathBuf = if out.is_empty() {
                    let mut s = std::ffi::OsString::from(&input);
                    s.push(".pqf");
                    PathBuf::from(s)
                } else {
                    PathBuf::from(out)
                };
                std::fs::write(&path, &ciphertext)?;
            }
            Ok(())
        }
        Command::Decrypt { key, input, output } => {
            let privkey_pem = std::fs::read_to_string(&key)?;
            let pp = if keygen::is_encrypted_key(&privkey_pem) {
                Some(prompt_passphrase("Enter passphrase for private key: ")?)
            } else {
                None
            };
            let pqf_data = read_input(&input)?;
            let plaintext = decrypt::decrypt_bytes(&privkey_pem, &pqf_data, pp.as_deref().map(|z| z.as_str()))?;
            let out = output.as_deref().unwrap_or("");
            if out == "-" || (out.is_empty() && input == "-") {
                io::stdout().write_all(&plaintext)?;
            } else {
                let path: PathBuf = if out.is_empty() {
                    PathBuf::from(&input).with_extension("")
                } else {
                    PathBuf::from(out)
                };
                std::fs::write(&path, &plaintext)?;
            }
            Ok(())
        }
        Command::Inspect { input } => inspect(input.as_path()),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "pqfile", &mut std::io::stdout());
            Ok(())
        }
    }
}

/// Reads all bytes from `path`. If `path` is `"-"`, reads from stdin.
fn read_input(path: &str) -> Result<Vec<u8>, PqfileError> {
    if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read(path)?)
    }
}

/// Prompts for a new passphrase with confirmation.
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

/// Prompts for an existing passphrase without confirmation.
fn prompt_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>, PqfileError> {
    Ok(zeroize::Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(PqfileError::Io)?
    ))
}

fn inspect(input: &std::path::Path) -> Result<(), PqfileError> {
    use std::io::BufReader;
    let file = std::fs::File::open(input)?;
    let mut reader = BufReader::new(file);
    let header = format::PqfHeader::read(&mut reader)?;

    println!("Magic:              PQFL");
    println!("Version:            {:#04x}", format::VERSION);
    println!("KEM variant:        {}", format::KEM_VARIANT);
    println!(
        "Nonce:              {}",
        header
            .nonce
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("Original file size: {} bytes", header.original_size);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
