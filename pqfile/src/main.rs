mod decrypt;
mod encrypt;
mod error;
mod format;
mod keygen;
mod passphrase;

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
        input: PathBuf,
        /// Write encrypted output to this path instead of <input>.pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    Decrypt {
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        input: PathBuf,
        /// Write decrypted output to this path instead of stripping .pqf.
        #[arg(short = 'o', long, value_name = "FILE")]
        output: Option<PathBuf>,
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
                let p = prompt_new_passphrase()?;
                Some(p)
            } else {
                None
            };
            let fp = keygen::keygen(&out, force, pp.as_deref())?;
            println!("Keys written to {}", out.display());
            println!("Public key fingerprint: {fp}");
            Ok(())
        }
        Command::Encrypt { recipient, input, output } => {
            encrypt::encrypt(&recipient, &input, output.as_deref())
        }
        Command::Decrypt { key, input, output } => {
            let privkey_pem = std::fs::read_to_string(&key)?;
            let pp = if needs_passphrase(&privkey_pem) {
                Some(prompt_passphrase("Enter passphrase for private key: ")?)
            } else {
                None
            };
            decrypt::decrypt(&key, &input, output.as_deref(), pp.as_deref())
        }
        Command::Inspect { input } => inspect(&input),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "pqfile", &mut std::io::stdout());
            Ok(())
        }
    }
}

/// Returns true if the PEM file uses the encrypted private key tag.
fn needs_passphrase(pem_str: &str) -> bool {
    pem::parse(pem_str)
        .map(|p| p.tag() == keygen::PRIV_ENC_TAG)
        .unwrap_or(false)
}

/// Prompts for a new passphrase with confirmation.
fn prompt_new_passphrase() -> Result<String, PqfileError> {
    let pp = rpassword::prompt_password("Enter passphrase: ")
        .map_err(|e| PqfileError::Io(e))?;
    let confirm = rpassword::prompt_password("Confirm passphrase: ")
        .map_err(|e| PqfileError::Io(e))?;
    if pp != confirm {
        eprintln!("error: passphrases do not match");
        std::process::exit(1);
    }
    Ok(pp)
}

/// Prompts for an existing passphrase without confirmation.
fn prompt_passphrase(prompt: &str) -> Result<String, PqfileError> {
    rpassword::prompt_password(prompt).map_err(|e| PqfileError::Io(e))
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
