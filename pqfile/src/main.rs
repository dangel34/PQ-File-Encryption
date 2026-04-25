use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use pqfile::decrypt;
use pqfile::encrypt;
use pqfile::error::PqfileError;
use pqfile::format;
use pqfile::keygen;

#[derive(Parser)]
#[command(name = "pqfile", about = "Quantum-resistant file encryption (ML-KEM-768 + ChaCha20-Poly1305)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new ML-KEM-768 key pair and write PEM files to a directory.
    Keygen {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Encrypt one or more files using a recipient's public key.
    Encrypt {
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        #[arg(required = true, value_name = "INPUT")]
        inputs: Vec<PathBuf>,
    },
    /// Decrypt one or more .pqf files using a private key.
    Decrypt {
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        #[arg(required = true, value_name = "INPUT")]
        inputs: Vec<PathBuf>,
    },
    /// Display the header metadata of a .pqf file without decrypting it.
    Inspect {
        input: PathBuf,
    },
}

fn run() -> Result<(), PqfileError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { out } => {
            let fingerprint = keygen::keygen(&out)?;
            println!("pubkey:      {}", out.join("pubkey.pem").display());
            println!("privkey:     {}", out.join("privkey.pem").display());
            println!("fingerprint: {fingerprint}");
            Ok(())
        }
        Command::Encrypt { recipient, inputs } => {
            let pub_pem = fs::read_to_string(&recipient)?;
            for input in &inputs {
                let output = {
                    let mut s = input.as_os_str().to_owned();
                    s.push(".pqf");
                    PathBuf::from(s)
                };
                encrypt::encrypt_file(&pub_pem, input, &output)?;
                println!("Encrypted  {} → {}", input.display(), output.display());
            }
            Ok(())
        }
        Command::Decrypt { key, inputs } => {
            let priv_pem = fs::read_to_string(&key)?;
            for input in &inputs {
                let output = input.with_extension("");
                decrypt::decrypt_file(&priv_pem, input, &output)?;
                println!("Decrypted  {} → {}", input.display(), output.display());
            }
            Ok(())
        }
        Command::Inspect { input } => inspect(&input),
    }
}

fn inspect(input: &std::path::Path) -> Result<(), PqfileError> {
    use std::io::BufReader;
    let file = std::fs::File::open(input)?;
    let mut reader = BufReader::new(file);
    let header = format::PqfHeader::read(&mut reader)?;

    println!("Magic:              PQFL");
    println!("Version:            {:#04x}", format::VERSION);
    println!("KEM variant:        {}", format::KEM_VARIANT);
    println!("Header size:        {} bytes", format::HEADER_SIZE);
    println!(
        "Nonce:              {}",
        header.nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
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
