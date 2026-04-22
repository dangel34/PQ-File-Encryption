mod decrypt;
mod encrypt;
mod error;
mod format;
mod keygen;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    },
    Encrypt {
        #[arg(short = 'r', value_name = "PUBKEY")]
        recipient: PathBuf,
        input: PathBuf,
    },
    Decrypt {
        #[arg(short = 'k', value_name = "PRIVKEY")]
        key: PathBuf,
        input: PathBuf,
    },
    Inspect {
        input: PathBuf,
    },
}

fn run() -> Result<(), PqfileError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { out } => keygen::keygen(&out),
        Command::Encrypt { recipient, input } => encrypt::encrypt(&recipient, &input),
        Command::Decrypt { key, input } => decrypt::decrypt(&key, &input),
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
