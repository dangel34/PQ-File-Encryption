//! `sign-keygen`, `sign`, `verify`, `signcrypt`, `signdecrypt`: ML-DSA-65 /
//! SLH-DSA-SHAKE-192f digital signatures, plus the combined sign-then-encrypt
//! / decrypt-then-verify commands.

use std::io::{self, Write};
use std::path::PathBuf;

use pqfile::error::PqfileError;
use pqfile::{format, keygen, sign, signcrypt};

use crate::commands::cert::{resolve_cert, resolve_single_recipient};
use crate::io_util::{
    emit_decrypt_verified_status, open_reader, resolve_decrypt_out_path,
    resolve_pqf_sibling_out_path, AtomicOutput, CliOutput,
};
use crate::json_util::{json_object, kv_str};
use crate::prompts::{maybe_prompt_passphrase, prompt_new_passphrase};

/// CLI-facing signature algorithm choice for `sign-keygen`.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum SigAlgorithmArg {
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

pub(crate) fn run_sign_keygen(
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

pub(crate) fn run_sign(
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

pub(crate) fn run_verify(
    key: PathBuf,
    ca_key: Option<PathBuf>,
    revocations: Option<PathBuf>,
    sig: PathBuf,
    input: PathBuf,
    json: bool,
) -> Result<(), PqfileError> {
    let pem = std::fs::read_to_string(&key)?;
    let vk_pem = resolve_cert(
        &pem,
        &key,
        ca_key.as_deref(),
        revocations.as_deref(),
        pqfile::cert::cert_use::SIGN,
    )?
    .unwrap_or(pem);
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_signcrypt(
    key: PathBuf,
    recipient: PathBuf,
    ca_key: Option<PathBuf>,
    revocations: Option<PathBuf>,
    input: PathBuf,
    output: Option<PathBuf>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let sk_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&sk_pem, "Enter passphrase for signing key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pem = std::fs::read_to_string(&recipient)?;
    let pubkey_pem = resolve_single_recipient(
        pem,
        &recipient,
        ca_key.as_deref(),
        revocations.as_deref(),
        pqfile::cert::cert_use::ENCRYPT,
    )?;

    let input_len = std::fs::metadata(&input)?.len();
    let out_path = resolve_pqf_sibling_out_path(&input, output, force)?;

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

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_signdecrypt(
    key: PathBuf,
    verifying_key: PathBuf,
    ca_key: Option<PathBuf>,
    revocations: Option<PathBuf>,
    input: String,
    output: Option<String>,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    let privkey_pem = std::fs::read_to_string(&key)?;
    let pp = maybe_prompt_passphrase(&privkey_pem, "Enter passphrase for private key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let pem = std::fs::read_to_string(&verifying_key)?;
    let vk_pem = resolve_cert(
        &pem,
        &verifying_key,
        ca_key.as_deref(),
        revocations.as_deref(),
        pqfile::cert::cert_use::SIGN,
    )?
    .unwrap_or(pem);

    let (to_stdout, out_path) = resolve_decrypt_out_path(&input, output.as_deref(), force)?;
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

    emit_decrypt_verified_status(
        json,
        to_stdout,
        &out_path,
        "signature",
        "valid",
        "Signature valid.",
    )
}
