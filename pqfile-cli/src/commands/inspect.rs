//! `inspect` (header display), `doctor` (key/file health check plus
//! `--calibrate`): commands that describe a key or `.pqf` file without
//! decrypting its payload.

use std::io::BufReader;
use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;
use pqfile::inspect::{inspect_stream, PqfHeaderInfo, RecipientInfo};
use pqfile::{format, keygen, revoke};

use crate::json_util::{json_object, kv_raw, kv_str};
use crate::prompts::maybe_prompt_passphrase;

fn kem_variant_name(variant: u16) -> &'static str {
    match variant {
        512 => "ML-KEM-512",
        768 => "ML-KEM-768",
        1024 => "ML-KEM-1024",
        0x0301 => "Hybrid X25519+ML-KEM-768",
        _ => "unknown",
    }
}

pub(crate) fn inspect(input: &Path, json: bool) -> Result<(), PqfileError> {
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
        #[cfg(feature = "tlock")]
        PqfHeaderInfo::TimeLocked {
            chain_hash,
            round,
            nonce,
            original_size,
        } => {
            let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let chain_hex: String = chain_hash.iter().map(|b| format!("{b:02x}")).collect();
            if json {
                println!(
                    "{}",
                    json_object(&[
                        kv_str("status", "ok"),
                        kv_str("magic", "PQFL"),
                        kv_str("version", &format!("{raw_version:#04x}")),
                        kv_raw("header_authenticated", auth_json),
                        kv_str("mode", "tlock"),
                        kv_str("chain_hash", &chain_hex),
                        kv_raw("round", &round.to_string()),
                        kv_str("nonce", &nonce_hex),
                        kv_raw("original_size", &original_size.to_string()),
                    ])
                );
            } else {
                println!("Magic:              PQFL");
                println!("Version:            {raw_version:#04x} (time-locked)");
                println!("Auth. header:       {auth_str}");
                println!("Chain hash:         {chain_hex}");
                println!("Round:              {round}");
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

pub(crate) fn run_calibrate(target_ms: u64, json: bool) -> Result<(), PqfileError> {
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

pub(crate) fn run_doctor(
    file: PathBuf,
    pubkey: Option<PathBuf>,
    json: bool,
) -> Result<(), PqfileError> {
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
        #[cfg(feature = "tlock")]
        PqfHeaderInfo::TimeLocked {
            round,
            original_size,
            ..
        } => {
            let v = format!("{:#04x}", content.get(4).copied().unwrap_or(0));
            let k = format!("time-locked (round {round})");
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
