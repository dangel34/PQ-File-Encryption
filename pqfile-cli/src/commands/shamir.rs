//! `split-key` and `reconstruct-key`: M-of-N Shamir secret sharing of a
//! private key's seed.

use std::path::PathBuf;

use pqfile::error::PqfileError;
use pqfile::{keygen, shamir};

use crate::io_util::write_private_file;
use crate::json_util::{json_object, json_str, kv_raw, kv_str};
use crate::prompts::maybe_prompt_passphrase;

pub(crate) fn run_split_key(
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

pub(crate) fn run_reconstruct_key(
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
