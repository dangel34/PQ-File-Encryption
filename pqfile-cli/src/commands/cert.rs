//! `issue-cert`, `verify-cert`, `revoke-cert`, and the certificate-resolution
//! helpers shared by every command that accepts a certificate in place of a
//! raw key (`encrypt -r`, `verify -k`, `signcrypt -r`, `signdecrypt -v`,
//! `seal -r`).

use std::path::{Path, PathBuf};

use pqfile::error::PqfileError;
use pqfile::{keygen, revoke};

use crate::io_util::ensure_overwrite_allowed;
use crate::json_util::{json_object, kv_str};
use crate::prompts::maybe_prompt_passphrase;

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

/// Reads the revocation list at `revocations`, if any, and checks `cert_pem`
/// against it. A `None` `revocations` is a no-op: revocation checking is
/// opt-in, mirroring how raw-key `.revoked` sidecar checking only happens
/// when the sidecar file exists.
pub(crate) fn check_cert_revocation(
    ca_vk_pem: &str,
    revocations: Option<&Path>,
    cert_pem: &str,
) -> Result<(), PqfileError> {
    let list_pem = revocations.map(std::fs::read_to_string).transpose()?;
    pqfile::cert::check_cert_not_revoked_pem(ca_vk_pem, list_pem.as_deref(), cert_pem)
}

/// Resolves `pem` (already read from `path`) to the key it actually
/// authorizes: if it's a certificate PEM produced by `issue-cert`, verifies
/// it against `ca_key` (required in that case), checks `required_use` and,
/// if `revocations` is supplied, that it has not been revoked, and returns
/// `Some(subject_pem)`. Otherwise returns `None`, leaving raw
/// (non-certificate) key handling - including any revocation check - to the
/// caller.
///
/// Reads and verifies `ca_key`/`revocations` fresh on every call, which is
/// the right tradeoff for the single-certificate call sites that use this
/// (`verify`, `signcrypt`, `signdecrypt`, `seal`) but wasteful for a loop
/// over many certificates against the same CA - see
/// [`resolve_cert_with_ca`], which `encrypt`'s multi-recipient loop uses
/// instead so the CA key and revocation list are each read and verified once
/// for the whole batch rather than once per recipient.
pub(crate) fn resolve_cert(
    pem: &str,
    path: &Path,
    ca_key: Option<&Path>,
    revocations: Option<&Path>,
    required_use: u8,
) -> Result<Option<String>, PqfileError> {
    if !pqfile::cert::is_certificate(pem) {
        return Ok(None);
    }
    let ca_vk_pem = ca_key.map(std::fs::read_to_string).transpose()?;
    let revocation_list = match (&ca_vk_pem, revocations) {
        (Some(ca_vk_pem), Some(p)) => {
            let list_pem = std::fs::read_to_string(p)?;
            Some(pqfile::cert::verify_revocation_list(ca_vk_pem, &list_pem)?)
        }
        _ => None,
    };
    resolve_cert_with_ca(
        pem,
        path,
        ca_vk_pem.as_deref(),
        revocation_list.as_ref(),
        required_use,
    )
}

/// Core of [`resolve_cert`], taking an already-loaded CA verifying key and an
/// already-verified revocation list rather than reading and verifying them
/// itself. Used directly by loops that resolve many certificates against the
/// same CA/revocation list in one command (currently just `encrypt`'s
/// multi-recipient loop) so each one isn't re-read and re-verified - the
/// revocation list's signature check in particular is real work, scaling
/// with both its entry count and the recipient count if repeated per
/// recipient.
pub(crate) fn resolve_cert_with_ca(
    pem: &str,
    path: &Path,
    ca_vk_pem: Option<&str>,
    revocations: Option<&pqfile::cert::RevocationList>,
    required_use: u8,
) -> Result<Option<String>, PqfileError> {
    if !pqfile::cert::is_certificate(pem) {
        return Ok(None);
    }
    let ca_vk_pem = ca_vk_pem.ok_or_else(|| {
        PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is a certificate; pass --ca-key <CA_VERIFYING_KEY> to verify it",
                path.display()
            ),
        ))
    })?;
    let cert = pqfile::cert::verify_cert(ca_vk_pem, pem, current_unix_secs())?;
    if !cert.permits(required_use) {
        return Err(PqfileError::CertUseNotPermitted {
            required: required_use,
            allowed: cert.allowed_use,
        });
    }
    if let Some(list) = revocations {
        pqfile::cert::check_cert_not_revoked(list, pem)?;
    }
    Ok(Some(cert.subject_pem))
}

/// Resolves `path`'s already-read `pem` to the key that should actually be
/// used for `required_use`: a certificate's verified, revocation-checked
/// subject key if `pem` is a certificate, otherwise `pem` itself after
/// checking the raw-key `.revoked` sidecar. Shared by every single-recipient
/// command that reads exactly one key/cert from `path` and resolves it via
/// [`resolve_cert`] (`encrypt`'s multi-recipient loop instead calls
/// [`resolve_cert_with_ca`] directly, since it resolves the CA key and
/// revocation list once for the whole batch rather than once per call).
pub(crate) fn resolve_single_recipient(
    pem: String,
    path: &Path,
    ca_key: Option<&Path>,
    revocations: Option<&Path>,
    required_use: u8,
) -> Result<String, PqfileError> {
    match resolve_cert(&pem, path, ca_key, revocations, required_use)? {
        Some(subject_pem) => Ok(subject_pem),
        None => {
            revoke::check_not_revoked(path, &pem)?;
            Ok(pem)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_issue_cert(
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

pub(crate) fn run_verify_cert(
    ca_key: PathBuf,
    revocations: Option<PathBuf>,
    cert: PathBuf,
    json: bool,
) -> Result<(), PqfileError> {
    let ca_vk_pem = std::fs::read_to_string(&ca_key)?;
    let cert_pem = std::fs::read_to_string(&cert)?;
    let now = current_unix_secs();
    let parsed = pqfile::cert::verify_cert(&ca_vk_pem, &cert_pem, now)?;
    check_cert_revocation(&ca_vk_pem, revocations.as_deref(), &cert_pem)?;
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_revoke_cert(
    ca_key: PathBuf,
    cert: PathBuf,
    existing: Option<PathBuf>,
    reason: &str,
    output: PathBuf,
    force: bool,
    json: bool,
) -> Result<(), PqfileError> {
    ensure_overwrite_allowed(&output, false, force)?;

    let ca_sk_pem = std::fs::read_to_string(&ca_key)?;
    let pp = maybe_prompt_passphrase(&ca_sk_pem, "Enter passphrase for CA signing key: ")?;
    let pp_str = pp.as_deref().map(|z| z.as_str());
    let cert_pem = std::fs::read_to_string(&cert)?;
    let existing_pem = existing.map(std::fs::read_to_string).transpose()?;

    let now = current_unix_secs();
    let list_pem = pqfile::cert::revoke_cert(
        &ca_sk_pem,
        pp_str,
        existing_pem.as_deref(),
        &cert_pem,
        reason,
        now,
    )?;
    std::fs::write(&output, &list_pem)?;

    let id_hex = pqfile::cert::cert_id_hex(&pqfile::cert::cert_id(&cert_pem)?);

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("output", &output.to_string_lossy()),
                kv_str("cert_id", &id_hex),
                kv_str("reason", reason),
            ])
        );
    } else {
        println!("Revocation list written to {}", output.display());
        println!("Revoked certificate id: {id_hex}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
