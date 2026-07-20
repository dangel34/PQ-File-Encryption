//! `check-update`: queries the GitHub Releases API for the latest release tag
//! and compares it against this binary's own version. Gated behind the
//! `update-check` Cargo feature (off by default; see Cargo.toml).
//!
//! This is the only thing in the CLI that touches the network outside the
//! `tlock` feature, and it only runs when this subcommand is invoked
//! explicitly - nothing calls it automatically. It never downloads or
//! executes anything; it only reports a version comparison.
//!
//! The GitHub API fetch and version-compare logic live in `update_check_common`,
//! shared with pqfile-gui the same way `fido2_common` is.

use crate::json_util::{json_object, kv_str};
use crate::update_check_common::{fetch_latest_tag, is_newer};
use pqfile::PqfileError;
use std::io;

pub(crate) fn run_check_update(json: bool) -> Result<(), PqfileError> {
    let current = env!("CARGO_PKG_VERSION");
    let latest_tag = fetch_latest_tag("pqfile-cli-update-check")
        .map_err(|e| PqfileError::Io(io::Error::other(format!("update check: {e}"))))?;
    let latest = latest_tag.trim_start_matches('v');
    let available = is_newer(latest, current);

    if json {
        println!(
            "{}",
            json_object(&[
                kv_str("status", "ok"),
                kv_str("current_version", current),
                kv_str("latest_version", latest),
                kv_str("update_available", if available { "true" } else { "false" }),
            ])
        );
    } else if available {
        println!(
            "A newer version is available: v{latest} (you have v{current}).\n\
             https://github.com/dangel34/PQ-File-Encryption/releases/tag/v{latest}"
        );
    } else {
        println!("pqfile v{current} is up to date.");
    }
    Ok(())
}
