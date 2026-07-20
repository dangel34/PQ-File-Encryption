//! Shared GitHub-Releases-API fetch and version-compare logic for the
//! `update-check` feature of both pqfile-cli and pqfile-gui.
//!
//! This file is the single source of truth: pqfile-gui's `update_check.rs`
//! pulls it in via `#[path = "../../pqfile-cli/src/update_check_common.rs"]`
//! rather than keeping a hand-copied twin, the same convention `fido2_common.rs`
//! and `hex_lines.rs` already use for CLI/GUI-shared code (see
//! `fido2_common.rs`'s header comment for why it lives inside pqfile-cli's
//! source tree instead of a separate workspace crate).

use std::time::Duration;

const RELEASES_API_URL: &str =
    "https://api.github.com/repos/dangel34/PQ-File-Encryption/releases/latest";

/// Fetches the latest release's tag name (e.g. `"v4.4.0"`) from the GitHub
/// Releases API. `user_agent` identifies the caller (GitHub requires a
/// `User-Agent` header on all API requests).
pub(crate) fn fetch_latest_tag(user_agent: &str) -> Result<String, String> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    let agent: ureq::Agent = config.into();

    let body: String = agent
        .get(RELEASES_API_URL)
        .header("User-Agent", user_agent)
        .call()
        .map_err(|e| format!("request failed: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading response failed: {e}"))?;

    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("response was not valid JSON: {e}"))?;
    value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "response was missing tag_name".to_owned())
}

/// Numeric `major.minor.patch` comparison. pqfile's release tags are always
/// plain `vX.Y.Z` with no pre-release suffix, so this deliberately doesn't
/// pull in a full semver parser for one three-number comparison.
pub(crate) fn is_newer(latest: &str, current: &str) -> bool {
    parse_version(latest) > parse_version(current)
}

fn parse_version(v: &str) -> (u64, u64, u64) {
    let mut parts = v
        .trim_start_matches('v')
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0));
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare() {
        assert!(is_newer("4.4.0", "4.3.1"));
        assert!(is_newer("4.3.2", "4.3.1"));
        assert!(is_newer("5.0.0", "4.3.1"));
        assert!(!is_newer("4.3.1", "4.3.1"));
        assert!(!is_newer("4.3.0", "4.3.1"));
        assert!(!is_newer("4.2.9", "4.3.1"));
    }

    #[test]
    fn version_compare_handles_v_prefix() {
        assert!(is_newer("v4.4.0", "4.3.1"));
        assert!(is_newer("4.4.0", "v4.3.1"));
    }

    #[test]
    fn malformed_version_defaults_to_zero_rather_than_panicking() {
        assert_eq!(parse_version("not-a-version"), (0, 0, 0));
        assert_eq!(parse_version("4.x.1"), (4, 0, 1));
    }
}
