//! Hand-rolled JSON output helpers for the CLI's `--json` mode.
//!
//! There is no `serde_json` dependency for output (only `update-check`'s
//! response *parsing* uses it) - every command builds its JSON by hand
//! through these helpers, which is enough for the flat, known-shape objects
//! every subcommand emits.

use pqfile::error::PqfileError;

pub(crate) fn json_escape(s: &str) -> String {
    // RFC 8259 §7: all characters in U+0000 to U+001F must be escaped.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Other ASCII control characters: emit \uXXXX escape.
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

pub(crate) fn kv_str(key: &str, val: &str) -> String {
    format!("{}:{}", json_str(key), json_str(val))
}

pub(crate) fn kv_raw(key: &str, raw: &str) -> String {
    format!("{}:{raw}", json_str(key))
}

pub(crate) fn json_object(pairs: &[String]) -> String {
    format!("{{{}}}", pairs.join(","))
}

/// Returns the stable numeric code for a `PqfileError`.
/// These codes are part of the public API; see `docs/ERROR_CODES.md`.
pub(crate) fn json_error_from(e: &PqfileError) -> String {
    json_object(&[
        kv_str("status", "error"),
        kv_raw("code", &e.code().to_string()),
        kv_str("message", &e.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fix #14: json_escape must handle all RFC 8259 control characters ──────

    #[test]
    fn json_escape_standard_escapes() {
        assert_eq!(json_escape("\""), "\\\"");
        assert_eq!(json_escape("\\"), "\\\\");
        assert_eq!(json_escape("\n"), "\\n");
        assert_eq!(json_escape("\r"), "\\r");
        assert_eq!(json_escape("\t"), "\\t");
    }

    #[test]
    fn json_escape_control_characters() {
        // NUL (0x00) and other low control characters must be \uXXXX-escaped.
        assert_eq!(json_escape("\x00"), "\\u0000");
        assert_eq!(json_escape("\x01"), "\\u0001");
        assert_eq!(json_escape("\x1f"), "\\u001f");
        // 0x20 (space) is NOT a control character and must pass through verbatim.
        assert_eq!(json_escape(" "), " ");
    }

    #[test]
    fn json_escape_mixed_string() {
        let s = "path\x00with\nnewline";
        let escaped = json_escape(s);
        // Must not contain raw NUL or raw newline.
        assert!(!escaped.contains('\x00'));
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("\\u0000"));
        assert!(escaped.contains("\\n"));
    }

    #[test]
    fn json_escape_printable_passthrough() {
        let s = "hello/world-OK_123";
        assert_eq!(json_escape(s), s);
    }
}
