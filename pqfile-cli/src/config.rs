//! User config file (`~/.config/pqfile/config.toml` / `%APPDATA%\pqfile\config.toml`)
//! supplying default `-r`/`-k` values for `encrypt`/`decrypt`/`check`.

use std::path::PathBuf;

use pqfile::error::PqfileError;

/// Optional user defaults loaded from the config file. Explicit flags always win;
/// the config is only consulted when the corresponding flag is absent, and never
/// when `--no-config` is passed.
#[derive(Default)]
pub(crate) struct CliConfig {
    /// Default recipient for `encrypt`: a `pqf1…` string or a pubkey.pem path.
    pub(crate) recipient: Option<String>,
    /// Default private key path for `decrypt` / `check`.
    pub(crate) key: Option<PathBuf>,
}

/// Platform config file location: `%APPDATA%\pqfile\config.toml` on Windows,
/// `$XDG_CONFIG_HOME/pqfile/config.toml` (falling back to `~/.config/...`) elsewhere.
fn config_path() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("pqfile").join("config.toml"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|base| base.join("pqfile").join("config.toml"))
    }
}

/// Loads the config file, treating a missing file as empty defaults but a
/// malformed file as a hard error — silently ignoring a typo would make the
/// command behave differently than the user configured.
pub(crate) fn load_config(no_config: bool) -> Result<CliConfig, PqfileError> {
    if no_config {
        return Ok(CliConfig::default());
    }
    let Some(path) = config_path() else {
        return Ok(CliConfig::default());
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CliConfig::default()),
        Err(e) => return Err(PqfileError::Io(e)),
    };
    parse_config_toml(&text).map_err(|msg| {
        PqfileError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{}: {msg}", path.display()),
        ))
    })
}

/// Parses the strict TOML subset the config file uses: `key = "value"` pairs,
/// blank lines, and `#` comments. Only basic strings with `\\` and `\"` escapes
/// are accepted; unknown keys are ignored for forward compatibility.
fn parse_config_toml(text: &str) -> Result<CliConfig, String> {
    let mut cfg = CliConfig::default();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {}: expected `key = \"value\"`", idx + 1));
        };
        let val =
            parse_toml_basic_string(v.trim()).map_err(|e| format!("line {}: {e}", idx + 1))?;
        match k.trim() {
            "recipient" => cfg.recipient = Some(val),
            "key" => cfg.key = Some(PathBuf::from(val)),
            _ => {}
        }
    }
    Ok(cfg)
}

fn parse_toml_basic_string(v: &str) -> Result<String, String> {
    let rest = v
        .strip_prefix('"')
        .ok_or("value must be a double-quoted string")?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let tail = chars.as_str().trim_start();
                if tail.is_empty() || tail.starts_with('#') {
                    return Ok(out);
                }
                return Err("unexpected content after closing quote".to_owned());
            }
            '\\' => match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => return Err(format!("unsupported escape `\\{other}`")),
                None => return Err("dangling escape at end of string".to_owned()),
            },
            other => out.push(other),
        }
    }
    Err("unterminated string".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn config_toml_parses_recipient_and_key() {
        let cfg = parse_config_toml(
            "# defaults\n\
             recipient = \"pqf1abcdef\"  # trailing comment\n\
             \n\
             key = \"C:\\\\keys\\\\privkey.pem\"\n\
             future_knob = \"ignored\"\n",
        )
        .unwrap();
        assert_eq!(cfg.recipient.as_deref(), Some("pqf1abcdef"));
        assert_eq!(cfg.key.as_deref(), Some(Path::new("C:\\keys\\privkey.pem")));
    }

    #[test]
    fn config_toml_rejects_malformed_lines() {
        assert!(parse_config_toml("recipient = unquoted").is_err());
        assert!(parse_config_toml("just some words").is_err());
        assert!(parse_config_toml("key = \"unterminated").is_err());
        assert!(parse_config_toml("key = \"bad escape \\n\"").is_err());
        assert!(parse_config_toml("key = \"trailing\" junk").is_err());
    }
}
