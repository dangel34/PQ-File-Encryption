use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum Tab {
    Keys,
    #[default]
    Keygen,
    Encrypt,
    Decrypt,
    Sign,
    Signcrypt,
    Archive,
    Shamir,
    Inspect,
    Clipboard,
    Settings,
}

/// The tabs shown in the primary nav row (the everyday encrypt/decrypt/key-management
/// path). Settings is rendered separately, pinned at the end of the row.
pub(crate) const PRIMARY_TABS: [Tab; 4] = [Tab::Keys, Tab::Keygen, Tab::Encrypt, Tab::Decrypt];

/// The specialized/PKI/multi-party tools tucked under the "More Tools" overflow menu.
pub(crate) const ADVANCED_TABS: [Tab; 6] = [
    Tab::Sign,
    Tab::Signcrypt,
    Tab::Archive,
    Tab::Shamir,
    Tab::Inspect,
    Tab::Clipboard,
];

/// Stable string key for a tab, used for both URL-hash deep-linking (WASM) and
/// persisting the last-visited tab across sessions (native).
pub(crate) fn tab_key(tab: Tab) -> &'static str {
    match tab {
        Tab::Keys => "keys",
        Tab::Keygen => "keygen",
        Tab::Encrypt => "encrypt",
        Tab::Decrypt => "decrypt",
        Tab::Sign => "sign",
        Tab::Signcrypt => "signcrypt",
        Tab::Archive => "archive",
        Tab::Shamir => "shamir",
        Tab::Inspect => "inspect",
        Tab::Clipboard => "clipboard",
        Tab::Settings => "settings",
    }
}

/// Display label (icon + text) for a tab, shared by the primary nav row and
/// the "More Tools" overflow menu.
pub(crate) fn tab_label(tab: Tab) -> &'static str {
    match tab {
        Tab::Keys => "🗝 Keys",
        Tab::Keygen => "🔑 Keygen",
        Tab::Encrypt => "🔒 Encrypt",
        Tab::Decrypt => "🔓 Decrypt",
        Tab::Sign => "✏ Sign",
        Tab::Signcrypt => "🔏 Sign & Encrypt",
        Tab::Archive => "📦 Archive",
        Tab::Shamir => "🔀 Split Key (Shamir)",
        Tab::Inspect => "🔍 Health Check",
        Tab::Clipboard => "📋 Clipboard",
        Tab::Settings => "⚙ Settings",
    }
}

/// Inverse of [`tab_key`], plus a couple of legacy/alias spellings.
pub(crate) fn tab_from_key(key: &str) -> Option<Tab> {
    match key {
        "keys" => Some(Tab::Keys),
        "keygen" | "generate" => Some(Tab::Keygen),
        "encrypt" => Some(Tab::Encrypt),
        "decrypt" => Some(Tab::Decrypt),
        "sign" => Some(Tab::Sign),
        "signcrypt" => Some(Tab::Signcrypt),
        "archive" => Some(Tab::Archive),
        "shamir" => Some(Tab::Shamir),
        "inspect" | "doctor" => Some(Tab::Inspect),
        "clipboard" | "tools" => Some(Tab::Clipboard),
        "settings" => Some(Tab::Settings),
        _ => None,
    }
}

#[derive(Clone, Default, Debug)]
pub(crate) enum OpStatus {
    #[default]
    None,
    Ok(String),
    Err(String),
}

pub(crate) struct PickedFile {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) error: Option<String>,
}

pub(crate) type Pending = Arc<Mutex<Option<PickedFile>>>;
pub(crate) type BatchPending = Arc<Mutex<Option<Vec<PickedFile>>>>;

/// A remembered key pair in the key management panel (native-only).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct KeyEntry {
    pub(crate) label: String,
    pub(crate) pubkey_path: PathBuf,
    pub(crate) privkey_path: Option<PathBuf>,
    pub(crate) fingerprint: String,
}

/// Shared state for a running batch-encrypt job. Polled from the UI thread each frame.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct EncryptJob {
    pub(crate) done: usize,
    pub(crate) total: usize,
    /// Completed file results: (original index in encrypt_files, status).
    pub(crate) results: Vec<(usize, OpStatus)>,
    pub(crate) finished: bool,
    /// Bytes processed in the currently-encrypting file (0 when idle).
    pub(crate) current_file_bytes_done: u64,
    /// Total bytes of the currently-encrypting file (0 when idle).
    pub(crate) current_file_bytes_total: u64,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type EncryptJobHandle = Arc<Mutex<EncryptJob>>;

/// Shared state for a running batch-decrypt job.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct DecryptBatchJob {
    pub(crate) done: usize,
    pub(crate) total: usize,
    /// Completed file results: (original index in decrypt_files, status).
    pub(crate) results: Vec<(usize, OpStatus)>,
    pub(crate) finished: bool,
    /// Bytes written for the currently-decrypting file (0 when idle).
    pub(crate) current_file_bytes_done: u64,
    /// Total bytes expected for the currently-decrypting file (0 when unknown/idle).
    pub(crate) current_file_bytes_total: u64,
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type DecryptBatchJobHandle = Arc<Mutex<DecryptBatchJob>>;

pub(crate) struct MultiFileEntry {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) path: Option<PathBuf>,
    pub(crate) status: OpStatus,
}

/// Which algorithm to use when generating a key pair.
#[derive(Clone, Copy, PartialEq, Default)]
pub(crate) enum KeygenAlgorithm {
    MlKem512,
    #[default]
    MlKem768,
    MlKem1024,
    HybridX25519MlKem768,
    MlDsa65,
    SlhDsa192f,
}

impl KeygenAlgorithm {
    pub(crate) fn level(self) -> u16 {
        match self {
            Self::MlKem512 => 512,
            Self::MlKem768 | Self::HybridX25519MlKem768 => 768,
            Self::MlKem1024 => 1024,
            Self::MlDsa65 | Self::SlhDsa192f => 0,
        }
    }
    pub(crate) fn hybrid(self) -> bool {
        self == Self::HybridX25519MlKem768
    }
    pub(crate) fn is_signing(self) -> bool {
        matches!(self, Self::MlDsa65 | Self::SlhDsa192f)
    }
    /// Signature algorithm for the signing variants; `None` for KEM variants.
    pub(crate) fn sig_algorithm(self) -> Option<pqfile::sign::SigAlgorithm> {
        match self {
            Self::MlDsa65 => Some(pqfile::sign::SigAlgorithm::MlDsa65),
            Self::SlhDsa192f => Some(pqfile::sign::SigAlgorithm::SlhDsaShake192f),
            _ => None,
        }
    }
}

/// A single encryption recipient (holds the loaded public key PEM).
pub(crate) struct RecipientEntry {
    pub(crate) name: String,
    pub(crate) pem: String,
    pub(crate) variant_name: String,
}

/// Extracts the `# Expires: YYYY-MM-DD` comment from a PEM string, if present.
/// Lines before the first `-----BEGIN` line are searched.
pub(crate) fn read_pem_expiry(pem_str: &str) -> Option<String> {
    for line in pem_str.lines() {
        if let Some(date) = line.strip_prefix("# Expires: ") {
            return Some(date.trim().to_owned());
        }
        if line.starts_with("-----BEGIN") {
            break;
        }
    }
    None
}

/// Returns days until expiry for a "YYYY-MM-DD" date string.
/// Positive = days remaining; 0 = expires today; negative = expired N days ago.
/// Returns `None` if `date_str` is empty, malformed, or system time is unavailable.
pub(crate) fn expiry_days_remaining(date_str: &str) -> Option<i64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_days = (SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() / 86400) as i64;
    let parts: Vec<i64> = date_str.split('-').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 3 {
        return None;
    }
    let (year, month, day) = (parts[0], parts[1], parts[2]);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let target_days = gregorian_days_since_epoch(year, month, day)?;
    Some(target_days - now_days)
}

/// Gregorian calendar date → days since Unix epoch (1970-01-01), using JDN arithmetic.
fn gregorian_days_since_epoch(year: i64, month: i64, day: i64) -> Option<i64> {
    let (y, m) = if month <= 2 {
        (year - 1, month + 12)
    } else {
        (year, month)
    };
    if y < -4716 {
        return None;
    }
    let a = y / 100;
    let b = 2 - a + a / 4;
    let jdn = ((365.25_f64 * (y + 4716) as f64) as i64)
        + ((30.6001_f64 * (m + 1) as f64) as i64)
        + day
        + b
        - 1524;
    Some(jdn - 2_440_588)
}

/// Days since Unix epoch (1970-01-01) → "YYYY-MM-DD" (reverse JDN), the
/// inverse of [`gregorian_days_since_epoch`].
pub(crate) fn days_since_epoch_to_ymd(days: i64) -> String {
    let jdn = days + 2_440_588;
    let a = jdn + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;
    let day = e - (153 * m + 2) / 5 + 1;
    let month = m + 3 - 12 * (m / 10);
    let year = 100 * b + d - 4800 + m / 10;
    format!("{year:04}-{month:02}-{day:02}")
}

/// Unix seconds → "YYYY-MM-DD" (UTC, truncated to the day).
pub(crate) fn unix_secs_to_ymd(secs: u64) -> String {
    days_since_epoch_to_ymd((secs / 86_400) as i64)
}

/// Current time as Unix seconds. Returns 0 if system time is unavailable
/// (e.g. before the epoch), which is not a realistic case in practice.
pub(crate) fn current_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns today's date for the expiry date picker widget.
pub(crate) fn today_date() -> jiff::civil::Date {
    let now_days = (current_unix_secs() / 86400) as i64;
    days_since_epoch_to_ymd(now_days)
        .parse()
        .expect("days_since_epoch_to_ymd always produces a valid YYYY-MM-DD string")
}

/// Parses a "YYYY-MM-DD" string for the expiry date picker widget, falling back to
/// today's date if the string is empty or malformed.
pub(crate) fn parse_expiry_date(date_str: &str) -> jiff::civil::Date {
    date_str.parse().unwrap_or_else(|_| today_date())
}

/// Detect the KEM variant display name from a public key PEM string.
pub(crate) fn pem_variant_name(pem_str: &str) -> String {
    if pem_str.contains("ML-KEM-1024") {
        "ML-KEM-1024".to_owned()
    } else if pem_str.contains("X25519+ML-KEM-768") {
        "Hybrid X25519+ML-KEM-768".to_owned()
    } else if pem_str.contains("ML-KEM-768") {
        "ML-KEM-768".to_owned()
    } else {
        "Unknown".to_owned()
    }
}

pub(crate) struct FileInput {
    pub(crate) name: String,
    pub(crate) data: Option<Vec<u8>>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) pending: Pending,
}

impl Default for FileInput {
    fn default() -> Self {
        Self {
            name: String::new(),
            data: None,
            path: None,
            pending: Arc::new(Mutex::new(None)),
        }
    }
}

impl FileInput {
    pub(crate) fn poll(&mut self) {
        if let Ok(mut g) = self.pending.try_lock() {
            if let Some(f) = g.take() {
                self.name = f.name;
                self.data = Some(f.data);
                self.path = f.path;
            }
        }
    }
    pub(crate) fn loaded(&self) -> bool {
        self.data.is_some()
    }
    pub(crate) fn as_str(&self) -> Option<&str> {
        self.data
            .as_deref()
            .and_then(|d| std::str::from_utf8(d).ok())
    }
    pub(crate) fn clear(&mut self) {
        self.name.clear();
        self.data = None;
        self.path = None;
    }
}

/// Which sub-section is active in the Decrypt tab.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum DecryptSubTab {
    #[default]
    Decrypt,
    Rekey,
    AddRecipient,
}

/// Which mode is active in the Encrypt tab: public-key recipients (v2/v3/v4/v8/v9),
/// or a v10 passphrase-only file with no key pair.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum EncryptMode {
    #[default]
    PublicKey,
    Passphrase,
}

/// Which mode is active in the Decrypt tab: a private key, or a v10
/// passphrase-only file.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum DecryptMode {
    #[default]
    PrivateKey,
    Passphrase,
}

/// Which second factor (if any) accompanies v10 passphrase mode, mirroring the
/// CLI's `--keyfile` / `--fido2` mutual exclusivity. The `Fido2` variant exists
/// on every target for code-sharing simplicity; only native builds with the
/// `fido2` feature ever expose UI to select it.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum SecondFactorMode {
    #[default]
    None,
    Keyfile,
    // Only ever constructed by UI code gated the same way; on a build without
    // the feature this variant is legitimately unreachable, not a mistake.
    #[cfg_attr(
        not(all(not(target_arch = "wasm32"), feature = "fido2")),
        allow(dead_code)
    )]
    Fido2,
}

/// Shared state for a background FIDO2 enrollment or secret-derivation
/// operation (native, `fido2` feature only). Both are single blocking CTAP2
/// round trips run on a spawned thread and polled from the UI thread, unlike
/// the multi-file `EncryptJob`/`DecryptBatchJob` above.
#[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
pub(crate) type Fido2Pending<T> = Arc<Mutex<Option<Result<T, String>>>>;

/// Which sub-section is active in the Sign tab.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum SignSubTab {
    #[default]
    Sign,
    Verify,
}

/// Which sub-section is active in the Keys tab's certificate panel.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum CertSubTab {
    #[default]
    Issue,
    Verify,
}

/// Which mode is active in the Signcrypt tab.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum SigncryptSubTab {
    #[default]
    Encrypt,
    Decrypt,
}

/// Which mode is active in the Archive tab.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum ArchiveSubTab {
    #[default]
    Create,
    Extract,
}

/// Which mode is active in the Shamir tab.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum ShamirSubTab {
    #[default]
    Split,
    Reconstruct,
}

pub(crate) struct Settings {
    pub(crate) dark_mode: bool,
    pub(crate) auto_clear: bool,
    pub(crate) confirm_overwrite: bool,
    /// Default KEM algorithm selected in the Keygen tab on startup.
    pub(crate) default_algorithm: KeygenAlgorithm,
    /// If non-zero, the Keygen tab pre-fills the expiry date this many days from today.
    pub(crate) default_expiry_days: u32,
    /// When true, clipboard plaintext is zeroized after `clipboard_clear_secs` seconds.
    pub(crate) clipboard_auto_clear: bool,
    pub(crate) clipboard_clear_secs: u32,
    /// Default output directory for keygen, encrypt, and decrypt (native only).
    /// Empty string means "same folder as the source file / chosen at keygen time".
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) output_dir: String,
    /// The tab the user was on when the app last closed, restored on the next
    /// launch so frequent users don't re-land on Keygen every time.
    pub(crate) last_tab: Tab,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dark_mode: true,
            auto_clear: false,
            confirm_overwrite: false,
            default_algorithm: KeygenAlgorithm::default(),
            default_expiry_days: 0,
            clipboard_auto_clear: false,
            clipboard_clear_secs: 60,
            #[cfg(not(target_arch = "wasm32"))]
            output_dir: String::new(),
            last_tab: Tab::Keygen,
        }
    }
}

impl Settings {
    pub(crate) fn load(storage: &dyn eframe::Storage) -> Self {
        let dark_mode = storage
            .get_string("dark_mode")
            .and_then(|s| s.parse().ok())
            .unwrap_or(true);
        let auto_clear = storage
            .get_string("auto_clear")
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);
        let confirm_overwrite = storage
            .get_string("confirm_overwrite")
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);
        let default_algorithm = match storage
            .get_string("default_algorithm")
            .as_deref()
            .unwrap_or("")
        {
            "512" => KeygenAlgorithm::MlKem512,
            "1024" => KeygenAlgorithm::MlKem1024,
            "hybrid768" => KeygenAlgorithm::HybridX25519MlKem768,
            "dsa65" => KeygenAlgorithm::MlDsa65,
            "slh192f" => KeygenAlgorithm::SlhDsa192f,
            _ => KeygenAlgorithm::MlKem768,
        };
        let default_expiry_days = storage
            .get_string("default_expiry_days")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0u32);
        let clipboard_auto_clear = storage
            .get_string("clipboard_auto_clear")
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);
        let clipboard_clear_secs = storage
            .get_string("clipboard_clear_secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(60u32);
        #[cfg(not(target_arch = "wasm32"))]
        let output_dir = storage.get_string("output_dir").unwrap_or_default();
        let last_tab = storage
            .get_string("last_tab")
            .and_then(|s| tab_from_key(&s))
            .unwrap_or(Tab::Keygen);
        Self {
            dark_mode,
            auto_clear,
            confirm_overwrite,
            default_algorithm,
            default_expiry_days,
            clipboard_auto_clear,
            clipboard_clear_secs,
            #[cfg(not(target_arch = "wasm32"))]
            output_dir,
            last_tab,
        }
    }

    pub(crate) fn save(&self, storage: &mut dyn eframe::Storage) {
        storage.set_string("dark_mode", self.dark_mode.to_string());
        storage.set_string("auto_clear", self.auto_clear.to_string());
        storage.set_string("confirm_overwrite", self.confirm_overwrite.to_string());
        let alg_str = match self.default_algorithm {
            KeygenAlgorithm::MlKem512 => "512",
            KeygenAlgorithm::MlKem768 => "768",
            KeygenAlgorithm::MlKem1024 => "1024",
            KeygenAlgorithm::HybridX25519MlKem768 => "hybrid768",
            KeygenAlgorithm::MlDsa65 => "dsa65",
            KeygenAlgorithm::SlhDsa192f => "slh192f",
        };
        storage.set_string("default_algorithm", alg_str.to_owned());
        storage.set_string("default_expiry_days", self.default_expiry_days.to_string());
        storage.set_string(
            "clipboard_auto_clear",
            self.clipboard_auto_clear.to_string(),
        );
        storage.set_string(
            "clipboard_clear_secs",
            self.clipboard_clear_secs.to_string(),
        );
        #[cfg(not(target_arch = "wasm32"))]
        storage.set_string("output_dir", self.output_dir.clone());
        storage.set_string("last_tab", tab_key(self.last_tab).to_owned());
    }
}
