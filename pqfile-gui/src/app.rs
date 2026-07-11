use crate::colors::{
    c_accent, c_bg, c_card, c_chrome, c_overlay, c_subtext, c_surface0, c_surface1, c_text,
};
use crate::theme::apply_theme;
use crate::types::{
    pem_variant_name, ArchiveSubTab, BatchPending, DecryptMode, DecryptSubTab, EncryptMode,
    FileInput, KeygenAlgorithm, MultiFileEntry, OpStatus, PickedFile, RecipientEntry,
    SecondFactorMode, Settings, ShamirSubTab, SignSubTab, SigncryptSubTab, Tab,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::types::{DecryptBatchJobHandle, EncryptJobHandle, KeyEntry};
use crate::widgets::{bullet, card, kv_row, section_label, tab_btn};
use crate::APP_VERSION;
use eframe::egui::{self, Color32, CornerRadius, Margin, RichText, Stroke, Vec2};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Handle to a running watchfolder thread.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct WatchHandle {
    /// New encrypted-file paths written by the watcher (populated by the bg thread).
    pub(crate) log_rx: std::sync::mpsc::Receiver<String>,
    /// Set to `true` by the UI thread to request the watcher stop.
    pub(crate) stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// State for the QR code modal window.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct QrModal {
    pub(crate) title: String,
    pub(crate) texture: egui::TextureHandle,
    pub(crate) data: String,
}

pub struct PqfileApp {
    pub(crate) tab: Tab,
    pub(crate) show_about: bool,
    pub(crate) show_legal: bool,
    pub(crate) help_modal_open: Option<Tab>,
    pub(crate) settings: Settings,
    pub(crate) app_icon: Option<egui::TextureHandle>,

    pub(crate) keygen_passphrase: Zeroizing<String>,
    pub(crate) keygen_passphrase_confirm: Zeroizing<String>,
    pub(crate) keygen_use_passphrase: bool,
    pub(crate) keygen_algorithm: KeygenAlgorithm,
    pub(crate) keygen_status: OpStatus,

    /// Staging slot: files/drops land here, then poll_files promotes to encrypt_recipients.
    pub(crate) encrypt_pubkey: FileInput,
    pub(crate) encrypt_recipients: Vec<RecipientEntry>,
    pub(crate) encrypt_files: Vec<MultiFileEntry>,
    pub(crate) encrypt_batch_pending: BatchPending,
    /// Public-key recipients, or a v10 passphrase-only file with no key pair.
    pub(crate) encrypt_mode: EncryptMode,
    pub(crate) encrypt_passphrase: Zeroizing<String>,
    pub(crate) encrypt_passphrase_confirm: Zeroizing<String>,
    pub(crate) encrypt_passphrase_visible: bool,
    /// Which v10 second factor (if any) accompanies the passphrase.
    pub(crate) encrypt_second_factor: SecondFactorMode,
    pub(crate) encrypt_keyfile: FileInput,
    pub(crate) encrypt_fido2_enrollment: FileInput,
    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
    pub(crate) encrypt_fido2_pin: Zeroizing<String>,
    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
    pub(crate) fido2_enroll_pin: Zeroizing<String>,
    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
    pub(crate) fido2_enroll_use_pin: bool,
    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
    pub(crate) fido2_enroll_status: OpStatus,
    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
    pub(crate) fido2_enroll_pending: Option<crate::types::Fido2Pending<()>>,
    /// Pad recipient count to the next power of two with random dummy slots (v9 format).
    pub(crate) encrypt_pad_recipients: bool,
    /// Pad plaintext length to a Padmé bucket before encrypting (hides exact file size).
    pub(crate) encrypt_pad: bool,
    /// Omit the .pqf magic, version byte, and KEM variant field entirely (single recipient only).
    pub(crate) encrypt_stealth: bool,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) encrypt_compress: bool,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) encrypt_compress_level: i32,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) encrypt_job: Option<EncryptJobHandle>,

    // WASM frame-by-frame encrypt queue (replaces the background thread).
    #[cfg(target_arch = "wasm32")]
    pub(crate) encrypt_wasm_queue: Vec<(usize, String, Vec<u8>)>,
    #[cfg(target_arch = "wasm32")]
    pub(crate) encrypt_wasm_target: Option<crate::tabs::encrypt::ResolvedEncryptTarget>,
    #[cfg(target_arch = "wasm32")]
    pub(crate) encrypt_wasm_done: usize,
    #[cfg(target_arch = "wasm32")]
    pub(crate) encrypt_wasm_total: usize,
    #[cfg(target_arch = "wasm32")]
    loader_hidden: bool,

    pub(crate) decrypt_privkey: FileInput,
    pub(crate) decrypt_files: Vec<MultiFileEntry>,
    pub(crate) decrypt_batch_pending: BatchPending,
    /// Passphrase unlocking `decrypt_privkey` itself, when that key is passphrase-encrypted.
    /// Unrelated to `decrypt_v10_passphrase` below (v10 has no key pair at all).
    pub(crate) decrypt_passphrase: Zeroizing<String>,
    /// A private key, or a v10 passphrase-only file with no key pair.
    pub(crate) decrypt_mode: DecryptMode,
    pub(crate) decrypt_v10_passphrase: Zeroizing<String>,
    pub(crate) decrypt_second_factor: SecondFactorMode,
    pub(crate) decrypt_keyfile: FileInput,
    pub(crate) decrypt_fido2_enrollment: FileInput,
    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
    pub(crate) decrypt_fido2_pin: Zeroizing<String>,
    /// File(s) were written with Encrypt tab's Stealth mode (no magic bytes to auto-detect).
    pub(crate) decrypt_stealth: bool,
    pub(crate) decrypt_status: OpStatus,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) decrypt_batch_job: Option<DecryptBatchJobHandle>,

    // ── Inspect tab (key/file health check) ──────────────────────────────
    pub(crate) doctor_file: FileInput,
    pub(crate) doctor_passphrase: Zeroizing<String>,
    pub(crate) doctor_result: Vec<crate::tabs::doctor::DoctorRow>,
    pub(crate) doctor_status: OpStatus,

    // ── Sign tab ──────────────────────────────────────────────────────────
    pub(crate) sign_sk: FileInput,
    pub(crate) sign_sk_passphrase: Zeroizing<String>,
    pub(crate) sign_sk_passphrase_visible: bool,
    pub(crate) sign_input_file: FileInput,
    pub(crate) sign_status: OpStatus,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) sign_sig_output_path: Option<String>,
    pub(crate) sign_vk: FileInput,
    pub(crate) sign_verify_file: FileInput,
    pub(crate) sign_sig_file: FileInput,
    pub(crate) sign_verify_status: OpStatus,

    // ── Signcrypt tab ─────────────────────────────────────────────────────
    pub(crate) signcrypt_sk: FileInput,
    pub(crate) signcrypt_sk_passphrase: Zeroizing<String>,
    pub(crate) signcrypt_sk_passphrase_visible: bool,
    pub(crate) signcrypt_pubkey: FileInput,
    pub(crate) signcrypt_input: FileInput,
    pub(crate) signcrypt_status: OpStatus,
    pub(crate) signdecrypt_privkey: FileInput,
    pub(crate) signdecrypt_privkey_passphrase: Zeroizing<String>,
    pub(crate) signdecrypt_privkey_passphrase_visible: bool,
    pub(crate) signdecrypt_vk: FileInput,
    pub(crate) signdecrypt_input: FileInput,
    pub(crate) signdecrypt_status: OpStatus,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) signdecrypt_output_path: Option<String>,

    // ── Archive tab ───────────────────────────────────────────────────────
    pub(crate) archive_pubkey: FileInput,
    pub(crate) archive_files: Vec<MultiFileEntry>,
    pub(crate) archive_batch_pending: BatchPending,
    pub(crate) archive_status: OpStatus,
    pub(crate) extract_privkey: FileInput,
    pub(crate) extract_privkey_passphrase: Zeroizing<String>,
    pub(crate) extract_privkey_passphrase_visible: bool,
    pub(crate) extract_input: FileInput,
    pub(crate) extract_list_only: bool,
    pub(crate) extract_status: OpStatus,
    pub(crate) extract_result: String,

    // ── Shamir tab ────────────────────────────────────────────────────────
    pub(crate) shamir_split_privkey: FileInput,
    pub(crate) shamir_split_passphrase: Zeroizing<String>,
    pub(crate) shamir_split_passphrase_visible: bool,
    pub(crate) shamir_split_threshold: u8,
    pub(crate) shamir_split_shares: u8,
    pub(crate) shamir_split_status: OpStatus,
    pub(crate) shamir_shares: Vec<MultiFileEntry>,
    pub(crate) shamir_shares_pending: BatchPending,
    pub(crate) shamir_reconstruct_status: OpStatus,

    // ── Keygen hardware key fields ────────────────────────────────────────
    pub(crate) keygen_use_hardware: bool,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) keygen_hardware_label: String,

    // ── Tools tab (Revoke + Rekey + Repassphrase) ─────────────────────────
    pub(crate) repassphrase_key: FileInput,
    pub(crate) repassphrase_old_passphrase: Zeroizing<String>,
    pub(crate) repassphrase_old_passphrase_visible: bool,
    pub(crate) repassphrase_new_passphrase: Zeroizing<String>,
    pub(crate) repassphrase_new_passphrase_confirm: Zeroizing<String>,
    pub(crate) repassphrase_new_passphrase_visible: bool,
    pub(crate) repassphrase_from_legacy: bool,
    pub(crate) repassphrase_status: OpStatus,

    pub(crate) revoke_pubkey: FileInput,
    pub(crate) revoke_reason: String,
    pub(crate) revoke_status: OpStatus,
    pub(crate) rekey_privkey: FileInput,
    pub(crate) rekey_privkey_passphrase: Zeroizing<String>,
    pub(crate) rekey_privkey_passphrase_visible: bool,
    pub(crate) rekey_new_pubkey: FileInput,
    pub(crate) rekey_input: FileInput,
    pub(crate) rekey_status: OpStatus,

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) keys: Vec<KeyEntry>,

    /// WASM-only: public keys persisted via localStorage. Each entry is (label, pem).
    #[cfg(target_arch = "wasm32")]
    pub(crate) wasm_saved_pubkeys: Vec<(String, String)>,

    // ── Sub-tab selection ─────────────────────────────────────────────────
    pub(crate) decrypt_sub_tab: DecryptSubTab,
    pub(crate) sign_sub_tab: SignSubTab,
    pub(crate) signcrypt_sub_tab: SigncryptSubTab,
    pub(crate) archive_sub_tab: ArchiveSubTab,
    pub(crate) shamir_sub_tab: ShamirSubTab,

    // ── Batch operation summaries ─────────────────────────────────────────
    pub(crate) encrypt_batch_summary: Option<OpStatus>,
    pub(crate) decrypt_batch_summary: Option<OpStatus>,

    // ── Key expiry fields (keygen tab) ────────────────────────────────────
    pub(crate) keygen_use_expiry: bool,
    pub(crate) keygen_expiry_date: String,

    // ── Recent file paths per operation (native only, last 5) ─────────────
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) recent_encrypt_files: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) recent_decrypt_files: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) recent_privkeys: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) recent_pubkeys: Vec<String>,

    // ── Watchfolder state (native only) ──────────────────────────────────
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) watch_dir: String,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) watch_active: bool,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) watch_handle: Option<WatchHandle>,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) watch_log: Vec<String>,

    // ── QR code modal ────────────────────────────────────────────────────
    /// When Some, a QR window is open showing the encoded PEM data.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) qr_modal: Option<QrModal>,

    // ── Clipboard encrypt / decrypt (Tools tab) ───────────────────────────
    pub(crate) clipboard_plain: Zeroizing<String>,
    pub(crate) clipboard_cipher: String,
    pub(crate) clipboard_pubkey: FileInput,
    pub(crate) clipboard_privkey: FileInput,
    pub(crate) clipboard_passphrase: Zeroizing<String>,
    pub(crate) clipboard_passphrase_visible: bool,
    pub(crate) clipboard_enc_status: OpStatus,
    pub(crate) clipboard_dec_status: OpStatus,
    /// Timestamp of the last clipboard encrypt/decrypt operation; used for auto-clear timer.
    pub(crate) clipboard_last_used: Option<std::time::Instant>,
}

impl Default for PqfileApp {
    fn default() -> Self {
        Self {
            tab: Tab::Keygen,
            show_about: false,
            show_legal: false,
            help_modal_open: None,
            settings: Settings::default(),
            app_icon: None,
            keygen_passphrase: Zeroizing::new(String::new()),
            keygen_passphrase_confirm: Zeroizing::new(String::new()),
            keygen_use_passphrase: false,
            keygen_algorithm: KeygenAlgorithm::default(),
            keygen_status: OpStatus::None,
            encrypt_pubkey: FileInput::default(),
            encrypt_recipients: Vec::new(),
            encrypt_files: Vec::new(),
            encrypt_batch_pending: Arc::new(Mutex::new(None)),
            encrypt_mode: EncryptMode::default(),
            encrypt_passphrase: Zeroizing::new(String::new()),
            encrypt_passphrase_confirm: Zeroizing::new(String::new()),
            encrypt_passphrase_visible: false,
            encrypt_second_factor: SecondFactorMode::default(),
            encrypt_keyfile: FileInput::default(),
            encrypt_fido2_enrollment: FileInput::default(),
            #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
            encrypt_fido2_pin: Zeroizing::new(String::new()),
            #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
            fido2_enroll_pin: Zeroizing::new(String::new()),
            #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
            fido2_enroll_use_pin: false,
            #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
            fido2_enroll_status: OpStatus::None,
            #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
            fido2_enroll_pending: None,
            encrypt_pad_recipients: false,
            encrypt_pad: false,
            encrypt_stealth: false,
            #[cfg(not(target_arch = "wasm32"))]
            encrypt_compress: false,
            #[cfg(not(target_arch = "wasm32"))]
            encrypt_compress_level: 3,
            #[cfg(not(target_arch = "wasm32"))]
            encrypt_job: None,
            decrypt_privkey: FileInput::default(),
            decrypt_files: Vec::new(),
            decrypt_batch_pending: Arc::new(Mutex::new(None)),
            decrypt_passphrase: Zeroizing::new(String::new()),
            decrypt_mode: DecryptMode::default(),
            decrypt_v10_passphrase: Zeroizing::new(String::new()),
            decrypt_second_factor: SecondFactorMode::default(),
            decrypt_keyfile: FileInput::default(),
            decrypt_fido2_enrollment: FileInput::default(),
            #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
            decrypt_fido2_pin: Zeroizing::new(String::new()),
            decrypt_stealth: false,
            decrypt_status: OpStatus::None,
            #[cfg(not(target_arch = "wasm32"))]
            decrypt_batch_job: None,
            doctor_file: FileInput::default(),
            doctor_passphrase: Zeroizing::new(String::new()),
            doctor_result: Vec::new(),
            doctor_status: OpStatus::None,
            sign_sk: FileInput::default(),
            sign_sk_passphrase: Zeroizing::new(String::new()),
            sign_sk_passphrase_visible: false,
            sign_input_file: FileInput::default(),
            sign_status: OpStatus::None,
            sign_sig_output_path: None,
            sign_vk: FileInput::default(),
            sign_verify_file: FileInput::default(),
            sign_sig_file: FileInput::default(),
            sign_verify_status: OpStatus::None,
            signcrypt_sk: FileInput::default(),
            signcrypt_sk_passphrase: Zeroizing::new(String::new()),
            signcrypt_sk_passphrase_visible: false,
            signcrypt_pubkey: FileInput::default(),
            signcrypt_input: FileInput::default(),
            signcrypt_status: OpStatus::None,
            signdecrypt_privkey: FileInput::default(),
            signdecrypt_privkey_passphrase: Zeroizing::new(String::new()),
            signdecrypt_privkey_passphrase_visible: false,
            signdecrypt_vk: FileInput::default(),
            signdecrypt_input: FileInput::default(),
            signdecrypt_status: OpStatus::None,
            signdecrypt_output_path: None,
            archive_pubkey: FileInput::default(),
            archive_files: Vec::new(),
            archive_batch_pending: Arc::new(Mutex::new(None)),
            archive_status: OpStatus::None,
            extract_privkey: FileInput::default(),
            extract_privkey_passphrase: Zeroizing::new(String::new()),
            extract_privkey_passphrase_visible: false,
            extract_input: FileInput::default(),
            extract_list_only: false,
            extract_status: OpStatus::None,
            extract_result: String::new(),
            shamir_split_privkey: FileInput::default(),
            shamir_split_passphrase: Zeroizing::new(String::new()),
            shamir_split_passphrase_visible: false,
            shamir_split_threshold: 2,
            shamir_split_shares: 3,
            shamir_split_status: OpStatus::None,
            shamir_shares: Vec::new(),
            shamir_shares_pending: Arc::new(Mutex::new(None)),
            shamir_reconstruct_status: OpStatus::None,
            keygen_use_hardware: false,
            #[cfg(not(target_arch = "wasm32"))]
            keygen_hardware_label: String::new(),
            repassphrase_key: FileInput::default(),
            repassphrase_old_passphrase: Zeroizing::new(String::new()),
            repassphrase_old_passphrase_visible: false,
            repassphrase_new_passphrase: Zeroizing::new(String::new()),
            repassphrase_new_passphrase_confirm: Zeroizing::new(String::new()),
            repassphrase_new_passphrase_visible: false,
            repassphrase_from_legacy: bool::default(),
            repassphrase_status: OpStatus::None,
            revoke_pubkey: FileInput::default(),
            revoke_reason: String::new(),
            revoke_status: OpStatus::None,
            rekey_privkey: FileInput::default(),
            rekey_privkey_passphrase: Zeroizing::new(String::new()),
            rekey_privkey_passphrase_visible: false,
            rekey_new_pubkey: FileInput::default(),
            rekey_input: FileInput::default(),
            rekey_status: OpStatus::None,
            #[cfg(not(target_arch = "wasm32"))]
            keys: Vec::new(),
            decrypt_sub_tab: DecryptSubTab::default(),
            sign_sub_tab: SignSubTab::default(),
            signcrypt_sub_tab: SigncryptSubTab::default(),
            archive_sub_tab: ArchiveSubTab::default(),
            shamir_sub_tab: ShamirSubTab::default(),
            encrypt_batch_summary: None,
            decrypt_batch_summary: None,
            keygen_use_expiry: false,
            keygen_expiry_date: String::new(),
            #[cfg(not(target_arch = "wasm32"))]
            watch_dir: String::new(),
            #[cfg(not(target_arch = "wasm32"))]
            watch_active: false,
            #[cfg(not(target_arch = "wasm32"))]
            watch_handle: None,
            #[cfg(not(target_arch = "wasm32"))]
            watch_log: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            recent_encrypt_files: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            recent_decrypt_files: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            recent_privkeys: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            recent_pubkeys: Vec::new(),
            clipboard_plain: Zeroizing::new(String::new()),
            clipboard_cipher: String::new(),
            clipboard_pubkey: FileInput::default(),
            clipboard_privkey: FileInput::default(),
            clipboard_passphrase: Zeroizing::new(String::new()),
            clipboard_passphrase_visible: false,
            clipboard_enc_status: OpStatus::None,
            clipboard_dec_status: OpStatus::None,
            clipboard_last_used: None,
            #[cfg(not(target_arch = "wasm32"))]
            qr_modal: None,
            #[cfg(target_arch = "wasm32")]
            encrypt_wasm_queue: Vec::new(),
            #[cfg(target_arch = "wasm32")]
            encrypt_wasm_target: None,
            #[cfg(target_arch = "wasm32")]
            encrypt_wasm_done: 0,
            #[cfg(target_arch = "wasm32")]
            encrypt_wasm_total: 0,
            #[cfg(target_arch = "wasm32")]
            loader_hidden: false,
            #[cfg(target_arch = "wasm32")]
            wasm_saved_pubkeys: Vec::new(),
        }
    }
}

impl PqfileApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings = cc.storage.map(Settings::load).unwrap_or_default();
        apply_theme(&cc.egui_ctx, settings.dark_mode);
        #[cfg(not(target_arch = "wasm32"))]
        let keys = cc.storage.map(load_keys).unwrap_or_default();
        #[cfg(target_arch = "wasm32")]
        let wasm_saved_pubkeys = cc.storage.map(load_wasm_pubkeys).unwrap_or_default();
        // Read URL hash on startup to select the initial tab (e.g. "/#encrypt").
        #[cfg(target_arch = "wasm32")]
        let initial_tab_from_hash: Option<Tab> = web_sys::window()
            .and_then(|w| w.location().hash().ok())
            .and_then(|h| tab_from_hash(&h));
        #[cfg(not(target_arch = "wasm32"))]
        let (recent_encrypt_files, recent_decrypt_files, recent_privkeys, recent_pubkeys) = {
            let s = cc.storage;
            (
                s.map(|s| load_recent(s, "recent_enc")).unwrap_or_default(),
                s.map(|s| load_recent(s, "recent_dec")).unwrap_or_default(),
                s.map(|s| load_recent(s, "recent_priv")).unwrap_or_default(),
                s.map(|s| load_recent(s, "recent_pub")).unwrap_or_default(),
            )
        };
        let app_icon = image::load_from_memory(include_bytes!("../icon.png"))
            .ok()
            .map(|img| {
                let img = img.into_rgba8();
                let (w, h) = img.dimensions();
                cc.egui_ctx.load_texture(
                    "app-icon",
                    egui::ColorImage::from_rgba_unmultiplied(
                        [w as usize, h as usize],
                        img.as_raw(),
                    ),
                    egui::TextureOptions::LINEAR,
                )
            });
        let default_algorithm = settings.default_algorithm;
        #[cfg(target_arch = "wasm32")]
        let initial_tab = initial_tab_from_hash.unwrap_or(Tab::Keygen);
        #[cfg(not(target_arch = "wasm32"))]
        let initial_tab = Tab::Keygen;
        Self {
            tab: initial_tab,
            settings,
            app_icon,
            keygen_algorithm: default_algorithm,
            #[cfg(not(target_arch = "wasm32"))]
            keys,
            #[cfg(target_arch = "wasm32")]
            wasm_saved_pubkeys,
            #[cfg(not(target_arch = "wasm32"))]
            recent_encrypt_files,
            #[cfg(not(target_arch = "wasm32"))]
            recent_decrypt_files,
            #[cfg(not(target_arch = "wasm32"))]
            recent_privkeys,
            #[cfg(not(target_arch = "wasm32"))]
            recent_pubkeys,
            ..Default::default()
        }
    }
}

// ── Frame ──────────────────────────────────────────────────────────────────

impl eframe::App for PqfileApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.settings.save(storage);
        #[cfg(not(target_arch = "wasm32"))]
        save_keys(&self.keys, storage);
        #[cfg(target_arch = "wasm32")]
        save_wasm_pubkeys(&self.wasm_saved_pubkeys, storage);
        #[cfg(not(target_arch = "wasm32"))]
        {
            save_recent(storage, "recent_enc", &self.recent_encrypt_files);
            save_recent(storage, "recent_dec", &self.recent_decrypt_files);
            save_recent(storage, "recent_priv", &self.recent_privkeys);
            save_recent(storage, "recent_pub", &self.recent_pubkeys);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        #[cfg(target_arch = "wasm32")]
        if !self.loader_hidden {
            crate::hide_loader();
            self.loader_hidden = true;
        }
        if self.poll_files() {
            ctx.request_repaint();
        }
        #[cfg(target_arch = "wasm32")]
        self.tick_encrypt_wasm(&ctx);
        self.handle_dropped_files(&ctx);

        // Clipboard auto-clear timer.
        if self.settings.clipboard_auto_clear {
            if let Some(t) = self.clipboard_last_used {
                let elapsed = t.elapsed().as_secs();
                let timeout = self.settings.clipboard_clear_secs as u64;
                if elapsed >= timeout {
                    *self.clipboard_plain = String::new();
                    self.clipboard_cipher.clear();
                    self.clipboard_last_used = None;
                    ctx.request_repaint();
                } else {
                    ctx.request_repaint_after(std::time::Duration::from_secs(timeout - elapsed));
                }
            }
        }

        // Drag-over overlay: paint above everything else when files are hovering
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        if hovering {
            let dark = self.settings.dark_mode;
            let accent = c_accent(dark);
            let painter = ctx.layer_painter(egui::LayerId::new(
                egui::Order::Foreground,
                egui::Id::new("drop_overlay"),
            ));
            let screen = ctx.viewport_rect();
            painter.rect_filled(screen, 0.0, Color32::from_black_alpha(140));
            painter.rect_stroke(
                screen.shrink(12.0),
                egui::CornerRadius::same(12),
                egui::Stroke::new(2.0, accent),
                egui::StrokeKind::Inside,
            );
            painter.text(
                screen.center(),
                egui::Align2::CENTER_CENTER,
                "Drop file here",
                egui::FontId::proportional(26.0),
                accent,
            );
        }

        let dark = self.settings.dark_mode;
        let chrome = c_chrome(dark);
        let bg = c_bg(dark);

        // ── Title bar ──────────────────────────────────────────────────────
        egui::Panel::top("top_bar")
            .exact_size(46.0)
            .frame(
                egui::Frame::NONE
                    .fill(chrome)
                    .inner_margin(Margin::symmetric(14, 0)),
            )
            .show(ui, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    if let Some(ref tex) = self.app_icon {
                        let pad = 4.0_f32;
                        let img_sz = 22.0_f32;
                        let side = img_sz + pad * 2.0;
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
                        ui.painter()
                            .rect_filled(rect, egui::CornerRadius::same(6), c_accent(dark));
                        egui::Image::new(tex)
                            .fit_to_exact_size(egui::vec2(img_sz, img_sz))
                            .paint_at(ui, rect.shrink(pad));
                        ui.add_space(6.0);
                    }
                    ui.label(
                        RichText::new("pqfile - Post-Quantum File Encryption")
                            .size(15.0)
                            .color(c_accent(dark))
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("ℹ  About").size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .clicked()
                        {
                            self.show_about = true;
                        }
                    });
                });
            });

        // ── Footer ─────────────────────────────────────────────────────────
        egui::Panel::bottom("footer")
            .exact_size(26.0)
            .frame(
                egui::Frame::NONE
                    .fill(chrome)
                    .inner_margin(Margin::symmetric(14, 0)),
            )
            .show(ui, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("v{APP_VERSION}"))
                            .size(11.0)
                            .color(c_overlay(dark)),
                    );
                    ui.label(RichText::new("|").size(11.0).color(c_overlay(dark)));
                    if ui
                        .add(
                            egui::Label::new(
                                RichText::new("Legal").size(11.0).color(c_overlay(dark)),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .clicked()
                    {
                        self.show_legal = true;
                    }
                    ui.label(RichText::new("|").size(11.0).color(c_overlay(dark)));
                    ui.hyperlink_to(
                        RichText::new("Privacy").size(11.0).color(c_overlay(dark)),
                        "https://nappi.work/privacy",
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(
                                "ML-KEM-768 · ML-KEM-1024 · Hybrid · ML-DSA-65 · SLH-DSA · ChaCha20-Poly1305",
                            )
                            .size(11.0)
                            .color(c_overlay(dark)),
                        );
                    });
                });
            });

        // ── About modal ────────────────────────────────────────────────────
        if self.show_about {
            self.show_about_window(&ctx, dark);
        }

        // ── Legal modal ────────────────────────────────────────────────────
        if self.show_legal {
            self.show_legal_window(&ctx, dark);
        }

        // ── QR code modal ──────────────────────────────────────────────────
        #[cfg(not(target_arch = "wasm32"))]
        if self.qr_modal.is_some() {
            self.show_qr_window(&ctx, dark);
        }

        // ── Tab help modal ─────────────────────────────────────────────────
        if self.help_modal_open.is_some() {
            self.show_tab_help_window(&ctx, dark);
        }

        // ── Central panel ──────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(bg))
            .show(ui, |ui| {
                // Tab strip
                egui::Frame::NONE
                    .fill(chrome)
                    .inner_margin(Margin::symmetric(14, 7))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            tab_btn(ui, &mut self.tab, Tab::Keys, "🗝 Keys", dark);
                            tab_btn(ui, &mut self.tab, Tab::Keygen, "🔑 Keygen", dark);
                            tab_btn(ui, &mut self.tab, Tab::Encrypt, "🔒 Encrypt", dark);
                            tab_btn(ui, &mut self.tab, Tab::Decrypt, "🔓 Decrypt", dark);
                            tab_btn(ui, &mut self.tab, Tab::Sign, "✏ Sign", dark);
                            tab_btn(ui, &mut self.tab, Tab::Signcrypt, "🔏 Signcrypt", dark);
                            tab_btn(ui, &mut self.tab, Tab::Archive, "📦 Archive", dark);
                            tab_btn(ui, &mut self.tab, Tab::Shamir, "🔀 Shamir", dark);
                            tab_btn(ui, &mut self.tab, Tab::Inspect, "🔍 Inspect", dark);
                            tab_btn(ui, &mut self.tab, Tab::Clipboard, "📋 Clipboard", dark);
                            tab_btn(ui, &mut self.tab, Tab::Settings, "⚙ Settings", dark);
                        });
                    });

                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        egui::Frame::NONE
                            .inner_margin(Margin::symmetric(18, 14))
                            .show(ui, |ui| match self.tab {
                                Tab::Keys => self.show_keys(ui, dark),
                                Tab::Keygen => self.show_keygen(ui, dark),
                                Tab::Encrypt => self.show_encrypt(ui, dark),
                                Tab::Decrypt => self.show_decrypt(ui, dark),
                                Tab::Sign => self.show_sign(ui, dark),
                                Tab::Signcrypt => self.show_signcrypt(ui, dark),
                                Tab::Archive => self.show_archive(ui, dark),
                                Tab::Shamir => self.show_shamir(ui, dark),
                                Tab::Inspect => self.show_inspect(ui, dark),
                                Tab::Clipboard => self.show_clipboard_tab(ui, dark),
                                Tab::Settings => self.show_settings(ui, &ctx, dark),
                            });
                    });
            });
    }
}

// ── Drag-and-drop ──────────────────────────────────────────────────────────

impl PqfileApp {
    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        for file in dropped {
            let name = if !file.name.is_empty() {
                file.name.clone()
            } else {
                file.path
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };

            let data = if let Some(bytes) = file.bytes {
                Some(bytes.to_vec())
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    file.path.as_ref().and_then(|p| std::fs::read(p).ok())
                }
                #[cfg(target_arch = "wasm32")]
                {
                    None
                }
            };

            let Some(data) = data else { continue };
            self.route_drop(name, data, file.path);
        }
    }

    /// Route a dropped file into the correct slot based on the active tab and
    /// the file's extension. Pure logic with no egui dependency; testable directly.
    pub(crate) fn route_drop(
        &mut self,
        name: String,
        data: Vec<u8>,
        path: Option<std::path::PathBuf>,
    ) {
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let picked = PickedFile {
            name,
            data,
            path,
            error: None,
        };
        match self.tab {
            Tab::Encrypt => {
                if ext == "pem" {
                    *self.encrypt_pubkey.pending.lock().unwrap() = Some(picked);
                } else {
                    self.encrypt_files.push(MultiFileEntry {
                        name: picked.name,
                        data: picked.data,
                        path: picked.path,
                        status: OpStatus::None,
                    });
                }
            }
            Tab::Decrypt => {
                if ext == "pem" {
                    *self.decrypt_privkey.pending.lock().unwrap() = Some(picked);
                } else {
                    self.decrypt_files.push(MultiFileEntry {
                        name: picked.name,
                        data: picked.data,
                        path: picked.path,
                        status: OpStatus::None,
                    });
                }
            }
            Tab::Sign => {
                if ext == "pem" {
                    *self.sign_sk.pending.lock().unwrap() = Some(picked);
                } else if ext == "sig" {
                    *self.sign_sig_file.pending.lock().unwrap() = Some(picked);
                } else {
                    *self.sign_input_file.pending.lock().unwrap() = Some(picked);
                }
            }
            Tab::Signcrypt => {
                if ext == "pqf" {
                    *self.signdecrypt_input.pending.lock().unwrap() = Some(picked);
                } else {
                    *self.signcrypt_input.pending.lock().unwrap() = Some(picked);
                }
            }
            Tab::Archive => {
                if ext == "pqf" {
                    *self.extract_input.pending.lock().unwrap() = Some(picked);
                } else {
                    self.archive_files.push(MultiFileEntry {
                        name: picked.name,
                        data: picked.data,
                        path: picked.path,
                        status: OpStatus::None,
                    });
                }
            }
            Tab::Shamir => {
                if ext == "pem" {
                    self.shamir_shares.push(MultiFileEntry {
                        name: picked.name,
                        data: picked.data,
                        path: picked.path,
                        status: OpStatus::None,
                    });
                }
            }
            Tab::Inspect => {
                *self.doctor_file.pending.lock().unwrap() = Some(picked);
            }
            _ => {}
        }
    }
}

// ── Polling helpers ────────────────────────────────────────────────────────

fn drain_batch_pending(pending: &BatchPending, files: &mut Vec<MultiFileEntry>) -> bool {
    if let Ok(mut g) = pending.try_lock() {
        if let Some(batch) = g.take() {
            files.extend(batch.into_iter().map(|p| MultiFileEntry {
                name: p.name,
                data: p.data,
                path: p.path,
                status: p.error.map(OpStatus::Err).unwrap_or(OpStatus::None),
            }));
            return true;
        }
    }
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn apply_job_results(results: Vec<(usize, OpStatus)>, files: &mut [MultiFileEntry]) {
    for (i, status) in results {
        if let Some(e) = files.get_mut(i) {
            e.status = status;
        }
    }
}

impl PqfileApp {
    fn promote_staged_pubkey(&mut self) {
        if !self.encrypt_pubkey.loaded() {
            return;
        }
        if let Some(pem) = self.encrypt_pubkey.as_str().map(str::to_owned) {
            if !self.encrypt_recipients.iter().any(|r| r.pem == pem) {
                let name = std::mem::take(&mut self.encrypt_pubkey.name);
                let variant_name = pem_variant_name(&pem);
                self.encrypt_recipients.push(RecipientEntry {
                    name,
                    pem,
                    variant_name,
                });
            }
        }
        self.encrypt_pubkey.clear();
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn drain_encrypt_job_results(&mut self) -> bool {
        let (results, finished) = if let Some(job) = self.encrypt_job.as_ref() {
            if let Ok(mut g) = job.try_lock() {
                (std::mem::take(&mut g.results), g.finished)
            } else {
                (Vec::new(), false)
            }
        } else {
            (Vec::new(), false)
        };
        apply_job_results(results, &mut self.encrypt_files);
        if finished {
            let ok = self
                .encrypt_files
                .iter()
                .filter(|e| matches!(e.status, OpStatus::Ok(_)))
                .count();
            let err = self
                .encrypt_files
                .iter()
                .filter(|e| matches!(e.status, OpStatus::Err(_)))
                .count();
            if ok + err > 0 {
                self.encrypt_batch_summary = Some(if err == 0 {
                    OpStatus::Ok(format!(
                        "{ok} file{} encrypted successfully.",
                        if ok == 1 { "" } else { "s" }
                    ))
                } else {
                    OpStatus::Err(format!("{ok} succeeded, {err} failed."))
                });
            }
            // Record successfully encrypted source files as recent.
            for e in &self.encrypt_files {
                if matches!(e.status, OpStatus::Ok(_)) {
                    if let Some(ref p) = e.path {
                        push_recent(
                            &mut self.recent_encrypt_files,
                            p.to_string_lossy().into_owned(),
                        );
                    }
                }
            }
            let all_ok = self.settings.auto_clear && err == 0 && ok > 0;
            if all_ok {
                self.encrypt_recipients.clear();
                self.encrypt_files.clear();
                self.encrypt_passphrase.clear();
                self.encrypt_passphrase_confirm.clear();
                self.encrypt_keyfile.clear();
                self.encrypt_fido2_pin.clear();
                self.encrypt_batch_summary = None;
            }
            self.encrypt_job = None;
        }
        finished
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn drain_decrypt_job_results(&mut self) -> bool {
        let (results, finished) = if let Some(job) = self.decrypt_batch_job.as_ref() {
            if let Ok(mut g) = job.try_lock() {
                (std::mem::take(&mut g.results), g.finished)
            } else {
                (Vec::new(), false)
            }
        } else {
            (Vec::new(), false)
        };
        apply_job_results(results, &mut self.decrypt_files);
        if finished {
            let ok = self
                .decrypt_files
                .iter()
                .filter(|e| matches!(e.status, OpStatus::Ok(_)))
                .count();
            let err = self
                .decrypt_files
                .iter()
                .filter(|e| matches!(e.status, OpStatus::Err(_)))
                .count();
            if ok + err > 0 {
                self.decrypt_batch_summary = Some(if err == 0 {
                    OpStatus::Ok(format!(
                        "{ok} file{} decrypted successfully.",
                        if ok == 1 { "" } else { "s" }
                    ))
                } else {
                    OpStatus::Err(format!("{ok} succeeded, {err} failed."))
                });
            }
            // Record successfully decrypted source files as recent.
            for e in &self.decrypt_files {
                if matches!(e.status, OpStatus::Ok(_)) {
                    if let Some(ref p) = e.path {
                        push_recent(
                            &mut self.recent_decrypt_files,
                            p.to_string_lossy().into_owned(),
                        );
                    }
                }
            }
            // Record the private key used as recent.
            if let Some(ref p) = self.decrypt_privkey.path {
                push_recent(&mut self.recent_privkeys, p.to_string_lossy().into_owned());
            }
            let all_ok = self.settings.auto_clear && err == 0 && ok > 0;
            if all_ok {
                self.decrypt_privkey.clear();
                self.decrypt_files.clear();
                self.decrypt_passphrase.clear();
                self.decrypt_v10_passphrase.clear();
                self.decrypt_keyfile.clear();
                self.decrypt_fido2_pin.clear();
                self.decrypt_batch_summary = None;
            }
            self.decrypt_batch_job = None;
        }
        finished
    }
}

// ── Polling ────────────────────────────────────────────────────────────────

impl PqfileApp {
    pub(crate) fn poll_files(&mut self) -> bool {
        self.encrypt_pubkey.poll();
        self.promote_staged_pubkey();
        self.encrypt_keyfile.poll();
        self.encrypt_fido2_enrollment.poll();
        self.decrypt_privkey.poll();
        self.decrypt_keyfile.poll();
        self.decrypt_fido2_enrollment.poll();
        self.doctor_file.poll();

        // Sign tab
        self.sign_sk.poll();
        self.sign_input_file.poll();
        self.sign_vk.poll();
        self.sign_verify_file.poll();
        self.sign_sig_file.poll();

        // Signcrypt tab
        self.signcrypt_sk.poll();
        self.signcrypt_pubkey.poll();
        self.signcrypt_input.poll();
        self.signdecrypt_privkey.poll();
        self.signdecrypt_vk.poll();
        self.signdecrypt_input.poll();

        // Archive tab
        self.archive_pubkey.poll();
        self.extract_privkey.poll();
        self.extract_input.poll();

        // Shamir tab
        self.shamir_split_privkey.poll();

        // Tools tab
        self.revoke_pubkey.poll();
        self.rekey_privkey.poll();
        self.rekey_new_pubkey.poll();
        self.rekey_input.poll();

        let enc_batch = drain_batch_pending(&self.encrypt_batch_pending, &mut self.encrypt_files);
        let dec_batch = drain_batch_pending(&self.decrypt_batch_pending, &mut self.decrypt_files);
        let arc_batch = drain_batch_pending(&self.archive_batch_pending, &mut self.archive_files);
        let sha_batch = drain_batch_pending(&self.shamir_shares_pending, &mut self.shamir_shares);
        let batch_arrived = enc_batch || dec_batch || arc_batch || sha_batch;

        #[cfg(not(target_arch = "wasm32"))]
        let enc_update = self.drain_encrypt_job_results();
        #[cfg(target_arch = "wasm32")]
        let enc_update = false;

        #[cfg(not(target_arch = "wasm32"))]
        let dec_update = self.drain_decrypt_job_results();
        #[cfg(target_arch = "wasm32")]
        let dec_update = false;

        #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
        self.poll_fido2_jobs();

        // Clipboard tool file slots
        self.clipboard_pubkey.poll();
        self.clipboard_privkey.poll();

        // Drain watchfolder log messages.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ref handle) = self.watch_handle {
            while let Ok(msg) = handle.log_rx.try_recv() {
                self.watch_log.push(msg);
                if self.watch_log.len() > 200 {
                    self.watch_log.drain(..100);
                }
            }
        }

        let singles_pending = [
            &self.encrypt_pubkey,
            &self.decrypt_privkey,
            &self.sign_sk,
            &self.sign_input_file,
            &self.sign_vk,
            &self.sign_verify_file,
            &self.sign_sig_file,
            &self.signcrypt_sk,
            &self.signcrypt_pubkey,
            &self.signcrypt_input,
            &self.signdecrypt_privkey,
            &self.signdecrypt_vk,
            &self.signdecrypt_input,
            &self.archive_pubkey,
            &self.extract_privkey,
            &self.extract_input,
            &self.shamir_split_privkey,
            &self.revoke_pubkey,
            &self.rekey_privkey,
            &self.rekey_new_pubkey,
            &self.rekey_input,
            &self.clipboard_pubkey,
            &self.clipboard_privkey,
        ]
        .iter()
        .any(|f| f.pending.try_lock().map(|g| g.is_some()).unwrap_or(false));

        let batch_pending = [
            &self.encrypt_batch_pending,
            &self.decrypt_batch_pending,
            &self.archive_batch_pending,
            &self.shamir_shares_pending,
        ]
        .iter()
        .any(|p| p.try_lock().map(|g| g.is_some()).unwrap_or(false));

        singles_pending || batch_arrived || batch_pending || enc_update || dec_update
    }
}

// ── About window ───────────────────────────────────────────────────────────

impl PqfileApp {
    fn show_about_window(&mut self, ctx: &egui::Context, dark: bool) {
        let mut close = false;

        egui::Window::new(
            RichText::new("About pqfile")
                .size(14.0)
                .strong()
                .color(c_text(dark)),
        )
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .fixed_size([430.0, 490.0])
        .frame(
            egui::Frame::window(&ctx.global_style())
                .fill(c_bg(dark))
                .stroke(Stroke::new(2.0, c_subtext(dark)))
                .corner_radius(CornerRadius::same(10)),
        )
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .max_height(440.0)
                .auto_shrink([true, true])
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(6.0);
                        if let Some(ref tex) = self.app_icon {
                            let pad = 6.0_f32;
                            let img_sz = 32.0_f32;
                            let total = egui::vec2(img_sz + pad * 2.0, img_sz + pad * 2.0);
                            let (rect, _) = ui.allocate_exact_size(total, egui::Sense::hover());
                            ui.painter().rect_filled(
                                rect,
                                egui::CornerRadius::same(10),
                                c_accent(dark),
                            );
                            egui::Image::new(tex)
                                .fit_to_exact_size(egui::vec2(img_sz, img_sz))
                                .paint_at(ui, rect.shrink(pad));
                        } else {
                            ui.label(RichText::new("🔐").size(40.0));
                        }
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("pqfile")
                                .size(20.0)
                                .strong()
                                .color(c_accent(dark)),
                        );
                        ui.label(
                            RichText::new("Post-Quantum File Encryption")
                                .size(13.0)
                                .color(c_subtext(dark)),
                        );
                        ui.label(
                            RichText::new(format!("Version {APP_VERSION}"))
                                .size(12.0)
                                .color(c_subtext(dark)),
                        );
                    });

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(10.0);

                    ui.label(
                        RichText::new(
                            "Quantum-resistant file encryption for the post-quantum era. \
                                 Encrypt any file with a public key. \
                                 Only the matching private key can decrypt it.",
                        )
                        .size(13.0)
                        .color(c_subtext(dark)),
                    );

                    ui.add_space(14.0);
                    section_label(ui, "CRYPTOGRAPHIC ALGORITHMS", dark);
                    card(ui, c_card(dark), c_surface1(dark), |ui| {
                        kv_row(
                            ui,
                            "Key encapsulation",
                            "ML-KEM-512/768/1024, X25519 Hybrid (FIPS 203)",
                            dark,
                        );
                        kv_row(
                            ui,
                            "Digital signatures",
                            "ML-DSA-65 (FIPS 204), SLH-DSA-SHAKE-192f (FIPS 205)",
                            dark,
                        );
                        kv_row(
                            ui,
                            "Symmetric cipher",
                            "ChaCha20-Poly1305  (RFC 8439)",
                            dark,
                        );
                        kv_row(ui, "Passphrase KDF", "Argon2id  (m=64 MiB, t=3, p=1)", dark);
                        kv_row(ui, "Randomness", "OS CSPRNG  (OsRng)", dark);
                        kv_row(ui, "File format", ".pqf  v3-v6 / multi-recipient v4", dark);
                    });

                    ui.add_space(10.0);
                    section_label(ui, "SECURITY PROPERTIES", dark);
                    card(ui, c_card(dark), c_surface1(dark), |ui| {
                        bullet(ui, "All operations run locally. No data is uploaded", dark);
                        bullet(ui, "Keys and shared secrets zeroized after use", dark);
                        bullet(ui, "AEAD authentication prevents silent corruption", dark);
                        bullet(ui, "Fresh nonce and KEM encapsulation per file", dark);
                    });

                    ui.add_space(10.0);
                    section_label(ui, "AUTHOR", dark);
                    card(ui, c_card(dark), c_surface1(dark), |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Created by")
                                    .size(12.5)
                                    .color(c_subtext(dark)),
                            );
                            ui.hyperlink_to(
                                RichText::new("dangel34").size(12.5).color(c_accent(dark)),
                                "https://github.com/dangel34",
                            );
                        });
                    });

                    ui.add_space(14.0);
                    ui.separator();
                    ui.add_space(10.0);

                    ui.vertical_centered(|ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Close").size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark))
                                .min_size(Vec2::new(88.0, 30.0)),
                            )
                            .clicked()
                        {
                            close = true;
                        }
                    });
                    ui.add_space(4.0);
                });
        });

        if close {
            self.show_about = false;
        }
    }

    fn show_legal_window(&mut self, ctx: &egui::Context, dark: bool) {
        let mut close = false;

        egui::Window::new(
            RichText::new("Legal Notices")
                .size(14.0)
                .strong()
                .color(c_text(dark)),
        )
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .fixed_size([480.0, 520.0])
        .frame(
            egui::Frame::window(&ctx.global_style())
                .fill(c_bg(dark))
                .stroke(Stroke::new(2.0, c_subtext(dark)))
                .corner_radius(CornerRadius::same(10)),
        )
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .max_height(470.0)
                .auto_shrink([true, true])
                .show(ui, |ui| {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Last updated: June 5, 2026")
                            .size(11.0)
                            .color(c_subtext(dark)),
                    );
                    ui.add_space(10.0);

                    section_label(ui, "WHAT PQFILE IS", dark);
                    ui.label(
                        RichText::new(
                            "pqfile is open-source software for encrypting and decrypting files \
                             using post-quantum cryptographic algorithms. It uses ML-KEM-768 \
                             (NIST FIPS 203) for key encapsulation and ChaCha20-Poly1305 for \
                             authenticated encryption. The browser-based version performs all \
                             cryptographic operations locally in your browser using WebAssembly. \
                             No key material, plaintexts, or ciphertexts are transmitted over \
                             the network.",
                        )
                        .size(12.5)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(10.0);

                    section_label(ui, "NO WARRANTY", dark);
                    ui.label(
                        RichText::new(
                            "This software is provided \"as is\" without warranty of any kind, \
                             express or implied, including but not limited to warranties of \
                             merchantability, fitness for a particular purpose, or \
                             non-infringement. The author makes no representations regarding \
                             the correctness, completeness, or security of this software.\n\n\
                             This software has not been independently audited by a third-party \
                             cryptographic security firm. Cryptographic software is complex and \
                             may contain defects. You are responsible for evaluating whether \
                             this software is appropriate for your use case.",
                        )
                        .size(12.5)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(10.0);

                    section_label(ui, "NO LIABILITY", dark);
                    ui.label(
                        RichText::new(
                            "To the maximum extent permitted by applicable law, the author is \
                             not liable for any damages arising from use or inability to use \
                             this software, including but not limited to data loss, unauthorized \
                             access to encrypted or decrypted content, or damages resulting from \
                             cryptographic failures or implementation defects.",
                        )
                        .size(12.5)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(10.0);

                    section_label(ui, "EXPORT CONTROL", dark);
                    ui.label(
                        RichText::new(
                            "This software contains cryptographic functionality and is subject \
                             to U.S. Export Administration Regulations (EAR), 15 CFR Parts \
                             730-774. By downloading, accessing, using, or redistributing this \
                             software, you represent and warrant that:",
                        )
                        .size(12.5)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(4.0);
                    card(ui, c_card(dark), c_surface1(dark), |ui| {
                        bullet(
                            ui,
                            "You are not located in, and will not use this software in, any \
                             country or territory subject to U.S. economic sanctions or export \
                             restrictions, including Cuba, Iran, North Korea, and Syria",
                            dark,
                        );
                        bullet(
                            ui,
                            "You are not listed on any U.S. government restricted-party list",
                            dark,
                        );
                        bullet(
                            ui,
                            "Your use of this software does not otherwise violate the EAR or \
                             any applicable export control law",
                            dark,
                        );
                    });
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "This software uses only publicly documented, NIST-standardized \
                             cryptographic algorithms (FIPS 203 and a FIPS 197-compatible AEAD \
                             construction) and is published as open-source software under the \
                             MIT License. Its cryptographic functionality has been reported to \
                             the U.S. Bureau of Industry and Security under License Exception \
                             TSU (15 CFR 742.15(b)).",
                        )
                        .size(12.5)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(10.0);

                    section_label(ui, "SECURITY DISCLOSURES", dark);
                    ui.label(
                        RichText::new(
                            "If you discover a security vulnerability in pqfile, please report \
                             it responsibly. Do not open a public issue. Use the private \
                             security advisory feature on GitHub:",
                        )
                        .size(12.5)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(2.0);
                    ui.hyperlink_to(
                        RichText::new("Report a vulnerability (GitHub advisory)")
                            .size(12.5)
                            .color(c_accent(dark)),
                        "https://github.com/dangel34/PQ-File-Encryption/security/advisories/new",
                    );
                    ui.add_space(10.0);

                    section_label(ui, "PRIVACY", dark);
                    ui.label(
                        RichText::new(
                            "This site collects no personal information beyond standard server \
                             access logs (IP address, request metadata). See the Privacy Policy \
                             for full details.",
                        )
                        .size(12.5)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(2.0);
                    ui.hyperlink_to(
                        RichText::new("Privacy Policy")
                            .size(12.5)
                            .color(c_accent(dark)),
                        "https://nappi.work/privacy",
                    );
                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.vertical_centered(|ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Close").size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark))
                                .min_size(Vec2::new(88.0, 30.0)),
                            )
                            .clicked()
                        {
                            close = true;
                        }
                    });
                    ui.add_space(4.0);
                });
        });

        if close {
            self.show_legal = false;
        }
    }

    // ── Tab help modal ────────────────────────────────────────────────────────

    pub(crate) fn show_tab_help_window(&mut self, ctx: &egui::Context, dark: bool) {
        let tab = match self.help_modal_open {
            Some(t) => t,
            None => return,
        };

        let (title, body) = tab_help_content(tab);
        let mut close = false;

        egui::Window::new(RichText::new(title).size(14.0).strong().color(c_text(dark)))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .fixed_size([460.0, 460.0])
            .frame(
                egui::Frame::window(&ctx.global_style())
                    .fill(c_bg(dark))
                    .stroke(Stroke::new(2.0, c_subtext(dark)))
                    .corner_radius(CornerRadius::same(10)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(390.0)
                    .auto_shrink([true, true])
                    .show(ui, |ui| {
                        ui.add_space(6.0);
                        for paragraph in body {
                            if paragraph.starts_with("##") {
                                let heading = paragraph.trim_start_matches('#').trim();
                                ui.add_space(6.0);
                                section_label(ui, heading, dark);
                                ui.add_space(2.0);
                            } else {
                                ui.label(
                                    RichText::new(*paragraph).size(13.0).color(c_subtext(dark)),
                                );
                                ui.add_space(4.0);
                            }
                        }
                        ui.add_space(8.0);
                    });

                ui.separator();
                ui.add_space(6.0);
                ui.vertical_centered(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Close").size(13.0).color(c_text(dark)),
                            )
                            .fill(c_surface0(dark))
                            .min_size(Vec2::new(88.0, 30.0)),
                        )
                        .clicked()
                    {
                        close = true;
                    }
                });
                ui.add_space(4.0);
            });

        if close {
            self.help_modal_open = None;
        }
    }
}

fn tab_help_content(tab: Tab) -> (&'static str, &'static [&'static str]) {
    match tab {
        Tab::Keygen => ("Key Pair Generation", &[
            "This tab generates the cryptographic key pair that makes everything in pqfile work. \
             You create a public key that anyone can use to encrypt files for you, and a private \
             key that only you can use to decrypt them.",
            "## WHY POST-QUANTUM?",
            "Traditional encryption algorithms such as RSA and ECDSA rely on mathematical \
             problems that quantum computers will be able to solve efficiently. pqfile uses \
             ML-KEM (NIST FIPS 203), a Key Encapsulation Mechanism standardized specifically \
             to resist quantum attacks. Your keys will remain secure even as quantum hardware \
             matures.",
            "## SECURITY LEVELS",
            "ML-KEM-512 offers a good balance of security and performance for most uses. \
             ML-KEM-768 is the recommended default and matches the security of AES-192. \
             ML-KEM-1024 provides the highest level of assurance. Hybrid X25519 + ML-KEM-768 \
             combines a classical algorithm with the post-quantum one for defense in depth.",
            "## SIGNING KEYS",
            "ML-DSA-65 (FIPS 204) is the default signing algorithm: fast, with 3.3 KB \
             signatures. SLH-DSA-SHAKE-192f (FIPS 205) is a hash-based alternative at the \
             same security category, resting on more conservative assumptions - choose it \
             for very long-lived signatures (archives, releases) if you accept slower \
             signing and 35 KB signatures.",
            "## PROTECTING YOUR PRIVATE KEY",
            "Your private key is the crown jewel. If you lose it, files encrypted to your \
             public key cannot be recovered. If someone obtains it, they can read your files. \
             Using a passphrase encrypts the private key at rest using Argon2id with \
             memory-hard parameters. Hardware-backed keys store the seed in your OS credential \
             store for an additional layer of protection.",
        ]),
        Tab::Encrypt => ("Encrypt Files", &[
            "Encryption transforms a file into ciphertext that only the intended recipient \
             can read. pqfile uses authenticated encryption, so the recipient can verify \
             the file has not been tampered with during transit or storage.",
            "## HOW IT WORKS",
            "You load the recipient's public key (.pem file), choose the file you want to \
             protect, and pqfile produces a .pqf file. The contents are split into chunks, \
             each independently authenticated with ChaCha20-Poly1305, so even a partial file \
             transfer can be verified up to the point of truncation.",
            "## MULTIPLE RECIPIENTS",
            "You can add several public keys to encrypt one file for multiple people at once. \
             A single random session key encrypts the payload. Each recipient's key wraps a \
             copy of that session key. Any one of them can decrypt independently.",
            "## ANONYMOUS MODE",
            "When you use multiple recipients, pqfile automatically uses the v8 anonymous \
             format. This hides which key type each recipient uses and randomizes the order \
             of recipient entries, so an observer cannot tell how many or what kind of keys \
             were used.",
            "## PADDING & STEALTH MODE",
            "The Padding checkbox rounds the ciphertext length to a coarser bucket (at most \
             ~12% overhead) so an observer watching file sizes cannot determine the exact \
             plaintext length. The true size still travels inside the authenticated header; \
             decrypting strips the padding back off automatically, with nothing to configure \
             on the Decrypt tab. Stealth mode (single recipient only) goes further and omits \
             the .pqf magic bytes, version byte, and KEM variant field entirely, so the output \
             is not identifiable as pqfile ciphertext at all. Because there is nothing left on \
             the wire to auto-detect, decrypting a stealth file requires checking \"Stealth \
             mode\" on the Decrypt tab yourself.",
        ]),
        Tab::Decrypt => ("Decrypt / Rekey", &[
            "Decryption recovers the original file from a .pqf ciphertext using your private \
             key. Each chunk is authenticated before any plaintext is written, so you can trust \
             that what you receive is exactly what was encrypted.",
            "## WHAT HAPPENS STEP BY STEP",
            "pqfile reads the file header to find the KEM ciphertext for your key, runs \
             ML-KEM decapsulation to recover the session key, then streams through the payload \
             verifying and decrypting each 64-kilobyte chunk. No plaintext is written until \
             every chunk in the batch passes its authentication check.",
            "## PASSPHRASE-PROTECTED KEYS",
            "If your private key was created with a passphrase, you will be prompted for it. \
             The passphrase is used locally to unlock your private key and is never transmitted \
             anywhere. Hardware-backed keys retrieve the seed from your OS credential store \
             automatically without a passphrase prompt.",
            "## IF DECRYPTION FAILS",
            "A decryption failure almost always means the file was modified or corrupted after \
             encryption, the wrong private key was used, or the file was not a valid .pqf file. \
             pqfile reports the failure immediately rather than producing potentially \
             compromised output.",
            "## REKEY",
            "Rekeying transfers an encrypted file to a new recipient without decrypting the \
             payload. The session key is decapsulated using the old private key and then \
             re-encapsulated for the new recipient. The encrypted content itself is untouched. \
             Only supported for files using the default 64 KiB chunk size.",
            "## STEALTH MODE FILES",
            "If a file was encrypted with Stealth mode (Encrypt tab), it has no .pqf magic \
             bytes or header for pqfile to recognize automatically. Check \"Stealth mode\" \
             above the file list before decrypting; there is nothing in the file itself that \
             reveals this.",
        ]),
        Tab::Inspect => ("Inspect File or Key", &[
            "Inspect runs health checks on a key file (.pem) or encrypted file (.pqf) and \
             shows all header metadata. No decryption key is required.",
            "## KEY HEALTH CHECKS",
            "For key files: passphrase protection, hardware-backed status, expiry with days \
             remaining, revocation sidecar check (desktop), and Argon2 parameter version \
             (enter passphrase to detect pqfile <4.0 legacy p=1 keys).",
            "## FILE CHECKS",
            "For .pqf files: format version, KEM algorithm, original size, compression, \
             header validity, and recipient anonymity grade. The Raw Details section shows \
             the nonce and hex version codes.",
            "## ICONS",
            "✔ = pass, ⚠ = warning (action recommended), ✖ = fail (action required), \
             · = informational or not applicable.",
        ]),
        Tab::Sign => ("Digital Signatures", &[
            "Signing lets you prove that a file came from you and has not been modified. \
             pqfile supports two post-quantum signature algorithms: ML-DSA-65 (NIST FIPS 204, \
             the default - fast, 3.3 KB signatures) and SLH-DSA-SHAKE-192f (NIST FIPS 205 - \
             hash-based, resting on more conservative security assumptions; slower signing \
             and 35 KB signatures, suited to long-lived signatures). Both offer the same \
             NIST security category.",
            "## KEY GENERATION",
            "Generate a signing key pair from the Keygen tab (select ML-DSA-65 or \
             SLH-DSA-SHAKE-192f as the algorithm). A signing key pair consists of a private \
             signing key and a public verifying key. Share your verifying key with anyone \
             who needs to confirm your signatures. When signing or verifying, the algorithm \
             is detected from the key automatically.",
            "## SIGNING A FILE",
            "Signing produces a small detached .sig file alongside the original. The signature \
             covers the entire file content. If even one byte changes after signing, \
             verification will fail.",
            "## VERIFYING A SIGNATURE",
            "To verify, you need the original file, the .sig file, and the sender's verifying \
             key. Successful verification means the file is exactly as the signer created it \
             and the signature was produced by the holder of the corresponding private key.",
            "## SIGNATURES VS ENCRYPTION",
            "Signing proves authenticity and integrity but does not hide the contents. \
             Encryption hides the contents but by itself does not prove who created them. \
             Use the Signcrypt tab if you need both properties at once.",
        ]),
        Tab::Signcrypt => ("Signcrypt", &[
            "Signcrypt combines signing and encryption into a single operation. The sender's \
             signature is placed inside the encrypted payload, so it is protected by the same \
             authentication as the file contents.",
            "## WHY NOT SIGN THEN ENCRYPT SEPARATELY?",
            "If you sign a file and then encrypt it, a recipient could theoretically strip the \
             outer signature and re-encrypt with a different key, making it appear the content \
             came from someone else. With signcrypt, the signature lives inside the AEAD \
             ciphertext and cannot be removed or substituted without breaking authentication.",
            "## HOW TO SIGNDECRYPT",
            "The recipient uses their private decryption key and your verifying key together. \
             pqfile decrypts the file and then confirms the signature before reporting success. \
             If the signature does not match, the operation fails even if decryption succeeds.",
            "## A NOTE ON OUTPUT",
            "During signdecrypt, plaintext is written to the output as it is decrypted, before \
             the final signature check completes. If you are writing to a file or socket, \
             please be aware that the output should be treated as unverified until the \
             operation returns successfully.",
        ]),
        Tab::Archive => ("Encrypted Archive", &[
            "The archive format packs multiple files into a single .pqf container. All files \
             are authenticated together, so the recipient can be confident that the entire \
             collection is intact and unmodified.",
            "## CREATING AN ARCHIVE",
            "Select the recipient's public key, add the files you want to include, and pqfile \
             bundles them into a single encrypted stream. The archive preserves file names, \
             sizes, and modification times.",
            "## EXTRACTING AN ARCHIVE",
            "Use the private key matching the public key that was used to encrypt. pqfile \
             authenticates every chunk before writing any file to disk, so an extraction will \
             either succeed completely or fail before producing output.",
            "## PATH SAFETY",
            "The extractor checks every file path in the archive against the output directory. \
             Paths containing traversal components such as .. are rejected before any files are \
             written, preventing a crafted archive from writing outside the intended location.",
        ]),
        Tab::Keys => ("Key Management", &[
            "The Keys panel gives you a quick overview of the key pairs you work with \
             regularly. You can store references to key files so you do not have to locate \
             them each time you encrypt or decrypt.",
            "## KEY FINGERPRINTS",
            "Each public key has a SHA3-256 fingerprint displayed in a short colon-separated \
             hex format. Fingerprints are a convenient way to confirm you are using the right \
             key without reading the full PEM data. Share your fingerprint alongside your \
             public key so recipients can verify they have the authentic version.",
            "## ORGANIZING KEYS",
            "You can label and store key pairs in the panel for easy recall. Clicking a stored \
             key pre-loads it into the Encrypt or Decrypt tab, saving time when working with \
             the same key frequently.",
        ]),
        Tab::Shamir => ("Shamir Key Splitting", &[
            "Shamir's Secret Sharing lets you split a private key into N shares such that \
             any M of them can reconstruct the original key, but fewer than M reveal \
             nothing. This is useful for secure key backup, team key custody, and \
             organizational access controls.",
            "## A PRACTICAL EXAMPLE",
            "A team of five people might split a key with a threshold of three. Three members \
             must cooperate to reconstruct the key and perform a decryption. No single person \
             or pair can act alone. Shares can be stored in separate locations for resilience \
             against physical loss.",
            "## SECURITY PROPERTIES",
            "The splitting uses GF(256) polynomial interpolation over each byte of the seed. \
             Any set of shares smaller than the threshold is computationally equivalent to \
             having no information about the original key. Shares include a fingerprint to \
             detect mixing of shares from different keys.",
            "## RECONSTRUCTION",
            "Provide at least the threshold number of share files. pqfile verifies that all \
             shares belong to the same key before reconstructing, and checks the derived public \
             key fingerprint against the stored value. The result is an unencrypted private key \
             that you can then protect with a passphrase if needed.",
        ]),
        Tab::Clipboard => ("Clipboard", &[
            "The Clipboard tab lets you encrypt or decrypt small pieces of text without \
             writing any file to disk. This is useful for sharing secrets via messaging \
             apps, email, or other text channels.",
            "## ENCRYPT TEXT",
            "Load a recipient public key, type or paste your plaintext, then click \
             Encrypt & Copy. The ciphertext is copied to your clipboard and shown in the \
             decrypt area so you can verify it immediately.",
            "## DECRYPT TEXT",
            "Paste a PEM ciphertext block, load your private key, and click Decrypt. \
             The recovered plaintext appears in the encrypt area.",
            "## AUTO-CLEAR",
            "An optional timer zeroizes both text areas after a configurable period of \
             inactivity. Configure it in Settings → Clipboard.",
        ]),
        Tab::Settings => ("Settings", &[
            "Settings let you configure how pqfile behaves across sessions. Preferences are \
             saved automatically and restored the next time you open the application.",
            "## OUTPUT DIRECTORY",
            "The default output directory is where generated keys, encrypted files, and \
             signatures are saved. Setting this once avoids having to navigate to the same \
             folder repeatedly.",
            "## CONFIRM BEFORE OVERWRITING",
            "When enabled, pqfile will not overwrite existing key files during key generation. \
             This prevents accidental replacement of keys that are already in use.",
            "## THEME",
            "Choose between light and dark themes. The theme preference is stored locally and \
             applies immediately.",
        ]),
    }
}

// ── Key list persistence ───────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn save_keys(keys: &[KeyEntry], storage: &mut dyn eframe::Storage) {
    storage.set_string("keys.count", keys.len().to_string());
    for (i, k) in keys.iter().enumerate() {
        storage.set_string(&format!("keys.{i}.label"), k.label.clone());
        storage.set_string(
            &format!("keys.{i}.pubkey"),
            k.pubkey_path.to_string_lossy().into_owned(),
        );
        storage.set_string(
            &format!("keys.{i}.privkey"),
            k.privkey_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        storage.set_string(&format!("keys.{i}.fp"), k.fingerprint.clone());
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn load_keys(storage: &dyn eframe::Storage) -> Vec<KeyEntry> {
    let count: usize = storage
        .get_string("keys.count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let label = storage
            .get_string(&format!("keys.{i}.label"))
            .unwrap_or_default();
        let pubkey_str = storage
            .get_string(&format!("keys.{i}.pubkey"))
            .unwrap_or_default();
        let privkey_str = storage
            .get_string(&format!("keys.{i}.privkey"))
            .unwrap_or_default();
        let fingerprint = storage
            .get_string(&format!("keys.{i}.fp"))
            .unwrap_or_default();
        if pubkey_str.is_empty() {
            continue;
        }
        let pubkey_path = std::path::PathBuf::from(&pubkey_str);
        let privkey_path = if privkey_str.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(&privkey_str))
        };
        out.push(KeyEntry {
            label,
            pubkey_path,
            privkey_path,
            fingerprint,
        });
    }
    out
}

// ── WASM public key persistence ────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
pub(crate) fn save_wasm_pubkeys(keys: &[(String, String)], storage: &mut dyn eframe::Storage) {
    let n = keys.len().min(50);
    storage.set_string("wpk_count", n.to_string());
    for (i, (label, pem)) in keys.iter().take(50).enumerate() {
        storage.set_string(&format!("wpk_{i}_label"), label.clone());
        storage.set_string(&format!("wpk_{i}_pem"), pem.clone());
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn load_wasm_pubkeys(storage: &dyn eframe::Storage) -> Vec<(String, String)> {
    let count: usize = storage
        .get_string("wpk_count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
        .min(50);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let label = storage
            .get_string(&format!("wpk_{i}_label"))
            .unwrap_or_default();
        let pem = storage
            .get_string(&format!("wpk_{i}_pem"))
            .unwrap_or_default();
        if !pem.is_empty() {
            out.push((label, pem));
        }
    }
    out
}

// ── QR code helpers ────────────────────────────────────────────────────────

impl PqfileApp {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn open_qr(&mut self, ctx: &egui::Context, title: String, data: &str) {
        use image::Rgba;
        use qrcode::QrCode;

        let code = match QrCode::new(data.as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };
        let qr_img = code
            .render::<Rgba<u8>>()
            .dark_color(Rgba([0, 0, 0, 255]))
            .light_color(Rgba([255, 255, 255, 255]))
            .min_dimensions(200, 200)
            .max_dimensions(360, 360)
            .build();
        let (w, h) = (qr_img.width() as usize, qr_img.height() as usize);
        let pixels: Vec<u8> = qr_img.into_raw();
        let color_image = egui::ColorImage::from_rgba_unmultiplied([w, h], &pixels);
        let texture = ctx.load_texture("qr_code", color_image, egui::TextureOptions::NEAREST);
        self.qr_modal = Some(QrModal {
            title,
            texture,
            data: data.to_owned(),
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn show_qr_window(&mut self, ctx: &egui::Context, dark: bool) {
        use crate::colors::{c_bg, c_subtext, c_surface0, c_text};
        use eframe::egui::{CornerRadius, Stroke, Vec2};

        let modal = match self.qr_modal.take() {
            Some(m) => m,
            None => return,
        };
        let mut keep_open = true;

        egui::Window::new(
            RichText::new(&modal.title)
                .size(14.0)
                .strong()
                .color(c_text(dark)),
        )
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .frame(
            egui::Frame::window(&ctx.global_style())
                .fill(c_bg(dark))
                .stroke(Stroke::new(2.0, c_subtext(dark)))
                .corner_radius(CornerRadius::same(10)),
        )
        .show(ctx, |ui| {
            ui.add_space(6.0);
            ui.vertical_centered(|ui| {
                let sz = modal.texture.size_vec2();
                let (img_rect, _) = ui.allocate_exact_size(sz, egui::Sense::hover());
                egui::Image::new(&modal.texture)
                    .fit_to_exact_size(sz)
                    .paint_at(ui, img_rect);
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Scan to load this key on another device, \
                         or copy it to paste directly.",
                    )
                    .size(12.0)
                    .color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("⎘  Copy").size(13.0).color(c_text(dark)),
                            )
                            .fill(c_surface0(dark))
                            .min_size(Vec2::new(80.0, 28.0)),
                        )
                        .on_hover_text("Copy to clipboard again")
                        .clicked()
                    {
                        ui.ctx().copy_text(modal.data.clone());
                    }
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Close").size(13.0).color(c_text(dark)),
                            )
                            .fill(c_surface0(dark))
                            .min_size(Vec2::new(80.0, 28.0)),
                        )
                        .clicked()
                    {
                        keep_open = false;
                    }
                });
                ui.add_space(4.0);
            });
        });

        if keep_open {
            self.qr_modal = Some(modal);
        }
    }
}

// ── Watchfolder helpers ────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
impl PqfileApp {
    /// Start watching `dir`, encrypting new files for the current encrypt recipients.
    pub(crate) fn start_watch(&mut self, ctx: &egui::Context) {
        use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::sync::Arc;
        use std::time::Duration;

        let dir = self.watch_dir.clone();
        if dir.is_empty() {
            return;
        }
        let pub_pems: Vec<String> = self
            .encrypt_recipients
            .iter()
            .map(|r| r.pem.clone())
            .collect();
        if pub_pems.is_empty() {
            return;
        }
        let output_dir = if self.settings.output_dir.is_empty() {
            dir.clone()
        } else {
            self.settings.output_dir.clone()
        };
        let confirm = self.settings.confirm_overwrite;

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let stop_clone = Arc::clone(&stop_flag);
        let ctx = ctx.clone();

        std::thread::spawn(move || {
            let (ev_tx, ev_rx) = mpsc::channel();
            let mut watcher =
                match recommended_watcher(move |res: notify::Result<notify::Event>| {
                    if let Ok(ev) = res {
                        let _ = ev_tx.send(ev);
                    }
                }) {
                    Ok(w) => w,
                    Err(_) => return,
                };
            if watcher
                .watch(std::path::Path::new(&dir), RecursiveMode::NonRecursive)
                .is_err()
            {
                return;
            }

            while !stop_clone.load(Ordering::Relaxed) {
                match ev_rx.recv_timeout(Duration::from_millis(300)) {
                    Ok(ev) => {
                        if matches!(ev.kind, EventKind::Create(_)) {
                            for path in ev.paths {
                                // Skip already-encrypted files and dotfiles.
                                let ext = path
                                    .extension()
                                    .map(|e| e.to_ascii_lowercase().to_string_lossy().into_owned())
                                    .unwrap_or_default();
                                if ext == "pqf"
                                    || path
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .map(|n| n.starts_with('.'))
                                        .unwrap_or(false)
                                {
                                    continue;
                                }
                                if let Ok(data) = std::fs::read(&path) {
                                    let name = path
                                        .file_name()
                                        .map(|n| n.to_string_lossy().into_owned())
                                        .unwrap_or_default();
                                    let out_name = format!("{name}.pqf");
                                    let out_path =
                                        std::path::PathBuf::from(&output_dir).join(&out_name);
                                    let original_size = data.len() as u64;
                                    use pqfile::encrypt;
                                    use pqfile::format::adaptive_chunk_size;
                                    let chunk_size = adaptive_chunk_size(original_size);
                                    let result = if pub_pems.len() == 1 {
                                        let mut r = std::io::Cursor::new(&data);
                                        let mut out = Vec::new();
                                        encrypt::encrypt_stream(
                                            &pub_pems[0],
                                            original_size,
                                            chunk_size,
                                            &mut r,
                                            &mut out,
                                        )
                                        .map(|_| out)
                                    } else {
                                        let pem_refs: Vec<&str> =
                                            pub_pems.iter().map(|s| s.as_str()).collect();
                                        let mut r = std::io::Cursor::new(&data);
                                        let mut out = Vec::new();
                                        encrypt::encrypt_stream_multi_anon(
                                            &pem_refs,
                                            original_size,
                                            &mut r,
                                            &mut out,
                                        )
                                        .map(|_| out)
                                    };
                                    let msg = match result {
                                        Ok(ct) => {
                                            if !confirm || !out_path.exists() {
                                                match std::fs::write(&out_path, &ct) {
                                                    Ok(()) => format!("✔ {out_name}"),
                                                    Err(e) => format!("✖ {name}: {e}"),
                                                }
                                            } else {
                                                format!("⚠ skipped {name} (output exists)")
                                            }
                                        }
                                        Err(e) => format!("✖ {name}: {e}"),
                                    };
                                    let _ = tx.send(msg);
                                    ctx.request_repaint();
                                }
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => break,
                }
            }
        });

        self.watch_handle = Some(WatchHandle {
            log_rx: rx,
            stop_flag,
        });
        self.watch_active = true;
        self.watch_log.clear();
    }

    pub(crate) fn stop_watch(&mut self) {
        if let Some(ref handle) = self.watch_handle {
            handle
                .stop_flag
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.watch_handle = None;
        self.watch_active = false;
    }
}

// ── Recent file persistence ────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn save_recent(storage: &mut dyn eframe::Storage, key: &str, list: &[String]) {
    storage.set_string(&format!("{key}.len"), list.len().to_string());
    for (i, s) in list.iter().enumerate() {
        storage.set_string(&format!("{key}.{i}"), s.clone());
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn load_recent(storage: &dyn eframe::Storage, key: &str) -> Vec<String> {
    let n: usize = storage
        .get_string(&format!("{key}.len"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
        .min(10);
    (0..n)
        .filter_map(|i| storage.get_string(&format!("{key}.{i}")))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Push a file path to the front of a recent list (dedup + cap at 5).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn push_recent(list: &mut Vec<String>, path: String) {
    list.retain(|p| p != &path);
    list.insert(0, path);
    list.truncate(5);
}

// ── URL hash tab routing (WASM) ────────────────────────────────────────────

/// Map a URL fragment (e.g. `"#encrypt"`) to a `Tab` variant for deep-linking.
#[cfg(target_arch = "wasm32")]
fn tab_from_hash(hash: &str) -> Option<Tab> {
    match hash.trim_start_matches('#').to_lowercase().as_str() {
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
