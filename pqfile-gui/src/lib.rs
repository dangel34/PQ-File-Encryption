use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui::{self, Color32, Margin, RichText, Rounding, Stroke, Vec2};
use pqfile::{decrypt, encrypt, format, keygen};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// ── Version ────────────────────────────────────────────────────────────────

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(not(target_arch = "wasm32"))]
const GITHUB_REPO: &str = "dangel34/PQ-File-Encryption";

// ── Catppuccin Mocha (dark) ────────────────────────────────────────────────

const D_BASE: Color32     = Color32::from_rgb(30,  30,  46);
const D_MANTLE: Color32   = Color32::from_rgb(24,  24,  37);
const D_SURFACE0: Color32 = Color32::from_rgb(49,  50,  68);
const D_SURFACE1: Color32 = Color32::from_rgb(69,  71,  90);
const D_OVERLAY: Color32  = Color32::from_rgb(108, 112, 134);
const D_SUBTEXT: Color32  = Color32::from_rgb(166, 173, 200);
const D_TEXT: Color32     = Color32::from_rgb(205, 214, 244);
const D_ACCENT: Color32   = Color32::from_rgb(137, 180, 250);
const D_GREEN: Color32    = Color32::from_rgb(166, 227, 161);
const D_RED: Color32      = Color32::from_rgb(243, 139, 168);

// ── Catppuccin Latte (light) ───────────────────────────────────────────────

const L_BASE: Color32     = Color32::from_rgb(239, 241, 245);
const L_MANTLE: Color32   = Color32::from_rgb(230, 233, 239);
const L_SURFACE0: Color32 = Color32::from_rgb(204, 208, 218);
const L_SURFACE1: Color32 = Color32::from_rgb(188, 192, 204);
const L_OVERLAY: Color32  = Color32::from_rgb(140, 143, 161);
const L_SUBTEXT: Color32  = Color32::from_rgb(108, 111, 133);
const L_TEXT: Color32     = Color32::from_rgb(76,  79,  105);
const L_ACCENT: Color32   = Color32::from_rgb(30,  102, 245);
const L_GREEN: Color32    = Color32::from_rgb(64,  160, 43);
const L_RED: Color32      = Color32::from_rgb(210, 15,  57);

// ── Per-theme colour helpers ───────────────────────────────────────────────

fn c_bg(d: bool)       -> Color32 { if d { D_BASE }     else { L_BASE } }
fn c_chrome(d: bool)   -> Color32 { if d { D_MANTLE }   else { L_MANTLE } }
fn c_card(d: bool)     -> Color32 { if d { D_MANTLE }   else { L_MANTLE } }
fn c_surface0(d: bool) -> Color32 { if d { D_SURFACE0 } else { L_SURFACE0 } }
fn c_surface1(d: bool) -> Color32 { if d { D_SURFACE1 } else { L_SURFACE1 } }
fn c_overlay(d: bool)  -> Color32 { if d { D_OVERLAY }  else { L_OVERLAY } }
fn c_subtext(d: bool)  -> Color32 { if d { D_SUBTEXT }  else { L_SUBTEXT } }
fn c_text(d: bool)     -> Color32 { if d { D_TEXT }     else { L_TEXT } }
fn c_accent(d: bool)   -> Color32 { if d { D_ACCENT }   else { L_ACCENT } }
fn c_green(d: bool)    -> Color32 { if d { D_GREEN }    else { L_GREEN } }
fn c_red(d: bool)      -> Color32 { if d { D_RED }      else { L_RED } }

// ── WASM entry ────────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    use wasm_bindgen::JsCast as _;
    let canvas = web_sys::window()
        .unwrap()
        .document()
        .unwrap()
        .get_element_by_id("pqfile_canvas")
        .unwrap()
        .dyn_into::<web_sys::HtmlCanvasElement>()
        .unwrap();
    wasm_bindgen_futures::spawn_local(async move {
        eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(|cc| Ok(Box::new(PqfileApp::new(cc)))),
            )
            .await
            .expect("failed to start eframe");
    });
    Ok(())
}

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(PartialEq, Default, Clone, Copy)]
enum Tab {
    #[default]
    Keygen,
    Encrypt,
    Decrypt,
    Inspect,
    Settings,
}

#[derive(Default)]
enum OpStatus {
    #[default]
    None,
    Ok(String),
    Err(String),
}

#[derive(Default)]
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
enum UpdateStatus {
    #[default]
    Idle,
    Checking,
    UpToDate,
    Available(String),
    Downloading,
    RestartRequired,
    InstallFailed(String),
    Failed(String),
}

struct PickedFile {
    name: String,
    data: Vec<u8>,
    path: Option<PathBuf>,
}

type Pending = Arc<Mutex<Option<PickedFile>>>;

struct FileInput {
    name: String,
    data: Option<Vec<u8>>,
    path: Option<PathBuf>,
    pending: Pending,
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
    fn poll(&mut self) {
        if let Ok(mut g) = self.pending.try_lock() {
            if let Some(f) = g.take() {
                self.name = f.name;
                self.data = Some(f.data);
                self.path = f.path;
            }
        }
    }
    fn loaded(&self) -> bool { self.data.is_some() }
    fn as_str(&self) -> Option<&str> {
        self.data.as_deref().and_then(|d| std::str::from_utf8(d).ok())
    }
    fn clear(&mut self) {
        self.name.clear();
        self.data = None;
        self.path = None;
    }
}

// ── Settings ───────────────────────────────────────────────────────────────

struct Settings {
    dark_mode: bool,
    auto_clear: bool,
    #[cfg(not(target_arch = "wasm32"))]
    confirm_overwrite: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dark_mode: true,
            auto_clear: false,
            #[cfg(not(target_arch = "wasm32"))]
            confirm_overwrite: false,
        }
    }
}

// ── App ────────────────────────────────────────────────────────────────────

pub struct PqfileApp {
    tab: Tab,
    show_about: bool,
    settings: Settings,

    #[cfg(not(target_arch = "wasm32"))]
    keygen_dir: String,
    keygen_status: OpStatus,
    keygen_fingerprint: String,

    encrypt_pubkey: FileInput,
    encrypt_plain: FileInput,
    encrypt_status: OpStatus,

    decrypt_privkey: FileInput,
    decrypt_pqf: FileInput,
    decrypt_status: OpStatus,

    inspect_pqf: FileInput,
    inspect_result: String,
    inspect_status: OpStatus,

    update_status: UpdateStatus,
    #[cfg(not(target_arch = "wasm32"))]
    update_result: Arc<Mutex<Option<Result<String, String>>>>,
    #[cfg(not(target_arch = "wasm32"))]
    install_result: Arc<Mutex<Option<Result<(), String>>>>,
}

impl Default for PqfileApp {
    fn default() -> Self {
        Self {
            tab: Tab::Keygen,
            show_about: false,
            settings: Settings::default(),
            #[cfg(not(target_arch = "wasm32"))]
            keygen_dir: String::new(),
            keygen_status: OpStatus::None,
            keygen_fingerprint: String::new(),
            encrypt_pubkey: FileInput::default(),
            encrypt_plain: FileInput::default(),
            encrypt_status: OpStatus::None,
            decrypt_privkey: FileInput::default(),
            decrypt_pqf: FileInput::default(),
            decrypt_status: OpStatus::None,
            inspect_pqf: FileInput::default(),
            inspect_result: String::new(),
            inspect_status: OpStatus::None,
            update_status: UpdateStatus::Idle,
            #[cfg(not(target_arch = "wasm32"))]
            update_result: Arc::new(Mutex::new(None)),
            #[cfg(not(target_arch = "wasm32"))]
            install_result: Arc::new(Mutex::new(None)),
        }
    }
}

impl PqfileApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx, true);
        Self::default()
    }
}

// ── Theme ──────────────────────────────────────────────────────────────────

fn apply_theme(ctx: &egui::Context, dark: bool) {
    let mut v = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };

    let (base, mantle, surf0, surf1, overlay, subtext, text, accent) = if dark {
        (D_BASE, D_MANTLE, D_SURFACE0, D_SURFACE1, D_OVERLAY, D_SUBTEXT, D_TEXT, D_ACCENT)
    } else {
        (L_BASE, L_MANTLE, L_SURFACE0, L_SURFACE1, L_OVERLAY, L_SUBTEXT, L_TEXT, L_ACCENT)
    };

    let shadow_alpha = if dark { 80u8 } else { 24u8 };

    v.panel_fill = mantle;
    v.window_fill = base;
    v.override_text_color = Some(text);

    v.widgets.noninteractive.bg_fill = surf0;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, subtext);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, surf1);

    v.widgets.inactive.bg_fill = surf0;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, text);
    v.widgets.inactive.bg_stroke = Stroke::NONE;

    v.widgets.hovered.bg_fill = surf1;
    v.widgets.hovered.fg_stroke = Stroke::new(1.5, accent);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, accent);

    v.widgets.active.bg_fill = accent;
    v.widgets.active.fg_stroke = Stroke::new(1.5, mantle);

    v.selection.bg_fill = Color32::from_rgba_premultiplied(
        accent.r(), accent.g(), accent.b(), 55,
    );
    v.selection.stroke = Stroke::new(1.0, accent);

    v.window_rounding = Rounding::same(8.0);
    v.window_stroke = Stroke::new(1.0, surf1);
    v.popup_shadow = egui::Shadow {
        offset: Vec2::new(0.0, 4.0),
        blur: 16.0,
        spread: 0.0,
        color: Color32::from_black_alpha(shadow_alpha),
    };

    let r = Rounding::same(6.0);
    v.widgets.noninteractive.rounding = r;
    v.widgets.inactive.rounding = r;
    v.widgets.hovered.rounding = r;
    v.widgets.active.rounding = r;

    let _ = overlay;

    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);
    style.spacing.window_margin = Margin::same(16.0);
    ctx.set_style(style);
}

// ── Frame ──────────────────────────────────────────────────────────────────

impl eframe::App for PqfileApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.poll_files() {
            ctx.request_repaint();
        }
        self.handle_dropped_files(ctx);

        let dark = self.settings.dark_mode;
        let chrome = c_chrome(dark);
        let bg     = c_bg(dark);

        // ── Title bar ──────────────────────────────────────────────────────
        egui::TopBottomPanel::top("top_bar")
            .exact_height(46.0)
            .frame(egui::Frame::none().fill(chrome).inner_margin(Margin::symmetric(14.0, 0.0)))
            .show(ctx, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new("🔐  pqfile")
                            .size(16.0)
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
        egui::TopBottomPanel::bottom("footer")
            .exact_height(26.0)
            .frame(egui::Frame::none().fill(chrome).inner_margin(Margin::symmetric(14.0, 0.0)))
            .show(ctx, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("v{APP_VERSION}")).size(11.0).color(c_overlay(dark)));
                    // Update badge
                    match &self.update_status {
                        UpdateStatus::Available(ver) => {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new(format!("↑ v{ver} available"))
                                    .size(11.0)
                                    .color(c_accent(dark)),
                            );
                        }
                        UpdateStatus::RestartRequired => {
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new("↻ restart to apply update")
                                    .size(11.0)
                                    .color(c_green(dark)),
                            );
                        }
                        _ => {}
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new("ML-KEM-768 · ChaCha20-Poly1305")
                                .size(11.0)
                                .color(c_overlay(dark)),
                        );
                    });
                });
            });

        // ── About modal ────────────────────────────────────────────────────
        if self.show_about {
            self.show_about_window(ctx, dark);
        }

        // ── Central panel ──────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(bg))
            .show(ctx, |ui| {
                // Drop zone hint overlay when files are being hovered
                let hovered = ctx.input(|i| !i.raw.hovered_files.is_empty());
                if hovered {
                    let rect = ui.ctx().screen_rect();
                    ui.painter().rect_filled(
                        rect,
                        Rounding::same(0.0),
                        Color32::from_rgba_premultiplied(
                            c_accent(dark).r(),
                            c_accent(dark).g(),
                            c_accent(dark).b(),
                            30,
                        ),
                    );
                    ui.painter().text(
                        rect.center(),
                        egui::Align2::CENTER_CENTER,
                        "Drop files here",
                        egui::FontId::proportional(22.0),
                        c_accent(dark),
                    );
                }

                // Tab strip
                egui::Frame::none()
                    .fill(chrome)
                    .inner_margin(Margin::symmetric(14.0, 7.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            tab_btn(ui, &mut self.tab, Tab::Keygen,   "🔑  Keygen",   dark);
                            tab_btn(ui, &mut self.tab, Tab::Encrypt,  "🔒  Encrypt",  dark);
                            tab_btn(ui, &mut self.tab, Tab::Decrypt,  "🔓  Decrypt",  dark);
                            tab_btn(ui, &mut self.tab, Tab::Inspect,  "🔍  Inspect",  dark);
                            tab_btn(ui, &mut self.tab, Tab::Settings, "⚙  Settings", dark);
                        });
                    });

                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        egui::Frame::none()
                            .inner_margin(Margin::symmetric(18.0, 14.0))
                            .show(ui, |ui| match self.tab {
                                Tab::Keygen   => self.show_keygen(ui, dark),
                                Tab::Encrypt  => self.show_encrypt(ui, dark),
                                Tab::Decrypt  => self.show_decrypt(ui, dark),
                                Tab::Inspect  => self.show_inspect(ui, dark),
                                Tab::Settings => self.show_settings(ui, ctx, dark),
                            });
                    });
            });
    }
}

// ── Polling ────────────────────────────────────────────────────────────────

impl PqfileApp {
    fn poll_files(&mut self) -> bool {
        self.encrypt_pubkey.poll();
        self.encrypt_plain.poll();
        self.decrypt_privkey.poll();
        self.decrypt_pqf.poll();
        self.inspect_pqf.poll();

        let file_pending = [
            &self.encrypt_pubkey,
            &self.encrypt_plain,
            &self.decrypt_privkey,
            &self.decrypt_pqf,
            &self.inspect_pqf,
        ]
        .iter()
        .any(|f| f.pending.try_lock().map(|g| g.is_some()).unwrap_or(false));

        // Drain update-check result on native.
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(mut g) = self.update_result.try_lock() {
                if let Some(result) = g.take() {
                    self.update_status = match result {
                        Ok(latest) => {
                            if latest == APP_VERSION {
                                UpdateStatus::UpToDate
                            } else {
                                UpdateStatus::Available(latest)
                            }
                        }
                        Err(e) => UpdateStatus::Failed(e),
                    };
                    return true;
                }
            }
        }

        // Drain install result on native.
        #[cfg(not(target_arch = "wasm32"))]
        {
            if let Ok(mut g) = self.install_result.try_lock() {
                if let Some(result) = g.take() {
                    self.update_status = match result {
                        Ok(()) => UpdateStatus::RestartRequired,
                        Err(e) => UpdateStatus::InstallFailed(e),
                    };
                    return true;
                }
            }
        }

        file_pending
    }
}

// ── Drag-and-drop ──────────────────────────────────────────────────────────

impl PqfileApp {
    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        for file in dropped {
            let data: Option<Vec<u8>> = if let Some(bytes) = file.bytes.as_ref() {
                Some(bytes.to_vec())
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    file.path.as_ref().and_then(|p| std::fs::read(p).ok())
                }
                #[cfg(target_arch = "wasm32")]
                { None }
            };

            let data = match data {
                Some(d) => d,
                None => continue,
            };

            let name = if !file.name.is_empty() {
                file.name.clone()
            } else {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    file.path
                        .as_ref()
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                }
                #[cfg(target_arch = "wasm32")]
                { String::new() }
            };

            let path = file.path.clone();
            let is_pem = name.ends_with(".pem");
            let is_pqf = name.ends_with(".pqf");

            let loaded = FileInput {
                name,
                data: Some(data),
                path,
                pending: Arc::new(Mutex::new(None)),
            };

            match self.tab {
                Tab::Encrypt => {
                    if is_pem {
                        self.encrypt_pubkey = loaded;
                    } else {
                        self.encrypt_plain = loaded;
                    }
                }
                Tab::Decrypt => {
                    if is_pem {
                        self.decrypt_privkey = loaded;
                    } else if is_pqf {
                        self.decrypt_pqf = loaded;
                    }
                }
                Tab::Inspect if is_pqf => {
                    self.inspect_pqf = loaded;
                }
                _ => {}
            }
        }
    }
}

// ── About window ───────────────────────────────────────────────────────────

impl PqfileApp {
    fn show_about_window(&mut self, ctx: &egui::Context, dark: bool) {
        let mut close = false;

        egui::Window::new(RichText::new("About pqfile").size(14.0).strong().color(c_text(dark)))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(380.0)
            .max_height(440.0)
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(c_bg(dark))
                    .stroke(Stroke::new(1.0, c_surface1(dark)))
                    .rounding(Rounding::same(10.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.add_space(6.0);
                            ui.label(RichText::new("🔐").size(40.0));
                            ui.add_space(4.0);
                            ui.label(RichText::new("pqfile").size(24.0).strong().color(c_accent(dark)));
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
                                 Encrypt any file with a public key — only the matching \
                                 private key can decrypt it.",
                            )
                            .size(13.0)
                            .color(c_subtext(dark)),
                        );

                        ui.add_space(14.0);
                        section_label(ui, "CRYPTOGRAPHIC ALGORITHMS", dark);
                        card(ui, c_card(dark), c_surface1(dark), |ui| {
                            kv_row(ui, "Key encapsulation", "ML-KEM-768  (NIST FIPS 203)", dark);
                            kv_row(ui, "Symmetric cipher",  "ChaCha20-Poly1305  (RFC 8439)", dark);
                            kv_row(ui, "AEAD mode",         "STREAM  (64 KB chunks)", dark);
                            kv_row(ui, "Randomness",        "OS CSPRNG  (OsRng)", dark);
                            kv_row(ui, "File format",       ".pqf  (v0x03, 1111-byte header)", dark);
                        });

                        ui.add_space(10.0);
                        section_label(ui, "SECURITY PROPERTIES", dark);
                        card(ui, c_card(dark), c_surface1(dark), |ui| {
                            bullet(ui, "All operations run locally — no data is uploaded", dark);
                            bullet(ui, "Keys and shared secrets zeroized after use", dark);
                            bullet(ui, "Header + payload fully authenticated (STREAM AEAD)", dark);
                            bullet(ui, "Fresh nonce and KEM encapsulation per file", dark);
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
}

// ── Keygen tab ─────────────────────────────────────────────────────────────

impl PqfileApp {
    fn show_keygen(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Generate Key Pair", dark);
        ui.label(
            RichText::new("Creates a new ML-KEM-768 public/private key pair.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        {
            section_label(ui, "OUTPUT DIRECTORY", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.keygen_dir)
                            .hint_text("Choose a folder…")
                            .desired_width(ui.available_width() - 76.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Browse…").color(c_text(dark)))
                                .fill(c_surface0(dark)),
                        )
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.keygen_dir = p.to_string_lossy().into_owned();
                        }
                    }
                });
            });
            ui.add_space(14.0);
        }

        #[cfg(target_arch = "wasm32")]
        {
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.label(
                    RichText::new(
                        "pubkey.pem and privkey.pem will be downloaded to your downloads folder.",
                    )
                    .size(13.0)
                    .color(c_subtext(dark)),
                );
            });
            ui.add_space(14.0);
        }

        if ui
            .add(
                egui::Button::new(
                    RichText::new("⚡  Generate Key Pair")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(170.0, 32.0)),
            )
            .clicked()
        {
            match keygen::keygen_bytes() {
                Ok((pub_pem, priv_pem)) => {
                    let fp = keygen::pubkey_fingerprint(&pub_pem)
                        .unwrap_or_else(|_| "unknown".to_owned());
                    self.keygen_fingerprint = fp.clone();

                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        let dir = std::path::Path::new(&self.keygen_dir);
                        let r1 = std::fs::write(dir.join("pubkey.pem"), pub_pem.as_bytes());
                        let r2 = std::fs::write(dir.join("privkey.pem"), priv_pem.as_bytes());
                        self.keygen_status = match (r1, r2) {
                            (Ok(()), Ok(())) => OpStatus::Ok(format!(
                                "Keys saved to {}",
                                dir.display()
                            )),
                            (Err(e), _) | (_, Err(e)) => {
                                self.keygen_fingerprint.clear();
                                OpStatus::Err(e.to_string())
                            }
                        };
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        download_bytes("pubkey.pem", pub_pem.as_bytes());
                        download_bytes("privkey.pem", priv_pem.as_bytes());
                        self.keygen_status =
                            OpStatus::Ok("pubkey.pem and privkey.pem downloaded.".to_owned());
                    }
                }
                Err(e) => {
                    self.keygen_fingerprint.clear();
                    self.keygen_status = OpStatus::Err(e.to_string());
                }
            }
        }

        show_status(ui, &self.keygen_status, dark);

        if !self.keygen_fingerprint.is_empty() {
            ui.add_space(6.0);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Fingerprint")
                            .size(12.5)
                            .color(c_subtext(dark)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(&self.keygen_fingerprint)
                                .monospace()
                                .size(12.5)
                                .color(c_text(dark)),
                        );
                    });
                });
            });
        }
    }
}

// ── Encrypt tab ────────────────────────────────────────────────────────────

impl PqfileApp {
    fn show_encrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Encrypt File", dark);
        ui.label(
            RichText::new("Encrypt a file using a recipient's public key. You can also drag and drop files onto this tab.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        section_label(ui, "INPUTS", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(ui, "Public key (.pem)", &mut self.encrypt_pubkey, "PEM", &["pem"], dark);
            ui.add_space(2.0);
            file_row(ui, "File to encrypt", &mut self.encrypt_plain, "", &[], dark);
        });
        ui.add_space(14.0);

        let ready = self.encrypt_pubkey.loaded() && self.encrypt_plain.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔒  Encrypt")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(120.0, 32.0)),
            )
            .clicked()
        {
            let pub_pem = self.encrypt_pubkey.as_str().map(str::to_owned);
            let plain = self.encrypt_plain.data.clone();
            let plain_name = self.encrypt_plain.name.clone();
            let plain_path = self.encrypt_plain.path.clone();

            match (pub_pem, plain) {
                (Some(pub_pem), Some(plain)) => {
                    match encrypt::encrypt_bytes(&pub_pem, &plain) {
                        Ok(pqf) => {
                            let out_name = format!("{plain_name}.pqf");
                            let out_path = plain_path.map(|p| {
                                let mut s = p.as_os_str().to_owned();
                                s.push(".pqf");
                                PathBuf::from(s)
                            });
                            #[cfg(not(target_arch = "wasm32"))]
                            let confirm = self.settings.confirm_overwrite;
                            #[cfg(target_arch = "wasm32")]
                            let confirm = false;
                            self.encrypt_status = save_result(&out_name, &pqf, out_path, confirm);
                            if self.settings.auto_clear
                                && matches!(self.encrypt_status, OpStatus::Ok(_))
                            {
                                self.encrypt_pubkey.clear();
                                self.encrypt_plain.clear();
                            }
                        }
                        Err(e) => self.encrypt_status = OpStatus::Err(e.to_string()),
                    }
                }
                _ => {
                    self.encrypt_status = OpStatus::Err("Load both files first.".to_owned());
                }
            }
        }

        if !ready {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Load a public key and a file to continue (or drag and drop).")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }

        show_status(ui, &self.encrypt_status, dark);
    }
}

// ── Decrypt tab ────────────────────────────────────────────────────────────

impl PqfileApp {
    fn show_decrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Decrypt File", dark);
        ui.label(
            RichText::new("Decrypt a .pqf file using your private key. You can also drag and drop files onto this tab.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        section_label(ui, "INPUTS", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(ui, "Private key (.pem)", &mut self.decrypt_privkey, "PEM", &["pem"], dark);
            ui.add_space(2.0);
            file_row(ui, "Encrypted file (.pqf)", &mut self.decrypt_pqf, "PQF", &["pqf"], dark);
        });
        ui.add_space(14.0);

        let ready = self.decrypt_privkey.loaded() && self.decrypt_pqf.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔓  Decrypt")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(120.0, 32.0)),
            )
            .clicked()
        {
            let priv_pem = self.decrypt_privkey.as_str().map(str::to_owned);
            let pqf = self.decrypt_pqf.data.clone();
            let pqf_name = self.decrypt_pqf.name.clone();
            let pqf_path = self.decrypt_pqf.path.clone();

            match (priv_pem, pqf) {
                (Some(priv_pem), Some(pqf)) => {
                    match decrypt::decrypt_bytes(&priv_pem, &pqf) {
                        Ok(plain) => {
                            let out_name = PathBuf::from(&pqf_name)
                                .file_stem()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| pqf_name.clone());
                            let out_path = pqf_path.map(|p| p.with_extension(""));
                            #[cfg(not(target_arch = "wasm32"))]
                            let confirm = self.settings.confirm_overwrite;
                            #[cfg(target_arch = "wasm32")]
                            let confirm = false;
                            self.decrypt_status =
                                save_result(&out_name, &plain, out_path, confirm);
                            if self.settings.auto_clear
                                && matches!(self.decrypt_status, OpStatus::Ok(_))
                            {
                                self.decrypt_privkey.clear();
                                self.decrypt_pqf.clear();
                            }
                        }
                        Err(e) => self.decrypt_status = OpStatus::Err(e.to_string()),
                    }
                }
                _ => {
                    self.decrypt_status = OpStatus::Err("Load both files first.".to_owned());
                }
            }
        }

        if !ready {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Load a private key and a .pqf file to continue (or drag and drop).")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }

        show_status(ui, &self.decrypt_status, dark);
    }
}

// ── Inspect tab ────────────────────────────────────────────────────────────

impl PqfileApp {
    fn show_inspect(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Inspect .pqf File", dark);
        ui.label(
            RichText::new("View the header metadata of an encrypted file without decrypting it.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        section_label(ui, "FILE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(ui, "Encrypted file (.pqf)", &mut self.inspect_pqf, "PQF", &["pqf"], dark);
        });
        ui.add_space(14.0);

        let ready = self.inspect_pqf.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔍  Inspect")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(120.0, 32.0)),
            )
            .clicked()
        {
            if let Some(data) = &self.inspect_pqf.data {
                match format::PqfHeader::read(&mut Cursor::new(data.as_slice())) {
                    Ok(h) => {
                        let nonce: String =
                            h.nonce.iter().map(|b| format!("{b:02x}")).collect();
                        self.inspect_result = format!(
                            "Magic            PQFL\n\
                             Version          {:#04x}\n\
                             KEM variant      ML-KEM-{}\n\
                             Nonce            {}\n\
                             Original size    {} bytes",
                            format::VERSION,
                            format::KEM_VARIANT,
                            nonce,
                            h.original_size,
                        );
                        self.inspect_status = OpStatus::None;
                    }
                    Err(e) => {
                        self.inspect_result.clear();
                        self.inspect_status = OpStatus::Err(e.to_string());
                    }
                }
            } else {
                self.inspect_status = OpStatus::Err("Load a file first.".to_owned());
            }
        }

        if !self.inspect_result.is_empty() {
            ui.add_space(10.0);
            section_label(ui, "HEADER", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.label(
                    RichText::new(&self.inspect_result)
                        .monospace()
                        .size(13.0)
                        .color(c_text(dark)),
                );
            });
        }

        show_status(ui, &self.inspect_status, dark);
    }
}

// ── Settings tab ───────────────────────────────────────────────────────────

impl PqfileApp {
    fn show_settings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, dark: bool) {
        tab_heading(ui, "Settings", dark);
        ui.label(
            RichText::new("Configure appearance and behavior.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        // Appearance
        section_label(ui, "APPEARANCE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            let prev = self.settings.dark_mode;
            let row_w = ui.available_width();
            ui.allocate_ui(egui::vec2(row_w, 26.0), |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(RichText::new("Theme").size(13.0).color(c_text(dark)));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let label = if self.settings.dark_mode { "🌙  Dark" } else { "☀  Light" };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(label).size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .clicked()
                        {
                            self.settings.dark_mode = !self.settings.dark_mode;
                        }
                    });
                });
            });
            if self.settings.dark_mode != prev {
                apply_theme(ctx, self.settings.dark_mode);
            }
        });

        ui.add_space(10.0);

        // Behavior
        section_label(ui, "BEHAVIOR", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            setting_toggle(
                ui,
                &mut self.settings.auto_clear,
                "Clear inputs after success",
                "Removes loaded files from the form after a successful operation.",
                dark,
            );
            #[cfg(not(target_arch = "wasm32"))]
            {
                ui.add_space(8.0);
                setting_toggle(
                    ui,
                    &mut self.settings.confirm_overwrite,
                    "Protect existing files",
                    "Block output if a file with the same name already exists.",
                    dark,
                );
            }
        });

        ui.add_space(10.0);

        // Updates
        section_label(ui, "UPDATES", dark);
        let mut install_ver: Option<String> = None;
        let mut restart_now = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            let row_w = ui.available_width();
            ui.allocate_ui(egui::vec2(row_w, 26.0), |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("Current version: {APP_VERSION}"))
                            .size(13.0)
                            .color(c_text(dark)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            let busy = matches!(
                                self.update_status,
                                UpdateStatus::Checking | UpdateStatus::Downloading
                            );
                            if ui
                                .add_enabled(
                                    !busy,
                                    egui::Button::new(
                                        RichText::new(if busy { "Please wait…" } else { "Check for Updates" })
                                            .size(13.0)
                                            .color(c_text(dark)),
                                    )
                                    .fill(c_surface0(dark)),
                                )
                                .clicked()
                            {
                                self.update_status = UpdateStatus::Checking;
                                trigger_update_check(Arc::clone(&self.update_result));
                            }
                        }
                        #[cfg(target_arch = "wasm32")]
                        {
                            ui.label(
                                RichText::new("Web — always current")
                                    .size(12.0)
                                    .color(c_subtext(dark)),
                            );
                        }
                    });
                });
            });

            match &self.update_status {
                UpdateStatus::Idle => {}
                UpdateStatus::Checking => {
                    ui.add_space(4.0);
                    ui.label(RichText::new("Checking for updates…").size(12.0).color(c_subtext(dark)));
                }
                UpdateStatus::UpToDate => {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("You are on the latest version ({APP_VERSION})."))
                            .size(12.0)
                            .color(c_green(dark)),
                    );
                }
                UpdateStatus::Available(ver) => {
                    let ver = ver.clone();
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("Update available: v{ver}"))
                                .size(12.0)
                                .color(c_accent(dark)),
                        );
                        #[cfg(not(target_arch = "wasm32"))]
                        {
                            ui.add_space(8.0);
                            if ui
                                .button(
                                    RichText::new("Download & Install")
                                        .size(12.0)
                                        .color(c_text(dark)),
                                )
                                .clicked()
                            {
                                install_ver = Some(ver);
                            }
                        }
                    });
                }
                UpdateStatus::Downloading => {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Downloading update…")
                            .size(12.0)
                            .color(c_subtext(dark)),
                    );
                }
                UpdateStatus::RestartRequired => {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Update installed. Restart to apply.")
                                .size(12.0)
                                .color(c_green(dark)),
                        );
                        ui.add_space(8.0);
                        if ui
                            .button(RichText::new("Restart Now").size(12.0).color(c_text(dark)))
                            .clicked()
                        {
                            restart_now = true;
                        }
                    });
                }
                UpdateStatus::InstallFailed(e) => {
                    let e = e.clone();
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(format!("Update failed: {e}"))
                            .size(12.0)
                            .color(c_red(dark)),
                    );
                }
                UpdateStatus::Failed(e) => {
                    let e = e.clone();
                    ui.add_space(4.0);
                    ui.label(RichText::new(e).size(12.0).color(c_red(dark)));
                }
            }
        });

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(ver) = install_ver {
            self.update_status = UpdateStatus::Downloading;
            trigger_update_install(ver, Arc::clone(&self.install_result));
        }

        if restart_now {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let exe = std::env::current_exe().unwrap_or_default();
                let _ = std::process::Command::new(exe).spawn();
            }
            std::process::exit(0);
        }

        ui.add_space(10.0);

        // Security note
        section_label(ui, "SECURITY", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new(
                    "pqfile runs entirely on your device. No keys, files, or metadata \
                     are transmitted over the network. Private keys are zeroized from \
                     memory immediately after use.",
                )
                .size(12.0)
                .color(c_subtext(dark)),
            );
        });

        ui.add_space(10.0);

        // Danger zone
        section_label(ui, "DANGER ZONE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new("Clear all loaded files and reset status messages.")
                    .size(12.0)
                    .color(c_subtext(dark)),
            );
            ui.add_space(6.0);
            if ui
                .add(
                    egui::Button::new(
                        RichText::new("Clear All Inputs").size(13.0).color(c_red(dark)),
                    )
                    .fill(c_surface0(dark))
                    .stroke(Stroke::new(1.0, c_red(dark))),
                )
                .clicked()
            {
                self.encrypt_pubkey.clear();
                self.encrypt_plain.clear();
                self.encrypt_status = OpStatus::None;
                self.decrypt_privkey.clear();
                self.decrypt_pqf.clear();
                self.decrypt_status = OpStatus::None;
                self.inspect_pqf.clear();
                self.inspect_result.clear();
                self.inspect_status = OpStatus::None;
                self.keygen_status = OpStatus::None;
                self.keygen_fingerprint.clear();
            }
        });
    }
}

// ── Update check (native only) ─────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn trigger_update_check(result: Arc<Mutex<Option<Result<String, String>>>>) {
    std::thread::spawn(move || {
        let outcome = fetch_latest_version();
        *result.lock().unwrap() = Some(outcome);
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn fetch_latest_version() -> Result<String, String> {
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let response = ureq::get(&url)
        .set("User-Agent", &format!("pqfile/{APP_VERSION}"))
        .set("Accept", "application/vnd.github.v3+json")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(404, _) => "No releases published yet.".to_owned(),
            ureq::Error::Status(code, _) => format!("Server returned {code}."),
            e => format!("Network error: {e}"),
        })?;
    let body = response.into_string().map_err(|e| e.to_string())?;
    parse_tag_name(&body).ok_or_else(|| "Could not parse release info.".to_owned())
}

/// Extracts the version from `"tag_name": "vX.Y.Z"` (with or without space after colon).
#[cfg(not(target_arch = "wasm32"))]
fn parse_tag_name(json: &str) -> Option<String> {
    let key_pos = json.find("\"tag_name\"")?;
    let after_key = &json[key_pos + 10..]; // skip past "tag_name"
    let colon = after_key.find(':')?;
    let after_colon = &after_key[colon + 1..];
    let open_quote = after_colon.find('"')?;
    let value = &after_colon[open_quote + 1..];
    let close_quote = value.find('"')?;
    Some(value[..close_quote].trim_start_matches('v').to_owned())
}

// ── Self-update (native only) ──────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
fn trigger_update_install(version: String, result: Arc<Mutex<Option<Result<(), String>>>>) {
    std::thread::spawn(move || {
        let outcome = do_install(&version);
        *result.lock().unwrap() = Some(outcome);
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn do_install(version: &str) -> Result<(), String> {
    use std::io::Read;

    let asset = platform_asset_name()
        .ok_or_else(|| "No prebuilt release for this platform/architecture.".to_owned())?;

    let url = format!(
        "https://github.com/{GITHUB_REPO}/releases/download/v{version}/{asset}"
    );

    let response = ureq::get(&url)
        .set("User-Agent", &format!("pqfile/{APP_VERSION}"))
        .call()
        .map_err(|e| e.to_string())?;

    let mut bytes = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;

    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let temp_path = current_exe.with_extension("update_tmp");

    std::fs::write(&temp_path, &bytes).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
    }

    replace_exe(&current_exe, &temp_path)
}

#[cfg(target_os = "windows")]
fn replace_exe(current: &std::path::Path, new: &std::path::Path) -> Result<(), String> {
    // Windows locks running executables, so rename the current one out of the
    // way first, then move the new one into position.
    let old = current.with_extension("old");
    std::fs::rename(current, &old).map_err(|e| e.to_string())?;
    std::fs::rename(new, current).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "windows"))]
fn replace_exe(current: &std::path::Path, new: &std::path::Path) -> Result<(), String> {
    std::fs::rename(new, current).map_err(|e| e.to_string())
}

/// Maps the current platform to the GitHub release asset filename.
/// Returns None for unsupported platforms (ARM Linux, 32-bit, etc.).
#[cfg(not(target_arch = "wasm32"))]
fn platform_asset_name() -> Option<&'static str> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return Some("pqfile-desktop-linux-x86_64");

    #[cfg(all(target_os = "macos", any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Some("pqfile-desktop-macos-x86_64"); // aarch64 runs via Rosetta 2

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return Some("pqfile-desktop-windows-x86_64.exe");

    #[allow(unreachable_code)]
    None
}

// ── UI helpers ─────────────────────────────────────────────────────────────

fn tab_btn(ui: &mut egui::Ui, current: &mut Tab, target: Tab, label: &str, dark: bool) {
    let active = *current == target;
    let text_color = if active { c_accent(dark) } else { c_subtext(dark) };
    let fill = if active { c_surface1(dark) } else { Color32::TRANSPARENT };
    let stroke = if active { Stroke::new(1.0, c_accent(dark)) } else { Stroke::NONE };
    if ui
        .add(
            egui::Button::new(RichText::new(label).size(13.0).color(text_color))
                .fill(fill)
                .stroke(stroke),
        )
        .clicked()
    {
        *current = target;
    }
}

fn tab_heading(ui: &mut egui::Ui, text: &str, dark: bool) {
    ui.label(RichText::new(text).size(18.0).strong().color(c_text(dark)));
    ui.add_space(4.0);
}

fn section_label(ui: &mut egui::Ui, text: &str, dark: bool) {
    ui.label(RichText::new(text).size(10.5).color(c_overlay(dark)).strong());
    ui.add_space(3.0);
}

fn card(
    ui: &mut egui::Ui,
    fill: Color32,
    border: Color32,
    content: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::none()
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(12.0))
        .outer_margin(Margin::ZERO)
        .show(ui, content);
}

fn setting_toggle(
    ui: &mut egui::Ui,
    val: &mut bool,
    label: &str,
    desc: &str,
    dark: bool,
) {
    let row_w = ui.available_width();
    ui.allocate_ui(egui::vec2(row_w, 40.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(13.0).color(c_text(dark)));
                ui.label(RichText::new(desc).size(11.5).color(c_subtext(dark)));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                toggle_switch(ui, val, dark);
            });
        });
    });
}

fn toggle_switch(ui: &mut egui::Ui, on: &mut bool, dark: bool) -> egui::Response {
    let size = Vec2::new(36.0, 20.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    if ui.is_rect_visible(rect) {
        let t = ui.ctx().animate_bool(response.id, *on);
        let off_col = c_surface1(dark);
        let on_col  = c_accent(dark);
        let track = Color32::from_rgba_premultiplied(
            lerp_u8(off_col.r(), on_col.r(), t),
            lerp_u8(off_col.g(), on_col.g(), t),
            lerp_u8(off_col.b(), on_col.b(), t),
            255,
        );
        let r = rect.height() / 2.0;
        ui.painter().rect_filled(rect, Rounding::same(r), track);
        let knob_x = rect.left() + r + t * (rect.width() - 2.0 * r);
        ui.painter().circle_filled(
            egui::pos2(knob_x, rect.center().y),
            r - 2.0,
            Color32::WHITE,
        );
    }
    response
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t) as u8
}

fn kv_row(ui: &mut egui::Ui, key: &str, value: &str, dark: bool) {
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, 20.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.label(RichText::new(key).size(12.5).color(c_subtext(dark)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(value).size(12.5).color(c_text(dark)).monospace());
            });
        });
    });
}

fn bullet(ui: &mut egui::Ui, text: &str, dark: bool) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("·").size(13.0).color(c_accent(dark)));
        ui.label(RichText::new(text).size(12.5).color(c_subtext(dark)));
    });
}

fn file_row(
    ui: &mut egui::Ui,
    label: &str,
    slot: &mut FileInput,
    filter_name: &'static str,
    filter_exts: &'static [&'static str],
    dark: bool,
) {
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, 26.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.label(RichText::new(label).size(13.0).color(c_subtext(dark)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Button::new(RichText::new("Browse…").size(13.0).color(c_text(dark)))
                            .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    pick_file(Arc::clone(&slot.pending), filter_name, filter_exts);
                }
                let display = if slot.loaded() {
                    RichText::new(&slot.name).size(13.0).color(c_text(dark))
                } else {
                    RichText::new("No file chosen").size(13.0).color(c_overlay(dark))
                };
                ui.label(display);
            });
        });
    });
}

fn pick_file(pending: Pending, filter_name: &'static str, filter_exts: &'static [&'static str]) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        let mut d = rfd::FileDialog::new();
        if !filter_exts.is_empty() {
            d = d.add_filter(filter_name, filter_exts);
        }
        if let Some(path) = d.pick_file() {
            if let Ok(data) = std::fs::read(&path) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                *pending.lock().unwrap() = Some(PickedFile { name, data, path: Some(path) });
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        let mut d = rfd::AsyncFileDialog::new();
        if !filter_exts.is_empty() {
            d = d.add_filter(filter_name, filter_exts);
        }
        if let Some(file) = d.pick_file().await {
            let name = file.file_name();
            let data = file.read().await;
            *pending.lock().unwrap() = Some(PickedFile { name, data, path: None });
        }
    });
}

fn save_result(
    filename: &str,
    data: &[u8],
    native_path: Option<PathBuf>,
    confirm_overwrite: bool,
) -> OpStatus {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let path = native_path.unwrap_or_else(|| PathBuf::from(filename));
        if confirm_overwrite && path.exists() {
            return OpStatus::Err(format!(
                "Output already exists: {}  — disable overwrite protection in Settings.",
                path.display()
            ));
        }
        match std::fs::write(&path, data) {
            Ok(()) => OpStatus::Ok(format!("Saved →  {}", path.display())),
            Err(e) => OpStatus::Err(e.to_string()),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (native_path, confirm_overwrite);
        download_bytes(filename, data);
        OpStatus::Ok(format!("Downloaded: {filename}"))
    }
}

#[cfg(target_arch = "wasm32")]
fn download_bytes(filename: &str, data: &[u8]) {
    use wasm_bindgen::JsCast;
    let arr = js_sys::Uint8Array::new_with_length(data.len() as u32);
    arr.copy_from(data);
    let blob = web_sys::Blob::new_with_u8_array_sequence(&js_sys::Array::of1(&arr)).unwrap();
    let url = web_sys::Url::create_object_url_with_blob(&blob).unwrap();
    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();
    let body = document.body().unwrap();
    let a: web_sys::HtmlAnchorElement =
        document.create_element("a").unwrap().dyn_into().unwrap();
    a.set_href(&url);
    a.set_download(filename);
    body.append_child(&a).unwrap();
    a.click();
    body.remove_child(&a).unwrap();
    web_sys::Url::revoke_object_url(&url).unwrap();
}

fn show_status(ui: &mut egui::Ui, status: &OpStatus, dark: bool) {
    let (msg, color) = match status {
        OpStatus::None => return,
        OpStatus::Ok(m) if m.is_empty() => return,
        OpStatus::Ok(m)  => (m.as_str(), c_green(dark)),
        OpStatus::Err(m) => (m.as_str(), c_red(dark)),
    };
    ui.add_space(8.0);
    egui::Frame::none()
        .fill(Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), 22))
        .stroke(Stroke::new(
            1.0,
            Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), 80),
        ))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::symmetric(10.0, 6.0))
        .show(ui, |ui| {
            ui.label(RichText::new(msg).size(13.0).color(color));
        });
}
