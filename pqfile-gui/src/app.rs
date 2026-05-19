use std::sync::{Arc, Mutex};
use eframe::egui::{self, Color32, CornerRadius, Margin, RichText, Stroke, Vec2};
use crate::colors::{c_accent, c_bg, c_card, c_chrome, c_overlay, c_subtext, c_surface0, c_surface1, c_text};
use crate::theme::apply_theme;
use crate::types::{Tab, OpStatus, PickedFile, FileInput, BatchPending, MultiFileEntry, Settings};
use crate::widgets::{bullet, card, kv_row, section_label, tab_btn};
use crate::APP_VERSION;

pub struct PqfileApp {
    pub(crate) tab: Tab,
    pub(crate) show_about: bool,
    pub(crate) settings: Settings,

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) keygen_dir: String,
    pub(crate) keygen_passphrase: String,
    pub(crate) keygen_passphrase_confirm: String,
    pub(crate) keygen_use_passphrase: bool,
    pub(crate) keygen_status: OpStatus,

    pub(crate) encrypt_pubkey: FileInput,
    pub(crate) encrypt_files: Vec<MultiFileEntry>,
    pub(crate) encrypt_batch_pending: BatchPending,

    pub(crate) decrypt_privkey: FileInput,
    pub(crate) decrypt_pqf: FileInput,
    pub(crate) decrypt_passphrase: String,
    pub(crate) decrypt_status: OpStatus,

    pub(crate) inspect_pqf: FileInput,
    pub(crate) inspect_result: String,
    pub(crate) inspect_status: OpStatus,
}

impl Default for PqfileApp {
    fn default() -> Self {
        Self {
            tab: Tab::Keygen,
            show_about: false,
            settings: Settings::default(),
            #[cfg(not(target_arch = "wasm32"))]
            keygen_dir: String::new(),
            keygen_passphrase: String::new(),
            keygen_passphrase_confirm: String::new(),
            keygen_use_passphrase: false,
            keygen_status: OpStatus::None,
            encrypt_pubkey: FileInput::default(),
            encrypt_files: Vec::new(),
            encrypt_batch_pending: Arc::new(Mutex::new(None)),
            decrypt_privkey: FileInput::default(),
            decrypt_pqf: FileInput::default(),
            decrypt_passphrase: String::new(),
            decrypt_status: OpStatus::None,
            inspect_pqf: FileInput::default(),
            inspect_result: String::new(),
            inspect_status: OpStatus::None,
        }
    }
}

impl PqfileApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings = cc.storage
            .map(Settings::load)
            .unwrap_or_default();
        apply_theme(&cc.egui_ctx, settings.dark_mode);
        Self { settings, ..Default::default() }
    }
}

// ── Frame ──────────────────────────────────────────────────────────────────

impl eframe::App for PqfileApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.settings.save(storage);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if self.poll_files() {
            ctx.request_repaint();
        }
        self.handle_dropped_files(&ctx);

        // Drag-over overlay — paint above everything else when files are hovering
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
        let bg     = c_bg(dark);

        // ── Title bar ──────────────────────────────────────────────────────
        egui::Panel::top("top_bar")
            .exact_size(46.0)
            .frame(egui::Frame::NONE.fill(chrome).inner_margin(Margin::symmetric(14, 0)))
            .show_inside(ui, |ui| {
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
        egui::Panel::bottom("footer")
            .exact_size(26.0)
            .frame(egui::Frame::NONE.fill(chrome).inner_margin(Margin::symmetric(14, 0)))
            .show_inside(ui, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format!("v{APP_VERSION}")).size(11.0).color(c_overlay(dark)));
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
            self.show_about_window(&ctx, dark);
        }

        // ── Central panel ──────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(bg))
            .show_inside(ui, |ui| {
                // Tab strip
                egui::Frame::NONE
                    .fill(chrome)
                    .inner_margin(Margin::symmetric(14, 7))
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
                        egui::Frame::NONE
                            .inner_margin(Margin::symmetric(18, 14))
                            .show(ui, |ui| match self.tab {
                                Tab::Keygen   => self.show_keygen(ui, dark),
                                Tab::Encrypt  => self.show_encrypt(ui, dark),
                                Tab::Decrypt  => self.show_decrypt(ui, dark),
                                Tab::Inspect  => self.show_inspect(ui, dark),
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
                { file.path.as_ref().and_then(|p| std::fs::read(p).ok()) }
                #[cfg(target_arch = "wasm32")]
                { None }
            };

            let Some(data) = data else { continue };
            self.route_drop(name, data, file.path);
        }
    }

    /// Route a dropped file into the correct slot based on the active tab and
    /// the file's extension. Pure logic with no egui dependency — testable directly.
    pub(crate) fn route_drop(&mut self, name: String, data: Vec<u8>, path: Option<std::path::PathBuf>) {
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let picked = PickedFile { name, data, path };
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
                    *self.decrypt_pqf.pending.lock().unwrap() = Some(picked);
                }
            }
            Tab::Inspect => {
                *self.inspect_pqf.pending.lock().unwrap() = Some(picked);
            }
            _ => {}
        }
    }
}

// ── Polling ────────────────────────────────────────────────────────────────

impl PqfileApp {
    fn poll_files(&mut self) -> bool {
        self.encrypt_pubkey.poll();
        self.decrypt_privkey.poll();
        self.decrypt_pqf.poll();
        self.inspect_pqf.poll();

        // Drain any batch of files delivered by the async file picker.
        let batch_arrived = if let Ok(mut g) = self.encrypt_batch_pending.try_lock() {
            if let Some(batch) = g.take() {
                for picked in batch {
                    self.encrypt_files.push(MultiFileEntry {
                        name: picked.name,
                        data: picked.data,
                        path: picked.path,
                        status: OpStatus::None,
                    });
                }
                true
            } else {
                false
            }
        } else {
            false
        };

        let singles_pending = [
            &self.encrypt_pubkey,
            &self.decrypt_privkey,
            &self.decrypt_pqf,
            &self.inspect_pqf,
        ]
        .iter()
        .any(|f| f.pending.try_lock().map(|g| g.is_some()).unwrap_or(false));

        let batch_pending = self.encrypt_batch_pending
            .try_lock()
            .map(|g| g.is_some())
            .unwrap_or(false);

        singles_pending || batch_arrived || batch_pending
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
                egui::Frame::window(&ctx.global_style())
                    .fill(c_bg(dark))
                    .stroke(Stroke::new(1.0, c_surface1(dark)))
                    .corner_radius(CornerRadius::same(10)),
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
                            kv_row(ui, "Randomness",        "OS CSPRNG  (OsRng)", dark);
                            kv_row(ui, "File format",       ".pqf  (1115-byte header + AEAD)", dark);
                        });

                        ui.add_space(10.0);
                        section_label(ui, "SECURITY PROPERTIES", dark);
                        card(ui, c_card(dark), c_surface1(dark), |ui| {
                            bullet(ui, "All operations run locally — no data is uploaded", dark);
                            bullet(ui, "Keys and shared secrets zeroized after use", dark);
                            bullet(ui, "AEAD authentication prevents silent corruption", dark);
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
