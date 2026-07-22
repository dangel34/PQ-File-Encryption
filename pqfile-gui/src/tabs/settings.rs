use crate::app::PqfileApp;
#[cfg(not(target_arch = "wasm32"))]
use crate::colors::c_overlay;
use crate::colors::{c_card, c_red, c_subtext, c_surface0, c_surface1, c_text};
use crate::theme::apply_theme;
use crate::types::{KeygenAlgorithm, OpStatus, Tab};
use crate::widgets::{card, section_label, setting_toggle, tab_heading_help};
use eframe::egui::{self, RichText, Stroke};

impl PqfileApp {
    pub(crate) fn show_settings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, dark: bool) {
        if tab_heading_help(ui, "Settings", dark) {
            self.help_modal_open = Some(Tab::Settings);
        }
        ui.label(
            RichText::new("Configure appearance and behavior.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        self.show_appearance_section(ui, ctx, dark);

        #[cfg(not(target_arch = "wasm32"))]
        self.show_output_dir_section(ui, dark);

        #[cfg(all(not(target_arch = "wasm32"), feature = "audit"))]
        self.show_audit_log_section(ui, dark);

        self.show_behavior_section(ui, dark);
        self.show_defaults_section(ui, dark);
        self.show_clipboard_settings(ui, dark);
        self.show_danger_zone_section(ui, dark);
    }

    // ── Appearance ────────────────────────────────────────────────────────

    fn show_appearance_section(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, dark: bool) {
        section_label(ui, "APPEARANCE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            let prev = self.settings.dark_mode;
            let row_w = ui.available_width();
            ui.allocate_ui(egui::vec2(row_w, 26.0), |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(RichText::new("Theme").size(13.0).color(c_text(dark)));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let label = if self.settings.dark_mode {
                            "🌙  Dark"
                        } else {
                            "☀  Light"
                        };
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
    }

    // ── Output directory ──────────────────────────────────────────────────

    #[cfg(not(target_arch = "wasm32"))]
    fn show_output_dir_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "DEFAULT OUTPUT DIRECTORY", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new(
                    "Where encrypted, decrypted, and generated key files are saved. \
                     Leave blank to save next to the source file.",
                )
                .size(12.0)
                .color(c_subtext(dark)),
            );
            ui.add_space(6.0);
            let row_w = ui.available_width();
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.output_dir)
                        .hint_text("Same folder as source file (default)")
                        .desired_width((row_w - 80.0).max(50.0)),
                );
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Browse...").size(13.0).color(c_text(dark)),
                        )
                        .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.settings.output_dir = p.to_string_lossy().into_owned();
                    }
                }
            });
            if !self.settings.output_dir.is_empty() {
                ui.add_space(4.0);
                if ui
                    .add(
                        egui::Button::new(RichText::new("Clear").size(12.0).color(c_overlay(dark)))
                            .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    self.settings.output_dir.clear();
                }
            }
        });
        ui.add_space(10.0);
    }

    // ── Audit log ─────────────────────────────────────────────────────────

    #[cfg(all(not(target_arch = "wasm32"), feature = "audit"))]
    fn show_audit_log_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "AUDIT LOG", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new(
                    "When all three fields below are set, every encrypt/decrypt appends a \
                     signed, encrypted record here - a hash chain makes silent deletion or \
                     reordering detectable, without needing the auditor's private key to \
                     check. Leave any field blank to keep audit logging off.",
                )
                .size(12.0)
                .color(c_subtext(dark)),
            );
            ui.add_space(8.0);

            ui.label(RichText::new("Log file").size(12.5).color(c_text(dark)));
            let row_w = ui.available_width();
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.audit_log_path)
                        .hint_text("Off (no path set)")
                        .desired_width((row_w - 80.0).max(50.0)),
                );
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Browse...").size(13.0).color(c_text(dark)),
                        )
                        .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_file_name("audit.log")
                        .save_file()
                    {
                        self.settings.audit_log_path = p.to_string_lossy().into_owned();
                    }
                }
            });
            ui.add_space(6.0);

            ui.label(
                RichText::new("Your signing key (ML-DSA or SLH-DSA)")
                    .size(12.5)
                    .color(c_text(dark)),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.audit_key_path)
                        .hint_text("sign_privkey.pem")
                        .desired_width((row_w - 80.0).max(50.0)),
                );
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Browse...").size(13.0).color(c_text(dark)),
                        )
                        .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.settings.audit_key_path = p.to_string_lossy().into_owned();
                    }
                }
            });
            ui.add_space(6.0);
            ui.label(
                RichText::new("Signing key passphrase (if any, never saved to disk)")
                    .size(12.5)
                    .color(c_text(dark)),
            );
            ui.add(
                egui::TextEdit::singleline(&mut *self.audit_key_passphrase)
                    .password(true)
                    .desired_width(row_w),
            );
            ui.add_space(6.0);

            ui.label(
                RichText::new("Auditor's public key (or pqf1… recipient string)")
                    .size(12.5)
                    .color(c_text(dark)),
            );
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.audit_recipient_path)
                        .hint_text("pubkey.pem or pqf1…")
                        .desired_width((row_w - 80.0).max(50.0)),
                );
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Browse...").size(13.0).color(c_text(dark)),
                        )
                        .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_file() {
                        self.settings.audit_recipient_path = p.to_string_lossy().into_owned();
                    }
                }
            });
        });
        ui.add_space(10.0);
    }

    // ── Behavior ──────────────────────────────────────────────────────────

    fn show_behavior_section(&mut self, ui: &mut egui::Ui, dark: bool) {
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
                    "Block output if a file with the same name already exists (keygen, encrypt, decrypt).",
                    dark,
                );
            }
            #[cfg(all(not(target_arch = "wasm32"), feature = "update-check"))]
            {
                ui.add_space(8.0);
                setting_toggle(
                    ui,
                    &mut self.settings.auto_check_updates,
                    "Check for updates on startup",
                    "Checks GitHub once per launch. No file data or telemetry is sent, and \
                     nothing is ever downloaded or installed automatically.",
                    dark,
                );
                ui.add_space(6.0);
                self.show_update_check_row(ui, dark);
            }
        });
        ui.add_space(10.0);
    }

    // ── Defaults ─────────────────────────────────────────────────────────

    fn show_defaults_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "KEYGEN DEFAULTS", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new("Default algorithm for new key pairs.")
                    .size(12.0)
                    .color(c_subtext(dark)),
            );
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                ui.radio_value(
                    &mut self.settings.default_algorithm,
                    KeygenAlgorithm::MlKem512,
                    RichText::new("ML-KEM-512")
                        .size(12.5)
                        .color(c_subtext(dark)),
                );
                ui.add_space(4.0);
                ui.radio_value(
                    &mut self.settings.default_algorithm,
                    KeygenAlgorithm::MlKem768,
                    RichText::new("ML-KEM-768  (recommended)")
                        .size(12.5)
                        .color(c_subtext(dark)),
                );
                ui.add_space(4.0);
                ui.radio_value(
                    &mut self.settings.default_algorithm,
                    KeygenAlgorithm::MlKem1024,
                    RichText::new("ML-KEM-1024")
                        .size(12.5)
                        .color(c_subtext(dark)),
                );
                ui.add_space(4.0);
                ui.radio_value(
                    &mut self.settings.default_algorithm,
                    KeygenAlgorithm::HybridX25519MlKem768,
                    RichText::new("Hybrid X25519+ML-KEM-768")
                        .size(12.5)
                        .color(c_subtext(dark)),
                );
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Signing keys (ML-DSA-65 or SLH-DSA-SHAKE-192f) are always selected \
                     explicitly in the Keygen tab and do not have a default here.",
                )
                .size(11.5)
                .color(c_subtext(dark)),
            );
            ui.add_space(10.0);
            ui.label(
                RichText::new("Default key expiry (days from today). Set to 0 to disable.")
                    .size(12.0)
                    .color(c_subtext(dark)),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let mut days = self.settings.default_expiry_days as i32;
                ui.add(
                    egui::DragValue::new(&mut days)
                        .range(0..=3650)
                        .speed(1.0)
                        .suffix(" days"),
                );
                self.settings.default_expiry_days = days.max(0) as u32;
                if self.settings.default_expiry_days > 0 {
                    // Show what today + N days resolves to.
                    if let Some(date) = days_from_now(self.settings.default_expiry_days) {
                        ui.label(
                            RichText::new(format!("(expires {date})"))
                                .size(11.5)
                                .color(c_subtext(dark)),
                        );
                    }
                } else {
                    ui.label(
                        RichText::new("No default expiry")
                            .size(11.5)
                            .color(c_subtext(dark)),
                    );
                }
            });
        });
        ui.add_space(10.0);
    }

    // ── Clipboard ────────────────────────────────────────────────────────

    fn show_clipboard_settings(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "CLIPBOARD", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            setting_toggle(
                ui,
                &mut self.settings.clipboard_auto_clear,
                "Auto-clear clipboard text",
                "Zeroize plaintext and ciphertext in the clipboard tool after the timeout below.",
                dark,
            );
            if self.settings.clipboard_auto_clear {
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Clear after:")
                            .size(13.0)
                            .color(c_subtext(dark)),
                    );
                    let mut secs = self.settings.clipboard_clear_secs as i32;
                    ui.add(
                        egui::DragValue::new(&mut secs)
                            .range(5..=3600)
                            .speed(1.0)
                            .suffix(" s"),
                    );
                    self.settings.clipboard_clear_secs = secs.max(5) as u32;
                    ui.label(
                        RichText::new(if secs < 60 {
                            format!("({secs} seconds)")
                        } else {
                            format!("({:.0} minutes)", secs as f32 / 60.0)
                        })
                        .size(11.5)
                        .color(c_subtext(dark)),
                    );
                });
            }
        });
        ui.add_space(10.0);
    }

    // ── Danger zone ───────────────────────────────────────────────────────

    fn show_danger_zone_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "DANGER ZONE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new("Destructive actions that cannot be undone.")
                    .size(12.0)
                    .color(c_subtext(dark)),
            );
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Clear All Inputs")
                                .size(13.0)
                                .color(c_red(dark)),
                        )
                        .fill(c_surface0(dark))
                        .stroke(Stroke::new(1.0, c_red(dark))),
                    )
                    .on_hover_text(
                        "Remove all loaded files and reset status messages in every tab.",
                    )
                    .clicked()
                {
                    self.clear_all_inputs();
                }

                ui.add_space(8.0);

                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Clear Recent History")
                                .size(13.0)
                                .color(c_red(dark)),
                        )
                        .fill(c_surface0(dark))
                        .stroke(Stroke::new(1.0, c_red(dark))),
                    )
                    .on_hover_text(
                        "Clear the recent files list shown in the Encrypt and Decrypt tabs.",
                    )
                    .clicked()
                {
                    self.clear_recent_history();
                }
            });
        });
    }

    fn clear_all_inputs(&mut self) {
        self.encrypt_pubkey.clear();
        self.encrypt_recipients.clear();
        self.encrypt_files.clear();
        if let Ok(mut g) = self.encrypt_batch_pending.try_lock() {
            g.take();
        }
        self.decrypt_privkey.clear();
        self.decrypt_files.clear();
        if let Ok(mut g) = self.decrypt_batch_pending.try_lock() {
            g.take();
        }
        self.decrypt_status = OpStatus::None;
        self.keygen_status = OpStatus::None;
    }

    fn clear_recent_history(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.recent_encrypt_files.clear();
            self.recent_decrypt_files.clear();
            self.recent_privkeys.clear();
            self.recent_pubkeys.clear();
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Returns "YYYY-MM-DD" for today + `days` days, or None on overflow.
pub(crate) fn days_from_now(days: u32) -> Option<String> {
    use crate::types::{current_unix_secs, days_since_epoch_to_ymd};
    let now_days = (current_unix_secs() / 86400) as i64;
    Some(days_since_epoch_to_ymd(now_days + days as i64))
}
