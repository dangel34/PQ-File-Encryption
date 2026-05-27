use eframe::egui::{self, RichText, Stroke};
use crate::app::PqfileApp;
use crate::colors::{c_card, c_overlay, c_red, c_subtext, c_surface0, c_surface1, c_text};
use crate::theme::apply_theme;
use crate::types::OpStatus;
use crate::widgets::{card, section_label, setting_toggle, tab_heading};

impl PqfileApp {
    pub(crate) fn show_settings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, dark: bool) {
        tab_heading(ui, "Settings", dark);
        ui.label(
            RichText::new("Configure appearance and behavior.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        self.show_appearance_section(ui, ctx, dark);

        #[cfg(not(target_arch = "wasm32"))]
        self.show_output_dir_section(ui, dark);

        self.show_behavior_section(ui, dark);
        self.show_security_section(ui, dark);
        self.show_danger_zone_section(ui, dark);
    }

    fn show_appearance_section(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, dark: bool) {
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
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn show_output_dir_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "DEFAULT OUTPUT DIRECTORY", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new(
                    "Where encrypted, decrypted, and generated key files are saved. \
                     Leave blank to save next to the source file."
                )
                .size(12.0)
                .color(c_subtext(dark)),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.settings.output_dir)
                        .hint_text("Same folder as source file (default)")
                        .desired_width(ui.available_width() - 80.0),
                );
                if ui
                    .add(
                        egui::Button::new(RichText::new("Browse…").size(13.0).color(c_text(dark)))
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
                        egui::Button::new(
                            RichText::new("Clear").size(12.0).color(c_overlay(dark)),
                        )
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
        });
        ui.add_space(10.0);
    }

    fn show_security_section(&self, ui: &mut egui::Ui, dark: bool) {
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
    }

    fn show_danger_zone_section(&mut self, ui: &mut egui::Ui, dark: bool) {
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
                self.clear_all_inputs();
            }
        });
    }

    fn clear_all_inputs(&mut self) {
        self.encrypt_pubkey.clear();
        self.encrypt_recipients.clear();
        self.encrypt_files.clear();
        if let Ok(mut g) = self.encrypt_batch_pending.try_lock() { g.take(); }
        self.decrypt_privkey.clear();
        self.decrypt_files.clear();
        if let Ok(mut g) = self.decrypt_batch_pending.try_lock() { g.take(); }
        self.decrypt_status = OpStatus::None;
        self.inspect_pqf.clear();
        self.inspect_result.clear();
        self.inspect_status = OpStatus::None;
        self.keygen_status = OpStatus::None;
    }
}
