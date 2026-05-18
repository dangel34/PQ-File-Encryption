use eframe::egui::{self, RichText, Stroke};
use crate::app::PqfileApp;
use crate::colors::*;
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
                    "Block output if a file with the same name already exists (keygen, encrypt, decrypt).",
                    dark,
                );
            }
        });

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
            }
        });
    }
}
