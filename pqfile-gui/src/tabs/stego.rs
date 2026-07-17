use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_overlay, c_subtext, c_surface1};
use crate::types::{OpStatus, StegoSubTab};
use crate::widgets::{
    card, file_row, passphrase_row, save_result, section_label, seg_tabs, show_status,
};
use eframe::egui::{self, RichText, Vec2};
use pqfile::stego;
use zeroize::{Zeroize, Zeroizing};

impl PqfileApp {
    pub(crate) fn show_stego_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        ui.label(
            RichText::new(
                "Hide a file inside a cover image's pixel data, or recover one previously \
                 hidden. The passphrase keys detection itself: without it, nothing embedded \
                 in the image reveals that a payload is present, and a wrong passphrase is \
                 indistinguishable from a plain photo. A statistical analysis of the image's \
                 noise can still suggest something is embedded, so this is a \
                 plausible-deniability backup, not a steganalysis-hardened one.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(8.0);
        seg_tabs(
            ui,
            &mut self.stego_sub_tab,
            &[("Bury", StegoSubTab::Bury), ("Exhume", StegoSubTab::Exhume)],
            dark,
        );
        match self.stego_sub_tab {
            StegoSubTab::Bury => self.show_stego_bury_section(ui, dark),
            StegoSubTab::Exhume => self.show_stego_exhume_section(ui, dark),
        }
    }

    // ── Bury ──────────────────────────────────────────────────────────────

    fn show_stego_bury_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "BURY (HIDE A FILE INSIDE AN IMAGE)", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Cover image",
                &mut self.stego_bury_cover,
                "Image",
                &["png", "jpg", "jpeg"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "File to hide (ideally passphrase-encrypted)",
                &mut self.stego_bury_payload,
                "Any file",
                &[],
                dark,
            );
            ui.add_space(4.0);
            let mut visible = self.stego_bury_passphrase_visible;
            passphrase_row(
                ui,
                "Passphrase:",
                &mut self.stego_bury_passphrase,
                &mut visible,
                "keys detection and recovery",
                dark,
            );
            passphrase_row(
                ui,
                "Confirm:",
                &mut self.stego_bury_passphrase_confirm,
                &mut visible,
                "repeat passphrase",
                dark,
            );
            self.stego_bury_passphrase_visible = visible;
        });
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Output is always a lossless PNG regardless of the cover's original format - \
                 LSB embedding cannot survive a JPEG re-encode. If the passphrase is lost, \
                 the hidden file is unrecoverable.",
            )
            .size(11.5)
            .color(c_overlay(dark)),
        );
        ui.add_space(8.0);

        let ready = self.stego_bury_cover.loaded()
            && self.stego_bury_payload.loaded()
            && !self.stego_bury_passphrase.is_empty();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🖼  Bury")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .on_disabled_hover_text("Load a cover image and a file to hide, and set a passphrase.")
            .clicked()
        {
            self.do_stego_bury();
        }

        #[cfg(not(target_arch = "wasm32"))]
        crate::widgets::reveal_button_if_ok(
            ui,
            &self.stego_bury_status,
            &self.stego_bury_output_path,
            dark,
        );

        show_status(ui, &self.stego_bury_status, dark);
    }

    pub(crate) fn do_stego_bury(&mut self) {
        let cover = match self.stego_bury_cover.data.clone() {
            Some(d) => d,
            None => {
                self.stego_bury_status = OpStatus::Err("Load a cover image first.".to_owned());
                return;
            }
        };
        // The payload is nominally key material: keep the working copy zeroized.
        let payload = match self.stego_bury_payload.data.clone() {
            Some(d) => Zeroizing::new(d),
            None => {
                self.stego_bury_status = OpStatus::Err("Choose a file to hide first.".to_owned());
                return;
            }
        };
        if *self.stego_bury_passphrase != *self.stego_bury_passphrase_confirm {
            self.stego_bury_status = OpStatus::Err("Passphrases do not match.".to_owned());
            return;
        }

        match stego::bury(&cover, &payload, &self.stego_bury_passphrase) {
            Ok(png_bytes) => {
                let stem = file_stem(&self.stego_bury_payload.name);
                let out_name = format!("{stem}-hidden.png");
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.stego_bury_cover.path.as_deref(),
                    &out_name,
                    &self.settings.output_dir,
                    |p| p.with_file_name(&out_name),
                ));
                #[cfg(target_arch = "wasm32")]
                let native_path: Option<std::path::PathBuf> = None;
                #[cfg(not(target_arch = "wasm32"))]
                {
                    self.stego_bury_output_path = native_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned());
                }
                self.stego_bury_status = save_result(
                    &out_name,
                    &png_bytes,
                    native_path,
                    self.settings.confirm_overwrite,
                );
                if matches!(self.stego_bury_status, OpStatus::Ok(_)) {
                    self.stego_bury_passphrase.zeroize();
                    self.stego_bury_passphrase_confirm.zeroize();
                }
            }
            Err(e) => {
                self.stego_bury_status = OpStatus::Err(e.to_string());
            }
        }
    }

    // ── Exhume ────────────────────────────────────────────────────────────

    fn show_stego_exhume_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "EXHUME (RECOVER A HIDDEN FILE)", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Image produced by Bury",
                &mut self.stego_exhume_image,
                "Image",
                &["png"],
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "Passphrase:",
                &mut self.stego_exhume_passphrase,
                &mut self.stego_exhume_passphrase_visible,
                "as set at bury time",
                dark,
            );
            ui.add_space(4.0);
            let row_w = ui.available_width();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Output filename:")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.stego_exhume_filename)
                        .desired_width(row_w),
                );
            });
        });
        ui.add_space(8.0);

        let ready = self.stego_exhume_image.loaded() && !self.stego_exhume_passphrase.is_empty();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔎  Exhume")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .on_disabled_hover_text(
                "Load an image previously produced by Bury and enter its passphrase.",
            )
            .clicked()
        {
            self.do_stego_exhume();
        }

        #[cfg(not(target_arch = "wasm32"))]
        crate::widgets::reveal_button_if_ok(
            ui,
            &self.stego_exhume_status,
            &self.stego_exhume_output_path,
            dark,
        );

        show_status(ui, &self.stego_exhume_status, dark);
    }

    pub(crate) fn do_stego_exhume(&mut self) {
        let image = match self.stego_exhume_image.data.clone() {
            Some(d) => d,
            None => {
                self.stego_exhume_status = OpStatus::Err("Load an image first.".to_owned());
                return;
            }
        };

        match stego::exhume(&image, &self.stego_exhume_passphrase) {
            Ok(recovered) => {
                // Typically a private key: keep the in-memory copy zeroized.
                let recovered = Zeroizing::new(recovered);
                let out_name = if self.stego_exhume_filename.trim().is_empty() {
                    "recovered".to_owned()
                } else {
                    self.stego_exhume_filename.trim().to_owned()
                };
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.stego_exhume_image.path.as_deref(),
                    &out_name,
                    &self.settings.output_dir,
                    |p| p.with_file_name(&out_name),
                ));
                #[cfg(target_arch = "wasm32")]
                let native_path: Option<std::path::PathBuf> = None;
                #[cfg(not(target_arch = "wasm32"))]
                {
                    self.stego_exhume_output_path = native_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned());
                }
                self.stego_exhume_status = save_result(
                    &out_name,
                    &recovered,
                    native_path,
                    self.settings.confirm_overwrite,
                );
                if matches!(self.stego_exhume_status, OpStatus::Ok(_)) {
                    self.stego_exhume_passphrase.zeroize();
                }
            }
            Err(e) => {
                self.stego_exhume_status = OpStatus::Err(e.to_string());
            }
        }
    }
}

fn file_stem(name: &str) -> &str {
    std::path::Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name)
}
