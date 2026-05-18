use std::path::PathBuf;
use eframe::egui::{self, RichText, Vec2};
use pqfile::decrypt;
use crate::app::PqfileApp;
use crate::colors::*;
use crate::types::OpStatus;
use crate::widgets::{card, file_row, save_result, section_label, show_status, tab_heading};

impl PqfileApp {
    pub(crate) fn handle_decrypt(&mut self) {
        let priv_pem = self.decrypt_privkey.as_str().map(str::to_owned);
        let pqf = self.decrypt_pqf.data.clone();
        let pqf_name = self.decrypt_pqf.name.clone();
        let pqf_path = self.decrypt_pqf.path.clone();

        let (Some(priv_pem), Some(pqf)) = (priv_pem, pqf) else {
            self.decrypt_status = OpStatus::Err("Load both files first.".to_owned());
            return;
        };

        match decrypt::decrypt_bytes(&priv_pem, &pqf, None) {
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
                self.decrypt_status = save_result(&out_name, &plain, out_path, confirm);
                if self.settings.auto_clear && matches!(self.decrypt_status, OpStatus::Ok(_)) {
                    self.decrypt_privkey.clear();
                    self.decrypt_pqf.clear();
                }
            }
            Err(e) => self.decrypt_status = OpStatus::Err(e.to_string()),
        }
    }

    pub(crate) fn show_decrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Decrypt File", dark);
        ui.label(
            RichText::new("Decrypt a .pqf file using your private key.")
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
            self.handle_decrypt();
        }

        if !ready {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Load a private key and a .pqf file to continue.")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }

        show_status(ui, &self.decrypt_status, dark);
    }
}
