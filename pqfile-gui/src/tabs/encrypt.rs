use std::path::PathBuf;
use eframe::egui::{self, RichText, Vec2};
use pqfile::encrypt;
use crate::app::PqfileApp;
use crate::colors::*;
use crate::types::OpStatus;
use crate::widgets::{card, file_row, save_result, section_label, show_status, tab_heading};

impl PqfileApp {
    pub(crate) fn handle_encrypt(&mut self) {
        let pub_pem = self.encrypt_pubkey.as_str().map(str::to_owned);
        let plain = self.encrypt_plain.data.clone();
        let plain_name = self.encrypt_plain.name.clone();
        let plain_path = self.encrypt_plain.path.clone();

        let (Some(pub_pem), Some(plain)) = (pub_pem, plain) else {
            self.encrypt_status = OpStatus::Err("Load both files first.".to_owned());
            return;
        };

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
                if self.settings.auto_clear && matches!(self.encrypt_status, OpStatus::Ok(_)) {
                    self.encrypt_pubkey.clear();
                    self.encrypt_plain.clear();
                }
            }
            Err(e) => self.encrypt_status = OpStatus::Err(e.to_string()),
        }
    }

    pub(crate) fn show_encrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Encrypt File", dark);
        ui.label(
            RichText::new("Encrypt a file using a recipient's public key.")
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
            self.handle_encrypt();
        }

        if !ready {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Load a public key and a file to continue.")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }

        show_status(ui, &self.encrypt_status, dark);
    }
}
