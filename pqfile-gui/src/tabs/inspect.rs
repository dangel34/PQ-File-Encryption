use std::io::Cursor;
use eframe::egui::{self, RichText, Vec2};
use pqfile::{format, keygen};
use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1, c_text};
use crate::types::OpStatus;
use crate::widgets::{card, file_row, section_label, show_status, tab_heading};

impl PqfileApp {
    pub(crate) fn show_inspect(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Inspect .pqf File", dark);
        ui.label(
            RichText::new("View the header metadata of an encrypted file without decrypting it.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        section_label(ui, "FILE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Encrypted file (.pqf)",
                &mut self.inspect_pqf,
                "PQF",
                &["pqf"],
                dark,
            );
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
                        let ct_fp = keygen::fingerprint(&h.kem_ciphertext);
                        self.inspect_result = format!(
                            "Magic            PQFL\n\
                             Version          {:#04x}\n\
                             KEM variant      ML-KEM-{}\n\
                             Nonce            {}\n\
                             Ciphertext FP    {}\n\
                             Original size    {} bytes",
                            format::VERSION,
                            format::KEM_VARIANT,
                            nonce,
                            ct_fp,
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
