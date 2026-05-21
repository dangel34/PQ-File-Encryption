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
                let mut cursor = Cursor::new(data.as_slice());
                match format::PqfHeader::read_magic_version(&mut cursor) {
                    Ok(version) if version == format::VERSION || version == format::VERSION_V3 => {
                        match format::PqfHeader::read_body(&mut cursor, version) {
                            Ok(h) => {
                                let nonce: String =
                                    h.nonce.iter().map(|b| format!("{b:02x}")).collect();
                                let ct_fp = keygen::fingerprint(&h.kem_ciphertext);
                                let variant_name = variant_display(h.kem_variant);
                                self.inspect_result = format!(
                                    "Magic            PQFL\n\
                                     Version          {:#04x}\n\
                                     KEM variant      {}\n\
                                     Nonce            {}\n\
                                     Ciphertext FP    {}\n\
                                     Original size    {} bytes",
                                    h.version,
                                    variant_name,
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
                    }
                    Ok(version) if version == format::VERSION_V4 => {
                        match format::PqfHeaderV4::read_body(&mut cursor) {
                            Ok(h) => {
                                let nonce: String =
                                    h.nonce.iter().map(|b| format!("{b:02x}")).collect();
                                let n = h.recipients.len();
                                let mut lines = format!(
                                    "Magic            PQFL\n\
                                     Version          0x04  (multi-recipient)\n\
                                     Recipients       {n}\n"
                                );
                                for (i, r) in h.recipients.iter().enumerate() {
                                    let vname = variant_display(r.kem_variant);
                                    let ct_fp = keygen::fingerprint(&r.kem_ciphertext);
                                    lines.push_str(&format!(
                                        "  [{i}] variant      {vname}\n\
                                         \x20    CT FP        {ct_fp}\n"
                                    ));
                                }
                                lines.push_str(&format!(
                                    "Nonce            {}\n\
                                     Original size    {} bytes",
                                    nonce, h.original_size,
                                ));
                                self.inspect_result = lines;
                                self.inspect_status = OpStatus::None;
                            }
                            Err(e) => {
                                self.inspect_result.clear();
                                self.inspect_status = OpStatus::Err(e.to_string());
                            }
                        }
                    }
                    Ok(v) => {
                        self.inspect_result.clear();
                        self.inspect_status = OpStatus::Err(format!("Unsupported version: {v:#04x}"));
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

fn variant_display(kem_variant: u16) -> String {
    match kem_variant {
        768 => "ML-KEM-768".to_owned(),
        1024 => "ML-KEM-1024".to_owned(),
        0x0301 => "Hybrid X25519+ML-KEM-768".to_owned(),
        v => format!("unknown ({v:#06x})"),
    }
}
