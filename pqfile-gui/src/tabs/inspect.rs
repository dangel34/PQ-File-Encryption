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
                match do_inspect(data) {
                    Ok(result) => {
                        self.inspect_result = result;
                        self.inspect_status = OpStatus::None;
                    }
                    Err(msg) => {
                        self.inspect_result.clear();
                        self.inspect_status = OpStatus::Err(msg);
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

fn do_inspect(data: &[u8]) -> Result<String, String> {
    let mut cursor = Cursor::new(data);
    let version = format::PqfHeader::read_magic_version(&mut cursor)
        .map_err(|e| e.to_string())?;
    match version {
        v if v == format::VERSION
            || v == format::VERSION_V3
            || v == format::VERSION_V5
            || v == format::VERSION_V6 =>
        {
            let h = format::PqfHeader::read_body(&mut cursor, version)
                .map_err(|e| e.to_string())?;
            Ok(format_v2_header(&h))
        }
        v if v == format::VERSION_V4 => {
            let h = format::PqfHeaderV4::read_body(&mut cursor)
                .map_err(|e| e.to_string())?;
            Ok(format_v4_header(&h))
        }
        v if v == format::VERSION_V7 => {
            let h = format::PqfHeaderV7::read_body(&mut cursor)
                .map_err(|e| e.to_string())?;
            Ok(format_v7_header(&h))
        }
        v => Err(format!("Unsupported version: {v:#04x}")),
    }
}

fn format_v2_header(h: &format::PqfHeader) -> String {
    let nonce: String = h.nonce.iter().map(|b| format!("{b:02x}")).collect();
    let ct_fp = keygen::fingerprint(&h.kem_ciphertext);
    let variant_name = variant_display(h.kem_variant);
    let version_label = match h.version {
        v if v == format::VERSION    => "0x02  (single-recipient v2)".to_owned(),
        v if v == format::VERSION_V3 => "0x03  (single-recipient streaming)".to_owned(),
        v if v == format::VERSION_V5 => "0x05  (configurable chunk size)".to_owned(),
        v if v == format::VERSION_V6 => "0x06  (compress-then-encrypt)".to_owned(),
        v => format!("{v:#04x}"),
    };
    let mut result = format!(
        "Magic            PQFL\n\
         Version          {}\n\
         KEM variant      {}\n\
         Nonce            {}\n\
         Ciphertext FP    {}\n\
         Original size    {} bytes",
        version_label, variant_name, nonce, ct_fp, h.original_size,
    );
    if h.version == format::VERSION_V5 || h.version == format::VERSION_V6 {
        result.push_str(&format!("\nChunk size       {} bytes", h.chunk_size));
    }
    if h.version == format::VERSION_V6 {
        let algo = match h.compression_algo {
            format::COMPRESSION_NONE => "none".to_owned(),
            format::COMPRESSION_ZSTD => "zstd".to_owned(),
            x => format!("{x:#04x}"),
        };
        result.push_str(&format!("\nCompression      {algo}"));
    }
    result
}

fn format_multi_recipient_header(
    version_label: &str,
    recipients: &[(u16, &[u8])],
    nonce: &[u8],
    original_size: u64,
) -> String {
    let nonce_str: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let n = recipients.len();
    let mut lines = format!(
        "Magic            PQFL\n\
         Version          {version_label}\n\
         Recipients       {n}\n"
    );
    for (i, (kem_variant, kem_ciphertext)) in recipients.iter().enumerate() {
        let vname = variant_display(*kem_variant);
        let ct_fp = keygen::fingerprint(kem_ciphertext);
        lines.push_str(&format!(
            "  [{i}] variant      {vname}\n\
             \x20    CT FP        {ct_fp}\n"
        ));
    }
    lines.push_str(&format!(
        "Nonce            {nonce_str}\n\
         Original size    {original_size} bytes"
    ));
    lines
}

fn format_v4_header(h: &format::PqfHeaderV4) -> String {
    let recipients: Vec<(u16, &[u8])> = h.recipients.iter()
        .map(|r| (r.kem_variant, r.kem_ciphertext.as_slice()))
        .collect();
    format_multi_recipient_header("0x04  (multi-recipient)", &recipients, &h.nonce, h.original_size)
}

fn format_v7_header(h: &format::PqfHeaderV7) -> String {
    let recipients: Vec<(u16, &[u8])> = h.recipients.iter()
        .map(|r| (r.kem_variant, r.kem_ciphertext.as_slice()))
        .collect();
    format_multi_recipient_header("0x07  (anonymous multi-recipient)", &recipients, &h.nonce, h.original_size)
}

fn variant_display(kem_variant: u16) -> String {
    match kem_variant {
        512    => "ML-KEM-512".to_owned(),
        768    => "ML-KEM-768".to_owned(),
        1024   => "ML-KEM-1024".to_owned(),
        0x0301 => "Hybrid X25519+ML-KEM-768".to_owned(),
        v      => format!("unknown ({v:#06x})"),
    }
}
