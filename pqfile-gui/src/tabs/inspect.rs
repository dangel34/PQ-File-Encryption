use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1, c_text};
use crate::types::{OpStatus, Tab};
use crate::widgets::{card, file_row, section_label, show_status, tab_heading_help};
use eframe::egui::{self, RichText, Vec2};
use pqfile::format;
use pqfile::inspect::{inspect_stream, PqfHeaderInfo};
use std::io::Cursor;

impl PqfileApp {
    pub(crate) fn show_inspect(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Inspect .pqf File", dark) {
            self.help_modal_open = Some(Tab::Inspect);
        }
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
    let info = inspect_stream(&mut cursor).map_err(|e| e.to_string())?;
    Ok(format_header_info(&info))
}

fn format_header_info(info: &PqfHeaderInfo) -> String {
    match info {
        PqfHeaderInfo::Single {
            version,
            kem_variant,
            nonce,
            original_size,
            chunk_size,
            compression_algo,
        } => {
            let nonce_hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let variant_name = variant_display(*kem_variant);
            let version_label = match version {
                v if *v == format::VERSION => "0x02  (single-recipient v2)".to_owned(),
                v if *v == format::VERSION_V3 => "0x03  (single-recipient streaming)".to_owned(),
                v if *v == format::VERSION_V5 => "0x05  (configurable chunk size)".to_owned(),
                v if *v == format::VERSION_V6 => "0x06  (compress-then-encrypt)".to_owned(),
                v => format!("{v:#04x}"),
            };
            let mut result = format!(
                "Magic            PQFL\n\
                 Version          {version_label}\n\
                 KEM variant      {variant_name}\n\
                 Nonce            {nonce_hex}\n\
                 Original size    {original_size} bytes",
            );
            if *version == format::VERSION_V5 || *version == format::VERSION_V6 {
                result.push_str(&format!("\nChunk size       {chunk_size} bytes"));
            }
            if *version == format::VERSION_V6 {
                let algo = match compression_algo {
                    v if *v == format::COMPRESSION_NONE => "none".to_owned(),
                    v if *v == format::COMPRESSION_ZSTD => "zstd".to_owned(),
                    x => format!("{x:#04x}"),
                };
                result.push_str(&format!("\nCompression      {algo}"));
            }
            result
        }
        PqfHeaderInfo::Multi {
            recipients,
            nonce,
            original_size,
        } => format_multi_header("0x04  (multi-recipient)", recipients, nonce, *original_size),
        PqfHeaderInfo::AnonMulti {
            recipients,
            nonce,
            original_size,
        } => format_multi_header(
            "0x07  (anonymous multi-recipient, legacy)",
            recipients,
            nonce,
            *original_size,
        ),
        PqfHeaderInfo::AnonMultiV8 {
            slot_count,
            nonce,
            original_size,
        } => {
            let nonce_str: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "Magic            PQFL\n\
                 Version          0x08  (variant-blind anonymous multi-recipient)\n\
                 Slots            {slot_count}  (key types hidden)\n\
                 Nonce            {nonce_str}\n\
                 Original size    {original_size} bytes"
            )
        }
        _ => "Unsupported format version.".to_owned(),
    }
}

fn format_multi_header(
    version_label: &str,
    recipients: &[pqfile::inspect::RecipientInfo],
    nonce: &[u8; 12],
    original_size: u64,
) -> String {
    let nonce_str: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let n = recipients.len();
    let mut lines = format!(
        "Magic            PQFL\n\
         Version          {version_label}\n\
         Recipients       {n}\n"
    );
    for (i, r) in recipients.iter().enumerate() {
        let vname = variant_display(r.kem_variant);
        lines.push_str(&format!("  [{i}] variant      {vname}\n"));
    }
    lines.push_str(&format!(
        "Nonce            {nonce_str}\n\
         Original size    {original_size} bytes"
    ));
    lines
}

fn variant_display(kem_variant: u16) -> String {
    match kem_variant {
        512 => "ML-KEM-512".to_owned(),
        768 => "ML-KEM-768".to_owned(),
        1024 => "ML-KEM-1024".to_owned(),
        0x0301 => "Hybrid X25519+ML-KEM-768".to_owned(),
        v => format!("unknown ({v:#06x})"),
    }
}
