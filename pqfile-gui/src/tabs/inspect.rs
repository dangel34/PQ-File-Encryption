use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1, c_text};
use crate::types::{expiry_days_remaining, read_pem_expiry};
use crate::types::{OpStatus, Tab};
use crate::widgets::{card, file_row, section_label, show_status, tab_heading_help};
use eframe::egui::{self, RichText, Vec2};
use pqfile::format::{self, VERSION_V9};
use pqfile::inspect::{inspect_stream, PqfHeaderInfo};
use pqfile::keygen;
use std::io::Cursor;

impl PqfileApp {
    pub(crate) fn show_inspect(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Inspect .pqf File", dark) {
            self.help_modal_open = Some(Tab::Inspect);
        }
        ui.label(
            RichText::new(
                "View the header metadata of an encrypted file or run diagnostics on a key.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        section_label(ui, "FILE OR KEY", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Encrypted file (.pqf) or key (.pem)",
                &mut self.inspect_pqf,
                "PQF or PEM",
                &["pqf", "pem"],
                dark,
            );
        });
        ui.add_space(14.0);

        let ready = self.inspect_pqf.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔍  Inspect / Diagnose")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
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
            section_label(ui, "DETAILS", dark);
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
    // Detect file type: PEM key or .pqf ciphertext.
    if data.starts_with(b"-----BEGIN") {
        let pem_str =
            std::str::from_utf8(data).map_err(|_| "File is not valid UTF-8.".to_owned())?;
        Ok(format_key_info(pem_str))
    } else if data.starts_with(b"PQFL") {
        let mut cursor = Cursor::new(data);
        let info = inspect_stream(&mut cursor).map_err(|e| e.to_string())?;
        Ok(format_header_info(&info))
    } else {
        Err("File is neither a PEM key (-----BEGIN) nor a PQFL ciphertext.".to_owned())
    }
}

fn format_key_info(pem_str: &str) -> String {
    let is_encrypted = keygen::is_encrypted_key(pem_str);
    let is_hardware = keygen::is_hardware_key(pem_str);

    // Detect key type and variant from PEM header.
    let key_type = if pem_str.contains("ML-DSA") || pem_str.contains("SIGNING") {
        "ML-DSA signing key"
    } else if pem_str.contains("SHAMIR") || pem_str.contains("SHARE") {
        "Shamir share"
    } else if pem_str.contains("ML-KEM") || pem_str.contains("PRIVATE") {
        "ML-KEM private key"
    } else {
        "PEM key"
    };

    let variant = if pem_str.contains("ML-KEM-1024") {
        "ML-KEM-1024"
    } else if pem_str.contains("X25519+ML-KEM-768") || pem_str.contains("Hybrid") {
        "Hybrid X25519+ML-KEM-768"
    } else if pem_str.contains("ML-KEM-512") {
        "ML-KEM-512"
    } else if pem_str.contains("ML-KEM-768") {
        "ML-KEM-768"
    } else if pem_str.contains("ML-DSA-65") {
        "ML-DSA-65"
    } else {
        "unknown"
    };

    let passphrase_note = if is_hardware {
        "n/a (hardware-backed)"
    } else if is_encrypted {
        "yes"
    } else {
        "no"
    };

    let expiry_line = if let Some(date) = read_pem_expiry(pem_str) {
        let days_note = expiry_days_remaining(&date)
            .map(|d| {
                if d < 0 {
                    format!(" (EXPIRED {} days ago)", -d)
                } else if d <= 30 {
                    format!(" - expires in {d} day{}", if d == 1 { "" } else { "s" })
                } else {
                    format!(" - in {d} days")
                }
            })
            .unwrap_or_default();
        format!("\nExpires            {date}{days_note}")
    } else {
        "\nExpires            (not set)".to_owned()
    };

    let mut result = format!(
        "Type               {key_type}\n\
         Variant            {variant}\n\
         Passphrase-protected {passphrase_note}\n\
         Hardware-backed    {is_hardware}{expiry_line}",
    );

    if is_hardware {
        result.push_str(
            "\n\nNote: Seed is stored in OS credential store (Windows Credential Manager /\n\
             macOS Keychain / Linux Secret Service). The PEM file is a reference stub.",
        );
    }
    if is_encrypted && !is_hardware {
        result.push_str(
            "\n\nTip: Use Tools > Change Passphrase to re-encrypt or upgrade from p=1 \
             (pqfile <4.0) to the current Argon2id p=4 parameters.",
        );
    }

    // Native revocation sidecar check.
    #[cfg(not(target_arch = "wasm32"))]
    result.push_str(&native_revocation_note(pem_str));

    result
}

#[cfg(not(target_arch = "wasm32"))]
fn native_revocation_note(pem_str: &str) -> String {
    // We don't have the file path here (only the PEM content), so we can only
    // report if the key appears to be public (encapsulation key) and could have
    // a sidecar, but we can't actually check without the path.
    let _ = pem_str;
    "\n\nRevocation:        load via file picker in Tools > Revoke Key to check sidecar.".to_owned()
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
                "Magic              PQFL\n\
                 Version            {version_label}\n\
                 KEM variant        {variant_name}\n\
                 Nonce              {nonce_hex}\n\
                 Original size      {original_size} bytes",
            );
            if *version == format::VERSION_V5 || *version == format::VERSION_V6 {
                result.push_str(&format!("\nChunk size         {chunk_size} bytes"));
            }
            if *version == format::VERSION_V6 {
                let algo = match compression_algo {
                    v if *v == format::COMPRESSION_NONE => "none".to_owned(),
                    v if *v == format::COMPRESSION_ZSTD => "zstd".to_owned(),
                    x => format!("{x:#04x}"),
                };
                result.push_str(&format!("\nCompression        {algo}"));
            }
            result.push_str("\n\nHeader validity    OK");
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
            version,
            slot_count,
            nonce,
            original_size,
        } => {
            let nonce_str: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let (ver_label, slots_label) = if *version == VERSION_V9 {
                (
                    "0x09  (padded anonymous multi-recipient)".to_owned(),
                    format!("{slot_count}  (padded to next power of two; key types hidden)"),
                )
            } else {
                (
                    "0x08  (variant-blind anonymous multi-recipient)".to_owned(),
                    format!("{slot_count}  (key types hidden)"),
                )
            };
            format!(
                "Magic              PQFL\n\
                 Version            {ver_label}\n\
                 Slots              {slots_label}\n\
                 Nonce              {nonce_str}\n\
                 Original size      {original_size} bytes\n\n\
                 Header validity    OK"
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
        "Magic              PQFL\n\
         Version            {version_label}\n\
         Recipients         {n}\n"
    );
    for (i, r) in recipients.iter().enumerate() {
        let vname = variant_display(r.kem_variant);
        lines.push_str(&format!("  [{i}] variant        {vname}\n"));
    }
    lines.push_str(&format!(
        "Nonce              {nonce_str}\n\
         Original size      {original_size} bytes\n\n\
         Header validity    OK"
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
