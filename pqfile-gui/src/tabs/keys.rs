use crate::app::PqfileApp;
#[cfg(not(target_arch = "wasm32"))]
use crate::colors::{c_accent, c_chrome, c_overlay, c_red, c_surface0, c_text, c_yellow};
use crate::colors::{c_card, c_subtext, c_surface1};
use crate::types::Tab;
#[cfg(not(target_arch = "wasm32"))]
use crate::types::{expiry_days_remaining, read_pem_expiry, KeyDragPayload};
#[cfg(not(target_arch = "wasm32"))]
use crate::types::{pem_variant_name, RecipientEntry};
use crate::widgets::{card, tab_heading_help};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::{copy_text_btn, section_label};
use eframe::egui::{self, RichText};
#[cfg(not(target_arch = "wasm32"))]
use eframe::egui::{Color32, Stroke, Vec2};

#[cfg(not(target_arch = "wasm32"))]
enum KeyAction {
    Remove(usize),
    LoadPub(usize),
    LoadPriv(usize),
    Renew(usize),
}

impl PqfileApp {
    pub(crate) fn show_keys(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Key Management", dark) {
            self.help_modal_open = Some(Tab::Keys);
        }
        ui.label(
            RichText::new(
                "Remember key pairs for quick access, change passphrases, and revoke keys.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        self.show_keys_native(ui, dark);

        #[cfg(target_arch = "wasm32")]
        self.show_keys_wasm(ui, dark);
    }

    #[cfg(target_arch = "wasm32")]
    fn show_keys_wasm(&mut self, ui: &mut egui::Ui, dark: bool) {
        use crate::colors::{c_accent, c_chrome, c_overlay, c_surface0, c_text};
        use crate::types::RecipientEntry;
        use crate::widgets::section_label;

        section_label(ui, "REMEMBERED PUBLIC KEYS", dark);
        ui.label(
            RichText::new(
                "Public keys saved here persist across sessions in browser localStorage \
                 and can be loaded into Encrypt at any time.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(6.0);

        card(ui, c_card(dark), c_surface1(dark), |ui| {
            if self.wasm_saved_pubkeys.is_empty() {
                ui.label(
                    RichText::new(
                        "No saved keys yet. Use the ☆ Remember button in the Encrypt tab \
                         recipients list to save a public key here.",
                    )
                    .size(13.0)
                    .color(c_subtext(dark)),
                );
            } else {
                let mut forget_idx: Option<usize> = None;
                let mut use_idx: Option<usize> = None;
                for (i, (label, _pem)) in self.wasm_saved_pubkeys.iter().enumerate() {
                    if i > 0 {
                        ui.separator();
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(label).size(13.0).color(c_text(dark)));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("Forget").size(11.5).color(c_overlay(dark)),
                                    )
                                    .fill(c_surface0(dark)),
                                )
                                .on_hover_text("Remove from saved keys")
                                .clicked()
                            {
                                forget_idx = Some(i);
                            }
                            ui.add_space(4.0);
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("🔒 Use for Encrypt")
                                            .size(11.5)
                                            .color(c_chrome(dark)),
                                    )
                                    .fill(c_accent(dark)),
                                )
                                .on_hover_text(
                                    "Add to Encrypt recipients and switch to Encrypt tab",
                                )
                                .clicked()
                            {
                                use_idx = Some(i);
                            }
                        });
                    });
                }
                if let Some(i) = forget_idx {
                    self.wasm_saved_pubkeys.remove(i);
                }
                if let Some(i) = use_idx {
                    if let Some((label, pem)) = self.wasm_saved_pubkeys.get(i) {
                        let label = label.clone();
                        let pem = pem.clone();
                        let variant_name = crate::types::pem_variant_name(&pem);
                        if !self.encrypt_recipients.iter().any(|r| r.pem == pem) {
                            self.encrypt_recipients.push(RecipientEntry {
                                name: label,
                                pem,
                                variant_name,
                            });
                        }
                        self.tab = crate::types::Tab::Encrypt;
                    }
                }
            }
        });
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn show_keys_native(&mut self, ui: &mut egui::Ui, dark: bool) {
        use crate::types::KeyEntry;
        use pqfile::keygen;

        section_label(ui, "KEY PAIRS", dark);

        let mut action: Option<KeyAction> = None;

        card(ui, c_card(dark), c_surface1(dark), |ui| {
            if self.keys.is_empty() {
                ui.label(
                    RichText::new("No keys remembered yet. Import a key pair to get started.")
                        .size(13.0)
                        .color(c_overlay(dark)),
                );
            } else {
                for (i, entry) in self.keys.iter().enumerate() {
                    ui.add_space(if i == 0 { 0.0 } else { 10.0 });
                    // Read expiry from disk (PEM file comment).
                    let expiry: Option<String> = std::fs::read_to_string(&entry.pubkey_path)
                        .ok()
                        .as_deref()
                        .and_then(read_pem_expiry);

                    // Build drag payload (read public key PEM from disk).
                    let pub_pem_opt: Option<String> =
                        std::fs::read_to_string(&entry.pubkey_path).ok();

                    let drag_id = egui::Id::new("key_drag").with(i);
                    let mut row_action: Option<KeyAction> = None;
                    if let Some(ref pub_pem) = pub_pem_opt {
                        let payload = std::sync::Arc::new(KeyDragPayload {
                            label: entry.label.clone(),
                            pub_pem: pub_pem.clone(),
                            priv_path: entry.privkey_path.clone(),
                        });
                        ui.dnd_drag_source(drag_id, payload, |ui| {
                            row_action = key_entry_row(ui, i, entry, expiry.as_deref(), dark);
                        });
                    } else {
                        row_action = key_entry_row(ui, i, entry, expiry.as_deref(), dark);
                    }
                    if action.is_none() {
                        action = row_action;
                    }
                    if i + 1 < self.keys.len() {
                        ui.add_space(6.0);
                        ui.separator();
                    }
                }
            }
        });

        match action {
            Some(KeyAction::Remove(i)) => {
                self.keys.remove(i);
            }
            Some(KeyAction::LoadPub(i)) => self.apply_load_pub(i),
            Some(KeyAction::LoadPriv(i)) => self.apply_load_priv(i),
            Some(KeyAction::Renew(i)) => self.apply_renew(i),
            None => {}
        }

        ui.add_space(14.0);

        if ui
            .add(
                egui::Button::new(
                    RichText::new("+ Import Key Pair…")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .clicked()
        {
            if let Some(dir) = rfd::FileDialog::new()
                .set_title("Select the folder containing pubkey.pem")
                .pick_folder()
            {
                let pub_path = dir.join("pubkey.pem");
                if pub_path.exists() {
                    if let Ok(pub_pem) = std::fs::read_to_string(&pub_path) {
                        let fp = keygen::fingerprint_pem(&pub_pem);
                        let priv_path = dir.join("privkey.pem");
                        let privkey_path = if priv_path.exists() {
                            Some(priv_path)
                        } else {
                            None
                        };
                        let label = dir
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "Keys".to_owned());
                        if !self.keys.iter().any(|k| k.pubkey_path == pub_path) {
                            self.keys.push(KeyEntry {
                                label,
                                pubkey_path: pub_path,
                                privkey_path,
                                fingerprint: fp,
                            });
                        }
                    }
                }
            }
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Select the folder that contains pubkey.pem (and optionally privkey.pem).",
            )
            .size(12.0)
            .color(c_overlay(dark)),
        );

        ui.add_space(20.0);
        egui::CollapsingHeader::new("🔑  Change Passphrase")
            .default_open(false)
            .show(ui, |ui| {
                ui.add_space(8.0);
                self.show_repassphrase_section(ui, dark);
            });
        ui.add_space(8.0);
        egui::CollapsingHeader::new("🚫  Revoke Key")
            .default_open(false)
            .show(ui, |ui| {
                ui.add_space(8.0);
                self.show_revoke_section(ui, dark);
            });
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn apply_load_pub(&mut self, i: usize) {
        let path = self.keys[i].pubkey_path.clone();
        // Use the key's label as the recipient display name.
        let label = self.keys[i].label.clone();
        if let Ok(data) = std::fs::read(&path) {
            if let Ok(pem_str) = String::from_utf8(data) {
                if !self.encrypt_recipients.iter().any(|r| r.pem == pem_str) {
                    let variant_name = pem_variant_name(&pem_str);
                    self.encrypt_recipients.push(RecipientEntry {
                        name: label,
                        pem: pem_str,
                        variant_name,
                    });
                }
                self.tab = Tab::Encrypt;
            }
        }
    }

    /// Switch to the Keygen tab pre-filled with the key's label so the user can
    /// generate a replacement key with the same name.
    #[cfg(not(target_arch = "wasm32"))]
    fn apply_renew(&mut self, i: usize) {
        use crate::types::Tab;
        // Pre-fill keygen hardware label and switch tab.
        self.keygen_hardware_label = self.keys[i].label.clone();
        self.tab = Tab::Keygen;
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn apply_load_priv(&mut self, i: usize) {
        if let Some(path) = self.keys[i].privkey_path.clone() {
            if let Ok(data) = std::fs::read(&path) {
                self.decrypt_privkey.name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "privkey.pem".to_owned());
                self.decrypt_privkey.data = Some(data);
                self.decrypt_privkey.path = Some(path);
                self.tab = Tab::Decrypt;
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn key_entry_row(
    ui: &mut egui::Ui,
    i: usize,
    entry: &crate::types::KeyEntry,
    expiry: Option<&str>,
    dark: bool,
) -> Option<KeyAction> {
    use crate::colors::c_green;

    let pub_exists = entry.pubkey_path.exists();
    let priv_exists = entry
        .privkey_path
        .as_ref()
        .map(|p| p.exists())
        .unwrap_or(false);
    let mut action: Option<KeyAction> = None;

    // Compute expiry status.
    let expiry_info: Option<(String, egui::Color32)> = expiry.and_then(|date| {
        let days = expiry_days_remaining(date)?;
        let (label, color) = if days < 0 {
            (
                format!("✖ Expired {date} ({} days ago)", -days),
                c_red(dark),
            )
        } else if days <= 30 {
            (
                format!(
                    "⚠ Expires {date} (in {days} day{})",
                    if days == 1 { "" } else { "s" }
                ),
                c_yellow(dark),
            )
        } else {
            (
                format!(
                    "Expires {date} (in {days} day{})",
                    if days == 1 { "" } else { "s" }
                ),
                c_green(dark),
            )
        };
        Some((label, color))
    });

    ui.horizontal(|ui| {
        fingerprint_identicon(ui, &entry.fingerprint, dark);
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.label(
                RichText::new(&entry.label)
                    .size(13.0)
                    .color(c_text(dark))
                    .strong(),
            );
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&entry.fingerprint)
                        .size(12.0)
                        .monospace()
                        .color(c_subtext(dark)),
                );
                copy_text_btn(ui, &entry.fingerprint, dark);
            });
            if let Some((label, color)) = &expiry_info {
                ui.label(RichText::new(label).size(11.5).color(*color));
            }
            if !pub_exists {
                ui.label(
                    RichText::new("⚠ pubkey.pem not found")
                        .size(11.0)
                        .color(c_red(dark)),
                );
            } else {
                let path_str = entry
                    .pubkey_path
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                ui.label(RichText::new(&path_str).size(11.0).color(c_overlay(dark)));
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(RichText::new("x").size(11.0).color(c_overlay(dark)))
                        .fill(Color32::TRANSPARENT)
                        .stroke(Stroke::NONE),
                )
                .on_hover_text("Remove from list")
                .clicked()
            {
                action = Some(KeyAction::Remove(i));
            }
            ui.add_space(4.0);
            // Show Renew button when key is expired or near expiry.
            let show_renew = expiry_info
                .as_ref()
                .map(|(_, _)| {
                    expiry
                        .and_then(expiry_days_remaining)
                        .map(|d| d <= 30)
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if show_renew {
                if ui
                    .add(
                        egui::Button::new(RichText::new("↺ Renew").size(12.0).color(c_text(dark)))
                            .fill(c_surface0(dark))
                            .min_size(Vec2::new(70.0, 24.0)),
                    )
                    .on_hover_text("Open Keygen tab pre-filled with this key's label")
                    .clicked()
                {
                    action = Some(KeyAction::Renew(i));
                }
                ui.add_space(4.0);
            }
            if ui
                .add_enabled(
                    priv_exists,
                    egui::Button::new(RichText::new("🔓 Decrypt").size(12.0).color(c_text(dark)))
                        .fill(c_surface0(dark))
                        .min_size(Vec2::new(80.0, 24.0)),
                )
                .on_hover_text("Load private key into Decrypt tab")
                .clicked()
            {
                action = Some(KeyAction::LoadPriv(i));
            }
            ui.add_space(4.0);
            if ui
                .add_enabled(
                    pub_exists,
                    egui::Button::new(RichText::new("🔒 Encrypt").size(12.0).color(c_text(dark)))
                        .fill(c_surface0(dark))
                        .min_size(Vec2::new(80.0, 24.0)),
                )
                .on_hover_text("Load public key into Encrypt tab")
                .clicked()
            {
                action = Some(KeyAction::LoadPub(i));
            }
        });
    });
    action
}

/// Draw a small 5×5 identicon derived from a fingerprint hex string.
/// Each key gets a unique color+pattern so they are visually distinct at a glance.
#[cfg(not(target_arch = "wasm32"))]
fn fingerprint_identicon(ui: &mut egui::Ui, fingerprint: &str, dark: bool) {
    const CELL: f32 = 5.0;
    const GRID: usize = 5;
    const PAD: f32 = 2.0;
    let total = PAD * 2.0 + GRID as f32 * CELL;

    let hex_bytes: Vec<u8> = fingerprint
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .as_bytes()
        .chunks(2)
        .filter_map(|ch| u8::from_str_radix(std::str::from_utf8(ch).ok()?, 16).ok())
        .collect();

    let (rect, _) = ui.allocate_exact_size(egui::vec2(total, total), egui::Sense::hover());
    if !ui.is_rect_visible(rect) || hex_bytes.len() < 4 {
        return;
    }

    let hue = hex_bytes[0] as f32 / 255.0;
    let (fg_v, bg_v) = if dark { (0.80, 0.18) } else { (0.65, 0.88) };
    let on_color: egui::Color32 = egui::epaint::Hsva {
        h: hue,
        s: 0.65,
        v: fg_v,
        a: 1.0,
    }
    .into();
    let bg_color: egui::Color32 = egui::epaint::Hsva {
        h: hue,
        s: 0.15,
        v: bg_v,
        a: 1.0,
    }
    .into();

    let painter = ui.painter();
    painter.rect_filled(rect, 3.0, bg_color);

    // 5×5 grid with left-right symmetry: 15 unique cells (5 rows × 3 left cols mirrored).
    for row in 0..GRID {
        for col in 0..GRID {
            let sym_col = col.min(GRID - 1 - col);
            let bit_idx = row * 3 + sym_col;
            let byte_idx = 1 + bit_idx / 8;
            let bit_pos = bit_idx % 8;
            let on = hex_bytes
                .get(byte_idx)
                .map(|b| (b >> bit_pos) & 1 == 1)
                .unwrap_or(false);
            if on {
                let x = rect.min.x + PAD + col as f32 * CELL;
                let y = rect.min.y + PAD + row as f32 * CELL;
                painter.rect_filled(
                    egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(CELL - 1.0, CELL - 1.0)),
                    1.0,
                    on_color,
                );
            }
        }
    }
}
