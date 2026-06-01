use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1};
use crate::types::OpStatus;
use crate::widgets::{
    card, file_row, passphrase_row, save_result, section_label, show_status, tab_heading,
};
use eframe::egui::{self, RichText, Vec2};
use pqfile::rekey;
#[cfg(not(target_arch = "wasm32"))]
use pqfile::revoke;
use std::io::Cursor;

impl PqfileApp {
    pub(crate) fn show_tools(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Tools", dark);
        ui.label(
            RichText::new("Key revocation and file rekeying utilities.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        self.show_revoke_section(ui, dark);
        ui.add_space(20.0);
        self.show_rekey_section(ui, dark);
    }

    // ── Revoke ────────────────────────────────────────────────────────────

    fn show_revoke_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "REVOKE KEY", dark);
        ui.label(
            RichText::new(
                "Creates a .revoked sidecar alongside the public key file. \
                 Any subsequent encrypt using that key path will be blocked.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(6.0);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Public key to revoke",
                &mut self.revoke_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Reason:").size(13.0).color(c_subtext(dark)));
                ui.add(
                    egui::TextEdit::singleline(&mut self.revoke_reason)
                        .hint_text("e.g. key was compromised")
                        .desired_width(ui.available_width()),
                );
            });
        });
        ui.add_space(8.0);

        let ready = self.revoke_pubkey.loaded();

        // Revocation requires writing to disk (creating the .revoked sidecar alongside
        // the pubkey file), so it only works when we have an actual file path.
        #[cfg(not(target_arch = "wasm32"))]
        let path_available = self.revoke_pubkey.path.is_some();
        #[cfg(target_arch = "wasm32")]
        let path_available = false;

        if ui
            .add_enabled(
                ready && path_available,
                egui::Button::new(
                    RichText::new("🚫  Revoke Key")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .on_disabled_hover_text(if !ready {
                "Load a public key file first."
            } else {
                "Revocation requires the native desktop app (needs file system access)."
            })
            .clicked()
        {
            self.do_revoke();
        }

        #[cfg(target_arch = "wasm32")]
        if ready && !path_available {
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Revocation creates a sidecar file alongside pubkey.pem and requires \
                     the native desktop app.",
                )
                .size(12.0)
                .color(c_subtext(dark)),
            );
        }

        show_status(ui, &self.revoke_status, dark);
    }

    fn do_revoke(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let path = match self.revoke_pubkey.path.as_ref() {
                Some(p) => p.clone(),
                None => {
                    self.revoke_status =
                        OpStatus::Err("Load a public key file from disk first.".to_owned());
                    return;
                }
            };
            match revoke::revoke_key(&path, &self.revoke_reason) {
                Ok(fp) => {
                    self.revoke_status = OpStatus::Ok(format!(
                        "Revoked. Fingerprint: {fp}. Created {}",
                        revoke::revoked_path_for(&path).display()
                    ));
                }
                Err(e) => {
                    self.revoke_status = OpStatus::Err(e.to_string());
                }
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.revoke_status =
                OpStatus::Err("Revocation is not supported in the web version.".to_owned());
        }
    }

    // ── Rekey ─────────────────────────────────────────────────────────────

    fn show_rekey_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "REKEY FILE", dark);
        ui.label(
            RichText::new(
                "Switch a v3/v5 encrypted file to a new recipient without re-encrypting the payload. \
                 Only supported for files using the default 64 KiB chunk size.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(6.0);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Old private key (for decapsulation)",
                &mut self.rekey_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "Old key passphrase:",
                &mut self.rekey_privkey_passphrase,
                &mut self.rekey_privkey_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "New recipient public key",
                &mut self.rekey_new_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Encrypted file to rekey (.pqf)",
                &mut self.rekey_input,
                "PQF",
                &["pqf"],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.rekey_privkey.loaded()
            && self.rekey_new_pubkey.loaded()
            && self.rekey_input.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔄  Rekey File")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .clicked()
        {
            self.do_rekey();
        }

        show_status(ui, &self.rekey_status, dark);
    }

    fn do_rekey(&mut self) {
        let old_priv = match self.rekey_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.rekey_status = OpStatus::Err("Load the old private key first.".to_owned());
                return;
            }
        };
        let new_pub = match self.rekey_new_pubkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.rekey_status =
                    OpStatus::Err("Load the new recipient public key first.".to_owned());
                return;
            }
        };
        let data = match self.rekey_input.data.clone() {
            Some(d) => d,
            None => {
                self.rekey_status =
                    OpStatus::Err("Choose the .pqf file to rekey first.".to_owned());
                return;
            }
        };
        let passphrase = if self.rekey_privkey_passphrase.is_empty() {
            None
        } else {
            Some((*self.rekey_privkey_passphrase).clone())
        };

        let mut output = Vec::new();
        let mut reader = Cursor::new(&data);
        match rekey::rekey_stream(
            &old_priv,
            &new_pub,
            &mut reader,
            &mut output,
            passphrase.as_deref(),
        ) {
            Ok(()) => {
                let out_name = self.rekey_input.name.clone();
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = {
                    use std::path::PathBuf;
                    let base = self
                        .rekey_input
                        .path
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(&out_name));
                    let path = if self.settings.output_dir.is_empty() {
                        base
                    } else {
                        PathBuf::from(&self.settings.output_dir)
                            .join(base.file_name().unwrap_or_default())
                    };
                    Some(path)
                };
                #[cfg(target_arch = "wasm32")]
                let native_path: Option<std::path::PathBuf> = None;
                self.rekey_status = save_result(
                    &out_name,
                    &output,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.rekey_status = OpStatus::Err(e.to_string());
            }
        }
    }
}
