use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1};
#[cfg(not(target_arch = "wasm32"))]
use crate::colors::{c_surface0, c_text};
use crate::types::{OpStatus, Tab};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::reveal_in_explorer;
use crate::widgets::{
    card, file_row, passphrase_row, save_result, section_label, show_status, tab_heading_help,
};
use eframe::egui::{self, RichText, Vec2};
use pqfile::signcrypt;
use std::io::Cursor;

impl PqfileApp {
    pub(crate) fn show_signcrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Signcrypt  (ML-DSA-65 + Encryption)", dark) {
            self.help_modal_open = Some(Tab::Signcrypt);
        }
        ui.label(
            RichText::new(
                "Sign and encrypt a file in one step. The ML-DSA-65 signature is \
                 embedded inside the AEAD-authenticated ciphertext and cannot be stripped. \
                 Use Signdecrypt to verify the sender and decrypt in one step.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        self.show_signcrypt_section(ui, dark);
        ui.add_space(20.0);
        self.show_signdecrypt_section(ui, dark);
    }

    // ── Signcrypt ─────────────────────────────────────────────────────────

    fn show_signcrypt_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "SIGN + ENCRYPT", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Signing private key (sign_privkey.pem)",
                &mut self.signcrypt_sk,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "Signing key passphrase:",
                &mut self.signcrypt_sk_passphrase,
                &mut self.signcrypt_sk_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Recipient public key (pubkey.pem)",
                &mut self.signcrypt_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "File to sign and encrypt",
                &mut self.signcrypt_input,
                "Any file",
                &[],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.signcrypt_sk.loaded()
            && self.signcrypt_pubkey.loaded()
            && self.signcrypt_input.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔏  Sign and Encrypt")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
        {
            self.do_signcrypt();
        }

        show_status(ui, &self.signcrypt_status, dark);
    }

    fn do_signcrypt(&mut self) {
        let sk_pem = match self.signcrypt_sk.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.signcrypt_status =
                    OpStatus::Err("Load a signing private key first.".to_owned());
                return;
            }
        };
        let pub_pem = match self.signcrypt_pubkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.signcrypt_status =
                    OpStatus::Err("Load a recipient public key first.".to_owned());
                return;
            }
        };
        let data = match self.signcrypt_input.data.clone() {
            Some(d) => d,
            None => {
                self.signcrypt_status =
                    OpStatus::Err("Choose a file to sign and encrypt.".to_owned());
                return;
            }
        };
        let passphrase = if self.signcrypt_sk_passphrase.is_empty() {
            None
        } else {
            Some((*self.signcrypt_sk_passphrase).clone())
        };

        let mut output = Vec::new();
        match signcrypt::signcrypt_bytes(
            &sk_pem,
            &pub_pem,
            &data,
            &mut output,
            pqfile::format::CHUNK_SIZE,
            passphrase.as_deref(),
        ) {
            Ok(()) => {
                let out_name = format!("{}.pqf", self.signcrypt_input.name);
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = {
                    use std::path::PathBuf;
                    let base = self
                        .signcrypt_input
                        .path
                        .as_ref()
                        .map(|p| {
                            let mut q = p.clone();
                            q.set_extension("pqf");
                            q
                        })
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
                self.signcrypt_status = save_result(
                    &out_name,
                    &output,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.signcrypt_status = OpStatus::Err(e.to_string());
            }
        }
    }

    // ── Signdecrypt ───────────────────────────────────────────────────────

    fn show_signdecrypt_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "DECRYPT + VERIFY  (SIGNDECRYPT)", dark);

        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new(
                    "Warning: plaintext is streamed to the output before the signature \
                     is verified. Use the output only after this operation returns success.",
                )
                .size(12.0)
                .color(c_subtext(dark)),
            );
        });
        ui.add_space(6.0);

        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Decryption private key (privkey.pem)",
                &mut self.signdecrypt_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "Decryption key passphrase:",
                &mut self.signdecrypt_privkey_passphrase,
                &mut self.signdecrypt_privkey_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Sender's verifying key (sign_pubkey.pem)",
                &mut self.signdecrypt_vk,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Signcrypted file (.pqf)",
                &mut self.signdecrypt_input,
                "PQF",
                &["pqf"],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.signdecrypt_privkey.loaded()
            && self.signdecrypt_vk.loaded()
            && self.signdecrypt_input.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔓  Decrypt and Verify")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
        {
            self.do_signdecrypt();
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if matches!(&self.signdecrypt_status, OpStatus::Ok(_)) {
                if let Some(ref path) = self.signdecrypt_output_path.clone() {
                    ui.add_space(4.0);
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("📂  Reveal").size(12.0).color(c_text(dark)),
                            )
                            .fill(c_surface0(dark)),
                        )
                        .clicked()
                    {
                        reveal_in_explorer(path);
                    }
                }
            }
        }

        show_status(ui, &self.signdecrypt_status, dark);
    }

    fn do_signdecrypt(&mut self) {
        let priv_pem = match self.signdecrypt_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.signdecrypt_status =
                    OpStatus::Err("Load a decryption private key first.".to_owned());
                return;
            }
        };
        let vk_pem = match self.signdecrypt_vk.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.signdecrypt_status =
                    OpStatus::Err("Load the sender's verifying key first.".to_owned());
                return;
            }
        };
        let data = match self.signdecrypt_input.data.clone() {
            Some(d) => d,
            None => {
                self.signdecrypt_status =
                    OpStatus::Err("Choose a signcrypted .pqf file first.".to_owned());
                return;
            }
        };
        let passphrase = if self.signdecrypt_privkey_passphrase.is_empty() {
            None
        } else {
            Some((*self.signdecrypt_privkey_passphrase).clone())
        };

        let mut plaintext = Vec::new();
        let reader = Cursor::new(&data);
        match signcrypt::signdecrypt(
            &priv_pem,
            &vk_pem,
            reader,
            &mut plaintext,
            passphrase.as_deref(),
        ) {
            Ok(()) => {
                let out_name = self
                    .signdecrypt_input
                    .name
                    .strip_suffix(".pqf")
                    .unwrap_or(&self.signdecrypt_input.name)
                    .to_owned();
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = {
                    use std::path::PathBuf;
                    let base = self
                        .signdecrypt_input
                        .path
                        .as_ref()
                        .map(|p| p.with_extension(""))
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
                #[cfg(not(target_arch = "wasm32"))]
                {
                    self.signdecrypt_output_path = native_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned());
                }
                self.signdecrypt_status = save_result(
                    &out_name,
                    &plaintext,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.signdecrypt_status = OpStatus::Err(e.to_string());
            }
        }
    }
}
