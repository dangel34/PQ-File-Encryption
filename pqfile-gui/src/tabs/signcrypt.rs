use crate::app::PqfileApp;
use crate::colors::{c_card, c_subtext, c_surface1};
use crate::types::SigncryptSubTab;
use crate::types::{OpStatus, Tab};
use crate::widgets::{
    card, file_row, passphrase_row, save_result, section_label, seg_tabs, show_status,
    sig_algorithm_hint, tab_heading_help,
};
use eframe::egui::{self, RichText};
use pqfile::signcrypt;
use std::io::Cursor;

impl PqfileApp {
    pub(crate) fn show_signcrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Sign & Encrypt  (Signcrypt)", dark) {
            self.help_modal_open = Some(Tab::Signcrypt);
        }
        ui.label(
            RichText::new(
                "Sign and encrypt a file in one step. The signature (ML-DSA-65 or \
                 SLH-DSA-SHAKE-192f, detected from the signing key) is embedded inside \
                 the AEAD-authenticated ciphertext and cannot be stripped. \
                 Use Signdecrypt to verify the sender and decrypt in one step.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(10.0);

        seg_tabs(
            ui,
            &mut self.signcrypt_sub_tab,
            &[
                ("Sign + Encrypt", SigncryptSubTab::Encrypt),
                ("Decrypt + Verify", SigncryptSubTab::Decrypt),
            ],
            dark,
        );

        match self.signcrypt_sub_tab {
            SigncryptSubTab::Encrypt => self.show_signcrypt_section(ui, dark),
            SigncryptSubTab::Decrypt => self.show_signdecrypt_section(ui, dark),
        }
    }

    // ── Signcrypt ─────────────────────────────────────────────────────────

    fn show_signcrypt_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "SIGN + ENCRYPT", dark);
        let mut pp_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Signing private key (sign_privkey.pem)",
                &mut self.signcrypt_sk,
                "PEM",
                &["pem"],
                dark,
            );
            sig_algorithm_hint(ui, self.signcrypt_sk.as_str(), dark);
            ui.add_space(4.0);
            pp_submitted = passphrase_row(
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
        crate::widgets::action_button(
            ui,
            "🔏  Sign and Encrypt",
            180.0,
            ready,
            pp_submitted,
            dark,
            || self.do_signcrypt(),
        );

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
            Some(zeroize::Zeroizing::new(
                (*self.signcrypt_sk_passphrase).clone(),
            ))
        };

        let mut output = Vec::new();
        match signcrypt::signcrypt_bytes(
            &sk_pem,
            &pub_pem,
            &data,
            &mut output,
            pqfile::format::CHUNK_SIZE,
            passphrase.as_deref().map(String::as_str),
        ) {
            Ok(()) => {
                let out_name = format!("{}.pqf", self.signcrypt_input.name);
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.signcrypt_input.path.as_deref(),
                    &out_name,
                    &self.settings.output_dir,
                    |p| {
                        let mut q = p.to_path_buf();
                        q.set_extension("pqf");
                        q
                    },
                ));
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

        let mut pp_submitted = false;
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
            pp_submitted = passphrase_row(
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
            sig_algorithm_hint(ui, self.signdecrypt_vk.as_str(), dark);
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
        crate::widgets::action_button(
            ui,
            "🔓  Decrypt and Verify",
            180.0,
            ready,
            pp_submitted,
            dark,
            || self.do_signdecrypt(),
        );

        #[cfg(not(target_arch = "wasm32"))]
        crate::widgets::reveal_button_if_ok(
            ui,
            &self.signdecrypt_status,
            &self.signdecrypt_output_path,
            dark,
        );

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
            Some(zeroize::Zeroizing::new(
                (*self.signdecrypt_privkey_passphrase).clone(),
            ))
        };

        let mut plaintext = Vec::new();
        let reader = Cursor::new(&data);
        match signcrypt::signdecrypt(
            &priv_pem,
            &vk_pem,
            reader,
            &mut plaintext,
            passphrase.as_deref().map(String::as_str),
        ) {
            Ok(()) => {
                let out_name = self
                    .signdecrypt_input
                    .name
                    .strip_suffix(".pqf")
                    .unwrap_or(&self.signdecrypt_input.name)
                    .to_owned();
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.signdecrypt_input.path.as_deref(),
                    &out_name,
                    &self.settings.output_dir,
                    |p| p.with_extension(""),
                ));
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
