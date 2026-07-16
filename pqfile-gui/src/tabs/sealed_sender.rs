use crate::app::PqfileApp;
#[cfg(not(target_arch = "wasm32"))]
use crate::colors::c_text;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1, c_yellow};
use crate::types::{OpStatus, SealedSenderSubTab, Tab};
use crate::widgets::{
    card, file_row, passphrase_row, save_result, section_label, seg_tabs, show_status,
    tab_heading_help,
};
use eframe::egui::{self, RichText, Vec2};
use pqfile::sealed_sender;
use zeroize::Zeroize;

impl PqfileApp {
    pub(crate) fn show_sealed_sender(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Sealed Sender", dark) {
            self.help_modal_open = Some(Tab::SealedSender);
        }
        ui.label(
            RichText::new(
                "Prove your identity to a specific recipient without leaving behind proof a \
                 third party could ever check. Uses a separate X25519 identity key pair from \
                 your encryption and signing keys.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(10.0);

        seg_tabs(
            ui,
            &mut self.sealed_sender_sub_tab,
            &[
                ("Identity Keys", SealedSenderSubTab::Identity),
                ("Seal", SealedSenderSubTab::Seal),
                ("Unseal", SealedSenderSubTab::Unseal),
            ],
            dark,
        );

        match self.sealed_sender_sub_tab {
            SealedSenderSubTab::Identity => self.show_identity_keygen_section(ui, dark),
            SealedSenderSubTab::Seal => self.show_seal_section(ui, dark),
            SealedSenderSubTab::Unseal => self.show_unseal_section(ui, dark),
        }
    }

    // ── Identity keygen ───────────────────────────────────────────────────

    fn show_identity_keygen_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "GENERATE IDENTITY KEY PAIR", dark);

        #[cfg(not(target_arch = "wasm32"))]
        {
            let dir_display = if self.settings.output_dir.is_empty() {
                "Not set (configure in Settings)".to_owned()
            } else {
                self.settings.output_dir.clone()
            };
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.label(RichText::new(dir_display).size(13.0).color(
                    if self.settings.output_dir.is_empty() {
                        crate::colors::c_overlay(dark)
                    } else {
                        c_text(dark)
                    },
                ));
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "Writes identity_pubkey.pem and identity_privkey.pem. \
                         Change the directory in Settings > Default Output Directory.",
                    )
                    .size(11.5)
                    .color(crate::colors::c_overlay(dark)),
                );
            });
            ui.add_space(10.0);
        }
        #[cfg(target_arch = "wasm32")]
        {
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.label(
                    RichText::new(
                        "identity_pubkey.pem and identity_privkey.pem will be downloaded to \
                         your downloads folder.",
                    )
                    .size(13.0)
                    .color(c_subtext(dark)),
                );
            });
            ui.add_space(10.0);
        }

        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.checkbox(
                &mut self.identity_keygen_use_passphrase,
                RichText::new("Protect the identity private key with a passphrase")
                    .size(13.0)
                    .color(c_subtext(dark)),
            );
            if self.identity_keygen_use_passphrase {
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::singleline(&mut *self.identity_keygen_passphrase)
                        .hint_text("Enter passphrase…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::singleline(&mut *self.identity_keygen_passphrase_confirm)
                        .hint_text("Confirm passphrase…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            }
        });
        ui.add_space(10.0);

        if ui
            .add(
                egui::Button::new(
                    RichText::new("⚡  Generate Identity Key Pair")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(220.0, 32.0)),
            )
            .clicked()
        {
            self.do_identity_keygen();
        }

        show_status(ui, &self.identity_keygen_status, dark);
    }

    fn do_identity_keygen(&mut self) {
        let passphrase: Option<zeroize::Zeroizing<String>> = if self.identity_keygen_use_passphrase
        {
            if *self.identity_keygen_passphrase != *self.identity_keygen_passphrase_confirm {
                self.identity_keygen_status = OpStatus::Err("Passphrases do not match.".to_owned());
                return;
            }
            if self.identity_keygen_passphrase.is_empty() {
                self.identity_keygen_status =
                    OpStatus::Err("Enter a passphrase or uncheck the option.".to_owned());
                return;
            }
            Some(self.identity_keygen_passphrase.clone())
        } else {
            None
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            if self.settings.output_dir.trim().is_empty() {
                self.identity_keygen_status =
                    OpStatus::Err("Set a default output directory in Settings first.".to_owned());
                return;
            }
            let dir = std::path::Path::new(&self.settings.output_dir);
            let force = !self.settings.confirm_overwrite;
            self.identity_keygen_status = match sealed_sender::identity_keygen(
                dir,
                force,
                passphrase.as_deref().map(String::as_str),
            ) {
                Ok(r) => OpStatus::Ok(format!(
                    "Identity keys saved to {}\nFingerprint: {}",
                    dir.display(),
                    r.pk_fingerprint,
                )),
                Err(e) => OpStatus::Err(e.to_string()),
            };
        }

        #[cfg(target_arch = "wasm32")]
        {
            match sealed_sender::identity_keygen_bytes(passphrase.as_deref().map(String::as_str)) {
                Ok(r) => {
                    crate::widgets::download_bytes("identity_pubkey.pem", r.pk_pem.as_bytes());
                    crate::widgets::download_bytes("identity_privkey.pem", r.sk_pem.as_bytes());
                    self.identity_keygen_status = OpStatus::Ok(format!(
                        "identity_pubkey.pem and identity_privkey.pem downloaded.\n\
                         Fingerprint: {}",
                        r.pk_fingerprint,
                    ));
                }
                Err(e) => self.identity_keygen_status = OpStatus::Err(e.to_string()),
            }
        }

        self.identity_keygen_passphrase.zeroize();
        self.identity_keygen_passphrase_confirm.zeroize();
    }

    // ── Seal ──────────────────────────────────────────────────────────────

    fn show_seal_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "SEAL (ENCRYPT WITH DENIABLE AUTHENTICATION)", dark);
        let mut pp_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Your identity private key (identity_privkey.pem)",
                &mut self.seal_sender_identity_key,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            pp_submitted = passphrase_row(
                ui,
                "Identity key passphrase:",
                &mut self.seal_sender_identity_passphrase,
                &mut self.seal_sender_identity_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Recipient's identity public key (identity_pubkey.pem)",
                &mut self.seal_recipient_identity_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Recipient's encryption public key (pubkey.pem)",
                &mut self.seal_recipient_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "File to seal and encrypt",
                &mut self.seal_input,
                "Any file",
                &[],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.seal_sender_identity_key.loaded()
            && self.seal_recipient_identity_pubkey.loaded()
            && self.seal_recipient_pubkey.loaded()
            && self.seal_input.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🕶  Seal")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
            || (ready
                && (pp_submitted
                    || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
        {
            self.do_seal();
        }

        #[cfg(not(target_arch = "wasm32"))]
        crate::widgets::reveal_button_if_ok(ui, &self.seal_status, &self.seal_output_path, dark);

        show_status(ui, &self.seal_status, dark);
    }

    fn do_seal(&mut self) {
        let sk_pem = match self.seal_sender_identity_key.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.seal_status =
                    OpStatus::Err("Load your identity private key first.".to_owned());
                return;
            }
        };
        let recipient_identity_pk_pem = match self
            .seal_recipient_identity_pubkey
            .as_str()
            .map(str::to_owned)
        {
            Some(s) => s,
            None => {
                self.seal_status =
                    OpStatus::Err("Load the recipient's identity public key first.".to_owned());
                return;
            }
        };
        let recipient_pubkey_pem = match self.seal_recipient_pubkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.seal_status =
                    OpStatus::Err("Load the recipient's encryption public key first.".to_owned());
                return;
            }
        };
        let data = match self.seal_input.data.clone() {
            Some(d) => d,
            None => {
                self.seal_status = OpStatus::Err("Choose a file to seal.".to_owned());
                return;
            }
        };
        let passphrase = if self.seal_sender_identity_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.seal_sender_identity_passphrase).clone(),
            ))
        };

        let mut output = Vec::new();
        match sealed_sender::seal_bytes(
            &sk_pem,
            passphrase.as_deref().map(String::as_str),
            &recipient_identity_pk_pem,
            &recipient_pubkey_pem,
            &data,
            &mut output,
            pqfile::format::CHUNK_SIZE,
        ) {
            Ok(()) => {
                let out_name = format!("{}.pqf", self.seal_input.name);
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.seal_input.path.as_deref(),
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
                #[cfg(not(target_arch = "wasm32"))]
                {
                    self.seal_output_path = native_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned());
                }
                self.seal_status = save_result(
                    &out_name,
                    &output,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.seal_status = OpStatus::Err(e.to_string());
            }
        }
        self.seal_sender_identity_passphrase.zeroize();
    }

    // ── Unseal ────────────────────────────────────────────────────────────

    fn show_unseal_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "UNSEAL (DECRYPT + VERIFY SENDER)", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.label(
                RichText::new(
                    "No plaintext is released until the deniable-authentication tag verifies: \
                     unlike Signdecrypt, this is fully buffered internally.",
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
                "Your decryption private key (privkey.pem)",
                &mut self.unseal_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            pp_submitted |= passphrase_row(
                ui,
                "Decryption key passphrase:",
                &mut self.unseal_privkey_passphrase,
                &mut self.unseal_privkey_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Your identity private key (identity_privkey.pem)",
                &mut self.unseal_identity_key,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            pp_submitted |= passphrase_row(
                ui,
                "Identity key passphrase:",
                &mut self.unseal_identity_passphrase,
                &mut self.unseal_identity_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Sender's identity public key (identity_pubkey.pem)",
                &mut self.unseal_sender_identity_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Sealed file (.pqf)",
                &mut self.unseal_input,
                "PQF",
                &["pqf"],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.unseal_privkey.loaded()
            && self.unseal_identity_key.loaded()
            && self.unseal_sender_identity_pubkey.loaded()
            && self.unseal_input.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔓  Unseal")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
            || (ready
                && (pp_submitted
                    || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
        {
            self.do_unseal();
        }

        #[cfg(not(target_arch = "wasm32"))]
        crate::widgets::reveal_button_if_ok(
            ui,
            &self.unseal_status,
            &self.unseal_output_path,
            dark,
        );

        if let OpStatus::Err(m) = &self.unseal_status {
            if m.contains("authentication failed") {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "The claimed sender's identity key did not produce a matching tag. \
                         Either the file was not sealed for you, or the sender identity is wrong.",
                    )
                    .size(12.0)
                    .color(c_yellow(dark)),
                );
            }
        }

        show_status(ui, &self.unseal_status, dark);
    }

    fn do_unseal(&mut self) {
        let priv_pem = match self.unseal_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.unseal_status =
                    OpStatus::Err("Load your decryption private key first.".to_owned());
                return;
            }
        };
        let identity_sk_pem = match self.unseal_identity_key.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.unseal_status =
                    OpStatus::Err("Load your identity private key first.".to_owned());
                return;
            }
        };
        let sender_identity_pk_pem = match self
            .unseal_sender_identity_pubkey
            .as_str()
            .map(str::to_owned)
        {
            Some(s) => s,
            None => {
                self.unseal_status =
                    OpStatus::Err("Load the sender's identity public key first.".to_owned());
                return;
            }
        };
        let data = match self.unseal_input.data.clone() {
            Some(d) => d,
            None => {
                self.unseal_status = OpStatus::Err("Choose a sealed .pqf file first.".to_owned());
                return;
            }
        };
        let passphrase = if self.unseal_privkey_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.unseal_privkey_passphrase).clone(),
            ))
        };
        let identity_passphrase = if self.unseal_identity_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.unseal_identity_passphrase).clone(),
            ))
        };

        match sealed_sender::unseal_bytes(
            &priv_pem,
            passphrase.as_deref().map(String::as_str),
            &identity_sk_pem,
            identity_passphrase.as_deref().map(String::as_str),
            &sender_identity_pk_pem,
            data.as_slice(),
        ) {
            Ok(plaintext) => {
                let out_name = self
                    .unseal_input
                    .name
                    .strip_suffix(".pqf")
                    .unwrap_or(&self.unseal_input.name)
                    .to_owned();
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.unseal_input.path.as_deref(),
                    &out_name,
                    &self.settings.output_dir,
                    |p| p.with_extension(""),
                ));
                #[cfg(target_arch = "wasm32")]
                let native_path: Option<std::path::PathBuf> = None;
                #[cfg(not(target_arch = "wasm32"))]
                {
                    self.unseal_output_path = native_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().into_owned());
                }
                self.unseal_status = save_result(
                    &out_name,
                    &plaintext,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.unseal_status = OpStatus::Err(e.to_string());
            }
        }
        self.unseal_privkey_passphrase.zeroize();
        self.unseal_identity_passphrase.zeroize();
    }
}
