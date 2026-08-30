use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1};
use crate::types::{OpStatus, Tab};
use crate::widgets::{
    card, file_row, passphrase_row, section_label, show_status, tab_heading_help,
};
use eframe::egui::{self, RichText, Vec2};
use pqfile::repassphrase;
#[cfg(not(target_arch = "wasm32"))]
use pqfile::revoke;
use std::io::Cursor;
use zeroize::{Zeroize, Zeroizing};

impl PqfileApp {
    pub(crate) fn show_clipboard_tab(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Clipboard", dark) {
            self.help_modal_open = Some(Tab::Clipboard);
        }
        ui.label(
            RichText::new(
                "Encrypt or decrypt short text without writing any file to disk. \
                 Useful for sharing secrets via messaging apps or email.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        self.show_clipboard_section(ui, dark);
    }

    // ── Repassphrase ──────────────────────────────────────────────────────
    // The Change Passphrase and Revoke Key sections are mounted only by the
    // Keys tab's native show fn, so all four methods are dead code on wasm.

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn show_repassphrase_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "CHANGE / UPGRADE PASSPHRASE", dark);
        ui.label(
            RichText::new(
                "Change the passphrase on any encrypted private key, or upgrade a \
                 pqfile <4.0 key (Argon2id p=1) to the current p=4 parameters.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(6.0);
        let mut confirm_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Encrypted private key (.pem)",
                &mut self.repassphrase_key,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "Current passphrase:",
                &mut self.repassphrase_old_passphrase,
                &mut self.repassphrase_old_passphrase_visible,
                "Current passphrase",
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "New passphrase:",
                &mut self.repassphrase_new_passphrase,
                &mut self.repassphrase_new_passphrase_visible,
                "New passphrase",
                dark,
            );
            ui.add_space(2.0);
            confirm_submitted = passphrase_row(
                ui,
                "Confirm new:",
                &mut self.repassphrase_new_passphrase_confirm,
                &mut self.repassphrase_new_passphrase_visible,
                "Confirm new passphrase",
                dark,
            );
            ui.add_space(6.0);
            ui.checkbox(
                &mut self.repassphrase_from_legacy,
                RichText::new("--from-legacy: key was created with pqfile < 4.0 (Argon2id p=1)")
                    .size(12.0)
                    .color(c_subtext(dark)),
            );
        });
        ui.add_space(8.0);

        let ready = self.repassphrase_key.loaded()
            && !self.repassphrase_old_passphrase.is_empty()
            && !self.repassphrase_new_passphrase.is_empty();

        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔑  Change Passphrase")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .on_disabled_hover_text("Load an encrypted key and fill in both passphrase fields.")
            .clicked()
            || (ready
                && (confirm_submitted
                    || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
        {
            self.do_repassphrase();
        }

        show_status(ui, &self.repassphrase_status, dark);
    }

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    fn do_repassphrase(&mut self) {
        if *self.repassphrase_new_passphrase != *self.repassphrase_new_passphrase_confirm {
            self.repassphrase_status = OpStatus::Err("New passphrases do not match.".to_owned());
            return;
        }

        let key_pem = match self.repassphrase_key.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.repassphrase_status =
                    OpStatus::Err("Load an encrypted private key file first.".to_owned());
                return;
            }
        };
        let old_pp = zeroize::Zeroizing::new((*self.repassphrase_old_passphrase).clone());
        let new_pp = zeroize::Zeroizing::new((*self.repassphrase_new_passphrase).clone());
        let from_legacy = self.repassphrase_from_legacy;

        match repassphrase::repassphrase(&key_pem, old_pp.as_str(), new_pp.as_str(), from_legacy) {
            Ok(result) => {
                // Attempt to write back in-place on native; download on WASM.
                #[cfg(not(target_arch = "wasm32"))]
                {
                    if let Some(path) = self.repassphrase_key.path.as_ref() {
                        match crate::widgets::atomic_write_private(
                            path,
                            result.privkey_pem.as_bytes(),
                        ) {
                            Ok(()) => {
                                let note = if from_legacy {
                                    " (upgraded to Argon2id p=4)"
                                } else {
                                    ""
                                };
                                self.repassphrase_status =
                                    OpStatus::Ok(format!("Passphrase updated{note}."));
                                self.repassphrase_old_passphrase.zeroize();
                                self.repassphrase_new_passphrase.zeroize();
                                self.repassphrase_new_passphrase_confirm.zeroize();
                            }
                            Err(e) => {
                                self.repassphrase_status = OpStatus::Err(e.to_string());
                            }
                        }
                        return;
                    }
                }
                // WASM or no path: download the re-encrypted key.
                let name = self
                    .repassphrase_key
                    .name
                    .strip_suffix(".pem")
                    .map(|s| format!("{s}.new.pem"))
                    .unwrap_or_else(|| "privkey.new.pem".to_owned());
                #[cfg(target_arch = "wasm32")]
                crate::widgets::download_bytes(&name, result.privkey_pem.as_bytes());
                #[cfg(not(target_arch = "wasm32"))]
                let _ = name;
                let note = if from_legacy {
                    " (upgraded from p=1 to p=4)"
                } else {
                    ""
                };
                self.repassphrase_status =
                    OpStatus::Ok(format!("Re-encrypted key downloaded{note}."));
                self.repassphrase_old_passphrase.zeroize();
                self.repassphrase_new_passphrase.zeroize();
                self.repassphrase_new_passphrase_confirm.zeroize();
            }
            Err(e) => {
                self.repassphrase_status = OpStatus::Err(e.to_string());
            }
        }
    }

    // ── Revoke ────────────────────────────────────────────────────────────

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) fn show_revoke_section(&mut self, ui: &mut egui::Ui, dark: bool) {
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
            let row_w = ui.available_width();
            ui.horizontal(|ui| {
                ui.label(RichText::new("Reason:").size(13.0).color(c_subtext(dark)));
                ui.add(
                    egui::TextEdit::singleline(&mut self.revoke_reason)
                        .hint_text("e.g. key was compromised")
                        .desired_width(row_w),
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

    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
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

    // ── Clipboard encrypt / decrypt ───────────────────────────────────────

    fn show_clipboard_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        // Auto-clear status hint.
        let auto_clear_note = if self.settings.clipboard_auto_clear {
            format!(
                "Auto-clear active: text is zeroized after {} s of inactivity. \
                 Configure in Settings -> Clipboard.",
                self.settings.clipboard_clear_secs
            )
        } else {
            "Auto-clear is off. Enable it in Settings -> Clipboard.".to_owned()
        };
        ui.label(
            RichText::new(auto_clear_note)
                .size(11.5)
                .color(c_subtext(dark)),
        );
        ui.label(
            RichText::new(
                "This only clears pqfile's own text fields. Your OS clipboard history or a \
                 clipboard manager may retain a separate copy of anything copied here \
                 independently of this app.",
            )
            .size(11.5)
            .color(c_subtext(dark)),
        );
        ui.add_space(10.0);

        // ── Encrypt plain → cipher ────────────────────────────────────────
        section_label(ui, "ENCRYPT TEXT", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Recipient public key",
                &mut self.clipboard_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Plaintext:")
                    .size(13.0)
                    .color(c_subtext(dark)),
            );
            ui.add(
                egui::TextEdit::multiline(&mut *self.clipboard_plain)
                    .hint_text("Type or paste your secret text here…")
                    .desired_width(f32::INFINITY)
                    .desired_rows(4),
            );
        });
        ui.add_space(6.0);

        let enc_ready = self.clipboard_pubkey.loaded() && !self.clipboard_plain.is_empty();
        if ui
            .add_enabled(
                enc_ready,
                egui::Button::new(
                    RichText::new("🔒  Encrypt & Copy")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .clicked()
        {
            self.do_clipboard_encrypt(ui.ctx());
        }
        show_status(ui, &self.clipboard_enc_status, dark);

        ui.add_space(14.0);

        // ── Decrypt cipher → plain ────────────────────────────────────────
        section_label(ui, "DECRYPT TEXT", dark);
        let mut clip_pp_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Your private key",
                &mut self.clipboard_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            clip_pp_submitted = passphrase_row(
                ui,
                "Key passphrase:",
                &mut self.clipboard_passphrase,
                &mut self.clipboard_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("PEM ciphertext (paste here):")
                    .size(13.0)
                    .color(c_subtext(dark)),
            );
            ui.add(
                egui::TextEdit::multiline(&mut self.clipboard_cipher)
                    .hint_text(
                        "-----BEGIN PQFILE CIPHERTEXT-----\n…\n-----END PQFILE CIPHERTEXT-----",
                    )
                    .desired_width(f32::INFINITY)
                    .desired_rows(4),
            );
        });
        ui.add_space(6.0);

        let dec_ready = self.clipboard_privkey.loaded() && !self.clipboard_cipher.is_empty();
        if ui
            .add_enabled(
                dec_ready,
                egui::Button::new(
                    RichText::new("🔓  Decrypt")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(140.0, 32.0)),
            )
            .clicked()
            || (dec_ready
                && (clip_pp_submitted
                    || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
        {
            self.do_clipboard_decrypt();
        }
        show_status(ui, &self.clipboard_dec_status, dark);
    }

    fn do_clipboard_encrypt(&mut self, ctx: &egui::Context) {
        self.clipboard_last_used = Some(crate::types::current_unix_secs());
        let pub_pem = match self.clipboard_pubkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.clipboard_enc_status =
                    OpStatus::Err("Load a recipient public key first.".to_owned());
                return;
            }
        };
        let data = Zeroizing::new(self.clipboard_plain.as_bytes().to_vec());
        let original_size = data.len() as u64;
        let mut output = Vec::new();
        match pqfile::encrypt::encrypt_stream(
            &pub_pem,
            original_size,
            pqfile::format::CHUNK_SIZE,
            &mut Cursor::new(data.as_slice()),
            &mut output,
        ) {
            Ok(()) => {
                let cipher_pem = pem::encode(&pem::Pem::new("PQFILE CIPHERTEXT", output));
                ctx.copy_text(cipher_pem.clone());
                self.clipboard_cipher = cipher_pem;
                self.clipboard_enc_status =
                    OpStatus::Ok("Encrypted and copied to clipboard.".to_owned());
            }
            Err(e) => {
                self.clipboard_enc_status = OpStatus::Err(e.to_string());
            }
        }
    }

    fn do_clipboard_decrypt(&mut self) {
        self.clipboard_last_used = Some(crate::types::current_unix_secs());
        let priv_pem = match self.clipboard_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.clipboard_dec_status = OpStatus::Err("Load a private key first.".to_owned());
                return;
            }
        };
        let passphrase = if self.clipboard_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.clipboard_passphrase).clone(),
            ))
        };

        // Decode PEM wrapper to get raw .pqf bytes.
        let cipher_bytes = match pem::parse(self.clipboard_cipher.trim()) {
            Ok(p) => p.into_contents(),
            Err(e) => {
                self.clipboard_dec_status = OpStatus::Err(format!("Invalid PEM ciphertext: {e}"));
                return;
            }
        };

        let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        match pqfile::decrypt::decrypt_stream(
            &priv_pem,
            &mut Cursor::new(&cipher_bytes),
            &mut *out,
            passphrase.as_deref().map(String::as_str),
        ) {
            Ok(()) => match std::str::from_utf8(&out) {
                Ok(plain) => {
                    self.clipboard_plain.zeroize();
                    self.clipboard_plain.push_str(plain);
                    self.clipboard_dec_status = OpStatus::Ok("Decrypted successfully.".to_owned());
                }
                Err(e) => {
                    self.clipboard_dec_status =
                        OpStatus::Err(format!("Decrypted but content is not valid UTF-8: {e}"));
                }
            },
            Err(e) => {
                self.clipboard_dec_status = OpStatus::Err(e.to_string());
            }
        }
    }
}
