use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1};
#[cfg(not(target_arch = "wasm32"))]
use crate::colors::{c_overlay, c_surface0, c_text};
use crate::types::OpStatus;
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::reveal_in_explorer;
use crate::widgets::{
    card, file_row, passphrase_row, save_result, section_label, show_status, tab_heading,
};
use eframe::egui::{self, RichText, Vec2};
use pqfile::sign;

impl PqfileApp {
    pub(crate) fn show_sign(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Digital Signatures  (ML-DSA-65)", dark);
        ui.label(
            RichText::new(
                "Generate ML-DSA-65 signing key pairs, sign any file with a private key, \
                 and verify detached .sig signatures.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        self.show_sign_keygen_section(ui, dark);
        ui.add_space(20.0);
        self.show_sign_file_section(ui, dark);
        ui.add_space(20.0);
        self.show_verify_section(ui, dark);
    }

    // ── Key generation ─────────────────────────────────────────────────────

    fn show_sign_keygen_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "KEY GENERATION", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            // Output directory (native) or download note (WASM)
            #[cfg(not(target_arch = "wasm32"))]
            {
                ui.horizontal(|ui| {
                    let display = if self.settings.output_dir.is_empty() {
                        RichText::new("Not set - click Browse to choose a directory")
                            .size(13.0)
                            .color(c_overlay(dark))
                    } else {
                        RichText::new(&self.settings.output_dir)
                            .size(13.0)
                            .color(c_text(dark))
                    };
                    ui.label(
                        RichText::new("Output dir:")
                            .size(13.0)
                            .color(c_subtext(dark)),
                    );
                    ui.add_space(4.0);
                    ui.label(display);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Browse…").size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .clicked()
                        {
                            if let Some(p) = rfd::FileDialog::new()
                                .set_title("Choose output directory")
                                .pick_folder()
                            {
                                self.settings.output_dir = p.to_string_lossy().into_owned();
                            }
                        }
                    });
                });
                ui.add_space(6.0);
            }
            #[cfg(target_arch = "wasm32")]
            {
                ui.label(
                    RichText::new(
                        "sign_pubkey.pem and sign_privkey.pem will be downloaded to your downloads folder.",
                    )
                    .size(13.0)
                    .color(c_subtext(dark)),
                );
                ui.add_space(6.0);
            }

            ui.checkbox(
                &mut self.sign_keygen_use_passphrase,
                RichText::new("Protect private signing key with passphrase")
                    .size(13.0)
                    .color(c_subtext(dark)),
            );

            if self.sign_keygen_use_passphrase {
                ui.add_space(6.0);
                passphrase_row(
                    ui,
                    "Passphrase:",
                    &mut self.sign_keygen_passphrase,
                    &mut self.sign_keygen_passphrase_visible,
                    "Enter passphrase",
                    dark,
                );
                ui.add_space(2.0);
                passphrase_row(
                    ui,
                    "Confirm:",
                    &mut self.sign_keygen_passphrase_confirm,
                    &mut self.sign_keygen_passphrase_visible,
                    "Confirm passphrase",
                    dark,
                );
            }
        });
        ui.add_space(8.0);

        if ui
            .add(
                egui::Button::new(
                    RichText::new("🔑  Generate Signing Keys")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(200.0, 32.0)),
            )
            .clicked()
        {
            self.do_sign_keygen();
        }

        show_status(ui, &self.sign_keygen_status, dark);
    }

    fn do_sign_keygen(&mut self) {
        let passphrase: Option<String> = if self.sign_keygen_use_passphrase {
            let pp = (*self.sign_keygen_passphrase).clone();
            let pc = (*self.sign_keygen_passphrase_confirm).clone();
            if pp != pc {
                self.sign_keygen_status = OpStatus::Err("Passphrases do not match.".to_owned());
                return;
            }
            if pp.is_empty() {
                self.sign_keygen_status =
                    OpStatus::Err("Enter a passphrase or uncheck the option.".to_owned());
                return;
            }
            Some(pp)
        } else {
            None
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            let out_dir = if self.settings.output_dir.is_empty() {
                std::env::current_dir().unwrap_or_default()
            } else {
                std::path::PathBuf::from(&self.settings.output_dir)
            };
            let force = !self.settings.confirm_overwrite;
            match sign::sign_keygen(&out_dir, force, passphrase.as_deref()) {
                Ok(r) => {
                    self.sign_keygen_passphrase.clear();
                    self.sign_keygen_passphrase_confirm.clear();
                    self.sign_keygen_status = OpStatus::Ok(format!(
                        "Saved to {}   Fingerprint: {}",
                        out_dir.display(),
                        r.vk_fingerprint,
                    ));
                }
                Err(e) => {
                    self.sign_keygen_status = OpStatus::Err(e.to_string());
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            use crate::widgets::download_bytes;
            match sign::sign_keygen_bytes(passphrase.as_deref()) {
                Ok(r) => {
                    download_bytes("sign_pubkey.pem", r.vk_pem.as_bytes());
                    download_bytes("sign_privkey.pem", r.sk_pem.as_bytes());
                    self.sign_keygen_passphrase.clear();
                    self.sign_keygen_passphrase_confirm.clear();
                    self.sign_keygen_status =
                        OpStatus::Ok(format!("Downloaded   Fingerprint: {}", r.vk_fingerprint));
                }
                Err(e) => {
                    self.sign_keygen_status = OpStatus::Err(e.to_string());
                }
            }
        }
    }

    // ── Sign a file ────────────────────────────────────────────────────────

    fn show_sign_file_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "SIGN FILE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Signing private key (.pem)",
                &mut self.sign_sk,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "Passphrase (if encrypted key):",
                &mut self.sign_sk_passphrase,
                &mut self.sign_sk_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "File to sign",
                &mut self.sign_input_file,
                "Any file",
                &[],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.sign_sk.loaded() && self.sign_input_file.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("✏  Sign File")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(120.0, 32.0)),
            )
            .clicked()
        {
            self.do_sign_file();
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            if matches!(&self.sign_status, OpStatus::Ok(_)) {
                if let Some(path) = self.sign_sig_output_path.clone() {
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
                        reveal_in_explorer(&path);
                    }
                }
            }
        }

        show_status(ui, &self.sign_status, dark);
    }

    fn do_sign_file(&mut self) {
        let sk_pem = match self.sign_sk.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.sign_status = OpStatus::Err("Load a signing private key first.".to_owned());
                return;
            }
        };
        let data = match self.sign_input_file.data.clone() {
            Some(d) => d,
            None => {
                self.sign_status = OpStatus::Err("Choose a file to sign.".to_owned());
                return;
            }
        };
        let passphrase = if self.sign_sk_passphrase.is_empty() {
            None
        } else {
            Some((*self.sign_sk_passphrase).clone())
        };

        let sig_bytes = match sign::sign_bytes(&sk_pem, &data, passphrase.as_deref()) {
            Ok(b) => b,
            Err(e) => {
                self.sign_status = OpStatus::Err(e.to_string());
                return;
            }
        };

        let sig_pem = sign::encode_sig_pem(&sig_bytes);
        let sig_filename = format!("{}.sig", self.sign_input_file.name);

        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::path::PathBuf;
            let native_path: PathBuf = if let Some(input_path) = &self.sign_input_file.path {
                let base = sign::default_sig_path(input_path);
                if self.settings.output_dir.is_empty() {
                    base
                } else {
                    PathBuf::from(&self.settings.output_dir)
                        .join(base.file_name().unwrap_or_default())
                }
            } else {
                PathBuf::from(&sig_filename)
            };
            self.sign_sig_output_path = Some(native_path.to_string_lossy().into_owned());
            self.sign_status = save_result(
                &sig_filename,
                &sig_pem,
                Some(native_path),
                self.settings.confirm_overwrite,
            );
        }

        #[cfg(target_arch = "wasm32")]
        {
            self.sign_status = save_result(&sig_filename, &sig_pem, None, false);
        }
    }

    // ── Verify a signature ─────────────────────────────────────────────────

    fn show_verify_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "VERIFY SIGNATURE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Verifying public key (.pem)",
                &mut self.sign_vk,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "File to verify",
                &mut self.sign_verify_file,
                "Any file",
                &[],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Signature file (.sig)",
                &mut self.sign_sig_file,
                "SIG",
                &["sig"],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready =
            self.sign_vk.loaded() && self.sign_verify_file.loaded() && self.sign_sig_file.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("✔  Verify Signature")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .clicked()
        {
            self.do_verify();
        }

        show_status(ui, &self.sign_verify_status, dark);
    }

    fn do_verify(&mut self) {
        let vk_pem = match self.sign_vk.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.sign_verify_status =
                    OpStatus::Err("Load a verifying public key first.".to_owned());
                return;
            }
        };
        let data = match self.sign_verify_file.data.clone() {
            Some(d) => d,
            None => {
                self.sign_verify_status = OpStatus::Err("Choose a file to verify.".to_owned());
                return;
            }
        };
        let sig_pem_bytes = match self.sign_sig_file.data.clone() {
            Some(d) => d,
            None => {
                self.sign_verify_status = OpStatus::Err("Load a .sig signature file.".to_owned());
                return;
            }
        };

        let sig_bytes = match sign::decode_sig_pem(&sig_pem_bytes) {
            Ok(b) => b,
            Err(e) => {
                self.sign_verify_status = OpStatus::Err(format!("Invalid .sig file: {e}"));
                return;
            }
        };

        match sign::verify_bytes(&vk_pem, &data, &sig_bytes) {
            Ok(()) => {
                self.sign_verify_status = OpStatus::Ok(format!(
                    "Signature VALID   {}  verified by  {}",
                    self.sign_verify_file.name, self.sign_vk.name,
                ));
            }
            Err(e) => {
                self.sign_verify_status = OpStatus::Err(format!("Signature INVALID: {e}"));
            }
        }
    }
}

// ── GUI-level tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use pqfile::sign;

    // Round-trip: sign via bytes API, save as PEM, reload PEM, verify.
    #[test]
    fn sign_tab_roundtrip_via_pem_helpers() {
        let r = sign::sign_keygen_bytes(None).unwrap();
        let msg = b"gui roundtrip test";
        let raw_sig = sign::sign_bytes(&r.sk_pem, msg, None).unwrap();
        let pem_bytes = sign::encode_sig_pem(&raw_sig);
        let decoded = sign::decode_sig_pem(&pem_bytes).unwrap();
        sign::verify_bytes(&r.vk_pem, msg, &decoded).unwrap();
    }

    // Verifying a signature that was made against different data must fail.
    #[test]
    fn sign_tab_verify_wrong_data_fails() {
        let r = sign::sign_keygen_bytes(None).unwrap();
        let raw_sig = sign::sign_bytes(&r.sk_pem, b"original", None).unwrap();
        let pem_bytes = sign::encode_sig_pem(&raw_sig);
        let decoded = sign::decode_sig_pem(&pem_bytes).unwrap();
        assert!(sign::verify_bytes(&r.vk_pem, b"modified", &decoded).is_err());
    }

    // Verifying with the wrong verifying key must fail.
    #[test]
    fn sign_tab_verify_wrong_key_fails() {
        let r1 = sign::sign_keygen_bytes(None).unwrap();
        let r2 = sign::sign_keygen_bytes(None).unwrap();
        let raw_sig = sign::sign_bytes(&r1.sk_pem, b"data", None).unwrap();
        let pem_bytes = sign::encode_sig_pem(&raw_sig);
        let decoded = sign::decode_sig_pem(&pem_bytes).unwrap();
        assert!(sign::verify_bytes(&r2.vk_pem, b"data", &decoded).is_err());
    }

    // A truncated .sig PEM must be rejected cleanly.
    #[test]
    fn sign_tab_verify_truncated_sig_returns_error() {
        let r = sign::sign_keygen_bytes(None).unwrap();
        let raw_sig = sign::sign_bytes(&r.sk_pem, b"data", None).unwrap();
        let mut pem_bytes = sign::encode_sig_pem(&raw_sig);
        pem_bytes.truncate(pem_bytes.len() / 2);
        assert!(sign::decode_sig_pem(&pem_bytes).is_err());
    }

    // Passphrase-protected signing key: full roundtrip through PEM helpers.
    #[test]
    fn sign_tab_roundtrip_encrypted_key() {
        let r = sign::sign_keygen_bytes(Some("gui_pass")).unwrap();
        let msg = b"encrypted key gui test";
        let raw_sig = sign::sign_bytes(&r.sk_pem, msg, Some("gui_pass")).unwrap();
        let pem_bytes = sign::encode_sig_pem(&raw_sig);
        let decoded = sign::decode_sig_pem(&pem_bytes).unwrap();
        sign::verify_bytes(&r.vk_pem, msg, &decoded).unwrap();
    }

    // Wrong passphrase must surface a clear error, not panic or succeed.
    #[test]
    fn sign_tab_wrong_passphrase_returns_error() {
        let r = sign::sign_keygen_bytes(Some("correct")).unwrap();
        assert!(sign::sign_bytes(&r.sk_pem, b"data", Some("wrong")).is_err());
    }

    // Empty message signs and verifies cleanly.
    #[test]
    fn sign_tab_empty_message_roundtrip() {
        let r = sign::sign_keygen_bytes(None).unwrap();
        let raw_sig = sign::sign_bytes(&r.sk_pem, b"", None).unwrap();
        let pem_bytes = sign::encode_sig_pem(&raw_sig);
        let decoded = sign::decode_sig_pem(&pem_bytes).unwrap();
        sign::verify_bytes(&r.vk_pem, b"", &decoded).unwrap();
    }

    // Large binary data (1 MB) roundtrips cleanly through the GUI-layer helpers.
    #[test]
    fn sign_tab_large_binary_roundtrip() {
        let r = sign::sign_keygen_bytes(None).unwrap();
        let msg: Vec<u8> = (0u8..=255).cycle().take(1_000_000).collect();
        let raw_sig = sign::sign_bytes(&r.sk_pem, &msg, None).unwrap();
        let pem_bytes = sign::encode_sig_pem(&raw_sig);
        let decoded = sign::decode_sig_pem(&pem_bytes).unwrap();
        sign::verify_bytes(&r.vk_pem, &msg, &decoded).unwrap();
    }

    // ML-DSA signing is deterministic - same key + message always produces the same signature.
    #[test]
    fn sign_tab_signing_is_deterministic() {
        let r = sign::sign_keygen_bytes(None).unwrap();
        let msg = b"deterministic signing";
        let sig1 = sign::sign_bytes(&r.sk_pem, msg, None).unwrap();
        let sig2 = sign::sign_bytes(&r.sk_pem, msg, None).unwrap();
        assert_eq!(sig1, sig2, "ML-DSA signing should be deterministic");
        sign::verify_bytes(&r.vk_pem, msg, &sig1).unwrap();
    }

    // decode_sig_pem on an empty byte slice must return an error, not panic.
    #[test]
    fn sign_tab_decode_empty_bytes_returns_error() {
        assert!(sign::decode_sig_pem(&[]).is_err());
    }
}
