use eframe::egui::{self, RichText, Vec2};
use pqfile::keygen;
use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface0, c_surface1, c_text};
use crate::types::{KeygenAlgorithm, OpStatus};
use crate::widgets::{card, section_label, show_status, tab_heading};

impl PqfileApp {
    pub(crate) fn show_keygen(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Generate Key Pair", dark);
        ui.label(
            RichText::new("Creates a new post-quantum key pair for encryption.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        {
            section_label(ui, "OUTPUT DIRECTORY", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.keygen_dir)
                            .hint_text("Choose a folder…")
                            .desired_width(ui.available_width() - 76.0),
                    );
                    if ui
                        .add(
                            egui::Button::new(RichText::new("Browse…").color(c_text(dark)))
                                .fill(c_surface0(dark)),
                        )
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.keygen_dir = p.to_string_lossy().into_owned();
                        }
                    }
                });
            });
            ui.add_space(14.0);
        }

        #[cfg(target_arch = "wasm32")]
        {
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.label(
                    RichText::new(
                        "pubkey.pem and privkey.pem will be downloaded to your downloads folder.",
                    )
                    .size(13.0)
                    .color(c_subtext(dark)),
                );
            });
            ui.add_space(14.0);
        }

        section_label(ui, "ALGORITHM", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::MlKem768,
                    RichText::new("ML-KEM-768").size(13.0).color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::MlKem1024,
                    RichText::new("ML-KEM-1024").size(13.0).color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::HybridX25519MlKem768,
                    RichText::new("Hybrid X25519+ML-KEM-768").size(13.0).color(c_subtext(dark)),
                );
            });
            let desc = match self.keygen_algorithm {
                KeygenAlgorithm::MlKem768 => "Post-quantum only. 1184-byte public key, 64-byte seed. NIST FIPS 203.",
                KeygenAlgorithm::MlKem1024 => "Post-quantum only, higher security level. 1568-byte public key. NIST FIPS 203.",
                KeygenAlgorithm::HybridX25519MlKem768 => "Classical + post-quantum. X25519 shared secret combined with ML-KEM-768 via HKDF-SHA256.",
            };
            ui.add_space(4.0);
            ui.label(RichText::new(desc).size(12.0).color(c_subtext(dark)));
        });
        ui.add_space(14.0);

        section_label(ui, "PASSPHRASE (OPTIONAL)", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.keygen_use_passphrase, "");
                ui.label(
                    RichText::new("Protect private key with a passphrase")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
            });
            if self.keygen_use_passphrase {
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.keygen_passphrase)
                        .hint_text("Enter passphrase…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::singleline(&mut self.keygen_passphrase_confirm)
                        .hint_text("Confirm passphrase…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            }
        });
        ui.add_space(14.0);

        if ui
            .add(
                egui::Button::new(
                    RichText::new("⚡  Generate Key Pair")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(170.0, 32.0)),
            )
            .clicked()
        {
            self.handle_keygen();
        }

        show_status(ui, &self.keygen_status, dark);
    }

    pub(crate) fn handle_keygen(&mut self) {
        let passphrase: Option<&str> = if self.keygen_use_passphrase {
            if self.keygen_passphrase.is_empty() {
                self.keygen_status = OpStatus::Err("Enter a passphrase or uncheck the option.".to_owned());
                return;
            }
            if self.keygen_passphrase != self.keygen_passphrase_confirm {
                self.keygen_status = OpStatus::Err("Passphrases do not match.".to_owned());
                return;
            }
            Some(&self.keygen_passphrase)
        } else {
            None
        };

        let level = self.keygen_algorithm.level();
        let hybrid = self.keygen_algorithm.hybrid();

        #[cfg(not(target_arch = "wasm32"))]
        {
            if self.keygen_dir.trim().is_empty() {
                self.keygen_status = OpStatus::Err("Choose an output directory first.".to_owned());
                return;
            }
            let dir = std::path::Path::new(&self.keygen_dir);
            // force=true when confirm_overwrite is off (the default): overwrite freely.
            // force=false when confirm_overwrite is on: refuse if either key file exists.
            let force = !self.settings.confirm_overwrite;
            self.keygen_status = match keygen::keygen(dir, force, level, passphrase, hybrid) {
                Ok(fp) => OpStatus::Ok(format!(
                    "Keys saved to {}\nFingerprint: {fp}",
                    dir.display()
                )),
                Err(e) => OpStatus::Err(e.to_string()),
            };
        }

        #[cfg(target_arch = "wasm32")]
        {
            let result = if hybrid {
                keygen::keygen_bytes_hybrid_768(passphrase)
            } else {
                keygen::keygen_bytes(level, passphrase)
            };
            match result {
                Ok((pub_pem, priv_pem)) => {
                    let fp = keygen::fingerprint_pem(&pub_pem);
                    crate::widgets::download_bytes("pubkey.pem", pub_pem.as_bytes());
                    crate::widgets::download_bytes("privkey.pem", priv_pem.as_bytes());
                    self.keygen_status = OpStatus::Ok(format!(
                        "pubkey.pem and privkey.pem downloaded.\nFingerprint: {fp}"
                    ));
                }
                Err(e) => self.keygen_status = OpStatus::Err(e.to_string()),
            }
        }
    }
}
