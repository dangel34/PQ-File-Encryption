use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_green, c_red, c_subtext, c_surface1, c_yellow};
#[cfg(not(target_arch = "wasm32"))]
use crate::colors::{c_overlay, c_text};
use crate::types::{KeygenAlgorithm, OpStatus, Tab};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::atomic_write;
use crate::widgets::{card, section_label, show_status, tab_heading_help};
use eframe::egui::{self, RichText, Vec2};
use pqfile::keygen;
#[cfg(not(target_arch = "wasm32"))]
use pqfile::keygen::keygen_hardware;
use pqfile::sign;
#[cfg(not(target_arch = "wasm32"))]
use pqfile::sign::sign_keygen_hardware_with_algorithm;
use zeroize::Zeroize;

impl PqfileApp {
    pub(crate) fn show_keygen(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Generate Key Pair", dark) {
            self.help_modal_open = Some(Tab::Keygen);
        }
        ui.label(
            RichText::new(
                "Creates a new post-quantum key pair for encryption or signing (ML-DSA-65 or SLH-DSA).",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        {
            let dir_display = if self.settings.output_dir.is_empty() {
                "Not set (configure in Settings)".to_owned()
            } else {
                self.settings.output_dir.clone()
            };
            section_label(ui, "OUTPUT DIRECTORY", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.label(RichText::new(dir_display).size(13.0).color(
                    if self.settings.output_dir.is_empty() {
                        c_overlay(dark)
                    } else {
                        c_text(dark)
                    },
                ));
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Change in Settings > Default Output Directory.")
                        .size(11.5)
                        .color(c_overlay(dark)),
                );
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
            ui.horizontal_wrapped(|ui| {
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::MlKem512,
                    RichText::new("ML-KEM-512")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::MlKem768,
                    RichText::new("ML-KEM-768")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::MlKem1024,
                    RichText::new("ML-KEM-1024")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::HybridX25519MlKem768,
                    RichText::new("Hybrid X25519+ML-KEM-768")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::MlDsa65,
                    RichText::new("ML-DSA-65 (signing)")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add_space(8.0);
                ui.radio_value(
                    &mut self.keygen_algorithm,
                    KeygenAlgorithm::SlhDsa192f,
                    RichText::new("SLH-DSA-SHAKE-192f (signing)")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
            });
            let desc = match self.keygen_algorithm {
                KeygenAlgorithm::MlKem512 => "Post-quantum encryption key. 800-byte public key, 64-byte seed. NIST FIPS 203.",
                KeygenAlgorithm::MlKem768 => "Post-quantum encryption key (recommended). 1184-byte public key. NIST FIPS 203.",
                KeygenAlgorithm::MlKem1024 => "Post-quantum encryption key, highest security level. 1568-byte public key. NIST FIPS 203.",
                KeygenAlgorithm::HybridX25519MlKem768 => "Hybrid encryption key. X25519 + ML-KEM-768 combined via HKDF-SHA256 for classical + PQ security.",
                KeygenAlgorithm::MlDsa65 => "Post-quantum signing key. Outputs sign_privkey.pem + sign_pubkey.pem. Use in the Sign tab. NIST FIPS 204.",
                KeygenAlgorithm::SlhDsa192f => "Hash-based signing key with conservative security assumptions. Slower signing, 35 KB signatures. Best for long-lived signatures. NIST FIPS 205.",
            };
            ui.add_space(4.0);
            ui.label(RichText::new(desc).size(12.0).color(c_subtext(dark)));
        });
        ui.add_space(14.0);

        // Hardware keys are only available in the native build.
        #[cfg(not(target_arch = "wasm32"))]
        {
            section_label(ui, "HARDWARE KEY (OPTIONAL)", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.checkbox(
                    &mut self.keygen_use_hardware,
                    RichText::new("Store private key in OS credential store (hardware-backed)")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                if self.keygen_use_hardware {
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "The seed is stored in Windows Credential Manager / macOS Keychain \
                             / Linux Secret Service. No seed bytes are written to disk.",
                        )
                        .size(12.0)
                        .color(c_subtext(dark)),
                    );
                    ui.add_space(4.0);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.keygen_hardware_label)
                            .hint_text("Key label (e.g. my-pqfile-key)...")
                            .desired_width(f32::INFINITY),
                    );
                    // Disable passphrase when hardware is active.
                    self.keygen_use_passphrase = false;
                }
            });
            ui.add_space(14.0);
        }

        section_label(ui, "EXPIRY (OPTIONAL)", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            let prev_expiry = self.keygen_use_expiry;
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.keygen_use_expiry, "");
                ui.label(
                    RichText::new("Set expiry date")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
            });
            // When toggle is first switched on, pre-fill from settings default.
            if self.keygen_use_expiry
                && !prev_expiry
                && self.keygen_expiry_date.is_empty()
                && self.settings.default_expiry_days > 0
            {
                if let Some(date) =
                    crate::tabs::settings::days_from_now(self.settings.default_expiry_days)
                {
                    self.keygen_expiry_picker = crate::types::parse_expiry_date(&date);
                }
            }
            if self.keygen_use_expiry {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Expires:").size(13.0).color(c_subtext(dark)));
                    ui.add(
                        egui_extras::DatePickerButton::new(&mut self.keygen_expiry_picker)
                            .id_salt("keygen_expiry"),
                    );
                    ui.label(
                        RichText::new("Written as a comment in the PEM file.")
                            .size(11.5)
                            .color(c_subtext(dark)),
                    );
                });
                self.keygen_expiry_date = self.keygen_expiry_picker.to_string();
            }
        });
        ui.add_space(14.0);

        section_label(ui, "PASSPHRASE (OPTIONAL)", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            let hw_active = self.keygen_use_hardware;
            ui.add_enabled_ui(!hw_active, |ui| {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.keygen_use_passphrase, "");
                    ui.label(
                        RichText::new("Protect private key with a passphrase")
                            .size(13.0)
                            .color(c_subtext(dark)),
                    );
                });
            });
            if hw_active {
                ui.label(
                    RichText::new("Passphrase protection is not used with hardware-backed keys.")
                        .size(12.0)
                        .color(c_subtext(dark)),
                );
            } else if self.keygen_use_passphrase {
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::singleline(&mut *self.keygen_passphrase)
                        .hint_text("Enter passphrase…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
                // Passphrase strength meter
                if !self.keygen_passphrase.is_empty() {
                    let score = keygen::passphrase_strength(&self.keygen_passphrase);
                    let (label, color) = if score <= 2 {
                        ("Weak", c_red(dark))
                    } else if score <= 4 {
                        ("Fair", c_yellow(dark))
                    } else {
                        ("Strong", c_green(dark))
                    };
                    let fraction = (score as f32 / 7.0).min(1.0);
                    ui.add_space(3.0);
                    let row_w = ui.available_width();
                    ui.horizontal(|ui| {
                        let bar_w = (row_w - 48.0).max(40.0);
                        let (rect, _) =
                            ui.allocate_exact_size(egui::vec2(bar_w, 4.0), egui::Sense::hover());
                        let bg = eframe::egui::Color32::from_rgba_premultiplied(
                            color.r(),
                            color.g(),
                            color.b(),
                            40,
                        );
                        let filled = egui::Rect::from_min_size(
                            rect.min,
                            egui::vec2(rect.width() * fraction, rect.height()),
                        );
                        ui.painter().rect_filled(rect, 2.0, bg);
                        ui.painter().rect_filled(filled, 2.0, color);
                        ui.add_space(6.0);
                        ui.label(eframe::egui::RichText::new(label).size(11.0).color(color));
                    });
                }
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::singleline(&mut *self.keygen_passphrase_confirm)
                        .hint_text("Confirm passphrase…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            }
        });
        ui.add_space(14.0);

        ui.horizontal(|ui| {
            let btn_clicked = ui
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
                .clicked();
            let ctrl_enter =
                ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter));
            if btn_clicked || ctrl_enter {
                self.handle_keygen();
            }

            // Import from SSH ed25519 key (native only).
            #[cfg(not(target_arch = "wasm32"))]
            if ui
                .add(
                    egui::Button::new(
                        RichText::new("🔑  Import SSH key…")
                            .size(13.0)
                            .color(c_subtext(dark)),
                    )
                    .fill(c_surface1(dark))
                    .min_size(Vec2::new(150.0, 32.0)),
                )
                .on_hover_text(
                    "Import an unencrypted OpenSSH ed25519 private key. \
                     Derives an ML-KEM-768 key pair via HKDF. One-way, not \
                     interoperable with SSH.",
                )
                .clicked()
            {
                self.handle_ssh_import(ui.ctx());
            }
        });

        show_status(ui, &self.keygen_status, dark);

        // "Show QR" button after a successful native keygen (public key file exists).
        #[cfg(not(target_arch = "wasm32"))]
        if matches!(&self.keygen_status, crate::types::OpStatus::Ok(_))
            && !self.settings.output_dir.is_empty()
        {
            let pub_path = std::path::Path::new(&self.settings.output_dir).join("pubkey.pem");
            if pub_path.exists() {
                ui.add_space(6.0);
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("📷  Show QR code")
                                .size(13.0)
                                .color(c_subtext(dark)),
                        )
                        .fill(c_surface1(dark)),
                    )
                    .on_hover_text("Show public key as a QR code for air-gap transfer")
                    .clicked()
                {
                    if let Ok(pem_str) = std::fs::read_to_string(&pub_path) {
                        let title = "Public Key QR Code".to_owned();
                        self.open_qr(ui.ctx(), title, &pem_str);
                    }
                }
            }
        }
    }

    /// Import an OpenSSH ed25519 private key and derive an ML-KEM-768 key pair from it.
    /// Opens a file picker, reads the SSH key, runs the derivation, and saves the result.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn handle_ssh_import(&mut self, ctx: &egui::Context) {
        let _ = ctx;
        if self.settings.output_dir.trim().is_empty() {
            self.keygen_status =
                OpStatus::Err("Set a default output directory in Settings first.".to_owned());
            return;
        }
        let out_dir = std::path::Path::new(&self.settings.output_dir).to_owned();
        let force = !self.settings.confirm_overwrite;
        let passphrase: Option<zeroize::Zeroizing<String>> = if self.keygen_use_passphrase {
            let pp = zeroize::Zeroizing::new((*self.keygen_passphrase).clone());
            if pp.is_empty() {
                self.keygen_status =
                    OpStatus::Err("Enter a passphrase or uncheck the option.".to_owned());
                return;
            }
            Some(pp)
        } else {
            None
        };

        // Pick the SSH key file.
        let path = rfd::FileDialog::new()
            .set_title("Select OpenSSH ed25519 private key")
            .add_filter("PEM / SSH key", &["pem", "key", ""])
            .pick_file();
        let path = match path {
            Some(p) => p,
            None => return,
        };
        let ssh_pem = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                self.keygen_status = OpStatus::Err(format!("Could not read file: {e}"));
                return;
            }
        };

        match pqfile::keygen::import_key_from_ssh(
            &ssh_pem,
            passphrase.as_deref().map(String::as_str),
        ) {
            Ok((pub_pem, priv_pem)) => {
                // Apply expiry comment if set.
                let expiry = self
                    .keygen_use_expiry
                    .then(|| self.keygen_expiry_date.trim().to_owned())
                    .filter(|s| !s.is_empty());
                let (pub_pem, priv_pem) = if let Some(ref date) = expiry {
                    (
                        format!("# Expires: {date}\n{pub_pem}"),
                        format!("# Expires: {date}\n{priv_pem}"),
                    )
                } else {
                    (pub_pem, priv_pem)
                };

                // Overwrite check.
                let pub_path = out_dir.join("pubkey.pem");
                let priv_path = out_dir.join("privkey.pem");
                if !force && (pub_path.exists() || priv_path.exists()) {
                    self.keygen_status = OpStatus::Err(
                        "Key files already exist. Disable overwrite protection or move them first."
                            .to_owned(),
                    );
                    return;
                }

                let fp = pqfile::keygen::fingerprint_pem(&pub_pem);
                if let Err(e) = atomic_write(&pub_path, pub_pem.as_bytes())
                    .and_then(|_| atomic_write(&priv_path, priv_pem.as_bytes()))
                {
                    self.keygen_status = OpStatus::Err(e.to_string());
                } else {
                    let expiry_note = expiry
                        .map(|d| format!("\nExpires: {d}"))
                        .unwrap_or_default();
                    self.keygen_status = OpStatus::Ok(format!(
                        "Imported SSH key → ML-KEM-768 key pair saved to {}\n\
                         Fingerprint: {fp}{expiry_note}\n\
                         Warning: this key is not interoperable with SSH.",
                        out_dir.display()
                    ));
                }
            }
            Err(e) => {
                self.keygen_status = OpStatus::Err(e.to_string());
            }
        }
    }

    pub(crate) fn handle_keygen(&mut self) {
        if self.keygen_algorithm.is_signing() {
            self.handle_sign_keygen();
            return;
        }

        let passphrase: Option<&str> = if self.keygen_use_passphrase {
            if self.keygen_passphrase.is_empty() {
                self.keygen_status =
                    OpStatus::Err("Enter a passphrase or uncheck the option.".to_owned());
                return;
            }
            if self.keygen_passphrase != self.keygen_passphrase_confirm {
                self.keygen_status = OpStatus::Err("Passphrases do not match.".to_owned());
                return;
            }
            Some(self.keygen_passphrase.as_str())
        } else {
            None
        };

        let level = self.keygen_algorithm.level();
        let hybrid = self.keygen_algorithm.hybrid();

        #[cfg(not(target_arch = "wasm32"))]
        {
            if self.settings.output_dir.trim().is_empty() {
                self.keygen_status =
                    OpStatus::Err("Set a default output directory in Settings first.".to_owned());
                return;
            }
            let dir = std::path::Path::new(&self.settings.output_dir);
            let force = !self.settings.confirm_overwrite;

            if self.keygen_use_hardware {
                let label = self.keygen_hardware_label.trim().to_owned();
                if label.is_empty() {
                    self.keygen_status =
                        OpStatus::Err("Enter a label for the hardware key.".to_owned());
                    return;
                }
                self.keygen_status = match keygen_hardware(dir, force, level, hybrid, &label) {
                    Ok(fp) => OpStatus::Ok(format!(
                        "Hardware-backed keys saved to {}\n\
                             Seed stored in OS credential store.\nFingerprint: {fp}",
                        dir.display()
                    )),
                    Err(e) => OpStatus::Err(e.to_string()),
                };
            } else {
                self.keygen_status = match keygen::keygen(dir, force, level, passphrase, hybrid) {
                    Ok(fp) => {
                        // Prepend expiry comment to both PEM files if requested.
                        let expiry = self
                            .keygen_use_expiry
                            .then(|| self.keygen_expiry_date.trim().to_owned())
                            .filter(|s| !s.is_empty());
                        if let Some(ref date) = expiry {
                            for name in &["pubkey.pem", "privkey.pem"] {
                                let p = dir.join(name);
                                if let Ok(pem_str) = std::fs::read_to_string(&p) {
                                    let _ = atomic_write(
                                        &p,
                                        format!("# Expires: {date}\n{pem_str}").as_bytes(),
                                    );
                                }
                            }
                        }
                        let expiry_note = expiry
                            .map(|d| format!("\nExpires: {d}"))
                            .unwrap_or_default();
                        OpStatus::Ok(format!(
                            "Keys saved to {}\nFingerprint: {fp}{expiry_note}",
                            dir.display()
                        ))
                    }
                    Err(e) => OpStatus::Err(e.to_string()),
                };
            }
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
                    let expiry = self
                        .keygen_use_expiry
                        .then(|| self.keygen_expiry_date.trim().to_owned())
                        .filter(|s| !s.is_empty());
                    let (pub_pem, priv_pem) = if let Some(ref date) = expiry {
                        (
                            format!("# Expires: {date}\n{pub_pem}"),
                            format!("# Expires: {date}\n{priv_pem}"),
                        )
                    } else {
                        (pub_pem, priv_pem)
                    };
                    crate::widgets::download_bytes("pubkey.pem", pub_pem.as_bytes());
                    crate::widgets::download_bytes("privkey.pem", priv_pem.as_bytes());
                    let expiry_note = expiry
                        .map(|d| format!("\nExpires: {d}"))
                        .unwrap_or_default();
                    self.keygen_status = OpStatus::Ok(format!(
                        "pubkey.pem and privkey.pem downloaded.\nFingerprint: {fp}{expiry_note}"
                    ));
                }
                Err(e) => self.keygen_status = OpStatus::Err(e.to_string()),
            }
        }
    }

    pub(crate) fn handle_sign_keygen(&mut self) {
        let sig_alg = self
            .keygen_algorithm
            .sig_algorithm()
            .unwrap_or(pqfile::sign::SigAlgorithm::MlDsa65);
        let passphrase: Option<zeroize::Zeroizing<String>> = if self.keygen_use_passphrase {
            let pp = zeroize::Zeroizing::new((*self.keygen_passphrase).clone());
            let pc = zeroize::Zeroizing::new((*self.keygen_passphrase_confirm).clone());
            if *pp != *pc {
                self.keygen_status = OpStatus::Err("Passphrases do not match.".to_owned());
                return;
            }
            if pp.is_empty() {
                self.keygen_status =
                    OpStatus::Err("Enter a passphrase or uncheck the option.".to_owned());
                return;
            }
            Some(pp)
        } else {
            None
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            if self.settings.output_dir.trim().is_empty() {
                self.keygen_status =
                    OpStatus::Err("Set a default output directory in Settings first.".to_owned());
                return;
            }
            let dir = std::path::Path::new(&self.settings.output_dir);
            let force = !self.settings.confirm_overwrite;

            if self.keygen_use_hardware {
                let label = self.keygen_hardware_label.trim().to_owned();
                if label.is_empty() {
                    self.keygen_status =
                        OpStatus::Err("Enter a label for the hardware signing key.".to_owned());
                    return;
                }
                self.keygen_status =
                    match sign_keygen_hardware_with_algorithm(dir, force, &label, sig_alg) {
                        Ok(r) => OpStatus::Ok(format!(
                            "Hardware-backed signing keys saved to {}\n\
                         Seed stored in OS credential store.\nFingerprint: {}",
                            dir.display(),
                            r.vk_fingerprint,
                        )),
                        Err(e) => OpStatus::Err(e.to_string()),
                    };
            } else {
                self.keygen_status = match sign::sign_keygen_with_algorithm(
                    dir,
                    force,
                    passphrase.as_deref().map(String::as_str),
                    sig_alg,
                ) {
                    Ok(r) => {
                        self.keygen_passphrase.zeroize();
                        self.keygen_passphrase_confirm.zeroize();
                        OpStatus::Ok(format!(
                            "Signing keys saved to {}\nFingerprint: {}",
                            dir.display(),
                            r.vk_fingerprint,
                        ))
                    }
                    Err(e) => OpStatus::Err(e.to_string()),
                };
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            use crate::widgets::download_bytes;
            match sign::sign_keygen_bytes_with_algorithm(
                sig_alg,
                passphrase.as_deref().map(String::as_str),
            ) {
                Ok(r) => {
                    download_bytes("sign_pubkey.pem", r.vk_pem.as_bytes());
                    download_bytes("sign_privkey.pem", r.sk_pem.as_bytes());
                    self.keygen_passphrase.zeroize();
                    self.keygen_passphrase_confirm.zeroize();
                    self.keygen_status = OpStatus::Ok(format!(
                        "sign_pubkey.pem and sign_privkey.pem downloaded.\nFingerprint: {}",
                        r.vk_fingerprint,
                    ));
                }
                Err(e) => self.keygen_status = OpStatus::Err(e.to_string()),
            }
        }
    }
}
