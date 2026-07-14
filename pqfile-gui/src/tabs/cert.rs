use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_subtext, c_surface1};
use crate::types::{current_unix_secs, unix_secs_to_ymd, CertSubTab, OpStatus};
use crate::widgets::{
    card, file_row, kv_row, passphrase_row, save_result, section_label, seg_tabs, show_status,
};
use eframe::egui::{self, RichText, Vec2};
use pqfile::cert;
use zeroize::Zeroize;

impl PqfileApp {
    pub(crate) fn show_cert_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        ui.label(
            RichText::new(
                "A CA signing key attests to a subject public/verifying key's label, \
                 validity window, and permitted uses. The resulting certificate can be \
                 used in place of a raw key wherever pqfile accepts a recipient or \
                 verifying key, alongside the matching CA verifying key.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(8.0);
        seg_tabs(
            ui,
            &mut self.cert_sub_tab,
            &[
                ("Issue Certificate", CertSubTab::Issue),
                ("Verify Certificate", CertSubTab::Verify),
            ],
            dark,
        );
        match self.cert_sub_tab {
            CertSubTab::Issue => self.show_issue_cert_section(ui, dark),
            CertSubTab::Verify => self.show_verify_cert_section(ui, dark),
        }
    }

    // ── Issue certificate ────────────────────────────────────────────────────

    fn show_issue_cert_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "ISSUE CERTIFICATE", dark);
        let mut pp_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "CA signing key (.pem)",
                &mut self.cert_issue_ca_key,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            pp_submitted = passphrase_row(
                ui,
                "CA key passphrase (if encrypted):",
                &mut self.cert_issue_ca_passphrase,
                &mut self.cert_issue_ca_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Subject public/verifying key (.pem)",
                &mut self.cert_issue_subject_key,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            let row_w = ui.available_width();
            ui.horizontal(|ui| {
                ui.label(RichText::new("Label:").size(13.0).color(c_subtext(dark)));
                ui.add(
                    egui::TextEdit::singleline(&mut self.cert_issue_label)
                        .hint_text("e.g. alice's laptop")
                        .desired_width(row_w),
                );
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Valid for (days):")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add(egui::DragValue::new(&mut self.cert_issue_valid_days).range(1..=36_500));
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "(until {})",
                        unix_secs_to_ymd(
                            current_unix_secs() + u64::from(self.cert_issue_valid_days) * 86_400
                        )
                    ))
                    .size(12.0)
                    .color(c_subtext(dark)),
                );
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.checkbox(
                    &mut self.cert_issue_allow_encrypt,
                    RichText::new("Allow encrypt")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add_space(16.0);
                ui.checkbox(
                    &mut self.cert_issue_allow_sign,
                    RichText::new("Allow sign")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
            });
        });
        ui.add_space(8.0);

        let ready = self.cert_issue_ca_key.loaded()
            && self.cert_issue_subject_key.loaded()
            && !self.cert_issue_label.trim().is_empty()
            && (self.cert_issue_allow_encrypt || self.cert_issue_allow_sign);

        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("📜  Issue Certificate")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .on_disabled_hover_text(
                "Load the CA key and subject key, set a label, and allow at least one use.",
            )
            .clicked()
            || (ready
                && (pp_submitted
                    || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
        {
            self.do_issue_cert();
        }

        show_status(ui, &self.cert_issue_status, dark);
    }

    pub(crate) fn do_issue_cert(&mut self) {
        let ca_sk_pem = match self.cert_issue_ca_key.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.cert_issue_status = OpStatus::Err("Load a CA signing key first.".to_owned());
                return;
            }
        };
        let subject_pem = match self.cert_issue_subject_key.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.cert_issue_status =
                    OpStatus::Err("Load a subject public/verifying key first.".to_owned());
                return;
            }
        };
        let passphrase = if self.cert_issue_ca_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.cert_issue_ca_passphrase).clone(),
            ))
        };
        let mut allowed_use = 0u8;
        if self.cert_issue_allow_encrypt {
            allowed_use |= cert::cert_use::ENCRYPT;
        }
        if self.cert_issue_allow_sign {
            allowed_use |= cert::cert_use::SIGN;
        }

        let not_before = current_unix_secs();
        let not_after = not_before + u64::from(self.cert_issue_valid_days) * 86_400;

        match cert::issue_cert(
            &ca_sk_pem,
            passphrase.as_deref().map(String::as_str),
            &subject_pem,
            self.cert_issue_label.trim(),
            not_before,
            not_after,
            allowed_use,
        ) {
            Ok(cert_pem) => {
                let filename = format!("{}.cert.pem", sanitize_filename(&self.cert_issue_label));
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let native_path = if self.settings.output_dir.is_empty() {
                        std::path::PathBuf::from(&filename)
                    } else {
                        std::path::PathBuf::from(&self.settings.output_dir).join(&filename)
                    };
                    self.cert_issue_output_path = Some(native_path.to_string_lossy().into_owned());
                    self.cert_issue_status = save_result(
                        &filename,
                        cert_pem.as_bytes(),
                        Some(native_path),
                        self.settings.confirm_overwrite,
                    );
                }
                #[cfg(target_arch = "wasm32")]
                {
                    self.cert_issue_status =
                        save_result(&filename, cert_pem.as_bytes(), None, false);
                }
            }
            Err(e) => {
                self.cert_issue_status = OpStatus::Err(e.to_string());
            }
        }
        // The passphrase's one-shot job (unlocking the CA key for this signature) is
        // done either way; don't leave it sitting in memory for the rest of the session.
        self.cert_issue_ca_passphrase.zeroize();
    }

    // ── Verify certificate ───────────────────────────────────────────────────

    fn show_verify_cert_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "VERIFY CERTIFICATE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "CA verifying key (.pem)",
                &mut self.cert_verify_ca_vk,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Certificate file",
                &mut self.cert_verify_cert,
                "PEM",
                &["pem"],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.cert_verify_ca_vk.loaded() && self.cert_verify_cert.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("✔  Verify Certificate")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
        {
            self.do_verify_cert();
        }

        if let Some(c) = self.cert_verify_result.clone() {
            ui.add_space(8.0);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                kv_row(ui, "Label", &c.label, dark);
                kv_row(ui, "Valid from", &unix_secs_to_ymd(c.not_before), dark);
                kv_row(ui, "Valid until", &unix_secs_to_ymd(c.not_after), dark);
                kv_row(ui, "Allowed use", &use_str(c.allowed_use), dark);
                kv_row(
                    ui,
                    "Subject type",
                    &crate::types::pem_variant_name(&c.subject_pem),
                    dark,
                );
            });
        }

        show_status(ui, &self.cert_verify_status, dark);
    }

    pub(crate) fn do_verify_cert(&mut self) {
        self.cert_verify_result = None;
        let ca_vk_pem = match self.cert_verify_ca_vk.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.cert_verify_status =
                    OpStatus::Err("Load a CA verifying key first.".to_owned());
                return;
            }
        };
        let cert_pem = match self.cert_verify_cert.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.cert_verify_status =
                    OpStatus::Err("Load a certificate file first.".to_owned());
                return;
            }
        };
        match cert::verify_cert(&ca_vk_pem, &cert_pem, current_unix_secs()) {
            Ok(c) => {
                self.cert_verify_status =
                    OpStatus::Ok(format!("Certificate is valid: {}", c.label));
                self.cert_verify_result = Some(c);
            }
            Err(e) => {
                self.cert_verify_status = OpStatus::Err(e.to_string());
            }
        }
    }
}

fn sanitize_filename(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "certificate".to_owned()
    } else {
        cleaned
    }
}

fn use_str(mask: u8) -> String {
    let mut parts = Vec::new();
    if mask & cert::cert_use::ENCRYPT != 0 {
        parts.push("encrypt");
    }
    if mask & cert::cert_use::SIGN != 0 {
        parts.push("sign");
    }
    if parts.is_empty() {
        "(none)".to_owned()
    } else {
        parts.join(", ")
    }
}
