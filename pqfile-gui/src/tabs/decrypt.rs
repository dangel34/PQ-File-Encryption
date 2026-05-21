use std::io::Cursor;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};
use eframe::egui::{self, RichText, Vec2};
use pqfile::{decrypt, keygen};
use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_overlay, c_subtext, c_surface1};
use crate::types::OpStatus;
use crate::widgets::{card, file_row, save_result, section_label, show_status, tab_heading};

impl PqfileApp {
    pub(crate) fn handle_decrypt(&mut self, ctx: &egui::Context) {
        let priv_pem = self.decrypt_privkey.as_str().map(str::to_owned);
        let pqf = self.decrypt_pqf.data.clone();
        let pqf_name = self.decrypt_pqf.name.clone();

        let (Some(priv_pem), Some(pqf)) = (priv_pem, pqf) else {
            self.decrypt_status = OpStatus::Err("Load both files first.".to_owned());
            return;
        };

        let passphrase: Option<String> = if self.decrypt_passphrase.is_empty() {
            None
        } else {
            Some(self.decrypt_passphrase.clone())
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            let pqf_path = self.decrypt_pqf.path.clone();
            let confirm = self.settings.confirm_overwrite;
            let job: Arc<Mutex<Option<OpStatus>>> = Arc::new(Mutex::new(None));
            self.decrypt_job = Some(Arc::clone(&job));

            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let pp = passphrase.as_deref();
                let result: Result<Vec<u8>, _> = {
                    let mut cursor = Cursor::new(&pqf);
                    let mut out = Vec::new();
                    decrypt::decrypt_stream(&priv_pem, &mut cursor, &mut out, pp).map(|_| out)
                };
                let status = match result {
                    Ok(plain) => {
                        let out_name = PathBuf::from(&pqf_name)
                            .file_stem()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| pqf_name.clone());
                        let out_path = pqf_path.map(|p| p.with_extension(""));
                        save_result(&out_name, &plain, out_path, confirm)
                    }
                    Err(e) => OpStatus::Err(e.to_string()),
                };
                *job.lock().unwrap() = Some(status);
                ctx.request_repaint();
            });
            return;
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            let pp = passphrase.as_deref();
            let result: Result<Vec<u8>, _> = {
                let mut cursor = Cursor::new(&pqf);
                let mut out = Vec::new();
                decrypt::decrypt_stream(&priv_pem, &mut cursor, &mut out, pp).map(|_| out)
            };
            match result {
                Ok(plain) => {
                    let out_name = PathBuf::from(&pqf_name)
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| pqf_name.clone());
                    self.decrypt_status = save_result(&out_name, &plain, None, false);
                    if self.settings.auto_clear && matches!(self.decrypt_status, OpStatus::Ok(_)) {
                        self.decrypt_privkey.clear();
                        self.decrypt_pqf.clear();
                        self.decrypt_passphrase.clear();
                    }
                }
                Err(e) => self.decrypt_status = OpStatus::Err(e.to_string()),
            }
        }
    }

    pub(crate) fn show_decrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Decrypt File", dark);
        ui.label(
            RichText::new("Decrypt a .pqf file using your private key.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        let job_running = self.decrypt_job.is_some();
        #[cfg(target_arch = "wasm32")]
        let job_running = false;

        section_label(ui, "INPUTS", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(ui, "Private key (.pem)", &mut self.decrypt_privkey, "PEM", &["pem"], dark);
            ui.add_space(2.0);
            file_row(ui, "Encrypted file (.pqf)", &mut self.decrypt_pqf, "PQF", &["pqf"], dark);
        });
        ui.add_space(14.0);

        // Show passphrase field only when the loaded key is encrypted.
        let key_is_encrypted = self.decrypt_privkey.as_str()
            .map(|pem_str| keygen::is_encrypted_key(pem_str))
            .unwrap_or(false);
        if key_is_encrypted {
            section_label(ui, "PASSPHRASE", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.decrypt_passphrase)
                        .hint_text("Enter passphrase for private key…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            });
            ui.add_space(14.0);
        } else if self.decrypt_privkey.loaded() {
            // Key is loaded but unencrypted — clear any stale passphrase.
            self.decrypt_passphrase.clear();
        }

        let ready = self.decrypt_privkey.loaded() && self.decrypt_pqf.loaded() && !job_running;
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔓  Decrypt")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(120.0, 32.0)),
            )
            .clicked()
        {
            self.handle_decrypt(ui.ctx());
        }

        if !ready && !job_running {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Load a private key and a .pqf file to continue.")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }

        // Spinner while decrypting in the background.
        #[cfg(not(target_arch = "wasm32"))]
        if job_running {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(
                    RichText::new("Decrypting…")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
            });
        }

        show_status(ui, &self.decrypt_status, dark);
    }
}
