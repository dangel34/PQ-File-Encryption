use std::io::Cursor;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::{decrypt, keygen};
use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_green, c_overlay, c_red, c_subtext, c_surface0, c_surface1, c_text};
use crate::types::OpStatus;
use crate::widgets::{card, file_row, pick_pqf_files, save_result, section_label, show_status, tab_heading};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::pick_folder_pqf;

impl PqfileApp {
    pub(crate) fn handle_decrypt_batch(&mut self, ctx: &egui::Context) {
        if self.decrypt_files.is_empty() {
            self.decrypt_status = OpStatus::Err("Add at least one .pqf file.".to_owned());
            return;
        }
        let priv_pem = match self.decrypt_privkey.as_str().map(str::to_owned) {
            Some(p) => p,
            None => {
                self.decrypt_status = OpStatus::Err("Load a private key first.".to_owned());
                return;
            }
        };
        self.decrypt_status = OpStatus::None;

        let passphrase: Option<String> = if self.decrypt_passphrase.is_empty() {
            None
        } else {
            Some((*self.decrypt_passphrase).clone())
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            use crate::types::DecryptBatchJob;

            let confirm = self.settings.confirm_overwrite;
            let output_dir: Option<PathBuf> = if self.settings.output_dir.is_empty() {
                None
            } else {
                Some(PathBuf::from(&self.settings.output_dir))
            };
            let files: Vec<(usize, String, Vec<u8>, Option<PathBuf>)> = self
                .decrypt_files
                .iter()
                .enumerate()
                .map(|(i, e)| (i, e.name.clone(), e.data.clone(), e.path.clone()))
                .collect();
            let total = files.len();

            let job = Arc::new(Mutex::new(DecryptBatchJob {
                done: 0,
                total,
                results: Vec::new(),
                finished: false,
            }));
            self.decrypt_batch_job = Some(Arc::clone(&job));

            let ctx = ctx.clone();
            std::thread::spawn(move || {
                for (i, name, data, path) in files {
                    let pp = passphrase.as_deref();
                    let result: Result<Vec<u8>, _> = {
                        let mut cursor = Cursor::new(&data);
                        let mut out = Vec::new();
                        decrypt::decrypt_stream(&priv_pem, &mut cursor, &mut out, pp).map(|_| out)
                    };
                    let status = match result {
                        Ok(plain) => {
                            // Strip .pqf from name (which may be a relative path like subdir/file.txt.pqf)
                            let out_name = if name.ends_with(".pqf") {
                                name[..name.len() - 4].to_owned()
                            } else {
                                name.clone()
                            };
                            let out_path = if let Some(ref dir) = output_dir {
                                Some(dir.join(&out_name))
                            } else {
                                path.map(|p| p.with_extension(""))
                            };
                            save_result(&out_name, &plain, out_path, confirm)
                        }
                        Err(e) => OpStatus::Err(e.to_string()),
                    };
                    {
                        let mut g = job.lock().unwrap();
                        g.done += 1;
                        g.results.push((i, status));
                    }
                    ctx.request_repaint();
                }
                job.lock().unwrap().finished = true;
                ctx.request_repaint();
            });
            return;
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            let pp = passphrase.as_deref();
            for entry in &mut self.decrypt_files {
                let result: Result<Vec<u8>, _> = {
                    let mut cursor = Cursor::new(&entry.data);
                    let mut out = Vec::new();
                    decrypt::decrypt_stream(&priv_pem, &mut cursor, &mut out, pp).map(|_| out)
                };
                entry.status = match result {
                    Ok(plain) => {
                        let out_name = if entry.name.ends_with(".pqf") {
                            entry.name[..entry.name.len() - 4].to_owned()
                        } else {
                            entry.name.clone()
                        };
                        save_result(&out_name, &plain, None, false)
                    }
                    Err(e) => OpStatus::Err(e.to_string()),
                };
            }
            if self.settings.auto_clear
                && self.decrypt_files.iter().all(|e| matches!(e.status, OpStatus::Ok(_)))
            {
                self.decrypt_privkey.clear();
                self.decrypt_files.clear();
                self.decrypt_passphrase.clear();
            }
        }
    }

    pub(crate) fn show_decrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Decrypt File", dark);
        ui.label(
            RichText::new("Decrypt one or more .pqf files using your private key.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        let job_running = self.decrypt_batch_job.is_some();
        #[cfg(target_arch = "wasm32")]
        let job_running = false;

        // ── Private key ───────────────────────────────────────────────────────
        section_label(ui, "PRIVATE KEY", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(ui, "Private key (.pem)", &mut self.decrypt_privkey, "PEM", &["pem"], dark);
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
                    egui::TextEdit::singleline(&mut *self.decrypt_passphrase)
                        .hint_text("Enter passphrase for private key…")
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
            });
            ui.add_space(14.0);
        } else if self.decrypt_privkey.loaded() {
            self.decrypt_passphrase.clear();
        }

        // ── Files to decrypt ──────────────────────────────────────────────────
        section_label(ui, "FILES TO DECRYPT", dark);
        let mut to_remove: Option<usize> = None;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                if self.decrypt_files.is_empty() {
                    ui.label(
                        RichText::new("No files added. Browse or drag and drop .pqf files")
                            .size(13.0)
                            .color(c_overlay(dark)),
                    );
                } else {
                    let n = self.decrypt_files.len();
                    ui.label(
                        RichText::new(format!("{n} file{}", if n == 1 { "" } else { "s" }))
                            .size(13.0)
                            .color(c_subtext(dark)),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !job_running
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new("+ Add Files…").size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .clicked()
                    {
                        pick_pqf_files(std::sync::Arc::clone(&self.decrypt_batch_pending));
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    if !job_running
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new("+ Add Folder…").size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .on_hover_text("Recursively add every .pqf file inside a folder")
                            .clicked()
                    {
                        pick_folder_pqf(std::sync::Arc::clone(&self.decrypt_batch_pending));
                    }
                });
            });

            if !self.decrypt_files.is_empty() {
                ui.add_space(6.0);
                for (i, entry) in self.decrypt_files.iter().enumerate() {
                    let mut remove = false;
                    let w = ui.available_width();
                    ui.allocate_ui(egui::vec2(w, 22.0), |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.label(RichText::new(&entry.name).size(13.0).color(c_text(dark)));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if !job_running {
                                        remove = ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("x")
                                                        .size(11.0)
                                                        .color(c_overlay(dark)),
                                                )
                                                .fill(Color32::TRANSPARENT)
                                                .stroke(Stroke::NONE),
                                            )
                                            .clicked();
                                    }
                                    match &entry.status {
                                        OpStatus::None => {}
                                        OpStatus::Ok(_) => {
                                            ui.label(
                                                RichText::new("OK")
                                                    .size(12.0)
                                                    .color(c_green(dark)),
                                            );
                                        }
                                        OpStatus::Err(m) => {
                                            let display: String = m.chars().take(32).collect();
                                            ui.label(
                                                RichText::new(display)
                                                    .size(12.0)
                                                    .color(c_red(dark)),
                                            );
                                        }
                                    }
                                },
                            );
                        });
                    });
                    if remove && to_remove.is_none() {
                        to_remove = Some(i);
                    }
                }
            }
        });

        if let Some(i) = to_remove {
            self.decrypt_files.remove(i);
        }
        ui.add_space(14.0);

        // ── Decrypt All button ────────────────────────────────────────────────
        let n = self.decrypt_files.len();
        let ready = self.decrypt_privkey.loaded() && n > 0 && !job_running;
        let btn_label = if n == 0 {
            "🔓  Decrypt All".to_owned()
        } else {
            format!("🔓  Decrypt All ({n})")
        };
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new(btn_label).size(14.0).color(c_chrome(dark)).strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(170.0, 32.0)),
            )
            .clicked()
        {
            self.handle_decrypt_batch(ui.ctx());
        }

        if !ready && !job_running {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Load a private key and add at least one .pqf file to continue.")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }

        // ── Progress bar while running ────────────────────────────────────────
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(job) = &self.decrypt_batch_job {
            if let Ok(g) = job.try_lock() {
                let fraction = if g.total > 0 {
                    g.done as f32 / g.total as f32
                } else {
                    0.0
                };
                ui.add_space(10.0);
                ui.add(
                    egui::ProgressBar::new(fraction)
                        .desired_width(f32::INFINITY)
                        .animate(true),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("Decrypting… {}/{}", g.done, g.total))
                        .size(12.0)
                        .color(c_subtext(dark)),
                );
            }
        }

        show_status(ui, &self.decrypt_status, dark);
    }
}
