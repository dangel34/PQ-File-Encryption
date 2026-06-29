use crate::app::PqfileApp;
use crate::colors::{
    c_accent, c_card, c_chrome, c_green, c_overlay, c_red, c_subtext, c_surface0, c_surface1,
    c_text,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::types::KeyDragPayload;
use crate::types::{DecryptSubTab, OpStatus, Tab};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::pick_folder_pqf;
use crate::widgets::{
    card, file_row, passphrase_row, pick_pqf_files, save_result, scrollable_list, section_label,
    seg_tabs, show_status, tab_heading_help,
};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::{decrypt, keygen, rekey};
use std::io::Cursor;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};

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
        self.decrypt_batch_summary = None;

        let passphrase: Option<zeroize::Zeroizing<String>> = if self.decrypt_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new((*self.decrypt_passphrase).clone()))
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
                current_file_bytes_done: 0,
                current_file_bytes_total: 0,
            }));
            self.decrypt_batch_job = Some(Arc::clone(&job));

            let ctx = ctx.clone();
            std::thread::spawn(move || {
                for (i, name, data, path) in files {
                    let pp = passphrase.as_deref().map(String::as_str);
                    // Reset per-file byte progress.
                    {
                        let mut g = job.lock().unwrap();
                        g.current_file_bytes_done = 0;
                        g.current_file_bytes_total = 0;
                    }
                    let job_progress = Arc::clone(&job);
                    let ctx_progress = ctx.clone();
                    let result: Result<Vec<u8>, _> = {
                        let mut cursor = Cursor::new(&data);
                        let mut out = Vec::new();
                        decrypt::decrypt_stream_parallel_with_progress(
                            &priv_pem,
                            &mut cursor,
                            &mut out,
                            pp,
                            8, // parallel batch size (matches CLI default)
                            0, // total_hint unknown until header is parsed
                            &move |done: u64, total: u64| {
                                let mut g = job_progress.lock().unwrap();
                                g.current_file_bytes_done = done;
                                g.current_file_bytes_total = total;
                                drop(g);
                                ctx_progress.request_repaint();
                            },
                        )
                        .map(|_| out)
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
                        g.current_file_bytes_done = 0;
                        g.current_file_bytes_total = 0;
                        g.results.push((i, status));
                    }
                    ctx.request_repaint();
                }
                job.lock().unwrap().finished = true;
                ctx.request_repaint();
            });
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            let pp = passphrase.as_deref().map(String::as_str);
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
                && self
                    .decrypt_files
                    .iter()
                    .all(|e| matches!(e.status, OpStatus::Ok(_)))
            {
                self.decrypt_privkey.clear();
                self.decrypt_files.clear();
                self.decrypt_passphrase.clear();
            }
        }
    }

    pub(crate) fn show_decrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Decrypt / Rekey", dark) {
            self.help_modal_open = Some(Tab::Decrypt);
        }
        ui.label(
            RichText::new(
                "Decrypt .pqf files with your private key, or use Rekey to transfer a \
                 ciphertext to a new recipient without decrypting the payload.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(10.0);

        seg_tabs(
            ui,
            &mut self.decrypt_sub_tab,
            &[
                ("Decrypt Files", DecryptSubTab::Decrypt),
                ("Rekey File", DecryptSubTab::Rekey),
            ],
            dark,
        );

        match self.decrypt_sub_tab {
            DecryptSubTab::Decrypt => self.show_decrypt_section(ui, dark),
            DecryptSubTab::Rekey => self.show_rekey_section(ui, dark),
        }
    }

    fn show_decrypt_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        ui.add_space(4.0);

        #[cfg(not(target_arch = "wasm32"))]
        let job_running = self.decrypt_batch_job.is_some();
        #[cfg(target_arch = "wasm32")]
        let job_running = false;

        // ── Private key ───────────────────────────────────────────────────────
        section_label(ui, "PRIVATE KEY", dark);
        // Accept drag-drop of private key from the Keys panel (native only).
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (drop_resp, payload) =
                ui.dnd_drop_zone::<std::sync::Arc<KeyDragPayload>, _>(egui::Frame::NONE, |_ui| {});
            if drop_resp.response.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Copy);
            }
            if let Some(payload) = payload {
                if let Some(ref priv_path) = payload.priv_path {
                    if let Ok(data) = std::fs::read(priv_path) {
                        self.decrypt_privkey.name = priv_path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "privkey.pem".to_owned());
                        self.decrypt_privkey.data = Some(data);
                        self.decrypt_privkey.path = Some(priv_path.clone());
                    }
                }
            }
        }
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Private key (.pem)",
                &mut self.decrypt_privkey,
                "PEM",
                &["pem"],
                dark,
            );
        });
        ui.add_space(14.0);

        // Show passphrase field only when the loaded key is encrypted.
        let key_is_encrypted = self
            .decrypt_privkey
            .as_str()
            .map(keygen::is_encrypted_key)
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
                                    RichText::new("+ Add Folder…")
                                        .size(13.0)
                                        .color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .on_hover_text("Recursively add every .pqf file inside a folder")
                            .clicked()
                    {
                        pick_folder_pqf(std::sync::Arc::clone(&self.decrypt_batch_pending));
                    }
                    if !job_running
                        && !self.decrypt_files.is_empty()
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Clear all").size(12.0).color(c_subtext(dark)),
                                )
                                .fill(Color32::TRANSPARENT),
                            )
                            .clicked()
                    {
                        self.decrypt_files.clear();
                        self.decrypt_batch_summary = None;
                    }
                });
            });

            // Recent .pqf files when the list is empty (native only).
            #[cfg(not(target_arch = "wasm32"))]
            if self.decrypt_files.is_empty()
                && !job_running
                && !self.recent_decrypt_files.is_empty()
            {
                ui.add_space(6.0);
                ui.label(RichText::new("Recent:").size(11.5).color(c_subtext(dark)));
                let mut to_add: Option<std::path::PathBuf> = None;
                for path_str in self.recent_decrypt_files.iter().take(5) {
                    let path = std::path::Path::new(path_str);
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path_str.clone());
                    if path.exists()
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new(&name).size(12.0).color(c_text(dark)),
                                )
                                .fill(Color32::TRANSPARENT),
                            )
                            .on_hover_text(path_str.as_str())
                            .clicked()
                    {
                        to_add = Some(path.to_path_buf());
                    }
                }
                if let Some(p) = to_add {
                    if let Ok(data) = std::fs::read(&p) {
                        let name = p
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        self.decrypt_files.push(crate::types::MultiFileEntry {
                            name,
                            data,
                            path: Some(p),
                            status: crate::types::OpStatus::None,
                        });
                    }
                }
            }

            if !self.decrypt_files.is_empty() {
                ui.add_space(6.0);
                scrollable_list(ui, 154.0, c_card(dark), |ui| {
                    for (i, entry) in self.decrypt_files.iter().enumerate() {
                        let mut remove = false;
                        let w = ui.available_width();
                        ui.allocate_ui(egui::vec2(w, 22.0), |ui| {
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
                                                RichText::new("OK").size(12.0).color(c_green(dark)),
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
                                    ui.with_layout(
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(&entry.name)
                                                        .size(13.0)
                                                        .color(c_text(dark)),
                                                )
                                                .truncate(),
                                            )
                                            .on_hover_text(&entry.name);
                                        },
                                    );
                                },
                            );
                        });
                        if remove && to_remove.is_none() {
                            to_remove = Some(i);
                        }
                    }
                });
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
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    ready,
                    egui::Button::new(
                        RichText::new(&btn_label)
                            .size(14.0)
                            .color(c_chrome(dark))
                            .strong(),
                    )
                    .fill(c_accent(dark))
                    .min_size(Vec2::new(170.0, 32.0)),
                )
                .clicked()
                || (ready
                    && ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter)))
            {
                self.handle_decrypt_batch(ui.ctx());
            }
            if job_running {
                ui.add(egui::Spinner::new().size(20.0).color(c_accent(dark)));
            }
        });

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
                if g.current_file_bytes_done > 0 {
                    ui.add_space(2.0);
                    let mib = g.current_file_bytes_done as f32 / (1024.0 * 1024.0);
                    // Show indeterminate bar (total is unknown for decrypt); display byte count.
                    ui.add(
                        egui::ProgressBar::new(0.0)
                            .desired_width(f32::INFINITY)
                            .text(format!("{mib:.1} MiB"))
                            .animate(true),
                    );
                }
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("Decrypting… {}/{}", g.done, g.total))
                        .size(12.0)
                        .color(c_subtext(dark)),
                );
            }
        }

        // Batch operation summary
        if let Some(ref summary) = self.decrypt_batch_summary.clone() {
            ui.add_space(6.0);
            let has_fail = summary.contains("failed");
            let color = if has_fail {
                c_subtext(dark)
            } else {
                c_green(dark)
            };
            ui.label(RichText::new(summary.as_str()).size(12.5).color(color));
        }

        show_status(ui, &self.decrypt_status, dark);
    }

    // ── Rekey ─────────────────────────────────────────────────────────────

    fn show_rekey_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        ui.add_space(4.0);
        section_label(ui, "REKEY FILE", dark);
        ui.label(
            RichText::new(
                "Transfer a .pqf file to a new recipient without decrypting the payload. \
                 The session key is decapsulated with the old private key and re-encapsulated \
                 for the new recipient. The encrypted content is untouched.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(6.0);
        let mut pp_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Old private key (for decapsulation)",
                &mut self.rekey_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            pp_submitted = passphrase_row(
                ui,
                "Old key passphrase:",
                &mut self.rekey_privkey_passphrase,
                &mut self.rekey_privkey_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "New recipient public key",
                &mut self.rekey_new_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Encrypted file to rekey (.pqf)",
                &mut self.rekey_input,
                "PQF",
                &["pqf"],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.rekey_privkey.loaded()
            && self.rekey_new_pubkey.loaded()
            && self.rekey_input.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔄  Rekey File")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .clicked()
            || (ready
                && (pp_submitted
                    || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
        {
            self.do_rekey();
        }

        show_status(ui, &self.rekey_status, dark);
    }

    fn do_rekey(&mut self) {
        let old_priv = match self.rekey_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.rekey_status = OpStatus::Err("Load the old private key first.".to_owned());
                return;
            }
        };
        let new_pub = match self.rekey_new_pubkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.rekey_status =
                    OpStatus::Err("Load the new recipient public key first.".to_owned());
                return;
            }
        };
        let data = match self.rekey_input.data.clone() {
            Some(d) => d,
            None => {
                self.rekey_status =
                    OpStatus::Err("Choose the .pqf file to rekey first.".to_owned());
                return;
            }
        };
        let passphrase = if self.rekey_privkey_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.rekey_privkey_passphrase).clone(),
            ))
        };

        let mut output = Vec::new();
        let mut reader = Cursor::new(&data);
        match rekey::rekey_stream(
            &old_priv,
            &new_pub,
            &mut reader,
            &mut output,
            passphrase.as_deref().map(String::as_str),
        ) {
            Ok(()) => {
                let out_name = self.rekey_input.name.clone();
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = {
                    let base = self
                        .rekey_input
                        .path
                        .clone()
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
                let native_path: Option<PathBuf> = None;
                self.rekey_status = save_result(
                    &out_name,
                    &output,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.rekey_status = OpStatus::Err(e.to_string());
            }
        }
    }
}
