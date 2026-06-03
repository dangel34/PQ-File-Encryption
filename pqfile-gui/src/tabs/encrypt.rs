use crate::app::PqfileApp;
use crate::colors::{
    c_accent, c_card, c_chrome, c_green, c_overlay, c_red, c_subtext, c_surface0, c_surface1,
    c_text,
};
use crate::types::{KeyDragPayload, OpStatus, Tab};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::pick_folder_files;
use crate::widgets::{
    card, pick_file, pick_files, save_result, scrollable_list, section_label, show_status,
    tab_heading_help,
};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::{encrypt, format::adaptive_chunk_size};
use std::io::Cursor;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
use std::sync::Arc;

enum ListAction {
    None,
    Remove(usize),
    ClearAll,
}

impl PqfileApp {
    pub(crate) fn handle_encrypt_all(&mut self, ctx: &egui::Context) {
        if self.encrypt_recipients.is_empty() {
            return;
        }
        let pub_pems: Vec<String> = self
            .encrypt_recipients
            .iter()
            .map(|r| r.pem.clone())
            .collect();

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.start_encrypt_job(ctx, pub_pems);
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            self.run_encrypt_wasm(pub_pems);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn start_encrypt_job(&mut self, ctx: &egui::Context, pub_pems: Vec<String>) {
        use crate::types::EncryptJob;
        use std::sync::Mutex;

        let confirm = self.settings.confirm_overwrite;
        let compress = self.encrypt_compress;
        let compress_level = self.encrypt_compress_level;
        let pad_recipients = self.encrypt_pad_recipients;
        let output_dir: Option<PathBuf> = if self.settings.output_dir.is_empty() {
            None
        } else {
            Some(PathBuf::from(&self.settings.output_dir))
        };
        let files: Vec<(usize, String, Vec<u8>, Option<PathBuf>)> = self
            .encrypt_files
            .iter()
            .enumerate()
            .map(|(i, e)| (i, e.name.clone(), e.data.clone(), e.path.clone()))
            .collect();
        let total = files.len();

        let job = Arc::new(Mutex::new(EncryptJob {
            done: 0,
            total,
            results: Vec::new(),
            finished: false,
        }));
        self.encrypt_batch_summary = None;
        self.encrypt_job = Some(Arc::clone(&job));

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            for (i, name, data, path) in files {
                let out_name = format!("{name}.pqf");
                let out_path = resolve_out_path(&output_dir, &out_name, path);
                let original_size = data.len() as u64;
                let status = encrypt_entry(
                    &pub_pems,
                    &data,
                    original_size,
                    &out_name,
                    out_path,
                    compress,
                    compress_level,
                    pad_recipients,
                    confirm,
                );
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
    }

    // Enqueue files for frame-by-frame processing on WASM.
    #[cfg(target_arch = "wasm32")]
    fn run_encrypt_wasm(&mut self, pub_pems: Vec<String>) {
        let queue: Vec<(usize, String, Vec<u8>)> = self
            .encrypt_files
            .iter()
            .enumerate()
            .map(|(i, e)| (i, e.name.clone(), e.data.clone()))
            .collect();
        self.encrypt_wasm_total = queue.len();
        self.encrypt_wasm_done = 0;
        self.encrypt_wasm_queue = queue;
        self.encrypt_wasm_pub_pems = pub_pems;
    }

    // Called once per egui frame when the WASM queue is non-empty.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn tick_encrypt_wasm(&mut self, ctx: &egui::Context) {
        if self.encrypt_wasm_queue.is_empty() {
            return;
        }
        let (idx, name, data) = self.encrypt_wasm_queue.remove(0);
        // Browser limit: WASM addressing is 32-bit, so files ≥ 4 GiB cannot be processed.
        if data.len() > u32::MAX as usize {
            if idx < self.encrypt_files.len() {
                self.encrypt_files[idx].status = OpStatus::Err(format!(
                    "File too large for browser ({:.1} GiB). Use the desktop app (limit: 4 GiB).",
                    data.len() as f64 / 1_073_741_824.0
                ));
            }
            self.encrypt_wasm_done += 1;
            ctx.request_repaint();
            return;
        }
        let out_name = format!("{name}.pqf");
        let original_size = data.len() as u64;
        let pad = self.encrypt_pad_recipients;
        let status = encrypt_entry(
            &self.encrypt_wasm_pub_pems.clone(),
            &data,
            original_size,
            &out_name,
            None,
            false,
            3,
            pad,
            false,
        );
        if idx < self.encrypt_files.len() {
            self.encrypt_files[idx].status = status;
        }
        self.encrypt_wasm_done += 1;

        if self.encrypt_wasm_queue.is_empty() {
            // All done: apply auto-clear if every file succeeded.
            let all_ok = self.settings.auto_clear
                && self
                    .encrypt_files
                    .iter()
                    .all(|e| matches!(e.status, OpStatus::Ok(_)));
            if all_ok {
                self.encrypt_recipients.clear();
                self.encrypt_files.clear();
                self.encrypt_wasm_total = 0;
                self.encrypt_wasm_done = 0;
            }
            self.encrypt_wasm_pub_pems.clear();
        }

        ctx.request_repaint();
    }

    pub(crate) fn show_encrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Encrypt File", dark) {
            self.help_modal_open = Some(Tab::Encrypt);
        }
        ui.label(
            RichText::new("Encrypt one or more files to one or more recipients.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        let job_running = self.encrypt_job.is_some();
        #[cfg(target_arch = "wasm32")]
        let job_running = !self.encrypt_wasm_queue.is_empty();

        match self.show_recipients_card(ui, dark, job_running) {
            ListAction::Remove(i) => {
                self.encrypt_recipients.remove(i);
            }
            ListAction::ClearAll => {
                self.encrypt_recipients.clear();
                self.encrypt_batch_summary = None;
            }
            ListAction::None => {}
        }
        ui.add_space(14.0);

        match self.show_files_card(ui, dark, job_running) {
            ListAction::Remove(i) => {
                self.encrypt_files.remove(i);
            }
            ListAction::ClearAll => {
                self.encrypt_files.clear();
                self.encrypt_batch_summary = None;
            }
            ListAction::None => {}
        }
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        self.show_compress_card(ui, dark);

        self.show_encrypt_button(ui, dark, job_running);
        self.show_encrypt_progress(ui, dark);

        // Batch summary after job completes
        if let Some(ref summary) = self.encrypt_batch_summary.clone() {
            ui.add_space(6.0);
            let has_fail = summary.contains("failed");
            let color = if has_fail {
                c_subtext(dark)
            } else {
                c_green(dark)
            };
            ui.label(RichText::new(summary.as_str()).size(12.5).color(color));
        }

        let first_err = self.encrypt_files.iter().find_map(|e| {
            if let OpStatus::Err(m) = &e.status {
                Some(m.as_str())
            } else {
                None
            }
        });
        if let Some(msg) = first_err {
            show_status(ui, &OpStatus::Err(msg.to_owned()), dark);
        }

        // ── Watchfolder section (native only) ────────────────────────────────
        #[cfg(not(target_arch = "wasm32"))]
        self.show_watchfolder_section(ui, dark);
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn show_watchfolder_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        use crate::colors::{c_green, c_overlay, c_text};
        use crate::widgets::scrollable_list;

        ui.add_space(20.0);
        section_label(ui, "WATCH FOLDER (AUTO-ENCRYPT)", dark);
        ui.label(
            RichText::new(
                "Encrypt every new file that appears in a directory automatically. \
                 Uses the recipients configured above.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(6.0);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Watch folder:")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.watch_dir)
                        .hint_text("/path/to/folder")
                        .desired_width(ui.available_width() - 80.0),
                );
                if ui
                    .add(
                        egui::Button::new(RichText::new("Browse…").size(12.0).color(c_text(dark)))
                            .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new()
                        .set_title("Choose folder to watch")
                        .pick_folder()
                    {
                        self.watch_dir = p.to_string_lossy().into_owned();
                    }
                }
            });
            if !self.watch_log.is_empty() {
                ui.add_space(4.0);
                scrollable_list(ui, 80.0, c_card(dark), |ui| {
                    for msg in self.watch_log.iter().rev().take(50) {
                        let color = if msg.starts_with('✓') {
                            c_green(dark)
                        } else if msg.starts_with('⚠') {
                            eframe::egui::Color32::from_rgb(200, 140, 0)
                        } else {
                            c_red(dark)
                        };
                        ui.label(RichText::new(msg).size(11.5).color(color).monospace());
                    }
                });
            }
        });
        ui.add_space(8.0);

        let can_start = !self.watch_dir.is_empty() && !self.encrypt_recipients.is_empty();
        if self.watch_active {
            if ui
                .add(
                    egui::Button::new(
                        RichText::new("⏹  Stop Watching")
                            .size(14.0)
                            .color(c_chrome(dark))
                            .strong(),
                    )
                    .fill(c_accent(dark))
                    .min_size(Vec2::new(170.0, 32.0)),
                )
                .clicked()
            {
                self.stop_watch();
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Watching: {}", self.watch_dir))
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        } else {
            if ui
                .add_enabled(
                    can_start,
                    egui::Button::new(
                        RichText::new("▶  Watch This Folder")
                            .size(14.0)
                            .color(c_chrome(dark))
                            .strong(),
                    )
                    .fill(c_accent(dark))
                    .min_size(Vec2::new(170.0, 32.0)),
                )
                .on_disabled_hover_text("Set a folder and add at least one recipient first.")
                .clicked()
            {
                self.start_watch(ui.ctx());
            }
            if !can_start {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Set a folder path and add recipients to enable watching.")
                        .size(12.0)
                        .color(c_overlay(dark)),
                );
            }
        }
    }

    fn show_recipients_card(
        &mut self,
        ui: &mut egui::Ui,
        dark: bool,
        job_running: bool,
    ) -> ListAction {
        let mut action = ListAction::None;
        section_label(ui, "RECIPIENTS", dark);
        // Accept drag-drops from the Keys panel.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let (drop_resp, payload) =
                ui.dnd_drop_zone::<std::sync::Arc<KeyDragPayload>, _>(egui::Frame::NONE, |_ui| {});
            if drop_resp.response.hovered() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Copy);
            }
            if let Some(payload) = payload {
                let pem = payload.pub_pem.clone();
                if !self.encrypt_recipients.iter().any(|r| r.pem == pem) {
                    let variant_name = crate::types::pem_variant_name(&pem);
                    self.encrypt_recipients.push(crate::types::RecipientEntry {
                        name: payload.label.clone(),
                        pem,
                        variant_name,
                    });
                }
            }
        }
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                let n = self.encrypt_recipients.len();
                if n == 0 {
                    ui.label(
                        RichText::new("No recipients. Browse or drag and drop a public key")
                            .size(13.0)
                            .color(c_overlay(dark)),
                    );
                } else {
                    ui.label(
                        RichText::new(format!("{n} recipient{}", if n == 1 { "" } else { "s" }))
                            .size(13.0)
                            .color(c_subtext(dark)),
                    );
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if !job_running
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new("+ Add Recipient…")
                                        .size(13.0)
                                        .color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .clicked()
                    {
                        pick_file(Arc::clone(&self.encrypt_pubkey.pending), "PEM", &["pem"]);
                    }
                    let n = self.encrypt_recipients.len();
                    if !job_running
                        && n > 0
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Clear all").size(12.0).color(c_subtext(dark)),
                                )
                                .fill(Color32::TRANSPARENT),
                            )
                            .clicked()
                    {
                        action = ListAction::ClearAll;
                    }
                });
            });
            if !self.encrypt_recipients.is_empty() {
                ui.add_space(6.0);
                scrollable_list(ui, 154.0, c_card(dark), |ui| {
                    for (i, r) in self.encrypt_recipients.iter().enumerate() {
                        let remove = recipient_row(ui, &r.variant_name, &r.name, job_running, dark);
                        if remove && matches!(action, ListAction::None) {
                            action = ListAction::Remove(i);
                        }
                    }
                });
            }
        });
        action
    }

    fn show_files_card(&mut self, ui: &mut egui::Ui, dark: bool, job_running: bool) -> ListAction {
        let mut action = ListAction::None;
        section_label(ui, "FILES TO ENCRYPT", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                if self.encrypt_files.is_empty() {
                    ui.label(
                        RichText::new("No files added. Browse or drag and drop")
                            .size(13.0)
                            .color(c_overlay(dark)),
                    );
                } else {
                    let n = self.encrypt_files.len();
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
                        pick_files(Arc::clone(&self.encrypt_batch_pending));
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
                            .on_hover_text("Recursively add every file inside a folder")
                            .clicked()
                    {
                        pick_folder_files(Arc::clone(&self.encrypt_batch_pending));
                    }
                    if !job_running
                        && !self.encrypt_files.is_empty()
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Clear all").size(12.0).color(c_subtext(dark)),
                                )
                                .fill(Color32::TRANSPARENT),
                            )
                            .clicked()
                    {
                        action = ListAction::ClearAll;
                    }
                });
            });
            if !self.encrypt_files.is_empty() {
                ui.add_space(6.0);
                scrollable_list(ui, 154.0, c_card(dark), |ui| {
                    for (i, entry) in self.encrypt_files.iter().enumerate() {
                        let remove =
                            file_entry_row(ui, &entry.name, &entry.status, job_running, dark);
                        if remove && matches!(action, ListAction::None) {
                            action = ListAction::Remove(i);
                        }
                    }
                });
            } else {
                // Show recently used files when the list is empty (native only).
                #[cfg(not(target_arch = "wasm32"))]
                if !self.recent_encrypt_files.is_empty() && !job_running {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Recent:").size(11.5).color(c_subtext(dark)));
                    let mut to_add: Option<std::path::PathBuf> = None;
                    for path_str in self.recent_encrypt_files.iter().take(5) {
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
                            self.encrypt_files.push(crate::types::MultiFileEntry {
                                name,
                                data,
                                path: Some(p),
                                status: crate::types::OpStatus::None,
                            });
                        }
                    }
                }
            }
        });
        action
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn show_compress_card(&mut self, ui: &mut egui::Ui, dark: bool) {
        let single_recipient = self.encrypt_recipients.len() == 1;
        let multi_recipient = self.encrypt_recipients.len() > 1;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                ui.add_enabled(
                    single_recipient,
                    egui::Checkbox::new(&mut self.encrypt_compress, ""),
                );
                let compress_lbl = ui.label(
                    RichText::new("Compress before encrypting (zstd, single recipient only)")
                        .size(13.0)
                        .color(if single_recipient {
                            c_text(dark)
                        } else {
                            c_overlay(dark)
                        }),
                );
                if multi_recipient {
                    compress_lbl.on_hover_text(
                        "Compression is disabled for multi-recipient files because content \
                         length leaks information about the plaintext across independently \
                         keyed slots.",
                    );
                }
                if single_recipient && self.encrypt_compress {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Slider::new(&mut self.encrypt_compress_level, 1..=19).text(""),
                        )
                        .on_hover_text("Compression level (1=fastest, 19=best)");
                        ui.label(RichText::new("Level:").size(12.0).color(c_subtext(dark)));
                    });
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add_enabled(
                    multi_recipient,
                    egui::Checkbox::new(&mut self.encrypt_pad_recipients, ""),
                );
                ui.label(
                    RichText::new(
                        "Pad recipient count to next power of two (v9, multiple recipients only)",
                    )
                    .size(13.0)
                    .color(if multi_recipient {
                        c_text(dark)
                    } else {
                        c_overlay(dark)
                    }),
                )
                .on_hover_text(
                    "Adds random dummy slots so an observer cannot determine the exact \
                     number of real recipients. Produces v9 format instead of v8.",
                );
            });
        });
        ui.add_space(14.0);
    }

    fn show_encrypt_button(&mut self, ui: &mut egui::Ui, dark: bool, job_running: bool) {
        let n = self.encrypt_files.len();
        let ready = !self.encrypt_recipients.is_empty() && n > 0 && !job_running;
        let btn_label = if n == 0 {
            "🔒  Encrypt All".to_owned()
        } else {
            format!("🔒  Encrypt All ({n})")
        };
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new(btn_label)
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(170.0, 32.0)),
            )
            .clicked()
        {
            self.handle_encrypt_all(ui.ctx());
        }
        if !ready && !job_running {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Add at least one recipient key and one file to continue.")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }
        // Output path preview for first file (native only).
        #[cfg(not(target_arch = "wasm32"))]
        if ready {
            if let Some(first) = self.encrypt_files.first() {
                let out_name = format!("{}.pqf", first.name);
                let preview: String = if self.settings.output_dir.is_empty() {
                    if let Some(ref p) = first.path {
                        let mut s = p.as_os_str().to_owned();
                        s.push(".pqf");
                        std::path::PathBuf::from(s).to_string_lossy().into_owned()
                    } else {
                        out_name
                    }
                } else {
                    std::path::PathBuf::from(&self.settings.output_dir)
                        .join(&out_name)
                        .to_string_lossy()
                        .into_owned()
                };
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("Output: {preview}"))
                        .size(11.5)
                        .color(c_overlay(dark)),
                );
                if n > 1 {
                    ui.label(
                        RichText::new(format!("…and {} more", n - 1))
                            .size(11.5)
                            .color(c_overlay(dark)),
                    );
                }
            }
        }
    }

    fn show_encrypt_progress(&self, ui: &mut egui::Ui, dark: bool) {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(job) = &self.encrypt_job {
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
                    RichText::new(format!("Encrypting… {}/{}", g.done, g.total))
                        .size(12.0)
                        .color(c_subtext(dark)),
                );
            }
        }
        #[cfg(target_arch = "wasm32")]
        if self.encrypt_wasm_total > 0 {
            let fraction = self.encrypt_wasm_done as f32 / self.encrypt_wasm_total as f32;
            ui.add_space(10.0);
            ui.add(
                egui::ProgressBar::new(fraction)
                    .desired_width(f32::INFINITY)
                    .animate(!self.encrypt_wasm_queue.is_empty()),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!(
                    "Encrypting… {}/{}",
                    self.encrypt_wasm_done, self.encrypt_wasm_total
                ))
                .size(12.0)
                .color(c_subtext(dark)),
            );
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_out_path(
    output_dir: &Option<PathBuf>,
    out_name: &str,
    path: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(ref dir) = output_dir {
        Some(dir.join(out_name))
    } else {
        path.map(|p| {
            let mut s = p.as_os_str().to_owned();
            s.push(".pqf");
            PathBuf::from(s)
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn encrypt_entry(
    pub_pems: &[String],
    data: &[u8],
    original_size: u64,
    out_name: &str,
    out_path: Option<std::path::PathBuf>,
    compress: bool,
    compress_level: i32,
    pad_recipients: bool,
    confirm: bool,
) -> OpStatus {
    let chunk_size = adaptive_chunk_size(original_size);
    let (effective_path, effective_confirm) = (out_path, confirm);
    if pub_pems.len() == 1 {
        let mut reader = Cursor::new(data);
        let mut out = Vec::new();
        let result = if compress {
            encrypt::encrypt_stream_compressed(
                &pub_pems[0],
                original_size,
                chunk_size,
                compress_level,
                &mut reader,
                &mut out,
            )
        } else {
            encrypt::encrypt_stream(
                &pub_pems[0],
                original_size,
                chunk_size,
                &mut reader,
                &mut out,
            )
        };
        match result {
            Ok(()) => save_result(out_name, &out, effective_path, effective_confirm),
            Err(e) => OpStatus::Err(e.to_string()),
        }
    } else {
        let pem_refs: Vec<&str> = pub_pems.iter().map(|s| s.as_str()).collect();
        let mut reader = Cursor::new(data);
        let mut out = Vec::new();
        // v9: pad slot count to next power of two (stronger recipient-count anonymity)
        // v8: variant-blind slots, shuffled order (hides key types only)
        let result = if pad_recipients {
            encrypt::encrypt_stream_multi_anon_padded(
                &pem_refs,
                original_size,
                &mut reader,
                &mut out,
            )
        } else {
            encrypt::encrypt_stream_multi_anon(&pem_refs, original_size, &mut reader, &mut out)
        };
        match result {
            Ok(()) => save_result(out_name, &out, effective_path, effective_confirm),
            Err(e) => OpStatus::Err(e.to_string()),
        }
    }
}

fn recipient_row(
    ui: &mut egui::Ui,
    variant_name: &str,
    name: &str,
    job_running: bool,
    dark: bool,
) -> bool {
    let mut remove = false;
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, 22.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            let badge_color = variant_badge_color(variant_name, dark);
            ui.label(
                RichText::new(variant_name)
                    .size(11.0)
                    .color(badge_color)
                    .monospace(),
            );
            ui.add_space(6.0);
            ui.label(RichText::new(name).size(13.0).color(c_text(dark)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !job_running {
                    remove = ui
                        .add(
                            egui::Button::new(RichText::new("x").size(11.0).color(c_overlay(dark)))
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::NONE),
                        )
                        .clicked();
                }
            });
        });
    });
    remove
}

fn file_entry_row(
    ui: &mut egui::Ui,
    name: &str,
    status: &OpStatus,
    job_running: bool,
    dark: bool,
) -> bool {
    let mut remove = false;
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, 22.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.label(RichText::new(name).size(13.0).color(c_text(dark)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !job_running {
                    remove = ui
                        .add(
                            egui::Button::new(RichText::new("x").size(11.0).color(c_overlay(dark)))
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::NONE),
                        )
                        .clicked();
                }
                match status {
                    OpStatus::None => {}
                    OpStatus::Ok(_) => {
                        ui.label(RichText::new("OK").size(12.0).color(c_green(dark)));
                    }
                    OpStatus::Err(m) => {
                        let display: String = m.chars().take(32).collect();
                        ui.label(RichText::new(display).size(12.0).color(c_red(dark)));
                    }
                }
            });
        });
    });
    remove
}

fn variant_badge_color(variant_name: &str, dark: bool) -> eframe::egui::Color32 {
    use crate::colors::c_accent;
    if variant_name.starts_with("Hybrid") {
        if dark {
            eframe::egui::Color32::from_rgb(180, 120, 220)
        } else {
            eframe::egui::Color32::from_rgb(100, 40, 160)
        }
    } else if variant_name.contains("1024") {
        if dark {
            eframe::egui::Color32::from_rgb(100, 200, 240)
        } else {
            eframe::egui::Color32::from_rgb(0, 100, 160)
        }
    } else {
        c_accent(dark)
    }
}
