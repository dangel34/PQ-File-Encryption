use crate::app::PqfileApp;
use crate::colors::{
    c_accent, c_card, c_chrome, c_green, c_overlay, c_red, c_subtext, c_surface0, c_surface1,
    c_text, c_yellow,
};
use crate::types::{EncryptMode, OpStatus, SecondFactorMode, Tab};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::pick_folder_files;
use crate::widgets::{
    card, pick_file, pick_files, save_result, scrollable_list, section_label, show_status,
    tab_heading_help,
};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::padding::PadmeReader;
use pqfile::{encrypt, format::adaptive_chunk_size};
use std::io::{Cursor, Read};
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

enum ListAction {
    None,
    Remove(usize),
    ClearAll,
}

/// What to encrypt each file to, resolved once per batch (not once per file):
/// either the public-key recipient list, or a v10 passphrase with an optional
/// second factor. `Fido2 { .. }` carries the enrollment path and PIN rather
/// than an already-derived secret, since deriving it means touching hardware
/// and must happen on the worker thread, not the UI thread.
enum EncryptTarget {
    PublicKeys(Vec<String>),
    Passphrase {
        passphrase: Zeroizing<String>,
        keyfile: Option<Vec<u8>>,
        #[cfg_attr(
            not(all(not(target_arch = "wasm32"), feature = "fido2")),
            allow(dead_code)
        )]
        fido2: Option<(std::path::PathBuf, Option<Zeroizing<String>>)>,
    },
}

impl PqfileApp {
    pub(crate) fn handle_encrypt_all(&mut self, ctx: &egui::Context) {
        let target = match self.build_encrypt_target() {
            Ok(t) => t,
            Err(msg) => {
                self.encrypt_batch_summary = Some(OpStatus::Err(msg));
                return;
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.start_encrypt_job(ctx, target);
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = ctx;
            self.run_encrypt_wasm(target);
        }
    }

    /// Validates the current mode's inputs and builds the `EncryptTarget` for
    /// the batch, without touching any hardware or file I/O beyond what's
    /// already loaded in memory (FIDO2 derivation happens later, per-batch,
    /// on the worker thread).
    fn build_encrypt_target(&self) -> Result<EncryptTarget, String> {
        match self.encrypt_mode {
            EncryptMode::PublicKey => {
                if self.encrypt_recipients.is_empty() {
                    return Err("Add at least one recipient.".to_owned());
                }
                Ok(EncryptTarget::PublicKeys(
                    self.encrypt_recipients
                        .iter()
                        .map(|r| r.pem.clone())
                        .collect(),
                ))
            }
            EncryptMode::Passphrase => {
                if self.encrypt_passphrase.is_empty() {
                    return Err("Enter a passphrase.".to_owned());
                }
                if *self.encrypt_passphrase != *self.encrypt_passphrase_confirm {
                    return Err("Passphrases do not match.".to_owned());
                }
                let (keyfile, fido2) = match self.encrypt_second_factor {
                    SecondFactorMode::None => (None, None),
                    SecondFactorMode::Keyfile => {
                        let Some(data) = self.encrypt_keyfile.data.clone() else {
                            return Err("Choose a keyfile.".to_owned());
                        };
                        (Some(data), None)
                    }
                    SecondFactorMode::Fido2 => {
                        let Some(path) = self.encrypt_fido2_enrollment.path.clone() else {
                            return Err("Choose a FIDO2 enrollment file.".to_owned());
                        };
                        #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
                        let pin = if self.encrypt_fido2_pin.is_empty() {
                            None
                        } else {
                            Some(self.encrypt_fido2_pin.clone())
                        };
                        #[cfg(not(all(not(target_arch = "wasm32"), feature = "fido2")))]
                        let pin: Option<Zeroizing<String>> = None;
                        (None, Some((path, pin)))
                    }
                };
                Ok(EncryptTarget::Passphrase {
                    passphrase: self.encrypt_passphrase.clone(),
                    keyfile,
                    fido2,
                })
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn start_encrypt_job(&mut self, ctx: &egui::Context, target: EncryptTarget) {
        use crate::types::EncryptJob;
        use std::sync::Mutex;

        let confirm = self.settings.confirm_overwrite;
        let compress = self.encrypt_compress;
        let compress_level = self.encrypt_compress_level;
        let pad_recipients = self.encrypt_pad_recipients;
        let pad = self.encrypt_pad;
        let stealth = self.encrypt_stealth;
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
            current_file_bytes_done: 0,
            current_file_bytes_total: 0,
        }));
        self.encrypt_batch_summary = None;
        self.encrypt_job = Some(Arc::clone(&job));

        let ctx = ctx.clone();
        // Post-quantum crypto (esp. unoptimized debug builds) can use more
        // stack than the default ~2 MiB thread stack provides; spawn with a
        // larger stack to avoid a silent stack-overflow crash.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                // Resolve the FIDO2 second factor once for the whole batch: it
                // means touching hardware, so files reuse the same secret
                // rather than prompting a touch per file.
                let target = match resolve_encrypt_target(target) {
                    Ok(t) => t,
                    Err(msg) => {
                        for (i, ..) in &files {
                            job.lock()
                                .unwrap()
                                .results
                                .push((*i, OpStatus::Err(msg.clone())));
                        }
                        job.lock().unwrap().finished = true;
                        ctx.request_repaint();
                        return;
                    }
                };
                for (i, name, data, path) in files {
                    let out_name = format!("{name}.pqf");
                    let out_path = resolve_out_path(&output_dir, &out_name, path);
                    let original_size = data.len() as u64;
                    {
                        let mut g = job.lock().unwrap();
                        g.current_file_bytes_done = 0;
                        g.current_file_bytes_total = original_size;
                    }
                    let job_progress = Arc::clone(&job);
                    let ctx_progress = ctx.clone();
                    let progress = move |done: u64, _total: u64| {
                        job_progress.lock().unwrap().current_file_bytes_done = done;
                        ctx_progress.request_repaint();
                    };
                    let status = encrypt_entry(
                        &target,
                        &data,
                        original_size,
                        &out_name,
                        out_path,
                        compress,
                        compress_level,
                        pad_recipients,
                        pad,
                        stealth,
                        confirm,
                        &progress,
                    );
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
            })
            .expect("failed to spawn encrypt worker thread");
    }

    // Enqueue files for frame-by-frame processing on WASM.
    #[cfg(target_arch = "wasm32")]
    fn run_encrypt_wasm(&mut self, target: EncryptTarget) {
        let queue: Vec<(usize, String, Vec<u8>)> = self
            .encrypt_files
            .iter()
            .enumerate()
            .map(|(i, e)| (i, e.name.clone(), e.data.clone()))
            .collect();
        // WASM has no FIDO2 backend at all; resolve_encrypt_target only ever
        // does real work for the (unreachable here) Fido2 variant, so this
        // can't fail on this target.
        self.encrypt_wasm_target = resolve_encrypt_target(target).ok();
        self.encrypt_wasm_total = queue.len();
        self.encrypt_wasm_done = 0;
        self.encrypt_wasm_queue = queue;
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
        let pad_recipients = self.encrypt_pad_recipients;
        let pad = self.encrypt_pad;
        let stealth = self.encrypt_stealth;
        let status = if let Some(target) = &self.encrypt_wasm_target {
            encrypt_entry(
                target,
                &data,
                original_size,
                &out_name,
                None,
                false,
                3,
                pad_recipients,
                pad,
                stealth,
                false,
                &|_, _| {},
            )
        } else {
            OpStatus::Err("Encryption target was not resolved.".to_owned())
        };
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
                self.encrypt_passphrase.clear();
                self.encrypt_passphrase_confirm.clear();
            }
            self.encrypt_wasm_target = None;
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

        crate::widgets::seg_tabs(
            ui,
            &mut self.encrypt_mode,
            &[
                ("Public Key", EncryptMode::PublicKey),
                ("Passphrase", EncryptMode::Passphrase),
            ],
            dark,
        );

        match self.encrypt_mode {
            EncryptMode::PublicKey => {
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
            }
            EncryptMode::Passphrase => {
                self.show_encrypt_passphrase_card(ui, dark, job_running);
                ui.add_space(14.0);
                self.show_encrypt_second_factor_card(ui, dark, job_running);
                ui.add_space(14.0);
            }
        }

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
        if self.encrypt_mode == EncryptMode::PublicKey {
            self.show_compress_card(ui, dark);
        }

        self.show_padding_stealth_card(ui, dark);

        self.show_encrypt_button(ui, dark, job_running);
        self.show_encrypt_progress(ui, dark);

        // Batch summary after job completes
        if let Some(summary) = self.encrypt_batch_summary.clone() {
            show_status(ui, &summary, dark);
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

        // ── Watchfolder section (native only, public-key mode only) ──────────
        #[cfg(not(target_arch = "wasm32"))]
        if self.encrypt_mode == EncryptMode::PublicKey {
            self.show_watchfolder_section(ui, dark);
        }
    }

    fn show_encrypt_passphrase_card(&mut self, ui: &mut egui::Ui, dark: bool, job_running: bool) {
        section_label(ui, "PASSPHRASE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.add_enabled(
                !job_running,
                egui::TextEdit::singleline(&mut *self.encrypt_passphrase)
                    .hint_text("Enter passphrase…")
                    .password(!self.encrypt_passphrase_visible)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add_enabled(
                    !job_running,
                    egui::TextEdit::singleline(&mut *self.encrypt_passphrase_confirm)
                        .hint_text("Confirm passphrase…")
                        .password(!self.encrypt_passphrase_visible)
                        .desired_width(ui.available_width() - 60.0),
                );
                if ui
                    .checkbox(&mut self.encrypt_passphrase_visible, "show")
                    .changed()
                {}
            });
            if !self.encrypt_passphrase.is_empty()
                && !self.encrypt_passphrase_confirm.is_empty()
                && *self.encrypt_passphrase != *self.encrypt_passphrase_confirm
            {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Passphrases do not match.")
                        .size(12.0)
                        .color(c_red(dark)),
                );
            }
        });
        ui.label(
            RichText::new(
                "No key pair needed: the file is encrypted directly with this passphrase \
                 (v10 format). Anyone with the passphrase (and second factor, if set below) \
                 can decrypt it.",
            )
            .size(11.5)
            .color(c_subtext(dark)),
        );
    }

    fn show_encrypt_second_factor_card(
        &mut self,
        ui: &mut egui::Ui,
        dark: bool,
        job_running: bool,
    ) {
        section_label(ui, "SECOND FACTOR (OPTIONAL)", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.add_enabled_ui(!job_running, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut self.encrypt_second_factor,
                        SecondFactorMode::None,
                        "None",
                    );
                    ui.selectable_value(
                        &mut self.encrypt_second_factor,
                        SecondFactorMode::Keyfile,
                        "Keyfile",
                    );
                    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
                    ui.selectable_value(
                        &mut self.encrypt_second_factor,
                        SecondFactorMode::Fido2,
                        "FIDO2 token",
                    );
                });
                match self.encrypt_second_factor {
                    SecondFactorMode::None => {}
                    SecondFactorMode::Keyfile => {
                        ui.add_space(6.0);
                        crate::widgets::file_row(
                            ui,
                            "Keyfile (any non-empty file)",
                            &mut self.encrypt_keyfile,
                            "",
                            &[],
                            dark,
                        );
                        ui.label(
                            RichText::new(
                                "Decryption will require this exact file's bytes in addition \
                                 to the passphrase.",
                            )
                            .size(11.5)
                            .color(c_subtext(dark)),
                        );
                    }
                    SecondFactorMode::Fido2 => {
                        #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
                        self.show_encrypt_fido2_second_factor(ui, dark);
                    }
                }
            });
        });
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
            // Captured before entering `horizontal`: inside a horizontal layout,
            // `ui.available_width()` reports f32::INFINITY (the row has no end
            // yet), which previously fed an infinite desired_width into
            // TextEdit and crashed egui's layout code with a NaN rect.
            let row_w = ui.available_width();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Watch folder:")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.watch_dir)
                        .hint_text("/path/to/folder")
                        .desired_width((row_w - 80.0).max(50.0)),
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
                scrollable_list(ui, "encrypt_watch_log", 80.0, c_card(dark), |ui| {
                    for msg in self.watch_log.iter().rev().take(50) {
                        let color = if msg.starts_with('✔') {
                            c_green(dark)
                        } else if msg.starts_with('⚠') {
                            c_yellow(dark)
                        } else {
                            c_red(dark)
                        };
                        ui.label(RichText::new(msg).size(11.5).color(color));
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
                #[cfg(target_arch = "wasm32")]
                let mut remember_idx: Option<usize> = None;
                scrollable_list(ui, "encrypt_recipients", 154.0, c_card(dark), |ui| {
                    for (i, r) in self.encrypt_recipients.iter().enumerate() {
                        let remove = recipient_row(ui, &r.variant_name, &r.name, job_running, dark);
                        if remove && matches!(action, ListAction::None) {
                            action = ListAction::Remove(i);
                        }
                        #[cfg(target_arch = "wasm32")]
                        if !job_running
                            && ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("☆ Remember")
                                            .size(11.0)
                                            .color(c_subtext(dark)),
                                    )
                                    .fill(Color32::TRANSPARENT),
                                )
                                .on_hover_text(
                                    "Save this public key in the Keys tab for future sessions",
                                )
                                .clicked()
                        {
                            #[cfg(target_arch = "wasm32")]
                            {
                                remember_idx = Some(i);
                            }
                        }
                    }
                });
                #[cfg(target_arch = "wasm32")]
                if let Some(i) = remember_idx {
                    if let Some(r) = self.encrypt_recipients.get(i) {
                        let label = r.name.clone();
                        let pem = r.pem.clone();
                        if !self.wasm_saved_pubkeys.iter().any(|(_, p)| p == &pem) {
                            self.wasm_saved_pubkeys.push((label, pem));
                        }
                    }
                }
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
                scrollable_list(ui, "encrypt_files", 154.0, c_card(dark), |ui| {
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
                            egui::Slider::new(&mut self.encrypt_compress_level, 1..=22).text(""),
                        )
                        .on_hover_text(
                            "Compression level (1=fastest, 22=best; levels 20-22 are very slow)",
                        );
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

    /// Padmé length padding and stealth mode. Shown on both native and WASM
    /// builds (unlike compression, neither depends on platform-specific
    /// crates), so this is a separate card from `show_compress_card`.
    fn show_padding_stealth_card(&mut self, ui: &mut egui::Ui, dark: bool) {
        let single_recipient = self.encrypt_recipients.len() == 1;
        let multi_recipient = self.encrypt_recipients.len() > 1;
        #[cfg(not(target_arch = "wasm32"))]
        let compress_active = self.encrypt_compress;
        #[cfg(target_arch = "wasm32")]
        let compress_active = false;

        let pad_enabled = !compress_active;
        let stealth_enabled = single_recipient && !compress_active;

        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                ui.add_enabled(pad_enabled, egui::Checkbox::new(&mut self.encrypt_pad, ""));
                ui.label(
                    RichText::new("Pad plaintext length (hides exact file size)")
                        .size(13.0)
                        .color(if pad_enabled {
                            c_text(dark)
                        } else {
                            c_overlay(dark)
                        }),
                )
                .on_hover_text(
                    "Rounds the ciphertext length to a coarser bucket (at most ~12% overhead) \
                     so an observer watching file sizes cannot determine the exact plaintext \
                     length. The true size still travels inside the authenticated header; \
                     decrypting strips the padding back off automatically, with nothing to \
                     configure on the Decrypt tab. Not available together with compression \
                     (compression would shrink the padding back down, defeating it).",
                );
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add_enabled(
                    stealth_enabled,
                    egui::Checkbox::new(&mut self.encrypt_stealth, ""),
                );
                let stealth_lbl = ui.label(
                    RichText::new("Stealth mode (no magic bytes, single recipient only)")
                        .size(13.0)
                        .color(if stealth_enabled {
                            c_text(dark)
                        } else {
                            c_overlay(dark)
                        }),
                );
                stealth_lbl.on_hover_text(
                    "Omits the .pqf magic bytes, version byte, and KEM variant field entirely, \
                     so the output is not identifiable as pqfile ciphertext to an observer. \
                     Decrypting requires checking \"Stealth mode\" on the Decrypt tab yourself - \
                     there is nothing left on the file to auto-detect this.",
                );
            });
            if multi_recipient && self.encrypt_stealth {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "Stealth mode requires exactly one recipient; ignored for this batch.",
                    )
                    .size(11.5)
                    .color(c_yellow(dark)),
                );
            }
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
                self.handle_encrypt_all(ui.ctx());
            }
            if job_running {
                ui.add(egui::Spinner::new().size(20.0).color(c_accent(dark)));
            }
        });
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
                ui.add(egui::ProgressBar::new(fraction).animate(true));
                if g.current_file_bytes_total > 0 {
                    let byte_frac =
                        g.current_file_bytes_done as f32 / g.current_file_bytes_total as f32;
                    ui.add_space(2.0);
                    ui.add(egui::ProgressBar::new(byte_frac).show_percentage());
                }
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
            ui.add(egui::ProgressBar::new(fraction).animate(!self.encrypt_wasm_queue.is_empty()));
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
/// Wraps `data` with Padmé length padding when `pad` is set, otherwise reads it unchanged.
fn padded_reader(data: &[u8], original_size: u64, pad: bool) -> Box<dyn Read + '_> {
    if pad {
        Box::new(PadmeReader::new(Cursor::new(data), original_size))
    } else {
        Box::new(Cursor::new(data))
    }
}

/// [`EncryptTarget`] with any hardware-derived second factor already resolved
/// to bytes, ready to reuse across every file in the batch.
pub(crate) enum ResolvedEncryptTarget {
    PublicKeys(Vec<String>),
    Passphrase {
        passphrase: Zeroizing<String>,
        keyfile: Option<Vec<u8>>,
        fido2_secret: Option<Zeroizing<[u8; 32]>>,
    },
}

/// Resolves an [`EncryptTarget`] into a [`ResolvedEncryptTarget`], deriving
/// the FIDO2 secret (a blocking hardware touch) at most once regardless of
/// how many files the batch contains.
fn resolve_encrypt_target(target: EncryptTarget) -> Result<ResolvedEncryptTarget, String> {
    match target {
        EncryptTarget::PublicKeys(pems) => Ok(ResolvedEncryptTarget::PublicKeys(pems)),
        EncryptTarget::Passphrase {
            passphrase,
            keyfile,
            fido2,
        } => {
            let fido2_secret = match fido2 {
                None => None,
                Some((path, pin)) => Some(derive_fido2_secret(
                    &path,
                    pin.as_deref().map(String::as_str),
                )?),
            };
            Ok(ResolvedEncryptTarget::Passphrase {
                passphrase,
                keyfile,
                fido2_secret,
            })
        }
    }
}

/// Derives a FIDO2 `hmac-secret` output for `enrollment_path`, or fails with a
/// clear message when this build has no FIDO2 backend. `encrypt_second_factor`
/// can only be set to `Fido2` when the UI actually offers that option (native,
/// `fido2` feature), so the `unreachable!` below is provably dead in every
/// other build, but still has to type-check without the dependency present.
pub(crate) fn derive_fido2_secret(
    path: &std::path::Path,
    pin: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>, String> {
    #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
    {
        crate::fido2::derive_secret(path, pin).map_err(|e| e.to_string())
    }
    #[cfg(not(all(not(target_arch = "wasm32"), feature = "fido2")))]
    {
        let _ = (path, pin);
        unreachable!("Fido2 second factor selected without the fido2 feature/target")
    }
}

#[allow(clippy::too_many_arguments)]
fn encrypt_entry(
    target: &ResolvedEncryptTarget,
    data: &[u8],
    original_size: u64,
    out_name: &str,
    out_path: Option<std::path::PathBuf>,
    compress: bool,
    compress_level: i32,
    pad_recipients: bool,
    pad: bool,
    stealth: bool,
    confirm: bool,
    progress: &dyn Fn(u64, u64),
) -> OpStatus {
    let chunk_size = adaptive_chunk_size(original_size);
    let (effective_path, effective_confirm) = (out_path, confirm);

    let pub_pems: &[String] = match target {
        ResolvedEncryptTarget::PublicKeys(pems) => pems.as_slice(),
        ResolvedEncryptTarget::Passphrase {
            passphrase,
            keyfile,
            fido2_secret,
        } => {
            let mut reader = padded_reader(data, original_size, pad);
            let mut out = Vec::new();
            let result = if let Some(kf) = keyfile {
                encrypt::encrypt_stream_passphrase_keyfile(
                    passphrase,
                    kf,
                    original_size,
                    &mut *reader,
                    &mut out,
                )
            } else if let Some(hs) = fido2_secret {
                encrypt::encrypt_stream_passphrase_fido2(
                    passphrase,
                    hs,
                    original_size,
                    &mut *reader,
                    &mut out,
                )
            } else {
                encrypt::encrypt_stream_passphrase(
                    passphrase,
                    original_size,
                    &mut *reader,
                    &mut out,
                )
            };
            return match result {
                Ok(()) => save_result(out_name, &out, effective_path, effective_confirm),
                Err(e) => OpStatus::Err(e.to_string()),
            };
        }
    };

    // Stealth mode is single-recipient only; a stale checkbox left checked after adding a
    // second recipient is silently ignored here rather than erroring, matching how `compress`
    // is already silently ignored for the multi-recipient branch below.
    if stealth && pub_pems.len() == 1 {
        let mut reader = padded_reader(data, original_size, pad);
        let mut out = Vec::new();
        let result =
            encrypt::encrypt_stream_stealth(&pub_pems[0], original_size, &mut *reader, &mut out);
        return match result {
            Ok(()) => save_result(out_name, &out, effective_path, effective_confirm),
            Err(e) => OpStatus::Err(e.to_string()),
        };
    }

    if pub_pems.len() == 1 {
        let mut out = Vec::new();
        let result = if compress {
            let mut reader = Cursor::new(data);
            encrypt::encrypt_stream_compressed(
                &pub_pems[0],
                original_size,
                chunk_size,
                compress_level,
                &mut reader,
                &mut out,
            )
        } else {
            let mut reader = padded_reader(data, original_size, pad);
            encrypt::encrypt_stream_with_progress(
                &pub_pems[0],
                original_size,
                chunk_size,
                &mut *reader,
                &mut out,
                progress,
            )
        };
        match result {
            Ok(()) => save_result(out_name, &out, effective_path, effective_confirm),
            Err(e) => OpStatus::Err(e.to_string()),
        }
    } else {
        let pem_refs: Vec<&str> = pub_pems.iter().map(|s| s.as_str()).collect();
        let mut reader = padded_reader(data, original_size, pad);
        let mut out = Vec::new();
        // v9: pad slot count to next power of two (stronger recipient-count anonymity)
        // v8: variant-blind slots, shuffled order (hides key types only)
        let result = if pad_recipients {
            encrypt::encrypt_stream_multi_anon_padded_with_progress(
                &pem_refs,
                original_size,
                &mut *reader,
                &mut out,
                progress,
            )
        } else {
            encrypt::encrypt_stream_multi_anon_with_progress(
                &pem_refs,
                original_size,
                &mut *reader,
                &mut out,
                progress,
            )
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
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                let badge_color = variant_badge_color(variant_name, dark);
                ui.label(
                    RichText::new(variant_name)
                        .size(11.0)
                        .color(badge_color)
                        .monospace(),
                );
                ui.add_space(6.0);
                ui.add(
                    egui::Label::new(RichText::new(name).size(13.0).color(c_text(dark))).truncate(),
                )
                .on_hover_text(name);
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
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.add(
                    egui::Label::new(RichText::new(name).size(13.0).color(c_text(dark))).truncate(),
                )
                .on_hover_text(name);
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
