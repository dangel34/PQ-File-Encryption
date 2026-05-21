use std::io::Cursor;
#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;
use std::sync::Arc;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::{encrypt, format};
use crate::app::PqfileApp;
use crate::colors::{c_accent, c_card, c_chrome, c_overlay, c_red, c_green, c_subtext, c_surface0, c_surface1, c_text};
use crate::types::OpStatus;
use crate::widgets::{card, pick_file, pick_files, save_result, section_label, show_status, tab_heading};

impl PqfileApp {
    pub(crate) fn handle_encrypt_all(&mut self, ctx: &egui::Context) {
        if self.encrypt_recipients.is_empty() {
            return;
        }
        let pub_pems: Vec<String> = self.encrypt_recipients.iter().map(|r| r.pem.clone()).collect();

        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::sync::Mutex;
            use crate::types::EncryptJob;

            let confirm = self.settings.confirm_overwrite;
            let compress = self.encrypt_compress;
            let compress_level = self.encrypt_compress_level;
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
            self.encrypt_job = Some(Arc::clone(&job));

            let ctx = ctx.clone();
            std::thread::spawn(move || {
                for (i, name, data, path) in files {
                    let out_name = format!("{name}.pqf");
                    let out_path = path.map(|p| {
                        let mut s = p.as_os_str().to_owned();
                        s.push(".pqf");
                        PathBuf::from(s)
                    });
                    let original_size = data.len() as u64;
                    let status = if pub_pems.len() == 1 {
                        let mut reader = Cursor::new(&data);
                        let mut out = Vec::new();
                        let result = if compress {
                            encrypt::encrypt_stream_compressed(
                                &pub_pems[0], original_size, format::CHUNK_SIZE,
                                compress_level, &mut reader, &mut out,
                            )
                        } else {
                            encrypt::encrypt_stream(&pub_pems[0], original_size, format::CHUNK_SIZE, &mut reader, &mut out)
                        };
                        match result {
                            Ok(()) => save_result(&out_name, &out, out_path, confirm),
                            Err(e) => OpStatus::Err(e.to_string()),
                        }
                    } else {
                        let pem_refs: Vec<&str> = pub_pems.iter().map(|s| s.as_str()).collect();
                        let mut reader = Cursor::new(&data);
                        let mut out = Vec::new();
                        match encrypt::encrypt_stream_multi(&pem_refs, original_size, &mut reader, &mut out) {
                            Ok(()) => save_result(&out_name, &out, out_path, confirm),
                            Err(e) => OpStatus::Err(e.to_string()),
                        }
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
            for entry in &mut self.encrypt_files {
                let original_size = entry.data.len() as u64;
                let out_name = format!("{}.pqf", entry.name);
                entry.status = if pub_pems.len() == 1 {
                    let mut reader = Cursor::new(&entry.data);
                    let mut out = Vec::new();
                    match encrypt::encrypt_stream(&pub_pems[0], original_size, format::CHUNK_SIZE, &mut reader, &mut out) {
                        Ok(()) => save_result(&out_name, &out, None, false),
                        Err(e) => OpStatus::Err(e.to_string()),
                    }
                } else {
                    let pem_refs: Vec<&str> = pub_pems.iter().map(|s| s.as_str()).collect();
                    let mut reader = Cursor::new(&entry.data);
                    let mut out = Vec::new();
                    match encrypt::encrypt_stream_multi(&pem_refs, original_size, &mut reader, &mut out) {
                        Ok(()) => save_result(&out_name, &out, None, false),
                        Err(e) => OpStatus::Err(e.to_string()),
                    }
                };
            }
            let all_ok = self.settings.auto_clear
                && self.encrypt_files.iter().all(|e| matches!(e.status, OpStatus::Ok(_)));
            if all_ok {
                self.encrypt_recipients.clear();
                self.encrypt_files.clear();
            }
        }
    }

    pub(crate) fn show_encrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Encrypt File", dark);
        ui.label(
            RichText::new("Encrypt one or more files to one or more recipients.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        #[cfg(not(target_arch = "wasm32"))]
        let job_running = self.encrypt_job.is_some();
        #[cfg(target_arch = "wasm32")]
        let job_running = false;

        // ── Recipients ───────────────────────────────────────────────────────
        section_label(ui, "RECIPIENTS", dark);
        let mut to_remove_recipient: Option<usize> = None;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                let n = self.encrypt_recipients.len();
                if n == 0 {
                    ui.label(
                        RichText::new("No recipients — browse or drag & drop a public key")
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
                                    RichText::new("+ Add Recipient…").size(13.0).color(c_text(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .clicked()
                    {
                        pick_file(Arc::clone(&self.encrypt_pubkey.pending), "PEM", &["pem"]);
                    }
                });
            });

            if !self.encrypt_recipients.is_empty() {
                ui.add_space(6.0);
                for (i, r) in self.encrypt_recipients.iter().enumerate() {
                    let mut remove = false;
                    let w = ui.available_width();
                    ui.allocate_ui(egui::vec2(w, 22.0), |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            // Variant badge
                            let badge_color = variant_badge_color(&r.variant_name, dark);
                            ui.label(
                                RichText::new(&r.variant_name)
                                    .size(11.0)
                                    .color(badge_color)
                                    .monospace(),
                            );
                            ui.add_space(6.0);
                            ui.label(RichText::new(&r.name).size(13.0).color(c_text(dark)));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if !job_running {
                                        remove = ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("✕")
                                                        .size(11.0)
                                                        .color(c_overlay(dark)),
                                                )
                                                .fill(Color32::TRANSPARENT)
                                                .stroke(Stroke::NONE),
                                            )
                                            .clicked();
                                    }
                                },
                            );
                        });
                    });
                    if remove && to_remove_recipient.is_none() {
                        to_remove_recipient = Some(i);
                    }
                }
            }
        });

        if let Some(i) = to_remove_recipient {
            self.encrypt_recipients.remove(i);
        }
        ui.add_space(14.0);

        // ── Files to encrypt ─────────────────────────────────────────────────
        section_label(ui, "FILES TO ENCRYPT", dark);
        let mut to_remove: Option<usize> = None;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            ui.horizontal(|ui| {
                if self.encrypt_files.is_empty() {
                    ui.label(
                        RichText::new("No files added — browse or drag & drop")
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
                });
            });

            if !self.encrypt_files.is_empty() {
                ui.add_space(6.0);
                for (i, entry) in self.encrypt_files.iter().enumerate() {
                    let mut rc = false;
                    let w = ui.available_width();
                    ui.allocate_ui(egui::vec2(w, 22.0), |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.label(RichText::new(&entry.name).size(13.0).color(c_text(dark)));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if !job_running {
                                        rc = ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("✕")
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
                                                RichText::new("✓")
                                                    .size(13.0)
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
                    if rc && to_remove.is_none() {
                        to_remove = Some(i);
                    }
                }
            }
        });

        if let Some(i) = to_remove {
            self.encrypt_files.remove(i);
        }
        ui.add_space(14.0);

        // ── Compress option (native only, single recipient) ──────────────────
        #[cfg(not(target_arch = "wasm32"))]
        {
            let single_recipient = self.encrypt_recipients.len() == 1;
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.horizontal(|ui| {
                    ui.add_enabled(
                        single_recipient,
                        egui::Checkbox::new(&mut self.encrypt_compress, ""),
                    );
                    ui.label(
                        RichText::new("Compress before encrypting (zstd, single recipient only)")
                            .size(13.0)
                            .color(if single_recipient { c_text(dark) } else { c_overlay(dark) }),
                    );
                    if single_recipient && self.encrypt_compress {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.add(
                                egui::Slider::new(&mut self.encrypt_compress_level, 1..=19)
                                    .text(""),
                            )
                            .on_hover_text("Compression level (1=fastest, 19=best)");
                            ui.label(RichText::new("Level:").size(12.0).color(c_subtext(dark)));
                        });
                    }
                });
            });
            ui.add_space(14.0);
        }

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
                    RichText::new(btn_label).size(14.0).color(c_chrome(dark)).strong(),
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

        // Progress bar while a job is running.
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

        let first_err = self.encrypt_files.iter().find_map(|e| {
            if let OpStatus::Err(m) = &e.status { Some(m.as_str()) } else { None }
        });
        if let Some(msg) = first_err {
            show_status(ui, &OpStatus::Err(msg.to_owned()), dark);
        }
    }
}

fn variant_badge_color(variant_name: &str, dark: bool) -> eframe::egui::Color32 {
    use crate::colors::c_accent;
    if variant_name.starts_with("Hybrid") {
        if dark { eframe::egui::Color32::from_rgb(180, 120, 220) } else { eframe::egui::Color32::from_rgb(100, 40, 160) }
    } else if variant_name.contains("1024") {
        if dark { eframe::egui::Color32::from_rgb(100, 200, 240) } else { eframe::egui::Color32::from_rgb(0, 100, 160) }
    } else {
        c_accent(dark)
    }
}
