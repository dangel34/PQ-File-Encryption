use std::path::PathBuf;
use std::sync::Arc;
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::encrypt;
use crate::app::PqfileApp;
use crate::colors::*;
use crate::types::OpStatus;
use crate::widgets::{card, file_row, pick_files, save_result, section_label, show_status, tab_heading};

impl PqfileApp {
    pub(crate) fn handle_encrypt_all(&mut self) {
        let Some(pub_pem) = self.encrypt_pubkey.as_str().map(str::to_owned) else {
            return;
        };
        #[cfg(not(target_arch = "wasm32"))]
        let confirm = self.settings.confirm_overwrite;
        #[cfg(target_arch = "wasm32")]
        let confirm = false;

        for entry in &mut self.encrypt_files {
            let out_name = format!("{}.pqf", entry.name);
            let out_path = entry.path.as_ref().map(|p| {
                let mut s = p.as_os_str().to_owned();
                s.push(".pqf");
                PathBuf::from(s)
            });
            entry.status = match encrypt::encrypt_bytes(&pub_pem, &entry.data) {
                Ok(pqf) => save_result(&out_name, &pqf, out_path, confirm),
                Err(e)  => OpStatus::Err(e.to_string()),
            };
        }

        let all_ok = self.settings.auto_clear
            && self.encrypt_files.iter().all(|e| matches!(e.status, OpStatus::Ok(_)));
        if all_ok {
            self.encrypt_pubkey.clear();
            self.encrypt_files.clear();
        }
    }

    pub(crate) fn show_encrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        tab_heading(ui, "Encrypt File", dark);
        ui.label(
            RichText::new("Encrypt one or more files using a recipient's public key.")
                .size(13.0)
                .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        section_label(ui, "INPUTS", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(ui, "Public key (.pem)", &mut self.encrypt_pubkey, "PEM", &["pem"], dark);
        });
        ui.add_space(14.0);

        section_label(ui, "FILES TO ENCRYPT", dark);
        let mut to_remove: Option<usize> = None;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            // Header row: file count + Add Files button
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
                    if ui
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

            // Per-file rows
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

        let n = self.encrypt_files.len();
        let ready = self.encrypt_pubkey.loaded() && n > 0;
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
            self.handle_encrypt_all();
        }

        if !ready {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Load a public key and add files to continue.")
                    .size(12.0)
                    .color(c_overlay(dark)),
            );
        }

        // Show any per-file errors in aggregate via show_status for the overall run
        let first_err = self.encrypt_files.iter().find_map(|e| {
            if let OpStatus::Err(m) = &e.status { Some(m.as_str()) } else { None }
        });
        if let Some(msg) = first_err {
            show_status(ui, &OpStatus::Err(msg.to_owned()), dark);
        }
    }
}
