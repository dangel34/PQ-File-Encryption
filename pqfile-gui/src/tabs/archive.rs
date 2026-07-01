use crate::app::PqfileApp;
use crate::colors::{
    c_accent, c_card, c_chrome, c_overlay, c_red, c_subtext, c_surface0, c_surface1, c_text,
};
use crate::types::ArchiveSubTab;
use crate::types::{OpStatus, Tab};
use crate::widgets::{
    card, file_row, passphrase_row, pick_files, save_result, section_label, seg_tabs, show_status,
    tab_heading_help,
};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::archive;

impl PqfileApp {
    pub(crate) fn show_archive(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Encrypted Archive  (PQFA)", dark) {
            self.help_modal_open = Some(Tab::Archive);
        }
        ui.label(
            RichText::new(
                "Pack multiple files into a single authenticated .pqf archive, \
                 or extract / list files from an existing archive.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(10.0);

        seg_tabs(
            ui,
            &mut self.archive_sub_tab,
            &[
                ("Create", ArchiveSubTab::Create),
                ("Extract", ArchiveSubTab::Extract),
            ],
            dark,
        );

        match self.archive_sub_tab {
            ArchiveSubTab::Create => self.show_archive_create_section(ui, dark),
            ArchiveSubTab::Extract => self.show_archive_extract_section(ui, dark),
        }
    }

    // ── Create archive ────────────────────────────────────────────────────

    fn show_archive_create_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "CREATE ARCHIVE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Recipient public key",
                &mut self.archive_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
        });
        ui.add_space(6.0);

        section_label(ui, "FILES TO ARCHIVE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            if self.archive_files.is_empty() {
                ui.label(
                    RichText::new("No files added. Use Add Files or drag and drop.")
                        .size(13.0)
                        .color(c_overlay(dark)),
                );
            } else {
                let mut remove_idx: Option<usize> = None;
                for (i, entry) in self.archive_files.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&entry.name).size(12.5).color(c_text(dark)));
                        ui.label(
                            RichText::new(format!("({} bytes)", entry.data.len()))
                                .size(11.5)
                                .color(c_subtext(dark)),
                        );
                        if let OpStatus::Err(ref e) = entry.status {
                            ui.label(RichText::new(e).size(11.5).color(c_red(dark)));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new("✕").size(11.0).color(c_subtext(dark)),
                                    )
                                    .fill(Color32::TRANSPARENT)
                                    .stroke(Stroke::NONE),
                                )
                                .clicked()
                            {
                                remove_idx = Some(i);
                            }
                        });
                    });
                }
                if let Some(i) = remove_idx {
                    self.archive_files.remove(i);
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("+ Add Files").size(13.0).color(c_text(dark)),
                        )
                        .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    pick_files(std::sync::Arc::clone(&self.archive_batch_pending));
                }
                if !self.archive_files.is_empty()
                    && ui
                        .add(
                            egui::Button::new(
                                RichText::new("Clear all").size(12.0).color(c_subtext(dark)),
                            )
                            .fill(Color32::TRANSPARENT),
                        )
                        .clicked()
                {
                    self.archive_files.clear();
                }
            });
        });
        ui.add_space(8.0);

        let ready = self.archive_pubkey.loaded() && !self.archive_files.is_empty();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("📦  Create Archive")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
        {
            self.do_archive_create();
        }

        show_status(ui, &self.archive_status, dark);
    }

    fn do_archive_create(&mut self) {
        let pub_pem = match self.archive_pubkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.archive_status =
                    OpStatus::Err("Load a recipient public key first.".to_owned());
                return;
            }
        };
        if self.archive_files.is_empty() {
            self.archive_status = OpStatus::Err("Add at least one file to archive.".to_owned());
            return;
        }

        let entries: Vec<(String, Vec<u8>)> = self
            .archive_files
            .iter()
            .map(|e| (e.name.clone(), e.data.clone()))
            .collect();

        let mut output = Vec::new();
        match archive::create_from_memory(&pub_pem, &entries, &mut output) {
            Ok(()) => {
                let out_name = "archive.pqf".to_owned();
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = {
                    use std::path::PathBuf;
                    let path = if self.settings.output_dir.is_empty() {
                        PathBuf::from(&out_name)
                    } else {
                        PathBuf::from(&self.settings.output_dir).join(&out_name)
                    };
                    Some(path)
                };
                #[cfg(target_arch = "wasm32")]
                let native_path: Option<std::path::PathBuf> = None;
                self.archive_status = save_result(
                    &out_name,
                    &output,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.archive_status = OpStatus::Err(e.to_string());
            }
        }
    }

    // ── Extract archive ───────────────────────────────────────────────────

    fn show_archive_extract_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "EXTRACT / LIST ARCHIVE", dark);
        let mut pp_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Decryption private key",
                &mut self.extract_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            pp_submitted = passphrase_row(
                ui,
                "Key passphrase:",
                &mut self.extract_privkey_passphrase,
                &mut self.extract_privkey_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Encrypted archive (.pqf)",
                &mut self.extract_input,
                "PQF",
                &["pqf"],
                dark,
            );
            ui.add_space(4.0);
            ui.checkbox(
                &mut self.extract_list_only,
                RichText::new("List contents only (do not extract)")
                    .size(13.0)
                    .color(c_subtext(dark)),
            );
        });
        ui.add_space(8.0);

        let ready = self.extract_privkey.loaded() && self.extract_input.loaded();
        let btn_label = if self.extract_list_only {
            "🔍  List Contents"
        } else {
            "📂  Extract Files"
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
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
            || (ready
                && (pp_submitted
                    || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
        {
            self.do_archive_extract();
        }

        if !self.extract_result.is_empty() {
            ui.add_space(8.0);
            section_label(ui, "CONTENTS", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                egui::ScrollArea::vertical()
                    .max_height(200.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(&self.extract_result)
                                .size(12.0)
                                .color(c_text(dark))
                                .monospace(),
                        );
                    });
            });
        }

        show_status(ui, &self.extract_status, dark);
    }

    fn do_archive_extract(&mut self) {
        let priv_pem = match self.extract_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.extract_status = OpStatus::Err("Load a private key first.".to_owned());
                return;
            }
        };
        let data = match self.extract_input.data.clone() {
            Some(d) => d,
            None => {
                self.extract_status =
                    OpStatus::Err("Choose an archive .pqf file first.".to_owned());
                return;
            }
        };
        let passphrase = if self.extract_privkey_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.extract_privkey_passphrase).clone(),
            ))
        };

        use std::io::Cursor;

        if self.extract_list_only {
            match archive::list(
                &priv_pem,
                Cursor::new(&data),
                passphrase.as_deref().map(String::as_str),
            ) {
                Ok(entries) => {
                    let mut listing = String::new();
                    for e in &entries {
                        listing.push_str(&format!("{:<50}  {} bytes\n", e.path, e.file_size));
                    }
                    self.extract_result = listing;
                    self.extract_status =
                        OpStatus::Ok(format!("Archive contains {} file(s).", entries.len()));
                }
                Err(e) => {
                    self.extract_result.clear();
                    self.extract_status = OpStatus::Err(e.to_string());
                }
            }
            return;
        }

        // Full extraction
        self.extract_result.clear();

        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::path::PathBuf;
            let out_dir = if self.settings.output_dir.is_empty() {
                self.extract_input
                    .path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_owned())
                    .unwrap_or_else(|| PathBuf::from("."))
            } else {
                PathBuf::from(&self.settings.output_dir)
            };
            match archive::extract(
                &priv_pem,
                Cursor::new(&data),
                &out_dir,
                passphrase.as_deref().map(String::as_str),
            ) {
                Ok(paths) => {
                    self.extract_status = OpStatus::Ok(format!(
                        "Extracted {} file(s) to {}",
                        paths.len(),
                        out_dir.display()
                    ));
                }
                Err(e) => {
                    self.extract_status = OpStatus::Err(e.to_string());
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        {
            use crate::widgets::download_bytes;
            match archive::extract_to_memory(
                &priv_pem,
                Cursor::new(&data),
                passphrase.as_deref().map(String::as_str),
            ) {
                Ok(files) => {
                    for (path, bytes) in &files {
                        let filename = std::path::Path::new(path)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| path.clone());
                        download_bytes(&filename, bytes);
                    }
                    self.extract_status =
                        OpStatus::Ok(format!("Downloaded {} file(s).", files.len()));
                }
                Err(e) => {
                    self.extract_status = OpStatus::Err(e.to_string());
                }
            }
        }
    }
}
