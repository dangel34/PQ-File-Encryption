use crate::app::PqfileApp;
use crate::colors::{
    c_accent, c_card, c_chrome, c_overlay, c_red, c_subtext, c_surface0, c_surface1, c_text,
};
use crate::types::ShamirSubTab;
use crate::types::{OpStatus, Tab};
use crate::widgets::{
    card, file_row, passphrase_row, pick_files, save_result, scrollable_list, section_label,
    seg_tabs, show_status, tab_heading_help,
};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::shamir;

impl PqfileApp {
    pub(crate) fn show_shamir(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Shamir Key Splitting  (M-of-N)", dark) {
            self.help_modal_open = Some(Tab::Shamir);
        }
        ui.label(
            RichText::new(
                "Split a private key into N shares requiring M to reconstruct. \
                 Fewer than M shares reveal nothing about the original key.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(10.0);

        seg_tabs(
            ui,
            &mut self.shamir_sub_tab,
            &[
                ("Split Key", ShamirSubTab::Split),
                ("Reconstruct Key", ShamirSubTab::Reconstruct),
            ],
            dark,
        );

        match self.shamir_sub_tab {
            ShamirSubTab::Split => self.show_shamir_split_section(ui, dark),
            ShamirSubTab::Reconstruct => self.show_shamir_reconstruct_section(ui, dark),
        }
    }

    // ── Split ──────────────────────────────────────────────────────────────

    fn show_shamir_split_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "SPLIT KEY", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Private key to split",
                &mut self.shamir_split_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            passphrase_row(
                ui,
                "Key passphrase:",
                &mut self.shamir_split_passphrase,
                &mut self.shamir_split_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Threshold (M):")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                let mut t = self.shamir_split_threshold as i32;
                ui.add(
                    egui::DragValue::new(&mut t)
                        .range(2..=self.shamir_split_shares as i32)
                        .speed(1.0),
                );
                self.shamir_split_threshold = t.max(2) as u8;

                ui.add_space(16.0);

                ui.label(
                    RichText::new("Total shares (N):")
                        .size(13.0)
                        .color(c_subtext(dark)),
                );
                let mut n = self.shamir_split_shares as i32;
                ui.add(
                    egui::DragValue::new(&mut n)
                        .range(self.shamir_split_threshold as i32..=255)
                        .speed(1.0),
                );
                self.shamir_split_shares = n.max(self.shamir_split_threshold as i32) as u8;
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!(
                    "Any {} of {} shares can reconstruct the key.",
                    self.shamir_split_threshold, self.shamir_split_shares
                ))
                .size(12.0)
                .color(c_subtext(dark)),
            );
        });
        ui.add_space(8.0);

        let ready = self.shamir_split_privkey.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔀  Split Key")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(160.0, 32.0)),
            )
            .clicked()
        {
            self.do_shamir_split();
        }

        show_status(ui, &self.shamir_split_status, dark);

        // "Show QR" buttons for each saved share (native only).
        #[cfg(not(target_arch = "wasm32"))]
        if matches!(&self.shamir_split_status, crate::types::OpStatus::Ok(_)) {
            let out_dir = if self.settings.output_dir.is_empty() {
                self.shamir_split_privkey
                    .path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_owned())
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
            } else {
                std::path::PathBuf::from(&self.settings.output_dir)
            };
            let n = self.shamir_split_shares;
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                for i in 1..=n {
                    let share_path = out_dir.join(format!("share_{i}.pem"));
                    if share_path.exists()
                        && ui
                            .add(
                                egui::Button::new(
                                    RichText::new(format!("📷 QR share {i}"))
                                        .size(12.0)
                                        .color(c_subtext(dark)),
                                )
                                .fill(c_surface0(dark)),
                            )
                            .on_hover_text(format!("Show share {i} as QR code"))
                            .clicked()
                    {
                        if let Ok(pem_str) = std::fs::read_to_string(&share_path) {
                            let title = format!("Shamir Share {i} QR Code");
                            self.open_qr(ui.ctx(), title, &pem_str);
                        }
                    }
                }
            });
        }
    }

    fn do_shamir_split(&mut self) {
        let priv_pem = match self.shamir_split_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.shamir_split_status = OpStatus::Err("Load a private key first.".to_owned());
                return;
            }
        };
        let passphrase = if self.shamir_split_passphrase.is_empty() {
            None
        } else {
            Some((*self.shamir_split_passphrase).clone())
        };

        match shamir::split_key(
            &priv_pem,
            self.shamir_split_threshold,
            self.shamir_split_shares,
            passphrase.as_deref(),
        ) {
            Ok(result) => {
                let mut saved = 0usize;
                let mut errors: Vec<String> = Vec::new();
                for (i, pem_str) in result.share_pems.iter().enumerate() {
                    let filename = format!("share_{}.pem", i + 1);
                    #[cfg(not(target_arch = "wasm32"))]
                    let native_path = {
                        use std::path::PathBuf;
                        let base = self
                            .shamir_split_privkey
                            .path
                            .as_ref()
                            .and_then(|p| p.parent())
                            .map(|d| d.join(&filename))
                            .unwrap_or_else(|| PathBuf::from(&filename));
                        let path = if self.settings.output_dir.is_empty() {
                            base
                        } else {
                            PathBuf::from(&self.settings.output_dir).join(&filename)
                        };
                        Some(path)
                    };
                    #[cfg(target_arch = "wasm32")]
                    let native_path: Option<std::path::PathBuf> = None;
                    match save_result(
                        &filename,
                        pem_str.as_bytes(),
                        native_path,
                        self.settings.confirm_overwrite,
                    ) {
                        OpStatus::Ok(_) => saved += 1,
                        OpStatus::Err(e) => errors.push(e),
                        OpStatus::None => {}
                    }
                }
                if errors.is_empty() {
                    self.shamir_split_status = OpStatus::Ok(format!(
                        "Saved {saved} share(s). Public key fingerprint: {}",
                        result.pubkey_fingerprint
                    ));
                } else {
                    self.shamir_split_status = OpStatus::Err(errors.join("; "));
                }
            }
            Err(e) => {
                self.shamir_split_status = OpStatus::Err(e.to_string());
            }
        }
    }

    // ── Reconstruct ────────────────────────────────────────────────────────

    fn show_shamir_reconstruct_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        section_label(ui, "RECONSTRUCT KEY", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            if self.shamir_shares.is_empty() {
                ui.label(
                    RichText::new(
                        "No share files loaded. Use Add Shares or drag .pem share files here.",
                    )
                    .size(13.0)
                    .color(c_overlay(dark)),
                );
            } else {
                let mut remove_idx: Option<usize> = None;
                scrollable_list(ui, 154.0, c_card(dark), |ui| {
                    for (i, entry) in self.shamir_shares.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(&entry.name).size(12.5).color(c_text(dark)));
                            if let OpStatus::Err(ref e) = entry.status {
                                ui.label(RichText::new(e).size(11.5).color(c_red(dark)));
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("✕")
                                                    .size(11.0)
                                                    .color(c_subtext(dark)),
                                            )
                                            .fill(Color32::TRANSPARENT)
                                            .stroke(Stroke::NONE),
                                        )
                                        .clicked()
                                    {
                                        remove_idx = Some(i);
                                    }
                                },
                            );
                        });
                    }
                });
                if let Some(i) = remove_idx {
                    self.shamir_shares.remove(i);
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("+ Add Shares").size(13.0).color(c_text(dark)),
                        )
                        .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    pick_files(std::sync::Arc::clone(&self.shamir_shares_pending));
                }
                if !self.shamir_shares.is_empty()
                    && ui
                        .add(
                            egui::Button::new(
                                RichText::new("Clear all").size(12.0).color(c_subtext(dark)),
                            )
                            .fill(Color32::TRANSPARENT),
                        )
                        .clicked()
                {
                    self.shamir_shares.clear();
                }
            });
        });
        ui.add_space(8.0);

        let ready = self.shamir_shares.len() >= 2;
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔑  Reconstruct Key")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(180.0, 32.0)),
            )
            .clicked()
        {
            self.do_shamir_reconstruct();
        }

        show_status(ui, &self.shamir_reconstruct_status, dark);
    }

    fn do_shamir_reconstruct(&mut self) {
        if self.shamir_shares.is_empty() {
            self.shamir_reconstruct_status =
                OpStatus::Err("Add at least 2 share files.".to_owned());
            return;
        }

        let pem_strings: Vec<String> = self
            .shamir_shares
            .iter()
            .filter_map(|e| std::str::from_utf8(&e.data).ok().map(str::to_owned))
            .collect();

        let pem_refs: Vec<&str> = pem_strings.iter().map(|s| s.as_str()).collect();

        match shamir::reconstruct_key(&pem_refs) {
            Ok((pub_pem, priv_pem)) => {
                let pub_name = "pubkey.pem".to_owned();
                let priv_name = "privkey.pem".to_owned();
                #[cfg(not(target_arch = "wasm32"))]
                let (pub_path, priv_path) = {
                    use std::path::PathBuf;
                    let dir = if self.settings.output_dir.is_empty() {
                        PathBuf::from(".")
                    } else {
                        PathBuf::from(&self.settings.output_dir)
                    };
                    (Some(dir.join(&pub_name)), Some(dir.join(&priv_name)))
                };
                #[cfg(target_arch = "wasm32")]
                let (pub_path, priv_path): (
                    Option<std::path::PathBuf>,
                    Option<std::path::PathBuf>,
                ) = (None, None);

                let pub_status = save_result(
                    &pub_name,
                    pub_pem.as_bytes(),
                    pub_path,
                    self.settings.confirm_overwrite,
                );
                let priv_status = save_result(
                    &priv_name,
                    priv_pem.as_bytes(),
                    priv_path,
                    self.settings.confirm_overwrite,
                );

                match (pub_status, priv_status) {
                    (OpStatus::Ok(_), OpStatus::Ok(msg)) => {
                        self.shamir_reconstruct_status = OpStatus::Ok(msg);
                    }
                    (OpStatus::Err(e), _) | (_, OpStatus::Err(e)) => {
                        self.shamir_reconstruct_status = OpStatus::Err(e);
                    }
                    _ => {}
                }
            }
            Err(e) => {
                self.shamir_reconstruct_status = OpStatus::Err(e.to_string());
            }
        }
    }
}
