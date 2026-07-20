//! Optional, opt-in update check against the GitHub Releases API (native
//! only, `update-check` feature - see `Cargo.toml`).
//!
//! Never runs unless the user clicks "Check for Updates" in Settings or has
//! turned on automatic checks there (off by default). Never downloads or
//! installs anything - it only compares version strings and reports the
//! result. Runs on a background thread so the UI never blocks on the
//! network request, mirroring the FIDO2 enrollment job in
//! `tabs/fido2_ui.rs`.
//!
//! The GitHub API fetch and version-compare logic live in `update_check_common`,
//! physically reused here via `#[path]` rather than a hand-copied twin - see
//! `fido2.rs`'s header comment for why this convention is safe for pqfile-gui
//! (unpublished) to use against pqfile-cli's source tree (published).

#[path = "../../pqfile-cli/src/update_check_common.rs"]
mod update_check_common;

use crate::app::PqfileApp;
use crate::colors::{c_accent, c_green, c_red, c_surface0, c_text, c_yellow};
use eframe::egui::{self, RichText};
use std::sync::{Arc, Mutex};
use update_check_common::{fetch_latest_tag, is_newer};

#[derive(Clone)]
pub(crate) struct UpdateInfo {
    pub(crate) current: String,
    pub(crate) latest: String,
    pub(crate) available: bool,
}

pub(crate) type UpdateCheckPending = Arc<Mutex<Option<Result<UpdateInfo, String>>>>;

impl PqfileApp {
    /// Polled once per frame from the main update loop: drains the check
    /// job's result (if any) into `update_check_status`.
    pub(crate) fn poll_update_check(&mut self) {
        if let Some(pending) = &self.update_check_pending {
            let taken = pending.lock().unwrap().take();
            if let Some(result) = taken {
                self.update_check_status = Some(result);
                self.update_check_pending = None;
            }
        }
    }

    /// Spawns the background check if one isn't already running. Safe to
    /// call repeatedly (e.g. from a disabled-while-running button).
    pub(crate) fn start_update_check(&mut self, ctx: &egui::Context) {
        if self.update_check_pending.is_some() {
            return;
        }
        let pending: UpdateCheckPending = Arc::new(Mutex::new(None));
        self.update_check_pending = Some(Arc::clone(&pending));
        let ctx = ctx.clone();
        let current = crate::APP_VERSION.to_owned();
        std::thread::spawn(move || {
            let result = fetch_latest_tag("pqfile-gui-update-check").map(|tag| {
                let latest = tag.trim_start_matches('v').to_owned();
                let available = is_newer(&latest, &current);
                UpdateInfo {
                    current,
                    latest,
                    available,
                }
            });
            *pending.lock().unwrap() = Some(result);
            ctx.request_repaint();
        });
    }

    /// "Check for Updates" button and result row, shown in Settings right
    /// below the "Check for updates on startup" toggle.
    pub(crate) fn show_update_check_row(&mut self, ui: &mut egui::Ui, dark: bool) {
        let checking = self.update_check_pending.is_some();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !checking,
                    egui::Button::new(
                        RichText::new("Check for Updates now")
                            .size(12.5)
                            .color(c_text(dark)),
                    )
                    .fill(c_surface0(dark)),
                )
                .clicked()
            {
                self.start_update_check(ui.ctx());
            }
            if checking {
                ui.add(egui::Spinner::new().size(12.0));
            }
        });
        match &self.update_check_status {
            Some(Ok(info)) if info.available => {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("A newer version is available: v{}", info.latest))
                        .size(12.0)
                        .color(c_yellow(dark)),
                );
                ui.hyperlink_to(
                    RichText::new("View release")
                        .size(12.0)
                        .color(c_accent(dark)),
                    format!(
                        "https://github.com/dangel34/PQ-File-Encryption/releases/tag/v{}",
                        info.latest
                    ),
                );
            }
            Some(Ok(info)) => {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("pqfile v{} is up to date.", info.current))
                        .size(12.0)
                        .color(c_green(dark)),
                );
            }
            Some(Err(e)) => {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!("Update check failed: {e}"))
                        .size(11.5)
                        .color(c_red(dark)),
                );
            }
            None => {}
        }
    }
}
