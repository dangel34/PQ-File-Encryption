//! FIDO2 UI glue shared by the Encrypt and Decrypt tabs (native, `fido2` feature only).
//!
//! CTAP2 device I/O itself lives in `crate::fido2`; this module only draws
//! widgets and manages the background job for the one action that touches
//! hardware directly here (enrollment - secret *derivation* happens inside
//! each tab's own encrypt/decrypt worker thread, once per batch).

use crate::app::PqfileApp;
use crate::colors::{c_card, c_red, c_subtext, c_surface1, c_text};
use crate::types::{Fido2Pending, FileInput, OpStatus};
use crate::widgets::card;
use eframe::egui::{self, RichText};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

impl PqfileApp {
    /// Polled once per frame from the main update loop: drains the enroll
    /// job's result (if any) into `fido2_enroll_status`.
    pub(crate) fn poll_fido2_jobs(&mut self) {
        if let Some(pending) = &self.fido2_enroll_pending {
            let taken = pending.lock().unwrap().take();
            if let Some(result) = taken {
                self.fido2_enroll_status = match result {
                    Ok(()) => OpStatus::Ok(
                        "Enrollment created. Touch the token again whenever you use it.".to_owned(),
                    ),
                    Err(e) => OpStatus::Err(e),
                };
                self.fido2_enroll_pending = None;
            }
        }
    }

    /// "Enroll New Token…" button and status line, shared by both tabs. Only
    /// touches the global `fido2_enroll_*` fields, not either tab's own
    /// enrollment-file/PIN fields, so it's safe to call from either tab's
    /// method without a borrow conflict.
    fn show_fido2_enroll_widget(&mut self, ui: &mut egui::Ui, dark: bool) {
        let running = self.fido2_enroll_pending.is_some();
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.fido2_enroll_use_pin, "Token requires a PIN");
            if self.fido2_enroll_use_pin {
                ui.add(
                    egui::TextEdit::singleline(&mut *self.fido2_enroll_pin)
                        .password(true)
                        .hint_text("PIN")
                        .desired_width(100.0),
                );
            }
        });
        ui.add_space(4.0);
        if ui
            .add_enabled(
                !running,
                egui::Button::new(
                    RichText::new("🔑  Enroll New Token…")
                        .size(13.0)
                        .color(c_text(dark)),
                ),
            )
            .on_hover_text(
                "Creates a new CTAP2 credential on the attached security key and saves an \
                 enrollment file. Touch the token when it lights up.",
            )
            .clicked()
        {
            self.start_fido2_enroll(ui.ctx());
        }
        if running {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(14.0));
                ui.label(
                    RichText::new("Waiting for touch…")
                        .size(12.0)
                        .color(c_subtext(dark)),
                );
            });
        }
        crate::widgets::show_status(ui, &self.fido2_enroll_status, dark);
    }

    fn start_fido2_enroll(&mut self, ctx: &egui::Context) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save FIDO2 enrollment file")
            .set_file_name("fido2-enrollment.txt")
            .save_file()
        else {
            return;
        };
        let pin = if self.fido2_enroll_use_pin && !self.fido2_enroll_pin.is_empty() {
            Some((*self.fido2_enroll_pin).clone())
        } else {
            None
        };
        let pending: Fido2Pending<()> = Arc::new(Mutex::new(None));
        self.fido2_enroll_pending = Some(Arc::clone(&pending));
        self.fido2_enroll_status = OpStatus::None;
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = crate::fido2::enroll(&path, pin.as_deref()).map_err(|e| e.to_string());
            *pending.lock().unwrap() = Some(result);
            ctx.request_repaint();
        });
    }

    pub(crate) fn show_encrypt_fido2_second_factor(&mut self, ui: &mut egui::Ui, dark: bool) {
        crate::widgets::file_row(
            ui,
            "Enrollment file",
            &mut self.encrypt_fido2_enrollment,
            "Enrollment",
            &[],
            dark,
        );
        show_pin_field_if_needed(
            ui,
            dark,
            &self.encrypt_fido2_enrollment,
            &mut self.encrypt_fido2_pin,
        );
        ui.add_space(6.0);
        self.show_fido2_enroll_widget(ui, dark);
        ui.label(
            RichText::new(
                "Decryption will require touching this same physical token in addition to \
                 the passphrase.",
            )
            .size(11.5)
            .color(c_subtext(dark)),
        );
    }

    pub(crate) fn show_decrypt_fido2_second_factor(&mut self, ui: &mut egui::Ui, dark: bool) {
        crate::widgets::file_row(
            ui,
            "Enrollment file",
            &mut self.decrypt_fido2_enrollment,
            "Enrollment",
            &[],
            dark,
        );
        show_pin_field_if_needed(
            ui,
            dark,
            &self.decrypt_fido2_enrollment,
            &mut self.decrypt_fido2_pin,
        );
        ui.add_space(6.0);
        self.show_fido2_enroll_widget(ui, dark);
    }
}

/// Peeks the loaded enrollment file's `pin_required` flag (no hardware touch)
/// and shows a PIN entry field only when it's set.
fn show_pin_field_if_needed(
    ui: &mut egui::Ui,
    dark: bool,
    enrollment: &FileInput,
    pin: &mut Zeroizing<String>,
) {
    let Some(path) = enrollment.path.as_deref() else {
        return;
    };
    match crate::fido2::enrollment_requires_pin(path) {
        Some(true) => {
            ui.add_space(4.0);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("PIN:").size(13.0).color(c_subtext(dark)));
                    ui.add(
                        egui::TextEdit::singleline(&mut **pin)
                            .password(true)
                            .hint_text("Enter FIDO2 PIN…")
                            .desired_width(ui.available_width()),
                    );
                });
            });
        }
        Some(false) => {}
        None => {
            ui.add_space(4.0);
            ui.label(
                RichText::new("Could not read this enrollment file.")
                    .size(11.5)
                    .color(c_red(dark)),
            );
        }
    }
}
