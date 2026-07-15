//! WebAuthn PRF UI glue shared by the Encrypt and Decrypt tabs (wasm32 only).
//!
//! The browser-native equivalent of `tabs::fido2_ui` - the actual
//! `navigator.credentials` calls live in `crate::webauthn`; this module only
//! draws widgets and manages the pending state for the two actions that need
//! an async browser round trip: registering a new passkey here (secret
//! *derivation* for an encrypt/decrypt batch happens in each tab's own
//! `poll_encrypt_webauthn`/`poll_decrypt_webauthn`, once per batch).

use crate::app::PqfileApp;
use crate::colors::{c_subtext, c_text};
use crate::types::{OpStatus, WebAuthnPending};
use eframe::egui::{self, RichText};

impl PqfileApp {
    /// Polled once per frame from the main update loop: drains the
    /// registration job's result (if any) into `webauthn_enroll_status`,
    /// saving the resulting enrollment file (a browser download - there is no
    /// filesystem path to write to on wasm) on success.
    pub(crate) fn poll_webauthn_enroll_job(&mut self) {
        let Some(pending) = &self.webauthn_enroll_pending else {
            return;
        };
        let Some(result) = pending.lock().unwrap().take() else {
            return;
        };
        self.webauthn_enroll_pending = None;
        self.webauthn_enroll_status = match result {
            Ok(enrollment) => {
                let bytes = enrollment.serialize().into_bytes();
                match crate::widgets::save_result("webauthn-enrollment.txt", &bytes, None, false) {
                    OpStatus::Ok(_) => OpStatus::Ok(
                        "Passkey registered. Enrollment file downloaded - keep it, you'll load \
                         it back in whenever you encrypt or decrypt with this passkey."
                            .to_owned(),
                    ),
                    other => other,
                }
            }
            Err(e) => OpStatus::Err(e),
        };
    }

    /// "Register Passkey…" button and status line, shared by both tabs. Only
    /// touches the global `webauthn_enroll_*` fields, not either tab's own
    /// enrollment-file field, so it's safe to call from either tab's method
    /// without a borrow conflict.
    fn show_webauthn_enroll_widget(&mut self, ui: &mut egui::Ui, dark: bool) {
        let running = self.webauthn_enroll_pending.is_some();
        if ui
            .add_enabled(
                !running,
                egui::Button::new(
                    RichText::new("🔑  Register Passkey…")
                        .size(13.0)
                        .color(c_text(dark)),
                ),
            )
            .on_hover_text(
                "Creates a new passkey (Windows Hello, iCloud Keychain, or a security key) \
                 requesting the WebAuthn PRF extension, and downloads an enrollment file.",
            )
            .clicked()
        {
            self.start_webauthn_enroll(ui.ctx());
        }
        if running {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(14.0));
                ui.label(
                    RichText::new("Waiting for passkey…")
                        .size(12.0)
                        .color(c_subtext(dark)),
                );
            });
        }
        crate::widgets::show_status(ui, &self.webauthn_enroll_status, dark);
    }

    fn start_webauthn_enroll(&mut self, ctx: &egui::Context) {
        let pending: WebAuthnPending<crate::webauthn::Enrollment> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        self.webauthn_enroll_pending = Some(std::sync::Arc::clone(&pending));
        self.webauthn_enroll_status = OpStatus::None;
        let ctx = ctx.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let result = crate::webauthn::register().await;
            *pending.lock().unwrap() = Some(result);
            ctx.request_repaint();
        });
    }

    pub(crate) fn show_encrypt_webauthn_second_factor(&mut self, ui: &mut egui::Ui, dark: bool) {
        crate::widgets::file_row(
            ui,
            "Enrollment file",
            &mut self.encrypt_webauthn_enrollment,
            "Enrollment",
            &[],
            dark,
        );
        ui.add_space(6.0);
        self.show_webauthn_enroll_widget(ui, dark);
        ui.label(
            RichText::new(
                "Decryption will require presenting this same passkey in addition to the \
                 passphrase.",
            )
            .size(11.5)
            .color(c_subtext(dark)),
        );
    }

    pub(crate) fn show_decrypt_webauthn_second_factor(&mut self, ui: &mut egui::Ui, dark: bool) {
        crate::widgets::file_row(
            ui,
            "Enrollment file",
            &mut self.decrypt_webauthn_enrollment,
            "Enrollment",
            &[],
            dark,
        );
        ui.add_space(6.0);
        self.show_webauthn_enroll_widget(ui, dark);
    }
}
