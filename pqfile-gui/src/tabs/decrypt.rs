use crate::app::PqfileApp;
use crate::colors::{
    c_accent, c_card, c_chrome, c_green, c_overlay, c_red, c_subtext, c_surface0, c_surface1,
    c_text,
};
use crate::types::{DecryptMode, DecryptSubTab, OpStatus, SecondFactorMode, Tab};
#[cfg(not(target_arch = "wasm32"))]
use crate::widgets::pick_folder_pqf;
use crate::widgets::{
    card, file_row, passphrase_row, pick_pqf_files, save_result, scrollable_list, section_label,
    seg_tabs, show_status, tab_heading_help,
};
use eframe::egui::{self, Color32, RichText, Stroke, Vec2};
use pqfile::{add_recipient, decrypt, keygen, rekey};
use std::io::Cursor;
use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// What to decrypt each file with, resolved once per batch: either a private
/// key, or a v10 passphrase with an optional second factor. Mirrors
/// `tabs::encrypt::EncryptTarget` - see its docs for why FIDO2 carries a path
/// and PIN rather than an already-derived secret.
enum DecryptTarget {
    PrivateKey {
        priv_pem: String,
        unlock_passphrase: Option<Zeroizing<String>>,
    },
    Passphrase {
        passphrase: Zeroizing<String>,
        keyfile: Option<Vec<u8>>,
        #[cfg_attr(
            not(all(not(target_arch = "wasm32"), feature = "fido2")),
            allow(dead_code)
        )]
        fido2: Option<(PathBuf, Option<Zeroizing<String>>)>,
        // Browser-native equivalent of `fido2`, resolved asynchronously (a
        // passkey prompt) - see `handle_decrypt_batch`'s wasm branch and
        // `poll_decrypt_webauthn`.
        #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
        webauthn: Option<crate::webauthn::Enrollment>,
    },
}

/// [`DecryptTarget`] with any hardware-derived second factor already resolved
/// to bytes, ready to reuse across every file in the batch.
enum ResolvedDecryptTarget {
    PrivateKey {
        priv_pem: String,
        unlock_passphrase: Option<Zeroizing<String>>,
    },
    Passphrase {
        passphrase: Zeroizing<String>,
        keyfile: Option<Vec<u8>>,
        fido2_secret: Option<Zeroizing<[u8; 32]>>,
        webauthn_secret: Option<Zeroizing<[u8; 32]>>,
    },
}

/// Never called with `webauthn: Some(_)` - see `resolve_encrypt_target`'s
/// docs for why.
fn resolve_decrypt_target(target: DecryptTarget) -> Result<ResolvedDecryptTarget, String> {
    match target {
        DecryptTarget::PrivateKey {
            priv_pem,
            unlock_passphrase,
        } => Ok(ResolvedDecryptTarget::PrivateKey {
            priv_pem,
            unlock_passphrase,
        }),
        DecryptTarget::Passphrase {
            passphrase,
            keyfile,
            fido2,
            webauthn,
        } => {
            debug_assert!(
                webauthn.is_none(),
                "webauthn second factor must be resolved asynchronously before resolve_decrypt_target"
            );
            let fido2_secret = match fido2 {
                None => None,
                Some((path, pin)) => Some(crate::tabs::encrypt::derive_fido2_secret(
                    &path,
                    pin.as_deref().map(String::as_str),
                )?),
            };
            Ok(ResolvedDecryptTarget::Passphrase {
                passphrase,
                keyfile,
                fido2_secret,
                webauthn_secret: None,
            })
        }
    }
}

fn decrypt_entry(
    target: &ResolvedDecryptTarget,
    data: &[u8],
    stealth: bool,
    progress: &dyn Fn(u64, u64),
) -> Result<Vec<u8>, pqfile::error::PqfileError> {
    match target {
        ResolvedDecryptTarget::PrivateKey {
            priv_pem,
            unlock_passphrase,
        } => {
            let pp = unlock_passphrase.as_deref().map(String::as_str);
            if stealth {
                // decrypt_stream_stealth has no progress callback; the byte
                // progress bar simply stays at 0 for stealth files.
                let mut cursor = Cursor::new(data);
                let mut out = Vec::new();
                decrypt::decrypt_stream_stealth(priv_pem, &mut cursor, &mut out, pp).map(|_| out)
            } else {
                let mut cursor = Cursor::new(data);
                let mut out = Vec::new();
                #[cfg(not(target_arch = "wasm32"))]
                let result = decrypt::decrypt_stream_parallel_with_progress(
                    priv_pem,
                    &mut cursor,
                    &mut out,
                    pp,
                    8, // parallel batch size (matches CLI default)
                    0, // total_hint unknown until header is parsed
                    progress,
                );
                // No parallel/progress-tracked decrypt on WASM (matches the
                // original wasm-only branch this replaces).
                #[cfg(target_arch = "wasm32")]
                let result = {
                    let _ = progress;
                    decrypt::decrypt_stream(priv_pem, &mut cursor, &mut out, pp)
                };
                result.map(|_| out)
            }
        }
        ResolvedDecryptTarget::Passphrase {
            passphrase,
            keyfile,
            fido2_secret,
            webauthn_secret,
        } => {
            let mut cursor = Cursor::new(data);
            let mut out = Vec::new();
            let result = if let Some(kf) = keyfile {
                decrypt::decrypt_stream_passphrase_keyfile(passphrase, kf, &mut cursor, &mut out)
            } else if let Some(hs) = fido2_secret {
                decrypt::decrypt_stream_passphrase_fido2(passphrase, hs, &mut cursor, &mut out)
            } else if let Some(p) = webauthn_secret {
                decrypt::decrypt_stream_passphrase_webauthn_prf(
                    passphrase,
                    p,
                    &mut cursor,
                    &mut out,
                )
            } else {
                decrypt::decrypt_stream_passphrase(passphrase, &mut cursor, &mut out)
            };
            result.map(|_| out)
        }
    }
}

impl PqfileApp {
    pub(crate) fn handle_decrypt_batch(&mut self, ctx: &egui::Context) {
        if self.decrypt_files.is_empty() {
            self.decrypt_status = OpStatus::Err("Add at least one .pqf file.".to_owned());
            return;
        }
        let target = match self.build_decrypt_target() {
            Ok(t) => t,
            Err(msg) => {
                self.decrypt_status = OpStatus::Err(msg);
                return;
            }
        };
        self.decrypt_status = OpStatus::None;
        self.decrypt_batch_summary = None;

        let stealth = self.decrypt_stealth && self.decrypt_mode == DecryptMode::PrivateKey;

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
            // Post-quantum crypto (esp. unoptimized debug builds) can use more
            // stack than the default ~2 MiB thread stack provides; spawn with a
            // larger stack to avoid a silent stack-overflow crash.
            std::thread::Builder::new()
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    // Resolve the FIDO2 second factor once for the whole batch: it
                    // means touching hardware, so files reuse the same secret
                    // rather than prompting a touch per file.
                    let target = match resolve_decrypt_target(target) {
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
                        // Reset per-file byte progress.
                        {
                            let mut g = job.lock().unwrap();
                            g.current_file_bytes_done = 0;
                            g.current_file_bytes_total = 0;
                        }
                        let job_progress = Arc::clone(&job);
                        let ctx_progress = ctx.clone();
                        let progress = move |done: u64, total: u64| {
                            let mut g = job_progress.lock().unwrap();
                            g.current_file_bytes_done = done;
                            g.current_file_bytes_total = total;
                            drop(g);
                            ctx_progress.request_repaint();
                        };
                        let result = decrypt_entry(&target, &data, stealth, &progress);
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
                })
                .expect("failed to spawn decrypt worker thread");
        }

        #[cfg(target_arch = "wasm32")]
        {
            match target {
                DecryptTarget::Passphrase {
                    webauthn: Some(enrollment),
                    ..
                } => {
                    // WebAuthn PRF derivation is an async browser prompt, so
                    // it can't resolve synchronously the way every other
                    // second factor does. Kick it off and stop here -
                    // poll_decrypt_webauthn resumes once it sees the result.
                    // No resume field needed (unlike encrypt): decrypt_v10_passphrase
                    // is untouched in `self` and just re-read once this resolves.
                    let pending: crate::types::WebAuthnPending<Zeroizing<[u8; 32]>> =
                        std::sync::Arc::new(std::sync::Mutex::new(None));
                    self.decrypt_webauthn_derive_pending = Some(std::sync::Arc::clone(&pending));
                    let ctx = ctx.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        let result = crate::webauthn::derive_secret(&enrollment).await;
                        *pending.lock().unwrap() = Some(result);
                        ctx.request_repaint();
                    });
                }
                other => match resolve_decrypt_target(other) {
                    Ok(resolved) => self.run_decrypt_wasm(resolved, stealth),
                    Err(msg) => self.decrypt_status = OpStatus::Err(msg),
                },
            }
        }
    }

    /// Called once per frame: drains an outstanding WebAuthn PRF derivation
    /// kicked off by `handle_decrypt_batch` and, once it resolves, runs the
    /// decrypt batch that was deferred waiting for it.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn poll_decrypt_webauthn(&mut self) {
        let Some(pending) = &self.decrypt_webauthn_derive_pending else {
            return;
        };
        let Some(result) = pending.lock().unwrap().take() else {
            return;
        };
        self.decrypt_webauthn_derive_pending = None;
        match result {
            Ok(secret) => {
                let stealth = self.decrypt_stealth && self.decrypt_mode == DecryptMode::PrivateKey;
                let resolved = ResolvedDecryptTarget::Passphrase {
                    passphrase: self.decrypt_v10_passphrase.clone(),
                    keyfile: None,
                    fido2_secret: None,
                    webauthn_secret: Some(secret),
                };
                self.run_decrypt_wasm(resolved, stealth);
            }
            Err(msg) => self.decrypt_status = OpStatus::Err(msg),
        }
    }

    /// Runs an already-resolved decrypt batch synchronously to completion.
    /// `target` is either built directly (None/Keyfile second factor, or no
    /// passphrase mode at all) or resumed after an async WebAuthn PRF
    /// derivation completed (see `poll_decrypt_webauthn`).
    #[cfg(target_arch = "wasm32")]
    fn run_decrypt_wasm(&mut self, target: ResolvedDecryptTarget, stealth: bool) {
        for entry in &mut self.decrypt_files {
            let result = decrypt_entry(&target, &entry.data, stealth, &|_, _| {});
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
            self.decrypt_passphrase.zeroize();
            self.decrypt_v10_passphrase.zeroize();
        }
    }

    /// Validates the current mode's inputs and builds the `DecryptTarget` for
    /// the batch, without touching any hardware beyond what's already loaded.
    fn build_decrypt_target(&self) -> Result<DecryptTarget, String> {
        match self.decrypt_mode {
            DecryptMode::PrivateKey => {
                let priv_pem = self
                    .decrypt_privkey
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "Load a private key first.".to_owned())?;
                let unlock_passphrase = if self.decrypt_passphrase.is_empty() {
                    None
                } else {
                    Some(Zeroizing::new((*self.decrypt_passphrase).clone()))
                };
                Ok(DecryptTarget::PrivateKey {
                    priv_pem,
                    unlock_passphrase,
                })
            }
            DecryptMode::Passphrase => {
                if self.decrypt_v10_passphrase.is_empty() {
                    return Err("Enter the passphrase.".to_owned());
                }
                let (keyfile, fido2, webauthn) = match self.decrypt_second_factor {
                    SecondFactorMode::None => (None, None, None),
                    SecondFactorMode::Keyfile => {
                        let Some(data) = self.decrypt_keyfile.data.clone() else {
                            return Err("Choose the keyfile used at encryption time.".to_owned());
                        };
                        (Some(data), None, None)
                    }
                    SecondFactorMode::Fido2 => {
                        let Some(path) = self.decrypt_fido2_enrollment.path.clone() else {
                            return Err("Choose the FIDO2 enrollment file.".to_owned());
                        };
                        #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
                        let pin = if self.decrypt_fido2_pin.is_empty() {
                            None
                        } else {
                            Some(self.decrypt_fido2_pin.clone())
                        };
                        #[cfg(not(all(not(target_arch = "wasm32"), feature = "fido2")))]
                        let pin: Option<Zeroizing<String>> = None;
                        (None, Some((path, pin)), None)
                    }
                    SecondFactorMode::WebAuthnPrf => {
                        let Some(data) = self.decrypt_webauthn_enrollment.data.clone() else {
                            return Err("Choose the WebAuthn enrollment file.".to_owned());
                        };
                        let text = std::str::from_utf8(&data).map_err(|_| {
                            "Could not read the WebAuthn enrollment file.".to_owned()
                        })?;
                        let enrollment = crate::webauthn::Enrollment::parse(text)?;
                        (None, None, Some(enrollment))
                    }
                };
                Ok(DecryptTarget::Passphrase {
                    passphrase: self.decrypt_v10_passphrase.clone(),
                    keyfile,
                    fido2,
                    webauthn,
                })
            }
        }
    }

    pub(crate) fn show_decrypt(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Decrypt / Rekey", dark) {
            self.help_modal_open = Some(Tab::Decrypt);
        }
        ui.label(
            RichText::new(
                "Decrypt .pqf files with your private key, or use Rekey / Add Recipient to \
                 transfer or extend access to a ciphertext without decrypting the payload.",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(10.0);

        // Rekey and Add Recipient are rare, specialized operations (transfer or extend
        // ciphertext access without decrypting), so they're secondary links off the main
        // Decrypt flow rather than equally-weighted peer tabs — first-time users land
        // straight on the common path.
        match self.decrypt_sub_tab {
            DecryptSubTab::Decrypt => {
                self.show_decrypt_section(ui, dark);
                self.show_secondary_op_prompt(ui, dark);
            }
            DecryptSubTab::Rekey => {
                self.show_back_to_decrypt_link(ui, dark);
                self.show_rekey_section(ui, dark);
            }
            DecryptSubTab::AddRecipient => {
                self.show_back_to_decrypt_link(ui, dark);
                self.show_add_recipient_section(ui, dark);
            }
        }
    }

    fn show_secondary_op_prompt(&mut self, ui: &mut egui::Ui, dark: bool) {
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Need to transfer this file to a new recipient, or add one, ")
                    .size(12.0)
                    .color(c_subtext(dark)),
            );
            ui.label(
                RichText::new("without decrypting it?")
                    .size(12.0)
                    .color(c_subtext(dark)),
            );
            if ui
                .add(
                    egui::Label::new(
                        RichText::new("Rekey instead →")
                            .size(12.0)
                            .color(c_accent(dark))
                            .underline(),
                    )
                    .sense(egui::Sense::click()),
                )
                .clicked()
            {
                self.decrypt_sub_tab = DecryptSubTab::Rekey;
            }
            ui.label(RichText::new("·").size(12.0).color(c_subtext(dark)));
            if ui
                .add(
                    egui::Label::new(
                        RichText::new("Add a recipient →")
                            .size(12.0)
                            .color(c_accent(dark))
                            .underline(),
                    )
                    .sense(egui::Sense::click()),
                )
                .clicked()
            {
                self.decrypt_sub_tab = DecryptSubTab::AddRecipient;
            }
        });
    }

    fn show_back_to_decrypt_link(&mut self, ui: &mut egui::Ui, dark: bool) {
        if ui
            .add(
                egui::Label::new(
                    RichText::new("← Back to Decrypt")
                        .size(12.5)
                        .color(c_accent(dark))
                        .underline(),
                )
                .sense(egui::Sense::click()),
            )
            .clicked()
        {
            self.decrypt_sub_tab = DecryptSubTab::Decrypt;
        }
        ui.add_space(6.0);
    }

    fn show_decrypt_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        ui.add_space(4.0);

        #[cfg(not(target_arch = "wasm32"))]
        let job_running = self.decrypt_batch_job.is_some();
        #[cfg(target_arch = "wasm32")]
        let job_running = self.decrypt_webauthn_derive_pending.is_some();

        seg_tabs(
            ui,
            &mut self.decrypt_mode,
            &[
                ("Private Key", DecryptMode::PrivateKey),
                ("Passphrase", DecryptMode::Passphrase),
            ],
            dark,
        );

        match self.decrypt_mode {
            DecryptMode::PrivateKey => {
                // ── Private key ───────────────────────────────────────────
                section_label(ui, "PRIVATE KEY", dark);
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
                    self.decrypt_passphrase.zeroize();
                }

                // ── Options ─────────────────────────────────────────────
                card(ui, c_card(dark), c_surface1(dark), |ui| {
                    ui.horizontal(|ui| {
                        ui.add_enabled(
                            !job_running,
                            egui::Checkbox::new(&mut self.decrypt_stealth, ""),
                        );
                        ui.label(
                            RichText::new("Stealth mode (file has no magic bytes / .pqf header)")
                                .size(13.0)
                                .color(c_text(dark)),
                        )
                        .on_hover_text(
                            "Check this if the file(s) were encrypted with Stealth mode on the \
                             Encrypt tab. Such files have no .pqf magic or version byte, so pqfile \
                             cannot auto-detect them - you must say so yourself.",
                        );
                    });
                });
                ui.add_space(14.0);
            }
            DecryptMode::Passphrase => {
                section_label(ui, "PASSPHRASE", dark);
                card(ui, c_card(dark), c_surface1(dark), |ui| {
                    ui.add_enabled(
                        !job_running,
                        egui::TextEdit::singleline(&mut *self.decrypt_v10_passphrase)
                            .hint_text("Enter passphrase…")
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.label(
                    RichText::new(
                        "For files written with encrypt --passphrase (v10 format, no key pair).",
                    )
                    .size(11.5)
                    .color(c_subtext(dark)),
                );
                ui.add_space(14.0);

                section_label(ui, "SECOND FACTOR (IF ANY)", dark);
                card(ui, c_card(dark), c_surface1(dark), |ui| {
                    ui.add_enabled_ui(!job_running, |ui| {
                        ui.horizontal(|ui| {
                            ui.selectable_value(
                                &mut self.decrypt_second_factor,
                                SecondFactorMode::None,
                                "None",
                            );
                            ui.selectable_value(
                                &mut self.decrypt_second_factor,
                                SecondFactorMode::Keyfile,
                                "Keyfile",
                            );
                            #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
                            ui.selectable_value(
                                &mut self.decrypt_second_factor,
                                SecondFactorMode::Fido2,
                                "FIDO2 token",
                            );
                            // Disabled for now: see the matching comment in
                            // tabs/encrypt.rs's second-factor selector.
                            #[cfg(target_arch = "wasm32")]
                            ui.add_enabled_ui(false, |ui| {
                                ui.selectable_value(
                                    &mut self.decrypt_second_factor,
                                    SecondFactorMode::WebAuthnPrf,
                                    "Passkey",
                                )
                            })
                            .inner
                            .on_hover_text(
                                "Under implementation: browser/OS support for passkey-based \
                                 encryption (WebAuthn PRF) is still too inconsistent to enable yet.",
                            );
                        });
                        match self.decrypt_second_factor {
                            SecondFactorMode::None => {}
                            SecondFactorMode::Keyfile => {
                                ui.add_space(6.0);
                                file_row(
                                    ui,
                                    "Keyfile (same file used at encryption time)",
                                    &mut self.decrypt_keyfile,
                                    "",
                                    &[],
                                    dark,
                                );
                            }
                            SecondFactorMode::Fido2 => {
                                #[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
                                self.show_decrypt_fido2_second_factor(ui, dark);
                            }
                            SecondFactorMode::WebAuthnPrf => {
                                #[cfg(target_arch = "wasm32")]
                                self.show_decrypt_webauthn_second_factor(ui, dark);
                            }
                        }
                    });
                });
                ui.add_space(14.0);
            }
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
                scrollable_list(ui, "decrypt_files", 154.0, c_card(dark), |ui| {
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
        let mode_ready = match self.decrypt_mode {
            DecryptMode::PrivateKey => self.decrypt_privkey.loaded(),
            DecryptMode::Passphrase => !self.decrypt_v10_passphrase.is_empty(),
        };
        let ready = mode_ready && n > 0 && !job_running;
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
                ui.add(egui::ProgressBar::new(fraction).animate(true));
                if g.current_file_bytes_done > 0 {
                    ui.add_space(2.0);
                    let mib = g.current_file_bytes_done as f32 / (1024.0 * 1024.0);
                    // Show indeterminate bar (total is unknown for decrypt); display byte count.
                    ui.add(
                        egui::ProgressBar::new(0.0)
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
        if let Some(summary) = self.decrypt_batch_summary.clone() {
            show_status(ui, &summary, dark);
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
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.rekey_input.path.as_deref(),
                    &out_name,
                    &self.settings.output_dir,
                    |p| p.to_path_buf(),
                ));
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

    // ── Add Recipient ────────────────────────────────────────────────────

    fn show_add_recipient_section(&mut self, ui: &mut egui::Ui, dark: bool) {
        ui.add_space(4.0);
        section_label(ui, "ADD RECIPIENT", dark);
        ui.label(
            RichText::new(
                "Add a new recipient to a v4/v7/v8 multi-recipient .pqf file without \
                 re-encrypting the payload. The session key is recovered with an existing \
                 recipient's private key and re-encapsulated for the new recipient. The \
                 encrypted content is untouched.",
            )
            .size(12.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(6.0);
        let mut pp_submitted = false;
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Existing recipient's private key (for decapsulation)",
                &mut self.add_recipient_privkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            pp_submitted = passphrase_row(
                ui,
                "Existing key passphrase:",
                &mut self.add_recipient_privkey_passphrase,
                &mut self.add_recipient_privkey_passphrase_visible,
                "Leave empty for an unencrypted key",
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "New recipient public key",
                &mut self.add_recipient_new_pubkey,
                "PEM",
                &["pem"],
                dark,
            );
            ui.add_space(4.0);
            file_row(
                ui,
                "Encrypted file to add a recipient to (.pqf)",
                &mut self.add_recipient_input,
                "PQF",
                &["pqf"],
                dark,
            );
        });
        ui.add_space(8.0);

        let ready = self.add_recipient_privkey.loaded()
            && self.add_recipient_new_pubkey.loaded()
            && self.add_recipient_input.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("➕  Add Recipient")
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
            self.do_add_recipient();
        }

        show_status(ui, &self.add_recipient_status, dark);
    }

    fn do_add_recipient(&mut self) {
        let existing_priv = match self.add_recipient_privkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.add_recipient_status =
                    OpStatus::Err("Load an existing recipient's private key first.".to_owned());
                return;
            }
        };
        let new_pub = match self.add_recipient_new_pubkey.as_str().map(str::to_owned) {
            Some(s) => s,
            None => {
                self.add_recipient_status =
                    OpStatus::Err("Load the new recipient public key first.".to_owned());
                return;
            }
        };
        let data = match self.add_recipient_input.data.clone() {
            Some(d) => d,
            None => {
                self.add_recipient_status =
                    OpStatus::Err("Choose the .pqf file to add a recipient to first.".to_owned());
                return;
            }
        };
        let passphrase = if self.add_recipient_privkey_passphrase.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                (*self.add_recipient_privkey_passphrase).clone(),
            ))
        };

        let mut output = Vec::new();
        let mut reader = Cursor::new(&data);
        match add_recipient::add_recipient_stream(
            &existing_priv,
            &new_pub,
            &mut reader,
            &mut output,
            passphrase.as_deref().map(String::as_str),
        ) {
            Ok(_info) => {
                let out_name = self.add_recipient_input.name.clone();
                #[cfg(not(target_arch = "wasm32"))]
                let native_path = Some(crate::widgets::resolve_sibling_output_path(
                    self.add_recipient_input.path.as_deref(),
                    &out_name,
                    &self.settings.output_dir,
                    |p| p.to_path_buf(),
                ));
                #[cfg(target_arch = "wasm32")]
                let native_path: Option<PathBuf> = None;
                self.add_recipient_status = save_result(
                    &out_name,
                    &output,
                    native_path,
                    self.settings.confirm_overwrite,
                );
            }
            Err(e) => {
                self.add_recipient_status = OpStatus::Err(e.to_string());
            }
        }
    }
}
