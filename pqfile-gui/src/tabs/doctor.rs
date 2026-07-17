use crate::app::PqfileApp;
use crate::colors::{
    c_accent, c_card, c_chrome, c_green, c_overlay, c_red, c_subtext, c_surface1, c_text, c_yellow,
};
use crate::types::{expiry_days_remaining, read_pem_expiry, OpStatus, Tab};
use crate::widgets::{card, file_row, kv_row, section_label, show_status, tab_heading_help};
use eframe::egui::{self, RichText, Vec2};
use pqfile::{inspect, keygen};
use std::io::Cursor;
#[cfg(not(target_arch = "wasm32"))]
use zeroize::Zeroize;

pub(crate) enum CheckKind {
    Pass,
    Warn,
    Fail,
    Info,
}

pub(crate) enum DoctorRow {
    Section(String),
    Kv(String, String),
    Check(CheckKind, String, String),
}

impl PqfileApp {
    pub(crate) fn show_inspect(&mut self, ui: &mut egui::Ui, dark: bool) {
        if tab_heading_help(ui, "Health Check  (File or Key)", dark) {
            self.help_modal_open = Some(Tab::Inspect);
        }
        ui.label(
            RichText::new(
                "Health checks and header details for a key (.pem) or encrypted file (.pqf).",
            )
            .size(13.0)
            .color(c_subtext(dark)),
        );
        ui.add_space(14.0);

        section_label(ui, "FILE", dark);
        card(ui, c_card(dark), c_surface1(dark), |ui| {
            file_row(
                ui,
                "Private key (.pem) or encrypted file (.pqf)",
                &mut self.doctor_file,
                "PEM or PQF",
                &["pem", "pqf"],
                dark,
            );
        });
        ui.add_space(14.0);

        // Show passphrase field for encrypted non-hardware keys (legacy Argon2 detection).
        // Desktop only - WASM has no way to attempt decryption for the probe.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let is_encrypted_key = self
                .doctor_file
                .as_str()
                .map(|s| {
                    s.starts_with("-----BEGIN")
                        && keygen::is_encrypted_key(s)
                        && !keygen::is_hardware_key(s)
                })
                .unwrap_or(false);

            if is_encrypted_key {
                section_label(
                    ui,
                    "PASSPHRASE (optional - for legacy Argon2 detection)",
                    dark,
                );
                card(ui, c_card(dark), c_surface1(dark), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.doctor_passphrase)
                            .hint_text(
                                "Enter passphrase to detect Argon2id p=1 (pqfile <4.0) keys…",
                            )
                            .password(true)
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.add_space(14.0);
            } else if self.doctor_file.loaded() {
                self.doctor_passphrase.zeroize();
            }
        }

        let ready = self.doctor_file.loaded();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new("🔍  Run Inspect")
                        .size(14.0)
                        .color(c_chrome(dark))
                        .strong(),
                )
                .fill(c_accent(dark))
                .min_size(Vec2::new(170.0, 32.0)),
            )
            .clicked()
        {
            if let Some(data) = self.doctor_file.data.clone() {
                let path = self.doctor_file.path.clone();
                let pp = if self.doctor_passphrase.is_empty() {
                    None
                } else {
                    Some(zeroize::Zeroizing::new((*self.doctor_passphrase).clone()))
                };
                match run_inspect(&data, path.as_deref(), pp.as_deref().map(String::as_str)) {
                    Ok(rows) => {
                        self.doctor_result = rows;
                        self.doctor_status = OpStatus::None;
                    }
                    Err(msg) => {
                        self.doctor_result.clear();
                        self.doctor_status = OpStatus::Err(msg);
                    }
                }
            }
        }

        if !self.doctor_result.is_empty() {
            ui.add_space(10.0);
            section_label(ui, "HEALTH REPORT", dark);
            card(ui, c_card(dark), c_surface1(dark), |ui| {
                for row in &self.doctor_result {
                    match row {
                        DoctorRow::Section(title) => {
                            ui.add_space(4.0);
                            ui.label(RichText::new(title).size(11.5).color(c_overlay(dark)));
                            ui.add_space(2.0);
                        }
                        DoctorRow::Kv(key, val) => {
                            kv_row(ui, key, val, dark);
                        }
                        DoctorRow::Check(kind, label, val) => {
                            let (badge, color) = match kind {
                                CheckKind::Pass => ("✔  ", c_green(dark)),
                                CheckKind::Warn => ("⚠  ", c_yellow(dark)),
                                CheckKind::Fail => ("✖  ", c_red(dark)),
                                CheckKind::Info => ("·  ", c_subtext(dark)),
                            };
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(badge).size(12.0).color(color).monospace());
                                ui.label(RichText::new(label).size(12.5).color(c_subtext(dark)));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Min),
                                    |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(val).size(12.5).color(c_text(dark)),
                                            )
                                            .wrap(),
                                        );
                                    },
                                );
                            });
                        }
                    }
                }
            });
        }

        show_status(ui, &self.doctor_status, dark);
    }
}

fn run_inspect(
    data: &[u8],
    path: Option<&std::path::Path>,
    passphrase: Option<&str>,
) -> Result<Vec<DoctorRow>, String> {
    if data.starts_with(b"-----BEGIN") {
        let pem_str =
            std::str::from_utf8(data).map_err(|_| "File is not valid UTF-8.".to_owned())?;
        Ok(doctor_key(pem_str, path, passphrase))
    } else if data.starts_with(b"PQFL") {
        let mut cursor = Cursor::new(data);
        let info = inspect::inspect_stream(&mut cursor).map_err(|e| e.to_string())?;
        Ok(doctor_pqf(&info))
    } else {
        Err(
            "No .pqf header found (missing the PQFL magic bytes) and this isn't a PEM key \
             either. If this file was encrypted with Stealth mode on the Encrypt tab, that's \
             expected: Stealth files have no header by design, so there is nothing for Health \
             Check to read without decrypting the file. Decrypt it directly instead — enable \
             \"Stealth mode\" on the Decrypt tab first."
                .to_owned(),
        )
    }
}

fn chk(kind: CheckKind, label: &str, value: &str) -> DoctorRow {
    DoctorRow::Check(kind, label.to_owned(), value.to_owned())
}

// `path` and `passphrase` only feed the native-only checks (revocation
// sidecar, legacy-Argon2 probe), so they go unused on wasm.
#[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
fn doctor_key(
    pem_str: &str,
    path: Option<&std::path::Path>,
    passphrase: Option<&str>,
) -> Vec<DoctorRow> {
    let is_encrypted = keygen::is_encrypted_key(pem_str);
    let is_hardware = keygen::is_hardware_key(pem_str);
    let fp = keygen::fingerprint_pem(pem_str);

    let key_type = if pem_str.contains("SLH-DSA-SHAKE-192F") {
        "SLH-DSA-SHAKE-192f signing key"
    } else if pem_str.contains("ML-DSA") || pem_str.contains("SIGNING") {
        "ML-DSA-65 signing key"
    } else if pem_str.contains("SHAMIR") || pem_str.contains("SHARE") {
        "Shamir share"
    } else if pem_str.contains("X25519+ML-KEM") || pem_str.contains("Hybrid") {
        "Hybrid X25519+ML-KEM-768"
    } else if pem_str.contains("ML-KEM-1024") {
        "ML-KEM-1024"
    } else if pem_str.contains("ML-KEM-512") {
        "ML-KEM-512"
    } else {
        "ML-KEM-768"
    };

    let mut rows = vec![
        DoctorRow::Section("Key Information".to_owned()),
        DoctorRow::Kv("Type".to_owned(), key_type.to_owned()),
        DoctorRow::Kv("Fingerprint".to_owned(), fp),
        DoctorRow::Section("Health Checks".to_owned()),
    ];

    if is_hardware {
        rows.push(chk(
            CheckKind::Info,
            "Passphrase protection",
            "n/a (hardware-backed)",
        ));
    } else if is_encrypted {
        rows.push(chk(CheckKind::Pass, "Passphrase protection", "yes"));
    } else {
        rows.push(chk(
            CheckKind::Warn,
            "Passphrase protection",
            "no - consider adding one",
        ));
    }

    if is_hardware {
        rows.push(chk(
            CheckKind::Pass,
            "Hardware-backed",
            "yes (OS credential store)",
        ));
    } else {
        rows.push(chk(CheckKind::Info, "Hardware-backed", "no (software key)"));
    }

    if let Some(date) = read_pem_expiry(pem_str) {
        if let Some(days) = expiry_days_remaining(&date) {
            if days < 0 {
                rows.push(chk(
                    CheckKind::Fail,
                    "Expiry",
                    &format!("EXPIRED - {date} ({} days ago)", -days),
                ));
            } else if days <= 30 {
                rows.push(chk(
                    CheckKind::Warn,
                    "Expiry",
                    &format!(
                        "{date} - expires in {days} day{}",
                        if days == 1 { "" } else { "s" }
                    ),
                ));
            } else {
                rows.push(chk(
                    CheckKind::Pass,
                    "Expiry",
                    &format!("{date} ({days} days remaining)"),
                ));
            }
        } else {
            rows.push(chk(
                CheckKind::Info,
                "Expiry",
                &format!("{date} (date unreadable)"),
            ));
        }
    } else {
        rows.push(chk(CheckKind::Info, "Expiry", "not set"));
    }

    // Legacy Argon2 detection - native only, requires a passphrase probe.
    #[cfg(not(target_arch = "wasm32"))]
    if is_encrypted && !is_hardware {
        if let Some(pp) = passphrase {
            use pqfile::error::PqfileError;
            let is_legacy = matches!(
                pqfile::decrypt::decrypt_stream(
                    pem_str,
                    &mut b"PQFL".as_slice(),
                    &mut Vec::new(),
                    Some(pp),
                ),
                Err(PqfileError::LegacyKeyFormat)
            );
            if is_legacy {
                rows.push(chk(
                    CheckKind::Warn,
                    "Argon2 parameters",
                    "legacy p=1 (pqfile <4.0) - upgrade via Keys > Change Passphrase (legacy)",
                ));
            } else {
                rows.push(chk(CheckKind::Pass, "Argon2 parameters", "current (p=4)"));
            }
        } else {
            rows.push(chk(
                CheckKind::Info,
                "Argon2 parameters",
                "enter passphrase above to check",
            ));
        }
    }

    // Revocation sidecar - native only, inferred from file path.
    #[cfg(not(target_arch = "wasm32"))]
    {
        if !check_revocation(pem_str, path, &mut rows) {
            rows.push(chk(
                CheckKind::Info,
                "Revocation",
                "load key via file picker to check sidecar",
            ));
        }
    }
    #[cfg(target_arch = "wasm32")]
    rows.push(chk(
        CheckKind::Info,
        "Revocation",
        "not available in browser (no filesystem access)",
    ));

    rows
}

/// Looks for a revocation sidecar adjacent to the key file and appends a check row.
/// Returns true if a sidecar check was performed (path was available).
#[cfg(not(target_arch = "wasm32"))]
fn check_revocation(
    pem_str: &str,
    path: Option<&std::path::Path>,
    rows: &mut Vec<DoctorRow>,
) -> bool {
    use pqfile::error::PqfileError;

    let Some(p) = path else { return false };

    // The sidecar lives next to the PUBLIC key. If we loaded the private key,
    // look for pubkey.pem in the same directory.
    let pub_path = if p
        .file_name()
        .map(|n| n.to_string_lossy().contains("pub"))
        .unwrap_or(false)
    {
        p.to_path_buf()
    } else {
        p.parent().unwrap_or(p).join("pubkey.pem")
    };

    let pub_pem = if pub_path.exists() {
        match std::fs::read_to_string(&pub_path) {
            Ok(s) => s,
            Err(_) => {
                rows.push(chk(
                    CheckKind::Warn,
                    "Revocation",
                    "could not read companion pubkey.pem",
                ));
                return true;
            }
        }
    } else {
        // Try using the loaded PEM directly (user may have loaded the public key).
        if pem_str.contains("PUBLIC") || pem_str.contains("ENCAPSULATION") {
            pem_str.to_owned()
        } else {
            return false;
        }
    };

    match pqfile::revoke::check_not_revoked(&pub_path, &pub_pem) {
        Ok(()) => {
            rows.push(chk(CheckKind::Pass, "Revocation", "not revoked"));
        }
        Err(PqfileError::KeyRevoked { reason, .. }) => {
            let detail = if reason.is_empty() {
                "REVOKED".to_owned()
            } else {
                format!("REVOKED - {reason}")
            };
            rows.push(chk(CheckKind::Fail, "Revocation", &detail));
        }
        Err(_) => {
            rows.push(chk(CheckKind::Warn, "Revocation", "sidecar unreadable"));
        }
    }
    true
}

fn doctor_pqf(info: &inspect::PqfHeaderInfo) -> Vec<DoctorRow> {
    use pqfile::format;

    let mut rows = vec![DoctorRow::Section("File Information".to_owned())];

    match info {
        inspect::PqfHeaderInfo::Single {
            version,
            kem_variant,
            nonce,
            original_size,
            chunk_size,
            compression_algo,
        } => {
            let ver_label = match format::version_layout(*version) {
                v if v == format::VERSION => "v2 (single-recipient)",
                v if v == format::VERSION_V3 => "v3 (streaming)",
                v if v == format::VERSION_V5 => "v5 (configurable chunk)",
                v if v == format::VERSION_V6 => "v6 (compressed)",
                _ => "unknown version",
            };
            rows.push(DoctorRow::Kv("Format".to_owned(), ver_label.to_owned()));
            rows.push(DoctorRow::Kv(
                "Auth. header".to_owned(),
                if format::is_header_authenticated(*version) {
                    "yes".to_owned()
                } else {
                    "no".to_owned()
                },
            ));
            rows.push(DoctorRow::Kv(
                "KEM".to_owned(),
                variant_name(*kem_variant).to_owned(),
            ));
            rows.push(DoctorRow::Kv(
                "Original size".to_owned(),
                format!("{original_size} bytes"),
            ));
            let layout = format::version_layout(*version);
            if layout == format::VERSION_V5 || layout == format::VERSION_V6 {
                rows.push(DoctorRow::Kv(
                    "Chunk size".to_owned(),
                    format!("{chunk_size} bytes"),
                ));
            }
            if layout == format::VERSION_V6 {
                let algo = if *compression_algo == format::COMPRESSION_ZSTD {
                    "zstd"
                } else {
                    "unknown"
                };
                rows.push(DoctorRow::Kv("Compression".to_owned(), algo.to_owned()));
            }
            rows.push(DoctorRow::Section("Health Checks".to_owned()));
            rows.push(chk(CheckKind::Pass, "Header validity", "OK"));
            rows.push(chk(CheckKind::Info, "Recipients", "single"));
            rows.push(DoctorRow::Section("Raw Details".to_owned()));
            rows.push(DoctorRow::Kv(
                "Version (hex)".to_owned(),
                format!("{:#04x}", version),
            ));
            rows.push(DoctorRow::Kv(
                "Nonce".to_owned(),
                nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            ));
        }
        inspect::PqfHeaderInfo::Multi {
            recipients,
            nonce,
            original_size,
        } => {
            rows.push(DoctorRow::Kv(
                "Format".to_owned(),
                "v4 (multi-recipient)".to_owned(),
            ));
            rows.push(DoctorRow::Kv(
                "Recipients".to_owned(),
                recipients.len().to_string(),
            ));
            rows.push(DoctorRow::Kv(
                "Original size".to_owned(),
                format!("{original_size} bytes"),
            ));
            rows.push(DoctorRow::Section("Health Checks".to_owned()));
            rows.push(chk(CheckKind::Pass, "Header validity", "OK"));
            rows.push(chk(
                CheckKind::Warn,
                "Recipient anonymity",
                "none - re-encrypt with anonymous format for privacy",
            ));
            rows.push(DoctorRow::Section("Raw Details".to_owned()));
            rows.push(DoctorRow::Kv("Version (hex)".to_owned(), "0x04".to_owned()));
            for (i, r) in recipients.iter().enumerate() {
                rows.push(DoctorRow::Kv(
                    format!("Slot {i} KEM"),
                    variant_name(r.kem_variant).to_owned(),
                ));
            }
            rows.push(DoctorRow::Kv(
                "Nonce".to_owned(),
                nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            ));
        }
        inspect::PqfHeaderInfo::AnonMulti {
            recipients,
            nonce,
            original_size,
        } => {
            rows.push(DoctorRow::Kv(
                "Format".to_owned(),
                "v7 (anonymous multi-recipient, legacy)".to_owned(),
            ));
            rows.push(DoctorRow::Kv(
                "Slots".to_owned(),
                recipients.len().to_string(),
            ));
            rows.push(DoctorRow::Kv(
                "Original size".to_owned(),
                format!("{original_size} bytes"),
            ));
            rows.push(DoctorRow::Section("Health Checks".to_owned()));
            rows.push(chk(CheckKind::Pass, "Header validity", "OK"));
            rows.push(chk(CheckKind::Pass, "Recipient anonymity", "v7 anonymous"));
            rows.push(DoctorRow::Section("Raw Details".to_owned()));
            rows.push(DoctorRow::Kv("Version (hex)".to_owned(), "0x07".to_owned()));
            rows.push(DoctorRow::Kv(
                "Nonce".to_owned(),
                nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            ));
        }
        inspect::PqfHeaderInfo::AnonMultiV8 {
            version,
            slot_count,
            nonce,
            original_size,
        } => {
            let (ver_label, anon_detail) = if format::version_layout(*version) == format::VERSION_V9
            {
                (
                    "v9 (padded anonymous multi-recipient)",
                    "full (variant-blind + count-padded)",
                )
            } else {
                ("v8 (anonymous multi-recipient)", "strong (variant-blind)")
            };
            rows.push(DoctorRow::Kv("Format".to_owned(), ver_label.to_owned()));
            rows.push(DoctorRow::Kv("Slots".to_owned(), slot_count.to_string()));
            rows.push(DoctorRow::Kv(
                "Original size".to_owned(),
                format!("{original_size} bytes"),
            ));
            rows.push(DoctorRow::Section("Health Checks".to_owned()));
            rows.push(chk(CheckKind::Pass, "Header validity", "OK"));
            rows.push(chk(CheckKind::Pass, "Recipient anonymity", anon_detail));
            rows.push(DoctorRow::Section("Raw Details".to_owned()));
            rows.push(DoctorRow::Kv(
                "Version (hex)".to_owned(),
                format!("{:#04x}", version),
            ));
            rows.push(DoctorRow::Kv(
                "Nonce".to_owned(),
                nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            ));
        }
        inspect::PqfHeaderInfo::Passphrase {
            version,
            m_kib,
            t_cost,
            p_cost,
            flags,
            nonce,
            original_size,
        } => {
            rows.push(DoctorRow::Kv(
                "Format".to_owned(),
                "v10 (passphrase-only)".to_owned(),
            ));
            rows.push(DoctorRow::Kv(
                "Auth. header".to_owned(),
                if format::is_header_authenticated(*version) {
                    "yes".to_owned()
                } else {
                    "no".to_owned()
                },
            ));
            rows.push(DoctorRow::Kv(
                "Argon2id".to_owned(),
                format!("m={m_kib} KiB, t={t_cost}, p={p_cost}"),
            ));
            let keyfile_required = flags & 0x01 != 0;
            rows.push(DoctorRow::Kv(
                "Keyfile required".to_owned(),
                if keyfile_required {
                    "yes".to_owned()
                } else {
                    "no".to_owned()
                },
            ));
            rows.push(DoctorRow::Kv(
                "Original size".to_owned(),
                format!("{original_size} bytes"),
            ));
            rows.push(DoctorRow::Section("Health Checks".to_owned()));
            rows.push(chk(CheckKind::Pass, "Header validity", "OK"));
            rows.push(chk(
                CheckKind::Info,
                "Recipients",
                "passphrase (no key pair)",
            ));
            rows.push(DoctorRow::Section("Raw Details".to_owned()));
            rows.push(DoctorRow::Kv(
                "Version (hex)".to_owned(),
                format!("{:#04x}", version),
            ));
            rows.push(DoctorRow::Kv(
                "Nonce".to_owned(),
                nonce.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            ));
        }
        _ => {
            rows.push(DoctorRow::Section("Health Checks".to_owned()));
            rows.push(chk(
                CheckKind::Fail,
                "Header validity",
                "unsupported format version",
            ));
        }
    }

    rows
}

fn variant_name(v: u16) -> &'static str {
    match v {
        512 => "ML-KEM-512",
        768 => "ML-KEM-768",
        1024 => "ML-KEM-1024",
        0x0301 => "Hybrid X25519+ML-KEM-768",
        _ => "unknown",
    }
}
