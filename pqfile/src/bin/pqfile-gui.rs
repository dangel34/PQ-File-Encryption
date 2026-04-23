use eframe::egui;
use pqfile::{decrypt, encrypt, format, keygen};
use rfd::FileDialog;
use std::io::BufReader;
use std::path::{Path, PathBuf};

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("pqfile — Quantum-Resistant File Encryption")
            .with_inner_size([660.0, 300.0])
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native(
        "pqfile",
        options,
        Box::new(|_cc| Ok(Box::new(PqfileApp::default()))),
    )
    .unwrap();
}

#[derive(PartialEq, Default, Clone, Copy)]
enum Tab {
    #[default]
    Keygen,
    Encrypt,
    Decrypt,
    Inspect,
}

#[derive(Default)]
enum OpStatus {
    #[default]
    None,
    Ok(String),
    Err(String),
}

#[derive(Default)]
struct PqfileApp {
    tab: Tab,
    keygen_dir: String,
    keygen_status: OpStatus,
    encrypt_pubkey: String,
    encrypt_input: String,
    encrypt_status: OpStatus,
    decrypt_privkey: String,
    decrypt_input: String,
    decrypt_status: OpStatus,
    inspect_input: String,
    inspect_result: String,
    inspect_status: OpStatus,
}

impl eframe::App for PqfileApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Keygen, "🔑 Keygen");
                ui.selectable_value(&mut self.tab, Tab::Encrypt, "🔒 Encrypt");
                ui.selectable_value(&mut self.tab, Tab::Decrypt, "🔓 Decrypt");
                ui.selectable_value(&mut self.tab, Tab::Inspect, "🔍 Inspect");
            });
            ui.separator();
            match self.tab {
                Tab::Keygen => show_keygen(
                    ui,
                    &mut self.keygen_dir,
                    &mut self.keygen_status,
                ),
                Tab::Encrypt => show_encrypt(
                    ui,
                    &mut self.encrypt_pubkey,
                    &mut self.encrypt_input,
                    &mut self.encrypt_status,
                ),
                Tab::Decrypt => show_decrypt(
                    ui,
                    &mut self.decrypt_privkey,
                    &mut self.decrypt_input,
                    &mut self.decrypt_status,
                ),
                Tab::Inspect => show_inspect(
                    ui,
                    &mut self.inspect_input,
                    &mut self.inspect_result,
                    &mut self.inspect_status,
                ),
            }
        });
    }
}

fn show_keygen(ui: &mut egui::Ui, dir: &mut String, status: &mut OpStatus) {
    ui.heading("Generate Key Pair");
    ui.add_space(8.0);
    folder_row(ui, "Output directory:", dir);
    ui.add_space(8.0);
    if ui.button("Generate Key Pair").clicked() {
        *status = match keygen::keygen(Path::new(dir.as_str())) {
            Ok(()) => OpStatus::Ok(format!("Keys saved to {dir}")),
            Err(e) => OpStatus::Err(e.to_string()),
        };
    }
    show_status(ui, status);
}

fn show_encrypt(
    ui: &mut egui::Ui,
    pubkey: &mut String,
    input: &mut String,
    status: &mut OpStatus,
) {
    ui.heading("Encrypt File");
    ui.add_space(8.0);
    file_row(ui, "Public key (.pem):", pubkey, Some(("PEM", &["pem"])));
    file_row(ui, "Input file:        ", input, None);
    ui.add_space(8.0);
    if ui.button("Encrypt").clicked() {
        *status = match encrypt::encrypt(Path::new(pubkey.as_str()), Path::new(input.as_str())) {
            Ok(()) => OpStatus::Ok(format!("Encrypted → {input}.pqf")),
            Err(e) => OpStatus::Err(e.to_string()),
        };
    }
    show_status(ui, status);
}

fn show_decrypt(
    ui: &mut egui::Ui,
    privkey: &mut String,
    input: &mut String,
    status: &mut OpStatus,
) {
    ui.heading("Decrypt File");
    ui.add_space(8.0);
    file_row(ui, "Private key (.pem):", privkey, Some(("PEM", &["pem"])));
    file_row(ui, "Input file (.pqf): ", input, Some(("PQF encrypted", &["pqf"])));
    ui.add_space(8.0);
    if ui.button("Decrypt").clicked() {
        *status = match decrypt::decrypt(Path::new(privkey.as_str()), Path::new(input.as_str())) {
            Ok(()) => {
                let out = PathBuf::from(&*input)
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                OpStatus::Ok(format!("Decrypted → {out}"))
            }
            Err(e) => OpStatus::Err(e.to_string()),
        };
    }
    show_status(ui, status);
}

fn show_inspect(
    ui: &mut egui::Ui,
    input: &mut String,
    result: &mut String,
    status: &mut OpStatus,
) {
    ui.heading("Inspect .pqf File");
    ui.add_space(8.0);
    file_row(ui, "Input file (.pqf):", input, Some(("PQF encrypted", &["pqf"])));
    ui.add_space(8.0);
    if ui.button("Inspect").clicked() {
        match do_inspect(Path::new(input.as_str())) {
            Ok(text) => {
                *result = text;
                *status = OpStatus::None;
            }
            Err(e) => {
                result.clear();
                *status = OpStatus::Err(e);
            }
        }
    }
    if !result.is_empty() {
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new(result.as_str()).monospace());
        });
    }
    show_status(ui, status);
}

fn file_row(ui: &mut egui::Ui, label: &str, path: &mut String, filter: Option<(&str, &[&str])>) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.text_edit_singleline(path);
        if ui.button("Browse…").clicked() {
            let mut dialog = FileDialog::new();
            if let Some((name, exts)) = filter {
                dialog = dialog.add_filter(name, exts);
            }
            if let Some(p) = dialog.pick_file() {
                *path = p.to_string_lossy().into_owned();
            }
        }
    });
}

fn folder_row(ui: &mut egui::Ui, label: &str, path: &mut String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.text_edit_singleline(path);
        if ui.button("Browse…").clicked() {
            if let Some(p) = FileDialog::new().pick_folder() {
                *path = p.to_string_lossy().into_owned();
            }
        }
    });
}

fn do_inspect(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(file);
    let header = format::PqfHeader::read(&mut reader).map_err(|e| e.to_string())?;
    let nonce_hex: String = header.nonce.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "Magic:              PQFL\nVersion:            {:#04x}\nKEM variant:        {}\nNonce:              {}\nOriginal file size: {} bytes",
        format::VERSION,
        format::KEM_VARIANT,
        nonce_hex,
        header.original_size
    ))
}

fn show_status(ui: &mut egui::Ui, status: &OpStatus) {
    match status {
        OpStatus::None => {}
        OpStatus::Ok(msg) if !msg.is_empty() => {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(80, 200, 100), msg);
        }
        OpStatus::Ok(_) => {}
        OpStatus::Err(msg) => {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(230, 80, 80), msg);
        }
    }
}
