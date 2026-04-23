use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eframe::egui;
use pqfile::{decrypt, encrypt, format, keygen};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// ── WASM entry point ───────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    use wasm_bindgen::JsCast as _;
    let canvas = web_sys::window()
        .unwrap()
        .document()
        .unwrap()
        .get_element_by_id("pqfile_canvas")
        .unwrap()
        .dyn_into::<web_sys::HtmlCanvasElement>()
        .unwrap();
    let web_options = eframe::WebOptions::default();
    wasm_bindgen_futures::spawn_local(async move {
        eframe::WebRunner::new()
            .start(
                canvas,
                web_options,
                Box::new(|_cc| Ok(Box::new(PqfileApp::default()))),
            )
            .await
            .expect("failed to start eframe");
    });
    Ok(())
}

// ── Types ──────────────────────────────────────────────────────────────────

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

struct PickedFile {
    name: String,
    data: Vec<u8>,
    path: Option<PathBuf>,
}

type Pending = Arc<Mutex<Option<PickedFile>>>;

struct FileInput {
    name: String,
    data: Option<Vec<u8>>,
    path: Option<PathBuf>,
    pending: Pending,
}

impl Default for FileInput {
    fn default() -> Self {
        Self {
            name: String::new(),
            data: None,
            path: None,
            pending: Arc::new(Mutex::new(None)),
        }
    }
}

impl FileInput {
    fn poll(&mut self) {
        if let Ok(mut guard) = self.pending.try_lock() {
            if let Some(f) = guard.take() {
                self.name = f.name;
                self.data = Some(f.data);
                self.path = f.path;
            }
        }
    }

    fn loaded(&self) -> bool {
        self.data.is_some()
    }

    fn as_str(&self) -> Option<&str> {
        self.data.as_deref().and_then(|d| std::str::from_utf8(d).ok())
    }
}

// ── App ────────────────────────────────────────────────────────────────────

pub struct PqfileApp {
    tab: Tab,
    #[cfg(not(target_arch = "wasm32"))]
    keygen_dir: String,
    keygen_status: OpStatus,
    encrypt_pubkey: FileInput,
    encrypt_plain: FileInput,
    encrypt_status: OpStatus,
    decrypt_privkey: FileInput,
    decrypt_pqf: FileInput,
    decrypt_status: OpStatus,
    inspect_pqf: FileInput,
    inspect_result: String,
    inspect_status: OpStatus,
}

impl Default for PqfileApp {
    fn default() -> Self {
        Self {
            tab: Tab::Keygen,
            #[cfg(not(target_arch = "wasm32"))]
            keygen_dir: String::new(),
            keygen_status: OpStatus::None,
            encrypt_pubkey: FileInput::default(),
            encrypt_plain: FileInput::default(),
            encrypt_status: OpStatus::None,
            decrypt_privkey: FileInput::default(),
            decrypt_pqf: FileInput::default(),
            decrypt_status: OpStatus::None,
            inspect_pqf: FileInput::default(),
            inspect_result: String::new(),
            inspect_status: OpStatus::None,
        }
    }
}

impl eframe::App for PqfileApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.encrypt_pubkey.poll();
        self.encrypt_plain.poll();
        self.decrypt_privkey.poll();
        self.decrypt_pqf.poll();
        self.inspect_pqf.poll();

        // Keep re-rendering while async picks are pending
        if [
            &self.encrypt_pubkey,
            &self.encrypt_plain,
            &self.decrypt_privkey,
            &self.decrypt_pqf,
            &self.inspect_pqf,
        ]
        .iter()
        .any(|f| f.pending.try_lock().map(|g| g.is_some()).unwrap_or(false))
        {
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Keygen, "🔑 Keygen");
                ui.selectable_value(&mut self.tab, Tab::Encrypt, "🔒 Encrypt");
                ui.selectable_value(&mut self.tab, Tab::Decrypt, "🔓 Decrypt");
                ui.selectable_value(&mut self.tab, Tab::Inspect, "🔍 Inspect");
            });
            ui.separator();
            match self.tab {
                Tab::Keygen => self.show_keygen(ui),
                Tab::Encrypt => self.show_encrypt(ui),
                Tab::Decrypt => self.show_decrypt(ui),
                Tab::Inspect => self.show_inspect(ui),
            }
        });
    }
}

// ── Tab implementations ────────────────────────────────────────────────────

impl PqfileApp {
    fn show_keygen(&mut self, ui: &mut egui::Ui) {
        ui.heading("Generate Key Pair");
        ui.add_space(8.0);

        #[cfg(not(target_arch = "wasm32"))]
        {
            ui.horizontal(|ui| {
                ui.label("Output directory:");
                ui.text_edit_singleline(&mut self.keygen_dir);
                if ui.button("Browse…").clicked() {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.keygen_dir = p.to_string_lossy().into_owned();
                    }
                }
            });
            ui.add_space(8.0);
        }

        #[cfg(target_arch = "wasm32")]
        {
            ui.label("Clicking Generate will download pubkey.pem and privkey.pem.");
            ui.add_space(8.0);
        }

        if ui.button("Generate Key Pair").clicked() {
            match keygen::keygen_bytes() {
                Ok((pub_pem, priv_pem)) => {
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        let dir = std::path::Path::new(&self.keygen_dir);
                        let r1 = std::fs::write(dir.join("pubkey.pem"), pub_pem.as_bytes());
                        let r2 = std::fs::write(dir.join("privkey.pem"), priv_pem.as_bytes());
                        self.keygen_status = match (r1, r2) {
                            (Ok(()), Ok(())) => OpStatus::Ok(format!(
                                "Keys saved to {}",
                                dir.display()
                            )),
                            (Err(e), _) | (_, Err(e)) => OpStatus::Err(e.to_string()),
                        };
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        download_bytes("pubkey.pem", pub_pem.as_bytes());
                        download_bytes("privkey.pem", priv_pem.as_bytes());
                        self.keygen_status =
                            OpStatus::Ok("pubkey.pem and privkey.pem downloaded.".to_owned());
                    }
                }
                Err(e) => self.keygen_status = OpStatus::Err(e.to_string()),
            }
        }

        show_status(ui, &self.keygen_status);
    }

    fn show_encrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("Encrypt File");
        ui.add_space(8.0);
        file_row(ui, "Public key (.pem):", &mut self.encrypt_pubkey, "PEM", &["pem"]);
        file_row(ui, "Input file:        ", &mut self.encrypt_plain, "", &[]);
        ui.add_space(8.0);

        if ui.button("Encrypt").clicked() {
            let pub_pem = self.encrypt_pubkey.as_str().map(str::to_owned);
            let plain = self.encrypt_plain.data.clone();
            let plain_name = self.encrypt_plain.name.clone();
            let plain_path = self.encrypt_plain.path.clone();

            match (pub_pem, plain) {
                (Some(pub_pem), Some(plain)) => {
                    match encrypt::encrypt_bytes(&pub_pem, &plain) {
                        Ok(pqf) => {
                            let out_name = format!("{plain_name}.pqf");
                            let out_path = plain_path
                                .map(|p| {
                                    let mut s = p.as_os_str().to_owned();
                                    s.push(".pqf");
                                    PathBuf::from(s)
                                });
                            self.encrypt_status = save_result(&out_name, &pqf, out_path);
                        }
                        Err(e) => self.encrypt_status = OpStatus::Err(e.to_string()),
                    }
                }
                _ => {
                    self.encrypt_status =
                        OpStatus::Err("Load both files first.".to_owned());
                }
            }
        }

        show_status(ui, &self.encrypt_status);
    }

    fn show_decrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("Decrypt File");
        ui.add_space(8.0);
        file_row(ui, "Private key (.pem):", &mut self.decrypt_privkey, "PEM", &["pem"]);
        file_row(ui, "Input file (.pqf): ", &mut self.decrypt_pqf, "PQF encrypted", &["pqf"]);
        ui.add_space(8.0);

        if ui.button("Decrypt").clicked() {
            let priv_pem = self.decrypt_privkey.as_str().map(str::to_owned);
            let pqf = self.decrypt_pqf.data.clone();
            let pqf_name = self.decrypt_pqf.name.clone();
            let pqf_path = self.decrypt_pqf.path.clone();

            match (priv_pem, pqf) {
                (Some(priv_pem), Some(pqf)) => {
                    match decrypt::decrypt_bytes(&priv_pem, &pqf) {
                        Ok(plain) => {
                            let out_name = PathBuf::from(&pqf_name)
                                .file_stem()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| pqf_name.clone());
                            let out_path =
                                pqf_path.map(|p| p.with_extension(""));
                            self.decrypt_status = save_result(&out_name, &plain, out_path);
                        }
                        Err(e) => self.decrypt_status = OpStatus::Err(e.to_string()),
                    }
                }
                _ => {
                    self.decrypt_status =
                        OpStatus::Err("Load both files first.".to_owned());
                }
            }
        }

        show_status(ui, &self.decrypt_status);
    }

    fn show_inspect(&mut self, ui: &mut egui::Ui) {
        ui.heading("Inspect .pqf File");
        ui.add_space(8.0);
        file_row(ui, "Input file (.pqf):", &mut self.inspect_pqf, "PQF encrypted", &["pqf"]);
        ui.add_space(8.0);

        if ui.button("Inspect").clicked() {
            match &self.inspect_pqf.data {
                Some(data) => match format::PqfHeader::read(&mut Cursor::new(data.as_slice())) {
                    Ok(h) => {
                        let nonce: String =
                            h.nonce.iter().map(|b| format!("{b:02x}")).collect();
                        self.inspect_result = format!(
                            "Magic:              PQFL\nVersion:            {:#04x}\nKEM variant:        {}\nNonce:              {}\nOriginal file size: {} bytes",
                            format::VERSION, format::KEM_VARIANT, nonce, h.original_size
                        );
                        self.inspect_status = OpStatus::None;
                    }
                    Err(e) => {
                        self.inspect_result.clear();
                        self.inspect_status = OpStatus::Err(e.to_string());
                    }
                },
                None => {
                    self.inspect_status = OpStatus::Err("Load a file first.".to_owned());
                }
            }
        }

        if !self.inspect_result.is_empty() {
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.label(egui::RichText::new(&self.inspect_result).monospace());
            });
        }

        show_status(ui, &self.inspect_status);
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn file_row(
    ui: &mut egui::Ui,
    label: &str,
    slot: &mut FileInput,
    filter_name: &'static str,
    filter_exts: &'static [&'static str],
) {
    ui.horizontal(|ui| {
        ui.label(label);
        let display = if slot.loaded() { slot.name.as_str() } else { "(none)" };
        ui.monospace(display);
        if ui.button("Browse…").clicked() {
            pick_file(Arc::clone(&slot.pending), filter_name, filter_exts);
        }
    });
}

fn pick_file(pending: Pending, filter_name: &'static str, filter_exts: &'static [&'static str]) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        let mut d = rfd::FileDialog::new();
        if !filter_exts.is_empty() {
            d = d.add_filter(filter_name, filter_exts);
        }
        if let Some(path) = d.pick_file() {
            if let Ok(data) = std::fs::read(&path) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                *pending.lock().unwrap() = Some(PickedFile { name, data, path: Some(path) });
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        let mut d = rfd::AsyncFileDialog::new();
        if !filter_exts.is_empty() {
            d = d.add_filter(filter_name, filter_exts);
        }
        if let Some(file) = d.pick_file().await {
            let name = file.file_name();
            let data = file.read().await;
            *pending.lock().unwrap() = Some(PickedFile { name, data, path: None });
        }
    });
}

fn save_result(filename: &str, data: &[u8], native_path: Option<PathBuf>) -> OpStatus {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let path = native_path.unwrap_or_else(|| PathBuf::from(filename));
        match std::fs::write(&path, data) {
            Ok(()) => OpStatus::Ok(format!("Saved → {}", path.display())),
            Err(e) => OpStatus::Err(e.to_string()),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = native_path;
        download_bytes(filename, data);
        OpStatus::Ok(format!("Downloaded: {filename}"))
    }
}

#[cfg(target_arch = "wasm32")]
fn download_bytes(filename: &str, data: &[u8]) {
    use wasm_bindgen::JsCast;

    let arr = js_sys::Uint8Array::new_with_length(data.len() as u32);
    arr.copy_from(data);
    let parts = js_sys::Array::of1(&arr);
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts).unwrap();
    let url = web_sys::Url::create_object_url_with_blob(&blob).unwrap();

    let window = web_sys::window().unwrap();
    let document = window.document().unwrap();
    let body = document.body().unwrap();
    let a: web_sys::HtmlAnchorElement =
        document.create_element("a").unwrap().dyn_into().unwrap();
    a.set_href(&url);
    a.set_download(filename);
    body.append_child(&a).unwrap();
    a.click();
    body.remove_child(&a).unwrap();
    web_sys::Url::revoke_object_url(&url).unwrap();
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
