use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) enum Tab {
    #[default]
    Keygen,
    Encrypt,
    Decrypt,
    Inspect,
    Settings,
}

#[derive(Default)]
pub(crate) enum OpStatus {
    #[default]
    None,
    Ok(String),
    Err(String),
}

pub(crate) struct PickedFile {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) path: Option<PathBuf>,
}

pub(crate) type Pending = Arc<Mutex<Option<PickedFile>>>;

pub(crate) struct FileInput {
    pub(crate) name: String,
    pub(crate) data: Option<Vec<u8>>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) pending: Pending,
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
    pub(crate) fn poll(&mut self) {
        if let Ok(mut g) = self.pending.try_lock() {
            if let Some(f) = g.take() {
                self.name = f.name;
                self.data = Some(f.data);
                self.path = f.path;
            }
        }
    }
    pub(crate) fn loaded(&self) -> bool { self.data.is_some() }
    pub(crate) fn as_str(&self) -> Option<&str> {
        self.data.as_deref().and_then(|d| std::str::from_utf8(d).ok())
    }
    pub(crate) fn clear(&mut self) {
        self.name.clear();
        self.data = None;
        self.path = None;
    }
}

pub(crate) struct Settings {
    pub(crate) dark_mode: bool,
    pub(crate) auto_clear: bool,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) confirm_overwrite: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dark_mode: true,
            auto_clear: false,
            #[cfg(not(target_arch = "wasm32"))]
            confirm_overwrite: false,
        }
    }
}

impl Settings {
    pub(crate) fn load(storage: &dyn eframe::Storage) -> Self {
        let dark_mode = storage.get_string("dark_mode")
            .and_then(|s| s.parse().ok())
            .unwrap_or(true);
        let auto_clear = storage.get_string("auto_clear")
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);
        #[cfg(not(target_arch = "wasm32"))]
        let confirm_overwrite = storage.get_string("confirm_overwrite")
            .and_then(|s| s.parse().ok())
            .unwrap_or(false);
        Self {
            dark_mode,
            auto_clear,
            #[cfg(not(target_arch = "wasm32"))]
            confirm_overwrite,
        }
    }

    pub(crate) fn save(&self, storage: &mut dyn eframe::Storage) {
        storage.set_string("dark_mode", self.dark_mode.to_string());
        storage.set_string("auto_clear", self.auto_clear.to_string());
        #[cfg(not(target_arch = "wasm32"))]
        storage.set_string("confirm_overwrite", self.confirm_overwrite.to_string());
    }
}
