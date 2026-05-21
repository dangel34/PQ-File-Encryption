mod app;
mod colors;
mod tabs;
mod theme;
mod types;
mod widgets;

pub use app::PqfileApp;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

pub(crate) const APP_VERSION: &str = "3.2.0";

// ── WASM entry ────────────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    use wasm_bindgen::JsCast as _;

    // Route Rust panics to the browser console for easier debugging.
    console_error_panic_hook::set_once();

    let canvas = web_sys::window()
        .ok_or_else(|| JsValue::from_str("no window"))?
        .document()
        .ok_or_else(|| JsValue::from_str("no document"))?
        .get_element_by_id("pqfile_canvas")
        .ok_or_else(|| JsValue::from_str("canvas element not found"))?
        .dyn_into::<web_sys::HtmlCanvasElement>()?;
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(|cc| Ok(Box::new(PqfileApp::new(cc)))),
            )
            .await
        {
            web_sys::console::error_1(&e);
        }
    });
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::app::PqfileApp;
    use crate::types::{FileInput, MultiFileEntry, OpStatus, Settings, Tab};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use eframe::egui;

    fn test_ctx() -> egui::Context {
        egui::Context::default()
    }

    /// Spin-wait until all background encrypt/decrypt jobs have completed and
    /// their results have been drained back into app state.
    fn flush_jobs(app: &mut PqfileApp) {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            app.poll_files();
            let done = {
                #[cfg(not(target_arch = "wasm32"))]
                { app.encrypt_job.is_none() && app.decrypt_job.is_none() }
                #[cfg(target_arch = "wasm32")]
                { true }
            };
            if done { break; }
            assert!(Instant::now() < deadline, "background job timed out in test");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn loaded_input(name: &str, data: Vec<u8>, path: Option<PathBuf>) -> FileInput {
        FileInput { name: name.to_owned(), data: Some(data), path, pending: Default::default() }
    }

    fn file_entry(name: &str, data: Vec<u8>, path: Option<PathBuf>) -> MultiFileEntry {
        MultiFileEntry { name: name.to_owned(), data, path, status: OpStatus::None }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn keygen_empty_dir_sets_error() {
        let mut app = PqfileApp::default();
        app.handle_keygen();
        assert!(matches!(app.keygen_status, OpStatus::Err(_)));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn keygen_valid_dir_saves_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = PqfileApp::default();
        app.keygen_dir = tmp.path().to_string_lossy().into_owned();
        app.handle_keygen();
        assert!(matches!(app.keygen_status, OpStatus::Ok(_)));
        assert!(tmp.path().join("pubkey.pem").exists());
        assert!(tmp.path().join("privkey.pem").exists());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn keygen_confirm_overwrite_blocks_existing_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = PqfileApp::default();
        app.keygen_dir = tmp.path().to_string_lossy().into_owned();
        app.handle_keygen();
        assert!(matches!(app.keygen_status, OpStatus::Ok(_)), "first keygen should succeed");

        app.settings.confirm_overwrite = true;
        app.handle_keygen();
        assert!(matches!(app.keygen_status, OpStatus::Err(_)), "second keygen should fail when confirm_overwrite is set");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn keygen_without_confirm_overwrite_replaces_existing_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = PqfileApp::default();
        app.keygen_dir = tmp.path().to_string_lossy().into_owned();
        app.handle_keygen();
        assert!(matches!(app.keygen_status, OpStatus::Ok(_)), "first keygen should succeed");

        app.handle_keygen();
        assert!(matches!(app.keygen_status, OpStatus::Ok(_)), "second keygen should succeed when confirm_overwrite is off");
    }

    #[test]
    fn encrypt_all_no_pubkey_is_noop() {
        let mut app = PqfileApp::default();
        app.encrypt_files.push(file_entry("test.txt", b"hello".to_vec(), None));
        app.handle_encrypt_all(&test_ctx()); // no pubkey loaded — should return early without panicking
        assert!(matches!(app.encrypt_files[0].status, OpStatus::None), "status should remain None");
    }

    #[test]
    fn decrypt_missing_inputs_sets_error() {
        let mut app = PqfileApp::default();
        app.handle_decrypt(&test_ctx());
        assert!(matches!(app.decrypt_status, OpStatus::Err(_)));
    }

    #[test]
    fn encrypt_bad_key_sets_error() {
        let mut app = PqfileApp::default();
        app.encrypt_pubkey = loaded_input("bad.pem", b"not a valid key".to_vec(), None);
        app.encrypt_files.push(file_entry("test.txt", b"hello".to_vec(), None));
        app.poll_files(); // promote staging slot to recipients list
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);
        assert!(matches!(app.encrypt_files[0].status, OpStatus::Err(_)));
    }

    #[test]
    fn decrypt_bad_key_sets_error() {
        let mut app = PqfileApp::default();
        app.decrypt_privkey = loaded_input("bad.pem", b"not a valid key".to_vec(), None);
        app.decrypt_pqf = loaded_input("test.pqf", b"garbage".to_vec(), None);
        app.handle_decrypt(&test_ctx());
        flush_jobs(&mut app);
        assert!(matches!(app.decrypt_status, OpStatus::Err(_)));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let (pub_pem, priv_pem) = pqfile::keygen::keygen_bytes(768, None).unwrap();
        let plaintext = b"roundtrip test data".to_vec();

        // Encrypt
        let plain_path = tmp.path().join("input.txt");
        std::fs::write(&plain_path, &plaintext).unwrap();

        let mut app = PqfileApp::default();
        app.encrypt_pubkey = loaded_input("pubkey.pem", pub_pem.as_bytes().to_vec(), None);
        app.encrypt_files.push(file_entry("input.txt", plaintext.clone(), Some(plain_path)));
        app.poll_files(); // promote staging slot to recipients list
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);
        assert!(matches!(app.encrypt_files[0].status, OpStatus::Ok(_)), "encryption failed");

        // Decrypt
        let pqf_path = tmp.path().join("input.txt.pqf");
        let pqf_data = std::fs::read(&pqf_path).unwrap();

        app.decrypt_privkey = loaded_input("privkey.pem", priv_pem.as_bytes().to_vec(), None);
        app.decrypt_pqf = loaded_input("input.txt.pqf", pqf_data, Some(pqf_path));
        app.handle_decrypt(&test_ctx());
        flush_jobs(&mut app);
        assert!(matches!(app.decrypt_status, OpStatus::Ok(_)), "decryption failed");

        let decrypted = std::fs::read(tmp.path().join("input.txt")).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_all_multi_file_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let (pub_pem, _) = pqfile::keygen::keygen_bytes(768, None).unwrap();

        let mut app = PqfileApp::default();
        app.encrypt_pubkey = loaded_input("pubkey.pem", pub_pem.as_bytes().to_vec(), None);

        for name in ["a.txt", "b.txt", "c.txt"] {
            let path = tmp.path().join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            app.encrypt_files.push(file_entry(name, name.as_bytes().to_vec(), Some(path)));
        }

        app.poll_files(); // promote staging slot to recipients list
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);

        for entry in &app.encrypt_files {
            assert!(
                matches!(entry.status, OpStatus::Ok(_)),
                "{} failed: {:?}", entry.name,
                if let OpStatus::Err(e) = &entry.status { e.as_str() } else { "" }
            );
            assert!(tmp.path().join(format!("{}.pqf", entry.name)).exists());
        }
    }

    // ── Settings persistence ───────────────────────────────────────────────

    struct MockStorage(HashMap<String, String>);

    impl eframe::Storage for MockStorage {
        fn get_string(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn set_string(&mut self, key: &str, value: String) {
            self.0.insert(key.to_owned(), value);
        }
        fn flush(&mut self) {}
    }

    #[test]
    fn settings_load_returns_defaults_when_storage_empty() {
        let storage = MockStorage(HashMap::new());
        let s = Settings::load(&storage);
        assert!(s.dark_mode, "dark_mode default should be true");
        assert!(!s.auto_clear, "auto_clear default should be false");
        #[cfg(not(target_arch = "wasm32"))]
        assert!(!s.confirm_overwrite, "confirm_overwrite default should be false");
    }

    #[test]
    fn settings_load_reads_stored_values() {
        let mut map = HashMap::new();
        map.insert("dark_mode".to_owned(), "false".to_owned());
        map.insert("auto_clear".to_owned(), "true".to_owned());
        #[cfg(not(target_arch = "wasm32"))]
        map.insert("confirm_overwrite".to_owned(), "true".to_owned());
        let storage = MockStorage(map);
        let s = Settings::load(&storage);
        assert!(!s.dark_mode);
        assert!(s.auto_clear);
        #[cfg(not(target_arch = "wasm32"))]
        assert!(s.confirm_overwrite);
    }

    #[test]
    fn settings_load_ignores_invalid_values_and_uses_defaults() {
        let mut map = HashMap::new();
        map.insert("dark_mode".to_owned(), "not_a_bool".to_owned());
        map.insert("auto_clear".to_owned(), "1".to_owned()); // not valid bool::from_str
        let storage = MockStorage(map);
        let s = Settings::load(&storage);
        assert!(s.dark_mode);   // falls back to default true
        assert!(!s.auto_clear); // falls back to default false
    }

    #[test]
    fn settings_save_then_load_roundtrip() {
        let mut storage = MockStorage(HashMap::new());
        let original = Settings {
            dark_mode: false,
            auto_clear: true,
            #[cfg(not(target_arch = "wasm32"))]
            confirm_overwrite: true,
        };
        original.save(&mut storage);
        let loaded = Settings::load(&storage);
        assert_eq!(loaded.dark_mode, original.dark_mode);
        assert_eq!(loaded.auto_clear, original.auto_clear);
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(loaded.confirm_overwrite, original.confirm_overwrite);
    }

    // ── Drag-and-drop routing ──────────────────────────────────────────────

    #[test]
    fn drop_encrypt_tab_pem_goes_to_pubkey_slot() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Encrypt;
        app.route_drop("pubkey.pem".to_owned(), b"key-data".to_vec(), None);
        app.encrypt_pubkey.poll();
        assert!(app.encrypt_pubkey.loaded(), "pem should land in pubkey slot");
        assert!(app.encrypt_files.is_empty(), "file list should be empty");
    }

    #[test]
    fn drop_encrypt_tab_non_pem_goes_to_file_list() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Encrypt;
        app.route_drop("secret.txt".to_owned(), b"hello world".to_vec(), None);
        assert_eq!(app.encrypt_files.len(), 1, "txt should land in file list");
        assert_eq!(app.encrypt_files[0].name, "secret.txt");
        assert!(!app.encrypt_pubkey.loaded(), "pubkey slot should be empty");
    }

    #[test]
    fn drop_encrypt_tab_multiple_files_accumulate() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Encrypt;
        app.route_drop("a.txt".to_owned(), b"aaa".to_vec(), None);
        app.route_drop("b.txt".to_owned(), b"bbb".to_vec(), None);
        assert_eq!(app.encrypt_files.len(), 2);
    }

    #[test]
    fn drop_decrypt_tab_pem_goes_to_privkey_slot() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Decrypt;
        app.route_drop("privkey.pem".to_owned(), b"key-data".to_vec(), None);
        app.decrypt_privkey.poll();
        assert!(app.decrypt_privkey.loaded(), "pem should land in privkey slot");
        assert!(!app.decrypt_pqf.loaded(), "pqf slot should be empty");
    }

    #[test]
    fn drop_decrypt_tab_pqf_goes_to_pqf_slot() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Decrypt;
        app.route_drop("secret.txt.pqf".to_owned(), b"ciphertext".to_vec(), None);
        app.decrypt_pqf.poll();
        assert!(app.decrypt_pqf.loaded(), "pqf should land in pqf slot");
        assert!(!app.decrypt_privkey.loaded(), "privkey slot should be empty");
    }

    #[test]
    fn drop_inspect_tab_any_file_goes_to_inspect_slot() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Inspect;
        app.route_drop("anything.pqf".to_owned(), b"data".to_vec(), None);
        app.inspect_pqf.poll();
        assert!(app.inspect_pqf.loaded());
    }

    #[test]
    fn drop_keygen_tab_ignored() {
        let mut app = PqfileApp::default(); // default tab is Keygen
        app.route_drop("key.pem".to_owned(), b"data".to_vec(), None);
        app.encrypt_pubkey.poll();
        app.decrypt_privkey.poll();
        app.decrypt_pqf.poll();
        app.inspect_pqf.poll();
        assert!(!app.encrypt_pubkey.loaded());
        assert!(app.encrypt_files.is_empty(), "file list should be empty");
        assert!(!app.decrypt_privkey.loaded());
        assert!(!app.decrypt_pqf.loaded());
        assert!(!app.inspect_pqf.loaded());
    }

    #[test]
    fn drop_extension_matching_is_case_insensitive() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Encrypt;
        app.route_drop("PUBKEY.PEM".to_owned(), b"key-data".to_vec(), None);
        app.encrypt_pubkey.poll();
        assert!(app.encrypt_pubkey.loaded(), "uppercase .PEM should route to pubkey slot");
    }
}
