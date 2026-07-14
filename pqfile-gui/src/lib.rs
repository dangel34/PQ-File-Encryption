mod app;
mod colors;
#[cfg(all(not(target_arch = "wasm32"), feature = "fido2"))]
mod fido2;
mod tabs;
mod theme;
mod types;
mod widgets;

pub use app::PqfileApp;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

pub(crate) const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    pub(crate) fn hide_loader();
}

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
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use crate::app::PqfileApp;
    use crate::types::{
        DecryptMode, EncryptMode, FileInput, MultiFileEntry, OpStatus, SecondFactorMode, Settings,
        Tab,
    };
    use eframe::egui;
    use std::collections::HashMap;
    use std::path::PathBuf;

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
                {
                    app.encrypt_job.is_none() && app.decrypt_batch_job.is_none()
                }
                #[cfg(target_arch = "wasm32")]
                {
                    true
                }
            };
            if done {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "background job timed out in test"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn loaded_input(name: &str, data: Vec<u8>, path: Option<PathBuf>) -> FileInput {
        FileInput {
            name: name.to_owned(),
            data: Some(data),
            path,
            pending: Default::default(),
        }
    }

    fn file_entry(name: &str, data: Vec<u8>, path: Option<PathBuf>) -> MultiFileEntry {
        MultiFileEntry {
            name: name.to_owned(),
            data,
            path,
            status: OpStatus::None,
        }
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
        app.settings.output_dir = tmp.path().to_string_lossy().into_owned();
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
        app.settings.output_dir = tmp.path().to_string_lossy().into_owned();
        app.handle_keygen();
        assert!(
            matches!(app.keygen_status, OpStatus::Ok(_)),
            "first keygen should succeed"
        );

        app.settings.confirm_overwrite = true;
        app.handle_keygen();
        assert!(
            matches!(app.keygen_status, OpStatus::Err(_)),
            "second keygen should fail when confirm_overwrite is set"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn keygen_without_confirm_overwrite_replaces_existing_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = PqfileApp::default();
        app.settings.output_dir = tmp.path().to_string_lossy().into_owned();
        app.handle_keygen();
        assert!(
            matches!(app.keygen_status, OpStatus::Ok(_)),
            "first keygen should succeed"
        );

        app.handle_keygen();
        assert!(
            matches!(app.keygen_status, OpStatus::Ok(_)),
            "second keygen should succeed when confirm_overwrite is off"
        );
    }

    #[test]
    fn encrypt_all_no_pubkey_is_noop() {
        let mut app = PqfileApp::default();
        app.encrypt_files
            .push(file_entry("test.txt", b"hello".to_vec(), None));
        app.handle_encrypt_all(&test_ctx()); // no pubkey loaded; should return early without panicking
        assert!(
            matches!(app.encrypt_files[0].status, OpStatus::None),
            "status should remain None"
        );
    }

    #[test]
    fn decrypt_missing_inputs_sets_error() {
        let mut app = PqfileApp::default();
        app.handle_decrypt_batch(&test_ctx());
        assert!(matches!(app.decrypt_status, OpStatus::Err(_)));
    }

    #[test]
    fn encrypt_bad_key_sets_error() {
        let mut app = PqfileApp::default();
        app.encrypt_pubkey = loaded_input("bad.pem", b"not a valid key".to_vec(), None);
        app.encrypt_files
            .push(file_entry("test.txt", b"hello".to_vec(), None));
        app.poll_files(); // promote staging slot to recipients list
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);
        assert!(matches!(app.encrypt_files[0].status, OpStatus::Err(_)));
    }

    #[test]
    fn decrypt_bad_key_sets_error() {
        let mut app = PqfileApp::default();
        app.decrypt_privkey = loaded_input("bad.pem", b"not a valid key".to_vec(), None);
        app.decrypt_files
            .push(file_entry("test.pqf", b"garbage".to_vec(), None));
        app.handle_decrypt_batch(&test_ctx());
        flush_jobs(&mut app);
        assert!(matches!(app.decrypt_files[0].status, OpStatus::Err(_)));
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
        app.encrypt_files
            .push(file_entry("input.txt", plaintext.clone(), Some(plain_path)));
        app.poll_files(); // promote staging slot to recipients list
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);
        assert!(
            matches!(app.encrypt_files[0].status, OpStatus::Ok(_)),
            "encryption failed"
        );

        // Decrypt
        let pqf_path = tmp.path().join("input.txt.pqf");
        let pqf_data = std::fs::read(&pqf_path).unwrap();

        app.decrypt_privkey = loaded_input("privkey.pem", priv_pem.as_bytes().to_vec(), None);
        app.decrypt_files
            .push(file_entry("input.txt.pqf", pqf_data, Some(pqf_path)));
        app.handle_decrypt_batch(&test_ctx());
        flush_jobs(&mut app);
        assert!(
            matches!(app.decrypt_files[0].status, OpStatus::Ok(_)),
            "decryption failed"
        );

        let decrypted = std::fs::read(tmp.path().join("input.txt")).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_passphrase_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let plaintext = b"v10 passphrase roundtrip".to_vec();
        let plain_path = tmp.path().join("secret.txt");
        std::fs::write(&plain_path, &plaintext).unwrap();

        let mut app = PqfileApp::default();
        app.encrypt_mode = EncryptMode::Passphrase;
        app.encrypt_passphrase = zeroize::Zeroizing::new("hunter2".to_owned());
        app.encrypt_passphrase_confirm = zeroize::Zeroizing::new("hunter2".to_owned());
        app.encrypt_files.push(file_entry(
            "secret.txt",
            plaintext.clone(),
            Some(plain_path),
        ));
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);
        assert!(
            matches!(app.encrypt_files[0].status, OpStatus::Ok(_)),
            "encryption failed: {:?}",
            app.encrypt_files[0].status
        );

        let pqf_path = tmp.path().join("secret.txt.pqf");
        let pqf_data = std::fs::read(&pqf_path).unwrap();

        app.decrypt_mode = DecryptMode::Passphrase;
        app.decrypt_v10_passphrase = zeroize::Zeroizing::new("hunter2".to_owned());
        app.decrypt_files
            .push(file_entry("secret.txt.pqf", pqf_data, Some(pqf_path)));
        app.handle_decrypt_batch(&test_ctx());
        flush_jobs(&mut app);
        assert!(
            matches!(app.decrypt_files[0].status, OpStatus::Ok(_)),
            "decryption failed: {:?}",
            app.decrypt_files[0].status
        );

        let decrypted = std::fs::read(tmp.path().join("secret.txt")).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_passphrase_keyfile_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let plaintext = b"v10 keyfile second factor roundtrip".to_vec();
        let plain_path = tmp.path().join("secret.txt");
        std::fs::write(&plain_path, &plaintext).unwrap();
        let keyfile_bytes = b"the shared keyfile".to_vec();

        let mut app = PqfileApp::default();
        app.encrypt_mode = EncryptMode::Passphrase;
        app.encrypt_passphrase = zeroize::Zeroizing::new("hunter2".to_owned());
        app.encrypt_passphrase_confirm = zeroize::Zeroizing::new("hunter2".to_owned());
        app.encrypt_second_factor = SecondFactorMode::Keyfile;
        app.encrypt_keyfile = loaded_input("keyfile.bin", keyfile_bytes.clone(), None);
        app.encrypt_files.push(file_entry(
            "secret.txt",
            plaintext.clone(),
            Some(plain_path),
        ));
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);
        assert!(
            matches!(app.encrypt_files[0].status, OpStatus::Ok(_)),
            "encryption failed: {:?}",
            app.encrypt_files[0].status
        );

        let pqf_path = tmp.path().join("secret.txt.pqf");
        let pqf_data = std::fs::read(&pqf_path).unwrap();

        // Wrong keyfile must fail.
        let mut wrong = PqfileApp::default();
        wrong.decrypt_mode = DecryptMode::Passphrase;
        wrong.decrypt_v10_passphrase = zeroize::Zeroizing::new("hunter2".to_owned());
        wrong.decrypt_second_factor = SecondFactorMode::Keyfile;
        wrong.decrypt_keyfile = loaded_input("wrong.bin", b"wrong keyfile".to_vec(), None);
        wrong
            .decrypt_files
            .push(file_entry("secret.txt.pqf", pqf_data.clone(), None));
        wrong.handle_decrypt_batch(&test_ctx());
        flush_jobs(&mut wrong);
        assert!(
            matches!(wrong.decrypt_files[0].status, OpStatus::Err(_)),
            "decryption with the wrong keyfile must fail"
        );

        // Correct keyfile must succeed.
        app.decrypt_mode = DecryptMode::Passphrase;
        app.decrypt_v10_passphrase = zeroize::Zeroizing::new("hunter2".to_owned());
        app.decrypt_second_factor = SecondFactorMode::Keyfile;
        app.decrypt_keyfile = loaded_input("keyfile.bin", keyfile_bytes, None);
        app.decrypt_files
            .push(file_entry("secret.txt.pqf", pqf_data, Some(pqf_path)));
        app.handle_decrypt_batch(&test_ctx());
        flush_jobs(&mut app);
        assert!(
            matches!(app.decrypt_files[0].status, OpStatus::Ok(_)),
            "decryption failed: {:?}",
            app.decrypt_files[0].status
        );

        let decrypted = std::fs::read(tmp.path().join("secret.txt")).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_passphrase_mismatch_returns_error() {
        let mut app = PqfileApp::default();
        app.encrypt_mode = EncryptMode::Passphrase;
        app.encrypt_passphrase = zeroize::Zeroizing::new("hunter2".to_owned());
        app.encrypt_passphrase_confirm = zeroize::Zeroizing::new("different".to_owned());
        app.encrypt_files
            .push(file_entry("secret.txt", b"data".to_vec(), None));
        app.handle_encrypt_all(&test_ctx());
        assert!(
            matches!(app.encrypt_batch_summary, Some(OpStatus::Err(_))),
            "mismatched passphrases must be rejected before any job starts"
        );
        assert!(
            matches!(app.encrypt_files[0].status, OpStatus::None),
            "no encryption should have been attempted"
        );
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
            app.encrypt_files
                .push(file_entry(name, name.as_bytes().to_vec(), Some(path)));
        }

        app.poll_files(); // promote staging slot to recipients list
        app.handle_encrypt_all(&test_ctx());
        flush_jobs(&mut app);

        for entry in &app.encrypt_files {
            assert!(
                matches!(entry.status, OpStatus::Ok(_)),
                "{} failed: {:?}",
                entry.name,
                if let OpStatus::Err(e) = &entry.status {
                    e.as_str()
                } else {
                    ""
                }
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
        fn remove_string(&mut self, key: &str) {
            self.0.remove(key);
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
        assert!(
            !s.confirm_overwrite,
            "confirm_overwrite default should be false"
        );
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
        assert!(s.dark_mode); // falls back to default true
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
            #[cfg(not(target_arch = "wasm32"))]
            output_dir: "/tmp/test_out".to_owned(),
            ..Settings::default()
        };
        original.save(&mut storage);
        let loaded = Settings::load(&storage);
        assert_eq!(loaded.dark_mode, original.dark_mode);
        assert_eq!(loaded.auto_clear, original.auto_clear);
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(loaded.confirm_overwrite, original.confirm_overwrite);
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(loaded.output_dir, original.output_dir);
    }

    // ── Drag-and-drop routing ──────────────────────────────────────────────

    #[test]
    fn drop_encrypt_tab_pem_goes_to_pubkey_slot() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Encrypt;
        app.route_drop("pubkey.pem".to_owned(), b"key-data".to_vec(), None);
        app.encrypt_pubkey.poll();
        assert!(
            app.encrypt_pubkey.loaded(),
            "pem should land in pubkey slot"
        );
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
        assert!(
            app.decrypt_privkey.loaded(),
            "pem should land in privkey slot"
        );
        assert!(app.decrypt_files.is_empty(), "file list should be empty");
    }

    #[test]
    fn drop_decrypt_tab_pqf_goes_to_file_list() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Decrypt;
        app.route_drop("secret.txt.pqf".to_owned(), b"ciphertext".to_vec(), None);
        assert_eq!(app.decrypt_files.len(), 1, "pqf should land in file list");
        assert_eq!(app.decrypt_files[0].name, "secret.txt.pqf");
        assert!(
            !app.decrypt_privkey.loaded(),
            "privkey slot should be empty"
        );
    }

    #[test]
    fn drop_inspect_tab_any_file_goes_to_doctor_slot() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Inspect;
        app.route_drop("anything.pqf".to_owned(), b"data".to_vec(), None);
        app.doctor_file.poll();
        assert!(app.doctor_file.loaded());
    }

    #[test]
    fn drop_keygen_tab_ignored() {
        let mut app = PqfileApp::default(); // default tab is Keygen
        app.route_drop("key.pem".to_owned(), b"data".to_vec(), None);
        app.encrypt_pubkey.poll();
        app.decrypt_privkey.poll();
        app.doctor_file.poll();
        assert!(!app.encrypt_pubkey.loaded());
        assert!(
            app.encrypt_files.is_empty(),
            "encrypt file list should be empty"
        );
        assert!(!app.decrypt_privkey.loaded());
        assert!(
            app.decrypt_files.is_empty(),
            "decrypt file list should be empty"
        );
        assert!(!app.doctor_file.loaded());
    }

    #[test]
    fn drop_extension_matching_is_case_insensitive() {
        let mut app = PqfileApp::default();
        app.tab = Tab::Encrypt;
        app.route_drop("PUBKEY.PEM".to_owned(), b"key-data".to_vec(), None);
        app.encrypt_pubkey.poll();
        assert!(
            app.encrypt_pubkey.loaded(),
            "uppercase .PEM should route to pubkey slot"
        );
    }

    // ── Certificates (Keys tab panel + Encrypt tab cert-as-recipient) ───────

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn cert_issue_and_verify_roundtrip_via_gui() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let (subject_pub, _) = pqfile::keygen::keygen_bytes(768, None).unwrap();

        let mut app = PqfileApp::default();
        app.settings.output_dir = tmp.path().to_string_lossy().into_owned();
        app.cert_issue_ca_key = loaded_input("ca_sk.pem", ca.sk_pem.into_bytes(), None);
        app.cert_issue_subject_key =
            loaded_input("pubkey.pem", subject_pub.clone().into_bytes(), None);
        app.cert_issue_label = "alice's laptop".to_owned();
        app.cert_issue_valid_days = 365;
        app.cert_issue_allow_encrypt = true;
        app.do_issue_cert();
        let OpStatus::Ok(_) = &app.cert_issue_status else {
            panic!("issue_cert failed: {:?}", app.cert_issue_status);
        };

        let cert_path = app.cert_issue_output_path.clone().expect("output path set");
        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();

        let cert =
            pqfile::cert::verify_cert(&ca.vk_pem, &cert_pem, crate::types::current_unix_secs())
                .unwrap();
        assert_eq!(cert.label, "alice's laptop");
        assert!(cert.permits(pqfile::cert::cert_use::ENCRYPT));
        assert!(!cert.permits(pqfile::cert::cert_use::SIGN));
        assert_eq!(cert.subject_pem, subject_pub);
    }

    #[test]
    fn cert_verify_via_gui_accepts_valid_certificate() {
        let ca = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let (subject_pub, _) = pqfile::keygen::keygen_bytes(768, None).unwrap();
        let now = crate::types::current_unix_secs();
        let cert_pem = pqfile::cert::issue_cert(
            &ca.sk_pem,
            None,
            &subject_pub,
            "alice's laptop",
            now,
            now + 86_400,
            pqfile::cert::cert_use::ENCRYPT,
        )
        .unwrap();

        let mut app = PqfileApp::default();
        app.cert_verify_ca_vk = loaded_input("ca_vk.pem", ca.vk_pem.into_bytes(), None);
        app.cert_verify_cert = loaded_input("subject.cert", cert_pem.into_bytes(), None);
        app.do_verify_cert();

        assert!(matches!(app.cert_verify_status, OpStatus::Ok(_)));
        let result = app.cert_verify_result.expect("verify result populated");
        assert_eq!(result.label, "alice's laptop");
        assert!(result.permits(pqfile::cert::cert_use::ENCRYPT));
    }

    #[test]
    fn cert_verify_via_gui_rejects_wrong_ca_key() {
        let ca = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let other_ca = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let (subject_pub, _) = pqfile::keygen::keygen_bytes(768, None).unwrap();
        let now = crate::types::current_unix_secs();
        let cert_pem = pqfile::cert::issue_cert(
            &ca.sk_pem,
            None,
            &subject_pub,
            "x",
            now,
            now + 86_400,
            pqfile::cert::cert_use::ENCRYPT,
        )
        .unwrap();

        let mut app = PqfileApp::default();
        app.cert_verify_ca_vk = loaded_input("ca_vk.pem", other_ca.vk_pem.into_bytes(), None);
        app.cert_verify_cert = loaded_input("subject.cert", cert_pem.into_bytes(), None);
        app.do_verify_cert();

        assert!(matches!(app.cert_verify_status, OpStatus::Err(_)));
        assert!(app.cert_verify_result.is_none());
    }

    #[test]
    fn encrypt_promotes_certificate_recipient_when_ca_key_loaded() {
        let ca = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let (subject_pub, _) = pqfile::keygen::keygen_bytes(768, None).unwrap();
        let now = crate::types::current_unix_secs();
        let cert_pem = pqfile::cert::issue_cert(
            &ca.sk_pem,
            None,
            &subject_pub,
            "test recipient",
            now,
            now + 86_400,
            pqfile::cert::cert_use::ENCRYPT,
        )
        .unwrap();

        let mut app = PqfileApp::default();
        app.encrypt_ca_key = loaded_input("ca_vk.pem", ca.vk_pem.into_bytes(), None);
        app.encrypt_pubkey = loaded_input("recipient.cert", cert_pem.into_bytes(), None);
        app.poll_files();

        assert!(matches!(app.encrypt_recipient_error, OpStatus::None));
        assert_eq!(app.encrypt_recipients.len(), 1);
        assert_eq!(app.encrypt_recipients[0].pem, subject_pub);
        assert!(app.encrypt_recipients[0].name.contains("test recipient"));
    }

    #[test]
    fn encrypt_certificate_recipient_without_ca_key_sets_error() {
        let ca = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let (subject_pub, _) = pqfile::keygen::keygen_bytes(768, None).unwrap();
        let now = crate::types::current_unix_secs();
        let cert_pem = pqfile::cert::issue_cert(
            &ca.sk_pem,
            None,
            &subject_pub,
            "test recipient",
            now,
            now + 86_400,
            pqfile::cert::cert_use::ENCRYPT,
        )
        .unwrap();

        let mut app = PqfileApp::default();
        app.encrypt_pubkey = loaded_input("recipient.cert", cert_pem.into_bytes(), None);
        app.poll_files();

        assert!(matches!(app.encrypt_recipient_error, OpStatus::Err(_)));
        assert!(app.encrypt_recipients.is_empty());
    }

    #[test]
    fn encrypt_certificate_recipient_wrong_use_sets_error() {
        let ca = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let subject_signer = pqfile::sign::sign_keygen_bytes(None).unwrap();
        let now = crate::types::current_unix_secs();
        // Certified for SIGN only, then presented as an Encrypt recipient.
        let cert_pem = pqfile::cert::issue_cert(
            &ca.sk_pem,
            None,
            &subject_signer.vk_pem,
            "sign-only cert",
            now,
            now + 86_400,
            pqfile::cert::cert_use::SIGN,
        )
        .unwrap();

        let mut app = PqfileApp::default();
        app.encrypt_ca_key = loaded_input("ca_vk.pem", ca.vk_pem.into_bytes(), None);
        app.encrypt_pubkey = loaded_input("recipient.cert", cert_pem.into_bytes(), None);
        app.poll_files();

        assert!(matches!(app.encrypt_recipient_error, OpStatus::Err(_)));
        assert!(app.encrypt_recipients.is_empty());
    }
}
