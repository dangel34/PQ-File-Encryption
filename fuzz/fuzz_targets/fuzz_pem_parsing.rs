#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Exercise PEM parsing + fingerprinting — both paths must not panic.
        let _ = pqfile::keygen::fingerprint_pem(s);
        let _ = pqfile::keygen::is_encrypted_key(s);
    }
});
