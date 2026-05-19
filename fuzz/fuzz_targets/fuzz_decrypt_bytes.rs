#![no_main]
use libfuzzer_sys::fuzz_target;

// A real key pair generated once and reused across all fuzz inputs so the
// cost is key derivation (cheap) + attempted decapsulation/decryption
// (fast-fail on bad data) rather than fresh keygen per input.
static KEYS: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let (_, priv_pem) = KEYS.get_or_init(|| {
        pqfile::keygen::keygen_bytes(None).expect("keygen failed in fuzz setup")
    });
    // Any error is expected (DecryptionFailure, InvalidMagic, etc.).
    // A panic would be caught by the fuzzer as a crash.
    let _ = pqfile::decrypt::decrypt_bytes(priv_pem, data, None);
});
