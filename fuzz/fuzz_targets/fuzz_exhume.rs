//! Fuzzes the stego module in two directions:
//!
//! 1. Robustness: `exhume` on arbitrary bytes must return an error, never
//!    panic - the image decode, LSB extraction, and frame parsing all run on
//!    untrusted input. This is the path where an attacker-controlled LEN
//!    field could otherwise wrap 32-bit arithmetic.
//! 2. Round-trip correctness: any payload buried in a fixed cover must
//!    exhume back byte-identical.
//!
//! Both use the `#[cfg(fuzzing)]` entry points that take the 32-byte
//! KDF-stage key directly: a real Argon2id derivation (64 MiB, t=3) per
//! exec would reduce fuzz throughput to a handful of execs per second, and
//! the KDF itself is not the parser under test.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static COVER: OnceLock<Vec<u8>> = OnceLock::new();
const KEY: [u8; 32] = [7u8; 32];

fuzz_target!(|data: &[u8]| {
    let _ = pqfile::stego::fuzz_exhume_with_fixed_key(data, &KEY);

    let cover = COVER.get_or_init(|| pqfile::stego::fuzz_make_cover(64, 64));
    let payload = &data[..data.len().min(1024)];
    let stego = pqfile::stego::fuzz_bury_with_fixed_key(cover, payload, &KEY)
        .expect("bury within capacity must succeed");
    let recovered =
        pqfile::stego::fuzz_exhume_with_fixed_key(&stego, &KEY).expect("round-trip exhume");
    assert_eq!(recovered, payload);
});
