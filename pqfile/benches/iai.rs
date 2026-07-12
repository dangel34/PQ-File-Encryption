//! Deterministic instruction-count benchmarks (Valgrind/Callgrind), gated in CI at
//! +/-5% via `RegressionConfig`. Complements the wall-clock `crypto` criterion bench,
//! which stays for human-readable local numbers. See docs/ROADMAP.md "Deterministic
//! benchmark gate" for why this crate and this split.
//!
//! Argon2id is deliberately excluded: it's a memory-hard KDF, and under Valgrind's
//! ~20x slowdown it would dominate the CI time budget for no useful signal.

use std::hint::black_box;
use std::io::Cursor;

use iai_callgrind::{
    library_benchmark, library_benchmark_group, main, Callgrind, EventKind, LibraryBenchmarkConfig,
};
use pqfile::{decrypt, encrypt, inspect, keygen, shamir, PqfHeaderInfo};

const PLAINTEXT_SIZE: usize = 65_536;

#[library_benchmark]
fn bench_keygen_768() -> (String, String) {
    black_box(keygen::keygen_bytes(768, None).unwrap())
}

fn setup_encrypt() -> (String, Vec<u8>) {
    let (pub_pem, _) = keygen::keygen_bytes(768, None).unwrap();
    (pub_pem, vec![0xABu8; PLAINTEXT_SIZE])
}

#[library_benchmark]
#[bench::sixty_four_kib(setup = setup_encrypt)]
fn bench_encrypt_bytes((pub_pem, plaintext): (String, Vec<u8>)) -> Vec<u8> {
    black_box(encrypt::encrypt_bytes(&pub_pem, &plaintext).unwrap())
}

fn setup_decrypt() -> (String, Vec<u8>) {
    let (pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();
    let plaintext = vec![0xCDu8; PLAINTEXT_SIZE];
    let ciphertext = encrypt::encrypt_bytes(&pub_pem, &plaintext).unwrap();
    (priv_pem, ciphertext)
}

#[library_benchmark]
#[bench::sixty_four_kib(setup = setup_decrypt)]
fn bench_decrypt_bytes((priv_pem, ciphertext): (String, Vec<u8>)) -> Vec<u8> {
    black_box(decrypt::decrypt_bytes(&priv_pem, &ciphertext, None).unwrap())
}

fn setup_header() -> Vec<u8> {
    let (pub_pem, _) = keygen::keygen_bytes(768, None).unwrap();
    encrypt::encrypt_bytes(&pub_pem, b"x").unwrap()
}

#[library_benchmark]
#[bench::single_recipient(setup = setup_header)]
fn bench_inspect_header(ciphertext: Vec<u8>) -> PqfHeaderInfo {
    let mut reader = Cursor::new(&ciphertext);
    black_box(inspect::inspect_stream(&mut reader).unwrap())
}

fn setup_shamir_split() -> String {
    let (_pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();
    priv_pem
}

#[library_benchmark]
#[bench::three_of_five(setup = setup_shamir_split)]
fn bench_shamir_split(priv_pem: String) -> shamir::SplitResult {
    black_box(shamir::split_key(&priv_pem, 3, 5, None).unwrap())
}

fn setup_shamir_reconstruct() -> Vec<String> {
    let (_pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();
    shamir::split_key(&priv_pem, 3, 5, None).unwrap().share_pems
}

#[library_benchmark]
#[bench::three_of_five(setup = setup_shamir_reconstruct)]
fn bench_shamir_reconstruct(shares: Vec<String>) -> (String, String) {
    let refs: Vec<&str> = shares.iter().take(3).map(String::as_str).collect();
    black_box(shamir::reconstruct_key(&refs).unwrap())
}

library_benchmark_group!(
    name = kem_group;
    benchmarks = bench_keygen_768
);

library_benchmark_group!(
    name = aead_group;
    benchmarks = bench_encrypt_bytes, bench_decrypt_bytes
);

library_benchmark_group!(
    name = header_group;
    benchmarks = bench_inspect_header
);

library_benchmark_group!(
    name = shamir_group;
    benchmarks = bench_shamir_split, bench_shamir_reconstruct
);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 5.0f64)]));
    library_benchmark_groups = kem_group, aead_group, header_group, shamir_group
);
