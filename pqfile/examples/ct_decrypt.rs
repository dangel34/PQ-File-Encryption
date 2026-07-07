//! Constant-time statistical benchmark for the decryption error path.
//!
//! Implements the same minimal dudect-style Welch t-test as `ct_shamir.rs` to
//! verify that rejecting a tampered ciphertext takes the same time regardless
//! of *where* the corruption sits: class 0 flips the first byte of the chunk-0
//! Poly1305 tag, class 1 flips the last byte. A timing difference would
//! indicate a non-constant-time tag comparison somewhere in the reject path.
//!
//! Run with:
//!   cargo run --release --example ct_decrypt -p pqfile
//!
//! Requires a **quiet machine** (no background load). Let it run until you have
//! more than 100 000 samples. A |t| < 4.5 at that point means no detectable
//! timing side-channel. Each sample includes a full ML-KEM-768 decapsulation,
//! which is identical across classes and only adds class-independent noise.

use std::hint::black_box;
use std::time::Instant;

use pqfile::decrypt::decrypt_stream;
use pqfile::encrypt::encrypt_stream;
use pqfile::format::CHUNK_SIZE;
use pqfile::keygen::keygen_bytes;

fn main() {
    let (pub_pem, priv_pem) = keygen_bytes(768, None).expect("keygen");
    let plaintext = [0xA5u8; 1024];
    let mut ct = Vec::new();
    encrypt_stream(
        &pub_pem,
        plaintext.len() as u64,
        CHUNK_SIZE,
        &mut plaintext.as_slice(),
        &mut ct,
    )
    .expect("encrypt");

    // The single chunk's 16-byte tag is the last 16 bytes of the file.
    let tag_start = ct.len() - 16;
    let mut tampered_first = ct.clone();
    tampered_first[tag_start] ^= 0x01;
    let mut tampered_last = ct;
    tampered_last[tag_start + 15] ^= 0x01;

    // Online Welch t-test accumulators (two classes).
    let mut n = [0u64; 2];
    let mut sum = [0f64; 2];
    let mut sum_sq = [0f64; 2];

    // Seed a simple xorshift64 from the OS CSPRNG.
    let mut rng: u64 = {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    };

    let mut total: u64 = 0;

    loop {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let class = (rng & 1) as usize;

        let input = if class == 0 {
            &tampered_first
        } else {
            &tampered_last
        };

        let mut sink = Vec::with_capacity(plaintext.len());
        let t0 = Instant::now();
        let result = decrypt_stream(&priv_pem, &mut input.as_slice(), &mut sink, None);
        let ns = t0.elapsed().as_nanos() as f64;
        assert!(black_box(result).is_err(), "tampered file must not decrypt");

        n[class] += 1;
        sum[class] += ns;
        sum_sq[class] += ns * ns;
        total += 1;

        if total.is_multiple_of(10_000) && n[0] > 1 && n[1] > 1 {
            let m0 = sum[0] / n[0] as f64;
            let m1 = sum[1] / n[1] as f64;
            let v0 = (sum_sq[0] / n[0] as f64) - m0 * m0;
            let v1 = (sum_sq[1] / n[1] as f64) - m1 * m1;
            let se = (v0 / n[0] as f64 + v1 / n[1] as f64).sqrt();
            let t = if se > 0.0 { (m0 - m1) / se } else { 0.0 };
            let verdict = if t.abs() < 4.5 { "PASS" } else { "FAIL" };
            println!(
                "n={total:>9}  |t|={:.3}  m0={m0:.1}ns  m1={m1:.1}ns  {verdict}",
                t.abs()
            );
        }
    }
}
