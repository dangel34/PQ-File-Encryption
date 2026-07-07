//! Constant-time statistical benchmark for the wrong-passphrase rejection path.
//!
//! Implements the same minimal dudect-style Welch t-test as `ct_shamir.rs` to
//! verify that rejecting a wrong passphrase on a v10 file takes the same time
//! whether the guess is nothing like the real passphrase (class 0) or shares a
//! long common prefix with it (class 1). A timing difference would indicate a
//! data-dependent comparison somewhere between the Argon2id derivation and the
//! chunk-0 authentication failure.
//!
//! The fixture is encrypted with the minimum Argon2id parameters (m=8 KiB, t=1,
//! p=1) so each sample costs well under a millisecond; production parameters
//! would only add class-independent KDF time on top of the same code path.
//!
//! Run with:
//!   cargo run --release --example ct_passphrase -p pqfile
//!
//! Requires a **quiet machine** (no background load). Let it run until you have
//! more than 100 000 samples. A |t| < 4.5 at that point means no detectable
//! timing side-channel.

use std::hint::black_box;
use std::time::Instant;

use pqfile::decrypt::decrypt_stream_passphrase_with_limits;
use pqfile::encrypt::encrypt_stream_passphrase_with_params;

const REAL_PASSPHRASE: &str = "correct horse battery staple 42";

fn main() {
    let plaintext = [0x5Au8; 1024];
    let mut ct = Vec::new();
    encrypt_stream_passphrase_with_params(
        REAL_PASSPHRASE,
        8, // m_kib: Argon2id minimum, to keep per-sample cost low
        1, // t_cost
        1, // p_cost
        plaintext.len() as u64,
        &mut plaintext.as_slice(),
        &mut ct,
    )
    .expect("encrypt");

    // Class 0: completely unrelated guess of the same length.
    // Class 1: matches the real passphrase except for the final character.
    let unrelated: String = "x".repeat(REAL_PASSPHRASE.len());
    let near_miss: String = {
        let mut s = REAL_PASSPHRASE.to_owned();
        s.pop();
        s.push('#');
        s
    };

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

        let guess = if class == 0 { &unrelated } else { &near_miss };

        let mut sink = Vec::with_capacity(plaintext.len());
        let t0 = Instant::now();
        let result =
            decrypt_stream_passphrase_with_limits(guess, 8, 1, &mut ct.as_slice(), &mut sink);
        let ns = t0.elapsed().as_nanos() as f64;
        assert!(
            black_box(result).is_err(),
            "wrong passphrase must not decrypt"
        );

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
