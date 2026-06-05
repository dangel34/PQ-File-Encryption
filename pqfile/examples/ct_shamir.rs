//! Constant-time statistical benchmark for Shamir reconstruction.
//!
//! Implements a minimal dudect-style Welch t-test to verify that the GF(256)
//! Lagrange interpolation used by `reconstruct_raw` exhibits no timing
//! difference between share sets with different secret values.
//!
//! Run with:
//!   cargo run --example ct_shamir -p pqfile
//!
//! Requires a **quiet machine** (no background load). Let it run until you have
//! more than 100 000 samples. A |t| < 4.5 at that point means no detectable
//! timing side-channel.
//!
//! No external crates needed beyond `getrandom` (already a pqfile dependency).

use std::hint::black_box;
use std::time::Instant;

fn main() {
    const SEED_LEN: usize = 64; // ML-KEM-768 seed length

    // Two fixed share-sets: class 0 uses an all-zero secret, class 1 uses 0xFF.
    // The x-coordinates (share indices) are the same for both.
    let shares_0: Vec<(u8, Vec<u8>)> =
        vec![(1, vec![0x11u8; SEED_LEN]), (2, vec![0x22u8; SEED_LEN])];
    let shares_1: Vec<(u8, Vec<u8>)> = vec![
        (1, vec![0xFFu8 ^ 0x11; SEED_LEN]),
        (2, vec![0xFFu8 ^ 0x22; SEED_LEN]),
    ];

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
        // xorshift64: fast, uniform enough for class selection.
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let class = (rng & 1) as usize;

        let shares = if class == 0 { &shares_0 } else { &shares_1 };
        let slices: Vec<(u8, &[u8])> = shares.iter().map(|(x, y)| (*x, y.as_slice())).collect();

        let t0 = Instant::now();
        let _ = black_box(lagrange_interp_gf256(&slices));
        let ns = t0.elapsed().as_nanos() as f64;

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

// ── GF(256) arithmetic (same implementation as shamir.rs) ────────────────────

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        let b_lsb_mask = (0u8).wrapping_sub(b & 1);
        result ^= a & b_lsb_mask;
        let a_msb_mask = (0u8).wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & a_msb_mask);
        b >>= 1;
    }
    result
}

fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf_inv(x: u8) -> u8 {
    let x2 = gf_mul(x, x);
    let x4 = gf_mul(x2, x2);
    let x8 = gf_mul(x4, x4);
    let x16 = gf_mul(x8, x8);
    let x32 = gf_mul(x16, x16);
    let x64 = gf_mul(x32, x32);
    let x128 = gf_mul(x64, x64);
    gf_mul(
        x128,
        gf_mul(x64, gf_mul(x32, gf_mul(x16, gf_mul(x8, gf_mul(x4, x2))))),
    )
}

fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

/// Lagrange interpolation over GF(256) at x=0 — same algorithm as `reconstruct_raw`.
fn lagrange_interp_gf256(shares: &[(u8, &[u8])]) -> Vec<u8> {
    let len = shares[0].1.len();
    let xs: Vec<u8> = shares.iter().map(|(x, _)| *x).collect();
    let mut secret = vec![0u8; len];
    for (i, s) in secret.iter_mut().enumerate() {
        let mut val = 0u8;
        for (j, &xj) in xs.iter().enumerate() {
            let yj = shares[j].1[i];
            let mut num = 1u8;
            let mut den = 1u8;
            for (k, &xk) in xs.iter().enumerate() {
                if k != j {
                    num = gf_mul(num, xk);
                    den = gf_mul(den, gf_add(xj, xk));
                }
            }
            val = gf_add(val, gf_mul(yj, gf_div(num, den)));
        }
        *s = val;
    }
    secret
}
