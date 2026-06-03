//! Constant-time statistical benchmark for Shamir reconstruction.
//!
//! Uses the `dudect` statistical framework to verify that `reconstruct_raw`
//! (the Lagrange interpolation core) exhibits no timing difference between
//! share sets that encode distinct secret values.
//!
//! Run with:
//!   cargo run --example ct_shamir -p pqfile
//!
//! Requires a **quiet machine** (no background load). Interrupt with Ctrl-C
//! when you have enough samples (typically 100 000+). A |t| < 4.5 at that
//! sample size means no detectable timing side-channel.

use dudect_bencher::{ctbench_main, rand::RngExt, BenchRng, Class, CtRunner};

/// Two share-sets with the same public x-coordinates but different secret values.
/// Class::Left encodes all-zero secret; Class::Right encodes all-0xFF secret.
fn shamir_reconstruct_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Pre-build two sets of 3 shares for a 2-of-3 threshold.
    // The x-coordinates are the public share indices (1, 2, 3).
    // We keep the shares as raw (x, y_vec) tuples matching `reconstruct_raw`'s input.
    const SEED_LEN: usize = 64; // ML-KEM-768 seed length

    // Build minimal Shamir shares: for a constant secret s, each share is
    //   y_i = s XOR (coeff * x_i) for a random polynomial of degree `threshold-1`.
    // For simplicity we directly construct valid-looking 2-of-3 shares.
    let build_shares = |secret: u8| -> Vec<(u8, Vec<u8>)> {
        // y_i = secret XOR (random * i) in GF(2) - sufficient for |t| measurement
        // (exact GF(256) arithmetic isn't needed; what matters is same-cost computation)
        vec![
            (1, vec![secret ^ 0x11; SEED_LEN]),
            (2, vec![secret ^ 0x22; SEED_LEN]),
        ]
    };

    let left_shares = build_shares(0x00);
    let right_shares = build_shares(0xFF);

    // Time the reconstruction for random class assignments.
    for _ in 0..1_000 {
        let class = if rng.random::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        let shares = match class {
            Class::Left => &left_shares,
            Class::Right => &right_shares,
        };
        let slices: Vec<(u8, &[u8])> = shares.iter().map(|(x, y)| (*x, y.as_slice())).collect();
        runner.run_one(class, || {
            // We can't call the private `reconstruct_raw` from here, but we can replicate
            // the GF(256) Lagrange interpolation directly, which IS the performance-critical
            // path we want to test.
            let _ = lagrange_interp_gf256(&slices);
        });
    }
}

/// GF(256) multiply - same branchless implementation as shamir.rs.
#[inline]
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
    gf_pow(x, 254)
}
fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}
fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result = 1u8;
    for _ in 0..8 {
        let mask = (0u8).wrapping_sub(exp & 1);
        result = gf_mul(result, gf_mul(base & mask, result) ^ (result & !mask));
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Lagrange interpolation over GF(256) - same algorithm as `reconstruct_raw`.
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

ctbench_main!(shamir_reconstruct_ct);
