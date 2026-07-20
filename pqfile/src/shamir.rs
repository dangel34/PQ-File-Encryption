use std::path::Path;

use pem::Pem;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use crate::error::PqfileError;
use crate::format::{
    HYBRID_SEED_LEN_768, KEM_VARIANT_1024, KEM_VARIANT_512, KEM_VARIANT_768, KEM_VARIANT_HYBRID_768,
};
use crate::hardware;
use crate::kem_backend::{ActiveKemBackend, KemBackend, KemSize};
use crate::keygen::{
    PRIV_ENC_TAG, PRIV_ENC_TAG_1024, PRIV_ENC_TAG_512, PRIV_ENC_TAG_HYBRID_768, PRIV_TAG,
    PRIV_TAG_1024, PRIV_TAG_512, PRIV_TAG_HYBRID_768, PUB_TAG, PUB_TAG_1024, PUB_TAG_512,
    PUB_TAG_HYBRID_768,
};
use crate::passphrase;

/// PEM tag for an ML-KEM-512 Shamir key share.
pub const SHARE_TAG_512: &str = "ML-KEM-512 KEY SHARE";
/// PEM tag for an ML-KEM-768 Shamir key share.
pub const SHARE_TAG: &str = "ML-KEM-768 KEY SHARE";
/// PEM tag for an ML-KEM-1024 Shamir key share.
pub const SHARE_TAG_1024: &str = "ML-KEM-1024 KEY SHARE";
/// PEM tag for a hybrid X25519+ML-KEM-768 Shamir key share.
pub const SHARE_TAG_HYBRID_768: &str = "X25519+ML-KEM-768 KEY SHARE";

// Share body layout (version 1, introduced in pqfile v3.2.x):
//   version:     u8          = 1
//   kem_variant: u16 BE
//   threshold:   u8
//   total:       u8
//   x:           u8          (1-indexed share index)
//   pubkey_fp:   [u8; 16]    (first 16 bytes of SHA3-256 of derived public key, for verification)
//   y:           [u8; seed_len]
//
// The previous layout (pqfile v3.1.x and earlier) used pubkey_fp: [u8; 8] and
// SHARE_HEADER_LEN = 14. Shares from that version are detected and rejected with a
// clear diagnostic rather than producing incorrect results.

const SHARE_HEADER_LEN: usize = 1 + 2 + 1 + 1 + 1 + 16; // 22 bytes
const OLD_SHARE_HEADER_LEN: usize = 1 + 2 + 1 + 1 + 1 + 8; // 14 bytes (pre-v3.2.x)

// ── GF(256) arithmetic (AES irreducible polynomial: x^8+x^4+x^3+x+1 = 0x11B) ─

fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

// Constant-time GF(2^8) multiply using the AES irreducible polynomial x^8+x^4+x^3+x+1.
//
// Both conditional branches from the original loop-and-shift implementation have been
// replaced with branchless masks so the execution time does not depend on either `a`
// or `b`. The loop runs exactly 8 iterations regardless of the inputs.
//
// Correctness: the mask idiom `0u8.wrapping_sub(v & 1)` produces 0xFF when the
// low bit is 1 and 0x00 when it is 0, implementing a conditional assignment without
// a branch or variable-time load.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        // result ^= a if LSB of b is 1, else no-op - branchless via mask.
        let b_lsb_mask = (0u8).wrapping_sub(b & 1);
        result ^= a & b_lsb_mask;
        // Double a in GF(2^8): shift left and reduce by 0x1B if the MSB was set.
        let a_msb_mask = (0u8).wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1B & a_msb_mask);
        b >>= 1;
    }
    result
}

// x^{-1} = x^{254} in GF(2^8) by Fermat's little theorem.
//
// Computed via constant-time repeated squaring for the fixed exponent 254 = 0b11111110,
// eliminating the data-dependent loop exit that gf_pow(x, 254) would produce.
// All gf_mul calls are branchless, so timing depends only on the number of squarings
// (always 7), not on the value of x.
fn gf_inv(x: u8) -> u8 {
    let x2 = gf_mul(x, x);
    let x4 = gf_mul(x2, x2);
    let x8 = gf_mul(x4, x4);
    let x16 = gf_mul(x8, x8);
    let x32 = gf_mul(x16, x16);
    let x64 = gf_mul(x32, x32);
    let x128 = gf_mul(x64, x64);
    // x^254 = x^128 * x^64 * x^32 * x^16 * x^8 * x^4 * x^2
    gf_mul(
        x128,
        gf_mul(x64, gf_mul(x32, gf_mul(x16, gf_mul(x8, gf_mul(x4, x2))))),
    )
}

fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

// ── Shamir core ───────────────────────────────────────────────────────────────

/// A share's `(x, y_bytes)` pair; `y_bytes` is genuine secret material.
type RawShare = (u8, Zeroizing<Vec<u8>>);

/// Splits `secret` into `total` shares requiring `threshold` to reconstruct.
/// Returns (x, y_bytes) pairs; x values are 1..=total. Each share's y-bytes are
/// genuine secret material (any `threshold` of them reconstruct the input), so
/// they are wrapped in `Zeroizing` rather than returned as plain `Vec<u8>`.
fn split_raw(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<RawShare>, PqfileError> {
    let degree = (threshold - 1) as usize;
    let mut shares: Vec<RawShare> = (1..=total)
        .map(|x| (x, Zeroizing::new(vec![0u8; secret.len()])))
        .collect();

    // Polynomial coefficients are secret material: wrap in Zeroizing so they are
    // overwritten before the allocation is released.
    let mut coeff_buf = Zeroizing::new(vec![0u8; degree]);
    for (i, &s) in secret.iter().enumerate() {
        // Fresh random coefficients for each secret byte
        getrandom::fill(coeff_buf.as_mut()).map_err(|_| PqfileError::EncryptionFailure)?;
        for (j, (_, yvec)) in shares.iter_mut().enumerate() {
            let x = (j + 1) as u8;
            // Horner's method: P(x) = s + x*(c[0] + x*(c[1] + ... + x*c[degree-1]))
            let mut acc = coeff_buf[degree - 1];
            for k in (0..degree - 1).rev() {
                acc = gf_add(gf_mul(acc, x), coeff_buf[k]);
            }
            yvec[i] = gf_add(gf_mul(acc, x), s);
        }
    }
    Ok(shares)
}

/// Reconstructs the secret from shares via Lagrange interpolation at x=0.
///
/// `shares` is a slice of `(x, y_bytes)` pairs. `y_bytes` are borrowed to avoid
/// non-zeroizing copies of sensitive share material; callers should hold the originals
/// in `Zeroizing` wrappers so they are cleared on drop.
///
/// Timing note: the gf_mul calls inside Lagrange interpolation have timing that
/// depends only on the Lagrange coefficients (derived from the public x coordinates),
/// not on the secret y values. The y values appear only as the first argument to
/// gf_mul, whose XOR accumulation is data-independent from the loop structure.
fn reconstruct_raw(shares: &[(u8, &[u8])]) -> Result<Zeroizing<Vec<u8>>, PqfileError> {
    let len = shares[0].1.len();
    let xs: Vec<u8> = shares.iter().map(|(x, _)| *x).collect();

    // Reject shares with mismatched y-vector lengths (corrupted or mixed-key shares).
    for (i, (_, y)) in shares.iter().enumerate() {
        if y.len() != len {
            return Err(bad_arg(&format!(
                "share {} has wrong length ({} bytes, expected {})",
                i + 1,
                y.len(),
                len
            )));
        }
    }

    // Reject duplicate x values
    for i in 0..xs.len() {
        for j in i + 1..xs.len() {
            if xs[i] == xs[j] {
                return Err(bad_arg("duplicate share indices"));
            }
        }
    }

    let mut secret = Zeroizing::new(vec![0u8; len]);
    for i in 0..len {
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
            if den == 0 {
                return Err(bad_arg(
                    "degenerate Lagrange denominator (duplicate share index)",
                ));
            }
            val = gf_add(val, gf_mul(yj, gf_div(num, den)));
        }
        secret[i] = val;
    }
    Ok(secret)
}

// ── Seed / public-key utilities ───────────────────────────────────────────────

/// Decode the private key seed (plaintext bytes) from PEM, decrypting if needed.
fn extract_seed(
    privkey_pem: &str,
    passphrase: Option<&str>,
) -> Result<(u16, Zeroizing<Vec<u8>>), PqfileError> {
    let parsed = pem::parse(privkey_pem).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;

    // Hardware key stubs: load the seed from the OS credential store.
    if hardware::is_hardware_tag(parsed.tag()) {
        let seed = hardware::load_seed(parsed.contents())?;
        let variant = match parsed.tag() {
            t if t == hardware::HW_TAG_512 => KEM_VARIANT_512,
            t if t == hardware::HW_TAG_768 => KEM_VARIANT_768,
            t if t == hardware::HW_TAG_1024 => KEM_VARIANT_1024,
            t if t == hardware::HW_TAG_HYBRID_768 => KEM_VARIANT_HYBRID_768,
            tag => {
                return Err(PqfileError::InvalidPem(format!(
                    "hardware signing keys cannot be split; unexpected tag: {tag}"
                )))
            }
        };
        return Ok((variant, seed));
    }

    let (variant, seed) = match parsed.tag() {
        t @ (PRIV_TAG | PRIV_ENC_TAG) => {
            let seed = load_64byte_seed(t, parsed.contents(), passphrase)?;
            (KEM_VARIANT_768, seed)
        }
        t @ (PRIV_TAG_512 | PRIV_ENC_TAG_512) => {
            let seed = load_64byte_seed(t, parsed.contents(), passphrase)?;
            (KEM_VARIANT_512, seed)
        }
        t @ (PRIV_TAG_1024 | PRIV_ENC_TAG_1024) => {
            let seed = load_64byte_seed(t, parsed.contents(), passphrase)?;
            (KEM_VARIANT_1024, seed)
        }
        t @ (PRIV_TAG_HYBRID_768 | PRIV_ENC_TAG_HYBRID_768) => {
            let seed = if t == PRIV_ENC_TAG_HYBRID_768 {
                let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
                Zeroizing::new(passphrase::decrypt_hybrid_seed(parsed.contents(), pp)?.to_vec())
            } else {
                if parsed.contents().len() != HYBRID_SEED_LEN_768 {
                    return Err(PqfileError::InvalidKeyLength {
                        expected: HYBRID_SEED_LEN_768,
                        got: parsed.contents().len(),
                    });
                }
                Zeroizing::new(parsed.contents().to_vec())
            };
            (KEM_VARIANT_HYBRID_768, seed)
        }
        tag => {
            return Err(PqfileError::InvalidPem(format!(
                "unexpected PEM tag: {tag}"
            )))
        }
    };
    Ok((variant, seed))
}

fn load_64byte_seed(
    tag: &str,
    body: &[u8],
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, PqfileError> {
    if tag.contains("ENCRYPTED") {
        let pp = passphrase.ok_or(PqfileError::PassphraseRequired)?;
        Ok(Zeroizing::new(passphrase::decrypt_seed(body, pp)?.to_vec()))
    } else {
        if body.len() != 64 {
            return Err(PqfileError::InvalidKeyLength {
                expected: 64,
                got: body.len(),
            });
        }
        Ok(Zeroizing::new(body.to_vec()))
    }
}

/// Derive public key bytes from a private key seed and compute a 16-byte fingerprint.
fn pubkey_fp(kem_variant: u16, seed: &[u8]) -> Result<[u8; 16], PqfileError> {
    let pub_bytes = pubkey_bytes(kem_variant, seed)?;
    let hash = Sha3_256::digest(&pub_bytes);
    Ok(hash[..16]
        .try_into()
        .expect("SHA3-256 produces 32 bytes; slicing to 16 is always valid"))
}

fn pubkey_bytes(kem_variant: u16, seed: &[u8]) -> Result<Vec<u8>, PqfileError> {
    match kem_variant {
        KEM_VARIANT_512 => {
            let s: &[u8; 64] = seed.try_into().map_err(|_| bad_len(64, seed.len()))?;
            Ok(ActiveKemBackend::ek_from_seed(KemSize::Kem512, s))
        }
        KEM_VARIANT_768 => {
            let s: &[u8; 64] = seed.try_into().map_err(|_| bad_len(64, seed.len()))?;
            Ok(ActiveKemBackend::ek_from_seed(KemSize::Kem768, s))
        }
        KEM_VARIANT_1024 => {
            let s: &[u8; 64] = seed.try_into().map_err(|_| bad_len(64, seed.len()))?;
            Ok(ActiveKemBackend::ek_from_seed(KemSize::Kem1024, s))
        }
        KEM_VARIANT_HYBRID_768 => {
            if seed.len() != HYBRID_SEED_LEN_768 {
                return Err(bad_len(HYBRID_SEED_LEN_768, seed.len()));
            }
            let x25519_sk = X25519StaticSecret::from(
                <[u8; 32]>::try_from(&seed[..32])
                    .expect("seed length validated above; 32 bytes always available"),
            );
            let x25519_pk = X25519PublicKey::from(&x25519_sk);
            let ml_s: &[u8; 64] = seed[32..]
                .try_into()
                .map_err(|_| bad_len(64, seed.len() - 32))?;
            let ml_ek = ActiveKemBackend::ek_from_seed(KemSize::Kem768, ml_s);
            let mut out = Vec::new();
            out.extend_from_slice(x25519_pk.as_bytes());
            out.extend_from_slice(&ml_ek);
            Ok(out)
        }
        v => Err(PqfileError::UnsupportedKem(v)),
    }
}

/// Reconstruct the private and public key PEMs from a seed.
fn seed_to_pems(kem_variant: u16, seed: &[u8]) -> Result<(String, String), PqfileError> {
    let pub_bytes = pubkey_bytes(kem_variant, seed)?;
    let (pub_tag, priv_tag) = match kem_variant {
        KEM_VARIANT_512 => (PUB_TAG_512, PRIV_TAG_512),
        KEM_VARIANT_768 => (PUB_TAG, PRIV_TAG),
        KEM_VARIANT_1024 => (PUB_TAG_1024, PRIV_TAG_1024),
        KEM_VARIANT_HYBRID_768 => (PUB_TAG_HYBRID_768, PRIV_TAG_HYBRID_768),
        v => return Err(PqfileError::UnsupportedKem(v)),
    };
    Ok((
        pem::encode(&Pem::new(pub_tag, pub_bytes)),
        pem::encode(&Pem::new(priv_tag, seed.to_vec())),
    ))
}

// ── Share PEM encoding / decoding ─────────────────────────────────────────────

fn share_tag(kem_variant: u16) -> Result<&'static str, PqfileError> {
    match kem_variant {
        KEM_VARIANT_512 => Ok(SHARE_TAG_512),
        KEM_VARIANT_768 => Ok(SHARE_TAG),
        KEM_VARIANT_1024 => Ok(SHARE_TAG_1024),
        KEM_VARIANT_HYBRID_768 => Ok(SHARE_TAG_HYBRID_768),
        v => Err(PqfileError::UnsupportedKem(v)),
    }
}

fn encode_share_pem(
    kem_variant: u16,
    threshold: u8,
    total: u8,
    x: u8,
    fp16: &[u8; 16],
    y: &[u8],
) -> Result<String, PqfileError> {
    let tag = share_tag(kem_variant)?;
    let mut body = Vec::with_capacity(SHARE_HEADER_LEN + y.len());
    body.push(1u8);
    body.push((kem_variant >> 8) as u8);
    body.push((kem_variant & 0xFF) as u8);
    body.push(threshold);
    body.push(total);
    body.push(x);
    body.extend_from_slice(fp16);
    body.extend_from_slice(y);
    Ok(pem::encode(&Pem::new(tag, body)))
}

struct DecodedShare {
    kem_variant: u16,
    threshold: u8,
    total: u8,
    x: u8,
    pubkey_fp: [u8; 16],
    y: Zeroizing<Vec<u8>>,
}

// `Zeroizing<T>`'s `Debug` impl forwards to `T`'s, so deriving `Debug` here
// would print the raw share bytes in `y`. Redact it explicitly instead.
impl std::fmt::Debug for DecodedShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedShare")
            .field("kem_variant", &self.kem_variant)
            .field("threshold", &self.threshold)
            .field("total", &self.total)
            .field("x", &self.x)
            .field("pubkey_fp", &self.pubkey_fp)
            .field("y", &"<redacted>")
            .finish()
    }
}

fn seed_len_for_variant(kem_variant: u16) -> Option<usize> {
    match kem_variant {
        KEM_VARIANT_512 | KEM_VARIANT_768 | KEM_VARIANT_1024 => Some(64),
        KEM_VARIANT_HYBRID_768 => Some(HYBRID_SEED_LEN_768),
        _ => None,
    }
}

fn decode_share_pem(pem_str: &str) -> Result<DecodedShare, PqfileError> {
    let parsed = pem::parse(pem_str).map_err(|e| PqfileError::InvalidPem(e.to_string()))?;
    let body = parsed.contents();
    if body.len() < SHARE_HEADER_LEN + 1 {
        return Err(PqfileError::InvalidPem("share body too short".into()));
    }
    if body[0] != 1 {
        return Err(PqfileError::InvalidPem(format!(
            "unsupported share version: {}",
            body[0]
        )));
    }
    let kem_variant = u16::from_be_bytes([body[1], body[2]]);

    // Detect shares produced by pqfile v3.1.x or earlier, which used an 8-byte
    // fingerprint (OLD_SHARE_HEADER_LEN = 14) rather than the current 16-byte form.
    // Those shares cannot be decoded correctly with the new layout.
    if let Some(sl) = seed_len_for_variant(kem_variant) {
        if body.len() == OLD_SHARE_HEADER_LEN + sl {
            return Err(PqfileError::InvalidPem(
                "share was produced with pqfile v3.1.x or earlier (8-byte fingerprint). \
                 The fingerprint format changed in v3.2.x. Reconstruct the key from \
                 the original private key and split again."
                    .into(),
            ));
        }
    }

    let threshold = body[3];
    let total = body[4];
    let x = body[5];
    let pubkey_fp: [u8; 16] = body[6..22]
        .try_into()
        .expect("SHARE_HEADER_LEN = 22; length >= 23 checked above");
    let y = Zeroizing::new(body[22..].to_vec());
    Ok(DecodedShare {
        kem_variant,
        threshold,
        total,
        x,
        pubkey_fp,
        y,
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Result of splitting a private key into Shamir shares.
#[non_exhaustive]
pub struct SplitResult {
    /// PEM-encoded share files, one per share index.
    pub share_pems: Vec<String>,
    /// SHA3-256 fingerprint of the public key, colon-separated hex (matches keygen output).
    pub pubkey_fingerprint: String,
    /// Minimum number of shares required for reconstruction.
    pub threshold: u8,
    /// Total number of shares produced.
    pub total: u8,
}

/// Split a private key into `total` Shamir shares requiring `threshold` to reconstruct.
#[must_use = "split result must be saved or the shares are lost"]
pub fn split_key(
    privkey_pem: &str,
    threshold: u8,
    total: u8,
    passphrase: Option<&str>,
) -> Result<SplitResult, PqfileError> {
    if threshold < 2 {
        return Err(bad_arg("--threshold must be at least 2"));
    }
    if total < threshold {
        return Err(bad_arg("--shares must be >= --threshold"));
    }

    let (variant, seed) = extract_seed(privkey_pem, passphrase)?;
    let fp16 = pubkey_fp(variant, &seed)?;
    let fp_str = fp16
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    let raw_shares = split_raw(&seed, threshold, total)?;
    let share_pems: Result<Vec<_>, _> = raw_shares
        .iter()
        .map(|(x, y)| encode_share_pem(variant, threshold, total, *x, &fp16, y.as_slice()))
        .collect();

    Ok(SplitResult {
        share_pems: share_pems?,
        pubkey_fingerprint: fp_str,
        threshold,
        total,
    })
}

/// Reconstruct a private key (and derived public key) from M-of-N shares.
/// Returns `(privkey_pem, pubkey_pem)` - both unencrypted.
#[must_use = "reconstructed key must be saved or the key material is lost"]
pub fn reconstruct_key(share_pems: &[&str]) -> Result<(String, String), PqfileError> {
    if share_pems.is_empty() {
        return Err(bad_arg("no shares provided"));
    }

    let decoded: Vec<DecodedShare> = share_pems
        .iter()
        .map(|s| decode_share_pem(s))
        .collect::<Result<_, _>>()?;

    let variant = decoded[0].kem_variant;
    let fp = decoded[0].pubkey_fp;
    let threshold = decoded[0].threshold;

    for d in &decoded[1..] {
        if d.kem_variant != variant {
            return Err(bad_arg("shares have mismatched KEM variants"));
        }
        if d.pubkey_fp != fp {
            return Err(bad_arg(
                "shares are for different keys (fingerprint mismatch)",
            ));
        }
    }

    if (decoded.len() as u8) < threshold {
        return Err(bad_arg(&format!(
            "insufficient shares: need at least {threshold}, got {}",
            decoded.len()
        )));
    }

    // Borrow y slices directly to avoid non-zeroizing copies of sensitive share material.
    // The Zeroizing<Vec<u8>> in each DecodedShare clears the bytes on drop.
    let raw: Vec<(u8, &[u8])> = decoded.iter().map(|d| (d.x, d.y.as_slice())).collect();
    let secret = reconstruct_raw(&raw)?;

    // Verify the reconstructed seed produces the expected public key fingerprint
    let recomputed = pubkey_fp(variant, &secret)?;
    if recomputed != fp {
        return Err(PqfileError::ShareVerificationFailed);
    }

    seed_to_pems(variant, &secret)
}

/// Write share PEMs to `out_dir` as `share_1.pem` … `share_N.pem`.
pub fn write_shares(
    shares: &[String],
    out_dir: &Path,
    force: bool,
) -> Result<Vec<std::path::PathBuf>, PqfileError> {
    let mut paths = Vec::new();
    for (i, pem_str) in shares.iter().enumerate() {
        let path = out_dir.join(format!("share_{}.pem", i + 1));
        if !force && path.exists() {
            return Err(PqfileError::OutputExists(path));
        }
        crate::fsutil::write_private_file(&path, pem_str.as_bytes())?;
        paths.push(path);
    }
    Ok(paths)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn bad_arg(msg: &str) -> PqfileError {
    PqfileError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg))
}

fn bad_len(expected: usize, got: usize) -> PqfileError {
    PqfileError::InvalidKeyLength { expected, got }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::keygen_bytes;

    fn as_slices(shares: &[RawShare]) -> Vec<(u8, &[u8])> {
        shares.iter().map(|(x, y)| (*x, y.as_slice())).collect()
    }

    #[test]
    fn gf_mul_identity() {
        assert_eq!(gf_mul(0x53, 1), 0x53);
    }

    #[test]
    fn gf_mul_by_zero() {
        assert_eq!(gf_mul(0xFF, 0), 0);
    }

    #[test]
    fn gf_inv_roundtrip() {
        for x in 1u8..=255 {
            assert_eq!(gf_mul(x, gf_inv(x)), 1, "inv failed for x={x}");
        }
    }

    #[test]
    fn gf_inv_matches_brute_force_table() {
        // Independently verify gf_inv via the definition: x * x^{-1} == 1 for all x != 0.
        // Also spot-check known values from the AES S-box literature.
        assert_eq!(gf_inv(0x01), 0x01); // 1^{-1} = 1
        assert_eq!(gf_inv(0x02), 0x8d); // known AES field value
        assert_eq!(gf_inv(0x03), 0xf6);
        assert_eq!(gf_inv(0x53), gf_inv(0x53)); // reflexive
                                                // Full round-trip for all non-zero elements.
        for x in 1u8..=255 {
            let inv = gf_inv(x);
            assert_eq!(gf_mul(x, inv), 1, "x={x:#04x} inv={inv:#04x}");
            assert_eq!(gf_inv(inv), x, "double-inverse failed for x={x:#04x}");
        }
    }

    #[test]
    fn split_reconstruct_2_of_3() {
        let secret = b"this is a 64-byte test secret padded to exactly 64 bytes!!!!!!!!";
        let shares = split_raw(secret, 2, 3).unwrap();
        let recovered = reconstruct_raw(&as_slices(&shares[..2])).unwrap();
        assert_eq!(&*recovered, secret.as_ref());
    }

    #[test]
    fn split_reconstruct_3_of_5_non_consecutive() {
        let secret = [0xABu8; 64];
        let shares = split_raw(&secret, 3, 5).unwrap();
        let subset = [&shares[0], &shares[2], &shares[4]];
        let refs: Vec<(u8, &[u8])> = subset.iter().map(|(x, y)| (*x, y.as_slice())).collect();
        let recovered = reconstruct_raw(&refs).unwrap();
        assert_eq!(&*recovered, &secret);
    }

    #[test]
    fn insufficient_shares_gives_wrong_result() {
        let secret = [0x42u8; 64];
        let shares = split_raw(&secret, 3, 5).unwrap();
        // Only 2 of threshold-3 → Lagrange gives wrong answer
        let recovered = reconstruct_raw(&as_slices(&shares[..2])).unwrap();
        assert_ne!(&*recovered, &secret);
    }

    #[test]
    fn split_key_and_reconstruct_768() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        let result = split_key(&priv_pem, 2, 3, None).unwrap();
        assert_eq!(result.share_pems.len(), 3);
        let refs: Vec<&str> = result.share_pems.iter().map(|s| s.as_str()).collect();
        let (_, recovered_priv) = reconstruct_key(&refs[..2]).unwrap();
        // Fingerprint of recovered key should match original
        let result2 = split_key(&recovered_priv, 2, 2, None).unwrap();
        assert_eq!(result2.pubkey_fingerprint, result.pubkey_fingerprint);
    }

    #[test]
    fn split_key_and_reconstruct_512() {
        let (_, priv_pem) = keygen_bytes(512, None).unwrap();
        let result = split_key(&priv_pem, 2, 3, None).unwrap();
        let refs: Vec<&str> = result.share_pems.iter().map(|s| s.as_str()).collect();
        reconstruct_key(&refs).unwrap();
    }

    #[test]
    fn split_key_and_reconstruct_1024() {
        let (_, priv_pem) = keygen_bytes(1024, None).unwrap();
        let result = split_key(&priv_pem, 3, 5, None).unwrap();
        let refs: Vec<&str> = result.share_pems.iter().map(|s| s.as_str()).collect();
        reconstruct_key(&[refs[0], refs[2], refs[4]]).unwrap();
    }

    #[test]
    fn split_key_and_reconstruct_hybrid() {
        let (_, priv_pem) = crate::keygen::keygen_bytes_hybrid_768(None).unwrap();
        let result = split_key(&priv_pem, 2, 3, None).unwrap();
        assert_eq!(result.share_pems.len(), 3);
        let refs: Vec<&str> = result.share_pems.iter().map(|s| s.as_str()).collect();
        let (_, recovered_priv) = reconstruct_key(&refs[..2]).unwrap();
        let result2 = split_key(&recovered_priv, 2, 2, None).unwrap();
        assert_eq!(result2.pubkey_fingerprint, result.pubkey_fingerprint);
    }

    #[test]
    fn reconstruct_detects_insufficient_shares() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        let result = split_key(&priv_pem, 3, 5, None).unwrap();
        let refs: Vec<&str> = result.share_pems[..2].iter().map(|s| s.as_str()).collect();
        let err = reconstruct_key(&refs).unwrap_err();
        assert!(err.to_string().contains("insufficient"), "got: {err}");
    }

    #[test]
    fn reconstruct_detects_mismatched_keys() {
        let (_, priv1) = keygen_bytes(768, None).unwrap();
        let (_, priv2) = keygen_bytes(768, None).unwrap();
        let r1 = split_key(&priv1, 2, 2, None).unwrap();
        let r2 = split_key(&priv2, 2, 2, None).unwrap();
        let err =
            reconstruct_key(&[r1.share_pems[0].as_str(), r2.share_pems[1].as_str()]).unwrap_err();
        assert!(err.to_string().contains("different keys"), "got: {err}");
    }

    #[test]
    fn threshold_1_is_rejected() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        assert!(split_key(&priv_pem, 1, 3, None).is_err());
    }

    #[test]
    fn shares_less_than_threshold_is_rejected() {
        let (_, priv_pem) = keygen_bytes(768, None).unwrap();
        assert!(split_key(&priv_pem, 4, 3, None).is_err());
    }

    #[test]
    fn old_format_share_gives_clear_error() {
        // Construct a share body matching the pre-v3.2.x layout (8-byte fp, SHARE_HEADER_LEN=14).
        let mut body = Vec::new();
        body.push(1u8); // version
        body.extend_from_slice(&KEM_VARIANT_768.to_be_bytes());
        body.push(2u8); // threshold
        body.push(3u8); // total
        body.push(1u8); // x
        body.extend_from_slice(&[0xAAu8; 8]); // old 8-byte fp
        body.extend_from_slice(&[0xBBu8; 64]); // y (768 seed len)
        let pem_str = pem::encode(&pem::Pem::new(SHARE_TAG, body));
        let err = decode_share_pem(&pem_str).unwrap_err();
        assert!(
            err.to_string().contains("v3.1.x"),
            "expected old-format error, got: {err}"
        );
    }
}

// ── Statistical constant-time tests (requires --features timing-tests) ──────

/// Measures the mean and variance of `reconstruct_raw` timing for two classes
/// of secret values and asserts that the relative timing difference is < 10%.
///
/// This is a fast sanity check (< 1 second), not a rigorous statistical test.
/// For rigorous dudect analysis, run the standalone example:
///   cargo run --example ct_shamir -p pqfile
///
/// This test REQUIRES `--features timing-tests` and a reasonably quiet machine.
/// It is intentionally not run in CI.
#[cfg(feature = "timing-tests")]
#[test]
fn timing_shamir_reconstruct_basic() {
    const N: usize = 5_000;
    const SEED_LEN: usize = 64;

    let shares_0: Vec<(u8, Vec<u8>)> =
        vec![(1, vec![0x00u8; SEED_LEN]), (2, vec![0x00u8; SEED_LEN])];
    let shares_f: Vec<(u8, Vec<u8>)> =
        vec![(1, vec![0xFFu8; SEED_LEN]), (2, vec![0xFFu8; SEED_LEN])];

    fn time_batch(shares: &[(u8, Vec<u8>)], n: usize) -> u64 {
        let slices: Vec<(u8, &[u8])> = shares.iter().map(|(x, y)| (*x, y.as_slice())).collect();
        let start = std::time::Instant::now();
        for _ in 0..n {
            let _ = std::hint::black_box(reconstruct_raw(&slices));
        }
        start.elapsed().as_nanos() as u64
    }

    let t0 = time_batch(&shares_0, N);
    let tf = time_batch(&shares_f, N);

    let mean0 = t0 / N as u64;
    let meanf = tf / N as u64;
    let diff_pct = (mean0.max(meanf) - mean0.min(meanf)) as f64 / mean0.max(meanf) as f64 * 100.0;

    eprintln!("timing_shamir: mean(0x00)={mean0}ns mean(0xFF)={meanf}ns diff={diff_pct:.1}%");
    assert!(
        diff_pct < 10.0,
        "timing difference {diff_pct:.1}% exceeds 10% - possible timing side-channel; \
         run `cargo run --example ct_shamir` for rigorous dudect analysis"
    );
}
