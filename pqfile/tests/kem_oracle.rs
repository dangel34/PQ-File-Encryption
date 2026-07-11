//! Cross-implementation oracle test for ML-KEM.
//!
//! pqfile's production KEM backend is the RustCrypto `ml-kem` crate. This test
//! checks it against Cryspen's formally verified `libcrux-ml-kem` (a dev-dependency
//! only - pqfile does not depend on it in any build) to prove, rather than assume,
//! that the two implementations agree on FIPS 203 byte-for-byte. It is a
//! prerequisite for ever offering `libcrux-ml-kem` as an optional production
//! backend (see docs/ROADMAP.md, "Optional formally verified ML-KEM backend").
//!
//! For each parameter set pqfile ships (512/768/1024 - the hybrid X25519+ML-KEM-768
//! variant reuses the plain 768 code path, so it needs no separate case), this:
//!
//! 1. Derives a key pair from the same 64-byte seed with both crates and checks
//!    the public keys match (proves `ML-KEM.KeyGen_internal(d, z)` agrees).
//! 2. Encapsulates deterministically with the same 32-byte `m` with both crates
//!    and checks the ciphertext and shared secret are byte-identical (proves
//!    `ML-KEM.Encaps_internal(ek, m)` agrees).
//! 3. Decapsulates each crate's ciphertext with the *other* crate's private key
//!    and checks the shared secret still matches (proves `ML-KEM.Decaps_internal`
//!    agrees, and that the two wire formats are interchangeable).

// `libcrux-ml-kem` is a non-wasm32 dev-dependency (see Cargo.toml), so this whole
// file must not be compiled for wasm32 - matches the same guard on tests/property.rs.
#![cfg(not(target_arch = "wasm32"))]

use ml_kem::{
    kem::{Decapsulate, KeyExport},
    Ciphertext, DecapsulationKey1024, DecapsulationKey512, DecapsulationKey768, MlKem1024,
    MlKem512, MlKem768, Seed, B32,
};

fn random_seed() -> [u8; 64] {
    let mut seed = [0u8; 64];
    getrandom::fill(&mut seed).expect("getrandom");
    seed
}

fn random_m() -> [u8; 32] {
    let mut m = [0u8; 32];
    getrandom::fill(&mut m).expect("getrandom");
    m
}

#[test]
fn oracle_ml_kem_512() {
    use libcrux_ml_kem::mlkem512;

    let seed = random_seed();
    let m = random_m();

    let ml_dk = DecapsulationKey512::from_seed(Seed::try_from(seed.as_slice()).unwrap());
    let ml_ek = ml_dk.encapsulation_key();
    let lc_kp = mlkem512::generate_key_pair(seed);
    assert_eq!(
        ml_ek.to_bytes().as_slice(),
        lc_kp.pk().as_slice(),
        "512: public keys derived from the same seed must match"
    );

    let (ml_ct, ml_ss) = ml_ek.encapsulate_deterministic(&B32::try_from(m.as_slice()).unwrap());
    let (lc_ct, lc_ss) = mlkem512::encapsulate(lc_kp.public_key(), m);
    assert_eq!(
        ml_ct.as_slice(),
        lc_ct.as_slice(),
        "512: ciphertexts from the same (ek, m) must match"
    );
    assert_eq!(
        ml_ss.as_slice(),
        &lc_ss,
        "512: shared secrets from the same (ek, m) must match"
    );

    let lc_ct_from_ml = mlkem512::MlKem512Ciphertext::try_from(ml_ct.as_slice()).unwrap();
    let lc_ss_cross = mlkem512::decapsulate(lc_kp.private_key(), &lc_ct_from_ml);
    assert_eq!(
        lc_ss_cross,
        ml_ss.as_slice(),
        "512: libcrux must decapsulate an ml-kem ciphertext to the same secret"
    );

    let ml_ct_from_lc = Ciphertext::<MlKem512>::try_from(lc_ct.as_ref()).unwrap();
    let ml_ss_cross = ml_dk.decapsulate(&ml_ct_from_lc);
    assert_eq!(
        ml_ss_cross.as_slice(),
        &lc_ss,
        "512: ml-kem must decapsulate a libcrux ciphertext to the same secret"
    );
}

#[test]
fn oracle_ml_kem_768() {
    use libcrux_ml_kem::mlkem768;

    let seed = random_seed();
    let m = random_m();

    let ml_dk = DecapsulationKey768::from_seed(Seed::try_from(seed.as_slice()).unwrap());
    let ml_ek = ml_dk.encapsulation_key();
    let lc_kp = mlkem768::generate_key_pair(seed);
    assert_eq!(
        ml_ek.to_bytes().as_slice(),
        lc_kp.pk().as_slice(),
        "768: public keys derived from the same seed must match"
    );

    let (ml_ct, ml_ss) = ml_ek.encapsulate_deterministic(&B32::try_from(m.as_slice()).unwrap());
    let (lc_ct, lc_ss) = mlkem768::encapsulate(lc_kp.public_key(), m);
    assert_eq!(
        ml_ct.as_slice(),
        lc_ct.as_slice(),
        "768: ciphertexts from the same (ek, m) must match"
    );
    assert_eq!(
        ml_ss.as_slice(),
        &lc_ss,
        "768: shared secrets from the same (ek, m) must match"
    );

    let lc_ct_from_ml = mlkem768::MlKem768Ciphertext::try_from(ml_ct.as_slice()).unwrap();
    let lc_ss_cross = mlkem768::decapsulate(lc_kp.private_key(), &lc_ct_from_ml);
    assert_eq!(
        lc_ss_cross,
        ml_ss.as_slice(),
        "768: libcrux must decapsulate an ml-kem ciphertext to the same secret"
    );

    let ml_ct_from_lc = Ciphertext::<MlKem768>::try_from(lc_ct.as_ref()).unwrap();
    let ml_ss_cross = ml_dk.decapsulate(&ml_ct_from_lc);
    assert_eq!(
        ml_ss_cross.as_slice(),
        &lc_ss,
        "768: ml-kem must decapsulate a libcrux ciphertext to the same secret"
    );
}

#[test]
fn oracle_ml_kem_1024() {
    use libcrux_ml_kem::mlkem1024;

    let seed = random_seed();
    let m = random_m();

    let ml_dk = DecapsulationKey1024::from_seed(Seed::try_from(seed.as_slice()).unwrap());
    let ml_ek = ml_dk.encapsulation_key();
    let lc_kp = mlkem1024::generate_key_pair(seed);
    assert_eq!(
        ml_ek.to_bytes().as_slice(),
        lc_kp.pk().as_slice(),
        "1024: public keys derived from the same seed must match"
    );

    let (ml_ct, ml_ss) = ml_ek.encapsulate_deterministic(&B32::try_from(m.as_slice()).unwrap());
    let (lc_ct, lc_ss) = mlkem1024::encapsulate(lc_kp.public_key(), m);
    assert_eq!(
        ml_ct.as_slice(),
        lc_ct.as_slice(),
        "1024: ciphertexts from the same (ek, m) must match"
    );
    assert_eq!(
        ml_ss.as_slice(),
        &lc_ss,
        "1024: shared secrets from the same (ek, m) must match"
    );

    let lc_ct_from_ml = mlkem1024::MlKem1024Ciphertext::try_from(ml_ct.as_slice()).unwrap();
    let lc_ss_cross = mlkem1024::decapsulate(lc_kp.private_key(), &lc_ct_from_ml);
    assert_eq!(
        lc_ss_cross,
        ml_ss.as_slice(),
        "1024: libcrux must decapsulate an ml-kem ciphertext to the same secret"
    );

    let ml_ct_from_lc = Ciphertext::<MlKem1024>::try_from(lc_ct.as_ref()).unwrap();
    let ml_ss_cross = ml_dk.decapsulate(&ml_ct_from_lc);
    assert_eq!(
        ml_ss_cross.as_slice(),
        &lc_ss,
        "1024: ml-kem must decapsulate a libcrux ciphertext to the same secret"
    );
}
