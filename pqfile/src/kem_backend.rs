//! Backend-agnostic ML-KEM operations.
//!
//! Every KEM call site in `encrypt.rs`, `decrypt.rs`, `keygen.rs`, `keys.rs`, and
//! `shamir.rs` goes through [`KemBackend`] instead of constructing `ml-kem`'s typed
//! keys directly, so the backend can be swapped without touching those call sites.
//! `MlKemBackend` (the RustCrypto `ml-kem` crate) is always compiled in and is the
//! default. `LibcruxBackend` (Cryspen's F*-verified `libcrux-ml-kem`) is available
//! behind the opt-in `kem-libcrux` feature. `pqfile/tests/kem_oracle.rs` proves the
//! two agree byte-for-byte on FIPS 203, so switching backends never changes wire
//! bytes. See docs/ROADMAP.md, "Optional formally verified ML-KEM backend".

use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) enum KemSize {
    Kem512,
    Kem768,
    Kem1024,
}

/// Backend-agnostic ML-KEM operations. All methods take/return raw bytes so no
/// backend-specific typed key ever crosses this boundary.
pub(crate) trait KemBackend {
    /// Derives raw EK bytes from a 64-byte seed. Infallible given a valid-length seed.
    fn ek_from_seed(size: KemSize, seed: &[u8; 64]) -> Vec<u8>;

    /// Parses a raw EK and encapsulates with fresh randomness. `Err(())` only on
    /// backend-side key rejection (e.g. ml-kem's modulus-range check); the call
    /// site maps this to its existing `PqfileError` variant.
    fn encapsulate(size: KemSize, ek_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), ()>;

    /// Decapsulates. Infallible given an already length-checked ciphertext (matches
    /// today's behavior: decapsulation never fails once the ciphertext parses).
    fn decapsulate(size: KemSize, seed: &[u8; 64], ct_bytes: &[u8]) -> Zeroizing<[u8; 32]>;
}

#[cfg(not(feature = "kem-libcrux"))]
pub(crate) type ActiveKemBackend = ml_backend::MlKemBackend;
#[cfg(feature = "kem-libcrux")]
pub(crate) type ActiveKemBackend = libcrux_backend::LibcruxBackend;

/// FIPS 203 §7.2 "Encapsulation Key Check": rejects a public key whose byte
/// encoding decodes to out-of-range polynomial coefficients. `ml-kem`'s typed
/// constructors already perform this; libcrux's raw `TryFrom<&[u8]>` is a
/// length-only check, so [`libcrux_backend::LibcruxBackend::encapsulate`] calls
/// this first to close the gap - reusing `ml-kem`'s already-audited validation
/// rather than re-implementing the coefficient bit-unpacking here. `ml-kem` is
/// always a dependency regardless of the `kem-libcrux` feature, so this
/// compiles and runs unconditionally, keeping both backends equally strict.
#[cfg_attr(not(feature = "kem-libcrux"), allow(dead_code))]
fn validate_ek(size: KemSize, ek_bytes: &[u8]) -> Result<(), ()> {
    use ml_kem::array::Array;
    use ml_kem::{EncapsulationKey1024, EncapsulationKey512, EncapsulationKey768};

    match size {
        KemSize::Kem512 => {
            let arr = Array::try_from(ek_bytes).map_err(|_| ())?;
            EncapsulationKey512::new(&arr).map(|_| ()).map_err(|_| ())
        }
        KemSize::Kem768 => {
            let arr = Array::try_from(ek_bytes).map_err(|_| ())?;
            EncapsulationKey768::new(&arr).map(|_| ()).map_err(|_| ())
        }
        KemSize::Kem1024 => {
            let arr = Array::try_from(ek_bytes).map_err(|_| ())?;
            EncapsulationKey1024::new(&arr).map(|_| ()).map_err(|_| ())
        }
    }
}

#[cfg(not(feature = "kem-libcrux"))]
pub(crate) mod ml_backend {
    use ml_kem::{
        array::Array,
        kem::{Decapsulate, Encapsulate},
        Ciphertext, DecapsulationKey1024, DecapsulationKey512, DecapsulationKey768,
        EncapsulationKey1024, EncapsulationKey512, EncapsulationKey768, KeyExport, MlKem1024,
        MlKem512, MlKem768, Seed,
    };
    use zeroize::Zeroizing;

    use super::{KemBackend, KemSize};

    fn seed_of(seed: &[u8; 64]) -> Seed {
        Seed::try_from(seed.as_slice()).expect("64-byte array always converts to Seed")
    }

    fn shared_key_bytes(ss: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(ss);
        out
    }

    pub(crate) struct MlKemBackend;

    impl KemBackend for MlKemBackend {
        fn ek_from_seed(size: KemSize, seed: &[u8; 64]) -> Vec<u8> {
            let seed = seed_of(seed);
            match size {
                KemSize::Kem512 => DecapsulationKey512::from_seed(seed)
                    .encapsulation_key()
                    .to_bytes()
                    .as_slice()
                    .to_vec(),
                KemSize::Kem768 => DecapsulationKey768::from_seed(seed)
                    .encapsulation_key()
                    .to_bytes()
                    .as_slice()
                    .to_vec(),
                KemSize::Kem1024 => DecapsulationKey1024::from_seed(seed)
                    .encapsulation_key()
                    .to_bytes()
                    .as_slice()
                    .to_vec(),
            }
        }

        fn encapsulate(
            size: KemSize,
            ek_bytes: &[u8],
        ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), ()> {
            match size {
                KemSize::Kem512 => {
                    let arr = Array::try_from(ek_bytes).map_err(|_| ())?;
                    let ek = EncapsulationKey512::new(&arr).map_err(|_| ())?;
                    let (ct, ss) = ek.encapsulate();
                    Ok((ct.as_slice().to_vec(), shared_key_bytes(ss.as_slice())))
                }
                KemSize::Kem768 => {
                    let arr = Array::try_from(ek_bytes).map_err(|_| ())?;
                    let ek = EncapsulationKey768::new(&arr).map_err(|_| ())?;
                    let (ct, ss) = ek.encapsulate();
                    Ok((ct.as_slice().to_vec(), shared_key_bytes(ss.as_slice())))
                }
                KemSize::Kem1024 => {
                    let arr = Array::try_from(ek_bytes).map_err(|_| ())?;
                    let ek = EncapsulationKey1024::new(&arr).map_err(|_| ())?;
                    let (ct, ss) = ek.encapsulate();
                    Ok((ct.as_slice().to_vec(), shared_key_bytes(ss.as_slice())))
                }
            }
        }

        fn decapsulate(size: KemSize, seed: &[u8; 64], ct_bytes: &[u8]) -> Zeroizing<[u8; 32]> {
            let seed = seed_of(seed);
            match size {
                KemSize::Kem512 => {
                    let dk = DecapsulationKey512::from_seed(seed);
                    let ct = Ciphertext::<MlKem512>::try_from(ct_bytes)
                        .expect("caller pre-validates ciphertext length");
                    shared_key_bytes(dk.decapsulate(&ct).as_slice())
                }
                KemSize::Kem768 => {
                    let dk = DecapsulationKey768::from_seed(seed);
                    let ct = Ciphertext::<MlKem768>::try_from(ct_bytes)
                        .expect("caller pre-validates ciphertext length");
                    shared_key_bytes(dk.decapsulate(&ct).as_slice())
                }
                KemSize::Kem1024 => {
                    let dk = DecapsulationKey1024::from_seed(seed);
                    let ct = Ciphertext::<MlKem1024>::try_from(ct_bytes)
                        .expect("caller pre-validates ciphertext length");
                    shared_key_bytes(dk.decapsulate(&ct).as_slice())
                }
            }
        }
    }
}

#[cfg(feature = "kem-libcrux")]
pub(crate) mod libcrux_backend {
    use libcrux_ml_kem::{mlkem1024, mlkem512, mlkem768};
    use zeroize::Zeroizing;

    use super::{validate_ek, KemBackend, KemSize};

    fn random_m() -> Result<[u8; 32], ()> {
        let mut m = [0u8; 32];
        getrandom::fill(&mut m).map_err(|_| ())?;
        Ok(m)
    }

    fn shared_key_bytes(ss: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(ss);
        out
    }

    pub(crate) struct LibcruxBackend;

    impl KemBackend for LibcruxBackend {
        fn ek_from_seed(size: KemSize, seed: &[u8; 64]) -> Vec<u8> {
            match size {
                KemSize::Kem512 => mlkem512::generate_key_pair(*seed).pk().to_vec(),
                KemSize::Kem768 => mlkem768::generate_key_pair(*seed).pk().to_vec(),
                KemSize::Kem1024 => mlkem1024::generate_key_pair(*seed).pk().to_vec(),
            }
        }

        fn encapsulate(
            size: KemSize,
            ek_bytes: &[u8],
        ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), ()> {
            validate_ek(size, ek_bytes)?;
            let m = random_m()?;
            match size {
                KemSize::Kem512 => {
                    let pk = mlkem512::MlKem512PublicKey::try_from(ek_bytes).map_err(|_| ())?;
                    let (ct, ss) = mlkem512::encapsulate(&pk, m);
                    Ok((ct.as_slice().to_vec(), shared_key_bytes(&ss)))
                }
                KemSize::Kem768 => {
                    let pk = mlkem768::MlKem768PublicKey::try_from(ek_bytes).map_err(|_| ())?;
                    let (ct, ss) = mlkem768::encapsulate(&pk, m);
                    Ok((ct.as_slice().to_vec(), shared_key_bytes(&ss)))
                }
                KemSize::Kem1024 => {
                    let pk = mlkem1024::MlKem1024PublicKey::try_from(ek_bytes).map_err(|_| ())?;
                    let (ct, ss) = mlkem1024::encapsulate(&pk, m);
                    Ok((ct.as_slice().to_vec(), shared_key_bytes(&ss)))
                }
            }
        }

        fn decapsulate(size: KemSize, seed: &[u8; 64], ct_bytes: &[u8]) -> Zeroizing<[u8; 32]> {
            match size {
                KemSize::Kem512 => {
                    let kp = mlkem512::generate_key_pair(*seed);
                    let ct = mlkem512::MlKem512Ciphertext::try_from(ct_bytes)
                        .expect("caller pre-validates ciphertext length");
                    shared_key_bytes(&mlkem512::decapsulate(kp.private_key(), &ct))
                }
                KemSize::Kem768 => {
                    let kp = mlkem768::generate_key_pair(*seed);
                    let ct = mlkem768::MlKem768Ciphertext::try_from(ct_bytes)
                        .expect("caller pre-validates ciphertext length");
                    shared_key_bytes(&mlkem768::decapsulate(kp.private_key(), &ct))
                }
                KemSize::Kem1024 => {
                    let kp = mlkem1024::generate_key_pair(*seed);
                    let ct = mlkem1024::MlKem1024Ciphertext::try_from(ct_bytes)
                        .expect("caller pre-validates ciphertext length");
                    shared_key_bytes(&mlkem1024::decapsulate(kp.private_key(), &ct))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{EK_LEN_1024, EK_LEN_512, EK_LEN_768};

    #[test]
    fn validate_ek_accepts_key_derived_from_seed() {
        let seed = [0x11u8; 64];
        for size in [KemSize::Kem512, KemSize::Kem768, KemSize::Kem1024] {
            let ek = ActiveKemBackend::ek_from_seed(size, &seed);
            assert!(validate_ek(size, &ek).is_ok());
        }
    }

    #[test]
    fn validate_ek_rejects_wrong_length() {
        for size in [KemSize::Kem512, KemSize::Kem768, KemSize::Kem1024] {
            assert!(validate_ek(size, &[0u8; 10]).is_err());
        }
    }

    #[test]
    fn validate_ek_rejects_out_of_range_coefficients() {
        // Correct length but all-0xFF bytes decode to out-of-range polynomial
        // coefficients (FIPS 203 modulus check) for every parameter set.
        for (size, len) in [
            (KemSize::Kem512, EK_LEN_512),
            (KemSize::Kem768, EK_LEN_768),
            (KemSize::Kem1024, EK_LEN_1024),
        ] {
            let bad = vec![0xFFu8; len];
            assert!(validate_ek(size, &bad).is_err());
        }
    }
}
