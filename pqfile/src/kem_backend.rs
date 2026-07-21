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

#[cfg(test)]
/// Known-answer tests against the official Wycheproof ML-KEM test vectors
/// (<https://github.com/C2SP/wycheproof>, `testvectors_v1/mlkem_*_test.json` and
/// `mlkem_*_keygen_seed_test.json`), run directly through `ActiveKemBackend` - the
/// same call sites `encrypt.rs`/`decrypt.rs`/`keygen.rs` use, so this exercises
/// whichever backend is active, including under `--features kem-libcrux`. Unlike a
/// roundtrip test, a bug that is wrong the same way on both the encrypt and decrypt
/// side can't hide here: the expected bytes come from an independent reference, not
/// from pqfile's own output. Only a small sample is vendored inline (not the full
/// multi-hundred-case corpus) to keep this a sanity check, not a vendored copy of
/// Wycheproof itself. See docs/ROADMAP.md, "NIST KAT/ACVP test vectors".
mod nist_kat {
    use super::{ActiveKemBackend, KemBackend, KemSize};

    /// Minimal local hex decoder (no `hex` dev-dependency needed for a handful
    /// of fixed-format test constants).
    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn mlkem512_keygen_matches_wycheproof_vectors() {
        // tcId 1, 2 from mlkem_512_keygen_seed_test.json
        let cases: [(&str, &str); 2] = [
            ("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f", "400865ed10b619aa5811139bc086825782b2b7124f757c83ae794444bc78a47896acf1262c81351077893bfc56f90449c2fa5f6e586dd37c0b9b581992638cb7e7bcbbb99afe4781d80a50e69463fbd988722c3635423e27466c71dcc674527ccd728968cbcdc00c5c9035bb0af2c9922c7881a41dd2875273925131230f6ca59e9136b39f956c93b3b2d14c641b089e07d0a840c893ecd76bbf92c805456668d07c621491c5c054991a656f511619556eb97782e27a3c785124c70b0daba6c624d18e0f9793f96ba9e1599b17b30dccc0b4f3766a07b23b257309cd76aba072c2b9c9744394c6ab9cb6c54a97b5c57861a58dc0a03519832ee32a07654a070c0c8c4e8648addc355f274fc6b92a087b3f9751923e44274f858c49caba72b65851b3adc48936955097cad9553f5a263f1844b52a020ff7ca89e881a01b95d957a3153c0a5e0a1ccd66b1821a2b8632546e24c7cbbc4cb08808cac37f7da6b16f8aced052cdb2564948f1ab0f768a0d3286ccc7c3749c63c781530fa1ae670542855004a645b522881ec1412bdae342085a9dd5f8126af96bbdb0c1af69a15562cb2a155a100309d1b641d08b2d4ed17bfbf0bc04265f9b10c108f850309504d772811bba8e2be16249aa737d879fc7fb255ee7a6a0a753bd93741c61658ec074f6e002b019345769113cc013ff7494ba8378b11a172260aaa53421bde03a35589d57e322fefa4100a4743926ab7d62258b87b31ccbb5e6b89cb10b271aa05d994bb5708b23ab327ecb93c0f3156869f0883da2064f795e0e2ab7d3c64d61d2303fc3a29e1619923ca801e59fd752ca6e7649d303c9d20788e1214651b06995eb260c929a1344a849b25ca0a01f1eb52913686bba619e23714464031a78439287fca78f4c0476223eea61b7f25a7ce42cca901b2aea129817894ba3470823854f3e5b28d86ba979e54671862d90470b1e7838972a81a48107d6ac0611406b21fbcce1db7702ea9dd6ba6e40527b9dc663f3c93bad056dc28511f66c3e0b928db8879d22c592685cc775a6cd574ac3bce3b27591c821929076358a2200b377365f7efb9e40c3bf0ff0432986ae4bc1a242ce9921aa9e22448819585dea308eb039"),
            ("d60b93492a1d8c1c7ba6fc0b733137f3406cee8110a93f170e7a78658af326d9003271531cf27285b8721ed5cb46853043b346a66cba6cf765f1b0eaa40bf672", "4b59447262a0bdbabdcddb3ffbd1c958aa04ac8ac815e054039ca2084ccde34b1b58212f8dcb9c8d7867d78120c2d84ccc20c0f136773b90088f273b017c4c29404043593192201f38eba1d4b326c653bf9b91a7f4387f0ae876f627b3ff878dc38aa3007a1a98387c3293396a74337ad51297075e09c1197cf50ea83c85f7085c1c81b07b87514f67898c64c9863b08744cae06da57c51bcc7ad588869806c4fb4e3430812af24ab7c1409ed89c0270a8632a4ab66a1009ec0253b4b128690f1ad7b3db743a1f85aa27d37c70c832b2b684b5b52aa6a7042a601dcda065f8f44008196504624e72a5099c686b82a283360c85ad425ed7c5af71c23747e21476462220f943a9381493e7060621b3d19674fa1bac0bd0b3b1cc484d7b6452d97d42898aa63674b25a51dbc655c9e7b647681c7a0a1d4714634754cd2401c0dfc4023b1b475ea1269e373ebb740c92d7be97755919c63aa939a471bc63d4b027799a34b2fb24a8690c4745385922b942f083b6c32a0d5c87f7a3b9fe168fa8b60d5f3247f9840c13259f992335debb52e7e08065264291f250c351c868d5ccb49c865be33c137c25bcb52b809351c476be47bb3dd7b85aae0a994ca746829597958a60ea55bde887c52a38a2dbf490cd506d0da19340d6cb4d1c1f5c84b4fc5357e21c0a44ec3a498aaa288c2b4e2196e1ac6e0b4213552621af049145687c4e69360a39afd69b38d9409842a65c36a5ca89b115897297d5c01d197154caeb77a44289a3f93e565690de3995501804dc519f7569bcc96a22e719840c542da779c943780a3c843efeec1a066050c6e47c4a39ad6e58266ca510ff3ab5dff37a2e34baf36abe5b09791f7b8e2391431d5a6a0b12ba077027ffdbb0ffaab72806d048fa066fcb4c487820a56b4bd10567f755bede04c91376330f797a56d59a465544b02ba68b96a0f95823d5e3b2c36c90423ac550abc796bc53833aace005a06b814db1d8c6a406bb5752cfb2b03a0824adb1ec265e5230b447a5082923ef1b0395f66c0fb913a9a133b29634716b65e889b0f80c4b02575ad3b8018331a67c3502c6195322bd2b71fd958cf071806587648fb31f7e4ee9ead48e0052b06244f3d1"),
        ];
        for (seed_hex, ek_hex) in cases {
            let seed: [u8; 64] = from_hex(seed_hex).try_into().unwrap();
            let ek = ActiveKemBackend::ek_from_seed(KemSize::Kem512, &seed);
            assert_eq!(ek, from_hex(ek_hex), "ek mismatch");
        }
    }

    #[test]
    fn mlkem512_decap_matches_wycheproof_vectors() {
        // tcId 2, 3 from mlkem_512_test.json
        let cases: [(&str, &str, &str); 2] = [
            ("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f", "113db2dd06871235e7bc36c9dcaa528fc26ce5db9ecc1dc32e957d7ffb3c7429d50c3c3577a515d3183a1b9d267b936b7eb8f543a3afb77765ca7938f78aa6438ce80a06a6966d0d06af75ba3e0d4f37bac73369f5a729f73e85729edd97c8c2a8cc2619e4cf7b6091869e909fd47d9709149204b0837d8d6f25d267972be63bad34b544523c01c09de3b1fa1d6b7b059eee9e652062fe870f68c68005339ea181e1d0767c152aeb38faf0f9245ae59d5cb0d2b7f201229ed97020d0623a46100d097b0ce1154e028ae6194de05de97dd9ae2e85ffd25d95eb22effe5ba19cd807c530ebaa9fe9f642ccacff47ed15c22bfe3036ebf8ad9c8ed23240aeebaa24d135755100b85ecee3174906e46312062ceecac75de5275256c2c1a653fd6915b1b30c8ecbb6fd4280437453173a96238bc7d108892343e033bcd98e437e789fc5bebaa12b2634b51ed0d589f11143a021d8ecce594fdd48dae84c8063ef3581bc378a48da4e51bb175b0db47f9dcf99318c30225ca7fa79c879bf1c9397b5ccc5efad94c500ed7f9f385d088e34932221fc0fc9afe51f6875548131697695478abdc8736f10095a6b92ec679fe0e2ae5d8b335355d58dae4d4f0b17aa5d1e52f1d45584a892c34ce4b04fcd00981d51caa16064bad92d019dc3aded919684112b29daa28b9dae09b86b21a93310d5fbc6527b224b9ce87d2782bb294673f0ec06f26b087652a18d6ad7b1c93303ef0561c0fc9cd4f678f606f192cf5df92b1548f5dd2687edbeccfc6d4e9de4bd50d3c74fb275abd9b3e90277db4a0069c0a2a7136f50cead4b2f1995faaf168040e9e4beb7c5722049d6da6402992fcea45097df7c1c20fb068222000576935a0806773451921f54c55fbf593a4f147c1fef3acaf0cfa907ae48c8c06312cfdf5186904bec7fed4ed933c9256ab04cbfa03a967c1f7ead4ab40df116be660e27ca2b543526d4b9684c31e1e42383b969f896299d71390cc85b703202acadecfa8c40965c08c53b5671e0d59455bc5a8586c655db8c2ade4ba8877f19b6000e18f8feadda7ede8fe80aa662d694c6d8c33b52", "319839e82ab6b222de7b619e80da8391522bbb37677018494a4742c53f9abfdf"),
            ("d60b93492a1d8c1c7ba6fc0b733137f3406cee8110a93f170e7a78658af326d9003271531cf27285b8721ed5cb46853043b346a66cba6cf765f1b0eaa40bf672", "2dfc1275d0391e151787bfe12ba647b3a69c28259119330d33a1ca00d40d5ba9a4ac9238b6ccaab9efdbe0770bf9b654f544ecd94711a760c4be7e51f328856596d921d9b77128d13e64ca588da7b3a93ad56c41d998ab5b48d626ebc546133aec9aa56c961e0cd4a01ba788eacdcd2b3ce1cc14b74f4fcbbb931d8891a68f37e8703e9f9bbdf9091bd1f4c8c03abac6af752d0c1855d1b1f7b78d14e4bba9600a3703e7aae5f8a850008f0f531f15599133df1d03722d5ccd499408700730af1ddbe1f5e232c4d8b6f725d5d0da5076a97d1496579252e75c12d1c4ab35d46e3e33211f53269794be9006bab36446f865555e62123964431ba1ee6e4d54f3491761f82d05eb394c90fb5aabbf6fcd82f7b9db1a771c05bbaa7fc41f0b9a768e77c6d3d570eebd8b22e27fe5c658ed55af1b3b6822ddd6aacd5d29e2fc01b8e50c56ed0cb28c7115ae230ca34d858207d05038c55c508093a46e70be3f13632c3665dc01dbc17582adc63c9d9fd49604f245717ee4569c004d3065517ed65c60226c63a74f88987fc82f2d740a17ddb8f57ec3bde6d7febafafc04ca6412618fcb8f65fc25ad35bc6c7a19459576fbd698f7354e88add8b01ef35a45f55b91327e4af1ec5f80a5fa93e4065c06ff221d717961ee4e9043f610a1a414932bffbf1155167148437c49a7ff2f0123f1bfcb87298fffdf02e35b3bb68d16f8d29544f0d4eeb7e64c45f75100cda51b4841722c4b387b130bb7fd821cc159d3af60fa54e48b86557925d4647ba01f6baf4b827649073237c633f407736a66cb0158880ca3404ff362a4367ca8e77e9354464788f6dd160e479d6df59b8d5f3ea060dd02d078bb6328fbc05d560b9c724d7e734ee3269d9d3515b54890e49d879506990fe734d04991979664b360b1882b5f3801e4607ddda5a2a7e885fe4a7a5d8e77cc5cb6da28adcc04e94e86742411834e74ef3cc27f753bb7bd819400b13f2d987a2aa671d687c9bac7ee629ce97ed76fcdfcc56bcd9251579f27e86eb781f270f69942ca19613fbeefbced31bbf2a3843f2dd7d73a5ee9d508d070f510f18aba", "3806942c857ab9bf77b1db8d57ec9dca0ffbf6f156f2e250d8b88cc2a74fa1a7"),
        ];
        for (seed_hex, ct_hex, k_hex) in cases {
            let seed: [u8; 64] = from_hex(seed_hex).try_into().unwrap();
            let ct = from_hex(ct_hex);
            let ss = ActiveKemBackend::decapsulate(KemSize::Kem512, &seed, &ct);
            assert_eq!(
                ss.as_slice(),
                from_hex(k_hex).as_slice(),
                "shared secret mismatch"
            );
        }
    }

    #[test]
    fn mlkem768_keygen_matches_wycheproof_vectors() {
        // tcId 1, 2 from mlkem_768_keygen_seed_test.json
        let cases: [(&str, &str); 2] = [
            ("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f", "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35fbaeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a51716aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c389137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028"),
            ("d60b93492a1d8c1c7ba6fc0b733137f3406cee8110a93f170e7a78658af326d9003271531cf27285b8721ed5cb46853043b346a66cba6cf765f1b0eaa40bf672", "93c140f6c47b7e53b96f72bb18447d277cc021c144a0f7a35e30b57386a78ac976376262320a5e7e1cb42e290de684462ce1067e920ee86c32418b130a5a41a0e8268cfa7e0db2b441cb927d7897c42b1d50f9b32868a35a2c04cfe91040e9a9208902f20c477e1b1ee5c290d2e5244eb1b4b7b4c6ad074533b58d9914a6aa8829f96789f5cb87607569983003f3a2461c33c81a3672af5924c4ba37e6827fccf86d8b4103fbe9c0f6226dd0a2145a6b7aec76b186466f9c67bf169039259574456497140c8cf4ac05091973ac8c08d809465785a677a032ac09ad1d666e8c48462813ce5ac75f184b38251c30e362b0e2501d6800c8ad103c8b773780b6717cf15c401139acd54b1598b2b7c79492a86631090268c70d875bc040cb2b75a386fa96b092b8cbc25c47f70aa76cd8b9afc12b42b536e27c5578831a96dbbab7138c3f247e955a6c08b4407d4708f1914bfa48af4b28533f747b860b7076c028e245c9727b42f3248fb0408b3ef0c4918ab76ab96daca81afb1211ab3a0329ba1a5b069a68934c1ce84c2f72839311257fa19e72c62fb5686b61416caf8b22d2b26a6dd01bb7387f88eb8606980a5e2259cbd56ca1ec051cfc66f96239991a2360d75dafa1534c8a05ab9c95e2e586853714600a3455511b62d94525d8b1a965ce69f986731888d1ecce536000e4863322a83e3c8475d9eba5414a65b0561d24a7b09dca6ffe23836058bec0a85671641008c831233c7890783dafe8c359a263e796869118c4e74002dc3b0ec5b1c4ac641bafe30eb2bb743713bfed2c1e79c4a6f46593006acb35f7031f194807b893aa7a9323162168d384d0e96f2f23368626a2e027891ac94f12f30a044b85f0322ce2b16517d36aa3f23b5f391be394b54ddc28e5a9775372869a7b50b4898c072c0669d43c641a3cb5e8c170ba63bed6ad1008615201305e292e1c818e1ef64f3e0c52fba67e7249c1ec4a140dc89ce0050647f1c19f5897c77b9059040b4b5b4282e0669cb4c658f48f67338413c92fc7412e444bc635dabc93c51b030784f21461dca210cc6a54fdc25bba09705baa77c1826636b16644a5ada51270d8317a787abf53192d40dc765bfb45c7dcae58481af3a49fe762b90bac1f6f69a5de8045981c67906b9f692625fcb6a4df2641688aba61fa49a84b47c96661e4701e5826c1108069c4b9c6e480251c4b021d11cfdaca12bbf9c09a0234186668e389454ac4046f5b2468aa2fa9b117868574e729574ee57ea7495af310627b85916d6b4c708374f9fb0c9c3aa4664c6651281d8eeb98132c1af13a816ca5b869f50b50b291efd466dea090918630c6fc77247c458aa82568a41dd9d4708af3bbca5a5716447e8c2c24ad788a8632473fdc4a257196bd2b549091176fe654d3694e10a118f7b66d1cd5af199b6e90b3bffa88a92e36717fd4bbfcc78b0e08634bc080c86885c92c8ef67aa4933c7df097891369bac5fc5d0c36737aa60971310adf02c257f76a7a7b3f7e132c2a71c52ff4affb6846391c0868241a3df13408d419a78bcffd49619b03a192c683900a244289c9f7b4564823900ceacffd9a9371260d5e57a8271196f4759eead0ceac318966e76f68de95ab9db2ba4fbf83c3b27092cd339cfe48d5ca0ba11591d04566f4ed24a5"),
        ];
        for (seed_hex, ek_hex) in cases {
            let seed: [u8; 64] = from_hex(seed_hex).try_into().unwrap();
            let ek = ActiveKemBackend::ek_from_seed(KemSize::Kem768, &seed);
            assert_eq!(ek, from_hex(ek_hex), "ek mismatch");
        }
    }

    #[test]
    fn mlkem768_decap_matches_wycheproof_vectors() {
        // tcId 2, 3 from mlkem_768_test.json
        let cases: [(&str, &str, &str); 2] = [
            ("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f", "c8391085b8d3ea9794212541b2914f08964d33521d3f67ad66096ebfb1f706424b49558f755b5625bae236f2e0079601c766f7d960808f7e2bb0c7a5e066ed346de628f8c57eebabbb0c22d911548463693ef3ce52a53f7ff415f00e657ae1c5a48fa5ec6e4be5cf462daffc84d2f6d5ff55dc9bbe8bb0d725ec64fd4cd4bd8dba0a844e8b5ce4b6a28934d7f7a050991fe185b506b451dabfad52d52cb2114ca7d9a5cf986c8fdc1bc10ec0c1869e50c03c55a76192a1049aca636ba9020bdaa8d0f58c763b0b89845ca06d4c4ddc21433e16b9c62e44871fdbc05ba218af871fdd7dcfa464e60faa5265264ce1391bd9a8c5faa7626d5f159b9805b975710a3503a0b858a11c6a647cc0e19ac88b1be9056c95b4d2087d0951d1d2f4992491117e6347794ba54571ec49bba71af3413d38a30bf5872248d1f6d07c86baf782e73d2637f043d341a00921857d8b21ddf3e1d6310036ed27af49e5de1b900fe4de79808ff29f9570859612b15adc01fbb265b305b1e3a12ae419da5b74261fa284c101da3d8dca8b2e4521aca571ef44a058e844ff32b16d5aaea05f7f3af8e2ab16222e347662eddfb891d0ecc2a55c5638f9dde92d9a3d544a5f901ac501acd1ea6a010201fcb10ad702c425a94bdf5890d500a2a147eee1d1fcba8c3abe7c2dfe70f346f033d816a0b2791b4f0b2d956d9ee5971715399a5688302495e2e07c1c8c01527184bcd0c208bc159f2e13318c0bb3dd24a6a7fc849f83385ed4dba07fe1d7bd5640cc9ed5ccfdd68763cb0d0edf61b292177fc1d2d3c11dd0495056bcb12558aebcfddef9feb4aebc57afd9023c65cfe65a24e33f1b00111e92e63e011eaf0b212cf95743cd07f5189ece1f205b7f6fcb2e6b1961b5404cebe47c8cd13b8599d5b49e6d87eeda36e9b8fc4c00635896aa2b75896e336d1b612ee13db811e1f07e61748d920f4865f3f11741399dc6162c91ca168a02329dff821d58198712dd558abb099b3a0baf9da1b730b2aa73bcf58d74f357b06f7211c804b6c8af16ff3509fad1d35b14bfdced7db8a6a25c48e5956480724daa057cd660b67ee3e472574182679d485838a6476eac02141075c812af7967ba7c9185cc2abd2a4545b80f3d3104d58d654a57792dcfabbe9c0715e8de2ef81ef404c8168fd7a43efab3d448e686a088efd26a26159948926723d7eccc39e3c1b719cf8becb7be7e964f22cd8cb1b7e25e800ea97d60a64cc0bbd9cb407a3ab9f88f5e29169eeafd4e0322fde6590ae093ce8feeae98b622caa7556ff426c9e7a404ce69355830a7a67767a76c7d9a97b84bfcf50a02f75c235d2f9c671138049ffc7c8055926c03eb3fb87f9695185a42eca9a41655873d30a6b3bf428b246223484a8ff61ee3eeafff10e99c2c13a76284d063e56ab711a35a85b5383df81da23490f66e8ea3fcba067f5530c6541c2b8f74717c35023e7b9b3956c3ee2ff84ba03ccf4b4b5321b9240895481bc6d63c1693c1847852f8e97f50a133532ac3ee1e52d464", "e7184a0975ee3470878d2d159ec83129c8aec253d4ee17b4810311d198cd0368"),
            ("d60b93492a1d8c1c7ba6fc0b733137f3406cee8110a93f170e7a78658af326d9003271531cf27285b8721ed5cb46853043b346a66cba6cf765f1b0eaa40bf672", "b3b339d73dfe8e3db262cdea792b4e3ecd712a75750a3b206800f11116637b58bc75ea61bd74070d7132309176608c33989fc510852c0f8d07e9862b79b069cfb3e5b78f277a74dcc832ada24f7d522e53a7cf16a7c7d952ed9f4dd4be4910d880e2e7c5b23c6cf9077e3d350ed3e7bb54ca7b39a9f68e98d2fc844c62f3eed092c8c008e4c2a28b3b1d9f34488655741ddcc440be7828ae39f25f52f57d8b1cfe3967af165e5affaddc8a85cd4939221762be2f71155c780ada5103976c77a76f838bc52a72544b22cfde6b6e843b4e552f1ba47419a8a8bf53c388537c1c08c272a02f4923d9edcc54dc767e6613c6f832889ec05ca805fc09e326d242517e91607005af03cd1acb242e630d6c20499dec187d8e5f6d421e2ceef7e3f74b751214fd58b6583bdc5ede65bbb643974d5cb45533f0a733a3353724e2d7e6821d99d317eec8781d3f1e03528fda480da8cd8e8adc51585a14acb5da154a68573b0566e5e49a53b4cb8061cdc795d13899032d549ac8f7c35099eb2ba0f0df4c9558444f4fe5f88bc46c6fca1b257c62d2116efd1c8cdef5717068405201c086da4143de277649f32538f537f8bf13a65c05747cd44f740736966422bd247f4be9a05acbcce53b9c1b0019096f93dfa86948d7b01d10952926b7a6e0e51792f9be6bab620b9fec660a2348818e4b47cd5934ffbcef5aaf20c3acf9494ae4df9d23f62a2571eca8d37fb1c8d29d5df0fa30c2f17fe3788032d124090dfbd000155ad8deca87190d66bcc9b1e3de392bacad79dc62be0d96eaf448feec5ef03544db3a782e5f9ffa20493d5ae6a58481d23cac7d3eaad57887bdd706eebf15f505d07e3592766710a658513598c94d2ff3eda5b5e900fcc9da8c012633c96a8b9e1da548dff60b1a763bb3f5ada6eea3290a01f7367f7c2384097ebee2960d904141b6c7bb30bf640350da34b9516d9f73100476e7bc077e0f88dfdeeaf9a2855448393cc26e14ac50b67065bb3694933bc64c622958a11637f9c995e17f15cfa663e7121c4ebd5fc1e153bea84c66843c90110e587462c623dc67ff0da5dadbade9b9724ff804227e188a00aa6c70bba00aaace8a035b96a595ee726fab666a08a4979ebd1e230a9c48afe7779cdd9f0d019e2400db9f686011ab05c4109db273c236646b481ac7251fd70d23188f943f6f282bf059279464645c9552de905996f2ef355a4d307448aed53728b490baf108a7d2579dc46e44334d1d99f310c8c953d4b3fbbf6b15a99b263775a1f9f0c0fbdfa260415ff4f61c263362c95fe9fa72767b8625f09b91c393fed48bc8f628ccc76b5ca49d9c01223ab4c1a9f25ac97ada8783b576575fa699140394e53daedf683ee53172ca9ff70c27a3f940675e3239e44a24804098486decb72ac8d41bda6e2d3585e2edc1e47cf1999fc67aa000677ba66ac22576ea087b6e7affd5c1617b3d94fdd314d17e6d37f9e5347807fe21fc5a9d75b3a25541cfe4a2d2c9efd00859d713cd6f67314cba4cc270fdb2e6", "5f0c5d9f39d3e724b5a2bd54e69e360f72ffab5d4d6cc5e572fecba80acd4796"),
        ];
        for (seed_hex, ct_hex, k_hex) in cases {
            let seed: [u8; 64] = from_hex(seed_hex).try_into().unwrap();
            let ct = from_hex(ct_hex);
            let ss = ActiveKemBackend::decapsulate(KemSize::Kem768, &seed, &ct);
            assert_eq!(
                ss.as_slice(),
                from_hex(k_hex).as_slice(),
                "shared secret mismatch"
            );
        }
    }

    #[test]
    fn mlkem1024_keygen_matches_wycheproof_vectors() {
        // tcId 1, 2 from mlkem_1024_keygen_seed_test.json
        let cases: [(&str, &str); 2] = [
            ("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f", "537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c3183d2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d7421598a6278ec7ebfabca0ef488b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745f2944016ec457f39b18d604a07a1abe07bc844050ffa8a06fa154a49d88fac775452d6a7c0e589bfb5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f319739f40c4f42b24aca7098fb8ff5f9ac20292d02b56ac746801acccc84863dee32878497b69438bf991776286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b74425c26e4a20dd9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e7cc28f10344062c10e08eccced3c1f7d392c01d979dd718d8398374665a16a9870585c39d5589a50e133389c9b9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b276656b9d8a4eb71896ff589d4b893e7110f3bb948ece291dd86c0b7468a678c746980c12aa6b95e2b0cbe4331bb24a33a270153aa472c47312382ca365c5f35259d025746fc6595fe636c767510a69c1e8a176b7949958f2697399497a2fc7364a12c8198295239c826cb5082086077282ed628651fc04c639b438522a9de309b14b086d6e923c551623bd72a733cb0dabc54a9416a99e72c9fda1cb3fb9ba06b8adb2422d68cadc553c98202a17656478ac044ef3456378abce9991e0141ba79094fa8f77a300805d2d32ffc62bf0ca4554c330c2bb7042db35102f68b1a0062583865381c74dd913af70b26cf0923d0c4cb971692222552a8f4b788b4afd1341a9df415cf203900f5ccf7f65988949a75580d049639853100854b21f4018003502bb1ba95f556a5d67c7eb52410eba288a6d0635ca8a4f6d696d0a020c826938d34943c3808c79cc007768533216bc1b29da6c812eff3340baa8d2e65344f09bd47894f5a3a4118715b3c5020679327f9189f7e10856b238bb9b0ab4ca85abf4b21f5c76bccd71850b22e045928276a0f2e951db0707c6a116dc19113fa762dc5f20bd5d2ab5be71744dc9cbdb51ea757963aac56a90a0d8023bed1f5cae8a64da047279b353a096a835b0b2b023b6aa048989233079aeb467e522fa27a5822921e5c551b4f537536e46f3a6a97e72c3b063104e09a040598940d872f6d871f5ef9b4355073b54769e45454e6a0819599408621ab4413b35507b0df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75161406e71c5ff92451a77522b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f99c730c45003aca2bf0f8424a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f60922ba19de73b1917f1853273555199a649318b50773345c997460856972acb43fc81ab6321b1c33c2bb5098bd489d696a0f70679c1213873d08bdad42844927216047205633212310ee9a06cb10016c805503c341a36d87e56072eabe23731e34af7e2328f85cdb370ccaf00515b64c9c54bc837578447aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad41bc680532b89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc265c0483a65ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866856bc1e034733b0485dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258b4af71221cd17530a700c32959c9436344b5316f09ccca7029a230d639dcb022d8ba79ba91cd6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166d0b0b81269b7d5f4b34fb022f69152f514004a7c685368552343bb60360fbb9945edf446d345bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376e5a6747a623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750762631c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd46fa7224461a5cc27405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a46d195581d173854b53d2293df3e9a822756cd8f212b325ca29b4f9f8cfbadf2e41869abfbad10738ad04cc752bc20c394746850e0c4847db"),
            ("d60b93492a1d8c1c7ba6fc0b733137f3406cee8110a93f170e7a78658af326d9003271531cf27285b8721ed5cb46853043b346a66cba6cf765f1b0eaa40bf672", "938a454364cf10a4c719113a23b242bc013962f13421ec0686e32ccb80840749643eb4b5cc4182cee2366717cf77f97da296a185440113770b6f755bc596cbbce021e94306b1e4ae437ab7dbc29527142a9223a8a7cb269391cad8f70c6cf666118830485ccaebba1bda242176559904713c6722c413d5c2b9c2669d58138ed5b23506a71c6182af6939dd40c51d678639238c8c071384c1256ee6a307475bb72bc93976c8976bb89c736d8fb19580cacb1f335b97d16943c0706f78095408cdad77a9fe967c4bca738960b3a3c171680426528a21578b79b226bda19a9bf132998a2149c463932d630b0f131e8096be462080e6d17107704f3b0cc90c3908cd645268375056e6072425b51a46c27a48b9c0db67b025a58ee37b44794430f3ae6cc74e1673c2b1d4b29db5370f590eaf6165e5806376f6a7d4825c74038792683f38893464103d82426593f366f96b023008be21956e6be8a4bd612d4f85239d62ab6c39069aa210b47b37ca85394c19327e5303cc9c54a5c63aeb104dacf67a1c1c3142710dcf682edac82471ba98c81a552ad2541b7338b2a0ce41354ccab879f549cfa58995eb8c64a8b30b6f384ec2e04dc1a11ae04c967f744024d70da780516777a1b1715f22cb1eb3511f5c4c99ce577836489a0f813a99a622390b52e4757843c772f6e75f470305259833b3993919f3aca66563f3eb7375f5883cfca72398b049170ebf0997ff277e44501fb0e83d0c5ca6c701048180ac68d857e0dc5d24b1628433c737b8808c290839d42c6a322250e0c22b81b4c018260d288c47976bcb84bcd0856c40448ca40b723b8144837965ad46b521ec4b405c28589b8536621a10678a75233e2cd59bc6e03f49d93925c5bcc133bea39a7e21907a19840c80225f1f154c270a4bf0206a16c241bf42cbd351055adc8519d38fc9d3b976e2144909053c5843c36b7b247a6ecd04c9d792a6fae968cbe11713592b287cc8b07b73c334bdbcb91d05c7ae4e86aa7547b4cc6403504acaef4c6e5b758f4e261c7624337000c187648325f36ac8854d4a8a1c2c732a0811b39439340e23c33af0ce5090ce800070306834321b5af9e4be13b22ea6655da11427f995a115dc86cda737aa99078407b9f78b914e831a6bec2c85f922f972bdda971b66761045813a852a0fd990136840835f8b5a72c5c8e8a65ce8d3ce957b06698261160031597a29e3388a4f5a5f0b96b70481a2e5738d3a50189496c75a856643899947c955be8871e808030a5757d6b46079454b54d51557cca964379bca5a8191698275dc51cb164f8e508fdaf480031a28afb1c9ccc65da9ac1cdec625131c6630188ffffbcb726133ca563da640c76a6c24105502ea3c24b918c5b818121cc68e2f1b62112a41594a6359876b91d058fd66861b7633d73cc7226b8debebcf90fcc390f761360554acf013ad03911b49b641c73687f4a73f8c290a2890c02c56e2a6567fb03826353d87ea41369673e1f9b920b36203cc9aa464192d01b6d859307927a629a24b34132cbceca487a0cb3c7442aba47c4a077fbe7442c2a4221a200a93e726518830b11b690f0497ac0851a5b27ea20253065a9ae7e6567fc26500edb11346955aeb2d9c6c228f1644f21b34e3694c05016284bcaf746ab6344a10eec87cd0f76a611ab64ec86288c339294aa15233abfb680036d2155fe77363530c3ee0c4b8b74a54e9a2453ca081d01f9626867632870b178d25b831fd133a2ac0596e688652c1772e2979305c5e2a10949bf35bdc08cecd6771b7f659b61960a45054998472163c21d31024c0c24972d5b145608c1044718f60894bf5875a453d4a7c4569c63a2b38c2db6a4fb8dc9289610ef12754f37cb4dad3b66e135d1f75759622cd7fa03c4ba81d71ac9938c9a97839a12d7a4622943c381a048edb26c64926b3a807b644aebc9110c54b06d4ea1cbf6462a55b31c7f5202cca8b7c698d9559276a1a3963cc56dd26ce3c051167f299d80c3a8ee894f134567cea1032c845d79ccd95313f04d6459d1ba72e00cc604365a9c5c5185005f17a0397a559a0b28f31b41a5e0948c81501e902b9cc253f6eba88172bbb92024984fa99c5bab08dc01504556aabe8c81bc99c56fc771ddc85d37b7c50182345e189267934564aa9dd80bcdc25b127f1244763644004e5eaf06b095b892bae095e0ba7f9d2700a50"),
        ];
        for (seed_hex, ek_hex) in cases {
            let seed: [u8; 64] = from_hex(seed_hex).try_into().unwrap();
            let ek = ActiveKemBackend::ek_from_seed(KemSize::Kem1024, &seed);
            assert_eq!(ek, from_hex(ek_hex), "ek mismatch");
        }
    }

    #[test]
    fn mlkem1024_decap_matches_wycheproof_vectors() {
        // tcId 2, 3 from mlkem_1024_test.json
        let cases: [(&str, &str, &str); 2] = [
            ("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f", "c9bead6b0c1114389bd4761c73ab9095b5809daac9f659bb564af226173052a4a3e7f2e5fd47d2b02aaeb5189e06b9f4ae98b619cb63efbdf3989a94b36e8ea0d700633b950a0ae2a78ed92e85c85c70e13e626fb263fac9681521c3ab22fdab29173c9616a2b037083ff7b2e019b5bcde068fac257ef8f12798411693c1bdcc65420997a513a8a69502620be8e4ce7362e412a76cf51c1f2433f1ab64ce0e5d2f56d7c9ade994d0e35d0aeef3ac515b482437664d8c1d25e5a5507cf80f970d3ea7226aacdc457cbf88a0560aa35bb2c5c455867e2159910a35810befe3aa10eb04d8d57147cb8f66d2b070bac43d1f1ffdd57a9399951f64965727bcb9f66ad42309dafc799c1c540af1af93eff68a86d61f5115db662dee7ac9a362677762b6a164a0fa0a4d859e4b8c8dbdb4e183f5e6808fc52229650caf7cf3e16de3d895d148c35448ab8c2753c9831b24bd4921497eaa192565cabfd83c0c68dfe7d392abf5e5e6f84bb9f5af4b7118c0b558105f9c10c9b6d70682e1de6e0689d7106a6374bd34aed7229e6cb356f2ea65e680ce7b1e2c3704e116a38542826e8a001141baf2e34de37a03040986d4c0cd5d57f0701ce930986fd9525b58e2e59f45b8dd04c0f35b0f47970cc67079618eb9e6d91e9b0f8c6d2e165cf448a2c1ebf71b6537e0f375185dfafef698b6239bb35580b315bcb5ed408c357f192def89bc1b75cdd6aae8b5faf0c3e13803f6bdfa76fb407fcbda790c329b3ee42fd3d3b03bd5003f0bc432f7ba39631112452dfd12140433ff8980eb6a526ba85ef99477378b4dc76635a5cd5040e43b8c1fe4ee5e158e423bfc0c893c1d5613bed08da719c9073184eeb36fd357380fb1873d8cbd36e2255e985b1b76819743a6584a9b3a580996c9c2eed9bbbfff78a6204b5e5eeae5f4efd2660078b37f0754ab5da862e666b145b5f23f3d0977799929dfa2aedda53d152eda1d0d0e4ea43f6ed889bb965eefe0a7c685bb36770eaa874242c0e229cf6ce56defa5aeae64d0c40dda8aa26eaeb31458f070a3bc72e1619ee9b5f642291c56df5b7e43db6c802fc74f4f3f9b5c0d355c3aae520aa31229d12f3e7cc5d48e691191a36b283765f4133f0ff1fe2f01c6648b2798a74eb5d842a248f524a7e7f8974211297b44f0dd19f386e86be6ba782de77fde887226f37a1c77bc5eddeee5bf46b67fb7478d559865f262caa84d64a8ce59e4df0818e14861526acd3483600f3dae7959d35d8181ca6a81ce791be00752da7759446a2cfbe00b8248b93491debd520220b755416d2fc6b7c8af2ff75e5bcbb8e7537380a5721c77484957a69271d8bafce0f166735ff869232de5d381afbf0e44d69172b79a35191949de09703b94222b13c385c6081e6d2ede1e57fe184ef8f60196b9a3a7b7eff7497191ca8741b5a01e79cb69a61142e6f5d080fbb3e566f79e146f75c8a1097860841b4747df604dba954e4a8d9e0dccc1f609d05cf8d31219ecd60c312de684552f09227cb829291c645732c5f5d4d711639f42a23080aa34fe1420f219bd6bcf4e3b29b9d02293b2da81383e0a51d2bb186c7b0a211a0cd63acbfc0210401e985d436b3803d5601c24136afd1562522e45b457cb439178be4a87cce40346d34ae0f3c39103c8a3ebc9c86c8db8fc5561eb0f3a143d4e9fe93a5cba6f6fcae5650d3f43d2668a5956c922893b816647ded0afc052a6c3d9d01a3d3af0f1ba807ff10491e131dc15e165cfd0650a1f2c313d7956141edcc61cb90e9e7abf2fe35fc9dc1bde88939fa11f7bbe3eb4d8ffa643b074d74f45113586e9bb12060003d71941f2da098dc0e96cad3255cf328ea2d3308c1f4585e89c613c426b7e798e1ec4e98fe6c71e7491f5eca0cd05115861bd160e3fe73a58a026ba538e0e256b92f1d7a2497570594856860ffd06b601ac575592f4ac612b5de7866042123ebc60c55768e3a7600a3260551f2bea22bbf6b6c8246e80f9125c4bb9db354dd64ae695c15f5071f4abb9639207cac7331b310f69a05f54b995de529a023f033b055db95287a14ba30a7cc526bb724c417fba290636a996f286e3e9e939e4fe1c398b5c6599959d0b4445a327ec469a1653cfaea7552cecec085ccaa68938ae4ac3c424f7e480439ebd2c992b5f6f95ec244b657dbdeaa9ae110aaf4d68bf4e27410d43ceef3e88e9c717dd44c9ee", "489dd1e9c2be4af3482bdb35bb26ce760e6e414da6ecbe489985748a825f1cd6"),
            ("d60b93492a1d8c1c7ba6fc0b733137f3406cee8110a93f170e7a78658af326d9003271531cf27285b8721ed5cb46853043b346a66cba6cf765f1b0eaa40bf672", "d0f902d86e1ac0a000f40e508ecb36f575902e319cf05ebb6de2ce63e02b912f9cfea50f513a4167a6f8973a656720aba76c83fc8caf1b9b922233e0356c9bc2b0f6fd5f083aac09b965c01208019d4d0f458f321a07197461eb3f71a136ab7fec0d7c1c6c868d6b2c890f09019f5159fa21642f44b8c1b89b9dbc49a0a9d294fe670ba0915a78c4a5a234af77b925e582eeb1437cebdfd3a86c98abd5723bd2fdf6b54fd79ed0dd867c5ff16fcbfc30bd1b739a912aa87c70e7213a3e42218db247422423089ead4e87ba998da1f354a1d1a65bd8c481c67c7aded64ceecbc1a9bf413e343433ba93fb79350187825e984f6e23f5dfde9b56ae1fa50ebd1e6c6b0141e3b9be3a5d1502dc21656d26dbce6eac70a596f23824d512ba86069a2a28182bf71275cad1639e947666a7c71f04d72bcba3036e774a23e95216af23b19d7af41f8db3f725d937915c72591fec65e902b486f9ef294608624d93da1096370c56a7f340629485cf0684e9ac76609b1f3d8f3b89bd20b87ff3805af4f2c62014a4b3f7e25c3cd12f505048464c490363b40ef68da9da2f25ad691df7bd4402c9e2a210a4ac9c2e1eb9f5f787b876e88ddab57ceae57741c9eb633280995ceb65a6871b767bca78b6569aefa1059d16c90a6afea36f5bce1d6928de55c9241c3b0f225ac7cd55b8ebf663b7c298f41c23fa8ccd279845a48e6614d500c6669cdc232b92178e7fd1fcf5b0b1a9c03f9bfaae1a8bdd856d91616e913f82a124bedb501dfb68d91f106b06acb3f9b6d473d8815ea27bb839856be5e5f26430615b97978f6113b042dad56475304aacb6d0ad777e63b4e8bf53a0c51c8e8b911147ea7404ce6d1a70770662b439fbd3d4e4c2788aef534ed19012b9387ebb9be3323daec6ebe149264c0253912f4f0eccce2d4cf5a7790e035c3a52c6a1541a5ac5be90526a5f031403227ee76d0836efc37a449bba10165ffe58f111dee2dfa288d3da3ac84894ae676f265b02bfa2a809fc622c3b8b4201ad59439d170e7022488e4e6cfd0fb5efe962a704905bc389001ae16ec46af47ff3a0ebf900a21fec6ccb754a89450134ef6945be8fb68960174342121c36cfad95025e336cfb15262caed34b3605ff9b305d98e53a0e1eea5f4f35ad7588b4f5ea0875f7a3c35ebd13863b299a05ffa14662ccc10cb949a56573a419bbab7424f7c13e537d497f002689fc6190d5a079019deeb265a238c1cebb9fccff0a3203783b03da50d589daf28ec573bab47207adeeaff281e180dc499d62c346b2485be4776f163361edb2fa9613537adaa4838396e32a91badc75487be6a1345ad93351bf4ba3b46084a2ba9421f0bdd9ef47be8fc22857cd0c5dc6b83e6a7ae7d0026bc61ca0361aff37b0d878400a1637a522a06fecb7be0e62b60fae2df2c7a1e68ec2992cdb505a5fd1ca7c1f53f0a8ea4162639af6ab32414b33cdf10b8aa579dd827c30b8c1780b3cd9d67320a11704057e0a77e998e1e4c12f3e5d8a13185ae6830911f88e7dc5cac7004abbc512c6ca69006b7dba74f147dc49785a1847a919a620c892d5a8ff3bd4b664bb73271d8d069ea19bf0e924e2869688cf0f26c1349abc29ce6b7fdccc1174f1a4b4fd26158b094808fee9d0ddbd996f785e6a1caddbc3293a1114feff09a19fa71f286f48721e810693ca9095d7b3c0b9736dfab4364dc1c0075e3face4dfe2eb1c815f713028312f1d106184c1bde874900591731dd75fa8f1505d816d51780f53b9b759b295cf5616acc7aa02ebe6b90252956275844bff4865637eea40969fef0ca595979b9215edfccaa44e09e67d8419928e09be7eee4d240d24f70db6bee802729b4244c619f38df99d0635a3125e2cc7c65bbe41caf795fc6d474ccb000f54f6c4daae2b62e62e2211f1258985e55fc5942d8c738c7df8a184ad34308dc798f4933031095ffd01997150899cfac81c533e6b1d92002640babf3ae3b73371964dd6dac95d8927ac33c4bab3e7a7d115fd1722b8c625da2c967d29764ef85240cec35bff4f507e3d0a02ec6d26a7ab90b8c50f392b8160ec34ddbd389a15bd47558b5b890cb45aee2e7c9f516201ad9e603c71fb631d0b930147a8bdba49e1dd0ca6fa3a8a089b520726dc78ac914d0c41d5ffd5875f798eafa2554c1ffed8b4e03f316a195c95c9a7c1351a06231ac84ad6269280ecf63a73", "425ada67204ff5b30a9d1cb545bcb4a6dbbd923cb3ca284911a1c5fe491ffb39"),
        ];
        for (seed_hex, ct_hex, k_hex) in cases {
            let seed: [u8; 64] = from_hex(seed_hex).try_into().unwrap();
            let ct = from_hex(ct_hex);
            let ss = ActiveKemBackend::decapsulate(KemSize::Kem1024, &seed, &ct);
            assert_eq!(
                ss.as_slice(),
                from_hex(k_hex).as_slice(),
                "shared secret mismatch"
            );
        }
    }
}
