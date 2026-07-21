//! Algorithm-distrust list: lets a future release flag a cryptographic
//! algorithm this crate supports as no longer trustworthy - the equivalent of
//! TLS's protocol-version deprecation - without breaking the ability to read
//! files or keys that already used it. `pqfile-cli`'s `doctor` and `inspect`
//! subcommands surface a warning (never a hard failure) when a checked file
//! or key uses a listed algorithm.
//!
//! Empty today: no algorithm this crate supports (ML-KEM-512/768/1024,
//! the X25519+ML-KEM-768 hybrid, ML-DSA-65, SLH-DSA-SHAKE-192f) has been
//! judged untrustworthy. This module exists so that decision, if it is ever
//! made, is a one-line addition to [`DISTRUSTED_ALGORITHMS`](crate::distrust::DISTRUSTED_ALGORITHMS)
//! rather than a new mechanism designed under time pressure. See `docs/ROADMAP.md`,
//! "Algorithm-distrust mechanism".

/// One entry in the distrust list.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct DistrustEntry {
    /// Canonical algorithm identifier, matched case-insensitively. Uses this
    /// crate's own algorithm names - the same strings [`kem_variant_algorithm_name`]
    /// and [`key_pem_algorithm_name`] return (e.g. `"ML-KEM-512"`,
    /// `"X25519+ML-KEM-768"` for the hybrid KEM, `"ML-DSA-65"`,
    /// `"SLH-DSA-SHAKE-192f"`).
    pub algorithm: &'static str,
    /// Why this algorithm is distrusted, shown alongside the warning.
    pub reason: &'static str,
    /// Date (`YYYY-MM-DD`) the distrust decision was recorded.
    pub since: &'static str,
}

/// Algorithms pqfile no longer recommends. Empty as of this writing - see the
/// module docs.
pub const DISTRUSTED_ALGORITHMS: &[DistrustEntry] = &[];

/// Looks up `algorithm` (case-insensitive) in `entries`.
///
/// Exists separately from [`check`] so the matching logic itself can be
/// exercised in tests against a synthetic list, without depending on a real
/// algorithm having been distrusted.
#[must_use]
pub fn check_against<'a>(
    entries: &'a [DistrustEntry],
    algorithm: &str,
) -> Option<&'a DistrustEntry> {
    entries
        .iter()
        .find(|e| e.algorithm.eq_ignore_ascii_case(algorithm))
}

/// Looks up `algorithm` (case-insensitive) against the built-in
/// [`DISTRUSTED_ALGORITHMS`] list. Returns `None` for every algorithm this
/// crate currently supports, since the list is empty.
#[must_use]
pub fn check(algorithm: &str) -> Option<&'static DistrustEntry> {
    check_against(DISTRUSTED_ALGORITHMS, algorithm)
}

/// Canonical distrust-list identifier for a numeric KEM variant, as stored in
/// `.pqf` headers ([`crate::inspect::PqfHeaderInfo`]) and returned by
/// [`crate::keys::PqfPrivateKey::kem_variant`]/[`crate::keys::PqfPublicKey::kem_variant`].
/// `None` for an unrecognised variant.
#[must_use]
pub fn kem_variant_algorithm_name(variant: u16) -> Option<&'static str> {
    match crate::keys::algorithm_name(variant) {
        "unknown" => None,
        name => Some(name),
    }
}

/// Checks a numeric KEM variant against the distrust list.
#[must_use]
pub fn check_kem_variant(variant: u16) -> Option<&'static DistrustEntry> {
    kem_variant_algorithm_name(variant).and_then(check)
}

/// Canonical distrust-list identifier for a recognised pqfile key PEM (KEM
/// private/public key, or signing/verifying key). `None` for an
/// unrecognised tag.
///
/// Hardware-backed key stubs are not covered: the algorithm lives inside a
/// credential-store-backed seed this function never touches.
#[must_use]
pub fn key_pem_algorithm_name(pem_str: &str) -> Option<&'static str> {
    crate::keys::PqfPrivateKey::from_pem(pem_str)
        .ok()
        .and_then(|k| kem_variant_algorithm_name(k.kem_variant()))
        .or_else(|| {
            crate::keys::PqfPublicKey::from_pem(pem_str)
                .ok()
                .and_then(|k| kem_variant_algorithm_name(k.kem_variant()))
        })
        .or_else(|| {
            crate::keys::PqfSigningKey::from_pem(pem_str)
                .ok()
                .map(|k| k.algorithm())
        })
        .or_else(|| {
            crate::keys::PqfVerifyingKey::from_pem(pem_str)
                .ok()
                .map(|k| k.algorithm())
        })
}

/// Checks a key PEM's algorithm against the distrust list. See
/// [`key_pem_algorithm_name`] for what is and is not recognised.
#[must_use]
pub fn check_key_pem(pem_str: &str) -> Option<&'static DistrustEntry> {
    key_pem_algorithm_name(pem_str).and_then(check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{
        KEM_VARIANT_1024, KEM_VARIANT_512, KEM_VARIANT_768, KEM_VARIANT_HYBRID_768,
    };
    use crate::keygen::keygen_bytes_hybrid_768;
    use crate::sign::{sign_keygen_bytes, sign_keygen_bytes_with_algorithm, SigAlgorithm};

    const TEST_LIST: &[DistrustEntry] = &[DistrustEntry {
        algorithm: "ML-KEM-512",
        reason: "test reason - not a real distrust decision",
        since: "2026-01-01",
    }];

    #[test]
    fn check_against_finds_case_insensitive_match() {
        let hit = check_against(TEST_LIST, "ml-kem-512");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().since, "2026-01-01");
        assert!(check_against(TEST_LIST, "ML-KEM-512").is_some());
        assert!(check_against(TEST_LIST, "Ml-Kem-512").is_some());
    }

    #[test]
    fn check_against_returns_none_for_unlisted_algorithm() {
        assert!(check_against(TEST_LIST, "ML-KEM-768").is_none());
        assert!(check_against(TEST_LIST, "").is_none());
    }

    #[test]
    fn check_against_empty_list_never_matches() {
        assert!(check_against(&[], "ML-KEM-512").is_none());
    }

    #[test]
    fn real_list_is_empty_and_check_finds_nothing() {
        // No pqfile-supported algorithm is distrusted as of this writing;
        // this test documents that fact and will fail (correctly) the moment
        // someone adds an entry without updating it.
        assert!(DISTRUSTED_ALGORITHMS.is_empty());
        assert!(check("ML-KEM-512").is_none());
        assert!(check("ML-KEM-768").is_none());
        assert!(check("ML-KEM-1024").is_none());
        assert!(check("X25519+ML-KEM-768").is_none());
        assert!(check("ML-DSA-65").is_none());
        assert!(check("SLH-DSA-SHAKE-192f").is_none());
    }

    #[test]
    fn kem_variant_algorithm_name_maps_every_known_variant() {
        assert_eq!(
            kem_variant_algorithm_name(KEM_VARIANT_512),
            Some("ML-KEM-512")
        );
        assert_eq!(
            kem_variant_algorithm_name(KEM_VARIANT_768),
            Some("ML-KEM-768")
        );
        assert_eq!(
            kem_variant_algorithm_name(KEM_VARIANT_1024),
            Some("ML-KEM-1024")
        );
        assert_eq!(
            kem_variant_algorithm_name(KEM_VARIANT_HYBRID_768),
            Some("X25519+ML-KEM-768")
        );
        assert_eq!(kem_variant_algorithm_name(0xFFFF), None);
    }

    #[test]
    fn check_kem_variant_would_match_a_distrusted_512_via_check_against() {
        // check_kem_variant itself is bound to the real (empty) list, so it
        // can't demonstrate a "found" result today. This instead proves the
        // exact string it would look up for KEM_VARIANT_512 is the same one
        // check_against's tests above already prove matches correctly -
        // closing the loop between the two halves of the pipeline.
        let name = kem_variant_algorithm_name(KEM_VARIANT_512).unwrap();
        assert!(check_against(TEST_LIST, name).is_some());
        assert!(check_kem_variant(KEM_VARIANT_512).is_none());
    }

    #[test]
    fn key_pem_algorithm_name_recognises_every_key_type() {
        let (kem_pub, kem_priv) = crate::keygen::keygen_bytes(768, None).unwrap();
        assert_eq!(key_pem_algorithm_name(&kem_priv), Some("ML-KEM-768"));
        assert_eq!(key_pem_algorithm_name(&kem_pub), Some("ML-KEM-768"));

        let (hybrid_pub, hybrid_priv) = keygen_bytes_hybrid_768(None).unwrap();
        assert_eq!(
            key_pem_algorithm_name(&hybrid_priv),
            Some("X25519+ML-KEM-768")
        );
        assert_eq!(
            key_pem_algorithm_name(&hybrid_pub),
            Some("X25519+ML-KEM-768")
        );

        let mldsa = sign_keygen_bytes(None).unwrap();
        assert_eq!(key_pem_algorithm_name(&mldsa.sk_pem), Some("ML-DSA-65"));
        assert_eq!(key_pem_algorithm_name(&mldsa.vk_pem), Some("ML-DSA-65"));

        let slh = sign_keygen_bytes_with_algorithm(SigAlgorithm::SlhDsaShake192f, None).unwrap();
        assert_eq!(
            key_pem_algorithm_name(&slh.sk_pem),
            Some("SLH-DSA-SHAKE-192f")
        );
        assert_eq!(
            key_pem_algorithm_name(&slh.vk_pem),
            Some("SLH-DSA-SHAKE-192f")
        );
    }

    #[test]
    fn key_pem_algorithm_name_returns_none_for_garbage() {
        assert_eq!(key_pem_algorithm_name("not a pem at all"), None);
    }

    #[test]
    fn check_key_pem_finds_nothing_against_the_real_empty_list() {
        let (_, kem_priv) = crate::keygen::keygen_bytes(512, None).unwrap();
        assert!(check_key_pem(&kem_priv).is_none());
    }
}
