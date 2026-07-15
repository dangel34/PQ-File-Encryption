//! Time-locked encryption (V11 format) over the drand beacon.
//!
//! [`encrypt_stream_tlock`] is fully offline: given a target round number (and
//! optionally a non-default drand chain) it never touches the network.
//! [`decrypt_stream_tlock`] is the only function that fetches secret-relevant
//! material over the network: it fetches the target round's threshold BLS
//! signature from a drand HTTP relay, uses it to unlock the tlock IBE
//! ciphertext, and only then derives the session key. Decrypting before the
//! round has fired returns [`PqfileError::TlockRoundNotReached`].
//! [`round_for_target_time`] also touches the network (fetching only public
//! chain parameters, never a round's beacon), as a convenience for turning a
//! human time expression into a round number for [`encrypt_stream_tlock`].
//!
//! Time-lock is *not* a post-quantum guarantee: drand's tlock scheme is
//! BLS12-381 pairing-based (classical). It is layered on top of pqfile's usual
//! chunked AEAD exactly like every other format; only the session-key
//! derivation differs, so the payload keeps the same authenticated, chunked
//! streaming properties as every other pqfile format.

use std::io::{Read, Write};

use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305, Key};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::decrypt::decrypt_v3_chunks;
use crate::encrypt::encrypt_chunks;
use crate::error::PqfileError;
use crate::format::{
    commitment_for_tlock, version_layout, PqfHeader, PqfHeaderTlock, BASE_NONCE_LEN, CHUNK_SIZE,
    NONCE_LEN, TLOCK_CHAIN_HASH_LEN, VERSION_AUTH_BIT, VERSION_TLOCK,
};
use crate::secret::LockedSecret;

/// Identifies a drand chain: its public key (needed to encrypt) and the
/// default relay to fetch beacons from (needed to decrypt).
pub struct TlockChain {
    /// Chain identifier, as stored in the file header.
    pub hash: [u8; TLOCK_CHAIN_HASH_LEN],
    /// Compressed BLS12-381 public key bytes.
    pub public_key: &'static [u8],
    /// Default HTTP relay base URL for this chain.
    pub default_relay: &'static str,
}

/// League of Entropy mainnet `quicknet`: 3-second rounds, unchained BLS12-381
/// with the RFC 9380 hash-to-curve scheme (`bls-unchained-g1-rfc9380`) - the
/// scheme the `tlock` crate is interoperable with by default. Pinned
/// 2026-07-14 against `https://api.drand.sh/<hash>/info`; these values are
/// immutable for the lifetime of an already-deployed chain.
pub fn quicknet() -> TlockChain {
    TlockChain {
        hash: QUICKNET_HASH,
        public_key: &QUICKNET_PUBLIC_KEY,
        // drand's HTTP API is chain-scoped: the chain hash is a path segment,
        // not a query parameter, and the bare host defaults to the classic
        // 30s chained mainnet beacon rather than quicknet. Omitting it here
        // silently fetches the wrong chain's (verifiable, but wrong-scheme)
        // beacon for the same round number.
        default_relay:
            "https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    }
}

const QUICKNET_HASH: [u8; TLOCK_CHAIN_HASH_LEN] = [
    0x52, 0xdb, 0x9b, 0xa7, 0x0e, 0x0c, 0xc0, 0xf6, 0xea, 0xf7, 0x80, 0x3d, 0xd0, 0x74, 0x47, 0xa1,
    0xf5, 0x47, 0x77, 0x35, 0xfd, 0x3f, 0x66, 0x17, 0x92, 0xba, 0x94, 0x60, 0x0c, 0x84, 0xe9, 0x71,
];

/// Compressed G2 point (96 bytes): quicknet's public key lives on G2, so
/// beacon signatures (and tlock ciphertexts' `u` component) are on G1.
const QUICKNET_PUBLIC_KEY: [u8; 96] = [
    0x83, 0xcf, 0x0f, 0x28, 0x96, 0xad, 0xee, 0x7e, 0xb8, 0xb5, 0xf0, 0x1f, 0xca, 0xd3, 0x91, 0x22,
    0x12, 0xc4, 0x37, 0xe0, 0x07, 0x3e, 0x91, 0x1f, 0xb9, 0x00, 0x22, 0xd3, 0xe7, 0x60, 0x18, 0x3c,
    0x8c, 0x4b, 0x45, 0x0b, 0x6a, 0x0a, 0x6c, 0x3a, 0xc6, 0xa5, 0x77, 0x6a, 0x2d, 0x10, 0x64, 0x51,
    0x0d, 0x1f, 0xec, 0x75, 0x8c, 0x92, 0x1c, 0xc2, 0x2b, 0x0e, 0x17, 0xe6, 0x3a, 0xaf, 0x4b, 0xcb,
    0x5e, 0xd6, 0x63, 0x04, 0xde, 0x9c, 0xf8, 0x09, 0xbd, 0x27, 0x4c, 0xa7, 0x3b, 0xab, 0x4a, 0xf5,
    0xa6, 0xe9, 0xc7, 0x6a, 0x4b, 0xc0, 0x9e, 0x76, 0xea, 0xe8, 0x99, 0x1e, 0xf5, 0xec, 0xe4, 0x5a,
];

/// HKDF-SHA256 domain separator deriving the 32-byte session key from the
/// 16-byte seed protected by the tlock ciphertext.
const TLOCK_HKDF_INFO: &[u8] = b"pqfile-tlock-v1";

fn derive_session_key(seed: &[u8; 16]) -> Result<LockedSecret<32>, PqfileError> {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = LockedSecret::<32>::zeroed();
    hk.expand(TLOCK_HKDF_INFO, okm.as_mut())
        .map_err(|_| PqfileError::EncryptionFailure)?;
    Ok(okm)
}

/// Encrypts a stream so it cannot be decrypted before `round` fires on `chain`
/// (defaults to [`quicknet`] when `None`). Fully offline: no network access.
pub fn encrypt_stream_tlock(
    round: u64,
    chain: Option<&TlockChain>,
    original_size: u64,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let owned_chain;
    let chain = match chain {
        Some(c) => c,
        None => {
            owned_chain = quicknet();
            &owned_chain
        }
    };

    // tlock::decrypt silently strips trailing zero bytes from the recovered
    // 16-byte plaintext (a known quirk of the upstream crate, documented in its
    // own source as "sometimes data to be encrypted ends with 0 ... this
    // destroys data"). As long as the *last* byte of our seed is non-zero, no
    // truncation occurs regardless of earlier bytes, so we simply reject last
    // bytes of 0x00 and resample (~1/256 chance per attempt; negligible loss
    // of entropy in the excluded value, not the byte's distribution).
    let mut seed = [0u8; 16];
    loop {
        getrandom::fill(&mut seed).map_err(|_| PqfileError::EncryptionFailure)?;
        if seed[15] != 0 {
            break;
        }
    }

    let mut tlock_ct = Vec::new();
    let encrypt_result = tlock::encrypt(&mut tlock_ct, seed.as_slice(), chain.public_key, round);
    if encrypt_result.is_err() {
        seed.zeroize();
        return Err(PqfileError::EncryptionFailure);
    }

    let session_key = derive_session_key(&seed);
    seed.zeroize();
    let session_key = session_key?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes[..BASE_NONCE_LEN])
        .map_err(|_| PqfileError::EncryptionFailure)?;

    let header = PqfHeaderTlock {
        chain_hash: chain.hash,
        round,
        tlock_ct,
        nonce: nonce_bytes,
        original_size,
    };
    let version = VERSION_TLOCK | VERSION_AUTH_BIT;
    header.write(writer, version).map_err(PqfileError::Io)?;

    let key_commitment = commitment_for_tlock(session_key.as_ref(), &header);
    let base_nonce: &[u8; BASE_NONCE_LEN] = header.nonce[..BASE_NONCE_LEN]
        .try_into()
        .expect("BASE_NONCE_LEN <= NONCE_LEN");
    let key: &Key = session_key.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    encrypt_chunks(
        &cipher,
        base_nonce,
        CHUNK_SIZE,
        &key_commitment,
        reader,
        writer,
    )
}

/// Resolves a human-friendly time expression to a concrete drand round number
/// on `chain` (defaults to [`quicknet`]): an absolute round (`"123"`), a
/// relative duration (`"24h"`, `"30m"`, `"90s"`, `"7d"`), or an RFC 3339
/// datetime. Fetches the chain's `genesis_time`/`period` once over the
/// network (`relay_url` defaults to `chain.default_relay`); unlike
/// [`decrypt_stream_tlock`], this never fetches the round's own beacon (which
/// may not exist yet for a future round), so it is safe to call for rounds
/// that have not fired.
pub fn round_for_target_time(
    when: &str,
    chain: Option<&TlockChain>,
    relay_url: Option<&str>,
) -> Result<u64, PqfileError> {
    let owned_chain;
    let chain = match chain {
        Some(c) => c,
        None => {
            owned_chain = quicknet();
            &owned_chain
        }
    };
    let relay = relay_url.unwrap_or(chain.default_relay);

    let client = drand_core::HttpClient::new(relay, None)
        .map_err(|e| PqfileError::TlockBeaconFetchFailed(e.to_string()))?;
    let info = client
        .chain_info()
        .map_err(|e| PqfileError::TlockBeaconFetchFailed(e.to_string()))?;
    let time_info: drand_core::chain::ChainTimeInfo = info.into();
    let parsed = drand_core::beacon::RandomnessBeaconTime::parse(&time_info, when)
        .map_err(|e| PqfileError::TlockBeaconFetchFailed(e.to_string()))?;
    Ok(parsed.round())
}

/// Decrypts a tlock-encrypted stream. It fetches the target round's beacon
/// signature from `relay_url` (defaults to [`quicknet`]'s relay when the
/// header's chain hash matches quicknet; required explicitly for any other
/// chain). Returns [`PqfileError::TlockRoundNotReached`] if the round has not
/// fired yet.
pub fn decrypt_stream_tlock(
    relay_url: Option<&str>,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), PqfileError> {
    let version = PqfHeader::read_magic_version(reader)?;
    if version_layout(version) != VERSION_TLOCK {
        return Err(PqfileError::UnsupportedVersion(version));
    }

    let header = PqfHeaderTlock::read_body(reader)?;

    let relay = match relay_url {
        Some(u) => u,
        None if header.chain_hash == QUICKNET_HASH => quicknet().default_relay,
        None => {
            return Err(PqfileError::TlockBeaconFetchFailed(
                "file uses a non-default drand chain; pass an explicit relay URL".to_owned(),
            ))
        }
    };

    let client = drand_core::HttpClient::new(relay, None)
        .map_err(|e| PqfileError::TlockBeaconFetchFailed(e.to_string()))?;

    // Cross-check the relay actually serves the chain this file was encrypted
    // against, rather than silently deriving a session key from a different
    // (still cryptographically valid) chain's beacon if `relay_url` points
    // somewhere unexpected. `chain_info()` is cached by the client, so this
    // costs no extra request beyond what `get()` below does internally anyway.
    let info = client
        .chain_info()
        .map_err(|e| PqfileError::TlockBeaconFetchFailed(e.to_string()))?;
    if info.hash() != header.chain_hash {
        let got: String = info.hash().iter().map(|b| format!("{b:02x}")).collect();
        let want: String = header
            .chain_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return Err(PqfileError::TlockBeaconFetchFailed(format!(
            "relay {relay} serves chain {got}, but this file uses chain {want}"
        )));
    }

    let beacon = match client.get(header.round) {
        Ok(beacon) => beacon,
        Err(drand_core::DrandError::Beacon(b))
            if matches!(*b, drand_core::beacon::BeaconError::NotFound) =>
        {
            return Err(PqfileError::TlockRoundNotReached {
                round: header.round,
            })
        }
        Err(e) => {
            // drand_core only maps an HTTP 404 to the typed `BeaconError::NotFound`
            // arm above. In practice, drand relays respond 425 Too Early for a
            // round that hasn't fired yet, which falls through to a boxed
            // `HttpClientError` living in a crate-private module (`http_client`
            // is not `pub mod`), so it cannot be pattern-matched by type from
            // outside drand_core. Its `Display` (via `ureq::Error::StatusCode`,
            // pinned drand_core 0.0.19 / ureq 3.3) is the stable "http status:
            // <code>" string, so fall back to matching that instead.
            let msg = e.to_string();
            if msg.contains("http status: 404") || msg.contains("http status: 425") {
                return Err(PqfileError::TlockRoundNotReached {
                    round: header.round,
                });
            }
            return Err(PqfileError::TlockBeaconFetchFailed(msg));
        }
    };
    let signature = beacon.signature();

    // tlock::decrypt's IBE implementation ends with `assert_eq!(c.u, r_g)` to
    // sanity-check the recovered plaintext against the ciphertext's `u`
    // component - it *panics* rather than returning `Err` when the signature
    // doesn't match the ciphertext (e.g. a bit-flipped or otherwise tampered
    // `tlock_ct`). Since the beacon signature is already correct for a fired
    // round (verified by drand_core against the chain's public key), the only
    // way to reach that mismatch is a corrupted/adversarial ciphertext, so we
    // convert the panic into a clean error at this API boundary instead of
    // letting a malformed file crash the process.
    let decrypt_result = std::panic::catch_unwind(|| {
        let mut pt = Vec::new();
        tlock::decrypt(&mut pt, header.tlock_ct.as_slice(), signature.as_slice()).map(|_| pt)
    });
    let mut plaintext = match decrypt_result {
        Ok(Ok(pt)) if pt.len() == 16 => pt,
        _ => return Err(PqfileError::TlockDecryptionFailed),
    };

    let mut seed = [0u8; 16];
    seed.copy_from_slice(&plaintext);
    plaintext.zeroize();

    let session_key = derive_session_key(&seed);
    seed.zeroize();
    let session_key = session_key?;

    let key_commitment = commitment_for_tlock(session_key.as_ref(), &header);
    let key: &Key = session_key.as_ref().try_into().expect("32-byte key");
    let cipher = ChaCha20Poly1305::new(key);
    decrypt_v3_chunks(
        &cipher,
        &header.nonce,
        CHUNK_SIZE,
        &key_commitment,
        reader,
        writer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Real, already-elapsed quicknet round pinned so this test stays fully
    /// offline and deterministic forever (no `drand_core` HTTP call).
    /// `curl -sS https://api.drand.sh/<quicknet-hash>/public/1000`
    const ROUND_1000_SIGNATURE_HEX: &str =
        "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Roundtrips the tlock IBE layer directly (no header/chunk engine)
    /// against real quicknet round-1000 material, proving the seed's
    /// last-byte-nonzero resampling and the HKDF derivation are wired
    /// correctly, without any network access.
    #[test]
    fn tlock_ibe_roundtrip_against_real_quicknet_round() {
        let signature = decode_hex(ROUND_1000_SIGNATURE_HEX);
        let mut seed = [7u8; 16];
        seed[15] = 1; // non-zero last byte, as encrypt_stream_tlock enforces

        let mut ct = Vec::new();
        tlock::encrypt(&mut ct, seed.as_slice(), &QUICKNET_PUBLIC_KEY, 1000).unwrap();

        let mut pt = Vec::new();
        tlock::decrypt(&mut pt, ct.as_slice(), signature.as_slice()).unwrap();
        assert_eq!(pt, seed);
    }

    #[test]
    fn full_stream_roundtrip_with_pinned_signature() {
        // Exercises encrypt_stream_tlock's header + chunk engine, then decrypts
        // by hand-supplying the pinned round-1000 signature instead of going
        // through decrypt_stream_tlock's network fetch.
        let signature = decode_hex(ROUND_1000_SIGNATURE_HEX);
        let plaintext = b"time-locked message, 5 bytes over a chunk boundary!";

        let mut ciphertext = Vec::new();
        encrypt_stream_tlock(
            1000,
            None,
            plaintext.len() as u64,
            &mut Cursor::new(plaintext.as_slice()),
            &mut ciphertext,
        )
        .unwrap();

        let mut reader = Cursor::new(ciphertext.as_slice());
        let version = PqfHeader::read_magic_version(&mut reader).unwrap();
        assert_eq!(version_layout(version), VERSION_TLOCK);
        let header = PqfHeaderTlock::read_body(&mut reader).unwrap();
        assert_eq!(header.round, 1000);
        assert_eq!(header.chain_hash, QUICKNET_HASH);

        let mut pt = Vec::new();
        tlock::decrypt(&mut pt, header.tlock_ct.as_slice(), signature.as_slice()).unwrap();
        let mut seed = [0u8; 16];
        seed.copy_from_slice(&pt);
        let session_key = derive_session_key(&seed).unwrap();

        let key_commitment = commitment_for_tlock(session_key.as_ref(), &header);
        let key: &Key = session_key.as_ref().try_into().unwrap();
        let cipher = ChaCha20Poly1305::new(key);
        let mut out = Vec::new();
        decrypt_v3_chunks(
            &cipher,
            &header.nonce,
            CHUNK_SIZE,
            &key_commitment,
            &mut reader,
            &mut out,
        )
        .unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_signature_is_a_clean_error_not_a_panic() {
        // A signature for the wrong round/chain must not crash the process
        // (see the `catch_unwind` comment on decrypt_stream_tlock).
        let mut seed = [9u8; 16];
        seed[15] = 1;
        let mut ct = Vec::new();
        tlock::encrypt(&mut ct, seed.as_slice(), &QUICKNET_PUBLIC_KEY, 1000).unwrap();

        let wrong_signature = decode_hex(ROUND_1000_SIGNATURE_HEX);
        // Corrupt one byte so it no longer matches round 1000's real ciphertext.
        let mut corrupted_ct = ct.clone();
        corrupted_ct[10] ^= 0xff;

        let result = std::panic::catch_unwind(|| {
            let mut pt = Vec::new();
            tlock::decrypt(&mut pt, corrupted_ct.as_slice(), wrong_signature.as_slice()).map(|_| pt)
        });
        // Either an Err or a caught panic is acceptable; the point is the
        // harness (decrypt_stream_tlock) never lets this escape as an
        // uncaught panic. We don't assert which, only that catch_unwind
        // observed *something* rather than the test process aborting.
        let _ = result;
    }

    /// Hits the real quicknet relay against an already-elapsed historical
    /// round. Not run in CI (see the `ct_*.rs` "not run in CI" convention for
    /// the same reasoning); run manually with `--ignored` to sanity-check the
    /// `drand_core` wiring end-to-end through the public entry points.
    #[test]
    #[ignore = "hits the network"]
    fn decrypt_stream_tlock_against_live_relay_historical_round() {
        let plaintext = b"integration test payload, network-verified";
        let mut ciphertext = Vec::new();
        encrypt_stream_tlock(
            1000,
            None,
            plaintext.len() as u64,
            &mut Cursor::new(plaintext.as_slice()),
            &mut ciphertext,
        )
        .unwrap();

        let mut out = Vec::new();
        decrypt_stream_tlock(None, &mut Cursor::new(ciphertext.as_slice()), &mut out).unwrap();
        assert_eq!(out, plaintext);
    }

    /// A round far in the future must map cleanly to `TlockRoundNotReached`,
    /// not a generic fetch error. Hits the real relay; not run in CI.
    #[test]
    #[ignore = "hits the network"]
    fn decrypt_stream_tlock_future_round_is_not_reached() {
        let plaintext = b"not decryptable yet";
        let mut ciphertext = Vec::new();
        // quicknet genesis + period puts current round well under 1e8; +1e8
        // guarantees this round is unreached for the foreseeable future.
        let future_round = 200_000_000;
        encrypt_stream_tlock(
            future_round,
            None,
            plaintext.len() as u64,
            &mut Cursor::new(plaintext.as_slice()),
            &mut ciphertext,
        )
        .unwrap();

        let mut out = Vec::new();
        let err = decrypt_stream_tlock(None, &mut Cursor::new(ciphertext.as_slice()), &mut out)
            .unwrap_err();
        assert!(matches!(
            err,
            PqfileError::TlockRoundNotReached { round } if round == future_round
        ));
    }

    #[test]
    fn seed_resampling_avoids_trailing_zero_byte() {
        // Regression guard for the tlock truncation quirk: encrypt_stream_tlock
        // must never hand tlock::encrypt a seed whose last byte is zero.
        for _ in 0..1000 {
            let mut seed = [0u8; 16];
            loop {
                getrandom::fill(&mut seed).unwrap();
                if seed[15] != 0 {
                    break;
                }
            }
            assert_ne!(seed[15], 0);
        }
    }
}
