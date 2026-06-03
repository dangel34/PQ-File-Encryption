//! Generates the golden ciphertext files committed in `pqfile/tests/compat/`.
//!
//! Run once whenever a wire format changes (and update the relevant file) to regenerate:
//!
//!   cargo run --example gen_compat_vectors -p pqfile
//!
//! The generated files are committed to the repository. The `compat` integration
//! test suite decrypts each file on every CI push to catch silent regressions.

use std::fs;
use std::path::Path;

use pqfile::encrypt::{
    encrypt_stream, encrypt_stream_compressed, encrypt_stream_multi, encrypt_stream_multi_anon,
};
use pqfile::format::CHUNK_SIZE;
use pqfile::keygen::{keygen_bytes, keygen_bytes_hybrid_768};

const OUT_DIR: &str = "pqfile/tests/compat";
const PLAINTEXT: &[u8] = b"pqfile compat vector - do not change";

fn write(dir: &Path, name: &str, data: &[u8]) {
    let path = dir.join(name);
    fs::write(&path, data).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("wrote {}", path.display());
}

fn main() {
    let dir = Path::new(OUT_DIR);
    fs::create_dir_all(dir).expect("cannot create compat dir");

    // Store plaintext so the test can load it without hard-coding it.
    write(dir, "plaintext.bin", PLAINTEXT);

    // v2 - whole-file AEAD, ML-KEM-768
    {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let ct = pqfile::encrypt::encrypt_bytes(&pub_pem, PLAINTEXT).unwrap();
        write(dir, "v2_768.pqf", &ct);
        write(dir, "v2_768.priv.pem", priv_pem.as_bytes());
    }

    // v3 - 64 KiB chunked stream, ML-KEM-512
    {
        let (pub_pem, priv_pem) = keygen_bytes(512, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            PLAINTEXT.len() as u64,
            CHUNK_SIZE,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        write(dir, "v3_512.pqf", &ct);
        write(dir, "v3_512.priv.pem", priv_pem.as_bytes());
    }

    // v3 - 64 KiB chunked stream, ML-KEM-1024
    {
        let (pub_pem, priv_pem) = keygen_bytes(1024, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            PLAINTEXT.len() as u64,
            CHUNK_SIZE,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        write(dir, "v3_1024.pqf", &ct);
        write(dir, "v3_1024.priv.pem", priv_pem.as_bytes());
    }

    // v3 - hybrid X25519+ML-KEM-768
    {
        let (pub_pem, priv_pem) = keygen_bytes_hybrid_768(None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            PLAINTEXT.len() as u64,
            CHUNK_SIZE,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        write(dir, "v3_hybrid.pqf", &ct);
        write(dir, "v3_hybrid.priv.pem", priv_pem.as_bytes());
    }

    // v4 - multi-recipient (2 keys), ML-KEM-768
    {
        let (pub1, priv1) = keygen_bytes(768, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream_multi(
            &[pub1.as_str(), pub2.as_str()],
            PLAINTEXT.len() as u64,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        write(dir, "v4_multi.pqf", &ct);
        write(dir, "v4_multi.priv1.pem", priv1.as_bytes());
        write(dir, "v4_multi.priv2.pem", priv2.as_bytes());
    }

    // v5 - custom chunk size (8 KiB), ML-KEM-768
    {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream(
            &pub_pem,
            PLAINTEXT.len() as u64,
            8192,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        write(dir, "v5_8k.pqf", &ct);
        write(dir, "v5_8k.priv.pem", priv_pem.as_bytes());
    }

    // v6 - zstd-compressed, ML-KEM-768 (native only; skipped on wasm)
    #[cfg(not(target_arch = "wasm32"))]
    {
        let (pub_pem, priv_pem) = keygen_bytes(768, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream_compressed(
            &pub_pem,
            PLAINTEXT.len() as u64,
            CHUNK_SIZE,
            3,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        write(dir, "v6_zstd.pqf", &ct);
        write(dir, "v6_zstd.priv.pem", priv_pem.as_bytes());
    }

    // v8 - anonymous multi-recipient (3 keys, mixed variants)
    {
        let (pub1, priv1) = keygen_bytes(512, None).unwrap();
        let (pub2, priv2) = keygen_bytes(768, None).unwrap();
        let (pub3, priv3) = keygen_bytes(1024, None).unwrap();
        let mut ct = Vec::new();
        encrypt_stream_multi_anon(
            &[pub1.as_str(), pub2.as_str(), pub3.as_str()],
            PLAINTEXT.len() as u64,
            &mut { PLAINTEXT },
            &mut ct,
        )
        .unwrap();
        write(dir, "v8_anon.pqf", &ct);
        write(dir, "v8_anon.priv1.pem", priv1.as_bytes());
        write(dir, "v8_anon.priv2.pem", priv2.as_bytes());
        write(dir, "v8_anon.priv3.pem", priv3.as_bytes());
    }

    println!("done - {} test vectors written to {OUT_DIR}/", 9 + 1); // +1 plaintext.bin
}
