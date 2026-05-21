use std::io::Cursor;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pqfile::{encrypt, decrypt, keygen};
use pqfile::format::CHUNK_SIZE;

fn bench_encrypt_bytes(c: &mut Criterion) {
    let (pub_pem, _) = keygen::keygen_bytes(768, None).unwrap();

    let mut group = c.benchmark_group("encrypt_bytes");
    for size in [1_024usize, 1_048_576, 104_857_600] {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| encrypt::encrypt_bytes(&pub_pem, pt).unwrap());
        });
    }
    group.finish();
}

fn bench_decrypt_bytes(c: &mut Criterion) {
    let (pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();

    let mut group = c.benchmark_group("decrypt_bytes");
    for size in [1_024usize, 1_048_576, 104_857_600] {
        let plaintext = vec![0xCDu8; size];
        let ciphertext = encrypt::encrypt_bytes(&pub_pem, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            b.iter(|| decrypt::decrypt_bytes(&priv_pem, ct, None).unwrap());
        });
    }
    group.finish();
}

fn bench_encrypt_stream(c: &mut Criterion) {
    let (pub_pem, _) = keygen::keygen_bytes(768, None).unwrap();

    let mut group = c.benchmark_group("encrypt_stream");
    for size in [1_024usize, 1_048_576, 104_857_600] {
        let plaintext = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                let mut reader = Cursor::new(pt);
                let mut writer = Vec::with_capacity(pt.len() + 4096);
                encrypt::encrypt_stream(&pub_pem, pt.len() as u64, CHUNK_SIZE, &mut reader, &mut writer)
                    .unwrap();
            });
        });
    }
    group.finish();
}

fn bench_decrypt_stream(c: &mut Criterion) {
    let (pub_pem, priv_pem) = keygen::keygen_bytes(768, None).unwrap();

    let mut group = c.benchmark_group("decrypt_stream");
    for size in [1_024usize, 1_048_576, 104_857_600] {
        let plaintext = vec![0xCDu8; size];
        let mut reader = Cursor::new(&plaintext);
        let mut ciphertext = Vec::new();
        encrypt::encrypt_stream(&pub_pem, size as u64, CHUNK_SIZE, &mut reader, &mut ciphertext).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            b.iter(|| {
                let mut reader = Cursor::new(ct);
                let mut writer = Vec::with_capacity(size);
                decrypt::decrypt_stream(&priv_pem, &mut reader, &mut writer, None).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        b.iter(|| keygen::keygen_bytes(768, None).unwrap());
    });
}

criterion_group!(
    benches,
    bench_encrypt_bytes,
    bench_decrypt_bytes,
    bench_encrypt_stream,
    bench_decrypt_stream,
    bench_keygen,
);
criterion_main!(benches);
