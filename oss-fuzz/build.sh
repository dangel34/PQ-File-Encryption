#!/bin/bash -eu
# OSS-Fuzz build script for pqfile.
# See https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/

cd "$SRC/pqfile"

# Build all fuzz targets.
for target in fuzz_header_read fuzz_decrypt_bytes fuzz_pem_parsing; do
    cargo fuzz build "$target" \
        --fuzz-dir fuzz \
        -O \
        -- \
        -C opt-level=3
    cp "fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
done
