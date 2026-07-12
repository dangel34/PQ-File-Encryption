#!/usr/bin/env bash
# PGO training workload for the pqfile CLI binary (release.yml's `build` job).
#
# Exercises every hot crypto path once: ML-KEM 512/768/1024/hybrid keygen and
# single-recipient encrypt/decrypt (covers ChaCha20Poly1305 plus all KEM
# sizes), multi-recipient encrypt/decrypt (covers the AES-256-GCM session-key
# wrap path), and zstd compression. Each roundtrip runs against a small and a
# multi-chunk-sized input so both the single-chunk and streaming-chunk paths
# get profiled.
#
# Deliberately not covered: v10 `--passphrase` mode. `rpassword` reads
# directly from the controlling terminal device rather than stdin, so its
# prompt can't be scripted headlessly in CI. The KDF that mode alone exercises
# (Argon2id) is already treated as out of scope for instruction-level perf
# tuning elsewhere (see pqfile/benches/iai.rs) since it is deliberately
# memory-hard, so the coverage gap has low practical cost.
#
# Usage: pgo_workload.sh <path-to-pqfile-binary>
set -euo pipefail

BIN="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Two sizes so both the single-chunk and multi-chunk streaming paths run.
head -c 4096 /dev/urandom >"$WORK/small.bin"
head -c 4194304 /dev/urandom >"$WORK/large.bin" # 4 MiB: several 64 KiB chunks

keygen() {
  local dir="$1"
  shift
  mkdir -p "$dir"
  "$BIN" keygen --out "$dir" --force "$@"
}

roundtrip() {
  local pubkey="$1" privkey="$2" infile="$3" outdir="$4"
  shift 4
  mkdir -p "$outdir"
  "$BIN" encrypt -r "$pubkey" "$infile" -o "$outdir/out.pqf" --force "$@"
  "$BIN" decrypt -k "$privkey" "$outdir/out.pqf" -o "$outdir/out.dec" --force
}

# ML-KEM 512 / 768 / 1024, single recipient, small + large input.
for variant in 512 768 1024; do
  keygen "$WORK/k$variant" --level "$variant"
  for size in small large; do
    roundtrip "$WORK/k$variant/pubkey.pem" "$WORK/k$variant/privkey.pem" \
      "$WORK/$size.bin" "$WORK/rt_${variant}_${size}"
  done
done

# Hybrid X25519+ML-KEM-768.
keygen "$WORK/khybrid" --hybrid
for size in small large; do
  roundtrip "$WORK/khybrid/pubkey.pem" "$WORK/khybrid/privkey.pem" \
    "$WORK/$size.bin" "$WORK/rt_hybrid_${size}"
done

# Multi-recipient (AES-256-GCM key-wrap path, v4 format). Reuses the 768 and
# 1024 keys generated above.
"$BIN" encrypt -r "$WORK/k768/pubkey.pem" -r "$WORK/k1024/pubkey.pem" \
  "$WORK/large.bin" -o "$WORK/multi.pqf" --force
"$BIN" decrypt -k "$WORK/k768/privkey.pem" "$WORK/multi.pqf" -o "$WORK/multi.dec" --force

# zstd compression path.
"$BIN" encrypt -r "$WORK/k768/pubkey.pem" "$WORK/large.bin" \
  -o "$WORK/compressed.pqf" --force --compress
"$BIN" decrypt -k "$WORK/k768/privkey.pem" "$WORK/compressed.pqf" \
  -o "$WORK/compressed.dec" --force

echo "PGO training workload finished."
