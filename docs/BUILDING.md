# Building & Testing Locally

Quick reference for building, running, and testing every part of the project.

---

## Prerequisites (one-time setup)

```powershell
# Rust toolchain (if not already installed)
winget install Rustlang.Rustup

# WASM target for the web build
rustup target add wasm32-unknown-unknown

# Trunk - dev server + bundler for the web build
cargo install trunk

# Optional: code coverage
cargo install cargo-llvm-cov
```

---

## Desktop app

```powershell
# Debug build (fast compile, slower runtime; fine for UI testing)
cargo build -p pqfile-desktop
./target/debug/pqfile-desktop.exe

# Release build (what you ship)
cargo build --release -p pqfile-desktop
./target/release/pqfile-desktop.exe
```

> **Icon note:** `pqfile-desktop/assets/icon.png` and `icon.ico` must exist before the
> release build or `build.rs` will emit a warning and skip icon embedding.
> The PNG is already committed. Convert it to ICO with icoconvert.com and drop it at
> `pqfile-desktop/assets/icon.ico` and `pqfile-desktop/packaging/assets/icon.ico`.

---

## Web app (WASM)

```powershell
cd pqfile-gui

# Debug build + live-reload dev server, open http://localhost:8080
# Compiles fast; WASM is large and unoptimized, fine for UI testing
trunk serve

# Debug build only, no server (output goes to pqfile-gui/dist/)
trunk build

# Release build, optimized, small WASM, what you deploy
trunk build --release
```

Serve `dist/` locally to test a build without trunk:

```powershell
cd pqfile-gui/dist
python -m http.server 8080   # http://localhost:8080
```

---

## CLI

```powershell
# Build
cargo build --release -p pqfile

# Quick smoke test
$bin = "./target/release/pqfile.exe"

# 1. Generate keys
& $bin keygen --out ./tmp/keys/

# 2. Encrypt
& $bin encrypt -r ./tmp/keys/pubkey.pem ./tmp/keys/pubkey.pem -o ./tmp/test.pqf

# 3. Decrypt
& $bin decrypt -k ./tmp/keys/privkey.pem ./tmp/test.pqf -o ./tmp/recovered.pem

# 4. Inspect header (no decryption)
& $bin inspect ./tmp/test.pqf
```

---

## Tests

```powershell
# All workspace tests
cargo test --workspace

# GUI-only tests (includes encrypt/decrypt roundtrips)
cargo test -p pqfile-gui

# Core library tests only
cargo test -p pqfile

# Show output for failing tests
cargo test --workspace -- --nocapture

# Coverage report (opens in browser)
cargo llvm-cov --workspace --open
```

---

## Windows installer (Inno Setup)

```powershell
# 1. Build the release binary first
cargo build --release -p pqfile-desktop

# 2. Open Inno Setup and compile, or run from command line:
iscc pqfile-desktop\packaging\setup.iss

# Output: pqfile-desktop\packaging\output\pqfile-setup-4.0.0.exe
```

Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php) installed.

---

## Bump version (all crates at once)

```powershell
# Updates version in all Cargo.toml files + setup.iss
.\bump-version.ps1 -Version 3.3.0
```
