# pqfile (mobile bindings: Kotlin / Swift)

Kotlin (Android) and Swift (iOS) bindings for
[`pqfile`](https://github.com/dangel34/PQ-File-Encryption), a quantum-resistant
file encryption library: ML-KEM (512/768/1024) and hybrid X25519+ML-KEM-768
key encapsulation with ChaCha20-Poly1305 authenticated encryption. Generated from
one Rust interface definition with [uniffi-rs](https://mozilla.github.io/uniffi-rs/)
(the same tool Firefox uses for its Android/iOS bindings); the crypto itself
lives entirely in the `pqfile` Rust crate, not in this binding layer.

## Status

**The Rust binding layer is done and tested; the Android/iOS packaging is
not.** This crate builds and its Rust-level tests pass (`cargo test`, 7 cases
mirroring the Python/Node.js suites - see `tests/roundtrip.rs`), and
`uniffi-bindgen` successfully generates both Kotlin and Swift source from it
(commands below). What's still missing:

- No Android target has been cross-compiled (`aarch64-linux-android` etc.) -
  needs `cargo-ndk` and the Android NDK, neither installed on this
  repo's dev machine.
- No iOS target has been cross-compiled (`aarch64-apple-ios` etc.) or bundled
  into an XCFramework - that requires Xcode, which only runs on macOS.
- No Gradle module or Swift package wraps the generated bindings for a real
  app to depend on - see "Packaging (not done yet)" below for the shape that
  would take.
- The generated Kotlin/Swift source in `bindings/` (gitignored, produced by
  the commands below) has been read over for sanity - correct camelCase
  names, checked-exception/`throws` signatures, `ByteArray`/`Data` for
  buffers, `UShort`/`UInt16` for the `level` parameter - but never compiled or
  run through an actual Kotlin or Swift toolchain, since neither is available
  here.

## Layout

- `src/lib.rs` - the exported interface: `keygen`, `keygen_hybrid`,
  `encrypt_bytes`, `decrypt_bytes`, `encrypt_file`, `decrypt_file`, all
  `#[uniffi::export]`-annotated plain Rust functions (the single-recipient
  streaming path, same as the Python/Node.js bindings) plus a `KeyPair`
  record and a `PqfileMobileError` error type.
- `src/bin/uniffi-bindgen.rs` - the standard `uniffi::uniffi_bindgen_main()`
  entry point used to generate bindings for any target language.
- `tests/roundtrip.rs` - calls the exported functions directly as Rust
  (not through the Kotlin/Swift FFI boundary, which nothing here can drive).

Unlike the Python and Node.js bindings, every function here is **synchronous**.
There is no single native async runtime shared by Kotlin coroutines and
Swift's `async`/`await`, so wrapping these in `AsyncTask`/`allow_threads`-style
machinery would mean picking one platform's async model over the other for no
real benefit - callers are expected to invoke these from a background
thread/coroutine themselves (`withContext(Dispatchers.IO) { ... }` on Android,
`Task { ... }` or `DispatchQueue.global()` on iOS), exactly as they already
would for any other blocking native call.

## Building and generating bindings (verified on this machine)

```sh
cargo build --release
cargo run --release --bin uniffi-bindgen -- generate \
    --library target/release/pqfile_mobile.dll \
    --language kotlin --out-dir bindings/kotlin
cargo run --release --bin uniffi-bindgen -- generate \
    --library target/release/pqfile_mobile.dll \
    --language swift --out-dir bindings/swift
```

(Substitute `libpqfile_mobile.so` / `libpqfile_mobile.dylib` for `.dll` on
Linux/macOS.) `bindings/` is gitignored - it's tied to the FFI checksum of
whatever you just built, so regenerate it rather than trusting a stale copy.

## Packaging (not done yet - needs a machine with the right SDKs)

**Android**: install [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) and the
`aarch64-linux-android` / `armv7-linux-androideabi` / `x86_64-linux-android`
targets, cross-compile a `.so` per ABI into `jniLibs/<abi>/`, and wrap the
generated `bindings/kotlin/uniffi/pqfile_mobile/pqfile_mobile.kt` plus those
`.so` files in a Gradle library module for Maven publishing.

**iOS**: on macOS with Xcode installed, cross-compile for
`aarch64-apple-ios` (device) and `aarch64-apple-ios-sim`/`x86_64-apple-ios`
(simulator), combine them into an XCFramework
(`xcodebuild -create-xcframework`) alongside
`bindings/swift/pqfile_mobile.swift` and the generated `.h`/`.modulemap`, and
distribute via Swift Package Manager.

## Scope

This wraps `pqfile::encrypt`/`pqfile::decrypt`'s single-recipient streaming
path only (`keygen`/`keygen_hybrid`/`encrypt_bytes`/`decrypt_bytes`/`encrypt_file`/`decrypt_file`),
matching the Python and Node.js bindings. Multi-recipient encryption,
signing/`signcrypt`, Shamir sharing, and certificates are not yet exposed
here - see `docs/ROADMAP.md`, "Python, Node.js, and mobile bindings", for
status.

## Compatibility

Produces and reads the same `.pqf` wire format as the CLI, GUI, and the
Python/Node.js bindings (see `docs/FORMAT.md`), so files are interchangeable
in every direction.
