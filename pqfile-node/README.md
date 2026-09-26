# pqfile (Node.js bindings)

Node.js bindings for [`pqfile`](https://github.com/dangel34/PQ-File-Encryption), a
quantum-resistant file encryption library: ML-KEM (512/768/1024) and hybrid
X25519+ML-KEM-768 key encapsulation with ChaCha20-Poly1305 authenticated
encryption. Built with [napi-rs](https://napi.rs); the crypto itself lives
entirely in the `pqfile` Rust crate, not in this binding layer.

Every function returns a `Promise` and runs on libuv's worker thread pool
(napi-rs's `AsyncTask`), not on Node's main thread - Argon2id key derivation
and ML-KEM operations are CPU-heavy enough that running them inline would
block the event loop for the duration.

## Install

```sh
npm install @dangel34/pqfile
```

Published on npm as [`@dangel34/pqfile`](https://www.npmjs.com/package/@dangel34/pqfile)
(the unscoped name `pqfile` is blocked - npm treats it as too similar to the
existing `vfile` package). Prebuilt binary currently available for Windows
x64 only; macOS/Linux installs will get no working native binary until those
platform packages are bootstrapped (see "CI and publishing" below).

To build from source instead (e.g. to work on the bindings themselves):

```sh
npm install
npm run build
```

## Quick start

```js
const pqfile = require("@dangel34/pqfile");

// Generate a key pair
const { publicKey, privateKey } = await pqfile.keygen(); // level defaults to 768; also 512, 1024

// Encrypt / decrypt in memory
const ciphertext = await pqfile.encryptBytes(publicKey, Buffer.from("hello, post-quantum world"));
const plaintext = await pqfile.decryptBytes(privateKey, ciphertext);
console.log(plaintext.toString()); // "hello, post-quantum world"

// Encrypt / decrypt files directly (streams; flat memory use regardless of size)
await pqfile.encryptFile(publicKey, "report.pdf", "report.pdf.pqf");
await pqfile.decryptFile(privateKey, "report.pdf.pqf", "report.pdf");
```

A passphrase-protected private key:

```js
const { publicKey, privateKey } = await pqfile.keygen(undefined, "correct horse battery staple");
const plaintext = await pqfile.decryptBytes(privateKey, ciphertext, "correct horse battery staple");
```

Hybrid X25519 + ML-KEM-768 (defense in depth against a future ML-KEM break):

```js
const { publicKey, privateKey } = await pqfile.keygenHybrid();
```

## Errors

Failures reject the returned `Promise` with an `Error` whose message has the
stable numeric error code from
[`docs/ERROR_CODES.md`](../docs/ERROR_CODES.md) appended, e.g.
`decryption failure: authentication tag mismatch (code 7)`.

## Scope

This wraps `pqfile::encrypt`/`pqfile::decrypt`'s single-recipient streaming
path only (`keygen`/`keygenHybrid`/`encryptBytes`/`decryptBytes`/`encryptFile`/`decryptFile`).
Multi-recipient encryption, signing/`signcrypt`, Shamir sharing, certificates,
and the other CLI features are not yet exposed here - see
`docs/ROADMAP.md`, "Python, Node.js, and mobile bindings", for status.

## Compatibility

Produces and reads the same `.pqf` v3/v5 wire format as the `pqfile` CLI and
GUI (see `docs/FORMAT.md`), so files are interchangeable in both directions.

## CI and publishing

`ci.yml`'s `bindings-node` job builds this crate and runs the test suite on
every push/PR. `publish-node.yml` cross-builds the native addon for
Windows/Linux x64 and macOS (x86_64 and aarch64), arranges them into
napi-rs's standard per-platform `optionalDependencies` packages
(`napi create-npm-dirs`/`napi artifacts`, driven by `napi.targets` in
`package.json`), and publishes each of them plus the main `@dangel34/pqfile`
package with plain `npm publish` on a GitHub Release being published, via npm
Trusted Publishing (OIDC) - no stored token anywhere.

**Versioning**: since 4.3.5 the package is versioned in lockstep with the core
`pqfile` crate. `scripts/bump-version.ps1` bumps `package.json` (including
every `optionalDependencies` pin), `package-lock.json`, `Cargo.toml`/`Cargo.lock`,
and the version checks embedded in `index.js`, and both `release.yml` and
`publish-node.yml` fail if any of them disagree with the release tag. Before
that the package sat at `0.1.0`, so the v4.3.3 and v4.3.4 publish runs both
stopped at the "already on npm" guard and nothing new was ever published.

**Bootstrap history**: `@dangel34/pqfile` and `@dangel34/pqfile-win32-x64-msvc`
0.1.0 were published by hand for v4.3.3 (2026-07-24), since npm's Trusted
Publisher (unlike PyPI's "pending publisher") can only be configured from an
*already-existing* package's settings page: a one-off, interactive
`npm publish` per package from a maintainer's own npm login (an automated
`npm publish` can't complete npm's browser-based OTP challenge). That bootstrap
also forced the rename from the unscoped `pqfile` (rejected as too similar to
the existing `vfile` package, and separately hit npm's spam-detection
heuristic on the platform-specific name) to the scoped `@dangel34/pqfile`.

**Still open**: the other three platform packages (`@dangel34/pqfile-darwin-x64`,
`@dangel34/pqfile-darwin-arm64`, `@dangel34/pqfile-linux-x64-gnu`) don't exist
yet - each needs the same one-off manual bootstrap publish before CI can take
over publishing it; until then `publish-node.yml` skips them with a warning
rather than failing the release. No Mac or Linux machine is needed for that:
download the `bindings-<target>` artifact from any `publish-node.yml` run, drop
the `.node` file into the matching `npm/<platform>/` directory created by
`napi create-npm-dirs`, and `npm publish` it from there. Until then,
`npm install @dangel34/pqfile` on macOS/Linux succeeds but has no working
native binary (a soft `optionalDependencies` failure, not a hard install
error). `aarch64-unknown-linux-gnu` is deliberately left out of `napi.targets`
for now - cross-compiling it needs a zig toolchain step (`napi build --zig`)
this hasn't been wired up for.
