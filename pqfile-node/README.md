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
(`napi create-npm-dir`/`napi artifacts`), and publishes all of them plus the
main `@dangel34/pqfile` package on a GitHub Release being published, via npm
Trusted Publishing (OIDC) - no stored token anywhere.

**Status as of the `v4.3.3` release (2026-07-24)**: `@dangel34/pqfile` and
`@dangel34/pqfile-win32-x64-msvc` are published and live on npm. Getting there
needed a manual bootstrap first, since npm's Trusted Publisher (unlike
PyPI's "pending publisher") can only be configured from an *already-existing*
package's settings page: a one-off, interactive `npm publish` per package
from a maintainer's own npm login (`napi prepublish`'s own automated flow
can't complete npm's browser-based OTP challenge, since it shells out to
`npm publish` as a non-interactive subprocess). That bootstrap is also what
surfaced two real bugs, both fixed: the package needed renaming from the
unscoped `pqfile` (rejected as too similar to the existing `vfile` package,
and separately hit npm's spam-detection heuristic on the platform-specific
name) to the scoped `@dangel34/pqfile` - npm's own suggested remedy, which
resolved both issues at once; and `napi prepublish` turned out to only ever
publish the per-platform packages in its internal loop, never the root
package itself, so `publish-node.yml` gained an explicit `npm publish` step
after it.

**Still open**: the other three platform packages (`@dangel34/pqfile-darwin-x64`,
`@dangel34/pqfile-darwin-arm64`, `@dangel34/pqfile-linux-x64-gnu`) don't exist
yet - each needs the same one-off manual bootstrap publish from a machine
that can actually build for that platform before CI can take over publishing
it automatically. Until then, `npm install @dangel34/pqfile` on macOS/Linux
succeeds but has no working native binary (a soft `optionalDependencies`
failure, not a hard install error). The macOS/Linux legs of the *build*
matrix (as opposed to publish) have only ever been cross-checked by reading
napi-rs's own source, not built on this repo's Windows dev machine.
`aarch64-unknown-linux-gnu` is deliberately left out of `napi.triples` for
now - cross-compiling it needs a zig toolchain step (`napi build --zig`) this
hasn't been wired up for.
