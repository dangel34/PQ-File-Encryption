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

## Install (from source, until prebuilt binaries are published)

```sh
npm install
npm run build
```

Published on npm as `@dangel34/pqfile` (the unscoped name `pqfile` is blocked -
npm treats it as too similar to the existing `vfile` package).

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
every push/PR. `publish-node.yml` is scaffolding for the actual npm release -
it cross-builds the native addon for Windows/Linux x64 and macOS
(x86_64 and aarch64), arranges them into napi-rs's standard per-platform
`optionalDependencies` packages (`napi create-npm-dir`/`napi artifacts`), and
would publish all of them plus the main `@dangel34/pqfile` package
(`napi prepublish`) on a GitHub Release being published. The `artifacts`
step's file-matching convention has been verified locally (a fake downloaded
artifact directory was correctly picked up and copied into place). It
publishes via npm Trusted Publishing (OIDC) rather than a stored token, which
needs npm's Trusted Publisher registered on the `@dangel34/pqfile` package
first (npmjs.com -> package -> Settings -> Trusted Publisher) - GitHub
Actions, owner `dangel34`, repository `PQ-File-Encryption`, workflow
`publish-node.yml`, environment `release`. Unlike PyPI's "pending publisher,"
npm's Trusted Publisher is configured from an *existing* package's own
settings page, so the very first publish needed to happen some other way: a
manual, interactive `npm publish` per package (`napi prepublish`'s automated
flow can't complete npm's browser-based OTP challenge, since it shells out to
`npm publish` as a non-interactive subprocess). Two more npm-side blocks
turned up doing that bootstrap publish, both unrelated to anything in this
repo: the unscoped name `pqfile` was rejected as too similar to the existing
`vfile` package (fixed by scoping to `@dangel34/pqfile`, npm's own suggested
remedy - `publishConfig.access: "public"` was added so a scoped package still
publishes publicly by default), and the platform-specific package name
`pqfile-win32-x64-msvc` was separately rejected by npm's spam-detection
heuristic before the rename (unresolved as of this writing - the scoped
equivalent, `@dangel34/pqfile-win32-x64-msvc`, has not yet been retried). The
macOS/Linux legs of the build matrix have only ever been cross-checked by
reading napi-rs's own source, not built on this repo's Windows dev machine.
`aarch64-unknown-linux-gnu` is deliberately left out of `napi.triples` for
now - cross-compiling it needs a zig toolchain step (`napi build --zig`) this
hasn't been wired up for.
