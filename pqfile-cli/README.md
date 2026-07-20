# pqfile-cli

Command-line interface for [`pqfile`](../pqfile), the quantum-resistant file encryption
library. Published to crates.io as [`pqfile-cli`](https://crates.io/crates/pqfile-cli)
(`cargo install pqfile-cli`); prebuilt binaries are also on the
[GitHub releases page](https://github.com/dangel34/PQ-File-Encryption/releases/latest), or
build it from source:

```sh
cargo build --release -p pqfile-cli
```

For usage (keygen, encrypt, decrypt, sign, archive, and every other subcommand), see the
root [README.md](../README.md) and [docs/QUICKSTART.md](../docs/QUICKSTART.md). `pqfile --help`
and `pqfile <subcommand> --help` are also authoritative. `pqfile completions <shell>` and
`pqfile man` generate a shell completion script and a roff man page respectively.

The `fido2` Cargo feature (off by default) adds `fido2-enroll` / `--fido2` support for
FIDO2 hardware security keys as a v10 passphrase second factor; it pulls in `libudev-dev`
on Linux, so it stays opt-in.

The `stego` Cargo feature (off by default) adds `bury` / `exhume` support for hiding a
file inside a cover image's pixel data under a passphrase that keys detection itself;
it pulls in the `image` crate's PNG/JPEG codecs plus `blake3`, so it stays opt-in.

The `tlock` Cargo feature (off by default) adds `tlock round` / `encrypt --tlock-round` /
`decrypt --tlock` support for time-locked encryption against a drand beacon; it pulls in
the only network-capable dependencies in the workspace, so it stays opt-in.

The `update-check` Cargo feature (off by default, but compiled into the published release
binaries) adds the `check-update` subcommand, which queries the GitHub Releases API and
reports whether a newer version exists; it never runs unless invoked explicitly.
