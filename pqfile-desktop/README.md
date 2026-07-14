# pqfile-desktop

Native desktop binary for [`pqfile`](../pqfile): a thin `eframe` shell around the shared
GUI in [`pqfile-gui`](../pqfile-gui), with the `fido2` feature always enabled (hardware
security key support). Not published to crates.io.

```sh
cargo build --release -p pqfile-desktop
```

Prebuilt binaries for Windows, macOS, and Linux are published on the
[GitHub releases page](https://github.com/dangel34/PQ-File-Encryption/releases/latest). See
the root [README.md](../README.md) and [docs/QUICKSTART.md](../docs/QUICKSTART.md) for more.
