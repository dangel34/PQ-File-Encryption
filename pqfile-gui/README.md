# pqfile-gui

Shared [egui](https://github.com/emilk/egui) GUI for [`pqfile`](../pqfile), built as a
library crate so it can back two different shells: the native desktop app in
[`pqfile-desktop`](../pqfile-desktop), and a WASM web build. It is not published to
crates.io.

Build the native desktop app:

```sh
cargo run --release -p pqfile-desktop
```

Build the WASM web app (requires `trunk`):

```sh
trunk build --release
```

See the root [README.md](../README.md) for a feature overview and
[docs/QUICKSTART.md](../docs/QUICKSTART.md) for deployment instructions. The `fido2` Cargo
feature (always on for `pqfile-desktop`, unavailable on `wasm32` since there is no browser
HID API) adds hardware security key support as a v10 passphrase second factor.
