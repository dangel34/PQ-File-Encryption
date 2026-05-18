# pqfile - Quick Start

Get up and running in a few minutes. For full reference documentation see [README.md](README.md).

---

## Install

Requires Rust 1.74 or later.

```
git clone <repo>
cd PQ-File-Encryption
```

### CLI only

```
cargo build --release -p pqfile
```

Binary lands at `target/release/pqfile`. To install to your Cargo bin directory:

```
cargo install --path pqfile
```

### Native GUI

```
cargo build --release -p pqfile-desktop
./target/release/pqfile-desktop
```

### Web GUI (WASM)

```
rustup target add wasm32-unknown-unknown   # one-time
cargo install trunk                        # one-time

cd pqfile-gui
trunk build --release
```

Output goes to `pqfile-gui/dist/`. Serve that folder with any static host.

---

## CLI - Common workflow

### 1. Generate a key pair

```
pqfile keygen --out ./keys/
```

Writes `pubkey.pem` and `privkey.pem` to the directory. Share `pubkey.pem` freely; keep `privkey.pem` private.

```
Keys written to ./keys/
Public key fingerprint: e2:a3:43:ab:78:8a:64:f3
```

Use `--force` to overwrite existing keys. Use `--passphrase` to encrypt the private key at rest (prompts interactively):

```
pqfile keygen --out ./keys/ --passphrase
```

### 2. Encrypt a file

```
pqfile encrypt -r ./keys/pubkey.pem secret.txt
```

Produces `secret.txt.pqf` alongside the original. Use `-o` for a custom output path:

```
pqfile encrypt -r pubkey.pem secret.txt -o /tmp/out.pqf
```

### 3. Decrypt a file

```
pqfile decrypt -k ./keys/privkey.pem secret.txt.pqf
```

Produces `secret.txt` (`.pqf` extension stripped). Use `-o` for a custom output path:

```
pqfile decrypt -k privkey.pem secret.txt.pqf -o recovered.txt
```

If the private key is passphrase-protected, you are prompted automatically. If the file has been tampered with, decryption fails with an authentication error and writes no output.

### 4. Inspect an encrypted file (no decryption)

```
pqfile inspect secret.txt.pqf
```

```
Magic:              PQFL
Version:            0x02
KEM variant:        768
Nonce:              a3f09c12de87b64c01e5a920
Original file size: 2048 bytes
```

---

## CLI - Shell completions

`pqfile completions <shell>` prints a completion script. Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

**Bash**
```bash
pqfile completions bash >> ~/.bash_completion
```

**Zsh** (place in a directory on your `$fpath`)
```zsh
pqfile completions zsh > ~/.zfunc/_pqfile
# Add to ~/.zshrc if ~/.zfunc is not already on fpath:
#   fpath=(~/.zfunc $fpath); autoload -Uz compinit && compinit
```

**Fish**
```fish
pqfile completions fish > ~/.config/fish/completions/pqfile.fish
```

**PowerShell**
```powershell
pqfile completions powershell >> $PROFILE
```

---

## GUI - Overview

The GUI has five tabs and behaves identically on native and web, except that the web version downloads output files to the browser's downloads folder instead of writing them to disk. Files can be loaded via the Browse buttons or by dragging and dropping onto the window.

| Tab | What it does |
|---|---|
| **Keygen** | Generate a key pair and save (native) or download (web) the PEM files |
| **Encrypt** | Load a public key + plaintext file, produce a `.pqf` encrypted file |
| **Decrypt** | Load a private key + `.pqf` file, recover the original file |
| **Inspect** | View the header of a `.pqf` file without decrypting it |
| **Settings** | Toggle dark/light theme, auto-clear inputs, overwrite protection |

---

## Deploying the web GUI

After `trunk build --release` inside `pqfile-gui/`, the `dist/` folder is a self-contained static site.

### Self-hosted (automated via CI)

Pushing a version tag (via `bump-version.ps1`) triggers `.github/workflows/deploy.yml`, which builds on the self-hosted runner and rsyncs `pqfile-gui/dist/` to `/var/www/pqfile/` with `--delete`. See [NGINX_DEPLOYMENT.md](NGINX_DEPLOYMENT.md) for the nginx configuration.

### Cloudflare Pages / Netlify / Vercel

Point the build output directory to `pqfile-gui/dist/`. Set the build command to:

```
cargo install trunk && rustup target add wasm32-unknown-unknown && trunk build --release
```

### Nginx / Apache (manual)

```
cp -r pqfile-gui/dist/* /var/www/html/
```

> All cryptographic operations run entirely in the browser via WebAssembly. No file data is sent to any server.

---

## Running the tests

```
cargo test --workspace
```

For a coverage report:

```
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --open
```
