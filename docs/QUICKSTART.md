# pqfile - Quick Start

Get up and running in a few minutes. For full reference documentation see [README.md](../README.md).

---

## Install

### Pre-built binaries

Download the latest release from the [Releases page](https://github.com/dangel34/PQ-File-Encryption/releases). Available archives:

| File | Platform |
|------|----------|
| `pqfile-x86_64-unknown-linux-gnu` | Linux x86-64 |
| `pqfile-x86_64-apple-darwin` | macOS Intel |
| `pqfile-aarch64-apple-darwin` | macOS Apple Silicon |
| `pqfile-x86_64-pc-windows-msvc.exe` | Windows x86-64 (CLI) |
| `pqfile-setup-{version}.exe` | Windows installer (GUI + CLI) |

Verify the download against `checksums.txt` (SHA-256):

```bash
sha256sum --check --ignore-missing checksums.txt
```

### Build from source

Requires Rust 1.74 or later.

```
git clone https://github.com/dangel34/PQ-File-Encryption
cd PQ-File-Encryption
```

**CLI only**

```
cargo build --release -p pqfile
```

Binary lands at `target/release/pqfile`. To install to your Cargo bin directory:

```
cargo install --path pqfile
```

**Native GUI**

```
cargo build --release -p pqfile-desktop
./target/release/pqfile-desktop
```

**Web GUI (WASM)**

```
rustup target add wasm32-unknown-unknown   # one-time
cargo install trunk                        # one-time

cd pqfile-gui
trunk build --release
```

Output goes to `pqfile-gui/dist/`. Serve that folder with any static host.

---

## CLI - Common workflow

The fastest start of all: run `pqfile` with no arguments. An interactive mode walks you through encrypting, decrypting, or generating a key pair with guided prompts, using the same code paths as the commands below. The rest of this section covers the flag-driven equivalents, which are what you want for scripts.

### 1. Generate a key pair

```
pqfile keygen --out ./keys/
```

Writes `pubkey.pem` and `privkey.pem` to the directory. Share `pubkey.pem` freely; keep `privkey.pem` private.

```
Keys written to ./keys/
Public key fingerprint: e2:a3:43:ab:78:8a:64:f3
```

Use `--force` to overwrite existing keys. Use `--passphrase` to encrypt the private key at rest (prompts interactively with confirmation):

```
pqfile keygen --out ./keys/ --passphrase
```

The passphrase option is also available in the GUI keygen tab via the "Protect private key with a passphrase" checkbox.

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
Version:            0x85
KEM variant:        768
Nonce:              a3f09c12de87b64c01e5a920
Original file size: 2048 bytes
Chunk size:         16384
Auth. header:       yes
```

Small files (under 1 MiB) now use a 16 KiB chunk size automatically when no `--chunk-size` flag is given, producing v5 format. Pass `--chunk-size 65536` to force v3. The high bit of the version byte (`0x85` = v5 layout) marks an authenticated header; files written by pqfile 4.2.4 and earlier show the plain version byte and `Auth. header: no`.

### 5. Diagnose a key or ciphertext file

```
pqfile doctor ./keys/privkey.pem
```

```
File:              ./keys/privkey.pem
Type:              private key
Encrypted:         false
Hardware-backed:   false
Legacy Argon2 p=1: false
Revocation:        not_checked
```

```
pqfile doctor secret.txt.pqf
```

```
File:         secret.txt.pqf
Type:         .pqf ciphertext
Version:      0x05
KEM info:     ML-KEM-768
Orig size:    2048 bytes
Header:       valid
```

Use `--json` for machine-readable output.

### 6. Pipe via stdin / stdout

Pass `-` as the input file to read from stdin, and omit `-o` (or pass `-o -`) to write to stdout. This enables composability with other tools:

```bash
# Encrypt from stdin, write to file
cat secret.txt | pqfile encrypt -r pubkey.pem - > out.pqf

# Decrypt from stdin, write to stdout (pipe into another command)
cat out.pqf | pqfile decrypt -k privkey.pem - | gpg --encrypt > double-wrapped.gpg

# Encrypt and pipe directly to a remote host
cat secret.txt | pqfile encrypt -r pubkey.pem - | ssh user@host 'cat > secret.pqf'
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

The GUI behaves identically on native and web, except that the web version downloads output files to the browser's downloads folder instead of writing them to disk. Files can be loaded via the Browse buttons or by dragging and dropping onto the window.

| Tab | What it does |
|---|---|
| **Keys** | Persistent registry of named key pairs with fingerprints and quick-load buttons for the Encrypt and Decrypt tabs, plus passphrase change and key revocation (native only) |
| **Keygen** | Generate an encryption or signing key pair and save (native) or download (web) the PEM files. Optional passphrase checkbox encrypts the private key at rest. |
| **Encrypt** | Load a public key + plaintext files, produce `.pqf` encrypted files; optional compression, length padding, and stealth mode |
| **Decrypt** | Load a private key + `.pqf` file, recover the original file. A passphrase field appears automatically when an encrypted private key is loaded. Includes a Rekey sub-tab. |
| **Sign / Signcrypt** | Detached signatures (ML-DSA-65 or SLH-DSA-SHAKE-192f) and combined sign-then-encrypt |
| **Archive** | Pack multiple files into one encrypted `.pqf` container and extract it |
| **Shamir** | Split a private key into M-of-N shares and reconstruct it |
| **Inspect** | View the header of a `.pqf` file, or health-check a key file, without decrypting |
| **Clipboard** | Encrypt/decrypt short text snippets without touching disk |
| **Settings** | Toggle dark/light theme, auto-clear inputs, overwrite protection |

See the [README GUI section](../README.md#gui) for the full per-tab feature list.

---

## Deploying the web GUI

After `trunk build --release` inside `pqfile-gui/`, the `dist/` folder is a self-contained static site.

### Self-hosted (automated via CI)

Running `bump-version.ps1` pushes a version tag, which triggers `.github/workflows/release.yml`. After the GitHub release is created, a deploy job runs on the self-hosted Raspberry Pi runner: it downloads the already-built WASM artifact and rsyncs it to `/var/www/pqfile/` with `--delete`. See [NGINX_DEPLOYMENT.md](NGINX_DEPLOYMENT.md) for the nginx configuration.

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
