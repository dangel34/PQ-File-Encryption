# Releasing pqfile

This document covers the end-to-end steps for cutting a new release.

---

## Version numbering

The project uses semantic versioning (`MAJOR.MINOR.PATCH`).

| Change type | Example |
|---|---|
| Breaking change to the `.pqf` format or key format | 2.0.0 |
| New feature (new CLI subcommand, new GUI tab, new library function) | 1.1.0 |
| Bug fix or internal refactor with no user-visible change | 1.0.2 |

All three crates (`pqfile`, `pqfile-gui`, `pqfile-desktop`) are versioned together and should always share the same version number.

---

## Pre-release checklist

- [ ] All tests pass locally: `cargo test --workspace`
- [ ] No SonarQube issues you intend to fix before release (check the badge in README)
- [ ] README is up to date with any new features or changed behaviour
- [ ] You are on the `main` branch with a clean working tree

---

## Step 1 — Bump versions, commit, and tag

Run the script from the repo root:

```powershell
.\bump-version.ps1 X.Y.Z
```

Optionally include a one-line RPM changelog summary (defaults to "Version bump"):

```powershell
.\bump-version.ps1 X.Y.Z -SpecChangelog "Fix foo and bar"
```

The script updates all version fields across the codebase, regenerates `Cargo.lock`, commits, tags, and pushes to `main` automatically.

Pushing `main` triggers the SonarQube analysis. Wait for it to pass before proceeding.

---

## Step 2 — Build release artifacts

Run all builds from the repository root.

### CLI binary

```
cargo build --release -p pqfile
```

Output: `target/release/pqfile` (Linux/macOS) or `target/release/pqfile.exe` (Windows)

### Native desktop GUI

```
cargo build --release -p pqfile-desktop
```

Output: `target/release/pqfile-desktop` (Linux/macOS) or `target/release/pqfile-desktop.exe` (Windows)

### Web GUI (WASM)

```
rustup target add wasm32-unknown-unknown   # one-time setup
cargo install trunk                        # one-time setup

cd pqfile-gui
trunk build --release
```

Output: `pqfile-gui/dist/` — a self-contained static folder ready to deploy.

### Debian package (optional)

```
cargo install cargo-deb   # one-time setup
cargo deb -p pqfile
```

Output: `target/debian/pqfile_X.Y.Z_amd64.deb`

### RPM package (optional)

```
cargo build --release -p pqfile
cp target/release/pqfile ~/rpmbuild/BUILD/
rpmbuild -bb pqfile/packaging/pqfile.spec
```

---

## Step 3 — Wait for the release workflow

Pushing the tag triggers `.github/workflows/release.yml`, which:

1. Runs the full test suite.
2. Builds CLI and desktop GUI binaries for all four platforms (Linux x86_64, macOS x86_64, macOS arm64, Windows x86_64).
3. Builds the Windows installer via Inno Setup.
4. Builds the WASM web app with trunk and archives it as `pqfile-web.tar.gz`.
5. Generates a `checksums.txt` (SHA-256) covering all artifacts.
6. Creates a **draft** GitHub release with all artifacts attached.

Monitor progress in the **Actions** tab. Once the workflow completes, open the draft release, review the auto-generated notes, and click **Publish release**.

---

## Step 4 — Web GUI deployment

Deployment is **automatic**. Pushing to `main` (Step 1) triggers `.github/workflows/deploy.yml`, which:

1. Builds the WASM app on the self-hosted Raspberry Pi runner.
2. Rsyncs `pqfile-gui/dist/` to `/var/www/pqfile/` with `--delete`.
3. Purges the Cloudflare cache (`purge_everything`) so visitors immediately get the new build.

No manual action is needed. Monitor progress in the **Actions** tab.

---

## After the release

- Confirm the SonarQube badge still shows passing.
- Verify the GitHub Release page shows the correct assets and tag.
- Smoke-test the downloaded binary: generate a key pair, encrypt a file, decrypt it.
