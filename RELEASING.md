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

## Step 1 — Bump versions

Edit the version in all of the following files:

| File | Field |
|---|---|
| `pqfile/Cargo.toml` | `version` |
| `pqfile-gui/Cargo.toml` | `version` |
| `pqfile-desktop/Cargo.toml` | `version` |
| `pqfile-gui/src/lib.rs` | `APP_VERSION` constant |
| `pqfile-desktop/packaging/setup.iss` | `AppVersion` |
| `pqfile/packaging/pqfile.spec` | `Version` + add a `%changelog` entry |
| `sonar-project.properties` | `sonar.projectVersion` |

Then regenerate the lock file:

```
cargo build --workspace
```

---

## Step 2 — Commit and tag

```
git add pqfile/Cargo.toml pqfile-gui/Cargo.toml pqfile-desktop/Cargo.toml Cargo.lock
git commit -m "chore: bump version to X.Y.Z"
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

Pushing `main` triggers the SonarQube analysis. Wait for it to pass before proceeding.

---

## Step 3 — Build release artifacts

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

## Step 4 — Create the GitHub Release

1. Go to **Releases → Draft a new release** on GitHub.
2. Select the tag `vX.Y.Z` you just pushed.
3. Set the release title to `vX.Y.Z`.
4. Write release notes (what changed since the last release).
5. Upload the artifacts you built in Step 3:
   - `pqfile` / `pqfile.exe`
   - `pqfile-desktop` / `pqfile-desktop.exe`
   - `pqfile_X.Y.Z_amd64.deb` (if built)
6. Click **Publish release**.

---

## Step 5 — Web GUI deployment

The GitHub Pages deployment is **automatic**. Pushing to `main` (Step 2) triggers `.github/workflows/pages.yml`, which builds the WASM app with trunk and deploys it to GitHub Pages at:

```
https://dangel34.github.io/PQ-File-Encryption/
```

No manual action is needed. You can monitor the deployment in the **Actions** tab. If you need to redeploy without a code change, use the **Run workflow** button on the `Deploy to GitHub Pages` workflow.

---

## After the release

- Confirm the SonarQube badge still shows passing.
- Verify the GitHub Release page shows the correct assets and tag.
- Smoke-test the downloaded binary: generate a key pair, encrypt a file, decrypt it.
