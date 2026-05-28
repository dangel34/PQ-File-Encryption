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

All three crates (`pqfile`, `pqfile-gui`, `pqfile-desktop`) are versioned together and always share the same version number.

---

## Step 1 - Bump versions, commit, and tag

Run the script from the repo root:

```powershell
pwsh -ExecutionPolicy Bypass -File .\bump-version.ps1  X.Y.Z
```

Optionally include a one-line RPM changelog summary (defaults to "Version bump"):

```powershell
pwsh -ExecutionPolicy Bypass -File .\bump-version.ps1  X.Y.Z -SpecChangelog "Fix foo and bar"
```

The script does the following automatically, aborting early if anything fails:

1. **Pre-flight**: verifies you are on `main` with a clean working tree.
2. **Tests**: runs `cargo test --workspace`; the bump will not proceed if any test fails.
3. **Version replacements**: updates all version fields across the codebase (`Cargo.toml` package versions, inter-crate dependency version constraints, `APP_VERSION` constant, `Formula/pqfile.rb`, Inno Setup `.iss`, RPM `.spec` version + changelog entry).
4. **Lock file**: regenerates `Cargo.lock` via `cargo build --workspace`.
5. **Commit, tag, push**: creates a `chore: bump version to X.Y.Z` commit, tags it `vX.Y.Z`, and pushes both to `origin`.

---

## Step 2 - Wait for CI

Pushing to `main` and the tag triggers two workflows in parallel:

### Release workflow (`.github/workflows/release.yml`)

Triggered by the `vX.Y.Z` tag. Runs the following jobs in order:

1. Version consistency check across all `Cargo.toml`, `lib.rs`, `.iss`, and `.spec`.
2. Full test suite (with Cargo cache).
3. Multi-platform builds: Linux x86_64, macOS x86_64, macOS arm64, Windows x86_64 (CLI + desktop GUI).
4. Windows installer via Inno Setup.
5. WASM web app build, archived as `pqfile-web.tar.gz`.
6. SHA-256 checksums for all artifacts + CycloneDX SBOMs (`sbom-pqfile.cdx.json`, `sbom-pqfile-gui.cdx.json`, `sbom-pqfile-desktop.cdx.json`).
7. Creates a **draft** GitHub release with all artifacts attached via the GitHub API.
8. Deploy job (runs on the self-hosted Raspberry Pi runner after the release is created): downloads the WASM artifact, rsyncs it to `/var/www/pqfile/`, and purges the Cloudflare cache.

Monitor progress in the **Actions** tab on GitHub. Once complete, open the draft release on GitHub (`https://github.com/dangel34/PQ-File-Encryption/releases`), review the auto-generated notes, and click **Publish release**. The deploy job runs automatically and requires no manual action.

---

## After the release

- Verify the GitHub Release page shows the correct assets and tag (including `sbom-*.cdx.json`).
- Verify `checksums.txt` lists all expected files and SHA-256 hashes are correct.
- Smoke-test the downloaded binary: generate a key pair, encrypt a file, decrypt it.

---

## Publishing to crates.io

This section covers publishing the `pqfile` library and `pqfile-cli` binary to crates.io. It is independent of the GitHub release workflow and requires no CI minutes.

### Pre-flight

1. **Commit all changes locally.** Cargo 1.73+ refuses to publish a crate with uncommitted changes to git-tracked files. Cargo only checks the local git state — you do **not** need to push before publishing. Push to GitHub separately once your Actions minutes are available.

   ```powershell
   git add -p          # stage selectively
   git commit -m "chore: prepare 3.2.0 for crates.io"
   # do NOT push yet if you want to avoid triggering CI
   ```

2. **Log in to crates.io** (one-time; your token is cached in `~/.cargo/credentials.toml`):

   ```powershell
   cargo login
   ```

   Paste your API token from <https://crates.io/settings/tokens>.

### Step 1 — Dry run

Always run a dry run first. It packages the crate, validates metadata, and reports any missing files without actually uploading anything.

```powershell
cargo publish --dry-run -p pqfile
```

Common things caught by dry run:
- Missing `LICENSE` file (now present at the repo root).
- `readme` path (`../README.md`) not resolving — cargo will warn if the file is outside the crate directory. If this fails, copy `README.md` into `pqfile/` or change the path to a relative one inside the crate.
- `documentation` URL set to `https://docs.rs/pqfile` — docs.rs builds automatically after publish; no action needed.

### Step 2 — Publish the library

```powershell
cargo publish -p pqfile
```

Wait 30–60 seconds for the index to propagate before publishing the CLI (which depends on `pqfile`).

### Step 3 — Publish the CLI

```powershell
cargo publish -p pqfile-cli
```

`pqfile-cli` depends on `pqfile = { workspace = true }`, which resolves to the crates.io version once `pqfile` is indexed. If cargo reports "no matching version", wait another minute and retry.

### What not to publish

Do **not** publish `pqfile-gui` or `pqfile-desktop` — they require system GUI libraries (GTK, X11) and are not useful as library crates. The WASM web app is deployed separately via the release workflow.

### Verifying the publish

- `pqfile`: <https://crates.io/crates/pqfile>
- `pqfile-cli`: <https://crates.io/crates/pqfile-cli>
- docs.rs page (auto-built within a few minutes): <https://docs.rs/pqfile>
