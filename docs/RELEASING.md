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
3. **Version replacements**: updates all version fields across the codebase (`Cargo.toml` package versions, inter-crate dependency version constraints, `APP_VERSION` constant, `Formula/pqfile.rb`, Inno Setup `.iss`, `sonar-project.properties`, RPM `.spec` version + changelog entry).
4. **Lock file**: regenerates `Cargo.lock` via `cargo build --workspace`.
5. **Commit, tag, push**: creates a `chore: bump version to X.Y.Z` commit, tags it `vX.Y.Z`, and pushes both to `origin`.

---

## Step 2 - Wait for CI

Pushing to `main` and the tag triggers two workflows in parallel:

### Release workflow (`.github/workflows/release.yml`)

Triggered by the `vX.Y.Z` tag. Runs the following jobs in order:

1. Version consistency check across all `Cargo.toml`, `lib.rs`, `.iss`, `.spec`, and `sonar-project.properties`.
2. Full test suite (with Cargo cache).
3. Multi-platform builds: Linux x86_64, macOS x86_64, macOS arm64, Windows x86_64 (CLI + desktop GUI).
4. Windows installer via Inno Setup.
5. WASM web app build, archived as `pqfile-web.tar.gz`.
6. SHA-256 checksums for all artifacts + CycloneDX SBOMs (`sbom-pqfile.cdx.json`, `sbom-pqfile-gui.cdx.json`, `sbom-pqfile-desktop.cdx.json`).
7. Cosign keyless signing of `checksums.txt` into `checksums.txt.bundle` (verifiable without a key via the sigstore transparency log).
8. Creates a **draft** GitHub release with all artifacts attached.
9. Deploy job (runs on the self-hosted Raspberry Pi runner after the release is created): downloads the WASM artifact, rsyncs it to `/var/www/pqfile/`, and purges the Cloudflare cache.

Monitor progress in the **Actions** tab. Once complete, open the draft release, review the auto-generated notes, and click **Publish release**. The deploy job runs automatically and requires no manual action.

---

## After the release

- Confirm the SonarQube badge still shows passing.
- Verify the GitHub Release page shows the correct assets and tag (including `checksums.txt.bundle` and `sbom-*.cdx.json`).
- Smoke-test the downloaded binary: generate a key pair, encrypt a file, decrypt it.
- **Verify cosign signature** (optional sanity check):
  ```
  cosign verify-blob \
    --bundle checksums.txt.bundle \
    --certificate-identity-regexp 'https://github.com/dangel34/.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    checksums.txt
  ```
