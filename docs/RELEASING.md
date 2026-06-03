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

Publishing `pqfile` and `pqfile-cli` is **automated** via `.github/workflows/publish.yml`, which triggers when the Release workflow completes successfully on this repository's own commits (forks cannot trigger it).

The workflow:
1. Checks out the exact commit SHA from the Release workflow run.
2. Publishes `pqfile` with `cargo publish -p pqfile --locked`.
3. Polls the crates.io index until `pqfile` is visible (up to 5 minutes, checking every 10 seconds).
4. Publishes `pqfile-cli` with `cargo publish -p pqfile-cli --locked`.

No manual steps are needed. Monitor the **Actions** tab for the "Publish to crates.io" workflow.

### Emergency manual publish

If the automated workflow fails and a manual publish is needed:

1. Commit all changes locally (`cargo 1.73+` refuses to publish with uncommitted changes).
2. Log in: `cargo login` (token from <https://crates.io/settings/tokens>).
3. Dry run first: `cargo publish --dry-run -p pqfile`.
4. Publish: `cargo publish -p pqfile --locked`.
5. Wait for index propagation, then: `cargo publish -p pqfile-cli --locked`.

### What not to publish

Do **not** publish `pqfile-gui` or `pqfile-desktop`. They require system GUI libraries and are not useful as library crates. The WASM web app is deployed via the release workflow.

### Verifying the publish

- `pqfile`: <https://crates.io/crates/pqfile>
- `pqfile-cli`: <https://crates.io/crates/pqfile-cli>
- docs.rs (auto-built within a few minutes): <https://docs.rs/pqfile>

---

## Release announcement checklist

In addition to the standard release notes, include the following for versions that contain breaking changes:

- **Shamir share format (v3.2.x and later)**: The share PEM body changed from an 8-byte to a 16-byte public key fingerprint. Shares produced by v3.1.x and earlier cannot be decoded by v3.2.x and later. Users who split keys before upgrading must reconstruct from the original private key and split again. Include explicit migration instructions in the announcement.
- **Hybrid HKDF (v3.2.x)**: The HKDF for the hybrid X25519+ML-KEM-768 key exchange was corrected. Files encrypted with a hybrid key before v3.2.x cannot be decrypted by v3.2.x and later. Re-encrypt those files before upgrading.
- **signcrypt parameter order (v3.3.x)**: `sign_passphrase` moved to the last argument position in `signcrypt` and `signcrypt_bytes`. Callers that used positional arguments must update their code.
