# Creating a release

This project uses GitHub Actions to build and publish releases automatically. All you need to do is push a version tag. The workflow handles building binaries for all platforms, packaging the WASM web app, deploying to GitHub Pages, and creating the GitHub Release with downloadable assets.

---

## Prerequisites

- Your changes are merged to `main` and CI is green
- You have push access to the repository (to push the tag)
- The version in `pqfile-gui/Cargo.toml` and `pqfile/Cargo.toml` matches what you intend to release

---

## Step 1 — Bump the version

Edit `pqfile/Cargo.toml` and `pqfile-gui/Cargo.toml`. Both should use the same version number.

```toml
[package]
version = "0.2.0"
```

Commit the bump:

```bash
git add pqfile/Cargo.toml pqfile-gui/Cargo.toml Cargo.lock
git commit -m "chore: bump version to 0.2.0"
git push origin main
```

Wait for CI to go green before tagging.

---

## Step 2 — Tag the commit

Tags must start with `v` to trigger the release workflow.

```bash
git tag v0.2.0
git push origin v0.2.0
```

That's it. The `release.yml` workflow fires automatically.

---

## Step 3 — Monitor the workflow

Open the **Actions** tab on GitHub. You will see a workflow run named after the tag. It has five jobs running in parallel and in sequence:

| Job | What it does |
|-----|-------------|
| CLI — linux/macos/windows | Compiles `pqfile` for each platform |
| Desktop — linux/macos/windows | Compiles `pqfile-desktop` for each platform |
| Web (WASM) | Runs `trunk build --release`, archives `dist/` |
| Deploy to GitHub Pages | Deploys the WASM build to GitHub Pages |
| Create GitHub Release | Assembles all artifacts and creates the release |

The release job runs last, after all build jobs succeed. If any build fails, the release is not created.

---

## Step 4 — Verify the release

Once the workflow finishes, go to the **Releases** page on GitHub. You should see:

- A release named `pqfile v0.2.0`
- Auto-generated release notes listing merged pull requests since the last tag
- Seven downloadable files:
  - `pqfile` (Linux CLI)
  - `pqfile` (macOS CLI)
  - `pqfile.exe` (Windows CLI)
  - `pqfile-desktop` (Linux GUI)
  - `pqfile-desktop` (macOS GUI)
  - `pqfile-desktop.exe` (Windows GUI)
  - `pqfile-web.tar.gz` (WASM web app)

The in-app update check (`pqfile-desktop`) reads the `tag_name` from the GitHub API and compares it to `CARGO_PKG_VERSION`. The "Download & Install" button downloads the correct platform binary directly from this release.

---

## Pre-releases

If the tag contains a hyphen (e.g. `v0.2.0-beta.1`, `v0.3.0-rc.1`), the workflow automatically marks the release as a pre-release. Pre-releases are visible on the Releases page but are not shown as the "latest" release via the GitHub API, so the in-app update check will not surface them to users on stable builds.

```bash
git tag v0.2.0-beta.1
git push origin v0.2.0-beta.1
```

---

## Deleting a bad release

If you pushed a tag by mistake or need to redo the release:

```bash
# Delete the tag locally and on remote
git tag -d v0.2.0
git push origin --delete v0.2.0
```

Then delete the draft/published release on GitHub via the Releases page UI before re-tagging.

---

## Versioning convention

This project follows [Semantic Versioning](https://semver.org):

| Change | Version bump | Example |
|--------|-------------|---------|
| Breaking change to `.pqf` format or key format | Major | `0.x.y` → `1.0.0` |
| New feature, backward-compatible | Minor | `0.1.x` → `0.2.0` |
| Bug fix, documentation, dependency update | Patch | `0.2.0` → `0.2.1` |

The `.pqf` file format version (`VERSION = 0x03` in `format.rs`) is independent of the crate version. Increment `VERSION` only when the on-disk format changes in a way that breaks backward compatibility.

---

## What the in-app updater does with the tag

When a user clicks **Check for Updates** in the Settings tab, the app calls:

```
GET https://api.github.com/repos/dangel34/PQ-File-Encryption/releases/latest
```

It extracts `tag_name` (e.g. `v0.2.0`), strips the `v`, and compares it to `CARGO_PKG_VERSION`. If they differ, it shows "Update available".

When the user clicks **Download & Install**, the app downloads the binary directly from:

```
https://github.com/dangel34/PQ-File-Encryption/releases/download/v{version}/{asset}
```

Where `{asset}` is the platform-specific filename. The binary is written to a temp file alongside the current executable, then the current executable is replaced. On Windows, the running `.exe` is first renamed to `.old` (cleaned up on next launch). On macOS and Linux, the file is replaced atomically with `rename`.

After install, a **Restart Now** button relaunches the process using the new binary.
