# Creating a Release

This project uses GitHub Actions to build and publish releases automatically. Once you push a version tag, the workflow compiles `pqfile` and `pqfile-desktop` for Linux, macOS, and Windows, builds the WASM web app, deploys it to GitHub Pages, and creates a GitHub Release with all the downloadable binaries — without you having to do any of that manually.

This guide assumes you are creating your **first release ever** from a clean, committed state.

---

## Before you begin — one-time GitHub setup

There are two things you need to configure in the GitHub repository settings before the release workflow will fully succeed. You only do this once.

### Enable GitHub Pages

The `deploy-pages` job in `release.yml` will fail unless GitHub Pages is turned on and pointed at GitHub Actions as the source.

1. Go to your repository on GitHub.
2. Click **Settings** (the gear icon in the top tab bar).
3. In the left sidebar, scroll down to **Pages**.
4. Under **Build and deployment → Source**, open the dropdown and select **GitHub Actions**.
5. Click **Save** if a save button appears.

That's it. You do not need to pick a branch or folder — Actions handles the deployment.

### Confirm Actions has write permissions

The release workflow needs to create releases and push to Pages. This is usually enabled by default on new repositories, but worth checking.

1. In **Settings**, go to **Actions → General** in the left sidebar.
2. Scroll to **Workflow permissions**.
3. Make sure **Read and write permissions** is selected.
4. Click **Save**.

---

## Step 1 — Push your code to GitHub

If you have committed locally but not pushed yet, push now:

```bash
git push origin main
```

If this is the very first push and you haven't set the remote yet:

```bash
git remote add origin https://github.com/dangel34/PQ-File-Encryption.git
git push -u origin main
```

You can confirm the push worked by visiting your repository URL in a browser and checking that your files are there.

---

## Step 2 — Wait for CI to go green

Every push to `main` triggers the CI workflow (`.github/workflows/ci.yml`). It runs two jobs:

| Job | What it does |
|-----|-------------|
| Test & Lint | `cargo test --workspace` + `cargo clippy --workspace -- -D warnings` on Linux |
| WASM Build | `trunk build --release` to make sure the web app compiles |

**You must wait for both jobs to pass before tagging.** If you tag a broken commit, the release workflow will fail too.

To check CI status:

1. Go to your repository on GitHub.
2. Click the **Actions** tab.
3. You will see a workflow run titled with your commit message. Click it.
4. Both jobs should show a green checkmark. If one is red, click into it to read the error, fix the code, commit, push, and wait again.

A green checkmark next to the commit message on the **Code** tab is the quickest signal — you'll see a small ✓ icon to the left of the commit hash.

---

## Step 3 — Confirm the version number

Open `pqfile/Cargo.toml` and `pqfile-gui/Cargo.toml`. Both should have the version you want to release:

```toml
[package]
version = "1.0.0"
```

They are currently both set to `1.0.0`. If that's the version you want, no change is needed. The version in these files is what gets baked into the compiled binaries and what the in-app update checker compares against.

If you need to change the version, edit both files, then commit and push:

```bash
git add pqfile/Cargo.toml pqfile-gui/Cargo.toml Cargo.lock
git commit -m "chore: bump version to 1.0.0"
git push origin main
```

Wait for CI to go green again before continuing.

---

## Step 4 — Create and push a version tag

Tags are what trigger the release workflow. The tag name **must start with `v`** — that is what `release.yml` listens for.

```bash
git tag v1.0.0
git push origin v1.0.0
```

The `git tag` command creates the tag on your current local commit. The `git push origin v1.0.0` sends it to GitHub, which immediately triggers the release workflow. Tags are not pushed by `git push` alone — you have to push them explicitly like this.

To confirm the tag was pushed, go to your repository on GitHub, click the **Code** tab, then click the **Tags** link (near the branch dropdown). You should see `v1.0.0` listed.

---

## Step 5 — Watch the release workflow

Go to the **Actions** tab. You should now see a new workflow run named `Release` with the tag `v1.0.0`. Click it to open it.

The workflow has five jobs that run in a specific order:

```
build-cli (Linux) ─┐
build-cli (macOS)  ├─► github-release
build-cli (Windows)│
                   │
build-desktop (Linux) ─┐
build-desktop (macOS)  ├─► github-release
build-desktop (Windows)│
                       │
build-wasm ────────────┴─► github-release
              │
              └──────────► deploy-pages
```

| Job | What it does | Approx. time |
|-----|-------------|--------------|
| CLI — linux | Compiles `pqfile` CLI for Linux | ~2 min |
| CLI — macos | Compiles `pqfile` CLI for macOS | ~3 min |
| CLI — windows | Compiles `pqfile` CLI for Windows | ~4 min |
| Desktop — linux | Compiles `pqfile-desktop` GUI for Linux (installs GTK deps first) | ~4 min |
| Desktop — macos | Compiles `pqfile-desktop` GUI for macOS | ~4 min |
| Desktop — windows | Compiles `pqfile-desktop` GUI for Windows | ~5 min |
| Web (WASM) | Runs `trunk build --release` and archives `dist/` | ~3 min |
| Deploy to GitHub Pages | Pushes the WASM build to your GitHub Pages site | ~1 min |
| Create GitHub Release | Downloads all 7 artifacts and creates the release | ~1 min |

The six build jobs (CLI × 3 and Desktop × 3) all run in parallel. The `github-release` job waits for all of them plus the WASM build to finish. Total wall time is typically 6–8 minutes.

While the workflow is running, each job shows a spinning indicator. A green checkmark means it finished successfully. A red ✗ means it failed — click the job to read the log.

**If any build job fails**, the `github-release` job will not run and no release will be created. Fix the problem, delete the bad tag (see the "Recovering from a bad tag" section below), and start over.

---

## Step 6 — Verify the release

Once all jobs are green, go to the **Releases** page of your repository (on the right side of the Code tab, under **Releases**, or navigate to `github.com/dangel34/PQ-File-Encryption/releases`).

You should see a release named **pqfile v1.0.0** with:

- Auto-generated release notes listing commits since the last release (on first release, this will list all commits)
- Seven downloadable files attached:

| File | What it is |
|------|-----------|
| `pqfile` (from linux artifact) | CLI binary for Linux |
| `pqfile` (from macos artifact) | CLI binary for macOS |
| `pqfile.exe` | CLI binary for Windows |
| `pqfile-desktop` (from linux artifact) | Desktop GUI for Linux |
| `pqfile-desktop` (from macos artifact) | Desktop GUI for macOS |
| `pqfile-desktop.exe` | Desktop GUI for Windows |
| `pqfile-web.tar.gz` | WASM web app (self-contained, can be served anywhere) |

Download one or two of the binaries and confirm they work correctly on your machine.

Your GitHub Pages site is also now live at `https://dangel34.github.io/PQ-File-Encryption/` with the web app deployed.

---

## Recovering from a bad tag

If you pushed a tag too early (before CI was green, or with the wrong version number), you can delete it and start over:

```bash
# Delete the tag locally
git tag -d v1.0.0

# Delete the tag on GitHub
git push origin --delete v1.0.0
```

Then go to the **Releases** page on GitHub and delete any draft or partial release that was created. After that, fix whatever was wrong, push, wait for CI, and re-tag.

---

## Making future releases

For every release after the first:

1. Make and commit your changes on `main`.
2. Edit `pqfile/Cargo.toml` and `pqfile-gui/Cargo.toml` — update the version number in both.
3. Commit the version bump: `git add pqfile/Cargo.toml pqfile-gui/Cargo.toml Cargo.lock && git commit -m "chore: bump version to X.Y.Z"`
4. `git push origin main` and wait for CI to go green.
5. `git tag vX.Y.Z && git push origin vX.Y.Z`

---

## Pre-releases (beta / release candidate)

If the tag contains a hyphen, the workflow automatically marks the GitHub Release as a pre-release. Pre-releases appear on the Releases page but are not returned by the GitHub API as the "latest" release, so the in-app update checker will not offer them to users on stable builds.

```bash
git tag v1.1.0-beta.1
git push origin v1.1.0-beta.1
```

---

## Versioning convention

This project follows [Semantic Versioning](https://semver.org):

| Change | Version bump | Example |
|--------|-------------|---------|
| Breaking change to `.pqf` format or key format | Major | `0.x.y` → `1.0.0` |
| New feature, backward-compatible | Minor | `1.0.x` → `1.1.0` |
| Bug fix, documentation, dependency update | Patch | `1.1.0` → `1.1.1` |

The `.pqf` file format version (`VERSION = 0x03` in `format.rs`) is separate from the crate version. Only increment `VERSION` when the on-disk format changes in a way that breaks backward compatibility with existing `.pqf` files.

---

## How the in-app updater uses the release

When a user clicks **Check for Updates** in the Settings tab, `pqfile-desktop` calls:

```
GET https://api.github.com/repos/dangel34/PQ-File-Encryption/releases/latest
```

It reads `tag_name` from the response (e.g. `"v1.0.0"`), strips the `v`, and compares it to the version baked into the running binary (`CARGO_PKG_VERSION`). If the release version is newer, the app shows "Update available: v1.0.0".

When the user clicks **Download & Install**, the app downloads the platform-specific binary directly from:

```
https://github.com/dangel34/PQ-File-Encryption/releases/download/v{version}/{asset}
```

On Windows it renames the running `.exe` to `.old`, places the new binary, and prompts **Restart Now**. On macOS and Linux it replaces the binary atomically with `rename`. The `.old` file is cleaned up on the next launch.

This is why the version in `Cargo.toml` and the tag name must match — if they don't, the update checker either never reports an update or reports one that loops forever.
