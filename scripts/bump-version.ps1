#Requires -Version 7
param(
    [Parameter(Mandatory)][string]$Version,
    [string]$SpecChangelog = "Version bump"
)

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Error "Version must be in X.Y.Z format (got: $Version)"
    exit 1
}

$root = Split-Path $PSScriptRoot -Parent

# ── Pre-flight checks ──────────────────────────────────────────────────────

$branch = git rev-parse --abbrev-ref HEAD
if ($branch -ne 'main') {
    Write-Error "Must be on 'main' branch to release (currently on '$branch')"
    exit 1
}

$dirty = git status --porcelain
if ($dirty) {
    Write-Error "Working tree is not clean. Commit or stash changes before releasing."
    exit 1
}

# Fail early if the tag already exists, before any files are modified.
if (git tag -l "v$Version" | Select-String "v$Version") {
    Write-Error "Tag v$Version already exists locally. Delete it first: git tag -d v$Version"
    exit 1
}
if (git ls-remote --tags origin "refs/tags/v$Version" | Select-String "v$Version") {
    Write-Error "Tag v$Version already exists on remote."
    exit 1
}

Write-Host "Checking formatting..."
cargo fmt --check
if ($LASTEXITCODE -ne 0) { Write-Error "cargo fmt check failed - run 'cargo fmt' then re-check"; exit 1 }
Write-Host "  fmt OK"

# Mirrors ci.yml's test-and-lint job plus every optional-feature job
# (fido2 x2, kem-libcrux, tlock x2) exactly, so a feature-gated regression is
# caught here instead of only after the tag is already pushed. Slower than a
# single default-features pass, but that's the actual bar CI holds every
# push to - a bump script that checks less than CI does is false confidence.
$checks = @(
    @{ Name = "clippy (workspace, async)";     Cmd = "cargo clippy --workspace --all-targets --features pqfile/async -- --deny warnings" }
    @{ Name = "test (workspace, async)";       Cmd = "cargo test --workspace --features pqfile/async -q" }
    @{ Name = "clippy (pqfile-cli, fido2)";    Cmd = "cargo clippy -p pqfile-cli --all-targets --features fido2 -- --deny warnings" }
    @{ Name = "test (pqfile-cli, fido2)";      Cmd = "cargo test -p pqfile-cli --features fido2 -q" }
    @{ Name = "clippy (pqfile-gui, fido2)";    Cmd = "cargo clippy -p pqfile-gui --all-targets --features fido2 -- --deny warnings" }
    @{ Name = "test (pqfile-gui, fido2)";      Cmd = "cargo test -p pqfile-gui --features fido2 -q" }
    @{ Name = "clippy (pqfile, kem-libcrux)";  Cmd = "cargo clippy -p pqfile --all-targets --features kem-libcrux -- --deny warnings" }
    @{ Name = "test (pqfile, kem-libcrux)";    Cmd = "cargo test -p pqfile --features kem-libcrux -q" }
    @{ Name = "clippy (pqfile, tlock)";        Cmd = "cargo clippy -p pqfile --all-targets --features tlock -- --deny warnings" }
    @{ Name = "test (pqfile, tlock)";          Cmd = "cargo test -p pqfile --features tlock -q" }
    @{ Name = "clippy (pqfile-cli, tlock)";    Cmd = "cargo clippy -p pqfile-cli --all-targets --features tlock -- --deny warnings" }
    @{ Name = "test (pqfile-cli, tlock)";      Cmd = "cargo test -p pqfile-cli --features tlock -q" }
)
foreach ($check in $checks) {
    Write-Host "Running $($check.Name)..."
    Invoke-Expression $check.Cmd
    if ($LASTEXITCODE -ne 0) { Write-Error "$($check.Name) failed - fix it before releasing"; exit 1 }
    Write-Host "  $($check.Name) OK"
}

# ── Version replacements ───────────────────────────────────────────────────

# Thin wrapper so Replace-InFile funnels console output through a 'Show-' verbed
# cmdlet instead of calling the non-pipeline-friendly Write-Host directly.
function Show-Line([string]$Text) {
    Write-Host $Text
}

function Replace-InFile([string]$path, [string]$pattern, [string]$replacement) {
    $content = Get-Content $path -Raw
    $updated = $content -replace $pattern, $replacement
    if ($content -eq $updated) { Write-Warning "No change in: $path"; return }
    Set-Content $path $updated -NoNewline
    Show-Line "  updated $($path.Replace($root, '.'))"
}

Write-Host "Bumping to v$Version..."

# Cargo.toml files: match only the package version line (line starts with 'version =')
$cargoPattern     = '(?m)^version = "\d+\.\d+\.\d+"'
$cargoReplacement = "version = `"$Version`""
Replace-InFile "$root\pqfile\Cargo.toml"         $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-cli\Cargo.toml"     $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-gui\Cargo.toml"     $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-desktop\Cargo.toml" $cargoPattern $cargoReplacement

# Inter-crate dependency version constraints
Replace-InFile "$root\Cargo.toml" `
    '((?:pqfile|pqfile-gui)\s*=\s*\{[^}]*version\s*=\s*)"[\d.]+"' `
    ('${1}"' + $Version + '"')
Replace-InFile "$root\pqfile-gui\Cargo.toml" `
    '(pqfile\s*=\s*\{[^}]*version\s*=\s*)"[\d.]+"' `
    ('${1}"' + $Version + '"')
Replace-InFile "$root\pqfile-desktop\Cargo.toml" `
    '(pqfile-gui\s*=\s*\{[^}]*version\s*=\s*)"[\d.]+"' `
    ('${1}"' + $Version + '"')

# pqfile-gui/src/lib.rs's APP_VERSION is env!("CARGO_PKG_VERSION") - no manual edit needed,
# it tracks pqfile-gui/Cargo.toml automatically.

# Inno Setup
Replace-InFile "$root\pqfile-desktop\packaging\setup.iss" `
    '#define AppVersion\s+"[\d.]+"' `
    "#define AppVersion   `"$Version`""

# RPM spec - Version field + prepend changelog entry
$specPath = "$root\pqfile-cli\packaging\pqfile.spec"
Replace-InFile $specPath `
    '(?m)^Version:\s+[\d.]+' `
    "Version:        $Version"

$date     = Get-Date -Format "ddd MMM dd yyyy"
$email    = git config user.email
$name     = git config user.name
$entry    = "* $date $name <$email> - $Version-1`n- $SpecChangelog"
$specContent = Get-Content $specPath -Raw
# Idempotent: a prior run of this script for the same $Version can be
# interrupted after this edit but before the commit (e.g. a later pre-flight
# check failing), leaving the file modified but uncommitted. Re-running would
# otherwise prepend a second, near-duplicate entry for the same version.
if ($specContent -match [regex]::Escape("- $Version-1")) {
    Write-Warning "changelog entry for $Version-1 already present in pqfile.spec; not duplicating"
} else {
    $specContent = $specContent -replace '(%changelog)', "%changelog`n$entry`n"
    Set-Content $specPath $specContent -NoNewline
    Write-Host "  added %changelog entry to pqfile-cli/packaging/pqfile.spec"
}

# docs/BUILDING.md - example output path
Replace-InFile "$root\docs\BUILDING.md" `
    'pqfile-setup-[\d.]+\.exe' `
    "pqfile-setup-$Version.exe"

# docs/CHANGELOG.md - stamp the unreleased section with today's date.
# The changelog uses a "## [Unreleased]" heading between releases; fall back to
# the older "[X.Y.Z] - unreleased" convention if someone pre-stamped the version.
$today = Get-Date -Format "yyyy-MM-dd"
$changelogRaw = Get-Content "$root\docs\CHANGELOG.md" -Raw
if ($changelogRaw -match '(?m)^## \[Unreleased\]') {
    Replace-InFile "$root\docs\CHANGELOG.md" `
        '(?m)^## \[Unreleased\]' `
        "## [$Version] - $today"
} else {
    Replace-InFile "$root\docs\CHANGELOG.md" `
        "\[$Version\] - unreleased[^\n]*" `
        "[$Version] - $today"
}

# sonar-project.properties - keep the reported project version in sync
Replace-InFile "$root\sonar-project.properties" `
    '(?m)^sonar\.projectVersion=[\d.]+' `
    "sonar.projectVersion=$Version"

# Language bindings - versioned in lockstep with the core crate, so every
# release republishes them to PyPI/npm. Before 4.3.5 they were left at 0.1.0,
# and the publish workflows "succeeded" by skipping a version that already
# existed, so binding fixes never shipped. release.yml's version check and
# both publish workflows now fail if any of these drift from the tag.
Replace-InFile "$root\pqfile-python\Cargo.toml"     $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-python\pyproject.toml" $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-node\Cargo.toml"       $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-mobile\Cargo.toml"     $cargoPattern $cargoReplacement

# pqfile-node/package.json: the package's own version plus every per-platform
# optionalDependencies pin (publish-node.yml publishes those at the same version).
Replace-InFile "$root\pqfile-node\package.json" `
    '("version":\s*)"[\d.]+"' `
    ('${1}"' + $Version + '"')
Replace-InFile "$root\pqfile-node\package.json" `
    '("@dangel34/pqfile-[a-z0-9-]+":\s*)"[\d.]+"' `
    ('${1}"' + $Version + '"')

# pqfile-node/index.js is generated by `napi build` and embeds the version in its
# binding-package version checks; patch it in place so it matches without a rebuild.
Replace-InFile "$root\pqfile-node\index.js" `
    "(bindingPackageVersion !== ')[\d.]+(')" `
    ('${1}' + $Version + '${2}')
Replace-InFile "$root\pqfile-node\index.js" `
    '(expected )[\d.]+( but got)' `
    ('${1}' + $Version + '${2}')

# Regenerate Cargo.lock - cargo check is much faster than cargo build
# (no codegen or linking, but still resolves and writes the lockfile)
Write-Host "Regenerating Cargo.lock..."
cargo check --workspace -q
if ($LASTEXITCODE -ne 0) { Write-Error "cargo check failed"; exit 1 }

# The workspace-excluded crates each keep their own Cargo.lock, which pins the
# path-dependency `pqfile` (and, for the bindings, the crate itself) at the old
# version. CI runs them with --locked, so a stale lock fails CI after the tag is
# already pushed - exactly what forced the follow-up lockfile commit and the
# cancelled release run for v4.3.4. Only these entries move; --offline keeps
# every other dependency exactly where it was.
Write-Host "Regenerating workspace-excluded Cargo.lock files..."
$excludedLocks = @(
    @{ Dir = "fuzz";          Pkgs = @("pqfile") }
    @{ Dir = "pqfile-python"; Pkgs = @("pqfile", "pqfile-python") }
    @{ Dir = "pqfile-node";   Pkgs = @("pqfile", "pqfile-node") }
    @{ Dir = "pqfile-mobile"; Pkgs = @("pqfile", "pqfile-mobile") }
)
foreach ($lock in $excludedLocks) {
    $pkgArgs = $lock.Pkgs | ForEach-Object { "-p"; $_ }
    Push-Location "$root\$($lock.Dir)"
    cargo update @pkgArgs --offline -q
    $code = $LASTEXITCODE
    Pop-Location
    if ($code -ne 0) { Write-Error "cargo update failed in $($lock.Dir)"; exit 1 }
    Show-Line "  updated ./$($lock.Dir)/Cargo.lock"
}

# pqfile-node/package-lock.json records the root version and the
# optionalDependencies pins. --package-lock-only never touches node_modules; the
# not-yet-published platform versions are recorded as unresolved optional
# entries, which `npm ci` accepts.
Write-Host "Regenerating pqfile-node/package-lock.json..."
Push-Location "$root\pqfile-node"
npm install --package-lock-only --ignore-scripts --no-audit --no-fund --silent
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { Write-Error "npm install --package-lock-only failed"; exit 1 }

# ── Commit, tag, push ─────────────────────────────────────────────────────

Write-Host "Committing..."

# Stage only the files we knowingly modified - never use git add -A here.
$filesToStage = @(
    "pqfile/Cargo.toml",
    "pqfile-cli/Cargo.toml",
    "pqfile-gui/Cargo.toml",
    "pqfile-desktop/Cargo.toml",
    "Cargo.toml",
    "Cargo.lock",
    "pqfile-desktop/packaging/setup.iss",
    "pqfile-cli/packaging/pqfile.spec",
    "docs/BUILDING.md",
    "docs/CHANGELOG.md",
    "sonar-project.properties",
    "fuzz/Cargo.lock",
    "pqfile-python/Cargo.toml",
    "pqfile-python/Cargo.lock",
    "pqfile-python/pyproject.toml",
    "pqfile-node/Cargo.toml",
    "pqfile-node/Cargo.lock",
    "pqfile-node/package.json",
    "pqfile-node/package-lock.json",
    "pqfile-node/index.js",
    "pqfile-mobile/Cargo.toml",
    "pqfile-mobile/Cargo.lock"
)
foreach ($f in $filesToStage) {
    git add "$root\$f"
}

git commit -m "chore: bump version to $Version"
git tag "v$Version"
git push origin main
git push origin "v$Version"

Write-Host "Done: v$Version tagged and pushed."
Write-Host "  -> CI release workflow will build artifacts and create a draft GitHub release."
Write-Host "  -> Deploy workflow will rebuild and publish the web app."
