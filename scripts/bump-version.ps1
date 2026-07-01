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

Write-Host "Running clippy..."
cargo clippy -q --workspace --all-targets -- --deny warnings
if ($LASTEXITCODE -ne 0) { Write-Error "Clippy failed - fix warnings before releasing"; exit 1 }
Write-Host "  clippy OK"

Write-Host "Running tests..."
cargo test --workspace -q
if ($LASTEXITCODE -ne 0) { Write-Error "Tests failed - aborting version bump"; exit 1 }
Write-Host "  all tests passed"

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
$specContent = $specContent -replace '(%changelog)', "%changelog`n$entry`n"
Set-Content $specPath $specContent -NoNewline
Write-Host "  added %changelog entry to pqfile-cli/packaging/pqfile.spec"

# docs/BUILDING.md - example output path
Replace-InFile "$root\docs\BUILDING.md" `
    'pqfile-setup-[\d.]+\.exe' `
    "pqfile-setup-$Version.exe"

# docs/CHANGELOG.md - stamp the unreleased section with today's date
$today = Get-Date -Format "yyyy-MM-dd"
Replace-InFile "$root\docs\CHANGELOG.md" `
    "\[$Version\] - unreleased[^\n]*" `
    "[$Version] - $today"

# sonar-project.properties - keep the reported project version in sync
Replace-InFile "$root\sonar-project.properties" `
    '(?m)^sonar\.projectVersion=[\d.]+' `
    "sonar.projectVersion=$Version"

# Regenerate Cargo.lock - cargo check is much faster than cargo build
# (no codegen or linking, but still resolves and writes the lockfile)
Write-Host "Regenerating Cargo.lock..."
cargo check --workspace -q
if ($LASTEXITCODE -ne 0) { Write-Error "cargo check failed"; exit 1 }

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
    "sonar-project.properties"
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
