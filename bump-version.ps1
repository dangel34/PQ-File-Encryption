#Requires -Version 7
param(
    [Parameter(Mandatory)][string]$Version,
    [string]$SpecChangelog = "Version bump"
)

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Error "Version must be in X.Y.Z format (got: $Version)"
    exit 1
}

$root = $PSScriptRoot

function Replace-InFile([string]$path, [string]$pattern, [string]$replacement) {
    $content = Get-Content $path -Raw
    $updated = $content -replace $pattern, $replacement
    if ($content -eq $updated) { Write-Warning "No change in: $path"; return }
    Set-Content $path $updated -NoNewline
    Write-Host "  updated $($path.Replace($root, '.'))"
}

Write-Host "Bumping to v$Version..."

# Cargo.toml files — match only the package version line (line starts with 'version =')
$cargoPattern     = '(?m)^version = "\d+\.\d+\.\d+"'
$cargoReplacement = "version = `"$Version`""
Replace-InFile "$root\pqfile\Cargo.toml"         $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-gui\Cargo.toml"     $cargoPattern $cargoReplacement
Replace-InFile "$root\pqfile-desktop\Cargo.toml" $cargoPattern $cargoReplacement

# pqfile-gui/src/lib.rs — APP_VERSION constant
Replace-InFile "$root\pqfile-gui\src\lib.rs" `
    'const APP_VERSION: &str = "\d+\.\d+\.\d+";' `
    "const APP_VERSION: &str = `"$Version`";"

# Inno Setup
Replace-InFile "$root\pqfile-desktop\packaging\setup.iss" `
    '#define AppVersion\s+"[\d.]+"' `
    "#define AppVersion   `"$Version`""

# sonar-project.properties
Replace-InFile "$root\sonar-project.properties" `
    'sonar\.projectVersion=[\d.]+' `
    "sonar.projectVersion=$Version"

# RPM spec — Version field + prepend changelog entry
$specPath = "$root\pqfile\packaging\pqfile.spec"
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
Write-Host "  added %changelog entry to pqfile/packaging/pqfile.spec"

# Regenerate Cargo.lock
Write-Host "Regenerating Cargo.lock..."
cargo build --workspace -q
if ($LASTEXITCODE -ne 0) { Write-Error "cargo build failed"; exit 1 }

# Commit, tag, push
Write-Host "Committing..."
git add -A

git commit -m "chore: bump version to $Version"
git tag "v$Version"
git push origin main
git push origin "v$Version"

Write-Host "Done — v$Version tagged and pushed."
