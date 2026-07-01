#Requires -Version 7
<#
.SYNOPSIS
    Comprehensive local test suite. Run before every commit or release.

.DESCRIPTION
    Mirrors the CI pipeline as closely as possible on a local machine.
    Runs in this order:
      1. cargo fmt --check
      2. cargo clippy (deny warnings)
      3. cargo test --workspace
      4. cargo check --workspace --release  (catch release-only issues)
      5. cargo doc --no-deps                (ensure docs build cleanly)
      6. em/en dash scan                   (no typographic dashes in source)
      7. FIXME / HACK / XXX scan           (no stray markers in library or CLI)
      8. cargo test --features timing-tests (slow; skipped with -Quick)
      9. cargo deny check                  (if cargo-deny is installed; skip with -NoDeny)
     10. cargo llvm-cov --summary-only     (opt-in with -Coverage)

.PARAMETER Quick
    Skip the slow steps: timing-tests (step 8).

.PARAMETER Coverage
    Run 'cargo llvm-cov --workspace --summary-only' as an extra step.
    Requires cargo-llvm-cov: cargo install cargo-llvm-cov --locked

.PARAMETER NoDeny
    Skip 'cargo deny check' even when cargo-deny is installed.

.EXAMPLE
    .\scripts\test-local.ps1
    .\scripts\test-local.ps1 -Quick
    .\scripts\test-local.ps1 -Coverage
#>
param(
    [switch]$Quick,
    [switch]$Coverage,
    [switch]$NoDeny
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Resolve repo root regardless of where the script is launched from.
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

# ── Output helpers ─────────────────────────────────────────────────────────────

$script:Results = [System.Collections.Generic.List[pscustomobject]]::new()

# Thin wrapper so console output funnels through one 'Show-' verbed cmdlet
# instead of each helper below calling the non-pipeline-friendly Write-Host directly.
function Show-Line([string]$Text = '', [string]$Color) {
    if ($Color) {
        Write-Host $Text -ForegroundColor $Color
    } else {
        Write-Host $Text
    }
}

function Write-Banner([string]$text) {
    $line = '=' * 56
    Show-Line
    Show-Line "  $line" Cyan
    Show-Line "  $text" Cyan
    Show-Line "  $line" Cyan
}

function Write-StepHeader([string]$name) {
    Show-Line
    Show-Line "  >> $name" Cyan
}

function Add-Result([string]$name, [string]$state, [double]$secs) {
    $script:Results.Add([pscustomobject]@{ Name = $name; State = $state; Secs = $secs })
    $t = "$([math]::Round($secs,1)) s"
    switch ($state) {
        'PASS' { Show-Line "     [PASS] $name  ($t)" Green }
        'FAIL' { Show-Line "     [FAIL] $name  ($t)" Red }
        'SKIP' { Show-Line "     [SKIP] $name" DarkGray }
    }
}

# Run a step defined as a scriptblock.
# The block may throw to signal failure; otherwise $LASTEXITCODE is checked.
function Invoke-Step([string]$Name, [scriptblock]$Block) {
    Write-StepHeader $Name
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ok = $true
    try {
        $null = & $Block
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    } catch {
        Show-Line "     Error: $_" Red
        $ok = $false
    }
    $sw.Stop()
    Add-Result $Name $(if ($ok) { 'PASS' } else { 'FAIL' }) $sw.Elapsed.TotalSeconds
}

function Skip-Step([string]$Name, [string]$Reason) {
    Show-Line
    Show-Line "  >> $Name" DarkGray
    Show-Line "     [SKIP] $Reason" DarkGray
    $script:Results.Add([pscustomobject]@{ Name = $Name; State = 'SKIP'; Secs = 0 })
}

# ── Pre-flight ─────────────────────────────────────────────────────────────────

$globalTimer = [Diagnostics.Stopwatch]::StartNew()

Write-Banner "pqfile - local test suite  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

$dirty = git status --porcelain 2>&1
if ($dirty) {
    Write-Host ''
    Write-Host '  [WARN] Uncommitted changes in working tree:' -ForegroundColor Yellow
    $dirty | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkYellow }
}

# ── Step 1: Formatting ─────────────────────────────────────────────────────────

Invoke-Step 'cargo fmt --check' {
    cargo fmt --check --all
}

# ── Step 2: Clippy ─────────────────────────────────────────────────────────────

Invoke-Step 'clippy (deny warnings)' {
    cargo clippy --workspace --all-targets -- --deny warnings
}

# ── Step 3: Tests ──────────────────────────────────────────────────────────────

Invoke-Step 'cargo test --workspace' {
    cargo test --workspace
}

# ── Step 4: Release check ──────────────────────────────────────────────────────
# cargo check compiles without linking - catches type/trait errors that only
# surface under release optimisations (e.g. inlining of platform-specific code).

Invoke-Step 'cargo check --workspace --release' {
    cargo check --workspace --release
}

# ── Step 5: Docs ───────────────────────────────────────────────────────────────

Invoke-Step 'cargo doc --no-deps (library only)' {
    cargo doc --no-deps -p pqfile 2>&1
}

# ── Step 6: Em/en dash scan ────────────────────────────────────────────────────
# CI does not enforce this but the project policy is zero typographic dashes.

Invoke-Step 'no em/en dashes in source' {
    $hits = Get-ChildItem -Path $root -Recurse -Include '*.rs', '*.md', '*.toml' |
        Where-Object { $_.FullName -notmatch '[\\/]target[\\/]' } |
        Select-String -Pattern '[—–]' -Encoding UTF8
    if ($hits) {
        $hits | ForEach-Object {
            $rel = $_.Path.Replace($root, '.').TrimStart('\/')
            Write-Host "     $rel`:$($_.LineNumber): $($_.Line.Trim())" -ForegroundColor Red
        }
        throw "em/en dashes found"
    }
}

# ── Step 7: FIXME / HACK / XXX scan ───────────────────────────────────────────
# Only scanned in the published library and CLI - GUI WIP markers are acceptable.

Invoke-Step 'no FIXME/HACK/XXX in pqfile + pqfile-cli' {
    $hits = Get-ChildItem -Path "$root/pqfile/src", "$root/pqfile-cli/src" `
        -Recurse -Include '*.rs' |
        Select-String -Pattern '\b(FIXME|HACK|XXX)\b' -Encoding UTF8
    if ($hits) {
        $hits | ForEach-Object {
            $rel = $_.Path.Replace($root, '.').TrimStart('\/')
            Write-Host "     $rel`:$($_.LineNumber): $($_.Line.Trim())" -ForegroundColor Red
        }
        throw "stray markers found"
    }
}

# ── Step 8: Timing / constant-time tests (slow) ────────────────────────────────

if ($Quick) {
    Skip-Step 'timing-tests (--features timing-tests)' '--Quick flag active'
} else {
    Invoke-Step 'timing-tests (--features timing-tests)' {
        cargo test -p pqfile --features timing-tests
    }
}

# ── Step 9: cargo deny ─────────────────────────────────────────────────────────

if ($NoDeny) {
    Skip-Step 'cargo deny check' '--NoDeny flag active'
} else {
    $denyAvailable = $null -ne (Get-Command cargo-deny -ErrorAction SilentlyContinue)
    if (-not $denyAvailable) {
        # Also try via 'cargo deny' subcommand (some installs use this path).
        $denyAvailable = (cargo deny --version 2>&1) -match 'cargo-deny'
    }
    if ($denyAvailable) {
        Invoke-Step 'cargo deny check' {
            cargo deny check advisories licenses bans sources
        }
    } else {
        Skip-Step 'cargo deny check' 'not installed  (cargo install cargo-deny --locked)'
    }
}

# ── Step 10: Coverage (opt-in) ─────────────────────────────────────────────────

if ($Coverage) {
    $covAvailable = (cargo llvm-cov --version 2>&1) -match 'cargo-llvm-cov'
    if ($covAvailable) {
        Invoke-Step 'cargo llvm-cov (coverage summary)' {
            cargo llvm-cov --workspace --summary-only
        }
    } else {
        Skip-Step 'cargo llvm-cov' 'not installed  (cargo install cargo-llvm-cov --locked)'
    }
} else {
    Skip-Step 'cargo llvm-cov' 'opt-in with -Coverage'
}

# ── Summary ────────────────────────────────────────────────────────────────────

$globalTimer.Stop()
$totalSecs = [math]::Round($globalTimer.Elapsed.TotalSeconds, 1)

Write-Banner "Summary  ($totalSecs s total)"

$passed  = @($script:Results | Where-Object State -eq 'PASS')
$failed  = @($script:Results | Where-Object State -eq 'FAIL')
$skipped = @($script:Results | Where-Object State -eq 'SKIP')

foreach ($r in $passed)  { Write-Host "  [PASS] $($r.Name)  ($([math]::Round($r.Secs,1)) s)" -ForegroundColor Green }
foreach ($r in $failed)  { Write-Host "  [FAIL] $($r.Name)" -ForegroundColor Red }
foreach ($r in $skipped) { Write-Host "  [SKIP] $($r.Name)" -ForegroundColor DarkGray }

Write-Host ''
if ($failed.Count -eq 0) {
    Write-Host "  All checks passed." -ForegroundColor Green
    exit 0
} else {
    Write-Host "  $($failed.Count) check(s) failed. Fix the issues above before committing." -ForegroundColor Red
    exit 1
}
