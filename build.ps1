<#
.SYNOPSIS
    Necromancer V2 — Polymorphic Build Script
    Produces a fresh binary hash on every invocation via three layered techniques:
      1. garble -seed=random   → Identity obfuscation + unique binary per build
      2. -ldflags BuildID=UUID → Unique embedded string (breaks hash blocklists)
      3. go:generate phantom   → Random 256-byte pad rewrites the data section

.USAGE
    # Standard polymorphic build (recommended)
    .\build.ps1

    # No-garble fallback (if garble not installed)
    .\build.ps1 -NoGarble

    # Specify output name
    .\build.ps1 -OutFile "payload.exe"
#>

param(
    [string]$OutFile   = "ad-necromancer-v2.exe",
    [switch]$NoGarble  = $false,
    [switch]$Debug     = $false
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

# ── Colors ──────────────────────────────────────────────────────────────────
function Green($m)  { Write-Host "[+] $m" -ForegroundColor Green  }
function Cyan($m)   { Write-Host "[*] $m" -ForegroundColor Cyan   }
function Yellow($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Red($m)    { Write-Host "[!] $m" -ForegroundColor Red    }

# ── Step 0: Check Go ─────────────────────────────────────────────────────────
Cyan "Checking Go toolchain..."
try { $goVer = (go version 2>&1); Green $goVer }
catch { Red "Go not found in PATH"; exit 1 }

# ── Step 1: Layer 3 — Regenerate random phantom pad ─────────────────────────
Cyan "Layer 3: Regenerating phantom pad (random binary mutation)..."
Push-Location "$Root\internal\phantom"
go run gen_phantom.go
if ($LASTEXITCODE -ne 0) { Red "gen_phantom.go failed"; exit 1 }
Green "Phantom pad regenerated → new data section hash"
Pop-Location

# ── Step 2: Layer 2 — Generate unique Build ID (UUID v4) ────────────────────
Cyan "Layer 2: Generating unique Build ID..."
$bytes = New-Object byte[] 16
([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($bytes)
$bytes[6] = ($bytes[6] -band 0x0f) -bor 0x40  # version 4
$bytes[8] = ($bytes[8] -band 0x3f) -bor 0x80  # variant bits
$BuildID = "{0}-{1}-{2}-{3}-{4}" -f `
    ([BitConverter]::ToString($bytes[0..3])  -replace "-","").ToLower(),
    ([BitConverter]::ToString($bytes[4..5])  -replace "-","").ToLower(),
    ([BitConverter]::ToString($bytes[6..7])  -replace "-","").ToLower(),
    ([BitConverter]::ToString($bytes[8..9])  -replace "-","").ToLower(),
    ([BitConverter]::ToString($bytes[10..15])-replace "-","").ToLower()
Green "Build ID: $BuildID"

# ── Step 3: Resolve garble ───────────────────────────────────────────────────
$useGarble = $false
if (-not $NoGarble) {
    $garblePath = (Get-Command garble -ErrorAction SilentlyContinue)?.Source
    if ($garblePath) {
        Green "garble found: $garblePath"
        $useGarble = $true
    } else {
        Yellow "garble not installed. Attempting install..."
        go install mvdan.cc/garble@latest 2>&1 | Out-Null
        $garblePath = (Get-Command garble -ErrorAction SilentlyContinue)?.Source
        if ($garblePath) {
            Green "garble installed: $garblePath"
            $useGarble = $true
        } else {
            Yellow "garble install failed — falling back to standard go build"
            Yellow "Install manually: go install mvdan.cc/garble@latest"
        }
    }
}

# ── Step 4: Build ────────────────────────────────────────────────────────────
$env:GOOS    = "windows"
$env:GOARCH  = "amd64"

$ldflags = "-s -w -X 'ad-necromancer/internal/phantom.BuildID=$BuildID'"
if ($Debug) { $ldflags = "-X 'ad-necromancer/internal/phantom.BuildID=$BuildID'" }

if ($useGarble) {
    # Layer 1: garble with a fresh random seed every build
    $garbleSeed = -join ((0..31) | ForEach-Object { [char]((Get-Random -Min 97 -Max 123)) })
    Cyan "Layer 1: Building with garble (seed=$garbleSeed)..."
    & garble -seed=$garbleSeed -literals -tiny build -trimpath `
        -ldflags $ldflags `
        -o $OutFile `
        ./cmd/ad-necromancer/
} else {
    Cyan "Building with standard go build (-trimpath)..."
    go build -trimpath `
        -ldflags $ldflags `
        -o $OutFile `
        ./cmd/ad-necromancer/
}

if ($LASTEXITCODE -ne 0) { Red "Build failed"; exit 1 }

# ── Step 5: Show result ──────────────────────────────────────────────────────
$item  = Get-Item $OutFile
$hash  = (Get-FileHash $OutFile -Algorithm SHA256).Hash
$sizeMB = [math]::Round($item.Length / 1MB, 2)

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Green "Build complete: $OutFile ($sizeMB MB)"
Cyan  "Build ID : $BuildID"
Cyan  "SHA-256  : $hash"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host ""

if ($useGarble) {
    Green "Polymorphism layers applied: garble (-literals -seed) + BuildID UUID + phantom pad"
} else {
    Yellow "Polymorphism layers applied: BuildID UUID + phantom pad (no garble)"
    Yellow "Run with garble for maximum obfuscation: install mvdan.cc/garble@latest"
}
