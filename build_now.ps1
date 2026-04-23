# Necromancer V2 — One-shot build script (PS5 compatible)
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

function Green($m)  { Write-Host "[+] $m" -ForegroundColor Green }
function Cyan($m)   { Write-Host "[*] $m" -ForegroundColor Cyan  }
function Yellow($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Red($m)    { Write-Host "[!] $m" -ForegroundColor Red   }

# Step 1: Regenerate phantom pad
Cyan "Regenerating phantom pad..."
Push-Location "$Root\internal\phantom"
go run gen_phantom.go
if ($LASTEXITCODE -ne 0) { Red "gen_phantom.go failed"; exit 1 }
Green "Phantom pad regenerated"
Pop-Location

# Step 2: Generate UUID v4 Build ID
$bytes = New-Object byte[] 16
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$bytes[6] = ($bytes[6] -band 0x0f) -bor 0x40
$bytes[8] = ($bytes[8] -band 0x3f) -bor 0x80
$p1 = [BitConverter]::ToString($bytes[0..3])  -replace "-",""
$p2 = [BitConverter]::ToString($bytes[4..5])  -replace "-",""
$p3 = [BitConverter]::ToString($bytes[6..7])  -replace "-",""
$p4 = [BitConverter]::ToString($bytes[8..9])  -replace "-",""
$p5 = [BitConverter]::ToString($bytes[10..15])-replace "-",""
$BuildID = "$($p1.ToLower())-$($p2.ToLower())-$($p3.ToLower())-$($p4.ToLower())-$($p5.ToLower())"
Green "Build ID: $BuildID"

# Step 3: Check garble availability
$garbleCmd = Get-Command garble -ErrorAction SilentlyContinue
if ($garbleCmd) {
    $useGarble = $true
    Green "garble found: $($garbleCmd.Source)"
} else {
    $useGarble = $false
    Yellow "garble not found — using standard go build"
    Yellow "Install with: go install mvdan.cc/garble@latest"
}

# Step 4: Build
$env:GOOS   = "windows"
$env:GOARCH = "amd64"
$ldflags = "-s -w -X ad-necromancer/internal/phantom.BuildID=$BuildID"
$outFile = "ad-necromancer-v2.exe"

if ($useGarble) {
    $chars = "abcdefghijklmnopqrstuvwxyz"
    $seed  = -join (1..32 | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] })
    Cyan "Building with garble -seed=$seed -literals -tiny..."
    & garble "-seed=$seed" -literals -tiny build -trimpath `
        -ldflags $ldflags `
        -o $outFile `
        ./cmd/ad-necromancer/
} else {
    Cyan "Building with standard go build -trimpath..."
    & go build -trimpath `
        -ldflags $ldflags `
        -o $outFile `
        ./cmd/ad-necromancer/
}

if ($LASTEXITCODE -ne 0) { Red "Build failed"; exit 1 }

# Step 5: Results
$hash   = (Get-FileHash $outFile -Algorithm SHA256).Hash
$sizeKB = [math]::Round((Get-Item $outFile).Length / 1KB)
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Green "Binary  : $outFile ($sizeKB KB)"
Cyan  "Build ID: $BuildID"
Cyan  "SHA-256 : $hash"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host ""
if ($useGarble) {
    Green "Layers: garble(-literals -seed) + BuildID UUID + phantom pad"
} else {
    Yellow "Layers: BuildID UUID + phantom pad (garble not used)"
}
