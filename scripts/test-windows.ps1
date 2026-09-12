# scripts/test-windows.ps1 — Windows local test execution with optional binary code-signing
#
# Usage:
#   .\scripts\test-windows.ps1
#   .\scripts\test-windows.ps1 -Thumbprint <CERT_THUMBPRINT>
#
[CmdletBinding()]
param(
    [string]$Thumbprint = "CAEEA5FAC496269C117C083B907780E42033C7C0",
    [string]$SigntoolPath = ""
)

$ErrorActionPreference = "Stop"

# Auto-detect signtool if not explicitly provided
if (-not $SigntoolPath) {
    $candidates = @(
        "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe",
        "C:\Program Files\Windows Kits\10\bin\*\x64\signtool.exe"
    )
    foreach ($cand in $candidates) {
        $found = Get-Item $cand -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) {
            $SigntoolPath = $found.FullName
            break
        }
    }
}

Write-Host "Building test binaries..." -ForegroundColor Cyan
cargo test --workspace --all-features --locked --no-run
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($SigntoolPath -and (Test-Path $SigntoolPath)) {
    Write-Host "Signing test binaries with $SigntoolPath..." -ForegroundColor Cyan
    $testExes = Get-ChildItem -Path "target\debug\deps\*.exe" -ErrorAction SilentlyContinue
    foreach ($exe in $testExes) {
        & $SigntoolPath sign /fd SHA256 /sha1 $Thumbprint $exe.FullName 2>$null | Out-Null
    }
}

Write-Host "Running tests..." -ForegroundColor Cyan
cargo test --workspace --all-features --locked
exit $LASTEXITCODE
