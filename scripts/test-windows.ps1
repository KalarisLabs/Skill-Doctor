# scripts/test-windows.ps1 — Windows local test execution with optional binary code-signing
#
# Usage:
#   .\scripts\test-windows.ps1 -Thumbprint <CERT_THUMBPRINT>
#   .\scripts\test-windows.ps1 -SkipSigning
#   .\scripts\test-windows.ps1
#
[CmdletBinding()]
param(
    [string]$Thumbprint = "",
    [string]$SigntoolPath = "",
    [switch]$SkipSigning
)

$ErrorActionPreference = "Stop"

Write-Host "Building test binaries..." -ForegroundColor Cyan
cargo test --workspace --all-features --locked --no-run
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $SkipSigning -and $Thumbprint) {
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

    if (-not $SigntoolPath -or -not (Test-Path $SigntoolPath)) {
        Write-Error "signtool.exe not found. Please install Windows SDK or specify -SigntoolPath."
        exit 1
    }

    Write-Host "Signing test binaries with $SigntoolPath (Thumbprint: $Thumbprint)..." -ForegroundColor Cyan
    $testExes = Get-ChildItem -Path "target\debug\deps\*.exe" -ErrorAction SilentlyContinue
    foreach ($exe in $testExes) {
        & $SigntoolPath sign /fd SHA256 /sha1 $Thumbprint $exe.FullName
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Code signing failed for $($exe.FullName) with exit code $LASTEXITCODE"
            exit $LASTEXITCODE
        }
    }
} elseif (-not $SkipSigning) {
    Write-Host "No -Thumbprint specified; running unsigned (pass -Thumbprint <SHA1> if AppLocker blocks execution, or -SkipSigning)..." -ForegroundColor Yellow
}

Write-Host "Running tests..." -ForegroundColor Cyan
cargo test --workspace --all-features --locked
exit $LASTEXITCODE
