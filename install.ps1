# Skill Doctor Install Script for Windows (PowerShell)

$ErrorActionPreference = "Stop"

$Repo = "KalarisLabs/Skill-Doctor"
$AssetName = "skill-doctor-windows-amd64.exe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installing Skill Doctor for Windows   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$DownloadUrl = "https://github.com/$Repo/releases/latest/download/$AssetName"
$TempPath = Join-Path $env:TEMP "skill-doctor.exe"

Write-Host "Downloading Skill Doctor binary..." -ForegroundColor Yellow
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath -UseBasicParsing
} catch {
    # Fallback to querying GitHub API if latest redirect isn't resolved
    Write-Host "Direct download failed, querying GitHub releases API..." -ForegroundColor DarkGray
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
    $Release = Invoke-RestMethod -Uri $ApiUrl -Headers @{"User-Agent"="PowerShell"}
    $Asset = $Release.assets | Where-Object { $_.name -eq $AssetName }
    if (-not $Asset) {
        Write-Error "Could not find release asset $AssetName on GitHub Releases."
        exit 1
    }
    Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $TempPath -UseBasicParsing
}

# Determine install location (user-specific to avoid requiring admin privileges)
$InstallDir = Join-Path $env:USERPROFILE ".skill-doctor\bin"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$DestPath = Join-Path $InstallDir "skill-doctor.exe"
Move-Item -Path $TempPath -Destination $DestPath -Force

# Add to User PATH persistently
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notmatch [regex]::Escape($InstallDir)) {
    Write-Host "Adding $InstallDir to user PATH..." -ForegroundColor DarkGray
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
}

# Update current session PATH so skill-doctor works immediately
if ($env:Path -notmatch [regex]::Escape($InstallDir)) {
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host "`nSkill Doctor installed successfully to $DestPath!" -ForegroundColor Green
Write-Host "Run 'skill-doctor --help' or 'skill-doctor scan <path>' to get started.`n" -ForegroundColor Green
