# Skill Doctor Install Script for Windows (PowerShell)

$ErrorActionPreference = "Stop"

$Repo = "KalarisLabs/Skill-Doctor"
$AssetName = "skill-doctor-windows-amd64.exe"

Write-Host "Installing Skill Doctor..."

# Fetch latest release data from GitHub API
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
$Release = Invoke-RestMethod -Uri $ApiUrl

$Asset = $Release.assets | Where-Object { $_.name -eq $AssetName }

if (-not $Asset) {
    Write-Error "Could not find release asset $AssetName"
    exit 1
}

$DownloadUrl = $Asset.browser_download_url
$TempPath = Join-Path $env:TEMP "skill-doctor.exe"

Write-Host "Downloading from $DownloadUrl..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempPath

# Determine install location (user-specific to avoid requiring admin)
$InstallDir = Join-Path $env:USERPROFILE "AppData\Local\Programs\SkillDoctor"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}

$DestPath = Join-Path $InstallDir "skill-doctor.exe"
Move-Item -Path $TempPath -Destination $DestPath -Force

# Add to PATH if not already there
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notmatch [regex]::Escape($InstallDir)) {
    Write-Host "Adding $InstallDir to user PATH..."
    [Environment]::SetEnvironmentVariable("PATH", $UserPath + ";" + $InstallDir, "User")
    Write-Host "Please restart your terminal to use the command."
}

Write-Host "✅ Skill Doctor installed successfully!"
Write-Host "Run 'skill-doctor --help' to get started."
