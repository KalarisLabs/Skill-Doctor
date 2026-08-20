# Skill Doctor Install Script for Windows (PowerShell)

$ErrorActionPreference = "Stop"

$Repo = "KalarisLabs/Skill-Doctor"
$AssetName = "skill-doctor-windows-amd64.exe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installing Skill Doctor for Windows   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$InstallDir = Join-Path $env:USERPROFILE ".skill-doctor\bin"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$DestPath = Join-Path $InstallDir "skill-doctor.exe"
$TempPath = Join-Path $env:TEMP "skill-doctor-download.exe"

Write-Host "Locating release asset for $AssetName..." -ForegroundColor Yellow

$DownloadUrl = $null

# First try direct latest release URL
$LatestDirect = "https://github.com/$Repo/releases/latest/download/$AssetName"

# Check if curl.exe is available (default on Win10/11)
$HasCurl = $null -ne (Get-Command "curl.exe" -ErrorAction SilentlyContinue)

if ($HasCurl) {
    & curl.exe -fSL -s "$LatestDirect" -o "$TempPath"
    if ($LASTEXITCODE -eq 0 -and (Test-Path "$TempPath") -and ((Get-Item "$TempPath").Length -gt 100000)) {
        $DownloadUrl = $LatestDirect
    }
}

if (-not $DownloadUrl) {
    # Query all releases to find the latest one that has the Windows binary
    Write-Host "Searching releases on GitHub..." -ForegroundColor DarkGray
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    $ApiUrl = "https://api.github.com/repos/$Repo/releases"
    $Releases = Invoke-RestMethod -Uri $ApiUrl -Headers @{"User-Agent"="PowerShell"}

    foreach ($Release in $Releases) {
        $Found = $Release.assets | Where-Object { $_.name -eq $AssetName }
        if ($Found) {
            $DownloadUrl = $Found.browser_download_url
            Write-Host "Found in release $($Release.tag_name): $DownloadUrl" -ForegroundColor DarkGray
            break
        }
    }

    if (-not $DownloadUrl) {
        Write-Error "Could not find $AssetName in any GitHub release."
        exit 1
    }

    if ($HasCurl) {
        & curl.exe -fSL "$DownloadUrl" -o "$TempPath"
    } else {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile "$TempPath" -UseBasicParsing
    }
}

if (-not (Test-Path "$TempPath") -or ((Get-Item "$TempPath").Length -lt 100000)) {
    Write-Error "Downloaded binary appears invalid or incomplete."
    exit 1
}

Move-Item -Path "$TempPath" -Destination "$DestPath" -Force

# Add to User PATH persistently (prepended so it takes highest priority)
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notmatch [regex]::Escape($InstallDir)) {
    Write-Host "Adding $InstallDir to user PATH..." -ForegroundColor DarkGray
    [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$UserPath", "User")
}

# Update current session PATH so skill-doctor works immediately
if ($env:Path -notmatch [regex]::Escape($InstallDir)) {
    $env:Path = "$InstallDir;$env:Path"
}

Write-Host "`nSkill Doctor installed successfully to $DestPath!" -ForegroundColor Green
Write-Host "Run 'skill-doctor --help' or 'skill-doctor scan <path>' to get started.`n" -ForegroundColor Green
