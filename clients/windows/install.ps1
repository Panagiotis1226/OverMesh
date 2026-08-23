# OverMesh Windows installer (run as Administrator).
#
#   1. Download the overmesh_windows_amd64 artifact from CI and unzip.
#   2. From that folder, in an elevated PowerShell:
#        Set-ExecutionPolicy -Scope Process Bypass
#        .\install.ps1
#   3. Join your mesh:
#        overmesh up -server your-server:41641 -key sk-...
#
# What it does: copies the binaries to Program Files\OverMesh, fetches
# the matching wintun.dll (the TUN driver wireguard-go uses on
# Windows), installs + starts the OverMesh service, adds a WireGuard
# firewall rule, and puts the install dir on PATH.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

$dest = Join-Path $env:ProgramFiles 'OverMesh'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Installing OverMesh to $dest"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

foreach ($bin in 'overmeshd.exe', 'overmesh.exe') {
    $src = Join-Path $here $bin
    if (-not (Test-Path $src)) { throw "$bin not found next to install.ps1" }
    Copy-Item $src $dest -Force
}

# Wintun: the userspace WireGuard data plane loads wintun.dll from the
# daemon's directory. Fetch the official signed build if missing.
$wintun = Join-Path $dest 'wintun.dll'
if (-not (Test-Path $wintun)) {
    $arch = if ([Environment]::Is64BitOperatingSystem) {
        if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    } else { 'x86' }
    Write-Host "Downloading wintun.dll ($arch)"
    $zip = Join-Path $env:TEMP 'wintun.zip'
    Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip
    $tmp = Join-Path $env:TEMP 'wintun-extract'
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    Copy-Item (Join-Path $tmp "wintun\bin\$arch\wintun.dll") $wintun
    Remove-Item $zip, $tmp -Recurse -Force
}

# Firewall: let WireGuard's UDP through.
if (-not (Get-NetFirewallRule -DisplayName 'OverMesh WireGuard' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'OverMesh WireGuard' -Direction Inbound `
        -Protocol UDP -LocalPort 41642 -Action Allow | Out-Null
}

# PATH for `overmesh` in new shells.
$path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($path -notlike "*$dest*") {
    [Environment]::SetEnvironmentVariable('Path', "$path;$dest", 'Machine')
}

# Service: install (idempotent) and start.
& (Join-Path $dest 'overmeshd.exe') -service uninstall 2>$null | Out-Null
& (Join-Path $dest 'overmeshd.exe') -service install
& (Join-Path $dest 'overmeshd.exe') -service start

Write-Host ''
Write-Host 'OverMesh installed. Join your mesh from a NEW elevated PowerShell:'
Write-Host '  overmesh up -server <your-server>:41641 -key sk-...'
Write-Host '  overmesh status'
