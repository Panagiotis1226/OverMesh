# OverMesh Windows uninstaller (run as Administrator).
#Requires -RunAsAdministrator
$ErrorActionPreference = 'SilentlyContinue'

$dest = Join-Path $env:ProgramFiles 'OverMesh'

& (Join-Path $dest 'overmesh.exe') down
& (Join-Path $dest 'overmeshd.exe') -service stop
& (Join-Path $dest 'overmeshd.exe') -service uninstall
Remove-NetFirewallRule -DisplayName 'OverMesh WireGuard'
Remove-Item $dest -Recurse -Force
# State (keys, OverDrop inbox) stays in $env:ProgramData\OverMesh —
# delete that folder too if you want the device to re-enroll fresh.
Write-Host 'OverMesh removed (state kept in ProgramData\OverMesh).'
