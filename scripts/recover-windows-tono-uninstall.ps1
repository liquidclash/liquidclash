#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Emergency recovery when Tono install/uninstall fails with result 3.

.DESCRIPTION
  Stops TonoService, runs emergency disarm + uninstall helper, and reports DNS.
  Run this from an elevated PowerShell on a stuck customer machine, then retry
  Tono_0.0.14_x64-setup.exe (or newer).

  Does not delete Program Files until the helper proves the kill switch is gone.
#>
$ErrorActionPreference = 'Continue'

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "=== $Message ===" -ForegroundColor Cyan
}

Write-Step "Elevation check"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    throw "Run this script as Administrator (right-click PowerShell -> Run as administrator)."
}

Write-Step "Service status"
Get-Service TonoService -ErrorAction SilentlyContinue | Format-List Name, Status, StartType, BinaryPathName

Write-Step "Stop TonoService (best effort)"
try {
    Stop-Service TonoService -Force -ErrorAction Stop
    Write-Host "Stopped TonoService."
} catch {
    Write-Host "Stop-Service: $($_.Exception.Message)"
}
sc.exe stop TonoService 2>&1 | Out-Host

$candidates = @(
    'C:\Program Files\Tono\resources\tono-service.exe',
    'C:\ProgramData\Tono\bin\tono-service.exe',
    'C:\Program Files\Tono\resources\tono-service-uninstall.exe'
)

Write-Step "Emergency disarm (if service binary present)"
$serviceExe = $candidates | Where-Object { Test-Path $_ -PathType Leaf -and $_ -like '*tono-service.exe' } | Select-Object -First 1
if ($serviceExe) {
    Write-Host "Running: $serviceExe --emergency-disarm"
    & $serviceExe --emergency-disarm 2>&1 | Out-Host
    Write-Host "ExitCode=$LASTEXITCODE"
} else {
    Write-Host "tono-service.exe not found; skip."
}

Write-Step "Uninstall helper"
$uninstallExe = 'C:\Program Files\Tono\resources\tono-service-uninstall.exe'
if (Test-Path $uninstallExe) {
    Write-Host "Running: $uninstallExe"
    & $uninstallExe 2>&1 | Out-Host
    Write-Host "ExitCode=$LASTEXITCODE  (0/2/4 = safe to continue install; 3 = still blocked)"
} else {
    Write-Host "tono-service-uninstall.exe not found."
}

Write-Step "DNS (should not be 198.18.0.2 / 127.0.0.1 for normal adapters)"
Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses } |
    Format-Table InterfaceAlias, ServerAddresses -AutoSize

Write-Step "Next steps"
Write-Host @"
1. If ExitCode was 0, 2, or 4: run Tono_0.0.14_x64-setup.exe (or newer) again.
2. If still 3: reboot Windows, run this script once more, then install again.
3. If DNS is stuck on 198.18.0.2: Settings > Network & Internet > adapter > DNS > Automatic (DHCP).
4. Send the full console output above to support if it still fails.
"@
