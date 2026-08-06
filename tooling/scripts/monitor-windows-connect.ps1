[CmdletBinding()]
param(
    [ValidateRange(5, 600)]
    [int]$DurationSeconds = 45,

    [ValidateRange(100, 5000)]
    [int]$IntervalMilliseconds = 200,

    [string]$OutputPath = (Join-Path $env:TEMP 'tono-connect-monitor.jsonl')
)

$ErrorActionPreference = 'Stop'
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

function Get-TonoFastState {
    # The Get-Net* cmdlets take roughly half a second per sample on a typical machine. netstat
    # gives the same PID-level evidence quickly enough to catch Mihomo's short bind/start window.
    $port53 = @(
        netstat.exe -ano |
            Where-Object { $_ -match '^\s*(TCP|UDP)\s+\S+:53\s' } |
            ForEach-Object { (($_.Trim()) -replace '\s+', ' ') } |
            Sort-Object
    )
    $processes = @(
        Get-Process Tono, mihomo, verge-mihomo -ErrorAction SilentlyContinue |
            Sort-Object ProcessName, Id |
            ForEach-Object {
                [ordered]@{
                    name = $_.ProcessName
                    pid = $_.Id
                    responding = if ($_.ProcessName -eq 'Tono') { $_.Responding } else { $null }
                }
            }
    )

    [ordered]@{
        port53 = $port53
        processes = $processes
    }
}

function Get-TonoSlowState {
    $dns = @(
        Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses.Count -gt 0 } |
            Sort-Object InterfaceIndex, AddressFamily |
            ForEach-Object {
                [ordered]@{
                    alias = $_.InterfaceAlias
                    index = $_.InterfaceIndex
                    family = [string]$_.AddressFamily
                    servers = @($_.ServerAddresses)
                }
            }
    )
    $service = Get-CimInstance Win32_Service -Filter "Name='TonoService'" -ErrorAction SilentlyContinue

    [ordered]@{
        dns = $dns
        service = if ($service) {
            [ordered]@{ state = $service.State; pid = [uint32]$service.ProcessId }
        } else {
            $null
        }
    }
}

$startedAt = Get-Date
$deadline = $startedAt.AddSeconds($DurationSeconds)
$lastFingerprint = $null
$lastEmission = [datetime]::MinValue
$sequence = 0
$slowState = Get-TonoSlowState
$nextSlowSample = $startedAt.AddSeconds(1)

Set-Content -LiteralPath $outputFullPath -Value '' -Encoding utf8NoBOM
while ((Get-Date) -lt $deadline) {
    $now = Get-Date
    if ($now -ge $nextSlowSample) {
        $slowState = Get-TonoSlowState
        $nextSlowSample = $now.AddSeconds(1)
    }
    $fastState = Get-TonoFastState
    $state = [ordered]@{
        port53 = $fastState.port53
        processes = $fastState.processes
        dns = $slowState.dns
        service = $slowState.service
    }
    $fingerprint = $state | ConvertTo-Json -Depth 6 -Compress
    $now = Get-Date
    if ($fingerprint -ne $lastFingerprint -or ($now - $lastEmission).TotalSeconds -ge 2) {
        $record = [ordered]@{
            sequence = $sequence
            at = $now.ToString('o')
            elapsed_ms = [int]($now - $startedAt).TotalMilliseconds
            changed = $fingerprint -ne $lastFingerprint
            state = $state
        }
        Add-Content -LiteralPath $outputFullPath -Value ($record | ConvertTo-Json -Depth 7 -Compress) -Encoding utf8NoBOM
        $sequence++
        $lastEmission = $now
        $lastFingerprint = $fingerprint
    }
    Start-Sleep -Milliseconds $IntervalMilliseconds
}

Write-Output $outputFullPath
