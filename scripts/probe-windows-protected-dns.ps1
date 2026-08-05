[CmdletBinding()]
param(
    [ValidateRange(5, 120)]
    [int]$WaitSeconds = 30,

    [string]$OutputPath = (Join-Path $env:TEMP 'tono-protected-dns-probe.json')
)

$ErrorActionPreference = 'Stop'
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitSeconds)
$ready = $false

while ([DateTimeOffset]::UtcNow -lt $deadline) {
    $listener = netstat.exe -ano | Where-Object { $_ -match '^\s*(TCP|UDP)\s+127\.0\.0\.1:53\s' }
    $ethernetDns = @(
        Get-DnsClientServerAddress -InterfaceAlias 'Ethernet' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            ForEach-Object ServerAddresses
    )
    if ($listener -and $ethernetDns -contains '127.0.0.1') {
        $ready = $true
        break
    }
    Start-Sleep -Milliseconds 100
}

function Invoke-DnsProbe {
    param([string]$Server)

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $parameters = @{
            Name        = 'www.gstatic.com'
            Type        = 'A'
            DnsOnly     = $true
            NoHostsFile = $true
            QuickTimeout = $true
            ErrorAction = 'Stop'
        }
        if ($Server) {
            $parameters.Server = $Server
        }
        $addresses = @(
            Resolve-DnsName @parameters |
                Where-Object { $_.Type -eq 'A' -and $_.IPAddress } |
                ForEach-Object IPAddress
        )
        [ordered]@{
            ok = $addresses.Count -gt 0
            elapsed_ms = $stopwatch.ElapsedMilliseconds
            addresses = $addresses
            error = if ($addresses.Count -gt 0) { $null } else { 'no A records' }
        }
    }
    catch {
        [ordered]@{
            ok = $false
            elapsed_ms = $stopwatch.ElapsedMilliseconds
            addresses = @()
            error = $_.Exception.Message
        }
    }
}

$result = if (-not $ready) {
    [ordered]@{
        ready = $false
        error = "protected DNS state did not appear within $WaitSeconds seconds"
    }
}
else {
    [ordered]@{
        ready = $true
        captured_at = [DateTimeOffset]::Now.ToString('o')
        listeners = @(netstat.exe -ano | Where-Object { $_ -match '^\s*(TCP|UDP)\s+127\.0\.0\.1:53\s' })
        dns = @(
            Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
                Where-Object { $_.ServerAddresses.Count -gt 0 } |
                ForEach-Object {
                    [ordered]@{
                        alias = $_.InterfaceAlias
                        index = $_.InterfaceIndex
                        family = [string]$_.AddressFamily
                        servers = @($_.ServerAddresses)
                    }
                }
        )
        tun_query = Invoke-DnsProbe -Server '198.18.0.2'
        loopback_query = Invoke-DnsProbe -Server '127.0.0.1'
        system_query = Invoke-DnsProbe
    }
}

$fullPath = [IO.Path]::GetFullPath($OutputPath)
$directory = Split-Path -Parent $fullPath
if ($directory) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fullPath -Encoding utf8NoBOM
Write-Output $fullPath
