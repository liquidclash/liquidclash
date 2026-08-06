[CmdletBinding()]
param(
    [ValidateRange(5, 120)]
    [int]$WaitSeconds = 30,

    [string]$OutputPath = (Join-Path $env:TEMP 'tono-protected-dns-probe.json')
)

$ErrorActionPreference = 'Stop'
$deadline = [DateTimeOffset]::UtcNow.AddSeconds($WaitSeconds)
$ready = $false
$protectedDnsV4 = '198.18.0.2'

function Get-PhysicalDnsState {
    $physicalIndexes = @(
        Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object Status -ne 'Disabled' |
            ForEach-Object ifIndex
    )

    @(
        Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
            Where-Object { $physicalIndexes -contains $_.InterfaceIndex } |
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
}

function Test-ProtectedDnsState {
    param([object[]]$DnsState)

    $ipv4 = @($DnsState | Where-Object family -eq 'IPv4')
    $ipv6 = @($DnsState | Where-Object family -eq 'IPv6')
    if ($ipv4.Count -eq 0) {
        return $false
    }

    $ipv4Protected = @($ipv4 | Where-Object {
        $_.servers.Count -eq 1 -and $_.servers[0] -eq $protectedDnsV4
    }).Count -eq $ipv4.Count
    $ipv6Protected = @($ipv6 | Where-Object { $_.servers.Count -eq 0 }).Count -eq $ipv6.Count
    $ipv4Protected -and $ipv6Protected
}

while ([DateTimeOffset]::UtcNow -lt $deadline) {
    $listener = netstat.exe -ano | Where-Object { $_ -match '^\s*(TCP|UDP)\s+127\.0\.0\.1:53\s' }
    $physicalDns = @(Get-PhysicalDnsState)
    if ($listener -and (Test-ProtectedDnsState -DnsState $physicalDns)) {
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

function Test-FakeIpAnswers {
    param([object]$Probe)

    if (-not $Probe.ok -or $Probe.addresses.Count -eq 0) {
        return $false
    }
    @($Probe.addresses | Where-Object {
        $parsed = $null
        [Net.IPAddress]::TryParse([string]$_, [ref]$parsed) -and
            $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            $parsed.GetAddressBytes()[0] -eq 198 -and
            $parsed.GetAddressBytes()[1] -eq 18
    }).Count -eq $Probe.addresses.Count
}

$result = if (-not $ready) {
    [ordered]@{
        ready = $false
        error = "protected DNS state did not appear within $WaitSeconds seconds"
    }
}
else {
    $tunQuery = Invoke-DnsProbe -Server $protectedDnsV4
    $loopbackQuery = Invoke-DnsProbe -Server '127.0.0.1'
    $systemQuery = Invoke-DnsProbe
    $proofOk = (Test-FakeIpAnswers -Probe $tunQuery) -and
        (Test-FakeIpAnswers -Probe $systemQuery) -and
        -not $loopbackQuery.ok
    [ordered]@{
        ready = $true
        proof_ok = $proofOk
        captured_at = [DateTimeOffset]::Now.ToString('o')
        listeners = @(netstat.exe -ano | Where-Object { $_ -match '^\s*(TCP|UDP)\s+127\.0\.0\.1:53\s' })
        # Supporting evidence only. The authenticated Service status and fake-IP system query are
        # authoritative because active virtual adapters may also be owned by Windows DNS.
        physical_dns = @(Get-PhysicalDnsState)
        all_dns = @(
            Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
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
        tun_query = $tunQuery
        loopback_query = $loopbackQuery
        system_query = $systemQuery
    }
}

$fullPath = [IO.Path]::GetFullPath($OutputPath)
$directory = Split-Path -Parent $fullPath
if ($directory) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $fullPath -Encoding utf8NoBOM
Write-Output $fullPath
if (-not $result.ready -or -not $result.proof_ok) {
    exit 1
}
