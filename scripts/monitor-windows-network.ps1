[CmdletBinding()]
param(
    [ValidateRange(5, 300)]
    [int]$DurationSeconds = 45,

    [ValidateRange(100, 5000)]
    [int]$IntervalMilliseconds = 200,

    [string]$OutputPath = (Join-Path $env:TEMP 'tono-network-monitor.jsonl')
)

$ErrorActionPreference = 'Stop'
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath
if ($outputDirectory) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
Set-Content -LiteralPath $outputFullPath -Value '' -Encoding utf8NoBOM

$deadline = (Get-Date).AddSeconds($DurationSeconds)
while ((Get-Date) -lt $deadline) {
    $startedAt = Get-Date
    $client = [Net.Sockets.TcpClient]::new()
    $connected = $false
    $errorText = $null
    try {
        $task = $client.ConnectAsync('1.1.1.1', 443)
        $connected = $task.Wait(1000) -and $client.Connected
        if (-not $connected) {
            $errorText = 'timeout'
        }
    }
    catch {
        $errorText = $_.Exception.GetBaseException().Message
    }
    finally {
        $client.Dispose()
    }

    [ordered]@{
        at = $startedAt.ToString('o')
        elapsed_ms = [int]((Get-Date) - $startedAt).TotalMilliseconds
        tcp_443 = $connected
        error = $errorText
    } | ConvertTo-Json -Compress | Add-Content -LiteralPath $outputFullPath -Encoding utf8NoBOM

    Start-Sleep -Milliseconds $IntervalMilliseconds
}

Write-Output $outputFullPath
