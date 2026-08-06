[CmdletBinding()]
param(
    [ValidateRange(30, 3600)]
    [int]$MaximumDurationSeconds = 900,

    [ValidateRange(250, 5000)]
    [int]$IntervalMilliseconds = 500,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [Parameter(Mandatory)]
    [string]$StagePath,

    [Parameter(Mandatory)]
    [string]$StopPath
)

$ErrorActionPreference = 'Continue'
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$directory = Split-Path -Parent $outputFullPath
New-Item -ItemType Directory -Path $directory -Force | Out-Null
Set-Content -LiteralPath $outputFullPath -Value '' -Encoding utf8NoBOM

$deadline = [DateTimeOffset]::Now.AddSeconds($MaximumDurationSeconds)
while ([DateTimeOffset]::Now -lt $deadline -and -not (Test-Path -LiteralPath $StopPath)) {
    $startedAt = [DateTimeOffset]::Now
    $stage = if (Test-Path -LiteralPath $StagePath) {
        (Get-Content -LiteralPath $StagePath -Raw -ErrorAction SilentlyContinue).Trim()
    } else {
        'unknown'
    }
    $ip = $null
    $errorText = $null
    $handler = $null
    $client = $null
    $request = $null
    $response = $null
    try {
        # A new HttpClient and Connection: close request prevent a connection established before
        # the fault from hiding a later physical-interface fallback.
        $handler = [Net.Http.HttpClientHandler]::new()
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(3)
        $request = [Net.Http.HttpRequestMessage]::new(
            [Net.Http.HttpMethod]::Get,
            "https://api.ipify.org?format=json&nonce=$([Guid]::NewGuid().ToString('N'))"
        )
        $request.Headers.ConnectionClose = $true
        $response = $client.Send($request)
        $response.EnsureSuccessStatusCode() | Out-Null
        $payload = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json
        $parsedAddress = $null
        if ($payload.ip -and [Net.IPAddress]::TryParse([string]$payload.ip, [ref]$parsedAddress)) {
            $ip = [string]$payload.ip
        } else {
            $errorText = 'public IP response omitted a valid address'
        }
    }
    catch {
        $errorText = $_.Exception.GetBaseException().Message
    }
    finally {
        if ($request) { $request.Dispose() }
        if ($response) { $response.Dispose() }
        if ($client) { $client.Dispose() }
        if ($handler) { $handler.Dispose() }
    }

    [ordered]@{
        at = $startedAt.ToString('o')
        stage = $stage
        elapsed_ms = [int]([DateTimeOffset]::Now - $startedAt).TotalMilliseconds
        ok = $null -ne $ip
        ip = $ip
        error = $errorText
    } | ConvertTo-Json -Compress |
        Add-Content -LiteralPath $outputFullPath -Encoding utf8NoBOM

    Start-Sleep -Milliseconds $IntervalMilliseconds
}

Write-Output $outputFullPath
