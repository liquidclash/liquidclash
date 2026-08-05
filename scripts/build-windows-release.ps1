[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$appRoot = Join-Path $repositoryRoot 'Tono-win\app'
$serviceManifest = Join-Path $repositoryRoot 'Tono-win\service\Cargo.toml'
$serviceTarget = Join-Path $repositoryRoot 'Tono-win\service\target\release'
$resourceRoot = Join-Path $appRoot 'src-tauri\resources'
$mihomoPath = Join-Path $appRoot 'src-tauri\sidecar\verge-mihomo-x86_64-pc-windows-msvc.exe'
$installerPath = Join-Path $appRoot "target\release\bundle\nsis\Tono_${Version}_x64-setup.exe"

$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path -LiteralPath $cargoBin) {
    $env:PATH = "$cargoBin;$env:PATH"
}
$sevenZipBin = 'C:\Program Files\7-Zip'
if (Test-Path -LiteralPath (Join-Path $sevenZipBin '7z.exe')) {
    $env:PATH = "$sevenZipBin;$env:PATH"
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [string[]]$ArgumentList = @(),

        [Parameter(Mandatory)]
        [string]$WorkingDirectory
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $FilePath @ArgumentList
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath exited with code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

foreach ($command in @('cargo', 'pnpm')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required build command is missing: $command"
    }
}
if (-not (Test-Path -LiteralPath $mihomoPath -PathType Leaf)) {
    throw "Stable Mihomo sidecar is missing: $mihomoPath"
}

Invoke-Checked -FilePath 'pnpm' -ArgumentList @('release-version', $Version) -WorkingDirectory $appRoot
Invoke-Checked -FilePath 'pnpm' -ArgumentList @('release:preflight', '--config-only') -WorkingDirectory $appRoot

$coreSha256 = (Get-FileHash -LiteralPath $mihomoPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($coreSha256 -notmatch '^[0-9a-f]{64}$') {
    throw "Invalid Mihomo SHA-256: $coreSha256"
}
$env:TONO_CORE_SHA256 = $coreSha256

$serviceBins = @('tono-service', 'tono-service-install', 'tono-service-uninstall')
$cargoArguments = @(
    'build',
    '--manifest-path', $serviceManifest,
    '--release',
    '--features', 'standalone,client'
)
foreach ($serviceBin in $serviceBins) {
    $cargoArguments += @('--bin', $serviceBin)
}
Invoke-Checked -FilePath 'cargo' -ArgumentList $cargoArguments -WorkingDirectory $repositoryRoot

foreach ($serviceBin in $serviceBins) {
    $source = Join-Path $serviceTarget "$serviceBin.exe"
    $destination = Join-Path $resourceRoot "$serviceBin.exe"
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Service build output is missing: $source"
    }
    Copy-Item -LiteralPath $source -Destination $destination -Force
}

# `option_env!("TONO_CORE_SHA256")` must survive into the production Service. A missing pin is
# deliberately fatal at runtime, so prove the exact digest is embedded before packaging it.
$servicePath = Join-Path $resourceRoot 'tono-service.exe'
$serviceAscii = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($servicePath))
if (-not $serviceAscii.Contains($coreSha256)) {
    throw 'The built Tono Service does not contain the injected Mihomo SHA-256 pin.'
}

Invoke-Checked -FilePath 'pnpm' -ArgumentList @('build') -WorkingDirectory $appRoot
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    throw "NSIS installer was not produced: $installerPath"
}
Invoke-Checked -FilePath 'pnpm' -ArgumentList @(
    'release:preflight', '--payload-only', $installerPath
) -WorkingDirectory $appRoot

[ordered]@{
    version = $Version
    installer = $installerPath
    installerSha256 = (Get-FileHash -LiteralPath $installerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    mihomoSha256 = $coreSha256
    serviceSha256 = (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant()
} | ConvertTo-Json
