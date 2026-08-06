#Requires -Version 7.2
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateRange(10, 300)]
    [int]$BaselineSeconds = 20,

    [ValidateRange(20, 300)]
    [int]$RecoverySeconds = 90,

    [ValidateSet('CoreCrash', 'ServiceCrash', 'AdapterFlap')]
    [string[]]$Faults = @(),

    [string]$AdapterName,

    [string[]]$AllowedProtectedEgressIp = @(),

    [string]$OutputDirectory = (Join-Path $env:ProgramData (
        'Tono\qa\' + [DateTimeOffset]::Now.ToString('yyyyMMdd-HHmmss')
    )),

    [switch]$ConfirmDisruptive
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$eventsPath = Join-Path $outputRoot 'events.jsonl'
$summaryPath = Join-Path $outputRoot 'summary.json'
$captureEtlPath = Join-Path $outputRoot 'packets.etl'
$capturePcapPath = Join-Path $outputRoot 'packets.pcapng'
$egressPath = Join-Path $outputRoot 'egress.jsonl'
$egressStagePath = Join-Path $outputRoot 'egress-stage.txt'
$egressStopPath = Join-Path $outputRoot 'egress-stop'
$dnsProbePath = Join-Path $outputRoot 'protected-dns.json'
$script:failures = [Collections.Generic.List[string]]::new()
$script:warnings = [Collections.Generic.List[string]]::new()
$script:unexpectedEgress = [Collections.Generic.List[string]]::new()
$script:pktmonStarted = $false
$script:egressMonitor = $null
$script:selectedAdapter = $null
$script:adapterDisabledByHarness = $false
$script:adapterRecoveryTask = $null
$script:baselineDiagnosis = $null
$script:crashedServicePid = $null

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
foreach ($evidencePath in @($eventsPath, $summaryPath, $captureEtlPath, $capturePcapPath, $egressPath)) {
    if (Test-Path -LiteralPath $evidencePath) {
        throw "OutputDirectory contains stale QA evidence; choose a new directory: $evidencePath"
    }
}
Set-Content -LiteralPath $eventsPath -Value '' -Encoding utf8NoBOM

function Write-QaEvent {
    param(
        [Parameter(Mandatory)] [string]$Kind,
        [Parameter(Mandatory)] [string]$Stage,
        [object]$Data
    )

    [ordered]@{
        at = [DateTimeOffset]::Now.ToString('o')
        kind = $Kind
        stage = $Stage
        data = $Data
    } | ConvertTo-Json -Depth 12 -Compress |
        Add-Content -LiteralPath $eventsPath -Encoding utf8NoBOM
}

function Get-ServiceSnapshot {
    $service = Get-CimInstance Win32_Service -Filter "Name='TonoService'" -ErrorAction SilentlyContinue
    if (-not $service) {
        return $null
    }
    [ordered]@{
        state = $service.State
        process_id = [uint32]$service.ProcessId
        start_mode = $service.StartMode
    }
}

function Get-DnsSnapshot {
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

function Get-DriverPath {
    @(
        (Join-Path $repositoryRoot 'apps\windows\service\target\release\tono-service-integration-driver.exe'),
        (Join-Path $repositoryRoot 'apps\windows\service\target\debug\tono-service-integration-driver.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}

function Get-TonoDiagnosis {
    $driver = Get-DriverPath
    if (-not $driver) {
        return [ordered]@{ available = $false; error = 'integration driver is not built' }
    }
    try {
        $text = (& $driver diagnose 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            return [ordered]@{ available = $true; error = $text }
        }
        [ordered]@{ available = $true; report = ($text | ConvertFrom-Json -Depth 20) }
    }
    catch {
        [ordered]@{ available = $true; error = $_.Exception.GetBaseException().Message }
    }
}

function Get-QaSnapshot {
    [ordered]@{
        service = Get-ServiceSnapshot
        processes = @(
            Get-Process Tono, mihomo, verge-mihomo -ErrorAction SilentlyContinue |
                Sort-Object ProcessName, Id |
                ForEach-Object { [ordered]@{ name = $_.ProcessName; process_id = $_.Id } }
        )
        adapters = @(
            Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                Sort-Object ifIndex |
                ForEach-Object {
                    [ordered]@{
                        alias = $_.Name
                        index = $_.ifIndex
                        status = [string]$_.Status
                        link_speed = [string]$_.LinkSpeed
                    }
                }
        )
        dns = @(Get-DnsSnapshot)
    }
}

function Test-ProtectedDiagnosis {
    param(
        [Parameter(Mandatory)] [object]$Diagnosis,
        [Parameter(Mandatory)] [string]$Stage
    )

    if (-not $Diagnosis.available -or $Diagnosis.error) {
        $message = "$Stage could not read the authenticated Service diagnosis"
        if ($Diagnosis.error) {
            $message += ": $($Diagnosis.error)"
        }
        $script:failures.Add($message)
        return
    }
    $killSwitch = $Diagnosis.report.kill_switch
    $dns = $Diagnosis.report.dns
    $protected = $killSwitch.code -eq 0 -and
        $killSwitch.data.wanted -eq $true -and
        $killSwitch.data.live -eq $true -and
        $killSwitch.data.verified -eq $true -and
        [string]$killSwitch.data.mode -eq 'locked' -and
        $killSwitch.data.tunnel_permit_rendered -eq $true -and
        $Diagnosis.report.service.code -eq 0 -and
        $Diagnosis.report.service.data.is_active -eq $true -and
        $null -ne $Diagnosis.report.service.data.core_pid
    if (-not $protected) {
        $script:failures.Add("$Stage did not recover a verified locked WFP policy")
    }
    if ($dns.code -ne 0 -or $dns.data.enabled -ne $true -or $dns.data.snapshot_present -ne $true) {
        $script:failures.Add("$Stage did not recover protected DNS")
    }
}

function Write-DiagnosisCheckpoint {
    param(
        [Parameter(Mandatory)] [string]$Stage,
        [switch]$RequireProtected
    )

    $diagnosis = Get-TonoDiagnosis
    Write-QaEvent -Kind 'diagnosis' -Stage $Stage -Data $diagnosis
    if ($RequireProtected) {
        Test-ProtectedDiagnosis -Diagnosis $diagnosis -Stage $Stage
    }
    $diagnosis
}

function Set-EgressStage {
    param([Parameter(Mandatory)] [string]$Stage)
    Set-Content -LiteralPath $egressStagePath -Value $Stage -Encoding utf8NoBOM
}

function Start-EgressMonitor {
    $monitorScript = Join-Path $PSScriptRoot 'monitor-windows-egress.ps1'
    $maximumDuration = [Math]::Min(3600, $BaselineSeconds + ($Faults.Count * ($RecoverySeconds + 30)) + 120)
    $quote = { param([string]$Value) "'" + $Value.Replace("'", "''") + "'" }
    $command = "& $(& $quote $monitorScript) -MaximumDurationSeconds $maximumDuration " +
        "-OutputPath $(& $quote $egressPath) -StagePath $(& $quote $egressStagePath) " +
        "-StopPath $(& $quote $egressStopPath)"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $script:egressMonitor = Start-Process -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded `
        -PassThru -WindowStyle Hidden
}

function Stop-EgressMonitor {
    if (-not $script:egressMonitor) {
        return
    }
    New-Item -ItemType File -Path $egressStopPath -Force | Out-Null
    if (-not $script:egressMonitor.WaitForExit(10000)) {
        Stop-Process -Id $script:egressMonitor.Id -Force -ErrorAction SilentlyContinue
        $script:warnings.Add('continuous egress monitor did not stop cleanly')
    }
}

function Test-EgressEvidence {
    if (-not (Test-Path -LiteralPath $egressPath -PathType Leaf)) {
        $script:failures.Add('continuous egress evidence is missing')
        return
    }
    $records = @(
        Get-Content -LiteralPath $egressPath -ErrorAction SilentlyContinue |
            Where-Object { $_.Trim() } |
            ForEach-Object { $_ | ConvertFrom-Json }
    )
    foreach ($record in @($records | Where-Object ok)) {
        if ($AllowedProtectedEgressIp -notcontains [string]$record.ip) {
            $script:unexpectedEgress.Add([string]$record.ip)
        }
    }
    foreach ($stage in @('baseline') + @($Faults | ForEach-Object { "$_-recovery" })) {
        $allowed = @($records | Where-Object {
            $_.stage -eq $stage -and $_.ok -and $AllowedProtectedEgressIp -contains [string]$_.ip
        })
        if ($allowed.Count -eq 0) {
            $script:failures.Add("$stage produced no successful allowlisted protected egress observation")
        }
    }
}

function Test-ProtectedDnsProof {
    param([Parameter(Mandatory)] [string]$Stage)

    $probeScript = Join-Path $PSScriptRoot 'probe-windows-protected-dns.ps1'
    & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $probeScript `
        -WaitSeconds 30 -OutputPath $dnsProbePath | Out-Null
    $exitCode = $LASTEXITCODE
    $proof = if (Test-Path -LiteralPath $dnsProbePath) {
        Get-Content -LiteralPath $dnsProbePath -Raw | ConvertFrom-Json
    } else {
        $null
    }
    Write-QaEvent -Kind 'dns-proof' -Stage $Stage -Data $proof
    if ($exitCode -ne 0 -or -not $proof.proof_ok) {
        $script:failures.Add("$Stage failed the protected DNS fake-IP proof")
    }
}

function Watch-QaStage {
    param(
        [Parameter(Mandatory)] [string]$Stage,
        [Parameter(Mandatory)] [int]$DurationSeconds
    )

    $deadline = [DateTimeOffset]::Now.AddSeconds($DurationSeconds)
    while ([DateTimeOffset]::Now -lt $deadline) {
        Write-QaEvent -Kind 'snapshot' -Stage $Stage -Data (Get-QaSnapshot)
        Start-Sleep -Seconds 2
    }
}

function Start-PacketCapture {
    if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
        throw 'pktmon.exe is unavailable; packet evidence is mandatory'
    }
    & pktmon.exe start --capture --pkt-size 0 --file-name $captureEtlPath | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $script:pktmonStarted = $true
        Write-QaEvent -Kind 'capture' -Stage 'preflight' -Data @{ started = $true; path = $captureEtlPath }
    }
    else {
        throw "pktmon start failed with exit code $LASTEXITCODE; stop any existing capture and remove stale filters before retrying"
    }
}

function Stop-PacketCapture {
    if (-not $script:pktmonStarted) {
        return
    }
    & pktmon.exe stop | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $script:failures.Add("pktmon stop failed with exit code $LASTEXITCODE")
    }
    $script:pktmonStarted = $false
    if (-not (Test-Path -LiteralPath $captureEtlPath -PathType Leaf)) {
        $script:failures.Add('pktmon capture stopped but packets.etl is missing')
        return
    }
    & pktmon.exe etl2pcap $captureEtlPath -o $capturePcapPath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $script:failures.Add("pktmon etl2pcap failed with exit code $LASTEXITCODE")
    }
    elseif (-not (Test-Path -LiteralPath $capturePcapPath -PathType Leaf) -or
        (Get-Item -LiteralPath $capturePcapPath).Length -eq 0) {
        $script:failures.Add('pktmon conversion reported success but packets.pcapng is missing or empty')
    }
}

function Invoke-CoreCrash {
    $corePid = [uint32]$script:baselineDiagnosis.report.service.data.core_pid
    $core = Get-Process -Id $corePid -ErrorAction SilentlyContinue
    if (-not $core -or $core.ProcessName -notmatch '(?i)mihomo') {
        throw "the Service-owned Core PID $corePid is not a live Mihomo process"
    }
    Write-QaEvent -Kind 'fault' -Stage 'CoreCrash' -Data @{ process_id = $corePid }
    Stop-Process -Id $corePid -Force
}

function Invoke-ServiceCrash {
    $service = Get-CimInstance Win32_Service -Filter "Name='TonoService'" -ErrorAction Stop
    if (-not $service -or [uint32]$service.ProcessId -eq 0) {
        throw 'TonoService is not running'
    }
    Write-QaEvent -Kind 'fault' -Stage 'ServiceCrash' -Data @{ process_id = [uint32]$service.ProcessId }
    $script:crashedServicePid = [uint32]$service.ProcessId
    Stop-Process -Id ([uint32]$service.ProcessId) -Force
}

function Install-AdapterRecoveryTask {
    $taskName = 'Tono-QA-Recover-' + [Guid]::NewGuid().ToString('N')
    $adapterIndex = [uint32]$script:selectedAdapter.ifIndex
    $recovery = @"
Enable-NetAdapter -InterfaceIndex $adapterIndex -Confirm:`$false -ErrorAction SilentlyContinue
Start-Service TonoService -ErrorAction SilentlyContinue
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($recovery))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    $script:adapterRecoveryTask = $taskName
}

function Restore-TestAdapter {
    if (-not $script:adapterDisabledByHarness) {
        if ($script:adapterRecoveryTask) {
            Unregister-ScheduledTask -TaskName $script:adapterRecoveryTask -Confirm:$false -ErrorAction SilentlyContinue
            $script:adapterRecoveryTask = $null
        }
        return
    }
    Enable-NetAdapter -InterfaceIndex $script:selectedAdapter.ifIndex -Confirm:$false -ErrorAction Continue
    $deadline = (Get-Date).AddSeconds(20)
    do {
        $adapter = Get-NetAdapter -InterfaceIndex $script:selectedAdapter.ifIndex -ErrorAction SilentlyContinue
        if ($adapter -and $adapter.Status -ne 'Disabled') {
            $script:adapterDisabledByHarness = $false
            break
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    if ($script:adapterDisabledByHarness) {
        $script:failures.Add("could not re-enable adapter '$($script:selectedAdapter.Name)'")
        return
    }
    if ($script:adapterRecoveryTask) {
        Unregister-ScheduledTask -TaskName $script:adapterRecoveryTask -Confirm:$false -ErrorAction SilentlyContinue
        $script:adapterRecoveryTask = $null
    }
}

function Invoke-AdapterFlap {
    Write-QaEvent -Kind 'fault' -Stage 'AdapterFlap' -Data @{
        adapter = $script:selectedAdapter.Name
        index = $script:selectedAdapter.ifIndex
    }
    Install-AdapterRecoveryTask
    $script:adapterDisabledByHarness = $true
    Disable-NetAdapter -InterfaceIndex $script:selectedAdapter.ifIndex -Confirm:$false
    Start-Sleep -Seconds 8
    Restore-TestAdapter
    Write-QaEvent -Kind 'recovery' -Stage 'AdapterFlap' -Data @{ adapter_enabled = $true }
}

function Assert-Preconditions {
    if ($Faults.Count -gt 0 -and -not $ConfirmDisruptive) {
        throw 'fault injection can interrupt this machine network; pass -ConfirmDisruptive explicitly'
    }
    if (-not (Get-Service TonoService -ErrorAction SilentlyContinue)) {
        throw 'TonoService is not installed'
    }
    if ($Faults -contains 'AdapterFlap') {
        if ([string]::IsNullOrWhiteSpace($AdapterName)) {
            throw '-AdapterName is required for AdapterFlap'
        }
        $matches = @(Get-NetAdapter -Physical -Name $AdapterName -ErrorAction SilentlyContinue)
        if ($matches.Count -ne 1) {
            throw "AdapterFlap requires exactly one physical adapter named '$AdapterName'"
        }
        if ($matches[0].Status -ne 'Up') {
            throw "AdapterFlap requires an adapter that is Up; '$AdapterName' is $($matches[0].Status)"
        }
        if ($matches[0].InterfaceDescription -match '(?i)wintun|wireguard|tono|mihomo') {
            throw 'refusing to flap a tunnel/virtual adapter; choose the physical uplink'
        }
        $defaultRoute = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object InterfaceIndex -eq $matches[0].ifIndex |
            Select-Object -First 1
        if (-not $defaultRoute) {
            throw "AdapterFlap requires the reviewed IPv4 default-route uplink; '$AdapterName' is not one"
        }
        $script:selectedAdapter = $matches[0]
    }
    if (-not (Get-DriverPath)) {
        $message = 'integration driver is not built; run cargo build --manifest-path apps/windows/service/Cargo.toml --release --features client --bin tono-service-integration-driver'
        throw $message
    }
    if ($AllowedProtectedEgressIp.Count -eq 0) {
        throw 'supply at least one -AllowedProtectedEgressIp; evidence-only runs cannot produce PASS'
    }
    if (-not (Get-Command pktmon.exe -ErrorAction SilentlyContinue)) {
        throw 'pktmon.exe is required; no QA run may claim success without packet evidence'
    }
}

$startedAt = [DateTimeOffset]::Now
$completed = $false
try {
    Assert-Preconditions
    Write-QaEvent -Kind 'start' -Stage 'preflight' -Data @{
        repository_commit = (& git -C $repositoryRoot rev-parse HEAD 2>$null)
        faults = @($Faults)
        allowed_protected_egress_ip = @($AllowedProtectedEgressIp)
        output_directory = $outputRoot
    }
    Set-EgressStage -Stage 'baseline'
    Start-EgressMonitor
    Start-PacketCapture
    $failureCount = $script:failures.Count
    $script:baselineDiagnosis = Write-DiagnosisCheckpoint -Stage 'baseline-start' -RequireProtected
    Test-ProtectedDnsProof -Stage 'baseline-start'
    if ($script:failures.Count -gt $failureCount) {
        throw 'baseline is not a fully verified protected connection; refusing fault injection'
    }
    Watch-QaStage -Stage 'baseline' -DurationSeconds $BaselineSeconds

    foreach ($fault in $Faults) {
        try {
            $failureCount = $script:failures.Count
            $script:baselineDiagnosis = Write-DiagnosisCheckpoint -Stage "${fault}-before" -RequireProtected
            if ($script:failures.Count -gt $failureCount) {
                throw "${fault} precondition is not a verified protected connection"
            }
            Set-EgressStage -Stage "${fault}-fault"
            switch ($fault) {
                'CoreCrash' { Invoke-CoreCrash }
                'ServiceCrash' { Invoke-ServiceCrash }
                'AdapterFlap' { Invoke-AdapterFlap }
            }
            Set-EgressStage -Stage "${fault}-recovery"
            Watch-QaStage -Stage "${fault}-recovery" -DurationSeconds $RecoverySeconds
            Write-DiagnosisCheckpoint -Stage "${fault}-recovered" -RequireProtected
            Test-ProtectedDnsProof -Stage "${fault}-recovered"
            if ($fault -eq 'ServiceCrash') {
                $recoveredService = Get-ServiceSnapshot
                if (-not $recoveredService -or $recoveredService.state -ne 'Running' -or
                    $recoveredService.process_id -eq $script:crashedServicePid) {
                    $script:failures.Add('ServiceCrash did not produce an SCM-recovered Service with a new PID')
                }
            }
        }
        catch {
            $message = "${fault}: $($_.Exception.GetBaseException().Message)"
            $script:failures.Add($message)
            Write-QaEvent -Kind 'error' -Stage $fault -Data @{ message = $message }
        }
        finally {
            if ($fault -eq 'AdapterFlap' -and $script:selectedAdapter) {
                Restore-TestAdapter
            }
        }
    }
    $completed = $true
}
catch {
    $script:failures.Add($_.Exception.GetBaseException().Message)
    Write-QaEvent -Kind 'error' -Stage 'harness' -Data @{ message = $_.Exception.GetBaseException().Message }
}
finally {
    Restore-TestAdapter
    Stop-EgressMonitor
    Stop-PacketCapture
    if ($AllowedProtectedEgressIp.Count -gt 0) {
        Test-EgressEvidence
    }

    $verdict = if ($script:unexpectedEgress.Count -gt 0 -or $script:failures.Count -gt 0) {
        'FAIL'
    }
    else {
        'PENDING_CAPTURE_REVIEW'
    }
    [ordered]@{
        started_at = $startedAt.ToString('o')
        finished_at = [DateTimeOffset]::Now.ToString('o')
        completed = $completed
        verdict = $verdict
        failures = @($script:failures)
        warnings = @($script:warnings)
        unexpected_egress_ip = @($script:unexpectedEgress | Sort-Object -Unique)
        events = $eventsPath
        egress_evidence = if (Test-Path -LiteralPath $egressPath) { $egressPath } else { $null }
        packet_capture = if (Test-Path -LiteralPath $capturePcapPath) { $capturePcapPath } else { $null }
    } | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $summaryPath -Encoding utf8NoBOM
    # Cleanup occurs only after observers stopped and the verdict was frozen, so ServiceCrash
    # measures SCM recovery rather than a harness-assisted restart.
    Start-Service TonoService -ErrorAction SilentlyContinue
}

Write-Output $summaryPath
if ($verdict -ne 'PENDING_CAPTURE_REVIEW') {
    exit 1
}
