<#
.SYNOPSIS
Run one original, bounded phase of the offline development ISO refresh workflow.
.PARAMETER Plan
Absolute durable plan.json outside the task worktree beneath the configured root.
.PARAMETER Phase
Initialize once, inspect Status, or execute one never-replayed workflow phase.
.PARAMETER PythonPath
Existing Python 3.14 interpreter with the locked build and inspection dependencies.
.PARAMETER OldRpm
Exact old public RPM selected only for the optional review comparison phase.
.PARAMETER NewRpm
Exact new public RPM selected only for the optional review comparison phase.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][ValidateSet('Initialize', 'Status', 'drift', 'compare', 'capture', 'admit', 'build', 'readback', 'install', 'verify', 'cleanup', 'protected')][string]$Phase,
    [string]$PythonPath = 'python',
    [string]$OldRpm = '',
    [string]$NewRpm = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Source inspection must not follow inherited repository, index or config overrides.
Get-ChildItem Env:GIT_* | Where-Object Name -NE 'GIT_ASKPASS' | Remove-Item
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.LifecycleOwnership.ps1')

<#
.SYNOPSIS
Durably publish one bounded original record without replacing evidence.
.PARAMETER Directory
Pinned external evidence directory.
.PARAMETER Name
Fixed workflow evidence filename.
.PARAMETER Record
Non-secret bounded task and phase record.
#>
function Write-InstallationRefreshEvidence {
    param([string]$Directory, [string]$Name, [System.Collections.IDictionary]$Record)
    if ($Name -cnotmatch '^[a-z][a-z0-9-]*\.json$') { throw 'Invalid workflow evidence name.' }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 12 -Compress) + "`n")
    if ($bytes.Length -gt 65536) { throw 'Workflow record exceeds its bounded size.' }
    $stage = Join-Path $Directory ('.refresh-' + [guid]::NewGuid().ToString('N') + '.pending')
    $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stage)
    try {
        $writer.Write($bytes, 0, $bytes.Length)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, (Join-Path $Directory $Name), $false)
    }
    finally { $writer.Dispose() }
}

<#
.SYNOPSIS
Read one bounded single-link JSON record while denying writers and replacement.
.PARAMETER Path
Exact durable workflow evidence path.
.PARAMETER MaximumBytes
Fixed evidence-kind bound; phase reports may contain the complete bounded package inventory.
#>
function Read-InstallationRefreshEvidence {
    param([string]$Path, [ValidateRange(1, 16777216)][int]$MaximumBytes = 65536)
    $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true)
    try {
        if ((Get-Item -LiteralPath $Path).Length -gt $MaximumBytes) { throw 'Workflow record exceeds its bound.' }
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    }
    finally { $pin.Dispose() }
}

<#
.SYNOPSIS
Require every original previous child absent and its recorded Windows job quiescent.
.PARAMETER Directory
Pinned durable workflow state directory.
.PARAMETER PlanSha256
Exact immutable plan binding of every consumer.
#>
function Assert-InstallationRefreshConsumersQuiescent {
    param([string]$Directory, [string]$PlanSha256)
    foreach ($item in @(Get-ChildItem -LiteralPath $Directory -Filter '*-child.json' -File)) {
        $original = Read-InstallationRefreshEvidence -Path $item.FullName
        if ($original.plan_sha256 -cne $PlanSha256 -or $original.phase -cnotmatch '^[a-z]+$') {
            throw 'Original workflow consumer binding differs; preserve it.'
        }
        $result = Read-InstallationRefreshEvidence -Path (Join-Path $Directory ($original.phase + '-result.json'))
        if ($result.whole_job_quiescent -ne $true -or $result.plan_sha256 -cne $PlanSha256) {
            throw 'Previous workflow job has no proven terminal result.'
        }
        $state = Get-AtlasoRecordedProcessIdentityState -ProcessId ([int]$original.pid) -StartFileTimeUtc ([long]$original.start_filetime_utc)
        if ($state -notin @('absent', 'reused')) { throw 'An original workflow consumer is still active.' }
        # A surviving named job must independently prove zero descendants. This
        # operation never resumes, restarts or terminates a previous consumer.
        $job = Open-AtlasoBoundedProcessJob -ProcessJobName ([string]$original.job_name)
        if ($job) {
            try {
                if (@($job.GetActiveProcessIds()).Count -ne 0) { throw 'An original refresh job still has live descendants; preserve and reconcile it.' }
            }
            finally { $job.Dispose() }
        }
    }
}

<#
.SYNOPSIS
Require original matching Linux completion proof for every native tool invocation.
.PARAMETER Directory
Exact phase-owned native protocol directory, when the phase uses WSL tools.
#>
function Test-InstallationRefreshNativeQuiescent {
    param([string]$Directory)
    if (-not (Test-Path -LiteralPath $Directory)) { return $true }
    $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($Directory, $true)
    try {
        $intents = @(Get-ChildItem -LiteralPath $Directory -Filter '*-intent.json' -File)
        if ($intents.Count -gt 20000) { throw 'Native tool inventory exceeds its bound.' }
        foreach ($intentFile in $intents) {
            $prefix = $intentFile.Name.Substring(0, $intentFile.Name.Length - '-intent.json'.Length)
            $originalPath = Join-Path $Directory ($prefix + '-original.json')
            $resultPath = Join-Path $Directory ($prefix + '-result.json')
            if (-not (Test-Path -LiteralPath $originalPath) -or -not (Test-Path -LiteralPath $resultPath)) { return $false }
            $intent = Read-InstallationRefreshEvidence -Path $intentFile.FullName
            $original = Read-InstallationRefreshEvidence -Path $originalPath
            $result = Read-InstallationRefreshEvidence -Path $resultPath
            if ($result.whole_group_quiescent -isnot [bool] -or -not $result.whole_group_quiescent -or
                $intent.request_id -cne $original.request_id -or $result.request_id -cne $original.request_id -or
                $result.pid -ne $original.pid -or $result.start_ticks -cne $original.start_ticks) { return $false }
        }
        return $true
    }
    finally { $pin.Dispose() }
}

$worktree = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..')).TrimEnd('\', '/')
$configuredRoot = Get-AtlasoLifecycleDurableRoot
$taskId = [string]$env:CODEX_THREAD_ID
if ($taskId -cnotmatch '^[0-9a-f-]{36}$') { throw 'An actual current Codex task is required; never substitute another identity.' }
if (-not [IO.Path]::IsPathFullyQualified($Plan)) { throw 'Plan must be an absolute durable plan.json path.' }
$planPath = [IO.Path]::GetFullPath($Plan)
if ([IO.Path]::GetFileName($planPath) -cne 'plan.json') { throw 'Use the fixed plan.json filename.' }
$stateDirectory = [IO.Path]::GetDirectoryName($planPath)
$python = (Get-Command $PythonPath -CommandType Application -ErrorAction Stop).Source
$protocol = Join-Path $worktree 'scripts/refresh_installation_iso.py'
$common = @('--plan', $planPath, '--configured-root', $configuredRoot)
$mutex = [Threading.Mutex]::new($false, ('Local\Atlaso-InstallationRefresh-' + $taskId))
$mutexHeld = $false
$statePin = $null
$planPin = $null
$sourceContext = $null
$creationPins = $null
$outputPin = $null
try {
    $mutexHeld = $mutex.WaitOne(0)
    if (-not $mutexHeld) { throw 'Another refresh controller owns this task; no consumer was started.' }
    $statePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($stateDirectory, $true)
    $planPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($planPath, $true)
    $descriptionJson = Invoke-AtlasoBoundedProcess -FilePath $python -ArgumentList (@('-I', '-B', $protocol, 'describe') + $common) `
        -TimeoutSeconds 90 -Action 'Validate immutable ISO refresh plan'
    $description = ($descriptionJson -join "`n") | ConvertFrom-Json -AsHashtable
    $planValue = $description.plan
    $planHash = [string]$description.plan_sha256
    if ($planValue.task_id -cne $taskId) { throw 'Plan belongs to a different actual task.' }
    Assert-InstallationRefreshConsumersQuiescent -Directory $stateDirectory -PlanSha256 $planHash
    if ($Phase -eq 'Status') {
        Invoke-AtlasoBoundedProcess -FilePath $python -ArgumentList (@('-I', '-B', $protocol, 'status') + $common) `
            -TimeoutSeconds 90 -Action 'Read ISO refresh phase history'
        return
    }
    $branch = ([string](& git -C $worktree branch --show-current)).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $branch -or $branch -ceq 'main') { throw 'A dedicated task branch is required.' }
    $sourceContext = [pscustomobject]@{
        Enabled = $true; Worktree = $worktree; WorktreeDirectoryId = [Atlaso.WorkstationFileIdentity]::Get($worktree)
        SourceCommit = [string]$planValue.installer_commit; Branch = $branch
    }
    Assert-AtlasoTestVmCheckoutSource -Context $sourceContext
    if ($Phase -eq 'Initialize') {
        $output = [string]$planValue.output_root
        & git -C $worktree check-ignore --quiet -- $output
        if ($LASTEXITCODE -ne 0) { throw 'Refresh output must be a Git-ignored task subtree.' }
        if (Test-Path -LiteralPath $output) { throw 'Initialization requires an absent original output root.' }
        $callback = {
            param($CreatedPath, $OriginalIdentity)
            Write-InstallationRefreshEvidence -Directory $stateDirectory -Name 'output-native-original.json' -Record ([ordered]@{
                schema = 1; task_id = $taskId; source_commit = $planValue.installer_commit; repository = 'mdaneri/Atlaso'
                plan_sha256 = $planHash; path = $CreatedPath; native_identity = $OriginalIdentity
                created_utc = [DateTimeOffset]::UtcNow.ToString('o'); cleanup_tool = 'scripts/cleanup-completed-task.ps1'
            })
        }.GetNewClosure()
        # Require the parent already exists so the only newly owned removal scope
        # is the exact output root, with its receipt published before first use.
        $parent = [IO.Path]::GetDirectoryName($output)
        $parentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($parent, $true)
        try { $creationPins = [Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath($output, $callback) }
        finally { $parentPin.Dispose() }
        $creationPins.Dispose()
        $creationPins = $null
        $outputPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($output, $true)
        $originalRoot = Read-InstallationRefreshEvidence -Path (Join-Path $stateDirectory 'output-native-original.json')
        if ([Atlaso.WorkstationFileIdentity]::Get($output) -cne $originalRoot.native_identity) { throw 'New output identity changed before first use.' }
        Invoke-AtlasoBoundedProcess -FilePath $python -ArgumentList (@('-I', '-B', $protocol, 'initialize') + $common) `
            -TimeoutSeconds 90 -Action 'Record original empty ISO refresh output'
        return
    }
    $Phase = $Phase.ToLowerInvariant()
    $outputPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([string]$planValue.output_root, $true)
    $preflightArguments = @('-I', '-B', $protocol, 'preflight') + $common + @('--phase', $Phase)
    if ($Phase -eq 'compare') { $preflightArguments += @('--old-rpm', $OldRpm, '--new-rpm', $NewRpm) }
    elseif ($OldRpm -or $NewRpm) { throw 'RPM review selectors require the compare phase.' }
    $intentJson = Invoke-AtlasoBoundedProcess -FilePath $python -ArgumentList $preflightArguments `
        -TimeoutSeconds 90 -Action 'Admit one original ISO refresh phase'
    $intent = ($intentJson -join "`n") | ConvertFrom-Json -AsHashtable
    $jobName = 'Local\Atlaso-ISORefresh-' + $intent.intent_id
    $childPath = Join-Path $stateDirectory ($Phase + '-child.json')
    $publisher = {
        param($ProcessJob)
        Write-InstallationRefreshEvidence -Directory $stateDirectory -Name ($Phase + '-child.json') -Record ([ordered]@{
            schema = 1; phase = $Phase; task_id = $taskId; plan_sha256 = $planHash; intent_id = $intent.intent_id
            pid = [int]$ProcessJob.RootProcess.Id; start_filetime_utc = $ProcessJob.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
            job_name = $jobName; boot_identity = Get-AtlasoWindowsBootIdentity; deadline_utc = $intent.deadline_utc
        })
    }.GetNewClosure()
    $remaining = [Math]::Floor(([DateTimeOffset]::Parse($intent.deadline_utc) - [DateTimeOffset]::UtcNow).TotalSeconds)
    if ($remaining -lt 1) { throw 'Original phase deadline expired before child creation; never restart it.' }
    $failure = $null
    $quiescent = $false
    try {
        Invoke-AtlasoBoundedStreamingProcess -FilePath $python `
            -ArgumentList (@('-I', '-B', $protocol, 'run') + $common + @('--phase', $Phase, '--child-receipt', $childPath)) `
            -TimeoutSeconds ([int]$remaining) -Action ('ISO refresh ' + $Phase) `
            -ProcessJobName $jobName -ProcessOwnershipPublisher $publisher -DeadlineUtc ([DateTimeOffset]::Parse($intent.deadline_utc))
        $quiescent = $true
    }
    catch {
        $failure = $_.Exception
        $quiescent = $failure.Data['AtlasoProcessTreeTerminationProven'] -eq $true
    }
    $nativeDirectory = Join-Path ([string]$planValue.output_root) ($Phase + '-temporary/native-tools')
    if (-not (Test-InstallationRefreshNativeQuiescent -Directory $nativeDirectory)) {
        $quiescent = $false
        if (-not $failure) { $failure = [InvalidOperationException]::new('Linux native tool quiescence is unproven; preserve original receipts.') }
    }
    $reportPath = Join-Path $stateDirectory ($Phase + '-report.json')
    $result = [ordered]@{
        schema = 1; phase = $Phase; operation_id = $planValue.operation_id; task_id = $taskId
        installer_commit = $planValue.installer_commit; plan_sha256 = $planHash; start_intent_id = $intent.intent_id
        status = $(if ($failure) { 'failed' } else { 'succeeded' }); whole_job_quiescent = $quiescent
        finished_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    if (-not $failure) {
        if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw 'Successful child has no durable phase report; preserve original evidence.' }
        $result.report_sha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($Phase -eq 'drift') { $result.disposition = (Read-InstallationRefreshEvidence -Path $reportPath -MaximumBytes 16777216).disposition }
    }
    Write-InstallationRefreshEvidence -Directory $stateDirectory -Name ($Phase + '-result.json') -Record $result
    if ($failure) { throw 'ISO refresh phase failed; original receipts and failure resources retained.' }
    $result | ConvertTo-Json -Compress
}
finally {
    if ($creationPins) { $creationPins.Dispose() }
    if ($outputPin) { $outputPin.Dispose() }
    if ($sourceContext -and $sourceContext.PSObject.Properties['CheckoutSourcePin']) { $sourceContext.CheckoutSourcePin.Dispose() }
    if ($planPin) { $planPin.Dispose() }
    if ($statePin) { $statePin.Dispose() }
    if ($mutexHeld) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
