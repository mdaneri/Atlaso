<#
.SYNOPSIS
Exercise supported retained 1Password credential-bridge inspection and reset.

.DESCRIPTION
Creates only synthetic non-secret markers and Windows processes beneath the
configured test TEMP root. Covers fail-closed identity states, explicit job
termination, terminal-phase resumption, WhatIf, and idempotency.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    '',
    Justification = 'Focused test constructs fixed synthetic values and never handles real credentials.'
)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$markerPath = Join-Path $repositoryRoot '.atlaso-local\onepassword-credential-cleanup.json'
$runnerPath = Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1'
$modulePath = Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.OnePasswordCredentials.psm1'
$cleanupModulePath = Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationCleanup.psm1'
. $runnerPath
Import-Module $modulePath -Force
Import-Module $cleanupModulePath -Force
$credentialModule = @(Get-Module -Name 'Atlaso.OnePasswordCredentials' -All |
    Where-Object { $_.Path -eq $modulePath })[-1]
$cleanupModule = @(Get-Module -Name 'Atlaso.WorkstationCleanup' -All |
    Where-Object { $_.Path -eq $cleanupModulePath })[-1]

<#
.SYNOPSIS
Create one exact synthetic credential bridge root under the test TEMP root.
#>
function New-TestCredentialBridgeRoot {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) (
        'atlaso-onepassword-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($root)
    return $root
}

<#
.SYNOPSIS
Create a valid schema-2 marker payload for a synthetic recovery case.

.PARAMETER RootPath
Exact synthetic bridge root.

.PARAMETER Phase
Durable cleanup phase.

.PARAMETER BootIdentity
Windows boot identity stored in the marker.

.PARAMETER OwnerProcessId
Recorded controller process identifier.

.PARAMETER OwnerProcessStartFileTimeUtc
Recorded controller process start identity.

.PARAMETER ProcessJobName
Exact named Windows job identity.

.PARAMETER ChildProcessId
Recorded root-child process identifier.

.PARAMETER ChildProcessStartFileTimeUtc
Recorded root-child process start identity.

.PARAMETER ProcessOwnershipPhase
Whether child ownership was durably prepared or assigned.
#>
function New-TestCredentialMarker {
    param(
        [Parameter(Mandatory = $true)][string]$RootPath,
        [ValidateSet('active', 'root-absent', 'retired')][string]$Phase = 'active',
        [string]$BootIdentity = (Get-AtlasoWindowsBootIdentity),
        [int]$OwnerProcessId = [int]::MaxValue,
        [long]$OwnerProcessStartFileTimeUtc = 1,
        [string]$ProcessJobName = ('Local\Atlaso-OnePassword-' + [guid]::NewGuid().ToString('N')),
        [int]$ChildProcessId = 0,
        [long]$ChildProcessStartFileTimeUtc = 0,
        [ValidateSet('prepared', 'assigned')][string]$ProcessOwnershipPhase = 'prepared'
    )

    $rootIdentity = & $credentialModule {
        param([string]$Path)
        Get-AtlasoPathIdentity -Path $Path -Description 'Synthetic credential bridge root'
    } $RootPath
    return [ordered]@{
        Schema                       = 2
        RootPath                     = [System.IO.Path]::GetFullPath($RootPath)
        RootIdentity                 = $rootIdentity
        BootIdentity                 = $BootIdentity
        Phase                        = $Phase
        OwnerProcessId               = $OwnerProcessId
        OwnerProcessStartFileTimeUtc = $OwnerProcessStartFileTimeUtc
        ProcessJobName               = $ProcessJobName
        ChildProcessId               = $ChildProcessId
        ChildProcessStartFileTimeUtc = $ChildProcessStartFileTimeUtc
        ProcessOwnershipPhase        = $ProcessOwnershipPhase
    }
}

<#
.SYNOPSIS
Durably publish one synthetic recovery marker.

.PARAMETER Marker
Marker payload to publish at the fixed checkout-local path.
#>
function Write-TestCredentialMarker {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Marker)

    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $markerPath))
    Write-AtlasoDurableJsonFile -Path $markerPath -Payload $Marker -Replace
}

<#
.SYNOPSIS
Require a recovery call to fail with one exact sanitized blocker code.

.PARAMETER Code
Expected recovery blocker code.

.PARAMETER Action
Recovery action expected to throw.
#>
function Assert-TestRecoveryBlocked {
    param(
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $failure = $null
    try {
        & $Action
    }
    catch {
        $failure = $_
    }
    if ($null -eq $failure -or
        -not $failure.Exception.Data['AtlasoOnePasswordRecoverySafe'] -or
        $failure.Exception.Data['AtlasoOnePasswordRecoveryCode'] -cne $Code -or
        $failure.Exception.Message -match [regex]::Escape($repositoryRoot)) {
        throw "Expected sanitized credential-recovery blocker '$Code'."
    }
}

<#
.SYNOPSIS
Remove one exact synthetic marker and bridge root during test teardown.

.PARAMETER RootPath
Optional exact bridge root created by the current test case.
#>
function Remove-TestCredentialState {
    param([string]$RootPath = '')

    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        Remove-Item -LiteralPath $markerPath -Force
    }
    if (-not [string]::IsNullOrWhiteSpace($RootPath) -and
        (Test-Path -LiteralPath $RootPath -PathType Container)) {
        [System.IO.Directory]::Delete($RootPath, $true)
    }
}

if (Test-Path -LiteralPath $markerPath) {
    throw 'The reset test cannot start with a retained checkout marker.'
}

$ancestryFailure = $null
try {
    & $cleanupModule {
        Assert-AtlasoPathHasNoReparsePoint `
            -Path ([System.IO.Path]::GetTempPath()) `
            -ItemReader {
                param([string]$ItemPath)
                throw [System.UnauthorizedAccessException]::new('Synthetic inaccessible ancestry')
            }
    }
}
catch {
    $ancestryFailure = $_
}
if ($null -eq $ancestryFailure -or
    $ancestryFailure.Exception.Message -notmatch 'cannot be inspected safely') {
    throw 'An inaccessible path-ancestry entry did not fail closed.'
}

$standaloneScript = Join-Path $repositoryRoot `
    'scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1'
$standaloneOutput = & (Get-Process -Id $PID).Path `
    -NoLogo -NoProfile -NonInteractive -File $standaloneScript -Inspect 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or
    $standaloneOutput -notmatch 'MarkerState\s*:\s*absent' -or
    $standaloneOutput -match [regex]::Escape($repositoryRoot)) {
    throw 'The standalone inspection command did not return sanitized missing-marker state.'
}

$missingInspection = Invoke-AtlasoOnePasswordCredentialBridgeReset `
    -RepositoryRoot $repositoryRoot `
    -Inspect
if ($missingInspection.MarkerState -cne 'absent' -or
    $missingInspection.Action -cne 'already-reset') {
    throw 'Missing-marker inspection was not an idempotent no-op.'
}
$missingReset = Invoke-AtlasoOnePasswordCredentialBridgeReset `
    -RepositoryRoot $repositoryRoot `
    -Confirm:$false
if ($missingReset.Result -cne 'already-reset') {
    throw 'Repeated missing-marker reset was not idempotent.'
}

$inactiveRoot = New-TestCredentialBridgeRoot
try {
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $inactiveRoot `
            -ChildProcessId ([int]::MaxValue - 1) `
            -ChildProcessStartFileTimeUtc 1 `
            -ProcessOwnershipPhase assigned)
    $inactiveOutput = & (Get-Process -Id $PID).Path `
        -NoLogo -NoProfile -NonInteractive -File $standaloneScript 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $inactiveOutput -notmatch 'Result\s*:\s*reset' -or
        $inactiveOutput -match [regex]::Escape($repositoryRoot) -or
        (Test-Path -LiteralPath $markerPath) -or
        (Test-Path -LiteralPath $inactiveRoot)) {
        throw 'The standalone current-boot inactive reset did not complete safely.'
    }
}
finally {
    Remove-TestCredentialState -RootPath $inactiveRoot
}

$previousBootRoot = New-TestCredentialBridgeRoot
try {
    $previousBoot = ([long](Get-AtlasoWindowsBootIdentity) - 1).ToString(
        [System.Globalization.CultureInfo]::InvariantCulture
    )
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $previousBootRoot `
            -BootIdentity $previousBoot)
    $previousResult = Invoke-AtlasoOnePasswordCredentialBridgeReset `
        -RepositoryRoot $repositoryRoot `
        -Confirm:$false
    if ($previousResult.Result -cne 'reset' -or
        (Test-Path -LiteralPath $markerPath) -or
        (Test-Path -LiteralPath $previousBootRoot)) {
        throw 'Previous-boot schema-2 recovery did not complete.'
    }
}
finally {
    Remove-TestCredentialState -RootPath $previousBootRoot
}

foreach ($terminalPhase in @('root-absent', 'retired')) {
    $terminalRoot = New-TestCredentialBridgeRoot
    try {
        $terminalMarker = New-TestCredentialMarker -RootPath $terminalRoot -Phase $terminalPhase
        [System.IO.Directory]::Delete($terminalRoot, $true)
        Write-TestCredentialMarker -Marker $terminalMarker
        $terminalResult = Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -Confirm:$false
        if ($terminalResult.Result -cne 'reset' -or (Test-Path -LiteralPath $markerPath)) {
            throw "Terminal marker phase '$terminalPhase' did not finish retirement."
        }
        $repeatResult = Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -Confirm:$false
        if ($repeatResult.Result -cne 'already-reset') {
            throw "Terminal marker phase '$terminalPhase' was not idempotent."
        }
    }
    finally {
        Remove-TestCredentialState -RootPath $terminalRoot
    }
}

$interruptedRoot = New-TestCredentialBridgeRoot
try {
    $interruptedMarker = New-TestCredentialMarker -RootPath $interruptedRoot
    [System.IO.Directory]::Delete($interruptedRoot, $true)
    Write-TestCredentialMarker -Marker $interruptedMarker
    $interruptedResult = Invoke-AtlasoOnePasswordCredentialBridgeReset `
        -RepositoryRoot $repositoryRoot `
        -Confirm:$false
    if ($interruptedResult.Result -cne 'reset' -or (Test-Path -LiteralPath $markerPath)) {
        throw 'An active marker interrupted after root deletion did not finish retirement.'
    }
}
finally {
    Remove-TestCredentialState -RootPath $interruptedRoot
}

$contradictoryTerminalRoot = New-TestCredentialBridgeRoot
try {
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $contradictoryTerminalRoot `
            -Phase root-absent)
    Assert-TestRecoveryBlocked -Code 'terminal-root-present' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -Confirm:$false | Out-Null
    }
}
finally {
    Remove-TestCredentialState -RootPath $contradictoryTerminalRoot
}

$unreadableRoot = New-TestCredentialBridgeRoot
try {
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker -RootPath $unreadableRoot)
    Assert-TestRecoveryBlocked -Code 'root-state-unavailable' -Action {
        & $credentialModule {
            param([string]$RepositoryRoot)
            Get-AtlasoOnePasswordCredentialRecoveryContext `
                -RepositoryRoot $RepositoryRoot `
                -RootItemReader {
                    param([string]$ItemPath)
                    throw [System.UnauthorizedAccessException]::new('Synthetic inaccessible root')
                } | Out-Null
        } $repositoryRoot
    }
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $unreadableRoot -PathType Container)) {
        throw 'A failed recorded-root inspection changed retained state.'
    }
}
finally {
    Remove-TestCredentialState -RootPath $unreadableRoot
}

$activeOwnerRoot = New-TestCredentialBridgeRoot
try {
    $currentProcess = Get-Process -Id $PID -ErrorAction Stop
    try {
        Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
                -RootPath $activeOwnerRoot `
                -OwnerProcessId $PID `
                -OwnerProcessStartFileTimeUtc $currentProcess.StartTime.ToUniversalTime().ToFileTimeUtc())
    }
    finally {
        $currentProcess.Dispose()
    }
    Assert-TestRecoveryBlocked -Code 'owner-active' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -TerminateOwnedProcess `
            -Confirm:$false | Out-Null
    }
    if (-not (Test-Path -LiteralPath $markerPath) -or
        -not (Test-Path -LiteralPath $activeOwnerRoot)) {
        throw 'Active-controller recovery changed retained state.'
    }
}
finally {
    Remove-TestCredentialState -RootPath $activeOwnerRoot
}

$reusedOwnerRoot = New-TestCredentialBridgeRoot
try {
    $currentProcess = Get-Process -Id $PID -ErrorAction Stop
    try {
        $reusedStart = $currentProcess.StartTime.ToUniversalTime().ToFileTimeUtc() - 1
    }
    finally {
        $currentProcess.Dispose()
    }
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $reusedOwnerRoot `
            -OwnerProcessId $PID `
            -OwnerProcessStartFileTimeUtc $reusedStart)
    Assert-TestRecoveryBlocked -Code 'owner-pid-reused' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -Confirm:$false | Out-Null
    }
}
finally {
    Remove-TestCredentialState -RootPath $reusedOwnerRoot
}

$reusedChildRoot = New-TestCredentialBridgeRoot
try {
    $currentProcess = Get-Process -Id $PID -ErrorAction Stop
    try {
        $reusedChildStart = $currentProcess.StartTime.ToUniversalTime().ToFileTimeUtc() - 1
    }
    finally {
        $currentProcess.Dispose()
    }
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $reusedChildRoot `
            -ChildProcessId $PID `
            -ChildProcessStartFileTimeUtc $reusedChildStart `
            -ProcessOwnershipPhase assigned)
    Assert-TestRecoveryBlocked -Code 'child-pid-reused' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -TerminateOwnedProcess `
            -Confirm:$false | Out-Null
    }
}
finally {
    Remove-TestCredentialState -RootPath $reusedChildRoot
}

$missingJobRoot = New-TestCredentialBridgeRoot
$missingJobChild = Start-Process `
    -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60') `
    -PassThru
try {
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $missingJobRoot `
            -ChildProcessId $missingJobChild.Id `
            -ChildProcessStartFileTimeUtc $missingJobChild.StartTime.ToUniversalTime().ToFileTimeUtc() `
            -ProcessOwnershipPhase assigned)
    Assert-TestRecoveryBlocked -Code 'active-child-missing-job' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -TerminateOwnedProcess `
            -Confirm:$false | Out-Null
    }
    if ($missingJobChild.HasExited) {
        throw 'A child without its exact job was terminated.'
    }
}
finally {
    if (-not $missingJobChild.HasExited) {
        $missingJobChild.Kill($true)
        [void]$missingJobChild.WaitForExit(10000)
    }
    $missingJobChild.Dispose()
    Remove-TestCredentialState -RootPath $missingJobRoot
}

$unrecordedRoot = New-TestCredentialBridgeRoot
$unrecordedJobName = 'Local\Atlaso-OnePassword-' + [guid]::NewGuid().ToString('N')
$unrecordedJob = New-AtlasoBoundedProcessJob `
    -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 60') `
    -ProcessJobName $unrecordedJobName `
    -DeferResume
try {
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $unrecordedRoot `
            -ProcessJobName $unrecordedJobName)
    $unrecordedJob.Resume()
    Assert-TestRecoveryBlocked -Code 'unrecorded-job-descendants' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -TerminateOwnedProcess `
            -Confirm:$false | Out-Null
    }
    if ($unrecordedJob.RootProcess.HasExited) {
        throw 'An unrecorded job descendant was terminated.'
    }
}
finally {
    if (-not $unrecordedJob.RootProcess.HasExited) {
        $unrecordedJob.TerminateAndWait(10000)
        [void]$unrecordedJob.RootProcess.WaitForExit(10000)
    }
    $unrecordedJob.Dispose()
    Remove-TestCredentialState -RootPath $unrecordedRoot
}

$ownedJobRoot = New-TestCredentialBridgeRoot
$ownedReadyPath = Join-Path $ownedJobRoot 'ready.txt'
$ownedToken = 'atlaso-reset-descendant-' + [guid]::NewGuid().ToString('N')
$ownedSource = @'
$null = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    'Start-Sleep -Seconds 60', '__ATLASO_TOKEN__'
)
[System.IO.File]::WriteAllText('__ATLASO_READY__', 'ready')
Start-Sleep -Seconds 60
'@.Replace('__ATLASO_TOKEN__', $ownedToken).
    Replace('__ATLASO_READY__', $ownedReadyPath.Replace("'", "''"))
$ownedEncodedSource = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ownedSource))
$ownedJobName = 'Local\Atlaso-OnePassword-' + [guid]::NewGuid().ToString('N')
$ownedJob = New-AtlasoBoundedProcessJob `
    -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $ownedEncodedSource) `
    -ProcessJobName $ownedJobName `
    -DeferResume
$ownedRootProcess = $ownedJob.RootProcess
try {
    Write-TestCredentialMarker -Marker (New-TestCredentialMarker `
            -RootPath $ownedJobRoot `
            -ProcessJobName $ownedJobName `
            -ChildProcessId $ownedJob.RootProcess.Id `
            -ChildProcessStartFileTimeUtc $ownedJob.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc() `
            -ProcessOwnershipPhase assigned)
    $ownedJob.Resume()
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $ownedReadyPath) -and [DateTime]::UtcNow -lt $readyDeadline) {
        Start-Sleep -Milliseconds 50
    }
    if (-not (Test-Path -LiteralPath $ownedReadyPath)) {
        throw 'The exact-owned-job fixture did not start its descendant.'
    }
    $inspection = Invoke-AtlasoOnePasswordCredentialBridgeReset `
        -RepositoryRoot $repositoryRoot `
        -Inspect
    if ($inspection.JobState -cne 'active-owned' -or
        $inspection.Action -cne 'rerun-with-terminate-owned-process') {
        throw "Inspection did not report the exact active owned job ($($inspection.JobState)/$($inspection.Action)/$($inspection.Blocker))."
    }
    Assert-TestRecoveryBlocked -Code 'termination-switch-required' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -Confirm:$false | Out-Null
    }
    $whatIf = Invoke-AtlasoOnePasswordCredentialBridgeReset `
        -RepositoryRoot $repositoryRoot `
        -TerminateOwnedProcess `
        -WhatIf `
        -Confirm:$false
    if ($whatIf.Result -cne 'what-if' -or
        -not (Test-Path -LiteralPath $markerPath) -or
        $ownedRootProcess.HasExited) {
        throw 'WhatIf changed the exact owned process or retained state.'
    }
    $ownedResetOutput = & (Get-Process -Id $PID).Path `
        -NoLogo -NoProfile -NonInteractive -File $standaloneScript `
        -TerminateOwnedProcess 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or
        $ownedResetOutput -notmatch 'Result\s*:\s*reset' -or
        $ownedResetOutput -match [regex]::Escape($repositoryRoot) -or
        (Test-Path -LiteralPath $markerPath) -or
        (Test-Path -LiteralPath $ownedJobRoot) -or
        -not $ownedRootProcess.HasExited) {
        throw 'The standalone exact-owned-job reset did not terminate and retire its state.'
    }
    if (@($ownedJob.GetActiveProcessIds()).Count -ne 0) {
        throw 'The exact credential-bridge job remained active after supported recovery.'
    }
    $ownedJob.Dispose()
    $ownedJob = $null
    $remainingJob = Open-AtlasoBoundedProcessJob -ProcessJobName $ownedJobName
    try {
        if ($null -ne $remainingJob) {
            throw 'The recorded credential-bridge job remained after supported recovery.'
        }
    }
    finally {
        if ($null -ne $remainingJob) {
            $remainingJob.Dispose()
        }
    }
    $descendants = @(Get-CimInstance -ClassName Win32_Process |
        Where-Object { $_.CommandLine -like "*$ownedToken*" })
    if ($descendants.Count -ne 0) {
        throw 'An exact-job descendant survived supported credential recovery.'
    }
}
finally {
    if ($null -ne $ownedJob) {
        if (-not $ownedJob.RootProcess.HasExited) {
            $ownedJob.TerminateAndWait(10000)
            [void]$ownedJob.RootProcess.WaitForExit(10000)
        }
        $ownedJob.Dispose()
    }
    elseif (-not $ownedRootProcess.HasExited) {
        $retainedJob = Open-AtlasoBoundedProcessJob -ProcessJobName $ownedJobName
        try {
            if ($null -ne $retainedJob) {
                $retainedJob.TerminateAndWait(10000)
                [void]$ownedRootProcess.WaitForExit(10000)
            }
        }
        finally {
            if ($null -ne $retainedJob) {
                $retainedJob.Dispose()
            }
        }
    }
    $ownedRootProcess.Dispose()
    Remove-TestCredentialState -RootPath $ownedJobRoot
}

$identityRoot = New-TestCredentialBridgeRoot
try {
    $identityMarker = New-TestCredentialMarker -RootPath $identityRoot
    [System.IO.Directory]::Delete($identityRoot, $true)
    [void][System.IO.Directory]::CreateDirectory($identityRoot)
    Write-TestCredentialMarker -Marker $identityMarker
    Assert-TestRecoveryBlocked -Code 'root-identity-mismatch' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -Confirm:$false | Out-Null
    }
}
finally {
    Remove-TestCredentialState -RootPath $identityRoot
}

$junctionTarget = Join-Path ([System.IO.Path]::GetTempPath()) (
    'atlaso-onepassword-junction-target-' + [guid]::NewGuid().ToString('N')
)
$junctionRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'atlaso-onepassword-credentials-' + [guid]::NewGuid().ToString('N')
)
[void][System.IO.Directory]::CreateDirectory($junctionTarget)
try {
    $null = New-Item -ItemType Junction -Path $junctionRoot -Target $junctionTarget
    $junctionIdentity = & $credentialModule {
        param([string]$Path)
        Get-AtlasoPathIdentity -Path $Path -Description 'Synthetic credential bridge junction'
    } $junctionRoot
    $junctionMarker = [ordered]@{
        Schema = 2; RootPath = $junctionRoot; RootIdentity = $junctionIdentity
        BootIdentity = Get-AtlasoWindowsBootIdentity; Phase = 'active'
        OwnerProcessId = [int]::MaxValue; OwnerProcessStartFileTimeUtc = 1
        ProcessJobName = 'Local\Atlaso-OnePassword-' + [guid]::NewGuid().ToString('N')
        ChildProcessId = 0; ChildProcessStartFileTimeUtc = 0; ProcessOwnershipPhase = 'prepared'
    }
    Write-TestCredentialMarker -Marker $junctionMarker
    Assert-TestRecoveryBlocked -Code 'root-ancestry-invalid' -Action {
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $repositoryRoot `
            -Confirm:$false | Out-Null
    }
}
finally {
    if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
        Remove-Item -LiteralPath $markerPath -Force
    }
    if (Test-Path -LiteralPath $junctionRoot) {
        Remove-Item -LiteralPath $junctionRoot -Force
    }
    if (Test-Path -LiteralPath $junctionTarget -PathType Container) {
        [System.IO.Directory]::Delete($junctionTarget, $true)
    }
}

foreach ($invalidFixture in @(
        '{',
        '{"Schema":1,"RootPath":"not-disclosed","BootIdentity":"1","Phase":"active"}',
        '{"Schema":2,"Schema":2}',
        '{"Schema":2}'
    )) {
    try {
        [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $markerPath))
        [System.IO.File]::WriteAllText($markerPath, $invalidFixture, [Text.UTF8Encoding]::new($false))
        $expectedCode = if ($invalidFixture -ceq '{') {
            'marker-json-invalid'
        }
        elseif ($invalidFixture -like '*"Schema":1*') {
            'legacy-marker'
        }
        else {
            'marker-schema-invalid'
        }
        Assert-TestRecoveryBlocked -Code $expectedCode -Action {
            Invoke-AtlasoOnePasswordCredentialBridgeReset `
                -RepositoryRoot $repositoryRoot `
                -Confirm:$false | Out-Null
        }
        $standaloneFailure = & (Get-Process -Id $PID).Path `
            -NoLogo -NoProfile -NonInteractive -File $standaloneScript -Inspect 2>&1 | Out-String
        if ($LASTEXITCODE -ne 1 -or
            $standaloneFailure -notmatch '^ERROR:' -or
            $standaloneFailure -match 'not-disclosed|RootPath|ProcessJobName' -or
            $standaloneFailure -match [regex]::Escape($repositoryRoot)) {
            throw 'The standalone reset command exposed invalid marker data or an operator path.'
        }
    }
    finally {
        Remove-TestCredentialState
    }
}

$legacyRoot = New-TestCredentialBridgeRoot
try {
    $legacyMarker = [ordered]@{
        Schema       = 1
        RootPath     = $legacyRoot
        BootIdentity = ([long](Get-AtlasoWindowsBootIdentity) - 1).ToString(
            [System.Globalization.CultureInfo]::InvariantCulture
        )
        Phase        = 'active'
    }
    Write-TestCredentialMarker -Marker $legacyMarker
    & $credentialModule {
        param([string]$RepositoryRoot)
        Invoke-AtlasoOnePasswordCredentialCleanupRecovery -RepositoryRoot $RepositoryRoot
    } $repositoryRoot
    if ((Test-Path -LiteralPath $markerPath) -or (Test-Path -LiteralPath $legacyRoot)) {
        throw 'Previous-boot legacy compatibility recovery did not retire exact state.'
    }
}
finally {
    Remove-TestCredentialState -RootPath $legacyRoot
}

$bridgeRootsBeforeRerun = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory |
    Where-Object { $_.Name -like 'atlaso-onepassword-credentials-*' } |
    ForEach-Object { $_.FullName })
$rerunPair = Get-AtlasoOnePasswordCredentialPair `
    -RepositoryRoot $repositoryRoot `
    -AdminPassword (ConvertTo-SecureString 'synthetic-reset-admin-123!' -AsPlainText -Force) `
    -RootPassword (ConvertTo-SecureString 'synthetic-reset-root-456!' -AsPlainText -Force) `
    -TimeoutSeconds 30 `
    -ConsumerDescription 'credential recovery rerun test'
$rerunPair = $null
$bridgeRootsAfterRerun = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory |
    Where-Object {
        $_.Name -like 'atlaso-onepassword-credentials-*' -and
        $_.FullName -notin $bridgeRootsBeforeRerun
    })
if ($bridgeRootsAfterRerun.Count -ne 0 -or (Test-Path -LiteralPath $markerPath)) {
    throw 'The normal credential bridge did not rerun cleanly after supported recovery.'
}

Write-Host 'Supported 1Password credential-bridge reset tests passed.'
