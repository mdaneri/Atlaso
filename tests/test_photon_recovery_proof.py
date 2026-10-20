"""Focused synthetic coverage for recovered Photon builder termination receipts."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

WRAPPER = Path("scripts/windows/vmware/build-photon-image.ps1").resolve()
ADDRESS_MODULE = Path("scripts/windows/vmware/Atlaso.WorkstationBuilderAddress.psm1").resolve()


def _pwsh() -> str:
    executable = shutil.which("pwsh")
    if executable is None:
        pytest.skip("PowerShell 7 is unavailable")
    return executable


def _run(path: Path, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    path.write_text(script, encoding="utf-8")
    return subprocess.run(
        [_pwsh(), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(path), *arguments],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )


SETUP = r"""
param($Wrapper, $AddressModule, $Repository, $Mode)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $AddressModule) 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module $AddressModule -Force
$module = Get-Module Atlaso.WorkstationBuilderAddress
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Wrapper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Photon wrapper parse failed.' }
$function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Save-AtlasoPhotonRecoveredBuilderTerminationProof'}, $true)
if ($null -eq $function) { throw 'Recovered-proof owner helper is missing.' }
Invoke-Expression $function.Extent.Text
function Assert-AtlasoStrictDescendantPath {
    param($ParentPath, $ChildPath, $FailureMessage)
    $parentPath = [IO.Path]::GetFullPath($ParentPath).TrimEnd('\') + '\'
    $resolvedChild = [IO.Path]::GetFullPath($ChildPath)
    if (-not $resolvedChild.StartsWith($parentPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw $FailureMessage
    }
}
$repo = [IO.Path]::GetFullPath($Repository)
$root = Join-Path $repo 'credentials/atlaso-photon-build-credentials-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
[void][IO.Directory]::CreateDirectory($root)
$pending = Join-Path $repo 'vmware-builder-addresses/pending-releases'
[void][IO.Directory]::CreateDirectory($pending)
$ledgerRoot = Join-Path $repo 'synthetic-ledger'
[void][IO.Directory]::CreateDirectory($ledgerRoot)
[IO.File]::WriteAllText((Join-Path $ledgerRoot 'reservations.lock'), '')
$boot = & $module { Get-AtlasoBuilderHostBootIdentity }
$childPid = 2147483000
$childTicks = [DateTime]::UtcNow.AddDays(-7).Ticks
$childFileTime = [DateTime]::new($childTicks, [DateTimeKind]::Utc).ToFileTimeUtc()
$marker = [pscustomobject][ordered]@{
    Schema = 3; RootPath = $root; RootIdentity = 'synthetic-root-identity'; BootIdentity = $boot
    Phase = 'active'; OwnerProcessId = 2147483001
    OwnerProcessStartFileTimeUtc = [DateTime]::UtcNow.AddDays(-8).ToFileTimeUtc()
    ProcessJobName = 'Local\Atlaso-Photon-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ChildProcessId = $childPid; ChildProcessStartFileTimeUtc = $childFileTime
    ProcessOwnershipPhase = 'assigned'
}
if ($Mode -eq 'legacy') { $marker.ProcessOwnershipPhase = 'prepared' }
$allocation = [pscustomobject][ordered]@{
    Id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; Address = '192.0.2.10'; Cidr = 24
    NetworkName = 'synthetic'; Subnet = '192.0.2.0'; Netmask = '255.255.255.0'
    OwnerPid = $childPid; OwnerStartTimeUtcTicks = $childTicks; HostBootIdentity = $boot
    RepositoryRoot = $repo; SourceCommit = ('a' * 40); SourceBranch = 'bug/984-builder-recovery-proof'
    OutputDirectory = (Join-Path $repo 'output'); VmName = 'synthetic-builder'
    VmxPath = (Join-Path $repo 'output/synthetic-builder.vmx'); CreatedUtc = [DateTime]::UtcNow.ToString('o')
}
$handoffPath = Join-Path $pending ('builder-address-reservation-' + $allocation.Id + '.json')
$ledgerPath = Join-Path $ledgerRoot 'reservations.json'
$ledgerAllocation = $allocation
if ($Mode -eq 'ledger_conflict') {
    $ledgerAllocation = $allocation | Select-Object *
    $ledgerAllocation.Address = '192.0.2.11'
}
$ledgerReservations = @($ledgerAllocation)
if ($Mode -eq 'missing_handoff_absent') { $ledgerReservations = @() }
[IO.File]::WriteAllText($handoffPath, ($allocation | ConvertTo-Json -Depth 8))
[IO.File]::WriteAllText($ledgerPath, ([ordered]@{Schema=1; Reservations=$ledgerReservations} | ConvertTo-Json -Depth 8))
if ($Mode -in @('missing_handoff_absent', 'missing_handoff_ledger', 'missing_handoff_no_ledger')) {
    Remove-Item -LiteralPath $handoffPath -Force
    if ($Mode -eq 'missing_handoff_no_ledger') { Remove-Item -LiteralPath $ledgerPath -Force }
}
$script:moduleRef = $module
function Save-AtlasoBuilderTerminationProof {
    param($HandoffPath, $ExpectedOwnerPid, $ExpectedOwnerStartTimeUtcTicks,
        $ExpectedReservationSha256, $RecoveryMarker)
    & $script:moduleRef {
        param($Path, $PidValue, $Ticks, $Fingerprint, $Recovery, $Ledger)
        Save-AtlasoBuilderTerminationProof -HandoffPath $Path -ExpectedOwnerPid $PidValue `
            -ExpectedOwnerStartTimeUtcTicks $Ticks -ExpectedReservationSha256 $Fingerprint `
            -RecoveryMarker $Recovery -StateRoot $Ledger
    } $HandoffPath $ExpectedOwnerPid $ExpectedOwnerStartTimeUtcTicks `
        $ExpectedReservationSha256 $RecoveryMarker $ledgerRoot
}
function Assert-AtlasoBuilderRecoveryAllocationAbsent {
    param($Marker, $RepositoryRoot)
    & $script:moduleRef {
        param($Recovery, $Repository, $Ledger)
        Assert-AtlasoBuilderRecoveryAllocationAbsent -Marker $Recovery `
            -RepositoryRoot $Repository -StateRoot $Ledger
    } $Marker $RepositoryRoot $ledgerRoot
}
if ($Mode -in @('child_mismatch', 'start_mismatch', 'boot_mismatch', 'repository_mismatch')) {
    if ($Mode -eq 'child_mismatch') { $marker.ChildProcessId++ }
    if ($Mode -eq 'start_mismatch') { $allocation.OwnerStartTimeUtcTicks++ }
    if ($Mode -eq 'boot_mismatch') { $allocation.HostBootIdentity = '1' }
    if ($Mode -eq 'repository_mismatch') { $allocation.RepositoryRoot = (Join-Path $repo 'other') }
    [IO.File]::WriteAllText($handoffPath, ($allocation | ConvertTo-Json -Depth 8))
}
if ($Mode -eq 'duplicate') {
    $duplicate = Join-Path $pending ('builder-address-reservation-' + ('b' * 32) + '.json')
    $allocation.Id = 'b' * 32
    [IO.File]::WriteAllText($duplicate, ($allocation | ConvertTo-Json -Depth 8))
}
$fingerprint = & $module { param($Value) Get-AtlasoBuilderReservationFingerprint -Reservation $Value } $allocation
if ($Mode -eq 'missing_handoff_absent') {
    Save-AtlasoPhotonRecoveredBuilderTerminationProof -Marker $marker -RepositoryRoot $repo
    if ((Test-Path -LiteralPath $handoffPath) -or -not (Test-Path -LiteralPath $root)) {
        throw 'Ledger-proven allocation absence changed cleanup state.'
    }
    'no-proof'
    exit 0
}
try {
    if ($Mode -eq 'ordinary') {
        Save-AtlasoBuilderTerminationProof -HandoffPath $handoffPath -ExpectedOwnerPid $childPid `
            -ExpectedOwnerStartTimeUtcTicks $childTicks
    }
    else { Save-AtlasoPhotonRecoveredBuilderTerminationProof -Marker $marker -RepositoryRoot $repo }
    if ($Mode -in @('child_mismatch', 'start_mismatch', 'boot_mismatch', 'repository_mismatch', 'duplicate', 'ledger_conflict', 'missing_handoff_ledger', 'missing_handoff_no_ledger')) {
        throw 'Conflicting synthetic ownership unexpectedly received a proof.'
    }
} catch {
    if ($Mode -notin @('child_mismatch', 'start_mismatch', 'boot_mismatch', 'repository_mismatch', 'duplicate', 'ledger_conflict', 'missing_handoff_ledger', 'missing_handoff_no_ledger')) { throw }
    $failureMessage = $_.Exception.Message
    if ($failureMessage -match 'Conflicting synthetic ownership unexpectedly received a proof') { throw }
    $expectedFailure = switch ($Mode) {
        'child_mismatch' { 'original child|repository remains without a uniquely bound handoff' }
        { $_ -in @('start_mismatch', 'boot_mismatch', 'repository_mismatch') } { 'conflicts with the original recovered child, boot or repository' }
        'duplicate' { 'Multiple retained allocations claim the original recovered builder child' }
        'ledger_conflict' { 'exact original ledger allocation' }
        'missing_handoff_ledger' { 'allocation for the original child or repository remains' }
        'missing_handoff_no_ledger' { 'allocation ledger is missing' }
    }
    if ($failureMessage -notmatch $expectedFailure) {
        throw "Unexpected recovery refusal for $Mode`: $failureMessage"
    }
    if ($Mode -in @('missing_handoff_ledger', 'missing_handoff_no_ledger')) {
        if ((Test-Path -LiteralPath $handoffPath) -or -not (Test-Path -LiteralPath $root)) {
            throw 'Missing-handoff refusal did not preserve cleanup state.'
        }
    }
    elseif (-not (Test-Path -LiteralPath $handoffPath) -or -not (Test-Path -LiteralPath $root)) {
        throw 'Refusal did not preserve recovery state.'
    }
    if ($marker.Phase -cne 'active') { throw 'Refusal changed the cleanup marker phase.' }
    'blocked'
    exit 0
}
$saved = Get-Content -LiteralPath $handoffPath -Raw | ConvertFrom-Json
if ($Mode -in @('child_mismatch', 'legacy')) {
    if ($saved.TerminationProof) { throw 'A mismatched child received a proof.' }
    'no-proof'
    exit 0
}
if ($Mode -eq 'ordinary') {
    if (-not $saved.TerminationProof -or $saved.TerminationProof.Schema -ne 1) {
        throw 'Ordinary completion did not preserve its schema-1 receipt contract.'
    }
}
elseif (-not $saved.TerminationProof -or $saved.TerminationProof.Schema -ne 2) {
    throw 'Schema-2 recovery receipt was not durably published.'
}
if ($Mode -eq 'valid') {
    # This models the already-completed, identity-bound cleanup boundary; later
    # verification runs only after this controller process has exited.
    [IO.Directory]::Delete($root, $true)
}
'proved'
"""

VERIFY_AND_RELEASE = r"""
param($AddressModule, $HandoffPath, $LedgerRoot, $Mode)
$ErrorActionPreference = 'Stop'
Import-Module $AddressModule -Force
$module = Get-Module Atlaso.WorkstationBuilderAddress
$handoff = Get-Content -LiteralPath $HandoffPath -Raw | ConvertFrom-Json
& $module {
    param($VmxPath, $ObservationMode)
    $script:FixtureRunningVmx = if ($ObservationMode -eq 'active_vm') { $VmxPath } else { '' }
    $script:FixtureAddressInUse = $ObservationMode -eq 'active_address'
    Set-Item Function:\Get-AtlasoRunningVmwareVmxPaths -Value {
        if ([string]::IsNullOrWhiteSpace($script:FixtureRunningVmx)) { @() }
        else { @($script:FixtureRunningVmx) }
    }
    Set-Item Function:\Test-AtlasoVmwareAddressObservedInUse -Value { [bool]$script:FixtureAddressInUse }
} $handoff.VmxPath $Mode
$verified = & $module { param($Value) Test-AtlasoBuilderTerminationProof -Reservation $Value } $handoff
if (-not $verified) { throw 'Recovered same-boot proof was not accepted after controller exit.' }
$result = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath `
    -VmrunPath 'synthetic-vmrun.exe' -StateRoot $LedgerRoot -Execute
if ($Mode -in @('active_vm', 'active_address')) {
    if ($result.Status -cne 'blocked') { throw 'An active provider observation did not retain the reservation.' }
    if (-not (Test-Path -LiteralPath $HandoffPath)) { throw 'A blocked provider observation retired the handoff.' }
    $retainedLedger = Get-Content -LiteralPath (Join-Path $LedgerRoot 'reservations.json') -Raw | ConvertFrom-Json
    if (@($retainedLedger.Reservations).Count -ne 1) { throw 'A blocked provider observation changed the ledger.' }
    'blocked'
    exit 0
}
if ($result.Status -cne 'released') { throw "Reservation release was blocked: $($result.Reason)" }
if (Test-Path -LiteralPath $HandoffPath) { throw 'Released handoff was not retired.' }
$ledger = Get-Content -LiteralPath (Join-Path $LedgerRoot 'reservations.json') -Raw | ConvertFrom-Json
if (@($ledger.Reservations).Count -ne 0) { throw 'Released allocation remains in the ledger.' }
'released'
"""

REAL_JOB_CONTROLLER = r"""
param($FirstBoot, $CleanupModule, $Repository, $MarkerPath, $LedgerRoot)
$ErrorActionPreference = 'Stop'
Import-Module $CleanupModule -Force
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($FirstBoot, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'FirstBoot source parse failed.' }
foreach ($name in @(
    'Initialize-AtlasoWorkstationProcessJobType', 'New-AtlasoBoundedProcessJob',
    'Move-AtlasoDurableFile', 'Write-AtlasoDurableJsonFile', 'Sync-AtlasoDirectoryMetadata',
    'Get-AtlasoWindowsBootIdentity'
)) {
    $node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -ceq $name}, $true)
    if ($null -eq $node) { throw "Expected FirstBoot function is missing: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$repo = [IO.Path]::GetFullPath($Repository)
$root = Join-Path $repo ('credentials/atlaso-photon-build-credentials-' + ('c' * 32))
$markerDir = Split-Path -Parent $MarkerPath
[void][IO.Directory]::CreateDirectory($root)
[void][IO.Directory]::CreateDirectory($markerDir)
[void][IO.Directory]::CreateDirectory($LedgerRoot)
[IO.File]::WriteAllText((Join-Path $LedgerRoot 'reservations.lock'), '')
$boot = Get-AtlasoWindowsBootIdentity
$id = 'c' * 32
$jobName = 'Local\Atlaso-Photon-' + $id
$pwsh = (Get-Command pwsh).Source
$job = $null
try {
    $job = New-AtlasoBoundedProcessJob -FilePath $pwsh `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Milliseconds 250') `
        -ProcessJobName $jobName -DeferResume -DiscardOutput
    if ($null -eq $job) { throw 'Bounded process helper returned no job object.' }
    $child = $job.RootProcess
    if ($null -eq $child) { throw "Bounded process job has no root process; returned type: $($job.GetType().FullName)." }
    $controller = Get-Process -Id $PID -ErrorAction Stop
    $childTicks = $child.StartTime.ToUniversalTime().Ticks
    $childFileTime = $child.StartTime.ToUniversalTime().ToFileTimeUtc()
    $marker = [pscustomobject][ordered]@{
        Schema = 3; RootPath = $root
        RootIdentity = Get-AtlasoPathIdentity -Path $root -Description 'Synthetic Photon cleanup root'
        BootIdentity = $boot; Phase = 'active'
        OwnerProcessId = $PID; OwnerProcessStartFileTimeUtc = $controller.StartTime.ToUniversalTime().ToFileTimeUtc()
        ProcessJobName = $jobName; ChildProcessId = $child.Id
        ChildProcessStartFileTimeUtc = $childFileTime; ProcessOwnershipPhase = 'assigned'
    }
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $marker
    $allocation = [pscustomobject][ordered]@{
        Id = $id; Address = '192.0.2.10'; Cidr = 24; NetworkName = 'synthetic'
        Subnet = '192.0.2.0'; Netmask = '255.255.255.0'; OwnerPid = $child.Id
        OwnerStartTimeUtcTicks = $childTicks; HostBootIdentity = $boot; RepositoryRoot = $repo
        SourceCommit = ('a' * 40); SourceBranch = 'bug/984-builder-recovery-proof'
        OutputDirectory = (Join-Path $repo 'output'); VmName = 'synthetic-builder'
        VmxPath = (Join-Path $repo 'output/synthetic-builder.vmx'); CreatedUtc = [DateTime]::UtcNow.ToString('o')
    }
    $pending = Join-Path $repo 'vmware-builder-addresses/pending-releases'
    [void][IO.Directory]::CreateDirectory($pending)
    $handoff = Join-Path $pending ('builder-address-reservation-' + $id + '.json')
    [IO.File]::WriteAllText($handoff, ($allocation | ConvertTo-Json -Depth 8))
    $ledger = [ordered]@{ Schema = 1; Reservations = @($allocation) }
    [IO.File]::WriteAllText((Join-Path $LedgerRoot 'reservations.json'), ($ledger | ConvertTo-Json -Depth 8))
    $job.Resume()
    $job.CompleteAndWait(10000)
    $child.Dispose()
    $controller.Dispose()
}
finally {
    if ($null -ne $job -and $null -ne $job.PSObject.Methods['Dispose']) {
        try { $job.TerminateAndWait(10000) } catch { }
        $job.Dispose()
    }
}
'controller-exited'
"""

REAL_JOB_RECOVERY = r"""
param($FirstBoot, $Wrapper, $AddressModule, $CleanupModule, $Repository, $MarkerPath, $LedgerRoot, $Mode)
$ErrorActionPreference = 'Stop'
Import-Module $CleanupModule -Force
Import-Module $AddressModule -Force
$module = Get-Module Atlaso.WorkstationBuilderAddress
$script:moduleRef = $module
function Get-AtlasoBuilderReservationFingerprint {
    param($Reservation)
    & $script:moduleRef { param($Value) Get-AtlasoBuilderReservationFingerprint -Reservation $Value } $Reservation
}
function Save-AtlasoBuilderTerminationProof {
    param($HandoffPath, $ExpectedOwnerPid, $ExpectedOwnerStartTimeUtcTicks,
        $ExpectedReservationSha256, $RecoveryMarker)
    & $script:moduleRef {
        param($Path, $PidValue, $Ticks, $Fingerprint, $Recovery, $Ledger)
        Save-AtlasoBuilderTerminationProof -HandoffPath $Path -ExpectedOwnerPid $PidValue `
            -ExpectedOwnerStartTimeUtcTicks $Ticks -ExpectedReservationSha256 $Fingerprint `
            -RecoveryMarker $Recovery -StateRoot $Ledger
    } $HandoffPath $ExpectedOwnerPid $ExpectedOwnerStartTimeUtcTicks `
        $ExpectedReservationSha256 $RecoveryMarker $LedgerRoot
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($FirstBoot, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'FirstBoot source parse failed.' }
foreach ($name in @(
    'Initialize-AtlasoWorkstationProcessJobType', 'Open-AtlasoBoundedProcessJob',
    'Get-AtlasoRecordedProcessIdentityState', 'Complete-AtlasoSameBootBoundedProcessRecovery',
    'Get-AtlasoWindowsBootIdentity', 'Get-AtlasoWindowsBootIdentityState',
    'Move-AtlasoDurableFile', 'Write-AtlasoDurableJsonFile', 'Sync-AtlasoDirectoryMetadata'
)) {
    $node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -ceq $name}, $true)
    if ($null -eq $node) { throw "Expected FirstBoot function is missing: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($CleanupModule, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Workstation cleanup module parse failed.' }
foreach ($name in @(
    'Assert-AtlasoStrictDescendantPath', 'Get-AtlasoPathIdentity', 'Test-AtlasoStrictDescendantPath',
    'Get-AtlasoCanonicalPath', 'Assert-AtlasoPathHasNoReparsePoint', 'Test-AtlasoSamePath'
)) {
    $node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -ceq $name}, $true)
    if ($null -eq $node) { throw "Expected cleanup function is missing: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Wrapper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Photon wrapper source parse failed.' }
foreach ($name in @(
    'Complete-AtlasoPhotonSameBootProcessRecovery',
    'Save-AtlasoPhotonRecoveredBuilderTerminationProof',
    'Complete-AtlasoPhotonBuildCleanup', 'Invoke-AtlasoPhotonBuildCleanupRecovery'
)) {
    $node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -ceq $name}, $true)
    if ($null -eq $node) { throw "Expected Photon wrapper function is missing: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$marker = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
if ($Mode -in @('root-absent', 'retired')) {
    if (Test-Path -LiteralPath $marker.RootPath) { [IO.Directory]::Delete([string]$marker.RootPath, $true) }
    $marker.Phase = $Mode
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $marker -Replace
}
$rootIdentity = [string]$marker.RootIdentity
$allocationFiles = @(Get-ChildItem -LiteralPath (Join-Path $Repository 'vmware-builder-addresses/pending-releases') `
    -Filter 'builder-address-reservation-*.json')
if ($allocationFiles.Count -ne 1) { throw 'Native-job fixture did not create exactly one handoff.' }
$handoffPath = $allocationFiles[0].FullName
if ($Mode -eq 'existing_proof_conflict') {
    Complete-AtlasoPhotonSameBootProcessRecovery -Marker $marker
    Save-AtlasoPhotonRecoveredBuilderTerminationProof -Marker $marker -RepositoryRoot $Repository
    $tampered = Get-Content -LiteralPath $handoffPath -Raw | ConvertFrom-Json
    $tampered.TerminationProof.RecoveryMarker.RootIdentity = 'conflicting-original-root'
    [IO.File]::WriteAllText($handoffPath, ($tampered | ConvertTo-Json -Depth 8))
    $originalMarkerBytes = [IO.File]::ReadAllBytes($MarkerPath)
    $tamperedHandoffBytes = [IO.File]::ReadAllBytes($handoffPath)
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $MarkerPath `
            -RepositoryRoot $Repository -AllowedParentRoots @(Join-Path $Repository 'credentials') `
            -ExpectedRootIdentity $rootIdentity
        throw 'A conflicting existing receipt unexpectedly retired cleanup state.'
    }
    catch {
        $diagnostic = if ($null -ne $_.Exception.InnerException) { $_.Exception.InnerException.Message }
            else { $_.Exception.Message }
        if ($diagnostic -notmatch 'retained termination receipt conflicts with the original process marker') {
            throw $diagnostic
        }
    }
    if (-not [System.Linq.Enumerable]::SequenceEqual[byte](
            [IO.File]::ReadAllBytes($MarkerPath), $originalMarkerBytes) -or
        -not [System.Linq.Enumerable]::SequenceEqual[byte](
            [IO.File]::ReadAllBytes($handoffPath), $tamperedHandoffBytes)) {
        throw 'Conflicting proof refusal changed persisted marker or handoff bytes.'
    }
    if (-not (Test-Path -LiteralPath $marker.RootPath -PathType Container)) {
        throw 'Conflicting proof refusal removed the credential root.'
    }
    'conflict-preserved'
    exit 0
}
if ($Mode -in @('failure_before_rename', 'failure_after_rename')) {
    $originalMarkerBytes = [IO.File]::ReadAllBytes($MarkerPath)
    & $module {
        param($FailureMode)
        $script:OriginalDurableMoveForTest = (Get-Command Move-AtlasoBuilderLedgerDurableFile).ScriptBlock
        $script:FailAfterRenameForTest = $FailureMode -eq 'failure_after_rename'
        $injectedMove = {
            param($SourcePath, $DestinationPath, [switch]$Replace)
            if ($script:FailAfterRenameForTest) {
                & $script:OriginalDurableMoveForTest -SourcePath $SourcePath `
                    -DestinationPath $DestinationPath -Replace:$Replace
            }
            throw 'Injected durable receipt publication interruption.'
        }
        Set-Item Function:\Move-AtlasoBuilderLedgerDurableFile -Value $injectedMove
    } $Mode
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $MarkerPath `
            -RepositoryRoot $Repository -AllowedParentRoots @(Join-Path $Repository 'credentials') `
            -ExpectedRootIdentity $rootIdentity
        throw 'Injected receipt interruption unexpectedly retired cleanup state.'
    }
    catch {
        $diagnostic = if ($null -ne $_.Exception.InnerException) { $_.Exception.InnerException.Message }
            else { $_.Exception.Message }
        if ($diagnostic -notmatch 'Injected durable receipt publication interruption') { throw $diagnostic }
    }
    if (-not [System.Linq.Enumerable]::SequenceEqual[byte](
            [IO.File]::ReadAllBytes($MarkerPath), $originalMarkerBytes)) {
        throw 'A failed receipt publication changed the original cleanup marker bytes.'
    }
    if (-not (Test-Path -LiteralPath $marker.RootPath -PathType Container)) {
        throw 'A failed receipt publication removed the credential root.'
    }
    $interruptedHandoff = Get-Content -LiteralPath $handoffPath -Raw | ConvertFrom-Json
    if ($Mode -eq 'failure_before_rename' -and $interruptedHandoff.TerminationProof) {
        throw 'A pre-rename interruption published a termination receipt.'
    }
    if ($Mode -eq 'failure_after_rename' -and -not $interruptedHandoff.TerminationProof) {
        throw 'A post-rename interruption lost its durably visible termination receipt.'
    }
    & $module { Set-Item Function:\Move-AtlasoBuilderLedgerDurableFile -Value $script:OriginalDurableMoveForTest }
}
try {
    Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $MarkerPath `
        -RepositoryRoot $Repository -AllowedParentRoots @(Join-Path $Repository 'credentials') `
        -ExpectedRootIdentity $rootIdentity
}
catch { throw $_.Exception.InnerException }
if (Test-Path -LiteralPath $MarkerPath) { throw 'Recovery cleanup did not retire the marker.' }
if (Test-Path -LiteralPath $marker.RootPath) { throw 'Recovery cleanup did not remove the exact credential root.' }
$finalHandoff = Get-Content -LiteralPath $handoffPath -Raw | ConvertFrom-Json
if (-not $finalHandoff.TerminationProof -or $finalHandoff.TerminationProof.Schema -ne 2) {
    throw 'Recovery retry did not retain a schema-2 proof.'
}
'recovered-and-retired'
"""

RECOVERY_GATES = r"""
param($FirstBoot, $Wrapper, $Mode)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($FirstBoot, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'FirstBoot source parse failed.' }
$node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $item.Name -ceq 'Complete-AtlasoSameBootBoundedProcessRecovery'}, $true)
if ($null -eq $node) { throw 'Bounded process recovery function is missing.' }
. ([scriptblock]::Create($node.Extent.Text))
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Wrapper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Photon wrapper source parse failed.' }
$node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $item.Name -ceq 'Complete-AtlasoPhotonSameBootProcessRecovery'}, $true)
if ($null -eq $node) { throw 'Photon bounded process recovery function is missing.' }
. ([scriptblock]::Create($node.Extent.Text))
$marker = [pscustomobject]@{
    Schema = 3; RootPath = 'C:\synthetic\atlaso-photon-build-credentials-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    RootIdentity = 'synthetic'; BootIdentity = 'same-boot'; Phase = 'active'
    OwnerProcessId = 41001; OwnerProcessStartFileTimeUtc = 1001
    ProcessJobName = 'Local\Atlaso-Photon-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ChildProcessId = 41002; ChildProcessStartFileTimeUtc = 1002
    ProcessOwnershipPhase = 'assigned'
}
function Get-AtlasoRecordedProcessIdentityState {
    param([int]$ProcessId, [long]$StartFileTimeUtc)
    if ($Mode -eq 'pid_reuse') { return 'reused' }
    if ($ProcessId -eq $marker.OwnerProcessId) { return 'absent' }
    return 'matching'
}
function Open-AtlasoBoundedProcessJob { $null }
try {
    Complete-AtlasoPhotonSameBootProcessRecovery -Marker $marker
    throw 'Unproven process ownership unexpectedly passed recovery.'
}
catch {
    if ($_.Exception.Message -notmatch 'active or its process identifier was reused|remains present without its exact process job') {
        throw
    }
}
if ($marker.Phase -cne 'active' -or $marker.PSObject.Properties.Name -contains 'TerminationProof') {
    throw 'Unproven process ownership changed the retained marker.'
}
'blocked'
"""

LEGACY_CURRENT_BOOT_RECOVERY = r"""
param($FirstBoot, $Wrapper, $CleanupModule, $Repository, $MarkerPath)
$ErrorActionPreference = 'Stop'
Import-Module $CleanupModule -Force
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($FirstBoot, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'FirstBoot source parse failed.' }
foreach ($name in @('Get-AtlasoWindowsBootIdentity', 'Get-AtlasoWindowsBootIdentityState')) {
    $node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -ceq $name}, $true)
    if ($null -eq $node) { throw "Expected boot identity function is missing: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($CleanupModule, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Cleanup module source parse failed.' }
foreach ($name in @(
    'Assert-AtlasoStrictDescendantPath', 'Get-AtlasoPathIdentity', 'Test-AtlasoStrictDescendantPath',
    'Get-AtlasoCanonicalPath', 'Assert-AtlasoPathHasNoReparsePoint', 'Test-AtlasoSamePath'
)) {
    $node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $item.Name -ceq $name}, $true)
    if ($null -eq $node) { throw "Expected cleanup function is missing: $name" }
    . ([scriptblock]::Create($node.Extent.Text))
}
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Wrapper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Photon wrapper source parse failed.' }
$node = $ast.Find({param($item) $item -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $item.Name -ceq 'Invoke-AtlasoPhotonBuildCleanupRecovery'}, $true)
if ($null -eq $node) { throw 'Photon cleanup recovery function is missing.' }
. ([scriptblock]::Create($node.Extent.Text))
$repo = [IO.Path]::GetFullPath($Repository)
$root = Join-Path $repo ('credentials/atlaso-photon-build-credentials-' + ('d' * 32))
[void][IO.Directory]::CreateDirectory($root)
$marker = [pscustomobject][ordered]@{
    Schema = 2; RootPath = $root
    RootIdentity = Get-AtlasoPathIdentity -Path $root -Description 'Synthetic legacy cleanup root'
    BootIdentity = Get-AtlasoWindowsBootIdentity; Phase = 'active'
}
[void][IO.Directory]::CreateDirectory((Split-Path -Parent $MarkerPath))
[IO.File]::WriteAllText($MarkerPath, ($marker | ConvertTo-Json -Depth 4 -Compress))
$before = [IO.File]::ReadAllBytes($MarkerPath)
try {
    Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $MarkerPath `
        -RepositoryRoot $repo -AllowedParentRoots @(Join-Path $repo 'credentials') `
        -ExpectedRootIdentity $marker.RootIdentity
    throw 'A current-boot legacy marker unexpectedly passed cleanup recovery.'
}
catch {
    $diagnostic = if ($null -ne $_.Exception.InnerException) { $_.Exception.InnerException.Message }
        else { $_.Exception.Message }
    if ($diagnostic -notmatch 'restart is required') { throw }
}
if (-not [System.Linq.Enumerable]::SequenceEqual[byte]([IO.File]::ReadAllBytes($MarkerPath), $before)) {
    throw 'Current-boot legacy refusal changed the marker bytes.'
}
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw 'Current-boot legacy refusal removed the cleanup root.'
}
'legacy-blocked'
"""

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native durable receipt publication requires Windows")


@pytest.mark.parametrize(
    "mode",
    [
        "valid",
        "ordinary",
        "child_mismatch",
        "start_mismatch",
        "boot_mismatch",
        "repository_mismatch",
        "duplicate",
        "ledger_conflict",
        "missing_handoff_absent",
        "missing_handoff_ledger",
        "missing_handoff_no_ledger",
    ],
)
def test_cleanup_recovery_publishes_only_unique_exact_allocation_proof(
    tmp_path_factory: pytest.TempPathFactory, mode: str
) -> None:
    """Publish a same-boot receipt only for one handoff matching marker and ledger.

    Args:
        tmp_path_factory: Pytest-owned synthetic repository root factory.
        mode: Allocation identity or ledger boundary under test.
    """
    tmp_path = tmp_path_factory.mktemp("r")
    repository = tmp_path / "repo"
    repository.mkdir()
    result = _run(tmp_path / "proof.ps1", SETUP, str(WRAPPER), str(ADDRESS_MODULE), str(repository), mode)
    assert result.returncode == 0, result.stderr
    if mode == "missing_handoff_absent":
        assert result.stdout.strip().endswith("no-proof")
        return
    if mode not in {"valid", "ordinary"}:
        assert result.stdout.strip().endswith("blocked")
        return
    assert result.stdout.strip().endswith("proved")
    if mode in {"valid", "ordinary"}:
        handoff = next(repository.rglob("builder-address-reservation-*.json"))
        ledger_root = repository / "synthetic-ledger"
        released = _run(
            tmp_path / "verify.ps1",
            VERIFY_AND_RELEASE,
            str(ADDRESS_MODULE),
            str(handoff),
            str(ledger_root),
            "inactive",
        )
        assert released.returncode == 0, released.stderr
        assert released.stdout.strip().endswith("released")


def test_prepared_marker_does_not_manufacture_an_unbound_receipt(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """A prepared schema-3 marker cannot prove termination of an assigned child."""
    tmp_path = tmp_path_factory.mktemp("legacy")
    repository = tmp_path / "repo"
    repository.mkdir()
    result = _run(tmp_path / "legacy.ps1", SETUP, str(WRAPPER), str(ADDRESS_MODULE), str(repository), "legacy")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("no-proof")
    handoff = next(repository.rglob("builder-address-reservation-*.json"))
    assert "TerminationProof" not in json.loads(handoff.read_text(encoding="utf-8"))


def test_current_boot_legacy_marker_remains_untouched(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """A current-boot legacy marker lacks job evidence and remains intact.

    Args:
        tmp_path_factory: Pytest-owned, short-path fixture root factory.
    """
    case_root = tmp_path_factory.mktemp("l")
    repository = case_root / "repo"
    repository.mkdir()
    firstboot = Path("scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1").resolve()
    cleanup_module = Path("scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1").resolve()
    result = _run(
        case_root / "legacy.ps1",
        LEGACY_CURRENT_BOOT_RECOVERY,
        str(firstboot),
        str(WRAPPER),
        str(cleanup_module),
        str(repository),
        str(repository / ".atlaso-photon-build-state" / "legacy.json"),
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("legacy-blocked")


@pytest.mark.parametrize("observation", ["active_vm", "active_address"])
def test_active_provider_observation_blocks_release_even_with_valid_receipt(
    tmp_path_factory: pytest.TempPathFactory, observation: str
) -> None:
    """A valid process receipt cannot override current VM or address evidence.

    Args:
        tmp_path_factory: Pytest-owned, short-path fixture root factory.
        observation: Provider boundary evidence that must retain allocation state.
    """
    case_root = tmp_path_factory.mktemp("p")
    repository = case_root / "repo"
    repository.mkdir()
    published = _run(case_root / "publish.ps1", SETUP, str(WRAPPER), str(ADDRESS_MODULE), str(repository), "valid")
    assert published.returncode == 0, published.stderr
    handoff = next(repository.rglob("builder-address-reservation-*.json"))
    ledger_root = repository / "synthetic-ledger"
    checked = _run(
        case_root / "provider-check.ps1",
        VERIFY_AND_RELEASE,
        str(ADDRESS_MODULE),
        str(handoff),
        str(ledger_root),
        observation,
    )
    assert checked.returncode == 0, checked.stderr
    assert checked.stdout.strip().endswith("blocked")
    retained = json.loads(handoff.read_text(encoding="utf-8"))
    ledger = json.loads((ledger_root / "reservations.json").read_text(encoding="utf-8"))
    assert retained["TerminationProof"]["Schema"] == 2
    assert len(ledger["Reservations"]) == 1


@pytest.mark.parametrize("case", ["pid_reuse", "unproven_job"])
def test_pid_reuse_and_unproven_job_block_proof_propagation(
    tmp_path_factory: pytest.TempPathFactory, case: str
) -> None:
    """Identity or job-membership uncertainty preserves marker evidence.

    Args:
        tmp_path_factory: Pytest-owned, short-path fixture root factory.
        case: Process reuse or absent job with a still-matching child.
    """
    case_root = tmp_path_factory.mktemp("g")
    firstboot = Path("scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1").resolve()
    result = _run(
        case_root / "gate.ps1",
        RECOVERY_GATES,
        str(firstboot),
        str(WRAPPER),
        case,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("blocked")


@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "failure_before_rename",
        "failure_after_rename",
        "root-absent",
        "retired",
        "existing_proof_conflict",
    ],
)
def test_real_bounded_job_recovery_publishes_receipt_before_cleanup_retirement(
    tmp_path_factory: pytest.TempPathFactory, mode: str
) -> None:
    """A completed native job can be recovered and cleaned by a later controller.

    Args:
        tmp_path_factory: Pytest-owned, short-path fixture root.
        mode: Publication, retirement, interruption, or conflicting-proof boundary.
    """
    case_root = tmp_path_factory.mktemp("j")
    repository = case_root / "repo"
    repository.mkdir()
    marker_path = repository / ".atlaso-photon-build-state" / "cleanup.json"
    ledger_root = repository / "synthetic-ledger"
    firstboot = Path("scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1").resolve()
    cleanup_module = Path("scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1").resolve()

    controller = _run(
        case_root / "controller.ps1",
        REAL_JOB_CONTROLLER,
        str(firstboot),
        str(cleanup_module),
        str(repository),
        str(marker_path),
        str(ledger_root),
    )
    assert controller.returncode == 0, controller.stderr
    assert controller.stdout.strip().endswith("controller-exited")
    persisted_marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert persisted_marker["Schema"] == 3
    assert persisted_marker["ProcessOwnershipPhase"] == "assigned"

    recovery = _run(
        case_root / "recovery.ps1",
        REAL_JOB_RECOVERY,
        str(firstboot),
        str(WRAPPER),
        str(ADDRESS_MODULE),
        str(cleanup_module),
        str(repository),
        str(marker_path),
        str(ledger_root),
        mode,
    )
    assert recovery.returncode == 0, recovery.stderr
    if mode == "existing_proof_conflict":
        assert recovery.stdout.strip().endswith("conflict-preserved")
        assert marker_path.exists()
        assert Path(persisted_marker["RootPath"]).exists()
        return
    assert recovery.stdout.strip().endswith("recovered-and-retired")
    assert not marker_path.exists()
    assert not Path(persisted_marker["RootPath"]).exists()

    handoff = next(repository.rglob("builder-address-reservation-*.json"))
    receipt = json.loads(handoff.read_text(encoding="utf-8"))["TerminationProof"]
    assert receipt["Schema"] == 2
    expected_phase = mode if mode in {"root-absent", "retired"} else "active"
    assert receipt["RecoveryMarker"] == {**persisted_marker, "Phase": expected_phase}
