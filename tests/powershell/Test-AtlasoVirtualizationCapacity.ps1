<#
.SYNOPSIS
Exercises peak/resume planning and the actual prerelease initial-admission boundary.
.PARAMETER RepositoryRoot
Exact source checkout for module loading and fixture ownership.
#>
[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/virtualization/Atlaso.VirtualizationCapacity.psm1') -Force
$capacityModule = Get-Module Atlaso.VirtualizationCapacity
$operation = Join-Path $RepositoryRoot 'test-results/never-created-capacity-operation'
$builder = Join-Path $operation 'builder'

& $capacityModule {
    Set-Item function:script:Get-AtlasoStorageVolume -Value {
        param($Path)
        [pscustomobject]@{ VolumeId='shared'; Path=$Path }
    }
    Set-Item function:script:Assert-AtlasoStorageCapacity -Value {
        param($Components, $Stage)
        $script:CapturedComponents = @($Components)
    }
}
$plan = @(Get-AtlasoVirtualizationStoragePlan -RepoRoot $RepositoryRoot -Operation $operation -BuilderOutput $builder)
Assert-AtlasoVirtualizationStoragePlan -Plan $plan
$initial = @(& $capacityModule { $script:CapturedComponents })
$initialBytes = [long](($initial | Measure-Object -Property Bytes -Sum).Sum)
if ($initialBytes -ne 178GB) { throw "Unexpected shared-volume peak: $initialBytes" }
if (@($initial | Where-Object Name -Like '*Hyper-V extraction*').Count) {
    throw 'Sequential VMware and Hyper-V smoke allocations were incorrectly combined.'
}
Assert-AtlasoVirtualizationStoragePlan -Plan $plan -Stage 5
$remaining = @(& $capacityModule { $script:CapturedComponents })
if ([long](($remaining | Measure-Object -Property Bytes -Sum).Sum) -ne 36GB) {
    throw 'Completed allocations were not removed from remaining demand.'
}
$candidatePlan = @(Get-AtlasoVirtualizationStoragePlan -RepoRoot $RepositoryRoot -Operation $operation -Resume Candidate -SourceBytes 1GB)
Assert-AtlasoVirtualizationStoragePlan -Plan $candidatePlan
$candidate = @(& $capacityModule { $script:CapturedComponents })
if ([long](($candidate | Measure-Object -Property Bytes -Sum).Sum) -ne 3GB) {
    throw 'Verified candidate resume incorrectly requires build/export/import capacity.'
}
$templatePlan = @(Get-AtlasoVirtualizationStoragePlan -RepoRoot $RepositoryRoot -Operation $operation -Resume Template)
if (@($templatePlan | Where-Object Start -EQ 1).Count) { throw 'Verified template reuse still budgets a new builder.' }

foreach ($resume in @('Build', 'Template')) {
    $retainedPlan = @(Get-AtlasoVirtualizationStoragePlan -RepoRoot $RepositoryRoot -Operation $operation `
        -BuilderOutput $builder -Resume $resume -RetainedSource)
    $reconstruction = @($retainedPlan | Where-Object Name -EQ 'verified source reconstruction')
    if ($reconstruction.Count -ne 1 -or $reconstruction[0].End -ne 0) {
        throw 'Retained source comparison copy survives its verification stage in the plan.'
    }
    Assert-AtlasoVirtualizationStoragePlan -Plan $retainedPlan
    $retainedPeak = [long]((@(& $capacityModule { $script:CapturedComponents }) | Measure-Object Bytes -Sum).Sum)
    $expectedPeak = if ($resume -eq 'Build') { 162GB } else { 94GB }
    if ($retainedPeak -ne $expectedPeak) { throw "Retained $resume peak double-counts existing source bytes." }
}
$newSource = @($plan | Where-Object Name -EQ 'verified source reconstruction')
if ($newSource[0].End -ne 7) { throw 'New source allocation was prematurely released.' }

& $capacityModule {
    Set-Item function:script:Get-AtlasoStorageVolume -Value {
        param($Path)
        [pscustomobject]@{ VolumeId=($(if ($Path -like '*never-created-capacity-operation*') { 'staging' } else { 'checkout' })); Path=$Path }
    }
}
Assert-AtlasoVirtualizationStoragePlan -Plan $plan
$separate = @(& $capacityModule { $script:CapturedComponents })
if (@($separate | Where-Object Name -Like '*compaction*').Count -ne 1 -or
    @($separate | Where-Object Name -Like '*VMware import*').Count -ne 1) {
    throw 'Independent destination volumes did not receive their own peak demand.'
}

# Run the real prerelease function against read-only metadata fixtures. The initial
# admission failure must precede credentials, staging and every downstream action.
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/virtualization/Atlaso.VirtualizationRelease.psm1') -Force
$releaseModule = Get-Module Atlaso.VirtualizationRelease
& $releaseModule {
    param($Root, $OperationPath)
    $script:CapacityTestRoot = $Root
    $script:CapacityTestOperation = $OperationPath
    Set-Item function:Get-AtlasoReleaseRepository -Value { 'fixture/repository' }
    Set-Item function:Get-AtlasoVirtualizationSourceIdentity -Value { [pscustomobject]@{ Version='0.9.1'; Commit=('a' * 40) } }
    Set-Item function:Resolve-AtlasoVirtualizationStagingRoot -Value { $script:CapacityTestOperation }
    Set-Item function:Get-AtlasoVirtualizationRetainedOperationTags -Value { }
    Set-Item function:Get-AtlasoVirtualizationRemoteTagNames -Value { }
    Set-Item function:Get-AtlasoVirtualizationReleaseTagNames -Value { }
    Set-Item function:Select-AtlasoVirtualizationPrereleaseTag -Value { 'virtualization-v0.9.1-rc.1' }
    Set-Item function:New-AtlasoVmwareBuilderIdentity -Value { [pscustomobject]@{ Name='fixture-builder' } }
    Set-Item function:Resolve-AtlasoVirtualizationBuilderOutput -Value { Join-Path $script:CapacityTestOperation 'builder' }
    Set-Item function:Assert-AtlasoVmwareBuilderPathBudget -Value { }
    Set-Item function:Resolve-AtlasoVirtualizationHyperVSwitches -Value { [pscustomobject]@{ Management='M'; Service='S' } }
    Set-Item function:Assert-AtlasoVirtualizationStoragePlan -Value { throw 'EXPECTED_INITIAL_CAPACITY_REFUSAL' }
    foreach ($name in @('Resolve-AtlasoVirtualizationStagingDirectory', 'Resolve-AtlasoOnePasswordEnvironmentId',
            'Invoke-AtlasoReleaseGh', 'Invoke-AtlasoVirtualizationReleaseImageBuilder',
            'Publish-AtlasoVirtualizationDraftAssets', 'New-AtlasoSmokeConsoleSession')) {
        Set-Item "function:$name" -Value { throw 'MUTATION_BEFORE_CAPACITY' }
    }
    try {
        Invoke-AtlasoVirtualizationPrerelease -RepoRoot $Root
        throw 'Initial capacity refusal was bypassed.'
    }
    catch {
        if ($_.Exception.Message -cne 'EXPECTED_INITIAL_CAPACITY_REFUSAL') { throw }
    }
} $RepositoryRoot $operation
if (Test-Path -LiteralPath $operation) { throw 'Failed initial admission created operation output.' }

# Evaluate the actual exporter admission command at an initially admitted boundary:
# 72 GiB free, 6 GiB extracted, then a validated 6 GiB first payload. The second
# check must discount that completed allocation while still refusing new pressure.
$exportAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'scripts/windows/virtualization/export-artifacts.ps1'), [ref]$null, [ref]$null)
$conversionChecks = @($exportAst.FindAll({
    param($Node)
    $Node -is [Management.Automation.Language.CommandAst] -and
    $Node.GetCommandName() -eq 'Assert-AtlasoStorageCapacity' -and
    $Node.Extent.Text -like '*remaining VHDX conversion and ZIP*'
}, $true))
if ($conversionChecks.Count -ne 1) { throw 'Expected one actual per-payload capacity check.' }
$checkConversion = [scriptblock]::Create($conversionChecks[0].Extent.Text)
& {
    $outputDirectory = $RepositoryRoot
    $roleName = 'fixture'
    $completedVhdxBytes = 0L
    $freeBytes = 66GB
    Set-Item function:Assert-AtlasoStorageCapacity -Value {
        param($Stage, $Components)
        if ([long]$Components[0].Bytes + 2GB -gt $freeBytes) { throw 'EXPECTED_CONVERSION_CAPACITY_REFUSAL' }
    }
    & $checkConversion
    $completedVhdxBytes = 6GB
    $freeBytes = 60GB
    & $checkConversion
    $freeBytes--
    try {
        & $checkConversion
        throw 'Concurrent space consumption was not refused.'
    } catch {
        if ($_.Exception.Message -cne 'EXPECTED_CONVERSION_CAPACITY_REFUSAL') { throw }
    }
}
Write-Host 'Virtualization capacity and initial-admission regression tests passed.'
