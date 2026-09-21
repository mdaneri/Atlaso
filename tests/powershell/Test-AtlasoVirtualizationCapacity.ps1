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
if ($initialBytes -ne 179GB) { throw "Unexpected shared-volume peak: $initialBytes" }
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
    $expectedPeak = if ($resume -eq 'Build') { 163GB } else { 94GB }
    if ($retainedPeak -ne $expectedPeak) { throw "Retained $resume peak double-counts existing source bytes." }
}
$newSource = @($plan | Where-Object Name -EQ 'verified source reconstruction')
if ($newSource[0].End -ne 7) { throw 'New source allocation was prematurely released.' }

# A source-size upper bound and pre-compaction disk high-water mark are not
# retained allocations after verification/compaction. Cross those evidence
# barriers using fresh free space, keeping every current-stage allocation.
Assert-AtlasoVirtualizationStoragePlan -Plan $plan -Stage 0 -ThroughStage 0
$sourceAdmission = @(& $capacityModule { $script:CapturedComponents })
if ([long](($sourceAdmission | Measure-Object Bytes -Sum).Sum) -ne 18GB -or
    @($sourceAdmission | Where-Object PeakStage -NE 'source verification').Count) {
    throw 'Source admission includes hypothetical later builder/import allocations.'
}
$verifiedPlan = @(Get-AtlasoVirtualizationStoragePlan -RepoRoot $RepositoryRoot -Operation $operation `
    -BuilderOutput $builder -SourceBytes 32MB -RetainedSource)
Assert-AtlasoVirtualizationStoragePlan -Plan $verifiedPlan -Stage 1 -ThroughStage 1
$buildAdmission = @(& $capacityModule { $script:CapturedComponents })
if ([long](($buildAdmission | Measure-Object Bytes -Sum).Sum) -ne (121GB + 32MB)) {
    throw 'Build admission must retain zero-fill/compaction bounds and the verified source copy size.'
}
if (@($buildAdmission | Where-Object Name -Like '*VMware import*').Count) {
    throw 'Smoke allocation overlaps build despite the compaction evidence barrier.'
}
$cachedPlan = @(Get-AtlasoVirtualizationStoragePlan -RepoRoot $RepositoryRoot -Operation $operation `
    -BuilderOutput $builder -SourceBytes 32MB -RetainedSource -VerifiedIsoCache)
Assert-AtlasoVirtualizationStoragePlan -Plan $cachedPlan -Stage 1 -ThroughStage 1
$cached = @(& $capacityModule { $script:CapturedComponents })
if ([long](($cached | Measure-Object Bytes -Sum).Sum) -ne (116GB + 32MB)) {
    throw 'Verified existing ISO allocation was budgeted again as a new download.'
}
# A volume with 124 GiB free admits this build with the 2 GiB reserve;
# one with 122 GiB cannot. The old 180 GiB forecast rejected both.
$buildRequired = [long](($buildAdmission | Measure-Object Bytes -Sum).Sum) + 2GB
if ($buildRequired -gt 124GB -or $buildRequired -le 122GB) {
    throw 'Build admission does not separate feasible capacity from an actual shortfall.'
}
Assert-AtlasoVirtualizationStoragePlan -Plan $verifiedPlan -Stage 2 -ThroughStage 2
$exportAdmission = @(& $capacityModule { $script:CapturedComponents })
if ([long](($exportAdmission | Measure-Object Bytes -Sum).Sum) -ne 68GB -or
    @($exportAdmission | Where-Object Name -Like '*zero fill*').Count) {
    throw 'Export admission counts existing compacted builder bytes a second time.'
}
foreach ($stage in @(3,4,5,6)) {
    Assert-AtlasoVirtualizationStoragePlan -Plan $verifiedPlan -Stage $stage -ThroughStage $stage
    $current = @(& $capacityModule { $script:CapturedComponents })
    $expected = @{3=70GB;4=84GB;5=36GB;6=8GB}[$stage]
    if ([long](($current | Measure-Object Bytes -Sum).Sum) -ne $expected) {
        throw "Stage $stage lost its conservative conversion/import/guest-growth or staging bound."
    }
}
try {
    Assert-AtlasoVirtualizationStoragePlan -Plan $plan -Stage 2 -ThroughStage 1
    throw 'Invalid horizon was admitted.'
} catch {
    if ($_.Exception.Message -cne 'Storage admission horizon precedes the next stage.') { throw }
}

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
Assert-AtlasoVirtualizationStoragePlan -Plan $verifiedPlan -Stage 1 -ThroughStage 1
$splitBuild = @(& $capacityModule { $script:CapturedComponents })
$builderBytes = [long](($splitBuild | Where-Object Path -EQ $builder | Measure-Object Bytes -Sum).Sum)
$checkoutBytes = [long](($splitBuild | Where-Object Path -NE $builder | Measure-Object Bytes -Sum).Sum)
if ($builderBytes -ne 108GB -or $checkoutBytes -ne (13GB + 32MB)) {
    throw 'Build admission lost the distinct builder and checkout volume budgets.'
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
    Set-Item function:Assert-AtlasoVirtualizationStoragePlan -Value {
        param($Plan, $Stage, $ThroughStage)
        if ($Stage -ne 0 -or $ThroughStage -ne 0) { throw 'Source evidence barrier was bypassed.' }
        throw 'EXPECTED_INITIAL_CAPACITY_REFUSAL'
    }
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

# Each real orchestration boundary must admit its own known inputs. Do not let
# a refactor accidentally restore the all-remaining guess or omit a stage.
$releaseAst = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $RepositoryRoot 'scripts/windows/virtualization/Atlaso.VirtualizationRelease.psm1'), [ref]$null, [ref]$null)
$stageChecks = @($releaseAst.FindAll({
    param($Node)
    $Node -is [Management.Automation.Language.CommandAst] -and
    $Node.GetCommandName() -eq 'Assert-AtlasoVirtualizationStoragePlan'
}, $true))
$stages = @()
foreach ($check in $stageChecks) {
    $arguments = @{}
    for ($i = 1; $i -lt $check.CommandElements.Count - 1; $i++) {
        $element = $check.CommandElements[$i]
        if ($element -is [Management.Automation.Language.CommandParameterAst] -and
            $element.ParameterName -in @('Stage','ThroughStage')) {
            $arguments[$element.ParameterName] = $check.CommandElements[$i+1].SafeGetValue()
        }
    }
    if ($arguments.Stage -ne $arguments.ThroughStage) { throw 'A stage crosses an unmeasured evidence boundary.' }
    $stages += $arguments.Stage
}
if (($stages -join ',') -cne '0,1,2,3,4,5,6') { throw 'A required admission boundary is absent or reordered.' }

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
