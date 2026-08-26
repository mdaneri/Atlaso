<#
.SYNOPSIS
Validates bounded VMware OVF output-directory replacement behavior.

.PARAMETER RepositoryRoot
The Atlaso repository root containing the module under test.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.OvfExport.psm1'
Import-Module $modulePath -Force

<#
.SYNOPSIS
Asserts that an action terminates with the expected message pattern.

.PARAMETER Action
The PowerShell action expected to terminate.

.PARAMETER Pattern
The wildcard pattern required in the terminating error message.
#>
function Assert-ThrowsLike {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike $Pattern) {
            throw "Expected error like '$Pattern', got: $($_.Exception.Message)"
        }
        return
    }
    throw "Expected error like '$Pattern', but the command succeeded."
}

<#
.SYNOPSIS
Creates a test directory containing a retention marker.

.PARAMETER Path
The exact test directory to create.
#>
function New-MarkerDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    Set-Content -LiteralPath (Join-Path $Path 'retain.marker') -Value 'retain' -NoNewline
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-ovf-export-$([guid]::NewGuid().ToString('N'))"
try {
    $fakeRepo = Join-Path $testRoot 'repository'
    $approvedRoot = Join-Path $fakeRepo 'image\vmware-workstation\ovf'
    New-Item -ItemType Directory -Force -Path $approvedRoot | Out-Null

    $canonicalPlan = Resolve-AtlasoOvfOutputPlan `
        -RepoRoot $fakeRepo `
        -OutputDirectory '' `
        -Name 'Atlaso-Photon'
    New-MarkerDirectory -Path $canonicalPlan.OutputDirectory
    Assert-ThrowsLike -Action {
        Clear-AtlasoOvfOutputDirectory -OutputPlan $canonicalPlan
    } -Pattern '*Pass -Force to replace it*'
    Clear-AtlasoOvfOutputDirectory -OutputPlan $canonicalPlan -Force

    New-MarkerDirectory -Path $canonicalPlan.OutputDirectory
    $explicitCanonicalPlan = Resolve-AtlasoOvfOutputPlan `
        -RepoRoot $fakeRepo `
        -OutputDirectory $canonicalPlan.OutputDirectory `
        -Name 'Atlaso-Photon' `
        -CallerSpecifiedOutputDirectory
    Assert-ThrowsLike -Action {
        Clear-AtlasoOvfOutputDirectory -OutputPlan $explicitCanonicalPlan
    } -Pattern '*Pass -Force to replace it*'
    if (-not (Test-Path -LiteralPath (Join-Path $explicitCanonicalPlan.OutputDirectory 'retain.marker'))) {
        throw 'Release mode removed an explicitly supplied canonical output directory without -Force.'
    }

    $alternatePath = Join-Path $approvedRoot 'alternate'
    New-MarkerDirectory -Path $alternatePath
    $alternatePlan = Resolve-AtlasoOvfOutputPlan `
        -RepoRoot $fakeRepo `
        -OutputDirectory $alternatePath `
        -Name 'Atlaso-Photon' `
        -CallerSpecifiedOutputDirectory
    Assert-ThrowsLike -Action {
        Clear-AtlasoOvfOutputDirectory -OutputPlan $alternatePlan
    } -Pattern '*Pass -Force to replace it*'
    if (-not (Test-Path -LiteralPath (Join-Path $alternatePath 'retain.marker'))) {
        throw 'Release mode removed an alternate output directory without -Force.'
    }
    Clear-AtlasoOvfOutputDirectory -OutputPlan $alternatePlan -Force
    if (Test-Path -LiteralPath $alternatePath) {
        throw '-Force did not replace an approved alternate OVF output directory.'
    }

    $externalPath = Join-Path $testRoot 'unrelated'
    New-MarkerDirectory -Path $externalPath
    $externalPlan = Resolve-AtlasoOvfOutputPlan `
        -RepoRoot $fakeRepo `
        -OutputDirectory $externalPath `
        -Name 'Atlaso-Photon' `
        -CallerSpecifiedOutputDirectory
    Assert-ThrowsLike -Action {
        Clear-AtlasoOvfOutputDirectory -OutputPlan $externalPlan -Force
    } -Pattern '*outside the approved root*'
    if (-not (Test-Path -LiteralPath (Join-Path $externalPath 'retain.marker'))) {
        throw 'An unrelated directory was changed while testing refusal.'
    }

    $escapedPlan = Resolve-AtlasoOvfOutputPlan `
        -RepoRoot $fakeRepo `
        -OutputDirectory '' `
        -Name '..\..\escaped-release'
    New-MarkerDirectory -Path $escapedPlan.OutputDirectory
    Assert-ThrowsLike -Action {
        Clear-AtlasoOvfOutputDirectory -OutputPlan $escapedPlan -Force
    } -Pattern '*outside the approved root*'
    if (-not (Test-Path -LiteralPath (Join-Path $escapedPlan.OutputDirectory 'retain.marker'))) {
        throw 'A traversal-shaped release name escaped the approved output boundary.'
    }

    foreach ($protectedPath in @(
            $fakeRepo,
            (Join-Path $fakeRepo 'image'),
            (Join-Path $fakeRepo 'image\vmware-workstation'),
            $approvedRoot
        )) {
        Assert-ThrowsLike -Action {
            Assert-AtlasoOvfRemovalTarget `
                -RepoRoot $fakeRepo `
                -ApprovedOutputRoot $approvedRoot `
                -OutputDirectory $protectedPath | Out-Null
        } -Pattern '*protected Atlaso path*'
    }

    $filesystemRoot = [System.IO.Path]::GetPathRoot($testRoot)
    Assert-ThrowsLike -Action {
        Assert-AtlasoOvfRemovalTarget `
            -RepoRoot $fakeRepo `
            -ApprovedOutputRoot $approvedRoot `
            -OutputDirectory $filesystemRoot | Out-Null
    } -Pattern '*filesystem root*'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

Write-Output 'Atlaso OVF export output-safety tests passed.'
