<#
.SYNOPSIS
Remove one exact pull-request-owned VMware Workstation lifecycle lab.

.PARAMETER PullRequestNumber
Exact positive GitHub pull-request number recorded by the lifecycle run.

.PARAMETER Purpose
Short lifecycle purpose used to derive the canonical lab identity.

.PARAMETER CollisionSuffix
Exact collision suffix reported by the lifecycle run being removed.

.PARAMETER VmrunPath
Optional exact path to the VMware vmrun executable.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 2147483647)]
    [int]$PullRequestNumber,
    [string]$Purpose = 'lifecycle',
    [Parameter(Mandatory = $true)]
    [string]$CollisionSuffix,
    [string]$VmrunPath = ''
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force

<#
.SYNOPSIS
Resolve vmrun from an exact override or supported Workstation installation.

.PARAMETER Path
Optional vmrun executable path supplied by the caller.
#>
function Resolve-VmrunPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "vmrun.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$lifecycleRoot = Join-Path $repoRoot 'test-results\vmware-workstation-lifecycle'
$vmIdentity = New-AtlasoVmwareTestIdentity `
    -PullRequestNumber $PullRequestNumber `
    -Purpose $Purpose `
    -CollisionSuffix $CollisionSuffix
$LabName = $vmIdentity.Name
$labRoot = Assert-AtlasoVmwareIdentityDirectory `
    -Path (Join-Path $lifecycleRoot $LabName) `
    -ExpectedName $LabName `
    -ParameterName 'LifecycleLabDirectory'

if (-not (Test-Path -LiteralPath $labRoot -PathType Container)) {
    Write-Host "No exact PR-owned Workstation lifecycle lab found: $labRoot"
    return
}

$resolvedLifecycleRoot = (Resolve-Path -LiteralPath $lifecycleRoot).Path
$resolvedLabRoot = (Resolve-Path -LiteralPath $labRoot).Path
Assert-AtlasoStrictDescendantPath `
    -ParentPath $resolvedLifecycleRoot `
    -ChildPath $resolvedLabRoot `
    -FailureMessage 'Refusing to remove lifecycle lab outside Workstation lifecycle results'
$planPath = Join-Path $resolvedLabRoot 'plan.json'
if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) {
    throw "Refusing lifecycle cleanup because the exact PR-owned plan is missing: $planPath"
}
$plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if (
    [string]$plan.lab_name -cne $LabName -or
    [int]$plan.pull_request_number -ne $PullRequestNumber -or
    [string]$plan.purpose -cne $vmIdentity.Purpose -or
    [string]$plan.collision_suffix -cne $vmIdentity.CollisionSuffix
) {
    throw "Refusing lifecycle cleanup because plan ownership does not match '$LabName': $planPath"
}
$vmRoot = Join-Path $resolvedLabRoot 'vms'
if (-not (Test-Path -LiteralPath $vmRoot -PathType Container)) {
    Write-Host "No retained VMware VM directory exists for the exact PR-owned lab: $vmRoot"
    return
}
$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
$expectedDisplayNames = @(
    "$LabName-Appliance",
    "$LabName-ClientA",
    "$LabName-ClientB",
    "$LabName-ESXiPXE"
)
$candidates = @(
    Get-ChildItem -LiteralPath $vmRoot -Recurse -Filter '*.vmx' -File |
        ForEach-Object {
            $resolvedPath = $_.FullName
            $displayName = Get-AtlasoVmxDisplayName -Path $resolvedPath
            if ($expectedDisplayNames -cnotcontains $displayName) {
                throw "Refusing lifecycle cleanup because VMX displayName is not owned by the exact lab '$LabName': $resolvedPath"
            }
            Assert-AtlasoVmwareOwnedVmx `
                -VmxPath $resolvedPath `
                -ExpectedDirectory $_.DirectoryName `
                -ExpectedName $displayName | Out-Null
            [pscustomobject]@{
                Path        = $resolvedPath
                DisplayName = $displayName
                Directory   = $_.DirectoryName
            }
        } |
        Sort-Object -Property Directory, DisplayName -Unique
)

if (-not $candidates) {
    Write-Host "No Workstation lifecycle VMs found for exact PR-owned lab: $LabName"
    return
}

foreach ($candidateGroup in $candidates | Group-Object -Property Directory) {
    $groupCandidates = @($candidateGroup.Group | Sort-Object -Property DisplayName)
    foreach ($candidate in $groupCandidates) {
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $vmRoot `
            -ChildPath $candidate.Path `
            -FailureMessage 'Refusing to remove VM outside Workstation lifecycle results'
    }

    if ($PSCmdlet.ShouldProcess($candidateGroup.Name, 'Stop and delete VMware Workstation lifecycle artifacts')) {
        Remove-AtlasoWorkstationVmArtifacts `
            -VmrunPath $resolvedVmrun `
            -VmxPaths @($groupCandidates.Path) `
            -RemovalRoot $candidateGroup.Name `
            -Confirm:$false
        Write-Host "Removed Workstation lifecycle VM directory: $($candidateGroup.Name)"
    }
}
