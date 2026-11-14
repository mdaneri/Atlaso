<#
.SYNOPSIS
Move the original stopped OVA management NIC to its peer's registered private LAN.
.DESCRIPTION
Run with fresh host admission from the trusted-host certificate procedure. The
original OVA, peer and LAN receipts must already exist.
.PARAMETER Plan
Absolute path to the public trusted-host plan beneath the task checkout's test-results directory.
.PARAMETER PlanSha256
Independently recorded SHA-256 of the original plan.
.PARAMETER SourceCommit
Exact reviewed commit of the task checkout.
.PARAMETER SourceBranch
Exact checked-out task branch.
.PARAMETER PullRequestNumber
Pull request that owns the original OVA.
.PARAMETER Name
Canonical name of the original imported OVA.
.PARAMETER VmrunSha256
Independently recorded SHA-256 of the plan's admitted VMware executable.
.PARAMETER PythonPath
Absolute path to the admitted Python interpreter.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$PlanSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$SourceBranch,
    [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{1,79}$')][string]$Name,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$VmrunSha256,
    [Parameter(Mandatory)][string]$PythonPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1')
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationLanSegments.ps1')

$worktree = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$output = Join-Path $worktree "test-results/$Name"
$vmx = Join-Path $output "$Name.vmx"
$selectors = @{
    Worktree = $worktree
    OutputDirectory = $output
    VmxPath = $vmx
    Name = $Name
    SourceCommit = $SourceCommit
    SourceBranch = $SourceBranch
    PullRequestNumber = $PullRequestNumber
}
$context = New-AtlasoTestVmOwnershipContext @selectors
if (-not $context.Enabled -or -not $context.ActiveTaskId) {
    throw 'An active Codex task must own the OVA transition.'
}

$pins = [Collections.Generic.List[IDisposable]]::new()
try {
    Assert-AtlasoTestVmCheckoutSource -Context $context
    foreach ($path in @($Plan, $PythonPath)) {
        if (-not [IO.Path]::IsPathFullyQualified($path) -or [IO.Path]::GetFullPath($path) -cne $path) {
            throw 'The OVA transition requires canonical absolute input paths.'
        }
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($path), $true))
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true))
    }
    if (-not $PSCmdlet.ShouldProcess($vmx, 'Move the original OVA management NIC to the certificate LAN')) { return }

    Assert-AtlasoLanSegmentUiClosed
    $entryPoint = @'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from scripts.interop.certificate_ova_identity import _run_owned_ova_transition

repository, plan, digest, vmx, task, pr, commit, evidence, identity, vmrun = sys.argv[1:]
_run_owned_ova_transition(Path(plan), digest, Path(repository), Path(vmx), task, int(pr), commit,
                          Path(evidence), identity, vmrun)
'@
    $arguments = @('-I', '-S', '-B', '-c', $entryPoint, $worktree, $Plan, $PlanSha256, $vmx,
        $context.TaskId, [string]$PullRequestNumber, $SourceCommit, $context.EvidenceDirectory,
        $context.EvidenceDirectoryId, $VmrunSha256)
    $launch = @{
        FilePath = $PythonPath
        ArgumentList = $arguments
        TimeoutSeconds = 180
        Action = 'Original OVA private LAN transition'
        ClearEnvironmentVariablePrefixes = @('PYTHON', 'ATLASO_NATIVE_', 'OP_', 'ONEPASSWORD_', 'GIT_')
    }
    Invoke-AtlasoBoundedProcess @launch
}
finally {
    for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Dispose() }
    if ($context.PSObject.Properties['CheckoutSourcePin']) { $context.CheckoutSourcePin.Dispose() }
}
