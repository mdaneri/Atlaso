<#
.SYNOPSIS
Validate canonical task and release VMware Photon builder identities.
.PARAMETER RepositoryRoot
Atlaso repository root containing the identity module.
.PARAMETER OutputDirectory
Isolated test directory for ownership manifests and VMX fixtures.
#>
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (
    Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.VmwareBuilderIdentity.psm1'
) -Force

$commit = 'a' * 40
$task = New-AtlasoVmwareBuilderIdentity `
    -PullRequestNumber 653 `
    -CollisionSuffix 'Run 02' `
    -Repository 'mdaneri/Atlaso' `
    -SourceBranch 'enhancement/653-pr-photon-builder-identity' `
    -SourceCommit $commit
if ($task.Name -cne 'Atlaso-PR-653-Photon-Builder-VMware-run-02' -or
    $task.Kind -cne 'pull_request' -or $task.PullRequestNumber -ne 653) {
    throw 'Task-owned Photon builder identity was not canonical.'
}

foreach ($branchName in @('feature/foo+bar', 'feature/fix@two', 'feature/foo=bar')) {
    $validBranch = New-AtlasoVmwareBuilderIdentity `
        -PullRequestNumber 653 `
        -Repository 'mdaneri/Atlaso' `
        -SourceBranch $branchName `
        -SourceCommit $commit
    if ($validBranch.SourceBranch -cne $branchName) {
        throw "Valid Git branch name was not preserved: $branchName"
    }
}
try {
    $null = New-AtlasoVmwareBuilderIdentity `
        -PullRequestNumber 653 `
        -Repository 'mdaneri/Atlaso' `
        -SourceBranch 'feature/bad..branch' `
        -SourceCommit $commit
    throw 'An invalid Git branch name was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'An invalid Git branch name was accepted.') { throw }
}

$release = New-AtlasoVmwareBuilderIdentity `
    -ReleaseVersion '0.9.250' `
    -SourceCommit $commit `
    -WorkflowRunId 12345
if ($release.Name -cne 'Atlaso-Release-v0-9-250-aaaaaaaaaaaa-Photon-Builder-VMware-run-12345' -or
    $release.Kind -cne 'release') {
    throw 'Release-owned Photon builder identity was not canonical.'
}

$releaseOutput = Join-Path (Join-Path $OutputDirectory 'release-parent') $release.Name
$releaseManifest = Get-AtlasoVmwareBuilderIdentityManifestPath -OutputDirectory $releaseOutput
Write-AtlasoVmwareBuilderIdentityManifest `
    -Path $releaseManifest `
    -OutputDirectory $releaseOutput `
    -Identity $release
$nextRelease = New-AtlasoVmwareBuilderIdentity `
    -ReleaseVersion '0.9.250' `
    -SourceCommit (('a' * 12) + ('b' * 28)) `
    -WorkflowRunId 12345
try {
    Write-AtlasoVmwareBuilderIdentityManifest `
        -Path $releaseManifest `
        -OutputDirectory $releaseOutput `
        -Identity $nextRelease `
        -ReplaceSameOwner
    throw 'A release manifest advanced to a different full source commit.'
}
catch {
    if ($_.Exception.Message -eq 'A release manifest advanced to a different full source commit.') { throw }
}

foreach ($invalid in @(0, -1)) {
    try {
        $null = New-AtlasoVmwareBuilderIdentity `
            -PullRequestNumber $invalid `
            -Repository 'mdaneri/Atlaso' `
            -SourceBranch 'enhancement/invalid' `
            -SourceCommit $commit
        throw "Invalid pull-request number $invalid was accepted."
    }
    catch {
        if ($_.Exception.Message -like 'Invalid pull-request number*was accepted.') { throw }
    }
}

$taskOutput = Join-Path (Join-Path $OutputDirectory 'fresh-parent') $task.Name
$manifestPath = Get-AtlasoVmwareBuilderIdentityManifestPath -OutputDirectory $taskOutput
Write-AtlasoVmwareBuilderIdentityManifest `
    -Path $manifestPath `
    -OutputDirectory $taskOutput `
    -Identity $task
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Builder identity manifest writer did not create the verified fresh output parent.'
}
$null = Assert-AtlasoVmwareBuilderIdentityManifest `
    -Path $manifestPath `
    -OutputDirectory $taskOutput `
    -Identity $task
$casedTaskOutput = Join-Path (Split-Path -Parent $taskOutput).ToUpperInvariant() $task.Name
if ($casedTaskOutput -ceq $taskOutput) {
    throw 'The ownership-manifest casing regression fixture did not change the output path spelling.'
}
$null = Assert-AtlasoVmwareBuilderIdentityManifest `
    -Path $manifestPath `
    -OutputDirectory $casedTaskOutput `
    -Identity $task

$nextTask = New-AtlasoVmwareBuilderIdentity `
    -PullRequestNumber 653 `
    -CollisionSuffix 'Run 02' `
    -Repository 'mdaneri/Atlaso' `
    -SourceBranch 'enhancement/653-pr-photon-builder-identity' `
    -SourceCommit ('b' * 40)
$null = Assert-AtlasoVmwareBuilderOwnershipManifest `
    -Path $manifestPath `
    -OutputDirectory $taskOutput `
    -Identity $nextTask
try {
    $null = Assert-AtlasoVmwareBuilderIdentityManifest `
        -Path $manifestPath `
        -OutputDirectory $taskOutput `
        -Identity $nextTask
    throw 'A same-owner manifest was accepted for retained reuse at a different commit.'
}
catch {
    if ($_.Exception.Message -eq 'A same-owner manifest was accepted for retained reuse at a different commit.') {
        throw
    }
}
Write-AtlasoVmwareBuilderIdentityManifest `
    -Path $manifestPath `
    -OutputDirectory $taskOutput `
    -Identity $nextTask `
    -ReplaceSameOwner
$null = Assert-AtlasoVmwareBuilderIdentityManifest `
    -Path $manifestPath `
    -OutputDirectory $taskOutput `
    -Identity $nextTask

$differentRepository = New-AtlasoVmwareBuilderIdentity `
    -PullRequestNumber 653 `
    -CollisionSuffix 'Run 02' `
    -Repository 'other/Atlaso' `
    -SourceBranch 'enhancement/653-pr-photon-builder-identity' `
    -SourceCommit ('c' * 40)
try {
    $null = Assert-AtlasoVmwareBuilderOwnershipManifest `
        -Path $manifestPath `
        -OutputDirectory $taskOutput `
        -Identity $differentRepository
    throw 'A differently owned repository manifest was accepted for replacement.'
}
catch {
    if ($_.Exception.Message -eq 'A differently owned repository manifest was accepted for replacement.') { throw }
}

try {
    $null = Assert-AtlasoVmwareBuilderIdentityManifest `
        -Path $manifestPath `
        -OutputDirectory $taskOutput `
        -Identity (New-AtlasoVmwareBuilderIdentity `
            -PullRequestNumber 654 `
            -Repository 'mdaneri/Atlaso' `
            -SourceBranch 'enhancement/654-other' `
            -SourceCommit $commit)
    throw 'A differently owned builder manifest was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'A differently owned builder manifest was accepted.') { throw }
}

try {
    $null = Assert-AtlasoVmwareBuilderOutputDirectory `
        -OutputDirectory (Join-Path $OutputDirectory 'Atlaso-Photon-Builder-VMware') `
        -Identity $task
    throw 'The legacy generic builder output was accepted.'
}
catch {
    if ($_.Exception.Message -eq 'The legacy generic builder output was accepted.') { throw }
}

New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
$vmxPath = Join-Path $taskOutput "$($task.Name).vmx"
[System.IO.File]::WriteAllText(
    $vmxPath,
    "displayName = `"$($task.Name)`"`n",
    [System.Text.UTF8Encoding]::new($false)
)
$null = Assert-AtlasoVmwareBuilderVmx `
    -VmxPath $vmxPath `
    -OutputDirectory $taskOutput `
    -Identity $task

[System.IO.File]::WriteAllText(
    $vmxPath,
    "displayName = `"Atlaso-Photon-Builder-VMware`"`n",
    [System.Text.UTF8Encoding]::new($false)
)
try {
    $null = Assert-AtlasoVmwareBuilderVmx `
        -VmxPath $vmxPath `
        -OutputDirectory $taskOutput `
        -Identity $task
    throw 'A generic displayName was accepted for a PR-owned builder.'
}
catch {
    if ($_.Exception.Message -eq 'A generic displayName was accepted for a PR-owned builder.') { throw }
}

Write-Output 'Atlaso VMware builder identity tests passed.'
