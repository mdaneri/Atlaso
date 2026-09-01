<#
.SYNOPSIS
Verify commit-derived VMware source snapshot admission and race resistance.
.PARAMETER RepositoryRoot
Atlaso repository root containing the source snapshot module.
.PARAMETER OutputDirectory
Fresh isolated test directory.
#>
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (
    Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.SourceSnapshot.psm1'
) -Force

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$sourceRepository = Join-Path $OutputDirectory 'source-repository'
$firstStaging = Join-Path $OutputDirectory 'first-staging'
New-Item -ItemType Directory -Path $sourceRepository, $firstStaging | Out-Null
& git -C $sourceRepository init --initial-branch=main | Out-Null
& git -C $sourceRepository config user.name 'Atlaso Snapshot Test'
& git -C $sourceRepository config user.email 'snapshot-test@example.invalid'
$trackedPath = Join-Path $sourceRepository 'tracked.txt'
[System.IO.File]::WriteAllText(
    $trackedPath,
    "admitted content`n",
    [System.Text.UTF8Encoding]::new($false)
)
& git -C $sourceRepository add tracked.txt
& git -C $sourceRepository commit -m 'admitted source' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Could not create the admitted source fixture commit.'
}
$admittedCommit = (& git -C $sourceRepository rev-parse HEAD).Trim()
$attachedIdentity = Get-AtlasoSourceCheckoutIdentity -RepositoryRoot $sourceRepository
if ($attachedIdentity.Commit -cne $admittedCommit -or
    $attachedIdentity.Branch -cne 'main' -or
    $attachedIdentity.Detached) {
    throw 'The attached source checkout identity was not admitted exactly.'
}
$snapshot = New-AtlasoImmutableSourceSnapshot `
    -RepositoryRoot $sourceRepository `
    -StagingRoot $firstStaging
if ($snapshot.Commit -cne $admittedCommit -or
    (Get-Content -LiteralPath (Join-Path $snapshot.Root 'tracked.txt') -Raw) -cne "admitted content`n") {
    throw 'The source snapshot did not reproduce the admitted commit.'
}
$null = Assert-AtlasoSourceSnapshotCommitBinding `
    -Root $snapshot.Root `
    -RepositoryRoot $sourceRepository `
    -Commit $admittedCommit `
    -ExpectedSha256 $snapshot.Sha256 `
    -ExpectedFileCount $snapshot.FileCount `
    -VerificationRoot (Join-Path $OutputDirectory 'first-commit-verification')
$null = Protect-AtlasoSourceSnapshot `
    -Root $snapshot.Root `
    -ExpectedSha256 $snapshot.Sha256 `
    -ExpectedFileCount $snapshot.FileCount
$snapshotWriteWasRejected = $false
try {
    [System.IO.File]::WriteAllText(
        (Join-Path $snapshot.Root 'tracked.txt'),
        "race content`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}
catch [System.UnauthorizedAccessException] {
    $snapshotWriteWasRejected = $true
}
if (-not $snapshotWriteWasRejected) {
    throw 'The protected source snapshot admitted a concurrent file mutation.'
}
$snapshotAdditionWasRejected = $false
try {
    [System.IO.File]::WriteAllText(
        (Join-Path $snapshot.Root 'injected.pkr.hcl'),
        "packer {}`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}
catch [System.UnauthorizedAccessException] {
    $snapshotAdditionWasRejected = $true
}
if (-not $snapshotAdditionWasRejected) {
    throw 'The protected source snapshot admitted a concurrent file injection.'
}

# Simulate an operator moving HEAD and changing tracked bytes while the long
# Packer phase consumes the already-admitted staging tree.
[System.IO.File]::WriteAllText(
    $trackedPath,
    "later checkout content`n",
    [System.Text.UTF8Encoding]::new($false)
)
& git -C $sourceRepository add tracked.txt
& git -C $sourceRepository commit -m 'later checkout state' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Could not create the simulated during-Packer checkout change.'
}
if ((& git -C $sourceRepository rev-parse HEAD).Trim() -ceq $admittedCommit) {
    throw 'The simulated during-Packer checkout change did not move HEAD.'
}
$null = Assert-AtlasoSourceSnapshot `
    -Root $snapshot.Root `
    -ExpectedSha256 $snapshot.Sha256 `
    -ExpectedFileCount $snapshot.FileCount
if ((Get-Content -LiteralPath (Join-Path $snapshot.Root 'tracked.txt') -Raw) -cne "admitted content`n") {
    throw 'A later checkout change altered the admitted source snapshot.'
}
Unprotect-AtlasoSourceSnapshot -Root $snapshot.Root

$laterCommit = (& git -C $sourceRepository rev-parse HEAD).Trim()
& git -C $sourceRepository checkout --detach $laterCommit 2>$null
if ($LASTEXITCODE -ne 0) {
    throw 'Could not create the detached source checkout fixture.'
}
$detachedIdentity = Get-AtlasoSourceCheckoutIdentity -RepositoryRoot $sourceRepository
if ($detachedIdentity.Commit -cne $laterCommit -or
    $detachedIdentity.Branch -cne "detached/$laterCommit" -or
    -not $detachedIdentity.Detached) {
    throw 'The detached source checkout identity was not admitted exactly.'
}
& git -C $sourceRepository checkout main 2>$null
if ($LASTEXITCODE -ne 0) {
    throw 'Could not restore the attached source checkout fixture.'
}

[System.IO.File]::WriteAllText(
    (Join-Path $snapshot.Root 'tracked.txt'),
    "tampered staged content`n",
    [System.Text.UTF8Encoding]::new($false)
)
try {
    $null = Assert-AtlasoSourceSnapshot `
        -Root $snapshot.Root `
        -ExpectedSha256 $snapshot.Sha256 `
        -ExpectedFileCount $snapshot.FileCount
    throw 'A changed staged source snapshot was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*no longer matches its admitted byte inventory*') {
        throw
    }
}
$tamperedInventory = Get-AtlasoSourceSnapshotInventory -Root $snapshot.Root
try {
    $null = Assert-AtlasoSourceSnapshotCommitBinding `
        -Root $snapshot.Root `
        -RepositoryRoot $sourceRepository `
        -Commit $admittedCommit `
        -ExpectedSha256 $tamperedInventory.Sha256 `
        -ExpectedFileCount $tamperedInventory.FileCount `
        -VerificationRoot (Join-Path $OutputDirectory 'tampered-commit-verification')
    throw 'A self-consistent but commit-mismatched source snapshot was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*does not match the admitted Git commit*') {
        throw
    }
}

$dirtyStaging = Join-Path $OutputDirectory 'dirty-staging'
New-Item -ItemType Directory -Path $dirtyStaging | Out-Null
[System.IO.File]::AppendAllText($trackedPath, "dirty`n")
try {
    $null = New-AtlasoImmutableSourceSnapshot `
        -RepositoryRoot $sourceRepository `
        -StagingRoot $dirtyStaging
    throw 'A tracked-dirty source working tree was admitted.'
}
catch {
    if ($_.Exception.Message -notlike '*must be completely clean before snapshot admission*') {
        throw
    }
}
& git -C $sourceRepository restore tracked.txt

$untrackedStaging = Join-Path $OutputDirectory 'untracked-staging'
New-Item -ItemType Directory -Path $untrackedStaging | Out-Null
[System.IO.File]::WriteAllText((Join-Path $sourceRepository 'untracked.txt'), 'untracked')
try {
    $null = New-AtlasoImmutableSourceSnapshot `
        -RepositoryRoot $sourceRepository `
        -StagingRoot $untrackedStaging
    throw 'An untracked source input was admitted.'
}
catch {
    if ($_.Exception.Message -notlike '*must be completely clean before snapshot admission*') {
        throw
    }
}

Write-Output 'Atlaso immutable source snapshot tests passed.'
