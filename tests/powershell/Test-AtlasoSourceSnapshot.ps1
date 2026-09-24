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
Import-Module (
    Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationCleanup.psm1'
) -Force

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$mutableDiskPath = Join-Path $OutputDirectory 'mutable-peer-disk.vmdk'
[IO.File]::WriteAllText($mutableDiskPath, 'preboot disk')
$mutableDiskIdentity = [Atlaso.WorkstationFileIdentity]::Get($mutableDiskPath)
$mutableDiskPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryMutableFile($mutableDiskPath)
try {
    [IO.File]::AppendAllText($mutableDiskPath, ' guest write')
    if ([Atlaso.WorkstationFileIdentity]::Get($mutableDiskPath) -cne $mutableDiskIdentity) {
        throw 'Guest-writable disk identity changed while pinned.'
    }
    $replacementPath = Join-Path $OutputDirectory 'replacement.vmdk'
    $replacementRejected = $false
    try { [IO.File]::Move($mutableDiskPath, $replacementPath) }
    catch [IO.IOException] { $replacementRejected = $true }
    if (-not $replacementRejected) { throw 'A pinned guest-writable disk was replaceable.' }
} finally {
    $mutableDiskPin.Dispose()
}
$proofRoot = Join-Path $OutputDirectory 'certificate-proof-pins'
New-Item -ItemType Directory -Path $proofRoot | Out-Null
$receiptPath = Join-Path $proofRoot 'original.json'
$segmentPath = Join-Path $proofRoot 'segment.json'
$fixturePath = Join-Path $proofRoot 'fixture.json'
$planPath = Join-Path $proofRoot 'proof-plan.json'
$caPath = Join-Path $proofRoot 'trusted-ca.pem'
[IO.File]::WriteAllText($caPath, 'test trust anchor')
[IO.File]::WriteAllText($receiptPath, '{"schema":1}')
[IO.File]::WriteAllText($segmentPath, '{"schema":1}')
$segmentSha = (Get-FileHash -LiteralPath $segmentPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($fixturePath, (@{
    lan_segment_receipt = $segmentPath; lan_segment_receipt_sha256 = $segmentSha
} | ConvertTo-Json -Compress))
$fixtureSha = (Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash.ToLowerInvariant()
$receiptSha = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText($planPath, (@{
    ca_path = $caPath
    peer_fixture = @{ path = $fixturePath; sha256 = $fixtureSha }
    predeployment_evidence = @{ path = $receiptPath; sha256 = $receiptSha }
} | ConvertTo-Json -Compress -Depth 4))
$proofPins = @(Protect-AtlasoCertificateProofInputs -Plan $planPath -EvidenceRoot $OutputDirectory)
try {
    foreach ($inputPath in @($planPath, $fixturePath, $receiptPath, $segmentPath, $caPath)) {
        $blocked = $false
        try {
            $write = [IO.File]::Open($inputPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
            $write.Dispose()
        } catch [IO.IOException] {
            $blocked = $true
        }
        if (-not $blocked) { throw 'Credentialed certificate proof input was writable while pinned.' }
    }
} finally {
    foreach ($pin in $proofPins) { $pin.Dispose() }
}
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

$pinRoot = Join-Path $OutputDirectory 'certificate-inspector-pin-fixture'
$scriptsRoot = Join-Path $pinRoot 'scripts'
New-Item -ItemType Directory -Path $scriptsRoot | Out-Null
$packagePath = Join-Path $scriptsRoot '__init__.py'
$ownerPath = Join-Path $scriptsRoot 'completed_task_files.py'
[IO.File]::WriteAllText($packagePath, 'admitted package')
[IO.File]::WriteAllText($ownerPath, 'admitted ownership module')
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
$directoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($scriptsRoot)
$packagePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($packagePath, $true)
$ownerPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($ownerPath, $true)
try {
    foreach ($path in @($packagePath, $ownerPath)) {
        $blocked = $false
        try { [IO.File]::WriteAllText($path, 'replacement') }
        catch [IO.IOException] { $blocked = $true }
        catch [UnauthorizedAccessException] { $blocked = $true }
        if (-not $blocked) { throw 'A pinned certificate dependency was replaced.' }
    }
}
finally {
    $ownerPin.Dispose()
    $packagePin.Dispose()
    $directoryPin.Dispose()
}

$runtimeFixture = Join-Path $OutputDirectory 'certificate-python-pin-fixture'
$venv = Join-Path $runtimeFixture 'venv'
$base = Join-Path $runtimeFixture 'base'
$python = Join-Path $venv 'Scripts/python.exe'
$dependency = Join-Path $venv 'Lib/site-packages/paramiko/__init__.py'
$baseLib = Join-Path $base 'Lib'
foreach ($directory in @((Split-Path $python), (Split-Path $dependency), $baseLib)) {
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
}
[IO.File]::WriteAllText($python, 'synthetic executable')
[IO.File]::WriteAllText($dependency, 'synthetic pinned import')
[IO.File]::WriteAllText((Join-Path $venv 'pyvenv.cfg'),
    "home = $base`ninclude-system-site-packages = false`n")
foreach ($number in 1..100) {
    [IO.File]::WriteAllText((Join-Path $baseLib "module$number.py"), 'synthetic stdlib import')
}
$runtime = Protect-AtlasoCertificatePythonRuntime -PythonPath $python -EvidenceRoot $OutputDirectory
try {
    $proofArguments = New-AtlasoCertificatePythonArguments -Runtime $runtime -ScriptPath $dependency `
        -ScriptArguments @('--help')
    if ((@($proofArguments[0..2]) -join ' ') -cne '-I -S -B' -or
        $proofArguments[-1] -cne '--help') {
        throw 'Certificate proof child could execute Python startup hooks.'
    }
    foreach ($path in @($python, $dependency, (Join-Path $baseLib 'module1.py'))) {
        $blocked = $false
        try { [IO.File]::WriteAllText($path, 'replaced') }
        catch [IO.IOException] { $blocked = $true }
        catch [UnauthorizedAccessException] { $blocked = $true }
        if (-not $blocked) { throw 'A pinned certificate Python dependency was replaced.' }
    }
}
finally {
    foreach ($pin in $runtime.Pins) { $pin.Dispose() }
}
$startupPath = Join-Path $venv 'Lib/site-packages/injected.pth'
[IO.File]::WriteAllText($startupPath, 'import injected')
try {
    $null = Protect-AtlasoCertificatePythonRuntime -PythonPath $python -EvidenceRoot $OutputDirectory
    throw 'A Python startup import was admitted.'
}
catch {
    if ($_.Exception.Message -notlike '*startup imports are not isolated*') { throw }
}

Write-Output 'Atlaso immutable source snapshot tests passed.'
