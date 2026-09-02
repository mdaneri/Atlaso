<#
.SYNOPSIS
Verify Photon image build-state roots remain beneath the exact task repository.
.PARAMETER RepositoryRoot
Atlaso repository root containing the supported Photon build wrapper.
#>
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
Import-Module (
    Join-Path $resolvedRepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationCleanup.psm1'
) -Force
. (Join-Path $resolvedRepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')
Import-Module (
    Join-Path $resolvedRepositoryRoot 'scripts\windows\vmware\Atlaso.SourceSnapshot.psm1'
) -Force
$wrapperPath = Join-Path $resolvedRepositoryRoot 'scripts\windows\vmware\build-photon-image.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $wrapperPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "Photon build wrapper parse failed: $($parseErrors[0].Message)"
}
$resolver = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Resolve-AtlasoPhotonBuildStateRoot'
        },
        $true
    )
)
if ($resolver.Count -ne 1) {
    throw 'Expected exactly one Photon build-state resolver.'
}
. ([scriptblock]::Create($resolver[0].Extent.Text))
$legacyRecovery = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-AtlasoLegacyBuilderAddressHandoffRecovery'
        },
        $true
    )
)
if ($legacyRecovery.Count -ne 1) {
    throw 'Expected exactly one legacy builder-address recovery function.'
}
. ([scriptblock]::Create($legacyRecovery[0].Extent.Text))
$cleanupFunction = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Complete-AtlasoPhotonBuildCleanup'
        },
        $true
    )
)
if ($cleanupFunction.Count -ne 1) {
    throw 'Expected exactly one Photon cleanup completion function.'
}
. ([scriptblock]::Create($cleanupFunction[0].Extent.Text))
$cleanupRecoveryFunction = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-AtlasoPhotonBuildCleanupRecovery'
        },
        $true
    )
)
if ($cleanupRecoveryFunction.Count -ne 1) {
    throw 'Expected exactly one Photon cleanup recovery function.'
}
. ([scriptblock]::Create($cleanupRecoveryFunction[0].Extent.Text))
$sameBootProcessRecoveryFunction = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Complete-AtlasoPhotonSameBootProcessRecovery'
        },
        $true
    )
)
if ($sameBootProcessRecoveryFunction.Count -ne 1) {
    throw 'Expected exactly one same-boot Photon process recovery function.'
}
. ([scriptblock]::Create($sameBootProcessRecoveryFunction[0].Extent.Text))
$credentialInitializer = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Initialize-AtlasoPhotonCredentialRoot'
        },
        $true
    )
)
if ($credentialInitializer.Count -ne 1) {
    throw 'Expected exactly one Photon credential-root initializer.'
}
. ([scriptblock]::Create($credentialInitializer[0].Extent.Text))
$sensitivePathValidatorFunction = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Assert-AtlasoPhotonSensitiveBuildPathIdentity'
        },
        $true
    )
)
if ($sensitivePathValidatorFunction.Count -ne 1) {
    throw 'Expected exactly one Photon sensitive-build path validator.'
}
. ([scriptblock]::Create($sensitivePathValidatorFunction[0].Extent.Text))

$expectedDefault = Join-Path $resolvedRepositoryRoot '.atlaso-local\photon-image-build-state'
$actualDefault = Resolve-AtlasoPhotonBuildStateRoot -RepositoryRoot $resolvedRepositoryRoot
if (-not $actualDefault.Equals($expectedDefault, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Default Photon build-state root escaped the task repository: $actualDefault"
}

$explicitChild = Join-Path $resolvedRepositoryRoot '.atlaso-local\photon-build-state-test'
$actualExplicit = Resolve-AtlasoPhotonBuildStateRoot `
    -RepositoryRoot $resolvedRepositoryRoot `
    -Path $explicitChild
if (-not $actualExplicit.Equals($explicitChild, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Explicit Photon build-state root changed unexpectedly: $actualExplicit"
}

$unignoredChild = Join-Path $resolvedRepositoryRoot 'photon-build-state-unignored'
$unignoredError = ''
try {
    Resolve-AtlasoPhotonBuildStateRoot `
        -RepositoryRoot $resolvedRepositoryRoot `
        -Path $unignoredChild | Out-Null
}
catch {
    $unignoredError = $_.Exception.Message
}
if ($unignoredError -cne 'Photon build state must remain inside a Git-ignored task subtree.' -or
    (Test-Path -LiteralPath $unignoredChild)) {
    throw "Unignored Photon build-state root did not fail before creating task state: $unignoredError"
}

$outsideRoot = Join-Path (Split-Path -Parent $resolvedRepositoryRoot) 'photon-build-state-outside'
$outsideError = ''
try {
    Resolve-AtlasoPhotonBuildStateRoot `
        -RepositoryRoot $resolvedRepositoryRoot `
        -Path $outsideRoot | Out-Null
}
catch {
    $outsideError = $_.Exception.Message
}
if (-not $outsideError.StartsWith(
        'Photon build state must remain beneath the exact task repository root:',
        [StringComparison]::Ordinal
    )) {
    throw "Outside Photon build-state root did not fail closed: $outsideError"
}

$currentBootIdentity = Get-AtlasoWindowsBootIdentity
if ($currentBootIdentity -notmatch '^[0-9]{1,19}$' -or
    -not (Test-AtlasoWindowsBootIdentityCurrent -BootIdentity $currentBootIdentity)) {
    throw 'The current Windows boot identity was not emitted as stable invariant ticks.'
}
$legacyBootIdentity = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).
    LastBootUpTime.ToUniversalTime().ToString('o')
$legacyRoundTrip = (@{ BootIdentity = $legacyBootIdentity } | ConvertTo-Json -Compress) |
    ConvertFrom-Json
if (-not (Test-AtlasoWindowsBootIdentityCurrent -BootIdentity $legacyRoundTrip.BootIdentity)) {
    throw 'A legacy JSON ISO boot identity did not match the same Windows boot.'
}

$fixtureRoot = Join-Path $resolvedRepositoryRoot (
    '.atlaso-local\photon-build-state-test-' + [guid]::NewGuid().ToString('N')
)
try {
    $selectiveRepository = Join-Path $fixtureRoot 'selective-ignore-repository'
    [void][System.IO.Directory]::CreateDirectory($selectiveRepository)
    & git -C $selectiveRepository init --quiet
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not initialize selective-ignore fixture repository.'
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $selectiveRepository '.gitignore'),
        "/state/*`n!/state/credentials/`n!/state/credentials/**`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    $selectiveStateRoot = Join-Path $selectiveRepository 'state'
    $selectiveIgnoreError = ''
    try {
        Resolve-AtlasoPhotonBuildStateRoot `
            -RepositoryRoot $selectiveRepository `
            -Path $selectiveStateRoot | Out-Null
    }
    catch {
        $selectiveIgnoreError = $_.Exception.Message
    }
    if ($selectiveIgnoreError -cne 'Photon build state must remain inside a Git-ignored task subtree.' -or
        (Test-Path -LiteralPath $selectiveStateRoot)) {
        throw "Selectively ignored Photon state did not fail before task-state creation: $selectiveIgnoreError"
    }

    $legacyStateRoot = Join-Path $fixtureRoot 'legacy-builder-addresses'
    $pendingRoot = Join-Path $legacyStateRoot 'pending-releases'
    [void][System.IO.Directory]::CreateDirectory($pendingRoot)
    $matchingPath = Join-Path $pendingRoot (
        'builder-address-reservation-' + [guid]::NewGuid().ToString('N') + '.json'
    )
    $foreignPath = Join-Path $pendingRoot (
        'builder-address-reservation-' + [guid]::NewGuid().ToString('N') + '.json'
    )
    $matching = [ordered]@{
        VmName        = 'Atlaso-PR-658-Photon-Builder-VMware'
        SourceBranch  = 'bug/623-624-photon-bootstrap-qemu'
        RepositoryRoot = $resolvedRepositoryRoot
    }
    $foreign = [ordered]@{
        VmName        = 'Atlaso-PR-675-Photon-Builder-VMware-factory-reset'
        SourceBranch  = 'bug/418-factory-reset-management-binding'
        RepositoryRoot = Join-Path (Split-Path -Parent $resolvedRepositoryRoot) 'foreign-repository'
    }
    [System.IO.File]::WriteAllText(
        $matchingPath,
        ($matching | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        $foreignPath,
        ($foreign | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $script:completedLegacyHandoffs = @()
    $script:resolvedLegacyVmrunCount = 0
    Set-Item -Path Function:Resolve-WorkstationVmrunPath -Value {
        param($Path)
        $script:resolvedLegacyVmrunCount += 1
        'resolved-vmrun.exe'
    }
    Set-Item -Path Function:Complete-AtlasoBuilderAddressReservationHandoff -Value {
        param($Path, $VmrunPath, $StateRoot, $ReservationStateRoot)
        if ($VmrunPath -cne 'resolved-vmrun.exe') {
            throw "Legacy recovery used an unexpected vmrun path: $VmrunPath"
        }
        $script:completedLegacyHandoffs += [System.IO.Path]::GetFullPath($Path)
    }
    Invoke-AtlasoLegacyBuilderAddressHandoffRecovery `
        -StateRoot $legacyStateRoot `
        -VmrunPath 'unused-vmrun.exe' `
        -RepositoryRoot $resolvedRepositoryRoot `
        -VmName 'Atlaso-PR-658-Photon-Builder-VMware' `
        -SourceBranch 'bug/623-624-photon-bootstrap-qemu'
    if ($script:resolvedLegacyVmrunCount -ne 1 -or
        $script:completedLegacyHandoffs.Count -ne 1 -or
        -not $script:completedLegacyHandoffs[0].Equals(
            $matchingPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Legacy recovery did not isolate the exact matching builder handoff.'
    }
    Remove-Item -LiteralPath $matchingPath -Force
    Invoke-AtlasoLegacyBuilderAddressHandoffRecovery `
        -StateRoot $legacyStateRoot `
        -VmrunPath 'must-not-resolve-vmrun.exe' `
        -RepositoryRoot $resolvedRepositoryRoot `
        -VmName 'Atlaso-PR-658-Photon-Builder-VMware' `
        -SourceBranch 'bug/623-624-photon-bootstrap-qemu'
    if ($script:resolvedLegacyVmrunCount -ne 1 -or
        $script:completedLegacyHandoffs.Count -ne 1) {
        throw 'Legacy recovery resolved vmrun without an exact matching handoff.'
    }

    $junctionContainer = Join-Path $fixtureRoot 'junction-container'
    $junctionTarget = Join-Path $fixtureRoot 'junction-target'
    [void][System.IO.Directory]::CreateDirectory($junctionContainer)
    [void][System.IO.Directory]::CreateDirectory($junctionTarget)
    $junctionParent = Join-Path $junctionContainer 'credentials'
    [void](New-Item -ItemType Junction -Path $junctionParent -Target $junctionTarget -ErrorAction Stop)
    $cleanupLeaf = 'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    $cleanupTarget = Join-Path $junctionTarget $cleanupLeaf
    [void][System.IO.Directory]::CreateDirectory($cleanupTarget)
    $sentinelPath = Join-Path $cleanupTarget 'preserve.txt'
    [System.IO.File]::WriteAllText($sentinelPath, 'preserve')
    $cleanupRoot = Join-Path $junctionParent $cleanupLeaf
    $cleanupMarker = [pscustomobject][ordered]@{
        Schema       = 2
        RootPath     = $cleanupRoot
        RootIdentity = 'junction-test-identity'
        BootIdentity = '1'
        Phase        = 'active'
    }
    $markerDirectory = Join-Path $fixtureRoot 'cleanup-markers'
    [void][System.IO.Directory]::CreateDirectory($markerDirectory)
    $markerDirectoryIdentity = Get-AtlasoPathIdentity `
        -Path $markerDirectory `
        -Description 'Photon cleanup marker test directory'
    $junctionError = ''
    try {
        Complete-AtlasoPhotonBuildCleanup `
            -MarkerPath (Join-Path $markerDirectory 'junction-cleanup-marker.json') `
            -Marker $cleanupMarker `
            -ExpectedRootPath $cleanupRoot `
            -ExpectedRootIdentity 'junction-test-identity' `
            -AllowedParentRoot $junctionParent `
            -RepositoryRoot $resolvedRepositoryRoot `
            -MarkerDirectoryIdentity $markerDirectoryIdentity
    }
    catch {
        $junctionError = $_.Exception.Message
    }
    if ($junctionError -notmatch 'reparse point' -or
        -not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) {
        throw 'Photon cleanup did not preserve a root redirected through a replaced ancestor junction.'
    }

    $identityParent = Join-Path $fixtureRoot 'identity-cleanup'
    [void][System.IO.Directory]::CreateDirectory($identityParent)
    $identityLeaf = 'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    $identityRoot = Join-Path $identityParent $identityLeaf
    [void][System.IO.Directory]::CreateDirectory($identityRoot)
    $originalSentinel = Join-Path $identityRoot 'original.txt'
    [System.IO.File]::WriteAllText($originalSentinel, 'original')
    $rootIdentity = Get-AtlasoPathIdentity `
        -Path $identityRoot `
        -Description 'Photon cleanup test root'
    $identityMarkerPath = Join-Path $markerDirectory 'identity-cleanup-marker.json'
    $identityMarker = [pscustomobject][ordered]@{
        Schema       = 2
        RootPath     = $identityRoot
        RootIdentity = $rootIdentity
        BootIdentity = '1'
        Phase        = 'active'
    }
    [System.IO.File]::WriteAllText(
        $identityMarkerPath,
        ($identityMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $renamedRoot = Join-Path $identityParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    Move-Item -LiteralPath $identityRoot -Destination $renamedRoot -ErrorAction Stop
    [void][System.IO.Directory]::CreateDirectory($identityRoot)
    $replacementSentinel = Join-Path $identityRoot 'replacement.txt'
    [System.IO.File]::WriteAllText($replacementSentinel, 'replacement')
    $identityError = ''
    try {
        Complete-AtlasoPhotonBuildCleanup `
            -MarkerPath $identityMarkerPath `
            -Marker $identityMarker `
            -ExpectedRootPath $identityRoot `
            -ExpectedRootIdentity $rootIdentity `
            -AllowedParentRoot $identityParent `
            -RepositoryRoot $resolvedRepositoryRoot `
            -MarkerDirectoryIdentity $markerDirectoryIdentity
    }
    catch {
        $identityError = $_.Exception.Message
    }
    if ($identityError -notmatch 'identity (moved or changed|changed immediately before deletion)' -or
        -not (Test-Path -LiteralPath $identityMarkerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $renamedRoot 'original.txt') -PathType Leaf) -or
        -not (Test-Path -LiteralPath $replacementSentinel -PathType Leaf)) {
        throw (
            'Photon cleanup did not preserve marker, original root, and replacement after an identity swap: ' +
            $identityError
        )
    }
    Set-Item -Path Function:Get-AtlasoWindowsBootIdentity -Value { 'current-test-boot' }
    $differentStateParent = Join-Path $fixtureRoot 'different-state\credentials'
    [void][System.IO.Directory]::CreateDirectory($differentStateParent)
    $recoveryError = ''
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $identityMarkerPath `
            -AllowedParentRoots @($differentStateParent) `
            -RepositoryRoot $resolvedRepositoryRoot
    }
    catch {
        $recoveryError = $_.Exception.Message
    }
    if ($recoveryError -notmatch 'unresolved sensitive cleanup' -or
        -not (Test-Path -LiteralPath $identityMarkerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $renamedRoot 'original.txt') -PathType Leaf) -or
        -not (Test-Path -LiteralPath $replacementSentinel -PathType Leaf)) {
        throw (
            'Photon reboot recovery did not preserve marker, original root, and replacement after an identity swap: ' +
            $recoveryError
        )
    }

    $schemaOneParent = Join-Path $fixtureRoot 'schema-one-cleanup'
    [void][System.IO.Directory]::CreateDirectory($schemaOneParent)
    $schemaOneRoot = Join-Path $schemaOneParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($schemaOneRoot)
    $schemaOneMarkerPath = Join-Path $fixtureRoot 'schema-one-cleanup-marker.json'
    $schemaOneMarker = [ordered]@{
        Schema       = 1
        RootPath     = $schemaOneRoot
        BootIdentity = 'current-test-boot'
        Phase        = 'active'
    }
    [System.IO.File]::WriteAllText(
        $schemaOneMarkerPath,
        ($schemaOneMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $sameBootError = ''
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $schemaOneMarkerPath `
            -AllowedParentRoots @($schemaOneParent) `
            -RepositoryRoot $resolvedRepositoryRoot
    }
    catch {
        $sameBootError = $_.Exception.Message
    }
    if ($sameBootError -notmatch 'unresolved sensitive cleanup' -or
        -not (Test-Path -LiteralPath $schemaOneRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $schemaOneMarkerPath -PathType Leaf)) {
        throw 'Photon cleanup did not retain active schema-1 state before boot proof.'
    }
    $schemaOneMarker.BootIdentity = 'prior-test-boot'
    [System.IO.File]::WriteAllText(
        $schemaOneMarkerPath,
        ($schemaOneMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    Invoke-AtlasoPhotonBuildCleanupRecovery `
        -MarkerPath $schemaOneMarkerPath `
        -AllowedParentRoots @($schemaOneParent) `
        -RepositoryRoot $resolvedRepositoryRoot
    if ((Test-Path -LiteralPath $schemaOneRoot) -or
        (Test-Path -LiteralPath $schemaOneMarkerPath)) {
        throw 'Photon cleanup did not upgrade and retire an active schema-1 marker after boot proof.'
    }

    # A pre-migration marker remains checkout-local, but its sensitive root was
    # created beneath the explicitly admitted host temporary directory.
    $legacyRepositoryRoot = Join-Path $fixtureRoot 'legacy-repository'
    $legacyMarkerDirectory = Join-Path $legacyRepositoryRoot 'cleanup-markers'
    $legacyTemporaryParent = Join-Path $fixtureRoot 'legacy-temporary-parent'
    [void][System.IO.Directory]::CreateDirectory($legacyMarkerDirectory)
    [void][System.IO.Directory]::CreateDirectory($legacyTemporaryParent)
    $legacyTemporaryRoot = Join-Path $legacyTemporaryParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($legacyTemporaryRoot)
    $legacyTemporaryMarkerPath = Join-Path $legacyMarkerDirectory 'legacy-temporary-marker.json'
    $legacyTemporaryMarker = [ordered]@{
        Schema = 1; RootPath = $legacyTemporaryRoot
        BootIdentity = 'prior-test-boot'; Phase = 'active'
    }
    [System.IO.File]::WriteAllText(
        $legacyTemporaryMarkerPath,
        ($legacyTemporaryMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    Invoke-AtlasoPhotonBuildCleanupRecovery `
        -MarkerPath $legacyTemporaryMarkerPath `
        -AllowedParentRoots @($legacyTemporaryParent) `
        -RepositoryRoot $legacyRepositoryRoot
    if ((Test-Path -LiteralPath $legacyTemporaryRoot) -or
        (Test-Path -LiteralPath $legacyTemporaryMarkerPath)) {
        throw 'Photon cleanup did not retire a legacy root beneath an explicitly admitted temporary parent.'
    }

    $absentSchemaOneRoot = Join-Path $schemaOneParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    $absentSchemaOneMarkerPath = Join-Path $markerDirectory 'schema-one-absent-marker.json'
    $absentSchemaOneMarker = [ordered]@{
        Schema = 1; RootPath = $absentSchemaOneRoot
        BootIdentity = 'prior-test-boot'; Phase = 'active'
    }
    [System.IO.File]::WriteAllText(
        $absentSchemaOneMarkerPath,
        ($absentSchemaOneMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $absentSchemaOneError = ''
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $absentSchemaOneMarkerPath `
            -AllowedParentRoots @($schemaOneParent) `
            -RepositoryRoot $resolvedRepositoryRoot
    }
    catch { $absentSchemaOneError = $_.Exception.Message }
    if ($absentSchemaOneError -notmatch 'unresolved sensitive cleanup' -or
        -not (Test-Path -LiteralPath $absentSchemaOneMarkerPath -PathType Leaf)) {
        throw 'Photon cleanup retired an absent schema-1 root without deletion-bound proof.'
    }

    $absentParent = Join-Path $fixtureRoot 'root-absent-cleanup'
    [void][System.IO.Directory]::CreateDirectory($absentParent)
    $absentRoot = Join-Path $absentParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($absentRoot)
    $absentIdentity = Get-AtlasoPathIdentity -Path $absentRoot -Description 'Root-absent test root'
    $absentMarkerPath = Join-Path $markerDirectory 'root-absent-marker.json'
    $absentMarker = [ordered]@{
        Schema = 2; RootPath = $absentRoot; RootIdentity = $absentIdentity
        BootIdentity = 'prior-test-boot'; Phase = 'active'
    }
    [System.IO.File]::WriteAllText(
        $absentMarkerPath,
        ($absentMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.Directory]::Delete($absentRoot)
    $absentRootError = ''
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $absentMarkerPath `
            -AllowedParentRoots @($absentParent) `
            -RepositoryRoot $resolvedRepositoryRoot
    }
    catch { $absentRootError = $_.Exception.Message }
    if ($absentRootError -notmatch 'unresolved sensitive cleanup' -or
        -not (Test-Path -LiteralPath $absentMarkerPath -PathType Leaf)) {
        throw 'Photon cleanup retired an absent schema-2 root without deletion-bound proof.'
    }

    $markerEscape = Join-Path $fixtureRoot 'marker-escape'
    $redirectedMarkerDirectory = Join-Path $fixtureRoot 'redirected-markers'
    [void][System.IO.Directory]::CreateDirectory($markerEscape)
    [void](New-Item -ItemType Junction -Path $redirectedMarkerDirectory -Target $markerEscape)
    $redirectedMarkerPath = Join-Path $redirectedMarkerDirectory 'cleanup.json'
    [System.IO.File]::WriteAllText(
        $redirectedMarkerPath,
        ($absentMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $redirectedMarkerError = ''
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $redirectedMarkerPath `
            -AllowedParentRoots @($absentParent) `
            -RepositoryRoot $resolvedRepositoryRoot
    }
    catch { $redirectedMarkerError = $_.Exception.Message }
    if ($redirectedMarkerError -notmatch 'unresolved sensitive cleanup' -or
        -not (Test-Path -LiteralPath (Join-Path $markerEscape 'cleanup.json'))) {
        throw 'Photon recovery followed a redirected fixed marker directory.'
    }

    $sameBootParent = Join-Path $fixtureRoot 'same-boot-recovery'
    $sameBootMarkerDirectory = Join-Path $fixtureRoot 'same-boot-markers'
    [void][System.IO.Directory]::CreateDirectory($sameBootParent)
    [void][System.IO.Directory]::CreateDirectory($sameBootMarkerDirectory)
    $pwshPath = (Get-Process -Id $PID).Path
    $exitedOwner = Start-Process `
        -FilePath $pwshPath `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 0') `
        -PassThru `
        -WindowStyle Hidden
    $exitedOwnerStart = $exitedOwner.StartTime.ToUniversalTime().ToFileTimeUtc()
    $exitedOwnerId = $exitedOwner.Id
    $exitedOwner.WaitForExit()
    $exitedOwner.Dispose()

    $sameBootRoot = Join-Path $sameBootParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($sameBootRoot)
    [System.IO.File]::WriteAllText((Join-Path $sameBootRoot 'plaintext.fixture'), 'test-only')
    $sameBootIdentity = Get-AtlasoPathIdentity -Path $sameBootRoot -Description 'Same-boot test root'
    $sameBootMarkerPath = Join-Path $sameBootMarkerDirectory 'same-boot.json'
    $sameBootJobName = 'Local\Atlaso-Photon-' + [guid]::NewGuid().ToString('N')
    Initialize-AtlasoWorkstationProcessJobType
    $sameBootJob = [Atlaso.WorkstationProcessJob]::CreateSuspended(
        $pwshPath,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 300'),
        $sameBootJobName
    )
    try {
        $sameBootChildId = $sameBootJob.RootProcess.Id
        $sameBootChildStart = $sameBootJob.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
        $sameBootMarker = [ordered]@{
            Schema = 3; RootPath = $sameBootRoot; RootIdentity = $sameBootIdentity
            BootIdentity = Get-AtlasoWindowsBootIdentity; Phase = 'active'
            OwnerProcessId = $exitedOwnerId; OwnerProcessStartFileTimeUtc = $exitedOwnerStart
            ProcessJobName = $sameBootJobName; ChildProcessId = $sameBootChildId
            ChildProcessStartFileTimeUtc = $sameBootChildStart; ProcessOwnershipPhase = 'assigned'
        }
        [System.IO.File]::WriteAllText(
            $sameBootMarkerPath,
            ($sameBootMarker | ConvertTo-Json -Compress),
            [System.Text.UTF8Encoding]::new($false)
        )
        $sameBootJob.Resume()
        $sameBootLiveStart = (Get-Process -Id $sameBootChildId -ErrorAction Stop).StartTime.
            ToUniversalTime().ToFileTimeUtc()
        if ($sameBootLiveStart -ne $sameBootChildStart) {
            throw "Same-boot fixture child start identity changed: $sameBootChildStart / $sameBootLiveStart"
        }
        $sameBootLiveState = Get-AtlasoRecordedProcessIdentityState `
            -ProcessId $sameBootChildId `
            -StartFileTimeUtc $sameBootChildStart
        if ($sameBootLiveState -cne 'matching') {
            throw "Same-boot fixture classifier changed the live child identity: $sameBootLiveState"
        }
        $sameBootReadback = Get-Content -LiteralPath $sameBootMarkerPath -Raw | ConvertFrom-Json
        $sameBootReadbackState = Get-AtlasoRecordedProcessIdentityState `
            -ProcessId ([int]$sameBootReadback.ChildProcessId) `
            -StartFileTimeUtc ([long]$sameBootReadback.ChildProcessStartFileTimeUtc)
        if ($sameBootReadbackState -cne 'matching') {
            throw "Same-boot marker readback changed the live child identity: $sameBootReadbackState / $($sameBootReadback.ChildProcessStartFileTimeUtc) / $sameBootLiveStart"
        }
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $sameBootMarkerPath `
            -AllowedParentRoots @($sameBootParent) `
            -RepositoryRoot $resolvedRepositoryRoot
        if ((Test-Path -LiteralPath $sameBootRoot) -or
            (Test-Path -LiteralPath $sameBootMarkerPath) -or
            $null -ne (Get-Process -Id $sameBootChildId -ErrorAction SilentlyContinue)) {
            throw 'Same-boot Photon recovery did not terminate its exact job and retire its root.'
        }
        # Marker absence is the idempotent terminal state.
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $sameBootMarkerPath `
            -AllowedParentRoots @($sameBootParent) `
            -RepositoryRoot $resolvedRepositoryRoot
    }
    finally {
        $sameBootJob.Dispose()
    }

    $terminalRoot = Join-Path $sameBootParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($terminalRoot)
    $terminalIdentity = Get-AtlasoPathIdentity -Path $terminalRoot -Description 'Terminal test root'
    $terminalChild = Start-Process `
        -FilePath $pwshPath `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 0') `
        -PassThru `
        -WindowStyle Hidden
    $terminalChildStart = $terminalChild.StartTime.ToUniversalTime().ToFileTimeUtc()
    $terminalChildId = $terminalChild.Id
    $terminalChild.WaitForExit()
    $terminalChild.Dispose()
    $terminalMarkerPath = Join-Path $sameBootMarkerDirectory 'terminal.json'
    $terminalMarker = [ordered]@{
        Schema = 3; RootPath = $terminalRoot; RootIdentity = $terminalIdentity
        BootIdentity = Get-AtlasoWindowsBootIdentity; Phase = 'active'
        OwnerProcessId = $exitedOwnerId; OwnerProcessStartFileTimeUtc = $exitedOwnerStart
        ProcessJobName = 'Local\Atlaso-Photon-' + [guid]::NewGuid().ToString('N')
        ChildProcessId = $terminalChildId; ChildProcessStartFileTimeUtc = $terminalChildStart
        ProcessOwnershipPhase = 'assigned'
    }
    [System.IO.File]::WriteAllText(
        $terminalMarkerPath,
        ($terminalMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    Invoke-AtlasoPhotonBuildCleanupRecovery `
        -MarkerPath $terminalMarkerPath `
        -AllowedParentRoots @($sameBootParent) `
        -RepositoryRoot $resolvedRepositoryRoot
    if ((Test-Path -LiteralPath $terminalRoot) -or (Test-Path -LiteralPath $terminalMarkerPath)) {
        throw 'Terminal same-boot interruption did not retire an absent exact child.'
    }

    $reusedRoot = Join-Path $sameBootParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($reusedRoot)
    $reusedMarkerPath = Join-Path $sameBootMarkerDirectory 'pid-reuse.json'
    $currentStart = (Get-Process -Id $PID).StartTime.ToUniversalTime().AddSeconds(-1).ToFileTimeUtc()
    $reusedMarker = [ordered]@{
        Schema = 3; RootPath = $reusedRoot
        RootIdentity = Get-AtlasoPathIdentity -Path $reusedRoot -Description 'PID reuse test root'
        BootIdentity = Get-AtlasoWindowsBootIdentity; Phase = 'active'
        OwnerProcessId = $exitedOwnerId; OwnerProcessStartFileTimeUtc = $exitedOwnerStart
        ProcessJobName = 'Local\Atlaso-Photon-' + [guid]::NewGuid().ToString('N')
        ChildProcessId = $PID; ChildProcessStartFileTimeUtc = $currentStart
        ProcessOwnershipPhase = 'assigned'
    }
    [System.IO.File]::WriteAllText(
        $reusedMarkerPath,
        ($reusedMarker | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $reusedError = ''
    try {
        Invoke-AtlasoPhotonBuildCleanupRecovery `
            -MarkerPath $reusedMarkerPath `
            -AllowedParentRoots @($sameBootParent) `
            -RepositoryRoot $resolvedRepositoryRoot
    }
    catch { $reusedError = $_.Exception.Message }
    if ($reusedError -notmatch 'unresolved sensitive cleanup' -or
        -not (Test-Path -LiteralPath $reusedRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $reusedMarkerPath -PathType Leaf)) {
        throw 'Same-boot Photon recovery did not fail closed on PID reuse.'
    }

    $replacementRoot = Join-Path $sameBootParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($replacementRoot)
    $replacementJobName = 'Local\Atlaso-Photon-' + [guid]::NewGuid().ToString('N')
    $replacementJob = [Atlaso.WorkstationProcessJob]::CreateSuspended(
        $pwshPath,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 300'),
        $replacementJobName
    )
    $foreignChild = Start-Process `
        -FilePath $pwshPath `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 300') `
        -PassThru `
        -WindowStyle Hidden
    try {
        $replacementJob.Resume()
        $replacementMarkerPath = Join-Path $sameBootMarkerDirectory 'job-replacement.json'
        $replacementMarker = [ordered]@{
            Schema = 3; RootPath = $replacementRoot
            RootIdentity = Get-AtlasoPathIdentity -Path $replacementRoot -Description 'Job replacement test root'
            BootIdentity = Get-AtlasoWindowsBootIdentity; Phase = 'active'
            OwnerProcessId = $exitedOwnerId; OwnerProcessStartFileTimeUtc = $exitedOwnerStart
            ProcessJobName = $replacementJobName; ChildProcessId = $foreignChild.Id
            ChildProcessStartFileTimeUtc = $foreignChild.StartTime.ToUniversalTime().ToFileTimeUtc()
            ProcessOwnershipPhase = 'assigned'
        }
        [System.IO.File]::WriteAllText(
            $replacementMarkerPath,
            ($replacementMarker | ConvertTo-Json -Compress),
            [System.Text.UTF8Encoding]::new($false)
        )
        $replacementError = ''
        try {
            Invoke-AtlasoPhotonBuildCleanupRecovery `
                -MarkerPath $replacementMarkerPath `
                -AllowedParentRoots @($sameBootParent) `
                -RepositoryRoot $resolvedRepositoryRoot
        }
        catch { $replacementError = $_.Exception.Message }
        if ($replacementError -notmatch 'unresolved sensitive cleanup' -or
            -not (Test-Path -LiteralPath $replacementRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $replacementMarkerPath -PathType Leaf) -or
            $foreignChild.HasExited) {
            throw 'Same-boot Photon recovery acted on a job/process identity replacement.'
        }
    }
    finally {
        $replacementJob.TerminateAndWait(10000)
        $replacementJob.Dispose()
        if (-not $foreignChild.HasExited) {
            $foreignChild.Kill($true)
            $foreignChild.WaitForExit()
        }
        $foreignChild.Dispose()
    }

    $descendantRoot = Join-Path $sameBootParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    [void][System.IO.Directory]::CreateDirectory($descendantRoot)
    $descendantJobName = 'Local\Atlaso-Photon-' + [guid]::NewGuid().ToString('N')
    $descendantCommand = "Start-Process -FilePath '$($pwshPath.Replace("'", "''"))' -ArgumentList @('-NoProfile','-Command','Start-Sleep 300') -WindowStyle Hidden; exit 0"
    $descendantJob = [Atlaso.WorkstationProcessJob]::CreateSuspended(
        $pwshPath,
        @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', $descendantCommand),
        $descendantJobName
    )
    try {
        $descendantRootId = $descendantJob.RootProcess.Id
        $descendantRootStart = $descendantJob.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
        $descendantJob.Resume()
        $descendantJob.RootProcess.WaitForExit(10000) | Out-Null
        $descendantMarkerPath = Join-Path $sameBootMarkerDirectory 'surviving-descendant.json'
        $descendantMarker = [ordered]@{
            Schema = 3; RootPath = $descendantRoot
            RootIdentity = Get-AtlasoPathIdentity -Path $descendantRoot -Description 'Descendant test root'
            BootIdentity = Get-AtlasoWindowsBootIdentity; Phase = 'active'
            OwnerProcessId = $exitedOwnerId; OwnerProcessStartFileTimeUtc = $exitedOwnerStart
            ProcessJobName = $descendantJobName; ChildProcessId = $descendantRootId
            ChildProcessStartFileTimeUtc = $descendantRootStart; ProcessOwnershipPhase = 'assigned'
        }
        [System.IO.File]::WriteAllText(
            $descendantMarkerPath,
            ($descendantMarker | ConvertTo-Json -Compress),
            [System.Text.UTF8Encoding]::new($false)
        )
        $descendantError = ''
        try {
            Invoke-AtlasoPhotonBuildCleanupRecovery `
                -MarkerPath $descendantMarkerPath `
                -AllowedParentRoots @($sameBootParent) `
                -RepositoryRoot $resolvedRepositoryRoot
        }
        catch { $descendantError = $_.Exception.Message }
        if ($descendantError -notmatch 'unresolved sensitive cleanup' -or
            -not (Test-Path -LiteralPath $descendantRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $descendantMarkerPath -PathType Leaf)) {
            throw 'Same-boot Photon recovery did not preserve a surviving unbound descendant.'
        }
    }
    finally {
        $descendantJob.TerminateAndWait(10000)
        $descendantJob.Dispose()
    }

    $sensitiveCredentialRoot = Join-Path $fixtureRoot 'sensitive-credential-root'
    $sensitiveBuildRoot = Join-Path $sensitiveCredentialRoot 'sensitive-build'
    $sensitiveEscapeRoot = Join-Path $fixtureRoot 'sensitive-escape'
    [void][System.IO.Directory]::CreateDirectory($sensitiveBuildRoot)
    [void][System.IO.Directory]::CreateDirectory($sensitiveEscapeRoot)
    $sensitiveBuildIdentity = Get-AtlasoPathIdentity `
        -Path $sensitiveBuildRoot `
        -Description 'Photon sensitive-build test root'
    $sensitiveIdentityPins = @{}
    $nestedPlaintextDirectory = Join-Path $sensitiveBuildRoot 'kickstart-src'
    $nestedPlaintextFile = Join-Path $nestedPlaintextDirectory 'photon-ks.json'
    [void][System.IO.Directory]::CreateDirectory($nestedPlaintextDirectory)
    [System.IO.File]::WriteAllText($nestedPlaintextFile, 'test-secret')
    Assert-AtlasoPhotonSensitiveBuildPathIdentity `
        -CredentialRoot $sensitiveCredentialRoot `
        -SensitiveBuildRoot $sensitiveBuildRoot `
        -RootIdentity $sensitiveBuildIdentity `
        -Path $nestedPlaintextFile `
        -IdentityPins $sensitiveIdentityPins
    $retainedPlaintextDirectory = Join-Path $sensitiveEscapeRoot 'retained-kickstart-src'
    Move-Item -LiteralPath $nestedPlaintextDirectory -Destination $retainedPlaintextDirectory
    [void][System.IO.Directory]::CreateDirectory($nestedPlaintextDirectory)
    [System.IO.File]::WriteAllText($nestedPlaintextFile, 'replacement')
    $nestedPlaintextError = ''
    try {
        Assert-AtlasoPhotonSensitiveBuildPathIdentity `
            -CredentialRoot $sensitiveCredentialRoot `
            -SensitiveBuildRoot $sensitiveBuildRoot `
            -RootIdentity $sensitiveBuildIdentity `
            -Path $nestedPlaintextFile `
            -IdentityPins $sensitiveIdentityPins
    }
    catch { $nestedPlaintextError = $_.Exception.Message }
    if ($nestedPlaintextError -notmatch 'identity changed' -or
        -not (Test-Path -LiteralPath (Join-Path $retainedPlaintextDirectory 'photon-ks.json'))) {
        throw 'Photon sensitive-build validation did not detect a replaced plaintext subtree.'
    }
    $renamedSensitiveRoot = Join-Path $sensitiveCredentialRoot 'sensitive-build-retained'
    Move-Item -LiteralPath $sensitiveBuildRoot -Destination $renamedSensitiveRoot -ErrorAction Stop
    [void](New-Item `
            -ItemType Junction `
            -Path $sensitiveBuildRoot `
            -Target $sensitiveEscapeRoot `
            -ErrorAction Stop)
    $sensitivePathError = ''
    try {
        Assert-AtlasoPhotonSensitiveBuildPathIdentity `
            -CredentialRoot $sensitiveCredentialRoot `
            -SensitiveBuildRoot $sensitiveBuildRoot `
            -RootIdentity $sensitiveBuildIdentity `
            -Path (Join-Path $sensitiveBuildRoot 'packer-vars\atlaso-photon.auto.pkrvars.hcl') `
            -IdentityPins $sensitiveIdentityPins
    }
    catch {
        $sensitivePathError = $_.Exception.Message
    }
    if ($sensitivePathError -notmatch 'reparse point|identity changed' -or
        -not (Test-Path -LiteralPath $renamedSensitiveRoot -PathType Container) -or
        (Test-Path -LiteralPath (Join-Path $sensitiveEscapeRoot 'packer-vars'))) {
        throw 'Photon sensitive-build validation did not block a redirected plaintext workspace.'
    }

    $stagingBuildState = Join-Path $fixtureRoot 'staging-build-state'
    $stagingEscape = Join-Path $fixtureRoot 'staging-escape'
    [void][System.IO.Directory]::CreateDirectory($stagingBuildState)
    [void][System.IO.Directory]::CreateDirectory($stagingEscape)
    $redirectedCredentialParent = Join-Path $stagingBuildState 'credentials'
    [void](New-Item `
            -ItemType Junction `
            -Path $redirectedCredentialParent `
            -Target $stagingEscape `
            -ErrorAction Stop)
    $escapedCredentialRoot = Join-Path $redirectedCredentialParent (
        'atlaso-photon-build-credentials-' + [guid]::NewGuid().ToString('N')
    )
    $stagingError = ''
    try {
        Initialize-AtlasoPhotonCredentialRoot `
            -BuildStateRoot $stagingBuildState `
            -CredentialStateRoot $redirectedCredentialParent `
            -CredentialRoot $escapedCredentialRoot | Out-Null
    }
    catch {
        $stagingError = $_.Exception.Message
    }
    if ($stagingError -notmatch 'reparse point' -or
        (Test-Path -LiteralPath (Join-Path $stagingEscape (Split-Path -Leaf $escapedCredentialRoot)))) {
        throw 'Photon credential staging did not fail before following a redirected parent.'
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedRepositoryRoot `
            -ChildPath $fixtureRoot `
            -FailureMessage 'Photon build-state test fixture escaped the repository'
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

Write-Host 'Photon build-state root tests passed.'
