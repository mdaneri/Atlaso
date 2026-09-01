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
    if ($identityError -notmatch 'identity moved or changed' -or
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
    Invoke-AtlasoPhotonBuildCleanupRecovery `
        -MarkerPath $absentMarkerPath `
        -AllowedParentRoots @($absentParent) `
        -RepositoryRoot $resolvedRepositoryRoot
    if ((Test-Path -LiteralPath $absentRoot) -or (Test-Path -LiteralPath $absentMarkerPath)) {
        throw 'Photon cleanup did not retire an active marker after proven root deletion.'
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

    $sensitiveCredentialRoot = Join-Path $fixtureRoot 'sensitive-credential-root'
    $sensitiveBuildRoot = Join-Path $sensitiveCredentialRoot 'sensitive-build'
    $sensitiveEscapeRoot = Join-Path $fixtureRoot 'sensitive-escape'
    [void][System.IO.Directory]::CreateDirectory($sensitiveBuildRoot)
    [void][System.IO.Directory]::CreateDirectory($sensitiveEscapeRoot)
    $sensitiveBuildIdentity = Get-AtlasoPathIdentity `
        -Path $sensitiveBuildRoot `
        -Description 'Photon sensitive-build test root'
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
            -Path (Join-Path $sensitiveBuildRoot 'packer-vars\atlaso-photon.auto.pkrvars.hcl')
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
