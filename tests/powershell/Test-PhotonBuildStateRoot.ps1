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
    Set-Item -Path Function:Complete-AtlasoBuilderAddressReservationHandoff -Value {
        param($Path, $VmrunPath, $StateRoot, $ReservationStateRoot)
        $script:completedLegacyHandoffs += [System.IO.Path]::GetFullPath($Path)
    }
    Invoke-AtlasoLegacyBuilderAddressHandoffRecovery `
        -StateRoot $legacyStateRoot `
        -VmrunPath 'unused-vmrun.exe' `
        -RepositoryRoot $resolvedRepositoryRoot `
        -VmName 'Atlaso-PR-658-Photon-Builder-VMware' `
        -SourceBranch 'bug/623-624-photon-bootstrap-qemu'
    if ($script:completedLegacyHandoffs.Count -ne 1 -or
        -not $script:completedLegacyHandoffs[0].Equals(
            $matchingPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Legacy recovery did not isolate the exact matching builder handoff.'
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
        Schema       = 1
        RootPath     = $cleanupRoot
        BootIdentity = '1'
        Phase        = 'active'
    }
    $junctionError = ''
    try {
        Complete-AtlasoPhotonBuildCleanup `
            -MarkerPath (Join-Path $fixtureRoot 'junction-cleanup-marker.json') `
            -Marker $cleanupMarker `
            -ExpectedRootPath $cleanupRoot `
            -AllowedParentRoot $junctionParent
    }
    catch {
        $junctionError = $_.Exception.Message
    }
    if ($junctionError -notmatch 'reparse point' -or
        -not (Test-Path -LiteralPath $sentinelPath -PathType Leaf)) {
        throw 'Photon cleanup did not preserve a root redirected through a replaced ancestor junction.'
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
