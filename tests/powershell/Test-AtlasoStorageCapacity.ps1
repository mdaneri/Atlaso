<#
.SYNOPSIS
Exercise storage volume identity resolution and storage-capacity admission checks with mocked volume evidence.
.PARAMETER RepositoryRoot
Atlaso checkout containing the virtualization storage capacity module.
.PARAMETER TaskStateRoot
Workspace directory for test artifacts. Defaults inside .task-state under the checkout.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [string]$TaskStateRoot = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path '.task-state')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts/windows/virtualization/Atlaso.StorageCapacity.psm1'
$fixtureRoot = Join-Path $TaskStateRoot ('storage-capacity-' + [guid]::NewGuid().ToString('N'))
if (-not (Test-Path -LiteralPath $TaskStateRoot)) {
    New-Item -ItemType Directory -Path $TaskStateRoot | Out-Null
}
$null = New-Item -ItemType Directory -Path $fixtureRoot -Force
$origTmp = $env:TEMP
$origTmpLower = $env:TMP
$env:TEMP = $TaskStateRoot
$env:TMP = $TaskStateRoot

Import-Module $modulePath -Force
$module = Get-Module Atlaso.StorageCapacity

<#
.SYNOPSIS
Require a command block to throw a message matching a pattern.
.PARAMETER Action
Command expected to fail.
.PARAMETER Pattern
Wildcard pattern required in the exception message.
#>
function Assert-AtlasoCapacityFailure {
    param([scriptblock]$Action, [string]$Pattern)
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike $Pattern) {
            throw
        }
        return
    }
    throw "Expected failure matching: $Pattern"
}

<#
.SYNOPSIS
Inject deterministic module-scope Get-Volume behavior.
.PARAMETER Fixtures
Map from lowercase existing paths to @{ UniqueId; SizeRemaining }.
#>
function Set-AtlasoVolumeResolver {
    param([hashtable]$Fixtures)
    $module.SessionState.PSVariable.Set('AtlasoStorageVolumeFixtures', $Fixtures)
    $module.SessionState.PSVariable.Set('AtlasoStorageVolumeResolver', {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [hashtable]$Fixtures = $null
        )

        $key = $Path.ToLowerInvariant()
        if ($null -eq $Fixtures -or -not $Fixtures.ContainsKey($key)) {
            throw "No simulated volume for path: $Path"
        }

        $entry = $Fixtures[$key]
        return [pscustomobject]@{
            UniqueId = $entry.UniqueId
            SizeRemaining = $entry.SizeRemaining
        }
    })
}

<#
.SYNOPSIS
Build deterministic volume metadata for an existing fixture directory.
.PARAMETER Path
Existing fixture path.
.PARAMETER VolumeId
Simulated operating-system volume identity.
.PARAMETER SizeRemaining
Simulated remaining bytes.
#>
function New-VolumeFixture {
    param([string]$Path, [string]$VolumeId, [long]$SizeRemaining)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Fixture path does not exist: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path.ToLowerInvariant(), @{
        UniqueId = $VolumeId
        SizeRemaining = $SizeRemaining
    }
}

try {
    # Shared and separate volume grouping (with shared volume ID aliases and case variations), no shortfall.
    $sharedA = Join-Path $fixtureRoot 'shared-a'
    $sharedB = Join-Path $fixtureRoot 'shared-b'
    $separate = Join-Path $fixtureRoot 'separate'
    New-Item -ItemType Directory -Path $sharedA,$sharedB,$separate | Out-Null

    $sharedAExisting = Join-Path $sharedA 'leaf'
    $sharedBExisting = Join-Path $sharedB 'leaf'
    $separateExisting = Join-Path $separate 'leaf'
    $sharedANonExisting = Join-Path $sharedA 'missing\target'
    $sharedBNonExisting = Join-Path $sharedB 'missing\target'
    $separateNonExisting = Join-Path $separate 'missing\target'

    $fixtures = @{}
    $sharedAKey, $sharedADef = New-VolumeFixture -Path $sharedA -VolumeId 'Vol-Shared' -SizeRemaining 4096
    $fixtures[$sharedAKey] = $sharedADef
    $sharedBKey, $sharedBDef = New-VolumeFixture -Path $sharedB -VolumeId 'vol-shared' -SizeRemaining 1024
    $fixtures[$sharedBKey] = $sharedBDef
    $separateKey, $separateDef = New-VolumeFixture -Path $separate -VolumeId 'Vol-Unique' -SizeRemaining 3072
    $fixtures[$separateKey] = $separateDef
    Set-AtlasoVolumeResolver -Fixtures $fixtures

    Assert-AtlasoStorageCapacity `
        -Components @(
            [pscustomobject]@{ Path = $sharedANonExisting; Name = 'shared-bytes'; Bytes = 64 },
            [pscustomobject]@{ Path = $sharedBNonExisting; Name = 'shared-alias'; Bytes = 32 },
            [pscustomobject]@{ Path = $separateNonExisting; Name = 'separate'; Bytes = 48 }
        ) -Stage Stage-Shared -HeadroomBytes 0

    # Exact-boundary equality: free equals required after component admission.
    $eqRoot = Join-Path $fixtureRoot 'equality'
    New-Item -ItemType Directory -Path $eqRoot | Out-Null
    $eqMissing = Join-Path $eqRoot 'missing\target'
    $eqKey, $eqDef = New-VolumeFixture -Path $eqRoot -VolumeId 'VOL-EQ' -SizeRemaining 1024
    $fixtures = @{}
    $fixtures[$eqKey] = $eqDef
    Set-AtlasoVolumeResolver -Fixtures $fixtures
    Assert-AtlasoStorageCapacity -Components @(
        [pscustomobject]@{ Path = $eqMissing; Name = 'exact'; Bytes = 1024 }
    ) -Stage Stage-Exact -HeadroomBytes 0

    # Distinct-volume insufficiency on the shared volume after min-remaining policy.
    $sharedAKey, $sharedAMin = New-VolumeFixture -Path $sharedA -VolumeId 'Vol-Shared' -SizeRemaining 64
    $sharedBKey, $sharedBMax = New-VolumeFixture -Path $sharedB -VolumeId 'VOL-SHARED' -SizeRemaining 80
    $fixtures = @{}
    $fixtures[$sharedAKey] = $sharedAMin
    $fixtures[$sharedBKey] = $sharedBMax
    Set-AtlasoVolumeResolver -Fixtures $fixtures
    Assert-AtlasoCapacityFailure {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $sharedANonExisting; Name = 'phase1'; Bytes = 32 },
            [pscustomobject]@{ Path = $sharedBNonExisting; Name = 'phase2'; Bytes = 48 }
        ) -Stage Stage-Insufficient -HeadroomBytes 16
    } "Storage admission failed for stage 'Stage-Insufficient': insufficient capacity on *"

    # Unknown volume evidence must fail closed.
    $unknownPath = Join-Path $fixtureRoot 'missing-volume\leaf'
    $fixtures = @{}
    Set-AtlasoVolumeResolver -Fixtures $fixtures
    Assert-AtlasoCapacityFailure {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $unknownPath; Name = 'missing'; Bytes = 1 }
        ) -Stage Stage-Unknown -HeadroomBytes 0
    } 'No simulated volume for path*'

    # Overflow defense using checked Int64 arithmetic with oversized component sums.
    $overflowRoot = Join-Path $fixtureRoot 'overflow'
    New-Item -ItemType Directory -Path $overflowRoot | Out-Null
    $overflowMissing = Join-Path $overflowRoot 'missing\target'
    $overflowKey, $overflowDef = New-VolumeFixture -Path $overflowRoot -VolumeId 'VOL-OVERFLOW' -SizeRemaining 9000000000000000000
    $fixtures = @{}
    $fixtures[$overflowKey] = $overflowDef
    Set-AtlasoVolumeResolver -Fixtures $fixtures
    $componentBytes = [long]5000000000000000000
    Assert-AtlasoCapacityFailure {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $overflowMissing; Name = 'a'; Bytes = $componentBytes },
            [pscustomobject]@{ Path = $overflowMissing; Name = 'b'; Bytes = $componentBytes }
        ) -Stage Stage-Overflow -HeadroomBytes 0
    } '*overflow*'

    # Invalid byte inputs must be rejected (negative and non-integer).
    $eqKey, $eqDef = New-VolumeFixture -Path $eqRoot -VolumeId 'VOL-EQ';
    $fixtures = @{}
    $fixtures[$eqKey] = $eqDef
    Set-AtlasoVolumeResolver -Fixtures $fixtures
    Assert-AtlasoCapacityFailure {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $eqMissing; Name = 'neg'; Bytes = -1 }
        ) -Stage Stage-Negative -HeadroomBytes 0
    } '*nonnegative*'
    Assert-AtlasoCapacityFailure {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $eqMissing; Name = 'bigint-neg'; Bytes = [System.Numerics.BigInteger]::Parse('-1') }
        ) -Stage Stage-Negative-BigInt -HeadroomBytes 0
    } '*nonnegative*'
    Assert-AtlasoCapacityFailure {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $eqMissing; Name = 'null'; Bytes = $null }
        ) -Stage Stage-Null -HeadroomBytes 0
    } '*nonnegative*'
    Assert-AtlasoCapacityFailure {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $eqMissing; Name = 'frac'; Bytes = 1.5 }
        ) -Stage Stage-Fractional -HeadroomBytes 0
    } '*nonnegative integer*'

    # Null remaining bytes from a simulated volume must fail validation.
    $eqKey, $eqDef = New-VolumeFixture -Path $eqRoot -VolumeId 'VOL-EQ-NULL' -SizeRemaining 1024
    $eqDef.SizeRemaining = $null
    $fixtures = @{}
    $fixtures[$eqKey] = $eqDef
    Set-AtlasoVolumeResolver -Fixtures $fixtures
    $nullVolumeFailed = $false
    try {
        Assert-AtlasoStorageCapacity -Components @(
            [pscustomobject]@{ Path = $eqMissing; Name = 'null-volume'; Bytes = 1 }
        ) -Stage Stage-Null-Volume -HeadroomBytes 0
    }
    catch {
        $nullVolumeFailed = $true
        if ($_.Exception.Message -notmatch 'volume\.SizeRemaining') {
            throw $_
        }
    }
    if (-not $nullVolumeFailed) {
        throw "Expected null volume remaining bytes to be rejected."
    }
    # Resolver returning more than one volume is unsupported.
    $module.SessionState.PSVariable.Set('AtlasoStorageVolumeResolver', {
        [CmdletBinding()]
        param(
            [string]$Path,
            [hashtable]$Fixtures = $null
        )
        return @(
            [pscustomobject]@{ UniqueId = 'VOL-1'; SizeRemaining = 64 },
            [pscustomobject]@{ UniqueId = 'VOL-2'; SizeRemaining = 64 }
        )
    })
    $module.SessionState.PSVariable.Set('AtlasoStorageVolumeFixtures', $null)
    Assert-AtlasoCapacityFailure {
        Get-AtlasoStorageVolume -Path $eqMissing
    } '*returned*volume*'
    Set-AtlasoVolumeResolver -Fixtures @{}

    # UNC path support is explicit fail-closed.
    $existingDriveRoot = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($env:SystemRoot))
    Assert-AtlasoCapacityFailure {
        Get-AtlasoStorageVolume -Path \\127.0.0.1\shared
    } 'UNC paths are unsupported*'

    # Root paths remain valid destination candidates for admission evidence.
    $rootKey, $rootDef = New-VolumeFixture -Path $existingDriveRoot -VolumeId 'VOL-ROOT' -SizeRemaining 2048
    $fixtures = @{}
    $fixtures[$rootKey] = $rootDef
    Set-AtlasoVolumeResolver -Fixtures $fixtures
    $rootVolume = Get-AtlasoStorageVolume -Path $existingDriveRoot
    if ($rootVolume.ExistingPath.ToLowerInvariant() -cne $rootKey) {
        throw "Expected filesystem root to resolve to its existing path, observed: $($rootVolume.ExistingPath)"
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }

    Remove-Module Atlaso.StorageCapacity -Force
    $env:TEMP = $origTmp
    $env:TMP = $origTmpLower
}

Write-Host 'Atlaso.StorageCapacity tests passed.'
