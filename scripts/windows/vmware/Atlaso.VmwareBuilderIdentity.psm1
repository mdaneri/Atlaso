<#
.SYNOPSIS
Build and verify canonical VMware Photon builder identities.

.DESCRIPTION
Defines the task-owned pull-request and protected release identity contracts
used by the Photon/Packer VMware builder. The helpers keep the canonical name,
output directory, VMX path, ownership manifest, and provenance bound together
before provider or recursive filesystem mutation is permitted.
#>

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force

<#
.SYNOPSIS
Create one validated task-owned or release-owned Photon builder identity.

.PARAMETER PullRequestNumber
Exact positive same-repository pull-request number for a task-owned build.

.PARAMETER CollisionSuffix
Optional collision-safe suffix for another builder owned by the same pull request.

.PARAMETER Repository
Canonical owner/repository identity proven for the pull request.

.PARAMETER SourceBranch
Exact task branch proven as the pull-request head branch.

.PARAMETER SourceCommit
Exact 40-character source commit proven as the pull-request head commit.

.PARAMETER ReleaseVersion
Strict synchronized release version for a protected release builder.

.PARAMETER WorkflowRunId
Optional positive workflow run ID that further distinguishes a release builder.
#>
function New-AtlasoVmwareBuilderIdentity {
    [CmdletBinding(DefaultParameterSetName = 'PullRequest')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'PullRequest')]
        [ValidateRange(1, 2147483647)]
        [int]$PullRequestNumber,

        [Parameter(ParameterSetName = 'PullRequest')]
        [string]$CollisionSuffix = '',

        [Parameter(Mandatory = $true, ParameterSetName = 'PullRequest')]
        [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
        [string]$Repository,

        [Parameter(Mandatory = $true, ParameterSetName = 'PullRequest')]
        [string]$SourceBranch,

        [Parameter(Mandatory = $true, ParameterSetName = 'PullRequest')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Release')]
        [ValidatePattern('^[0-9a-f]{40}$')]
        [string]$SourceCommit,

        [Parameter(Mandatory = $true, ParameterSetName = 'Release')]
        [ValidatePattern('^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')]
        [string]$ReleaseVersion,

        [Parameter(ParameterSetName = 'Release')]
        [ValidateRange(1, [long]::MaxValue)]
        [long]$WorkflowRunId = 0
    )

    if ($PSCmdlet.ParameterSetName -eq 'PullRequest') {
        $null = & git check-ref-format --branch $SourceBranch 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "SourceBranch is not one valid Git branch name: $SourceBranch"
        }
        # Reuse the #634 grammar for positive PR numbers and sanitized suffixes,
        # while retaining the operator-facing Photon builder purpose casing.
        $baseIdentity = New-AtlasoVmwareTestIdentity `
            -PullRequestNumber $PullRequestNumber `
            -Purpose 'photon-builder-vmware' `
            -CollisionSuffix $CollisionSuffix
        $name = "Atlaso-PR-$PullRequestNumber-Photon-Builder-VMware"
        if ($baseIdentity.CollisionSuffix) {
            $name = "$name-$($baseIdentity.CollisionSuffix)"
        }
        return [pscustomobject][ordered]@{
            SchemaVersion     = 1
            Kind              = 'pull_request'
            Name              = $name
            Repository        = $Repository
            PullRequestNumber = $PullRequestNumber
            SourceBranch      = $SourceBranch
            SourceCommit      = $SourceCommit
            CollisionSuffix   = [string]$baseIdentity.CollisionSuffix
            ReleaseVersion    = ''
            WorkflowRunId     = 0
        }
    }

    $versionToken = $ReleaseVersion -replace '\.', '-'
    $name = "Atlaso-Release-v$versionToken-$($SourceCommit.Substring(0, 12))-Photon-Builder-VMware"
    if ($WorkflowRunId -gt 0) {
        $name = "$name-run-$WorkflowRunId"
    }
    return [pscustomobject][ordered]@{
        SchemaVersion     = 1
        Kind              = 'release'
        Name              = $name
        Repository        = ''
        PullRequestNumber = 0
        SourceBranch      = ''
        SourceCommit      = $SourceCommit
        CollisionSuffix   = ''
        ReleaseVersion    = $ReleaseVersion
        WorkflowRunId     = $WorkflowRunId
    }
}

<#
.SYNOPSIS
Return the exact sibling ownership-manifest path for one builder output root.

.PARAMETER OutputDirectory
Canonical builder output directory.
#>
function Get-AtlasoVmwareBuilderIdentityManifestPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$OutputDirectory)

    $resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
    return "$resolvedOutput.builder-identity.json"
}

<#
.SYNOPSIS
Require an output directory to end with the canonical builder name.

.PARAMETER OutputDirectory
Requested Packer output directory.

.PARAMETER Identity
Validated builder identity that owns the directory.
#>
function Assert-AtlasoVmwareBuilderOutputDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][psobject]$Identity
    )

    return Assert-AtlasoVmwareIdentityDirectory `
        -Path $OutputDirectory `
        -ExpectedName ([string]$Identity.Name) `
        -ParameterName 'OutputDirectory'
}

<#
.SYNOPSIS
Write one durable non-secret builder ownership manifest.

.PARAMETER Path
Exact sibling manifest path.

.PARAMETER OutputDirectory
Canonical output directory owned by the identity.

.PARAMETER Identity
Validated task or release builder identity.

.PARAMETER ReplaceSameOwner
Replace an older source-commit binding only after the existing manifest proves
the same canonical task or release owner.
#>
function Write-AtlasoVmwareBuilderIdentityManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][psobject]$Identity,
        [switch]$ReplaceSameOwner
    )

    $resolvedOutput = Assert-AtlasoVmwareBuilderOutputDirectory `
        -OutputDirectory $OutputDirectory `
        -Identity $Identity
    $expectedPath = Get-AtlasoVmwareBuilderIdentityManifestPath -OutputDirectory $resolvedOutput
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    if (-not $resolvedPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Builder identity manifest path does not match the canonical output: $resolvedPath"
    }
    $payload = [ordered]@{
        schema_version      = 1
        kind                = [string]$Identity.Kind
        name                = [string]$Identity.Name
        output_directory    = $resolvedOutput
        repository          = [string]$Identity.Repository
        pull_request_number = [int]$Identity.PullRequestNumber
        source_branch       = [string]$Identity.SourceBranch
        source_commit       = [string]$Identity.SourceCommit
        collision_suffix    = [string]$Identity.CollisionSuffix
        release_version     = [string]$Identity.ReleaseVersion
        workflow_run_id     = [long]$Identity.WorkflowRunId
    }
    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf) {
        $existing = Assert-AtlasoVmwareBuilderOwnershipManifest `
            -Path $resolvedPath `
            -OutputDirectory $resolvedOutput `
            -Identity $Identity
        if ([string]$existing.source_commit -ceq [string]$Identity.SourceCommit) {
            return
        }
        if (-not $ReplaceSameOwner) {
            throw 'Builder identity manifest belongs to the same owner but a different source commit.'
        }
        if ([string]$Identity.Kind -cne 'pull_request') {
            throw 'Only a same-owner pull-request manifest may advance to a newer exact source commit.'
        }
    }
    $manifestParent = Split-Path -Parent $resolvedPath
    [void][System.IO.Directory]::CreateDirectory($manifestParent)
    $temporaryPath = "$resolvedPath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            (($payload | ConvertTo-Json -Depth 4) + "`n"),
            [System.Text.UTF8Encoding]::new($false)
        )
        [System.IO.File]::Move($temporaryPath, $resolvedPath, $true)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

<#
.SYNOPSIS
Verify one builder ownership manifest against its stable task or release owner.

.PARAMETER Path
Exact sibling manifest path to validate.

.PARAMETER OutputDirectory
Canonical builder output directory.

.PARAMETER Identity
Expected validated builder identity.
#>
function Assert-AtlasoVmwareBuilderOwnershipManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][psobject]$Identity
    )

    $resolvedOutput = Assert-AtlasoVmwareBuilderOutputDirectory `
        -OutputDirectory $OutputDirectory `
        -Identity $Identity
    $expectedPath = Get-AtlasoVmwareBuilderIdentityManifestPath -OutputDirectory $resolvedOutput
    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if (-not $resolvedPath.Equals($expectedPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Builder identity manifest is not the exact sibling of its canonical output directory.'
    }
    try {
        $manifest = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop | ConvertFrom-Json
    }
    catch {
        throw "Builder identity manifest is invalid: $($_.Exception.Message)"
    }
    $expected = [ordered]@{
        schema_version      = 1
        kind                = [string]$Identity.Kind
        name                = [string]$Identity.Name
        output_directory    = $resolvedOutput
        repository          = [string]$Identity.Repository
        pull_request_number = [int]$Identity.PullRequestNumber
        source_branch       = [string]$Identity.SourceBranch
        collision_suffix    = [string]$Identity.CollisionSuffix
        release_version     = [string]$Identity.ReleaseVersion
        workflow_run_id     = [long]$Identity.WorkflowRunId
    }
    foreach ($entry in $expected.GetEnumerator()) {
        $property = $manifest.PSObject.Properties[$entry.Key]
        if ($null -eq $property) {
            throw "Builder identity manifest does not match expected $($entry.Key)."
        }
        # Windows paths are case-insensitive, while every non-path ownership field remains ordinal.
        $comparison = if ($entry.Key -ceq 'output_directory') {
            [StringComparison]::OrdinalIgnoreCase
        }
        else {
            [StringComparison]::Ordinal
        }
        if (-not [string]::Equals([string]$property.Value, [string]$entry.Value, $comparison)) {
            throw "Builder identity manifest does not match expected $($entry.Key)."
        }
    }
    if ([string]$manifest.source_commit -notmatch '^[0-9a-f]{40}$') {
        throw 'Builder identity manifest contains an invalid source commit.'
    }
    return $manifest
}

<#
.SYNOPSIS
Verify one builder ownership manifest against an exact identity and output.

.PARAMETER Path
Exact sibling manifest path to validate.

.PARAMETER OutputDirectory
Canonical builder output directory.

.PARAMETER Identity
Expected validated builder identity, including its exact source commit.
#>
function Assert-AtlasoVmwareBuilderIdentityManifest {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][psobject]$Identity
    )

    $manifest = Assert-AtlasoVmwareBuilderOwnershipManifest `
        -Path $Path `
        -OutputDirectory $OutputDirectory `
        -Identity $Identity
    if ([string]$manifest.source_commit -cne [string]$Identity.SourceCommit) {
        throw 'Builder identity manifest does not match the exact expected source_commit.'
    }
    return $manifest
}

<#
.SYNOPSIS
Verify the canonical builder VMX path and display name.

.PARAMETER VmxPath
Exact builder VMX path.

.PARAMETER OutputDirectory
Canonical builder output directory.

.PARAMETER Identity
Expected validated builder identity.
#>
function Assert-AtlasoVmwareBuilderVmx {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][psobject]$Identity
    )

    $resolvedOutput = Assert-AtlasoVmwareBuilderOutputDirectory `
        -OutputDirectory $OutputDirectory `
        -Identity $Identity
    return Assert-AtlasoVmwareOwnedVmx `
        -VmxPath $VmxPath `
        -ExpectedDirectory $resolvedOutput `
        -ExpectedName ([string]$Identity.Name)
}

Export-ModuleMember -Function @(
    'Assert-AtlasoVmwareBuilderIdentityManifest',
    'Assert-AtlasoVmwareBuilderOwnershipManifest',
    'Assert-AtlasoVmwareBuilderOutputDirectory',
    'Assert-AtlasoVmwareBuilderVmx',
    'Get-AtlasoVmwareBuilderIdentityManifestPath',
    'New-AtlasoVmwareBuilderIdentity',
    'Write-AtlasoVmwareBuilderIdentityManifest'
)
