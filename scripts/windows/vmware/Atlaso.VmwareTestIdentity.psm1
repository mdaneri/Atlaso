<#
.SYNOPSIS
Build and verify canonical pull-request-owned VMware test identities.

.DESCRIPTION
Centralizes the repository-wide `Atlaso-PR-<number>-<purpose>[-<suffix>]`
contract used by normal test appliances and VMware lifecycle labs. The
helpers deliberately bind operator-visible names to exact filesystem and VMX
evidence before any reuse, redeploy, or cleanup mutation is allowed.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
Convert caller text into one bounded canonical VMware identity token.

.PARAMETER Value
Purpose or collision-suffix text to sanitize.

.PARAMETER ParameterName
Caller-facing parameter name used in validation errors.

.PARAMETER MaximumLength
Maximum length allowed after sanitization.
#>
function ConvertTo-AtlasoVmwareIdentityToken {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$ParameterName,
        [Parameter(Mandatory = $true)][ValidateRange(1, 64)][int]$MaximumLength
    )

    $token = ($Value.Trim().ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "$ParameterName must contain at least one ASCII letter or digit."
    }
    if ($token.Length -gt $MaximumLength) {
        throw "$ParameterName sanitizes to more than $MaximumLength characters. Choose a shorter value."
    }
    return $token
}

<#
.SYNOPSIS
Return the canonical identity for one pull-request-owned VMware test resource.

.PARAMETER PullRequestNumber
Exact positive GitHub pull-request number that owns the VM or lifecycle lab.

.PARAMETER Purpose
Short purpose text sanitized to lowercase ASCII words separated by hyphens.

.PARAMETER CollisionSuffix
Optional collision-safe suffix sanitized without removing the PR identity.
#>
function New-AtlasoVmwareTestIdentity {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 2147483647)]
        [int]$PullRequestNumber,

        [Parameter(Mandatory = $true)]
        [string]$Purpose,

        [string]$CollisionSuffix = ''
    )

    $canonicalPurpose = ConvertTo-AtlasoVmwareIdentityToken `
        -Value $Purpose `
        -ParameterName 'Purpose' `
        -MaximumLength 32
    $canonicalSuffix = ''
    if (-not [string]::IsNullOrWhiteSpace($CollisionSuffix)) {
        $canonicalSuffix = ConvertTo-AtlasoVmwareIdentityToken `
            -Value $CollisionSuffix `
            -ParameterName 'CollisionSuffix' `
            -MaximumLength 32
    }

    $name = "Atlaso-PR-$PullRequestNumber-$canonicalPurpose"
    if ($canonicalSuffix) {
        $name = "$name-$canonicalSuffix"
    }
    return [pscustomobject]@{
        Name              = $name
        PullRequestNumber = $PullRequestNumber
        Purpose           = $canonicalPurpose
        CollisionSuffix   = $canonicalSuffix
    }
}

<#
.SYNOPSIS
Require an output or lifecycle directory to use the canonical identity name.

.PARAMETER Path
Requested output or lifecycle directory path.

.PARAMETER ExpectedName
Canonical identity that must be the path's final component.

.PARAMETER ParameterName
Caller-facing path parameter name used in validation errors.
#>
function Assert-AtlasoVmwareIdentityDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [string]$ParameterName = 'OutputDirectory'
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    $leaf = [System.IO.Path]::GetFileName($resolvedPath.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ))
    if (-not $leaf.Equals($ExpectedName, [System.StringComparison]::Ordinal)) {
        throw "$ParameterName must end with the canonical VMware identity '$ExpectedName': $resolvedPath"
    }
    return $resolvedPath
}

<#
.SYNOPSIS
Verify that one VMX has the exact expected canonical name and path identity.

.PARAMETER VmxPath
Exact VMX file to verify before reuse, redeploy, or cleanup.

.PARAMETER ExpectedDirectory
Exact canonical directory that must contain the VMX.

.PARAMETER ExpectedName
Exact VMware display name and VMX filename stem expected for the owner.
#>
function Assert-AtlasoVmwareOwnedVmx {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$ExpectedDirectory,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )

    $resolvedDirectory = [System.IO.Path]::GetFullPath($ExpectedDirectory)
    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
    $expectedVmxPath = [System.IO.Path]::GetFullPath(
        (Join-Path $resolvedDirectory "$ExpectedName.vmx")
    )
    if (-not $resolvedVmxPath.Equals($expectedVmxPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing VMware mutation because the VMX path does not match the expected PR-owned identity '$ExpectedName': $resolvedVmxPath"
    }

    $displayNameLines = @(
        Get-Content -LiteralPath $resolvedVmxPath -ErrorAction Stop |
            Where-Object { $_ -match '^\s*displayName\b' }
    )
    if ($displayNameLines.Count -ne 1 -or $displayNameLines[0] -notmatch '^\s*displayName\s*=\s*"([^"\r\n]+)"\s*$') {
        throw "Refusing VMware mutation because the PR-owned VMX must contain one well-formed displayName: $resolvedVmxPath"
    }
    if (-not $Matches[1].Equals($ExpectedName, [System.StringComparison]::Ordinal)) {
        throw "Refusing VMware mutation because VMX displayName '$($Matches[1])' does not match the expected PR-owned identity '$ExpectedName': $resolvedVmxPath"
    }
    return $resolvedVmxPath
}

Export-ModuleMember -Function @(
    'Assert-AtlasoVmwareIdentityDirectory',
    'Assert-AtlasoVmwareOwnedVmx',
    'New-AtlasoVmwareTestIdentity'
)
