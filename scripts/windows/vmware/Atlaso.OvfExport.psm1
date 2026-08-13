Set-StrictMode -Version Latest

function ConvertTo-AtlasoNormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'A non-empty filesystem path is required.'
    }

    $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $fullPath = [System.IO.Path]::GetFullPath($providerPath)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.Length -gt $root.Length) {
        $fullPath = $fullPath.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )
    }
    return $fullPath
}

function Test-AtlasoPathEqual {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $comparison = if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
        [System.StringComparison]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparison]::Ordinal
    }
    return [string]::Equals(
        (ConvertTo-AtlasoNormalizedPath -Path $Left),
        (ConvertTo-AtlasoNormalizedPath -Path $Right),
        $comparison
    )
}

function Resolve-AtlasoOvfOutputPlan {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [AllowEmptyString()][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$Name,
        [switch]$CallerSpecifiedOutputDirectory
    )

    $resolvedRepoRoot = ConvertTo-AtlasoNormalizedPath -Path $RepoRoot
    $approvedOutputRoot = ConvertTo-AtlasoNormalizedPath -Path (
        Join-Path $resolvedRepoRoot 'image\vmware-workstation\ovf'
    )
    $canonicalOutputDirectory = ConvertTo-AtlasoNormalizedPath -Path (
        Join-Path $approvedOutputRoot $Name
    )
    $requestedOutputDirectory = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $canonicalOutputDirectory
    }
    else {
        ConvertTo-AtlasoNormalizedPath -Path $OutputDirectory
    }

    return [pscustomobject]@{
        RepoRoot                       = $resolvedRepoRoot
        ApprovedOutputRoot             = $approvedOutputRoot
        CanonicalOutputDirectory        = $canonicalOutputDirectory
        OutputDirectory                 = $requestedOutputDirectory
        CallerSpecifiedOutputDirectory  = [bool]$CallerSpecifiedOutputDirectory
    }
}

function Assert-AtlasoOvfRemovalTarget {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ApprovedOutputRoot,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    $resolvedRepoRoot = ConvertTo-AtlasoNormalizedPath -Path $RepoRoot
    $resolvedOutputRoot = ConvertTo-AtlasoNormalizedPath -Path $ApprovedOutputRoot
    $resolvedTarget = ConvertTo-AtlasoNormalizedPath -Path $OutputDirectory
    $filesystemRoot = ConvertTo-AtlasoNormalizedPath -Path ([System.IO.Path]::GetPathRoot($resolvedTarget))
    if (Test-AtlasoPathEqual -Left $resolvedTarget -Right $filesystemRoot) {
        throw "Refusing to recursively remove a filesystem root: $resolvedTarget"
    }

    $protectedPaths = @(
        $resolvedRepoRoot,
        (Join-Path $resolvedRepoRoot 'image'),
        (Join-Path $resolvedRepoRoot 'image\vmware-workstation'),
        $resolvedOutputRoot
    )
    foreach ($protectedPath in $protectedPaths) {
        if (Test-AtlasoPathEqual -Left $resolvedTarget -Right $protectedPath) {
            throw "Refusing to recursively remove protected Atlaso path: $resolvedTarget"
        }
    }

    $relativeTarget = [System.IO.Path]::GetRelativePath($resolvedOutputRoot, $resolvedTarget)
    $parentPrefix = "..$([System.IO.Path]::DirectorySeparatorChar)"
    $alternateParentPrefix = "..$([System.IO.Path]::AltDirectorySeparatorChar)"
    if (
        [System.IO.Path]::IsPathRooted($relativeTarget) -or
        $relativeTarget -eq '..' -or
        $relativeTarget.StartsWith($parentPrefix, [System.StringComparison]::Ordinal) -or
        $relativeTarget.StartsWith($alternateParentPrefix, [System.StringComparison]::Ordinal)
    ) {
        throw "Refusing to recursively remove OVF output outside the approved root $resolvedOutputRoot`: $resolvedTarget"
    }

    $currentPath = $resolvedTarget
    while ($true) {
        if (Test-Path -LiteralPath $currentPath) {
            $item = Get-Item -LiteralPath $currentPath -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing to recursively remove OVF output through a reparse point: $currentPath"
            }
        }
        if (Test-AtlasoPathEqual -Left $currentPath -Right $resolvedOutputRoot) {
            break
        }
        $parent = [System.IO.Directory]::GetParent($currentPath)
        if ($null -eq $parent) {
            throw "Could not prove OVF output is inside the approved root $resolvedOutputRoot`: $resolvedTarget"
        }
        $currentPath = $parent.FullName
    }

    return $resolvedTarget
}

function Clear-AtlasoOvfOutputDirectory {
    param(
        [Parameter(Mandatory = $true)]$OutputPlan,
        [switch]$Release,
        [switch]$Force
    )

    $resolvedTarget = $OutputPlan.OutputDirectory
    if (-not (Test-Path -LiteralPath $resolvedTarget)) {
        return
    }

    $resolvedTarget = Assert-AtlasoOvfRemovalTarget `
        -RepoRoot $OutputPlan.RepoRoot `
        -ApprovedOutputRoot $OutputPlan.ApprovedOutputRoot `
        -OutputDirectory $resolvedTarget
    $canonicalReleaseReplacement = (
        $Release -and
        -not $OutputPlan.CallerSpecifiedOutputDirectory -and
        (Test-AtlasoPathEqual -Left $resolvedTarget -Right $OutputPlan.CanonicalOutputDirectory)
    )
    if (-not $Force -and -not $canonicalReleaseReplacement) {
        throw "OVF output directory already exists: $resolvedTarget. Pass -Force to replace it."
    }

    Remove-Item -LiteralPath $resolvedTarget -Recurse -Force
}

Export-ModuleMember -Function @(
    'Assert-AtlasoOvfRemovalTarget',
    'Clear-AtlasoOvfOutputDirectory',
    'Resolve-AtlasoOvfOutputPlan'
)
