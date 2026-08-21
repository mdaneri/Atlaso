Set-StrictMode -Version Latest

function Get-AtlasoHypervCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPath = [System.IO.Path]::GetPathRoot($fullPath)
    if ($rootPath -and $fullPath.Equals($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $rootPath
    }
    return $fullPath.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}

function Test-AtlasoHypervSamePath {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    return (Get-AtlasoHypervCanonicalPath -Path $Left).Equals(
        (Get-AtlasoHypervCanonicalPath -Path $Right),
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

function Test-AtlasoHypervStrictDescendantPath {
    param(
        [Parameter(Mandatory = $true)][string]$ParentPath,
        [Parameter(Mandatory = $true)][string]$ChildPath
    )

    $resolvedParent = Get-AtlasoHypervCanonicalPath -Path $ParentPath
    $resolvedChild = Get-AtlasoHypervCanonicalPath -Path $ChildPath
    $relativePath = [System.IO.Path]::GetRelativePath($resolvedParent, $resolvedChild)
    if ($relativePath -eq '.' -or [System.IO.Path]::IsPathRooted($relativePath)) {
        return $false
    }
    return -not (
        $relativePath.Equals('..', [System.StringComparison]::OrdinalIgnoreCase) -or
        $relativePath.StartsWith("..$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or
        $relativePath.StartsWith("..$([System.IO.Path]::AltDirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase)
    )
}

function Assert-AtlasoHypervPathHasNoReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    $currentPath = Get-AtlasoHypervCanonicalPath -Path $Path
    while ($currentPath) {
        if (Test-Path -LiteralPath $currentPath) {
            $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing recursive Hyper-V cleanup through reparse point: $currentPath"
            }
        }
        $parentPath = Split-Path -Parent $currentPath
        if (-not $parentPath -or (Test-AtlasoHypervSamePath -Left $currentPath -Right $parentPath)) {
            break
        }
        $currentPath = $parentPath
    }
}

function Get-AtlasoHypervVmArtifactPaths {
    param([Parameter(Mandatory = $true)][object]$Vm)

    $paths = @()
    foreach ($propertyName in @('Path', 'ConfigurationLocation', 'CheckpointFileLocation', 'SnapshotFileLocation', 'SmartPagingFilePath')) {
        $property = $Vm.PSObject.Properties[$propertyName]
        if ($property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            $paths += [string]$property.Value
        }
    }
    $paths += @(
        Get-VMHardDiskDrive -VM $Vm -ErrorAction Stop |
            ForEach-Object { [string]$_.Path } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    foreach ($path in $paths) {
        if (-not [System.IO.Path]::IsPathFullyQualified($path)) {
            throw "Hyper-V inventory contains a non-absolute artifact path for VM '$($Vm.Name)': $path"
        }
    }
    return @($paths | Select-Object -Unique)
}

function Test-AtlasoHypervVmUsesArtifactRoot {
    param(
        [Parameter(Mandatory = $true)][object]$Vm,
        [Parameter(Mandatory = $true)][string]$RemovalRoot
    )

    foreach ($path in (Get-AtlasoHypervVmArtifactPaths -Vm $Vm)) {
        if (
            (Test-AtlasoHypervSamePath -Left $RemovalRoot -Right $path) -or
            (Test-AtlasoHypervStrictDescendantPath -ParentPath $RemovalRoot -ChildPath $path)
        ) {
            return $true
        }
    }
    return $false
}

function Get-AtlasoHypervVmsUsingArtifactRoot {
    param([Parameter(Mandatory = $true)][string]$RemovalRoot)

    return @(
        Get-VM -ErrorAction Stop |
            Where-Object { Test-AtlasoHypervVmUsesArtifactRoot -Vm $_ -RemovalRoot $RemovalRoot }
    )
}

function Remove-AtlasoHypervArtifactRoot {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$HypervRoot,
        [Parameter(Mandatory = $true)][string]$RemovalRoot
    )

    if (-not (Test-Path -LiteralPath $RemovalRoot)) {
        return
    }
    if (-not (Test-Path -LiteralPath $RemovalRoot -PathType Container)) {
        throw "Hyper-V artifact target exists but is not a directory; refusing to report cleanup success: $RemovalRoot"
    }

    $resolvedHypervRoot = (Resolve-Path -LiteralPath $HypervRoot -ErrorAction Stop).Path
    $resolvedRemovalRoot = (Resolve-Path -LiteralPath $RemovalRoot -ErrorAction Stop).Path
    if (-not (Test-AtlasoHypervStrictDescendantPath -ParentPath $resolvedHypervRoot -ChildPath $resolvedRemovalRoot)) {
        throw "Refusing to remove a Hyper-V artifact directory outside the canonical image root: $resolvedRemovalRoot"
    }
    Assert-AtlasoHypervPathHasNoReparsePoint -Path $resolvedHypervRoot
    Assert-AtlasoHypervPathHasNoReparsePoint -Path $resolvedRemovalRoot

    $vms = @(Get-AtlasoHypervVmsUsingArtifactRoot -RemovalRoot $resolvedRemovalRoot)
    if (-not $PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Stop and remove Hyper-V VMs, then remove artifact root')) {
        return
    }

    foreach ($vm in $vms) {
        $currentVm = @(Get-VM -ErrorAction Stop | Where-Object { $_.Id -eq $vm.Id })
        if ($currentVm.Count -ne 1) {
            throw "Hyper-V VM inventory changed before cleanup; artifacts were preserved: $($vm.Name)"
        }
        if ([string]$currentVm[0].State -ne 'Off') {
            Stop-VM -VM $currentVm[0] -TurnOff -Force -ErrorAction Stop
            $currentVm = @(Get-VM -ErrorAction Stop | Where-Object { $_.Id -eq $vm.Id })
            if ($currentVm.Count -ne 1 -or [string]$currentVm[0].State -ne 'Off') {
                throw "Hyper-V VM remains active after stop succeeded; artifacts were preserved: $($vm.Name)"
            }
        }
        Remove-VM -VM $currentVm[0] -Force -ErrorAction Stop
        if (@(Get-VM -ErrorAction Stop | Where-Object { $_.Id -eq $vm.Id }).Count -ne 0) {
            throw "Hyper-V VM remains registered after removal succeeded; artifacts were preserved: $($vm.Name)"
        }
    }

    if (@(Get-AtlasoHypervVmsUsingArtifactRoot -RemovalRoot $resolvedRemovalRoot).Count -ne 0) {
        throw "Hyper-V VM state changed before filesystem cleanup; artifacts were preserved: $resolvedRemovalRoot"
    }
    Remove-Item -LiteralPath $resolvedRemovalRoot -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $resolvedRemovalRoot) {
        throw "Hyper-V artifact directory remains after recursive cleanup; refusing to report success: $resolvedRemovalRoot"
    }
}

Export-ModuleMember -Function 'Remove-AtlasoHypervArtifactRoot'
