Set-StrictMode -Version Latest

if (-not ('Atlaso.HypervFinalPath' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Atlaso
{
    public static class HypervFinalPath
    {
        private const uint FileReadAttributes = 0x80;
        private const uint FileShareRead = 0x1;
        private const uint FileShareWrite = 0x2;
        private const uint FileShareDelete = 0x4;
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle file,
            StringBuilder path,
            uint pathLength,
            uint flags
        );

        public static string Get(string path)
        {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero
            ))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                StringBuilder result = new StringBuilder(512);
                uint length = GetFinalPathNameByHandleW(handle, result, (uint)result.Capacity, 0);
                if (length == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if (length >= result.Capacity)
                {
                    result = new StringBuilder((int)length + 1);
                    length = GetFinalPathNameByHandleW(handle, result, (uint)result.Capacity, 0);
                    if (length == 0 || length >= result.Capacity)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }

                string finalPath = result.ToString();
                if (finalPath.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    return @"\\" + finalPath.Substring(8);
                }
                if (finalPath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
                {
                    return finalPath.Substring(4);
                }
                return finalPath;
            }
        }
    }
}
'@
}

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

function Get-AtlasoHypervFinalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        return Get-AtlasoHypervCanonicalPath -Path ([Atlaso.HypervFinalPath]::Get($Path))
    }
    catch {
        throw "Hyper-V inventory path cannot be resolved for ownership validation: $Path ($($_.Exception.Message))"
    }
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
    foreach ($disk in @(Get-VMHardDiskDrive -VM $Vm -ErrorAction Stop)) {
        $diskPath = [string]$disk.Path
        $visitedDiskPaths = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        while (-not [string]::IsNullOrWhiteSpace($diskPath)) {
            if (-not [System.IO.Path]::IsPathFullyQualified($diskPath)) {
                throw "Hyper-V disk chain contains a non-absolute path for VM '$($Vm.Name)': $diskPath"
            }
            $canonicalDiskPath = Get-AtlasoHypervCanonicalPath -Path $diskPath
            if (-not $visitedDiskPaths.Add($canonicalDiskPath)) {
                throw "Hyper-V disk chain contains a cycle for VM '$($Vm.Name)': $diskPath"
            }
            $paths += $diskPath
            $diskMetadata = Get-VHD -Path $diskPath -ErrorAction Stop
            $diskPath = [string]$diskMetadata.ParentPath
        }
    }
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

    $resolvedRemovalRoot = Get-AtlasoHypervFinalPath -Path $RemovalRoot
    $usesArtifactRoot = $false
    foreach ($path in (Get-AtlasoHypervVmArtifactPaths -Vm $Vm)) {
        $lexicallyMatchesRemovalRoot = (
            (Test-AtlasoHypervSamePath -Left $RemovalRoot -Right $path) -or
            (Test-AtlasoHypervStrictDescendantPath -ParentPath $RemovalRoot -ChildPath $path)
        )
        if (-not (Test-Path -LiteralPath $path)) {
            if ($lexicallyMatchesRemovalRoot) {
                throw "Hyper-V inventory path cannot be resolved for ownership validation: $path"
            }
            continue
        }
        $resolvedInventoryPath = Get-AtlasoHypervFinalPath -Path $path
        $resolvedMatchesRemovalRoot = (
            (Test-AtlasoHypervSamePath -Left $resolvedRemovalRoot -Right $resolvedInventoryPath) -or
            (Test-AtlasoHypervStrictDescendantPath -ParentPath $resolvedRemovalRoot -ChildPath $resolvedInventoryPath)
        )
        if ($lexicallyMatchesRemovalRoot -or $resolvedMatchesRemovalRoot) {
            if (-not $resolvedMatchesRemovalRoot) {
                throw "Hyper-V inventory path resolves outside the requested artifact root: $path"
            }
            $usesArtifactRoot = $true
        }
    }
    return $usesArtifactRoot
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

    if ($null -eq (Get-Item -LiteralPath $RemovalRoot -Force -ErrorAction SilentlyContinue)) {
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
        if (-not (Test-AtlasoHypervVmUsesArtifactRoot -Vm $currentVm[0] -RemovalRoot $resolvedRemovalRoot)) {
            throw "Hyper-V VM no longer references the requested artifact root; artifacts were preserved: $($vm.Name)"
        }
        if ([string]$currentVm[0].State -ne 'Off') {
            Stop-VM -VM $currentVm[0] -TurnOff -Force -ErrorAction Stop
            $currentVm = @(Get-VM -ErrorAction Stop | Where-Object { $_.Id -eq $vm.Id })
            if ($currentVm.Count -ne 1 -or [string]$currentVm[0].State -ne 'Off') {
                throw "Hyper-V VM remains active after stop succeeded; artifacts were preserved: $($vm.Name)"
            }
            if (-not (Test-AtlasoHypervVmUsesArtifactRoot -Vm $currentVm[0] -RemovalRoot $resolvedRemovalRoot)) {
                throw "Hyper-V VM no longer references the requested artifact root after stop; artifacts were preserved: $($vm.Name)"
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
