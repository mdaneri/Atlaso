Set-StrictMode -Version Latest

if (-not ('Atlaso.WorkstationFileIdentity' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Atlaso
{
    public static class WorkstationFileIdentity
    {
        private const uint FileReadAttributes = 0x80;
        private const uint FileShareRead = 0x1;
        private const uint FileShareWrite = 0x2;
        private const uint FileShareDelete = 0x4;
        private const uint OpenExisting = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information
        );

        public static string Get(string path)
        {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FileReadAttributes,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero
            ))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return String.Format(
                    "{0:X8}:{1:X8}{2:X8}",
                    information.VolumeSerialNumber,
                    information.FileIndexHigh,
                    information.FileIndexLow
                );
            }
        }
    }
}
'@
}

function Get-AtlasoCanonicalPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

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

function Test-AtlasoSamePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Left,
        [Parameter(Mandatory = $true)]
        [string]$Right
    )

    $leftPath = Get-AtlasoCanonicalPath -Path $Left
    $rightPath = Get-AtlasoCanonicalPath -Path $Right
    return $leftPath.Equals($rightPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-AtlasoStrictDescendantPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParentPath,
        [Parameter(Mandatory = $true)]
        [string]$ChildPath
    )

    $resolvedParent = Get-AtlasoCanonicalPath -Path $ParentPath
    $resolvedChild = Get-AtlasoCanonicalPath -Path $ChildPath
    $relativePath = [System.IO.Path]::GetRelativePath($resolvedParent, $resolvedChild)
    if ($relativePath -eq '.' -or [System.IO.Path]::IsPathRooted($relativePath)) {
        return $false
    }

    $parentToken = '..'
    return -not (
        $relativePath.Equals($parentToken, [System.StringComparison]::OrdinalIgnoreCase) -or
        $relativePath.StartsWith(
            $parentToken + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        $relativePath.StartsWith(
            $parentToken + [System.IO.Path]::AltDirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    )
}

function Assert-AtlasoPathHasNoReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $currentPath = Get-AtlasoCanonicalPath -Path $Path
    while ($currentPath) {
        if (Test-Path -LiteralPath $currentPath) {
            $item = Get-Item -LiteralPath $currentPath -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing recursive VMware cleanup through reparse point: $currentPath"
            }
        }

        $parentPath = Split-Path -Parent $currentPath
        if (-not $parentPath -or (Test-AtlasoSamePath -Left $currentPath -Right $parentPath)) {
            break
        }
        $currentPath = $parentPath
    }
}

function Assert-AtlasoStrictDescendantPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParentPath,
        [Parameter(Mandatory = $true)]
        [string]$ChildPath,
        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    if (-not (Test-AtlasoStrictDescendantPath -ParentPath $ParentPath -ChildPath $ChildPath)) {
        throw "$FailureMessage`: $ChildPath"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $ParentPath
    Assert-AtlasoPathHasNoReparsePoint -Path $ChildPath
}

function Invoke-AtlasoVmrunChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Action
    )

    $output = @(& $VmrunPath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        $detail = ($output | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ }) -join ' '
        if ($detail) {
            throw "$Action failed with exit code $exitCode. vmrun output: $detail"
        }
        throw "$Action failed with exit code $exitCode."
    }
    return $output
}

function Get-AtlasoVmxFileIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$InventoryDescription
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$InventoryDescription contains a VMX path whose filesystem identity cannot be resolved; refusing filesystem cleanup: $Path"
    }
    try {
        return [Atlaso.WorkstationFileIdentity]::Get($Path)
    }
    catch {
        throw "$InventoryDescription contains a VMX path whose filesystem identity cannot be resolved; refusing filesystem cleanup: $Path"
    }
}

function Get-AtlasoVmxDisplayName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $displayNameLines = @(
        Get-Content -LiteralPath $Path |
            Where-Object { $_ -match '^\s*displayName\b' }
    )
    if ($displayNameLines.Count -ne 1) {
        throw "Refusing VMware cleanup because the VMX must contain exactly one displayName assignment: $Path"
    }
    if ($displayNameLines[0] -notmatch '^\s*displayName\s*=\s*"([^"\r\n]+)"\s*$') {
        throw "Refusing VMware cleanup because the VMX displayName assignment is malformed: $Path"
    }
    return $Matches[1]
}

function Resolve-AtlasoVerifiedVmxInventoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$InventoryDescription
    )

    if (-not [System.IO.Path]::IsPathFullyQualified($Path)) {
        throw "$InventoryDescription contains a non-absolute VMX path; refusing filesystem cleanup: $Path"
    }
    if (-not [System.IO.Path]::GetExtension($Path).Equals('.vmx', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$InventoryDescription contains a non-VMX path; refusing filesystem cleanup: $Path"
    }

    $canonicalPath = Get-AtlasoCanonicalPath -Path $Path
    if (-not $Path.Equals($canonicalPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$InventoryDescription contains a non-canonical VMX path; refusing filesystem cleanup: $Path"
    }
    Get-AtlasoVmxFileIdentity -Path $canonicalPath -InventoryDescription $InventoryDescription | Out-Null
    return $canonicalPath
}

function ConvertFrom-AtlasoVmrunInventoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$InventoryLine
    )

    $candidate = $InventoryLine.Trim()
    if (-not $candidate) {
        return $null
    }
    if ($candidate.Contains('"')) {
        if ($candidate -notmatch '^"([^\"]+)"$') {
            throw 'vmrun running-VM inventory contains an unbalanced or embedded quote; refusing filesystem cleanup.'
        }
        return $Matches[1]
    }
    return $candidate
}

function Get-AtlasoWorkstationVmPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('running')]
        [string]$State = 'running'
    )

    $output = @(Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'list') `
            -Action 'List running VMware Workstation VMs')
    if ($output.Count -lt 1 -or $output[0].ToString() -notmatch '^Total running VMs:\s*(\d+)\s*$') {
        throw 'vmrun list returned an unrecognized running-VM inventory; refusing filesystem cleanup.'
    }

    $declaredCount = [int]$Matches[1]
    $reportedPaths = @(
        $output |
            Select-Object -Skip 1 |
            ForEach-Object { ConvertFrom-AtlasoVmrunInventoryPath -InventoryLine $_.ToString() } |
            Where-Object { $_ }
    )
    if ($reportedPaths.Count -ne $declaredCount) {
        throw "vmrun list reported $declaredCount VMs but returned $($reportedPaths.Count) paths; refusing filesystem cleanup."
    }
    $paths = @(
        $reportedPaths | ForEach-Object {
            Resolve-AtlasoVerifiedVmxInventoryPath `
                -Path $_ `
                -InventoryDescription 'vmrun running-VM inventory'
        }
    )
    $fileIdentities = @(
        $paths | ForEach-Object {
            Get-AtlasoVmxFileIdentity -Path $_ -InventoryDescription 'vmrun running-VM inventory'
        }
    )
    $uniqueFileIdentities = @($fileIdentities | Select-Object -Unique)
    if ($uniqueFileIdentities.Count -ne $paths.Count) {
        throw 'vmrun running-VM inventory contains duplicate VMX paths; refusing filesystem cleanup.'
    }
    return $paths
}

function Resolve-AtlasoWorkstationInventoryPath {
    if (-not $env:APPDATA) {
        throw 'APPDATA is unavailable; refusing cleanup because VMware Workstation registration state cannot be verified.'
    }
    $inventoryPath = Join-Path $env:APPDATA 'VMware\inventory.vmls'
    if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
        throw "VMware Workstation inventory was not found; refusing cleanup because registration state cannot be verified: $inventoryPath"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $inventoryPath
    return (Resolve-Path -LiteralPath $inventoryPath).Path
}

function Get-AtlasoWorkstationRegisteredVmPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath
    )

    $paths = @()
    foreach ($line in Get-Content -LiteralPath $InventoryPath) {
        if ($line -notmatch '^\s*vmlist\d+\.config\b') {
            continue
        }
        if ($line -notmatch '^\s*vmlist\d+\.config\s*=\s*"(.*)"\s*$') {
            throw "VMware Workstation inventory contains an unrecognized registration entry; refusing filesystem cleanup: $InventoryPath"
        }
        $registeredPath = $Matches[1]
        if (-not $registeredPath) {
            continue
        }
        $paths += Resolve-AtlasoVerifiedVmxInventoryPath `
            -Path $registeredPath `
            -InventoryDescription 'VMware Workstation registration inventory'
    }
    $fileIdentities = @(
        $paths | ForEach-Object {
            Get-AtlasoVmxFileIdentity -Path $_ -InventoryDescription 'VMware Workstation registration inventory'
        }
    )
    $uniqueFileIdentities = @($fileIdentities | Select-Object -Unique)
    if ($uniqueFileIdentities.Count -ne $paths.Count) {
        throw "VMware Workstation registration inventory contains duplicate VMX paths; refusing filesystem cleanup: $InventoryPath"
    }
    return $paths
}

function Test-AtlasoWorkstationVmListed {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Paths,
        [Parameter(Mandatory = $true)]
        [string]$VmxPath
    )

    $targetIdentity = Get-AtlasoVmxFileIdentity -Path $VmxPath -InventoryDescription 'VMware cleanup target'
    foreach ($candidate in $Paths) {
        $candidateIdentity = Get-AtlasoVmxFileIdentity -Path $candidate -InventoryDescription 'VMware Workstation inventory'
        if ($candidateIdentity.Equals($targetIdentity, [System.StringComparison]::Ordinal)) {
            return $true
        }
    }
    return $false
}

function Assert-AtlasoWorkstationRemovalVmxSet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemovalRoot,
        [Parameter(Mandatory = $true)]
        [string[]]$ValidatedVmxPaths
    )

    $discoveredVmxPaths = @(
        Get-ChildItem `
            -LiteralPath $RemovalRoot `
            -Filter '*.vmx' `
            -File `
            -Recurse `
            -Force `
            -ErrorAction Stop |
            ForEach-Object {
                Assert-AtlasoStrictDescendantPath `
                    -ParentPath $RemovalRoot `
                    -ChildPath $_.FullName `
                    -FailureMessage 'Refusing to inspect a VMware VMX outside the exact artifact directory'
                (Resolve-Path -LiteralPath $_.FullName).Path
            }
    )
    $hasUnvalidatedVmx = $discoveredVmxPaths.Count -ne $ValidatedVmxPaths.Count
    if (-not $hasUnvalidatedVmx) {
        foreach ($discoveredVmxPath in $discoveredVmxPaths) {
            if (-not (Test-AtlasoWorkstationVmListed -Paths $ValidatedVmxPaths -VmxPath $discoveredVmxPath)) {
                $hasUnvalidatedVmx = $true
                break
            }
        }
    }
    if ($hasUnvalidatedVmx) {
        throw "Refusing to remove VMware artifacts because the directory contains an unvalidated VMX: $RemovalRoot"
    }
}

function Confirm-AtlasoWorkstationVmInactiveAndUnregistered {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true)]
        [string]$VmxPath,
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath
    )

    $runningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    if (Test-AtlasoWorkstationVmListed -Paths $runningPaths -VmxPath $VmxPath) {
        Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'stop', $VmxPath, 'hard') `
            -Action "Stop VMware Workstation VM '$VmxPath'" | Out-Null
        $runningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
        if (Test-AtlasoWorkstationVmListed -Paths $runningPaths -VmxPath $VmxPath) {
            throw "VMware Workstation VM remains running after stop succeeded: $VmxPath"
        }
    }

    $registeredPaths = @(Get-AtlasoWorkstationRegisteredVmPaths -InventoryPath $InventoryPath)
    if (Test-AtlasoWorkstationVmListed -Paths $registeredPaths -VmxPath $VmxPath) {
        Invoke-AtlasoVmrunChecked `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'unregister', $VmxPath) `
            -Action "Unregister VMware Workstation VM '$VmxPath'" | Out-Null
        $registeredPaths = @(Get-AtlasoWorkstationRegisteredVmPaths -InventoryPath $InventoryPath)
        if (Test-AtlasoWorkstationVmListed -Paths $registeredPaths -VmxPath $VmxPath) {
            throw "VMware Workstation VM remains registered after unregister succeeded: $VmxPath"
        }
    }
}

function Remove-AtlasoWorkstationVmArtifacts {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmrunPath,
        [Parameter(Mandatory = $true)]
        [string[]]$VmxPaths,
        [Parameter(Mandatory = $true)]
        [string]$RemovalRoot
    )

    $resolvedRemovalRoot = Get-AtlasoCanonicalPath -Path $RemovalRoot
    $inventoryPath = Resolve-AtlasoWorkstationInventoryPath
    $filesystemRoot = [System.IO.Path]::GetPathRoot($resolvedRemovalRoot)
    if (-not $filesystemRoot -or (Test-AtlasoSamePath -Left $resolvedRemovalRoot -Right $filesystemRoot)) {
        throw "Refusing to remove a filesystem root as a VMware artifact directory: $resolvedRemovalRoot"
    }
    Assert-AtlasoPathHasNoReparsePoint -Path $resolvedRemovalRoot

    $resolvedVmxPaths = @()
    foreach ($vmxPath in $VmxPaths) {
        $resolvedVmxPath = (Resolve-Path -LiteralPath $vmxPath).Path
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedRemovalRoot `
            -ChildPath $resolvedVmxPath `
            -FailureMessage 'Refusing to remove a VMware VMX outside the exact artifact directory'
        $resolvedVmxPaths += $resolvedVmxPath
    }
    if ($resolvedVmxPaths.Count -eq 0) {
        throw "Refusing to remove VMware artifacts without at least one validated VMX: $resolvedRemovalRoot"
    }

    Assert-AtlasoWorkstationRemovalVmxSet `
        -RemovalRoot $resolvedRemovalRoot `
        -ValidatedVmxPaths $resolvedVmxPaths

    if (-not $PSCmdlet.ShouldProcess($resolvedRemovalRoot, 'Stop, unregister, and remove VMware Workstation VM artifacts')) {
        return
    }

    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        Confirm-AtlasoWorkstationVmInactiveAndUnregistered `
            -VmrunPath $VmrunPath `
            -VmxPath $resolvedVmxPath `
            -InventoryPath $inventoryPath
    }

    $finalRunningPaths = @(Get-AtlasoWorkstationVmPaths -VmrunPath $VmrunPath -State running)
    $finalRegisteredPaths = @(Get-AtlasoWorkstationRegisteredVmPaths -InventoryPath $inventoryPath)
    foreach ($resolvedVmxPath in $resolvedVmxPaths) {
        if (
            (Test-AtlasoWorkstationVmListed -Paths $finalRunningPaths -VmxPath $resolvedVmxPath) -or
            (Test-AtlasoWorkstationVmListed -Paths $finalRegisteredPaths -VmxPath $resolvedVmxPath)
        ) {
            throw "VMware Workstation VM state changed before filesystem cleanup; artifacts were preserved: $resolvedVmxPath"
        }
    }

    Assert-AtlasoWorkstationRemovalVmxSet `
        -RemovalRoot $resolvedRemovalRoot `
        -ValidatedVmxPaths $resolvedVmxPaths

    if (Test-Path -LiteralPath $resolvedRemovalRoot) {
        Remove-Item -LiteralPath $resolvedRemovalRoot -Recurse -Force
    }
}

Export-ModuleMember -Function @(
    'Assert-AtlasoStrictDescendantPath',
    'Get-AtlasoVmxDisplayName',
    'Remove-AtlasoWorkstationVmArtifacts',
    'Test-AtlasoStrictDescendantPath'
)
