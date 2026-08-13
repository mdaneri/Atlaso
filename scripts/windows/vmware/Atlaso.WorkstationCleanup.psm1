Set-StrictMode -Version Latest

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
    return $canonicalPath
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
            ForEach-Object { $_.ToString().Trim().Trim('"') } |
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
    $uniquePaths = @($paths | Select-Object -Unique)
    if ($uniquePaths.Count -ne $paths.Count) {
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
        $paths += Resolve-AtlasoVerifiedVmxInventoryPath `
            -Path $registeredPath `
            -InventoryDescription 'VMware Workstation registration inventory'
    }
    $uniquePaths = @($paths | Select-Object -Unique)
    if ($uniquePaths.Count -ne $paths.Count) {
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

    foreach ($candidate in $Paths) {
        if (Test-AtlasoSamePath -Left $candidate -Right $VmxPath) {
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
    'Remove-AtlasoWorkstationVmArtifacts',
    'Test-AtlasoStrictDescendantPath'
)
