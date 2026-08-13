[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Name = 'Atlaso-VMware',
    [Parameter(Mandatory = $true)]
    [string]$ApplianceVmxPath,
    [string]$OutputDirectory = '',
    [string]$VmrunPath = '',
    [string]$ManagementNetwork = 'VMnet8',
    [string]$SiteANetwork = 'VMnet2',
    [string]$SiteBNetwork = 'VMnet3',
    [string]$TrunkNetwork = 'VMnet4',
    [string]$VdiskManagerPath = '',
    [string]$DepotVmdkPath = '',
    [string]$BackupVmdkPath = '',
    [ValidateScript({ $_ -eq '500GB' })]
    [string]$DepotDiskSize = '500GB',
    [ValidateScript({ $_ -eq '500GB' })]
    [string]$BackupDiskSize = '500GB',
    [switch]$SkipLabNetworkAdapters
)

$ErrorActionPreference = 'Stop'

function Resolve-VmrunPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "vmrun.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

function Invoke-Vmrun {
    param([string[]]$Arguments)
    & $resolvedVmrun @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Resolve-VdiskManagerPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "vmware-vdiskmanager.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmware-vdiskmanager.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command vmware-vdiskmanager.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmware-vdiskmanager.exe was not found. Install VMware Workstation Pro or pass -VdiskManagerPath.'
}

function ConvertTo-VmxString {
    param([string]$Value)
    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

function Set-VmxValue {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )

    $line = "$Key = $(ConvertTo-VmxString -Value $Value)"
    $content = @(Get-Content -LiteralPath $Path)
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
        if ($_ -match $pattern) {
            $updated = $true
            $line
        } else {
            $_
        }
    })
    if (-not $updated) {
        $content += $line
    }
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

function Get-VmxValue {
    param(
        [string]$Path,
        [string]$Key
    )

    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"(?<value>.*)"\s*$'
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match $pattern) {
            return $Matches.value
        }
    }
    return ''
}

function Assert-ClonedPayloadDisks {
    param([string]$VmxPath)

    $vmDirectory = Split-Path -Parent $VmxPath
    foreach ($payloadDisk in @(
            @{ Unit = 0; Name = 'Photon OS' },
            @{ Unit = 1; Name = 'Atlaso system content' }
        )) {
        $prefix = "scsi0:$($payloadDisk.Unit)"
        if ((Get-VmxValue -Path $VmxPath -Key "$prefix.present") -ne 'TRUE') {
            throw "VMware clone did not retain the $($payloadDisk.Name) disk at SCSI unit $($payloadDisk.Unit)."
        }
        $fileName = Get-VmxValue -Path $VmxPath -Key "$prefix.fileName"
        if ([string]::IsNullOrWhiteSpace($fileName)) {
            throw "VMware clone did not identify the $($payloadDisk.Name) VMDK at SCSI unit $($payloadDisk.Unit)."
        }
        $diskPath = if ([System.IO.Path]::IsPathRooted($fileName)) {
            $fileName
        } else {
            Join-Path $vmDirectory $fileName
        }
        if (-not (Test-Path -LiteralPath $diskPath -PathType Leaf)) {
            throw "VMware clone $($payloadDisk.Name) VMDK is missing: $diskPath"
        }
    }
}

function New-DataVmdk {
    param(
        [string]$Path,
        [string]$Size,
        [string]$Label
    )

    if (Test-Path -LiteralPath $Path) {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $buffer = [byte[]]::new([Math]::Min([int64]1MB, $stream.Length))
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
        } finally {
            $stream.Dispose()
        }
        $descriptor = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
        $extents = [regex]::Matches($descriptor, '(?im)(?:^|[\r\n\x00])\s*RW\s+(?<sectors>\d+)\s+')
        if ($extents.Count -eq 0) {
            throw "$Label data disk does not expose a readable VMDK capacity descriptor: $Path"
        }
        [int64]$capacityBytes = 0
        foreach ($extent in $extents) {
            $capacityBytes += [int64]$extent.Groups['sectors'].Value * 512
        }
        if ($capacityBytes -ne 500GB) {
            throw "$Label data disk must expose exactly 536870912000 bytes, but '$Path' exposes $capacityBytes bytes."
        }
        Write-Host "$Label data disk already exists: $Path"
        return
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    if ($PSCmdlet.ShouldProcess($Path, "Create growable $Label data VMDK")) {
        & $resolvedVdiskManager -c -s $Size -a lsilogic -t 0 $Path
        if ($LASTEXITCODE -ne 0) {
            throw "vmware-vdiskmanager failed to create $Label data disk with exit code $LASTEXITCODE."
        }
        Write-Host "Created $Label data disk: $Path"
    }
}

function Get-VmxDiskFileName {
    param(
        [string]$VmxPath,
        [string]$DiskPath
    )

    $vmDirectory = Split-Path -Parent $VmxPath
    $resolvedDiskPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DiskPath)
    if ((Split-Path -Parent $resolvedDiskPath) -eq $vmDirectory) {
        return Split-Path -Leaf $resolvedDiskPath
    }
    return $resolvedDiskPath
}

function Set-VmxScsiDisk {
    param(
        [string]$Path,
        [int]$Unit,
        [string]$DiskPath
    )

    $prefix = "scsi0:$Unit"
    Set-VmxValue -Path $Path -Key "$prefix.present" -Value 'TRUE'
    Set-VmxValue -Path $Path -Key "$prefix.fileName" -Value (Get-VmxDiskFileName -VmxPath $Path -DiskPath $DiskPath)
    Set-VmxValue -Path $Path -Key "$prefix.redo" -Value ''
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
$resolvedVdiskManager = Resolve-VdiskManagerPath -Path $VdiskManagerPath
$resolvedSourceVmx = (Resolve-Path -LiteralPath $ApplianceVmxPath).Path

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot "image\vmware-workstation\test-vms\$Name"
}
$resolvedOutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$targetVmx = Join-Path $resolvedOutputDirectory "$Name.vmx"
$resolvedDepotVmdkPath = if ($DepotVmdkPath) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DepotVmdkPath)
} else {
    Join-Path $resolvedOutputDirectory 'Atlaso-Depot.vmdk'
}
$resolvedBackupVmdkPath = if ($BackupVmdkPath) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupVmdkPath)
} else {
    Join-Path $resolvedOutputDirectory 'Atlaso-Backups.vmdk'
}

if (Test-Path -LiteralPath $targetVmx) {
    throw "VM already exists: $targetVmx. Remove it first or pass a different -Name/-OutputDirectory."
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $resolvedOutputDirectory) | Out-Null
if ($PSCmdlet.ShouldProcess($targetVmx, "Clone Atlaso Workstation VM from $resolvedSourceVmx")) {
    Invoke-Vmrun -Arguments @('-T', 'ws', 'clone', $resolvedSourceVmx, $targetVmx, 'full', '-cloneName', $Name)
}

if (-not (Test-Path -LiteralPath $targetVmx)) {
    throw "VMware clone completed but target VMX was not found: $targetVmx"
}

Assert-ClonedPayloadDisks -VmxPath $targetVmx
Set-VmxValue -Path $targetVmx -Key 'displayName' -Value $Name
Set-VmxValue -Path $targetVmx -Key 'disk.EnableUUID' -Value 'TRUE'
New-DataVmdk -Path $resolvedDepotVmdkPath -Size $DepotDiskSize -Label 'VCF Offline Depot'
New-DataVmdk -Path $resolvedBackupVmdkPath -Size $BackupDiskSize -Label 'VCF Backups'
Set-VmxScsiDisk -Path $targetVmx -Unit 2 -DiskPath $resolvedDepotVmdkPath
Set-VmxScsiDisk -Path $targetVmx -Unit 3 -DiskPath $resolvedBackupVmdkPath
& (Join-Path $PSScriptRoot 'set-test-nics.ps1') `
    -VmxPath $targetVmx `
    -ManagementNetwork $ManagementNetwork `
    -SiteANetwork $SiteANetwork `
    -SiteBNetwork $SiteBNetwork `
    -TrunkNetwork $TrunkNetwork `
    -SkipLabNetworkAdapters:$SkipLabNetworkAdapters
if (-not $?) {
    throw "VMware Workstation NIC configuration failed."
}

Write-Host "Created VMware Workstation VM: $Name"
Write-Host "Appliance VMX: $targetVmx"
Write-Host "Attached VCF Offline Depot disk: $resolvedDepotVmdkPath"
Write-Host "Attached VCF Backups disk: $resolvedBackupVmdkPath"
