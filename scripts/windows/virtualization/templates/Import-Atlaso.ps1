<#
.SYNOPSIS
Import a verified Atlaso Hyper-V ZIP payload as one Generation 2 virtual machine.
.PARAMETER Name
New Hyper-V virtual-machine name.
.PARAMETER ManagementSwitch
Existing Hyper-V switch for the management adapter.
.PARAMETER ServiceSwitch
Existing Hyper-V switch for the services adapter. Defaults to the management switch.
.PARAMETER DestinationRoot
Host directory beneath which a new VM-specific directory is created.
.PARAMETER Start
Start the imported virtual machine after its topology passes post-creation verification.
#>
[CmdletBinding()]
param(
    [string]$Name = 'Atlaso',
    [Parameter(Mandatory = $true)][string]$ManagementSwitch,
    [string]$ServiceSwitch = '',
    [string]$DestinationRoot = "$env:ProgramData\Atlaso\Virtual Machines",
    [switch]$Start
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$packageRoot = (Get-Item -LiteralPath $PSScriptRoot -Force -ErrorAction Stop)
if (-not $packageRoot.PSIsContainer -or
    ($packageRoot.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The extracted package root must be an ordinary directory, not a reparse point.'
}
if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_. -]*$' -or $Name -in @('.', '..')) {
    throw 'Name must be a simple Hyper-V virtual-machine name without path separators.'
}
$serviceSwitchName = if ($ServiceSwitch) { $ServiceSwitch } else { $ManagementSwitch }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    throw "A Hyper-V virtual machine named $Name already exists."
}
foreach ($switchName in @($ManagementSwitch, $serviceSwitchName) | Select-Object -Unique) {
    $switches = @(Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue)
    if ($switches.Count -ne 1) {
        throw "Hyper-V switch does not resolve to exactly one existing switch: $switchName"
    }
}

$manifestPath = Join-Path $packageRoot.FullName 'manifest.json'
$checksumsPath = Join-Path $packageRoot.FullName 'checksums.sha256'
try {
    $manifest = Get-Content -Raw -LiteralPath $manifestPath -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    throw 'manifest.json is missing or invalid JSON.'
}
if ([int]$manifest.schema_version -ne 1 -or
    [string]$manifest.kind -ne 'atlaso-hyperv-artifact' -or
    [string]$manifest.product_version -notmatch '^\d+\.\d+\.\d+$') {
    throw 'The package manifest is not a supported Atlaso Hyper-V artifact.'
}
if ([string]$manifest.source.kind -ne 'atlaso-validated-ova' -or
    [string]$manifest.source.commit -notmatch '^[0-9a-f]{40}$' -or
    [string]$manifest.source.ova_sha256 -notmatch '^[0-9a-f]{64}$' -or
    [int]$manifest.source.ova_validator -ne 1) {
    throw 'The package manifest does not bind a validated canonical OVA source.'
}
if ([string]$manifest.machine.firmware -ne 'uefi' -or
    [bool]$manifest.machine.secure_boot -or
    [int]$manifest.machine.cpu_count -ne 4 -or
    [int]$manifest.machine.memory_mib -ne 4096 -or
    [int]$manifest.machine.nic_count -ne 2 -or
    [string]$manifest.machine.disk_bus -ne 'scsi') {
    throw 'The package machine topology does not match the Atlaso Hyper-V contract.'
}

$expected = @{}
foreach ($line in Get-Content -LiteralPath $checksumsPath -ErrorAction Stop) {
    if ($line -notmatch '^(?<hash>[0-9a-f]{64})  (?<name>[^/\\]+)$') {
        throw 'checksums.sha256 contains an invalid entry.'
    }
    if ($expected.ContainsKey($Matches.name)) {
        throw "checksums.sha256 contains a duplicate entry: $($Matches.name)"
    }
    $expected[$Matches.name] = $Matches.hash
}
$packageFiles = @(Get-ChildItem -LiteralPath $packageRoot.FullName -File -Force |
        Where-Object Name -ne 'checksums.sha256' |
        ForEach-Object Name |
        Sort-Object)
$listedFiles = @($expected.Keys | Sort-Object)
if ($packageFiles.Count -ne 6 -or
    $listedFiles.Count -ne 6 -or
    (Compare-Object -ReferenceObject $packageFiles -DifferenceObject $listedFiles)) {
    throw 'Package contents do not match the exact checksums.sha256 inventory.'
}
foreach ($entry in $expected.GetEnumerator()) {
    $payloadPath = Join-Path $packageRoot.FullName $entry.Key
    $payload = Get-Item -LiteralPath $payloadPath -Force -ErrorAction Stop
    if ($payload.PSIsContainer -or
        ($payload.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Package payload must be an ordinary file: $($entry.Key)"
    }
    $actual = (Get-FileHash -LiteralPath $payload.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.Value) {
        throw "Package checksum mismatch: $($entry.Key)"
    }
}

$expectedRoles = @('photon_os', 'atlaso_system', 'vcf_offline_depot', 'vcf_backups')
$expectedSizes = @(42949672960, 21474836480, 536870912000, 536870912000)
$manifestDisks = @($manifest.disks | Sort-Object scsi_slot)
if ($manifestDisks.Count -ne 4 -or
    (@($manifestDisks | ForEach-Object { [int]$_.scsi_slot }) -join ',') -ne '0,1,2,3') {
    throw 'The package must contain exactly four disks at SCSI slots 0 through 3.'
}
for ($index = 0; $index -lt $manifestDisks.Count; $index++) {
    $disk = $manifestDisks[$index]
    $fileName = [string]$disk.file
    if ([string]$disk.role -ne $expectedRoles[$index] -or
        [string]$disk.format -ne 'vhdx' -or
        [long]$disk.virtual_size_bytes -ne $expectedSizes[$index] -or
        [long]$disk.bytes -le 0 -or
        [string]$disk.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [System.IO.Path]::GetFileName($fileName) -ne $fileName -or
        [System.IO.Path]::GetExtension($fileName) -ne '.vhdx' -or
        -not $expected.ContainsKey($fileName) -or
        $expected[$fileName] -ne [string]$disk.sha256) {
        throw "The disk at SCSI slot $index violates the Atlaso role, size, format, or checksum contract."
    }
}

$destinationRootPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationRoot)
$destinationRootPath = [System.IO.Path]::GetFullPath($destinationRootPath)
if ([System.IO.Path]::GetPathRoot($destinationRootPath) -eq $destinationRootPath) {
    throw 'DestinationRoot must not be a filesystem root.'
}
$cursor = [System.IO.Path]::GetPathRoot($destinationRootPath)
$relativeRoot = [System.IO.Path]::GetRelativePath($cursor, $destinationRootPath)
foreach ($component in $relativeRoot.Split(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.StringSplitOptions]::RemoveEmptyEntries
    )) {
    $cursor = Join-Path $cursor $component
    if (Test-Path -LiteralPath $cursor) {
        $item = Get-Item -LiteralPath $cursor -Force
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "DestinationRoot must traverse only ordinary directories: $cursor"
        }
    }
}
$vmRoot = [System.IO.Path]::GetFullPath((Join-Path $destinationRootPath $Name))
$destinationPrefix = $destinationRootPath.TrimEnd([System.IO.Path]::DirectorySeparatorChar) +
    [System.IO.Path]::DirectorySeparatorChar
if (-not $vmRoot.StartsWith($destinationPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The VM destination escaped DestinationRoot.'
}
if (Test-Path -LiteralPath $vmRoot) {
    throw "Destination already exists: $vmRoot"
}

$vmRootCreated = $false
$vmCreated = $false
$vm = $null
try {
    New-Item -ItemType Directory -Path $vmRoot | Out-Null
    $vmRootCreated = $true
    foreach ($disk in $manifestDisks) {
        $destinationDisk = Join-Path $vmRoot $disk.file
        Copy-Item -LiteralPath (Join-Path $packageRoot.FullName $disk.file) -Destination $destinationDisk
        $inspectedDisk = Get-VHD -Path $destinationDisk -ErrorAction Stop
        if ([string]$inspectedDisk.VhdFormat -ne 'VHDX' -or
            [string]$inspectedDisk.VhdType -ne 'Dynamic' -or
            [long]$inspectedDisk.Size -ne [long]$disk.virtual_size_bytes) {
            throw "Copied disk does not match the required dynamic VHDX capacity: $($disk.file)"
        }
    }

    $vm = New-VM `
        -Name $Name `
        -Generation 2 `
        -NoVHD `
        -Path $vmRoot `
        -MemoryStartupBytes 4GB `
        -SwitchName $ManagementSwitch
    $vmCreated = $true
    Set-VMProcessor -VM $vm -Count 4
    Set-VMFirmware -VM $vm -EnableSecureBoot Off
    Rename-VMNetworkAdapter -VM $vm -Name 'Network Adapter' -NewName 'Management'
    Add-VMNetworkAdapter -VM $vm -Name 'Services' -SwitchName $serviceSwitchName
    foreach ($disk in $manifestDisks) {
        Add-VMHardDiskDrive `
            -VM $vm `
            -ControllerType SCSI `
            -ControllerNumber 0 `
            -ControllerLocation ([int]$disk.scsi_slot) `
            -Path (Join-Path $vmRoot $disk.file)
    }
    $drives = @(Get-VMHardDiskDrive -VM $vm | Sort-Object ControllerLocation)
    if ($drives.Count -ne 4 -or
        (@($drives | ForEach-Object { [int]$_.ControllerLocation }) -join ',') -ne '0,1,2,3') {
        throw 'The created Hyper-V VM does not expose the required ordered four-disk topology.'
    }
    $adapters = @(Get-VMNetworkAdapter -VM $vm)
    $actualSwitches = @($adapters | ForEach-Object SwitchName | Sort-Object) -join ','
    $expectedSwitches = @($ManagementSwitch, $serviceSwitchName) | Sort-Object
    if ($adapters.Count -ne 2 -or
        $actualSwitches -ne ($expectedSwitches -join ',')) {
        throw 'The created Hyper-V VM does not expose the required two-switch topology.'
    }
    Set-VMFirmware -VM $vm -FirstBootDevice $drives[0]
    $verifiedVm = Get-VM -Name $Name -ErrorAction Stop
    if ([int]$verifiedVm.Generation -ne 2 -or
        [long]$verifiedVm.MemoryStartup -ne 4GB -or
        [int](Get-VMProcessor -VM $verifiedVm).Count -ne 4 -or
        (Get-VMFirmware -VM $verifiedVm).SecureBoot -ne 'Off') {
        throw 'The created Hyper-V VM does not match the required generation, CPU, memory, or firmware contract.'
    }
    if ($Start) {
        Start-VM -VM $verifiedVm | Out-Null
    }
    Get-VM -Name $Name
}
catch {
    # Never remove a VM that New-VM did not return to this invocation, even if a concurrent actor used the same name.
    if ($vmCreated -and $null -ne $vm) {
        Remove-VM -VM $vm -Force -ErrorAction Continue
    }
    if ($vmRootCreated -and (Test-Path -LiteralPath $vmRoot)) {
        Remove-Item -LiteralPath $vmRoot -Recurse -Force
    }
    throw
}
