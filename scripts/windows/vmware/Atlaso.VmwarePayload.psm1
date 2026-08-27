<#
.SYNOPSIS
Validate canonical Atlaso VMware payload layout and build provenance.
#>

Set-StrictMode -Version Latest

$script:PhotonPayloadBytes = 40GB
$script:SystemPayloadBytes = 20GB

<#
.SYNOPSIS
Return one unambiguous VMX assignment value.
.PARAMETER Path
VMX file to inspect.
.PARAMETER Key
VMX assignment key.
#>
function Get-AtlasoVmxValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Key
    )

    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*=\s*"(?<value>.*)"\s*$'
    $matchingLines = @(Get-Content -LiteralPath $Path | Where-Object { $_ -match $pattern })
    if ($matchingLines.Count -ne 1) {
        throw "VMware VMX must contain exactly one $Key assignment; found $($matchingLines.Count)."
    }
    $parsed = [regex]::Match(
        $matchingLines[0],
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    return $parsed.Groups['value'].Value
}

<#
.SYNOPSIS
Return the virtual capacity declared by an embedded VMDK descriptor.
.PARAMETER Path
VMDK file to inspect.
#>
function Get-AtlasoVmdkCapacityBytes {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $buffer = [byte[]]::new([Math]::Min([int64]1MB, $stream.Length))
        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
    }
    finally {
        $stream.Dispose()
    }
    $descriptor = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
    $extents = [regex]::Matches($descriptor, '(?im)(?:^|[\r\n\x00])\s*RW\s+(?<sectors>\d+)\s+')
    if ($extents.Count -eq 0) {
        throw "VMware payload disk does not expose a readable VMDK capacity descriptor: $Path"
    }
    [int64]$capacityBytes = 0
    foreach ($extent in $extents) {
        $capacityBytes += [int64]$extent.Groups['sectors'].Value * 512
    }
    return $capacityBytes
}

<#
.SYNOPSIS
Return the verified Photon and system-content payload layout.
.PARAMETER VmxPath
VMX file whose payload topology is validated.
.PARAMETER RequireExactlyTwoVmdks
Require the image directory to contain only the two payload VMDKs.
#>
function Get-AtlasoVmwarePayloadLayout {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [switch]$RequireExactlyTwoVmdks
    )

    $vmx = Get-Item -LiteralPath $VmxPath -ErrorAction Stop
    if ((Get-AtlasoVmxValue -Path $vmx.FullName -Key 'scsi0.virtualDev') -ne 'pvscsi') {
        throw 'VMware payload disks must use the PVSCSI controller.'
    }
    if ($RequireExactlyTwoVmdks) {
        $allVmdks = @(Get-ChildItem -LiteralPath $vmx.DirectoryName -Filter '*.vmdk' -File)
        if ($allVmdks.Count -ne 2) {
            throw "VMware image must contain exactly two payload VMDKs; found $($allVmdks.Count)."
        }
    }

    $contracts = @(
        @{ Role = 'photon_os'; DisplayName = 'Photon OS'; Unit = 0; CapacityBytes = $script:PhotonPayloadBytes },
        @{ Role = 'atlaso_system'; DisplayName = 'Atlaso system content'; Unit = 1; CapacityBytes = $script:SystemPayloadBytes }
    )
    $layout = foreach ($contract in $contracts) {
        $prefix = "scsi0:$($contract.Unit)"
        if ((Get-AtlasoVmxValue -Path $vmx.FullName -Key "$prefix.present") -ne 'TRUE') {
            throw "VMware image does not retain the $($contract.DisplayName) payload at SCSI unit $($contract.Unit)."
        }
        $fileName = Get-AtlasoVmxValue -Path $vmx.FullName -Key "$prefix.fileName"
        if ([string]::IsNullOrWhiteSpace($fileName) -or
            [System.IO.Path]::IsPathRooted($fileName) -or
            [System.IO.Path]::GetFileName($fileName) -ne $fileName -or
            [System.IO.Path]::GetExtension($fileName) -ne '.vmdk') {
            throw "VMware $($contract.DisplayName) payload must reference one local VMDK filename at SCSI unit $($contract.Unit)."
        }
        $disk = Get-Item -LiteralPath (Join-Path $vmx.DirectoryName $fileName) -ErrorAction Stop
        if (($disk.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "VMware $($contract.DisplayName) payload must not be a reparse point: $($disk.FullName)"
        }
        $capacityBytes = Get-AtlasoVmdkCapacityBytes -Path $disk.FullName
        if ($capacityBytes -ne $contract.CapacityBytes) {
            throw "VMware $($contract.DisplayName) payload at SCSI unit $($contract.Unit) must expose $($contract.CapacityBytes) bytes; found $capacityBytes."
        }
        [pscustomobject]@{
            Role          = $contract.Role
            DisplayName   = $contract.DisplayName
            ScsiUnit      = $contract.Unit
            File          = $disk
            CapacityBytes = $capacityBytes
        }
    }
    if ($layout[0].File.FullName -eq $layout[1].File.FullName) {
        throw 'VMware Photon OS and Atlaso system-content payloads resolve to the same VMDK.'
    }
    return @($layout)
}

<#
.SYNOPSIS
Verify role-bound payload provenance against current artifact bytes.
.PARAMETER VmxPath
VMX file whose provenance is validated.
.PARAMETER ProvenancePath
Optional explicit provenance document path.
#>
function Assert-AtlasoVmwarePayloadProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [string]$ProvenancePath = ''
    )

    $vmx = Get-Item -LiteralPath $VmxPath -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($ProvenancePath)) {
        $ProvenancePath = [System.IO.Path]::ChangeExtension($vmx.FullName, 'provenance.json')
    }
    if (-not (Test-Path -LiteralPath $ProvenancePath -PathType Leaf)) {
        throw "VMware build provenance is missing: $ProvenancePath"
    }
    try {
        $provenance = Get-Content -LiteralPath $ProvenancePath -Raw | ConvertFrom-Json
    }
    catch {
        throw "VMware build provenance is invalid: $($_.Exception.Message)"
    }
    if ($provenance.schema_version -ne 2) {
        throw 'VMware build provenance does not contain verified payload-disk roles.'
    }
    if ($provenance.vmx.name -ne $vmx.Name -or
        [long]$provenance.vmx.bytes -ne $vmx.Length -or
        $provenance.vmx.sha256 -ne (Get-FileHash -LiteralPath $vmx.FullName -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'VMware build provenance does not match the source VMX bytes.'
    }

    $layout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $vmx.FullName -RequireExactlyTwoVmdks)
    $records = @($provenance.payload_disks)
    if ($records.Count -ne 2) {
        throw 'VMware build provenance must identify exactly two verified payload-disk roles.'
    }
    foreach ($payload in $layout) {
        $record = @($records | Where-Object {
                $_.role -eq $payload.Role -and [int]$_.scsi_unit -eq $payload.ScsiUnit
            })
        if ($record.Count -ne 1 -or
            $record[0].name -ne $payload.File.Name -or
            [long]$record[0].capacity_bytes -ne $payload.CapacityBytes -or
            [long]$record[0].bytes -ne $payload.File.Length -or
            $record[0].sha256 -ne (Get-FileHash -LiteralPath $payload.File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw "VMware build provenance does not match the verified $($payload.DisplayName) payload at SCSI unit $($payload.ScsiUnit)."
        }
    }
    return $provenance
}

Export-ModuleMember -Function @(
    'Assert-AtlasoVmwarePayloadProvenance',
    'Get-AtlasoVmxValue',
    'Get-AtlasoVmwarePayloadLayout',
    'Get-AtlasoVmdkCapacityBytes'
)
