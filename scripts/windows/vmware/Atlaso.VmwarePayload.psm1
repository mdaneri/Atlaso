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
.PARAMETER ExpectedSourceCommit
Optional exact source commit required by a release caller.
.PARAMETER RequireCleanSource
Reject provenance recorded from a dirty tracked source tree.
.PARAMETER RequireReleaseBuilder
Reject provenance that was not produced by a protected release builder.
#>
function Assert-AtlasoVmwarePayloadProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [string]$ProvenancePath = '',
        [string]$ExpectedSourceCommit = '',
        [switch]$RequireCleanSource,
        [switch]$RequireReleaseBuilder
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
    if ($provenance.schema_version -ne 3) {
        throw 'VMware build provenance does not contain a verified immutable source snapshot, builder identity, and payload-disk roles.'
    }
    if ([string]$provenance.source_commit -notmatch '^[0-9a-f]{40}$' -or
        $null -eq $provenance.tracked_source_dirty) {
        throw 'VMware build provenance does not contain a valid source identity.'
    }
    if ([bool]$provenance.tracked_source_dirty) {
        throw 'VMware build provenance records a dirty tracked source tree.'
    }
    if ($null -eq $provenance.source_snapshot -or
        [int]$provenance.source_snapshot.schema_version -ne 1 -or
        [int]$provenance.source_snapshot.file_count -le 0 -or
        [string]$provenance.source_snapshot.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'VMware build provenance does not contain a valid immutable source snapshot identity.'
    }
    if ($ExpectedSourceCommit -and [string]$provenance.source_commit -cne $ExpectedSourceCommit) {
        throw "VMware build provenance does not identify expected source commit $ExpectedSourceCommit."
    }
    if ($RequireCleanSource -and [bool]$provenance.tracked_source_dirty) {
        throw 'VMware build provenance records a dirty tracked source tree.'
    }
    $identity = $provenance.builder_identity
    $vmxStem = [System.IO.Path]::GetFileNameWithoutExtension($vmx.Name)
    $outputLeaf = [System.IO.Path]::GetFileName($vmx.DirectoryName.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ))
    if ($null -eq $identity -or $identity.schema_version -ne 1 -or
        [string]$identity.name -cne $vmxStem -or [string]$identity.name -cne $outputLeaf -or
        [string]$identity.source_commit -cne [string]$provenance.source_commit -or
        (Get-AtlasoVmxValue -Path $vmx.FullName -Key 'displayName') -cne [string]$identity.name) {
        throw 'VMware build provenance does not bind the output directory, VMX filename, displayName, and source commit to one builder identity.'
    }
    if ([string]$identity.kind -ceq 'pull_request') {
        $null = & git check-ref-format --branch ([string]$identity.source_branch) 2>$null
        $sourceBranchIsValid = $LASTEXITCODE -eq 0
        $expectedTaskName = "Atlaso-PR-$([int]$identity.pull_request_number)-Photon-Builder-VMware"
        if (-not [string]::IsNullOrWhiteSpace([string]$identity.collision_suffix)) {
            $expectedTaskName = "$expectedTaskName-$([string]$identity.collision_suffix)"
        }
        if ([int]$identity.pull_request_number -le 0 -or
            [string]$identity.repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
            -not $sourceBranchIsValid -or
            [string]$identity.collision_suffix -notmatch '^(?:|[a-z0-9]+(?:-[a-z0-9]+)*)$' -or
            [string]$identity.name -cne $expectedTaskName -or
            -not [string]::IsNullOrWhiteSpace([string]$identity.release_version) -or
            [long]$identity.workflow_run_id -ne 0) {
            throw 'VMware task-builder provenance contains an invalid pull-request ownership identity.'
        }
    }
    elseif ([string]$identity.kind -ceq 'local') {
        $null = & git check-ref-format --branch ([string]$identity.source_branch) 2>$null
        $sourceBranchIsValid = $LASTEXITCODE -eq 0
        $expectedLocalName = "Atlaso-Local-$(([string]$identity.source_commit).Substring(0, 12))-Photon-Builder-VMware"
        if (-not [string]::IsNullOrWhiteSpace([string]$identity.collision_suffix)) {
            $expectedLocalName = "$expectedLocalName-$([string]$identity.collision_suffix)"
        }
        if ([int]$identity.pull_request_number -ne 0 -or
            [string]$identity.repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
            -not $sourceBranchIsValid -or
            [string]$identity.collision_suffix -notmatch '^(?:|[a-z0-9]+(?:-[a-z0-9]+)*)$' -or
            [string]$identity.name -cne $expectedLocalName -or
            -not [string]::IsNullOrWhiteSpace([string]$identity.release_version) -or
            [long]$identity.workflow_run_id -ne 0) {
            throw 'VMware local-builder provenance contains an invalid local/test ownership identity.'
        }
    }
    elseif ([string]$identity.kind -ceq 'release') {
        $version = [string]$identity.release_version
        $expectedReleaseName = if ($version -match '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
            "Atlaso-Release-v$($version -replace '\.', '-')-$(([string]$identity.source_commit).Substring(0, 12))-Photon-Builder-VMware"
        }
        else {
            ''
        }
        if ([long]$identity.workflow_run_id -gt 0) {
            $expectedReleaseName = "$expectedReleaseName-run-$([long]$identity.workflow_run_id)"
        }
        if ([string]::IsNullOrWhiteSpace($expectedReleaseName) -or
            [string]$identity.name -cne $expectedReleaseName -or
            [int]$identity.pull_request_number -ne 0 -or
            -not [string]::IsNullOrWhiteSpace([string]$identity.repository) -or
            -not [string]::IsNullOrWhiteSpace([string]$identity.source_branch) -or
            -not [string]::IsNullOrWhiteSpace([string]$identity.collision_suffix) -or
            [long]$identity.workflow_run_id -lt 0) {
            throw 'VMware release-builder provenance contains an invalid version-and-commit ownership identity.'
        }
    }
    else {
        throw 'VMware build provenance contains an unsupported builder identity kind.'
    }
    if ($RequireReleaseBuilder -and [string]$identity.kind -cne 'release') {
        throw 'Protected virtualization release work requires release-builder provenance.'
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

<#
.SYNOPSIS
Refresh role-bound VMware provenance after an admitted software deployment.
.PARAMETER VmxPath
VMX file whose current payload bytes are recorded.
.PARAMETER DeploymentSourcePath
Verified virtualization-source metadata that identifies the deployed software.
.PARAMETER ProvenancePath
Optional explicit provenance document path.
#>
function Update-AtlasoVmwarePayloadProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$DeploymentSourcePath,
        [string]$ProvenancePath = ''
    )

    $vmx = Get-Item -LiteralPath $VmxPath -ErrorAction Stop
    $source = Get-Item -LiteralPath $DeploymentSourcePath -ErrorAction Stop
    if ($source.PSIsContainer) {
        throw 'VMware deployment-source provenance must identify one file.'
    }
    if ([string]::IsNullOrWhiteSpace($ProvenancePath)) {
        $ProvenancePath = [System.IO.Path]::ChangeExtension($vmx.FullName, 'provenance.json')
    }
    try {
        $previous = Get-Content -LiteralPath $ProvenancePath -Raw -ErrorAction Stop | ConvertFrom-Json
    }
    catch {
        throw "VMware build provenance cannot be refreshed: $($_.Exception.Message)"
    }
    if ($previous.schema_version -ne 3 -or
        [string]$previous.source_commit -notmatch '^[0-9a-f]{40}$' -or
        $null -eq $previous.tracked_source_dirty -or
        [bool]$previous.tracked_source_dirty -or
        $null -eq $previous.source_snapshot -or
        [int]$previous.source_snapshot.schema_version -ne 1 -or
        [int]$previous.source_snapshot.file_count -le 0 -or
        [string]$previous.source_snapshot.sha256 -notmatch '^[0-9a-f]{64}$' -or
        $null -eq $previous.builder_identity) {
        throw 'VMware build provenance cannot be refreshed because its source identity is invalid.'
    }

    $payloadLayout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $vmx.FullName -RequireExactlyTwoVmdks)
    $provenance = [ordered]@{
        schema_version                   = 3
        source_commit                    = [string]$previous.source_commit
        tracked_source_dirty             = [bool]$previous.tracked_source_dirty
        source_snapshot                  = [ordered]@{
            schema_version = [int]$previous.source_snapshot.schema_version
            file_count     = [int]$previous.source_snapshot.file_count
            sha256         = [string]$previous.source_snapshot.sha256
        }
        builder_identity                 = $previous.builder_identity
        payload_state                    = 'software-deployed'
        deployment_source_name           = $source.Name
        deployment_source_sha256         = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        vmx                              = [ordered]@{
            name   = $vmx.Name
            bytes  = $vmx.Length
            sha256 = (Get-FileHash -LiteralPath $vmx.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        payload_disks                    = @($payloadLayout | ForEach-Object {
                [ordered]@{
                    role           = $_.Role
                    scsi_unit      = $_.ScsiUnit
                    name           = $_.File.Name
                    capacity_bytes = $_.CapacityBytes
                    bytes          = $_.File.Length
                    sha256         = (Get-FileHash -LiteralPath $_.File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            })
    }
    $temporaryPath = "$ProvenancePath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            (($provenance | ConvertTo-Json -Depth 5) + "`n"),
            [System.Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $ProvenancePath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
    $result = Assert-AtlasoVmwarePayloadProvenance `
        -VmxPath $vmx.FullName `
        -ProvenancePath $ProvenancePath
    return $result
}

Export-ModuleMember -Function @(
    'Assert-AtlasoVmwarePayloadProvenance',
    'Get-AtlasoVmxValue',
    'Get-AtlasoVmwarePayloadLayout',
    'Get-AtlasoVmdkCapacityBytes',
    'Update-AtlasoVmwarePayloadProvenance'
)
