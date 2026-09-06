<#
.SYNOPSIS
Validate canonical Atlaso VMware payload layout and build provenance.
#>

Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationReadiness.psm1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1')

$script:PhotonPayloadBytes = 40GB
$script:SystemPayloadBytes = 20GB

<#
.SYNOPSIS
Prove a completed template is inactive without starting or stopping it.
.PARAMETER VmxPath
Exact source template whose inactive state is required.
.PARAMETER VmrunPath
Optional VMware vmrun executable; discovered from the standard installation otherwise.
#>
function Assert-AtlasoTemplatePoweredOff {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [string]$VmrunPath = ''
    )
    if (-not $VmrunPath) {
        foreach ($programRoot in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
            if ([string]::IsNullOrWhiteSpace($programRoot)) { continue }
            $candidate = Join-Path $programRoot 'VMware\VMware Workstation\vmrun.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $VmrunPath = $candidate
                break
            }
        }
        if (-not $VmrunPath) {
            $VmrunPath = (Get-Command vmrun -CommandType Application -ErrorAction Stop).Source
        }
    }
    $vmx = Get-Item -LiteralPath $VmxPath -ErrorAction Stop
    if (($vmx.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The source template VMX must be an ordinary file.'
    }
    $identity = Get-AtlasoPathIdentity -Path $vmx.FullName -Description 'source template'
    foreach ($running in @(Get-AtlasoWorkstationRunningVmxPath -VmrunPath $VmrunPath -Deadline (Get-Date).AddSeconds(30))) {
        if ((Get-AtlasoPathIdentity -Path $running -Description 'running VMware VMX') -ceq $identity) {
            throw 'The completed source template is running. Preserve it and rebuild; export never initializes or repairs templates.'
        }
    }
    if ((Get-AtlasoPathIdentity -Path $vmx.FullName -Description 'source template') -cne $identity) {
        throw 'The source template identity changed during powered-off verification.'
    }
    if (@(Get-ChildItem -LiteralPath $vmx.DirectoryName -Filter '*.lck' -Force).Count -gt 0) {
        throw 'The source template has VMware locks; powered-off state is ambiguous.'
    }
    if (@(Get-ChildItem -LiteralPath $vmx.DirectoryName -Filter '*.vmss' -Force).Count -gt 0 -or
        @(Get-Content -LiteralPath $vmx.FullName | Where-Object { $_ -match '^\s*checkpoint\.vmState\s*=\s*"[^"]+"' }).Count -gt 0) {
        throw 'The source template has suspended state; rebuild a fully shut-down template.'
    }
}

<#
.SYNOPSIS
Bind export inputs to the software installed during template construction.
.PARAMETER TemplateContract
Completed-template contract from validated builder provenance.
.PARAMETER SoftwareSource
Verified software-source metadata selected for this export.
#>
function Assert-AtlasoTemplateSoftwareIdentity {
    param(
        [Parameter(Mandatory = $true)][psobject]$TemplateContract,
        [Parameter(Mandatory = $true)][psobject]$SoftwareSource
    )
    $boundSource = $TemplateContract.software_source
    if ($null -eq $boundSource -or
        @($boundSource.PSObject.Properties).Count -ne @($SoftwareSource.PSObject.Properties).Count) {
        throw 'The template lacks exact construction-time software-source evidence. Preserve it and rebuild.'
    }
    foreach ($property in $SoftwareSource.PSObject.Properties) {
        $boundProperty = $boundSource.PSObject.Properties[$property.Name]
        if ($null -eq $boundProperty -or [string]$boundProperty.Value -cne [string]$property.Value) {
            throw 'The template contains different software-source evidence. Preserve it and rebuild.'
        }
    }
}

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
.PARAMETER RequireTemplate
Require the completed uninitialized template contract.
.PARAMETER RequireReleaseBuilder
Reject provenance that was not produced by a protected release builder.
#>
function Assert-AtlasoVmwarePayloadProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [string]$ProvenancePath = '',
        [string]$ExpectedSourceCommit = '',
        [switch]$RequireCleanSource,
        [switch]$RequireReleaseBuilder,
        [switch]$RequireTemplate
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
    if ($RequireTemplate -or $RequireReleaseBuilder) {
        if ($RequireReleaseBuilder -and [string]$provenance.builder_identity.kind -cne 'release') {
            throw 'Protected virtualization release work requires release-builder provenance.'
        }
        $contractProperty = $provenance.PSObject.Properties['template_contract']
        if ($null -eq $contractProperty -or $null -eq $contractProperty.Value -or
            $contractProperty.Value.schema_version -ne 1 -or $contractProperty.Value.state -cne 'uninitialized') {
            throw 'Retained template lacks the uninitialized-template contract. Preserve it and rebuild with current tooling.'
        }
        if ($RequireReleaseBuilder -and ($null -eq $contractProperty.Value.software_source -or
                $contractProperty.Value.software_source.source_commit -cne $provenance.source_commit)) {
            throw 'Release template lacks matching construction-time published-software evidence. Rebuild; do not retrofit it.'
        }
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

Export-ModuleMember -Function @(
    'Assert-AtlasoTemplateSoftwareIdentity',
    'Assert-AtlasoTemplatePoweredOff',
    'Assert-AtlasoVmwarePayloadProvenance',
    'Get-AtlasoVmxValue',
    'Get-AtlasoVmwarePayloadLayout',
    'Get-AtlasoVmdkCapacityBytes'
)
