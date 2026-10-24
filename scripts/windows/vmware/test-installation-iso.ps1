<#
.SYNOPSIS
Create, verify, or remove an owned, isolated VMware VM for Atlaso installation ISO testing.
.DESCRIPTION
Creates a receipt-bound, EFI-only VM with an installation ISO, two blank SCSI disks,
no network adapters, and a serial named-pipe endpoint supplied by the caller. Before
first start it records logical-content baselines for both disks. Verify stops the
receipt-bound VM if needed and compares selected disk contents against those baselines.
.PARAMETER Mode
Select Create, Verify, or Cleanup.
.PARAMETER Worktree
Exact clean Atlaso worktree used to bind ownership.
.PARAMETER OutputDirectory
Canonical VM artifact directory beneath Worktree.
.PARAMETER PullRequestNumber
Owning pull request number for this test VM.
.PARAMETER LocalBuilder
Bind ownership as a local development VM instead of a pull-request VM.
.PARAMETER OwnershipRoot
Existing configured durable root for explicit human-run ownership.
.PARAMETER OwnershipTaskId
Exact task identity paired with OwnershipRoot for explicit human-run ownership.
.PARAMETER IsoPath
Pinned installation ISO path required when creating the VM.
.PARAMETER IsoSha256
Expected SHA-256 of the installation ISO.
.PARAMETER SerialPipePath
Pre-created caller-owned local named pipe endpoint for the guest serial port.
.PARAMETER OriginalReceiptPath
Original installation VM receipt path required for cleanup.
.PARAMETER OriginalReceiptSha256
Creation-time digest of OriginalReceiptPath.
.PARAMETER BaselineReceiptPath
Durable disk-baseline receipt path required for verification.
.PARAMETER BaselineReceiptSha256
Creation-time digest of BaselineReceiptPath.
.PARAMETER VmrunPath
Optional exact vmrun executable path.
.PARAMETER VdiskManagerPath
Optional exact vmware-vdiskmanager executable path.
.PARAMETER NoStart
Create the VM without starting it so a console host can attach to the serial pipe.
.PARAMETER VerifyTarget
Also compare the installation target disk with its pre-boot baseline during Verify.
.PARAMETER QemuImgPath
Optional exact qemu-img executable path used for logical disk comparisons.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Create', 'Verify', 'Cleanup')][string]$Mode = 'Create',
    [string]$Worktree = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path,
    [string]$OutputDirectory = '',
    [ValidateRange(0, 2147483647)][int]$PullRequestNumber = 0,
    [switch]$LocalBuilder,
    [string]$OwnershipRoot = '',
    [string]$OwnershipTaskId = '',
    [string]$IsoPath = '',
    [string]$IsoSha256 = '',
    [string]$SerialPipePath = '',
    [string]$OriginalReceiptPath = '',
    [string]$OriginalReceiptSha256 = '',
    [string]$BaselineReceiptPath = '',
    [string]$BaselineReceiptSha256 = '',
    [string]$VmrunPath = '',
    [string]$VdiskManagerPath = '',
    [string]$QemuImgPath = '',
    [switch]$NoStart,
    [switch]$VerifyTarget
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\virtualization\Atlaso.VirtualizationArtifacts.psm1') -Force

<#
.SYNOPSIS
Resolve an installed VMware executable or validate the explicit path.
.PARAMETER Path
Optional executable path supplied by the caller.
.PARAMETER FileName
Executable name to resolve from supported Workstation locations or PATH.
#>
function Resolve-InstallationVmTool {
    param([string]$Path, [string]$FileName)
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$FileName was not found at the selected path." }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    $candidates = @(
        @(
            (Join-Path $env:ProgramFiles "VMware\VMware Workstation\$FileName"),
            (Join-Path ${env:ProgramFiles(x86)} "VMware\VMware Workstation\$FileName")
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
    )
    if ($candidates.Count) { return (Resolve-Path -LiteralPath $candidates[0]).Path }
    $command = Get-Command $FileName -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    throw "$FileName was not found. Install VMware Workstation or pass its exact path."
}

<#
.SYNOPSIS
Quote a value for one VMware VMX assignment.
.PARAMETER Value
Text to encode as one VMX string while preserving spaces and path separators.
#>
function ConvertTo-InstallationVmxString {
    param([Parameter(Mandatory = $true)][string]$Value)
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    '"' + $escaped + '"'
}

<#
.SYNOPSIS
Validate the caller-created local serial named-pipe endpoint.
.PARAMETER Path
Pipe endpoint passed to VMware Workstation.
#>
function Assert-InstallationSerialPipePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path -notmatch '^\\\\\.\\pipe\\Atlaso-Installation-[0-9a-f]{32}$') {
        throw 'SerialPipePath must be the caller-created local Atlaso installation named pipe with a 32-character random suffix.'
    }
}

<#
.SYNOPSIS
Build the complete isolated EFI VM configuration.
.PARAMETER Name
Canonical display name.
.PARAMETER Iso
Pinned installation ISO path.
.PARAMETER TargetDisk
64 GiB target disk path.
.PARAMETER UnselectedDisk
4 GiB untouched disk path.
.PARAMETER SerialPipe
Caller-created local serial named-pipe endpoint.
.PARAMETER CleanupIdentity
Persistent non-secret cleanup identity.
#>
function New-InstallationVmConfiguration {
    param(
        [string]$Name, [string]$Iso, [string]$TargetDisk, [string]$UnselectedDisk,
        [string]$SerialPipe, [string]$CleanupIdentity
    )
    $lines = @(
        '.encoding = "windows-1252"', 'config.version = "8"', 'virtualHW.version = "21"',
        'pciBridge0.present = "TRUE"', 'firmware = "efi"', 'uefi.secureBoot.enabled = "FALSE"',
        "displayName = $(ConvertTo-InstallationVmxString $Name)", 'guestOS = "other5xlinux-64"',
        'memsize = "4096"', 'numvcpus = "2"',
        'scsi0.present = "TRUE"', 'scsi0.virtualDev = "lsilogic"',
        'scsi0:0.present = "TRUE"', "scsi0:0.fileName = $(ConvertTo-InstallationVmxString $TargetDisk)", 'scsi0:0.deviceType = "scsi-hardDisk"',
        'scsi0:1.present = "TRUE"', "scsi0:1.fileName = $(ConvertTo-InstallationVmxString $UnselectedDisk)", 'scsi0:1.deviceType = "scsi-hardDisk"',
        'sata0.present = "TRUE"', 'sata0:0.present = "TRUE"', "sata0:0.fileName = $(ConvertTo-InstallationVmxString $Iso)",
        'sata0:0.deviceType = "cdrom-image"', 'sata0:0.startConnected = "TRUE"',
        'serial0.present = "TRUE"', 'serial0.fileType = "pipe"', ('serial0.fileName = ' + (ConvertTo-InstallationVmxString $SerialPipe)),
        'serial0.pipe.endPoint = "client"', 'serial0.tryNoRxLoss = "FALSE"',
        'ethernet0.present = "FALSE"', ('guestinfo.atlaso.test_vm_cleanup_identity = ' + (ConvertTo-InstallationVmxString $CleanupIdentity))
    )
    return $lines
}

<#
.SYNOPSIS
Resolve a clean task-owned installation VM context.
.PARAMETER Root
Exact Atlaso worktree.
.PARAMETER Destination
Canonical VM artifact directory.
.PARAMETER Name
Canonical Workstation VM name.
#>
function New-InstallationVmContext {
    param([string]$Root, [string]$Destination, [string]$Name)
    $commit = ([string](& git -C $Root rev-parse HEAD 2>$null)).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the exact worktree commit.' }
    $branch = ([string](& git -C $Root branch --show-current 2>$null)).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the exact worktree branch.' }
    New-AtlasoTestVmOwnershipContext -Worktree $Root -OwnershipRoot $OwnershipRoot -OwnershipTaskId $OwnershipTaskId `
        -OutputDirectory $Destination -VmxPath (Join-Path $Destination "$Name.vmx") -Name $Name `
        -SourceCommit $commit -SourceBranch $branch -PullRequestNumber $PullRequestNumber -LocalBuilder:$LocalBuilder
}

<#
.SYNOPSIS
Publish the original installation VM ownership receipt.
.PARAMETER Context
Admitted task-owned VM context with a published intent.
.PARAMETER CleanupIdentity
Persistent non-secret identity embedded in the VMX.
.PARAMETER Iso
Pinned installation ISO path and digest record.
.PARAMETER VmxStream
Exclusive writer handle retained through durable receipt publication.
#>
function Publish-InstallationVmOriginalReceipt {
    param([psobject]$Context, [string]$CleanupIdentity, [psobject]$Iso, [System.IO.FileStream]$VmxStream)
    if (-not $VmxStream -or -not $VmxStream.CanRead -or -not $VmxStream.CanWrite -or
        -not [System.IO.Path]::GetFullPath($VmxStream.Name).Equals([string]$Context.VmxPath, [StringComparison]::OrdinalIgnoreCase) -or
        (Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath ([string]$Context.VmxPath)) -cne $CleanupIdentity) {
        throw 'The installation VMX writer or persistent ownership identity is invalid.'
    }
    $directoryIdentity = [Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory)
    $vmxIdentity = [Atlaso.WorkstationFileIdentity]::Get([string]$Context.VmxPath)
    $record = [ordered]@{
        schema = 1; phase = 'original-installation-vm-created'; task_id = $Context.TaskId
        repository = $Context.Repository; source_branch = $Context.Branch; source_commit = $Context.SourceCommit
        worktree = $Context.Worktree; pull_request_number = $Context.PullRequestNumber; local_builder = $Context.LocalBuilder
        canonical_name = $Context.Name; output_directory = $Context.OutputDirectory; vmx_path = $Context.VmxPath
        original_identities = [ordered]@{ directory = $directoryIdentity; vmx = $vmxIdentity }
        persistent_vm_identity_sha256 = Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value $CleanupIdentity
        installation_iso = $Iso; intent_path = $Context.IntentPath; intent_sha256 = $Context.IntentSha256
        cleanup_tool = 'scripts/windows/vmware/test-installation-iso.ps1 -Mode Cleanup -OriginalReceiptPath <original-path> -OriginalReceiptSha256 <creation-digest>'
        created_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $published = Publish-AtlasoTestVmOwnershipRecord -Context $Context -Record $record -Kind original
    if ([Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory) -cne $directoryIdentity -or
        [Atlaso.WorkstationFileIdentity]::Get([string]$Context.VmxPath) -cne $vmxIdentity) {
        throw 'The installation VM identities changed while publishing the original receipt.'
    }
    [pscustomobject]@{ Path = $published.Path; Sha256 = $published.Sha256; Record = $record }
}

<#
.SYNOPSIS
Read virtual size and filesystem identity for one ordinary VMDK.
.PARAMETER Path
VMDK path pinned while its filesystem identity and logical size are read.
.PARAMETER QemuImg
Resolved qemu-img executable used to inspect the VMDK.
#>
function Get-InstallationDiskEvidence {
    param([string]$Path, [string]$QemuImg)
    if ([IO.Path]::GetExtension($Path) -ine '.vmdk') { throw 'Installation disk evidence must reference a VMDK.' }
    $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true)
    try {
        $identity = [Atlaso.WorkstationFileIdentity]::Get($Path)
        $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $json = (Invoke-AtlasoBoundedProcess -FilePath $QemuImg -ArgumentList @('info', '--output=json', $Path) `
            -TimeoutSeconds 60 -Action 'Inspect installation test disk') -join "`n"
        if (-not $json) { throw 'qemu-img disk inspection returned no bounded result.' }
        $info = $json | ConvertFrom-Json -ErrorAction Stop
        if ($info.format -cne 'vmdk' -or [long]$info.'virtual-size' -le 0) { throw 'Installation test disk is not a nonempty VMDK.' }
        if ([Atlaso.WorkstationFileIdentity]::Get($Path) -cne $identity) { throw 'Installation test disk identity changed during inspection.' }
        [pscustomobject]@{
            path = [IO.Path]::GetFullPath($Path)
            file_identity = $identity
            file_bytes = [long]$file.Length
            virtual_size_bytes = [long]$info.'virtual-size'
            sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    finally { $pin.Dispose() }
}

<#
.SYNOPSIS
Create a standalone logical VMDK baseline and bind it to the original VM receipt.
.PARAMETER Context
Task-bound installation VM context with the original creation receipt.
.PARAMETER Original
Original VM receipt path, digest, and record.
.PARAMETER DiskTool
Resolved qemu-img executable used to create and check logical disk baselines.
.PARAMETER TargetDisk
Newly created installer target VMDK.
.PARAMETER UnselectedDisk
Newly created unselected VMDK.
#>
function Publish-InstallationDiskBaseline {
    param([psobject]$Context, [psobject]$Original, [string]$DiskTool, [string]$TargetDisk, [string]$UnselectedDisk)
    $entries = @()
    foreach ($disk in @(
            [pscustomobject]@{ role = 'target'; source = $TargetDisk; baseline = (Join-Path $Context.OutputDirectory 'target-64g.baseline.vmdk') },
            [pscustomobject]@{ role = 'unselected'; source = $UnselectedDisk; baseline = (Join-Path $Context.OutputDirectory 'unselected-4g.baseline.vmdk') }
        )) {
        if (Test-Path -LiteralPath $disk.baseline) { throw 'Installation disk baseline destination already exists.' }
        $sourceEvidence = Get-InstallationDiskEvidence -Path $disk.source -QemuImg $DiskTool
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $DiskTool -ArgumentList @(
            'convert', '-q', '-f', 'vmdk', '-O', 'vmdk', '-o', 'subformat=monolithicSparse', $disk.source, $disk.baseline
        ) -TimeoutSeconds 600 -Action 'Create installation test disk baseline' -DiscardOutput
        $baselineEvidence = Get-InstallationDiskEvidence -Path $disk.baseline -QemuImg $DiskTool
        if ($baselineEvidence.virtual_size_bytes -ne $sourceEvidence.virtual_size_bytes) { throw 'Installation disk baseline has the wrong virtual size.' }
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $DiskTool -ArgumentList @(
            'compare', '-f', 'vmdk', '-F', 'vmdk', $disk.source, $disk.baseline
        ) -TimeoutSeconds 600 -Action 'Validate installation test disk baseline' -DiscardOutput
        $entries += [ordered]@{ role = $disk.role; source = $sourceEvidence; baseline = $baselineEvidence }
    }
    $record = [ordered]@{
        schema = 1; phase = 'installation-disk-baseline'; task_id = $Context.TaskId
        repository = $Context.Repository; source_branch = $Context.Branch; source_commit = $Context.SourceCommit
        worktree = $Context.Worktree; pull_request_number = $Context.PullRequestNumber; local_builder = $Context.LocalBuilder
        canonical_name = $Context.Name; output_directory = $Context.OutputDirectory; vmx_path = $Context.VmxPath
        original_receipt_path = $Original.Path; original_receipt_sha256 = $Original.Sha256
        original_directory_identity = [string]$Original.Record.original_identities.directory
        persistent_vm_identity_sha256 = [string]$Original.Record.persistent_vm_identity_sha256
        disks = $entries; created_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $Context | Add-Member -NotePropertyName InvocationId -NotePropertyValue ([guid]::NewGuid().ToString('N')) -Force
    Publish-AtlasoTestVmOwnershipRecord -Context $Context -Record $record -Kind installation-baseline
}

<#
.SYNOPSIS
Compare a current VM disk against its receipt-bound logical baseline.
.PARAMETER Disk
One disk's source and baseline evidence from the durable baseline record.
.PARAMETER Role
Expected disk role, target or unselected.
.PARAMETER OutputDirectory
Exact receipt-bound VM artifact directory.
.PARAMETER QemuImg
Resolved qemu-img executable used for logical comparison.
#>
function Assert-InstallationDiskUnchanged {
    param([psobject]$Disk, [string]$Role, [string]$OutputDirectory, [string]$QemuImg)
    $expectedName = if ($Role -ceq 'target') { 'target-64g.vmdk' } else { 'unselected-4g.vmdk' }
    $expectedBaselineName = if ($Role -ceq 'target') { 'target-64g.baseline.vmdk' } else { 'unselected-4g.baseline.vmdk' }
    $sourcePath = Join-Path $OutputDirectory $expectedName
    $baselinePath = Join-Path $OutputDirectory $expectedBaselineName
    if ($Disk.role -cne $Role -or $Disk.source.path -cne $sourcePath -or $Disk.baseline.path -cne $baselinePath) {
        throw 'Installation disk baseline path or role does not match the admitted VM layout.'
    }
    foreach ($evidence in @($Disk.source, $Disk.baseline)) {
        if ([string]$evidence.file_identity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
            [string]$evidence.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [long]$evidence.virtual_size_bytes -le 0) { throw 'Installation disk baseline evidence is malformed.' }
    }
    $baselinePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($baselinePath, $true)
    $diskPin = $null
    try {
        if ([Atlaso.WorkstationFileIdentity]::Get($baselinePath) -cne [string]$Disk.baseline.file_identity -or
            (Get-FileHash -LiteralPath $baselinePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$Disk.baseline.sha256) {
            throw 'Installation disk baseline file changed; no comparison was accepted.'
        }
        $diskPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($sourcePath, $true)
        if ([Atlaso.WorkstationFileIdentity]::Get($sourcePath) -cne [string]$Disk.source.file_identity) {
            throw 'Installation test disk identity changed after baseline creation.'
        }
        $currentEvidence = Get-InstallationDiskEvidence -Path $sourcePath -QemuImg $QemuImg
        if ($currentEvidence.virtual_size_bytes -ne [long]$Disk.source.virtual_size_bytes) {
            throw 'Installation test disk virtual size changed after baseline creation.'
        }
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $QemuImg -ArgumentList @(
            'compare', '-f', 'vmdk', '-F', 'vmdk', $baselinePath, $sourcePath
        ) -TimeoutSeconds 600 -Action "Verify $Role installation disk logical contents" -DiscardOutput
    }
    finally {
        if ($diskPin) { $diskPin.Dispose() }
        $baselinePin.Dispose()
    }
}

<#
.SYNOPSIS
Read and decode one unique path assignment from the receipt-bound VMX.
.PARAMETER VmxLines
Previously read lines from the exact original installation VMX.
.PARAMETER Key
Unique storage-device filename key to read.
#>
function Get-InstallationVmxPathAssignment {
    param([string[]]$VmxLines, [string]$Key)
    $lines = @($VmxLines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($Key) + '\s*=') })
    if ($lines.Count -ne 1 -or $lines[0] -notmatch ('^\s*' + [regex]::Escape($Key) + '\s*=\s*"(?<path>(?:[^"\\]|\\.)+)"\s*$')) {
        throw 'Receipt-bound installation VMX has a missing, duplicated, or malformed storage path.'
    }
    $value = $Matches.path.Replace('\\', '\').Replace('\"', '"')
    if (-not [IO.Path]::IsPathFullyQualified($value)) { throw 'Receipt-bound installation VMX contains a non-absolute storage path.' }
    [IO.Path]::GetFullPath($value)
}

<#
.SYNOPSIS
Require the original VMX to attach only its two receipt-bound test disks and pinned ISO.
.PARAMETER VmxLines
Previously read lines from the exact original installation VMX.
.PARAMETER Context
Current task context with canonical VM name and disk paths.
.PARAMETER IsoPath
Pinned installation ISO path from the original VM receipt.
#>
function Assert-InstallationVmDiskBindings {
    param([string[]]$VmxLines, [psobject]$Context, [string]$IsoPath)
    $assignments = @(
        [pscustomobject]@{ key = 'scsi0:0.fileName'; expected = (Join-Path $Context.OutputDirectory 'target-64g.vmdk') },
        [pscustomobject]@{ key = 'scsi0:1.fileName'; expected = (Join-Path $Context.OutputDirectory 'unselected-4g.vmdk') },
        [pscustomobject]@{ key = 'sata0:0.fileName'; expected = $IsoPath }
    )
    $storageLines = @($VmxLines | Where-Object { $_ -match '^\s*(?:scsi|sata|ide|nvme)\d+:\d+\.fileName\s*=' })
    if ($storageLines.Count -ne $assignments.Count) { throw 'Receipt-bound installation VMX storage-device set changed.' }
    foreach ($assignment in $assignments) {
        $actual = Get-InstallationVmxPathAssignment -VmxLines $VmxLines -Key $assignment.key
        if (-not $actual.Equals([IO.Path]::GetFullPath($assignment.expected), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Receipt-bound installation VMX disk or ISO path changed.'
        }
    }
    $displayName = @($VmxLines | Where-Object { $_ -match '^\s*displayName\s*=' })
    if ($displayName.Count -ne 1 -or $displayName[0] -cne ('displayName = "' + $Context.Name + '"')) {
        throw 'Receipt-bound installation VMX display name changed.'
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    throw 'Pass a canonical -OutputDirectory beneath the exact -Worktree.'
}
$resolvedWorktree = (Resolve-Path -LiteralPath $Worktree).Path
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
$name = if ($PullRequestNumber -gt 0) {
    (New-AtlasoVmwareTestIdentity -PullRequestNumber $PullRequestNumber -Purpose installation-iso).Name
} else {
    $localCommit = ([string](& git -C $resolvedWorktree rev-parse --short=12 HEAD 2>$null)).Trim()
    if ($LASTEXITCODE -ne 0 -or $localCommit -notmatch '^[0-9a-f]{12}$') { throw 'Could not resolve the local VM name source commit.' }
    $fullLocalCommit = ([string](& git -C $resolvedWorktree rev-parse HEAD 2>$null)).Trim()
    (New-AtlasoVmwareTestIdentity -LocalBuilder -SourceCommit $fullLocalCommit -Purpose installation-iso).Name
}
$context = New-InstallationVmContext -Root $resolvedWorktree -Destination $resolvedOutput -Name $name

if ($Mode -eq 'Verify') {
    $vmxPin = $null
    $rootPin = $null
    try {
        if (-not $OriginalReceiptPath -or $OriginalReceiptSha256 -notmatch '^[0-9a-f]{64}$' -or
            -not $BaselineReceiptPath -or $BaselineReceiptSha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Verify requires the independently preserved original and disk-baseline receipt paths and SHA-256 digests.'
        }
        $original = Read-AtlasoTestVmSealedRecord -Context $context -Path $OriginalReceiptPath -Sha256 $OriginalReceiptSha256 `
            -Phase 'original-installation-vm-created'
        $baseline = Read-AtlasoTestVmSealedRecord -Context $context -Path $BaselineReceiptPath -Sha256 $BaselineReceiptSha256 `
            -Phase 'installation-disk-baseline'
        if ($original.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$original.original_identities.directory -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
            [string]$original.persistent_vm_identity_sha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            [string]$original.installation_iso.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not [IO.Path]::IsPathFullyQualified([string]$original.installation_iso.path)) {
            throw 'Original installation VM receipt is incomplete or malformed.'
        }
        if ([IO.Path]::GetFullPath($OriginalReceiptPath) -cne [string]$baseline.original_receipt_path -or
            $OriginalReceiptSha256 -cne [string]$baseline.original_receipt_sha256 -or
            [string]$baseline.source_commit -cne [string]$original.source_commit -or
            [string]$baseline.original_directory_identity -cne [string]$original.original_identities.directory -or
            [string]$baseline.persistent_vm_identity_sha256 -cne [string]$original.persistent_vm_identity_sha256 -or
            @($baseline.disks).Count -ne 2) {
            throw 'Disk-baseline receipt is not bound to the selected original installation VM receipt.'
        }
        $baselineRoles = @($baseline.disks | ForEach-Object { [string]$_.role } | Sort-Object)
        if (@(Compare-Object -ReferenceObject @('target', 'unselected') -DifferenceObject $baselineRoles).Count -ne 0) {
            throw 'Disk-baseline receipt must bind exactly one target and one unselected disk.'
        }
        if ([Atlaso.WorkstationFileIdentity]::Get($context.OutputDirectory) -cne [string]$original.original_identities.directory) {
            throw 'Installation VM artifact directory no longer matches its creation receipt.'
        }
        $vmxPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($context.VmxPath, $true)
        $rootPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($context.OutputDirectory, $true)
        if ([Atlaso.WorkstationFileIdentity]::Get($context.OutputDirectory) -cne [string]$original.original_identities.directory) {
            throw 'Installation VM artifact directory changed while its verification pin was acquired.'
        }
        $cleanupIdentity = Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath $context.VmxPath
        if ((Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value $cleanupIdentity) -cne [string]$original.persistent_vm_identity_sha256) {
            throw 'Installation VM persistent ownership identity differs from its creation receipt.'
        }
        $vmxLines = @(Get-Content -LiteralPath $context.VmxPath -ErrorAction Stop)
        Assert-InstallationVmDiskBindings -VmxLines $vmxLines -Context $context -IsoPath ([string]$original.installation_iso.path)
        if (-not $PSCmdlet.ShouldProcess($context.VmxPath, 'Stop the receipt-bound installation VM and compare disk contents')) {
            return
        }
        Assert-AtlasoTestVmCheckoutSource -Context $context
        $vmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($context.VmxPath)
        $vmxPin.Dispose()
        $vmxPin = $null
        $vmrun = Resolve-InstallationVmTool -Path $VmrunPath -FileName 'vmrun.exe'
        Confirm-AtlasoWorkstationVmInactive -VmrunPath $vmrun -VmxPath $context.VmxPath -ExpectedIdentity $vmxIdentity
        $vmxPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($context.VmxPath, $true)
        if ([Atlaso.WorkstationFileIdentity]::Get($context.OutputDirectory) -cne [string]$original.original_identities.directory) {
            throw 'Installation VM artifact directory changed while the VM was stopped.'
        }
        $cleanupIdentity = Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath $context.VmxPath
        if ((Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value $cleanupIdentity) -cne [string]$original.persistent_vm_identity_sha256) {
            throw 'Installation VM persistent ownership identity changed while the VM was stopped.'
        }
        $vmxLines = @(Get-Content -LiteralPath $context.VmxPath -ErrorAction Stop)
        Assert-InstallationVmDiskBindings -VmxLines $vmxLines -Context $context -IsoPath ([string]$original.installation_iso.path)
        $qemuImg = Resolve-InstallationVmTool -Path $QemuImgPath -FileName 'qemu-img.exe'
        $roles = @('unselected')
        if ($VerifyTarget) { $roles += 'target' }
        foreach ($role in $roles) {
            $disk = @($baseline.disks | Where-Object { $_.role -ceq $role })
            if ($disk.Count -ne 1) { throw "Disk-baseline receipt must contain exactly one $role disk." }
            Assert-InstallationDiskUnchanged -Disk $disk[0] -Role $role -OutputDirectory $context.OutputDirectory -QemuImg $qemuImg
        }
        [pscustomobject]@{
            ReceiptPath = [IO.Path]::GetFullPath($OriginalReceiptPath)
            BaselineReceiptPath = [IO.Path]::GetFullPath($BaselineReceiptPath)
            VerifiedRoles = [string[]]$roles
            LogicalContentsUnchanged = $true
        }
    }
    finally {
        if ($rootPin) { $rootPin.Dispose() }
        if ($vmxPin) { $vmxPin.Dispose() }
        if ($context.PSObject.Properties['CheckoutSourcePin'] -and $context.CheckoutSourcePin) {
            $context.CheckoutSourcePin.Dispose()
        }
    }
    return
}

if ($Mode -eq 'Cleanup') {
    if (-not $OriginalReceiptPath -or $OriginalReceiptSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Cleanup requires the original receipt path and its independently preserved SHA-256.'
    }
    if (-not [System.IO.Path]::IsPathFullyQualified($OriginalReceiptPath)) { throw 'The original receipt path must be absolute.' }
    $receiptPath = [System.IO.Path]::GetFullPath($OriginalReceiptPath)
    $evidencePrefix = [string]$context.EvidenceDirectory + [System.IO.Path]::DirectorySeparatorChar
    if (-not $receiptPath.StartsWith($evidencePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The original receipt is outside the admitted durable evidence directory.'
    }
    $evidencePin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([string]$context.EvidenceDirectory, $true)
    $receiptPin = $null
    try {
        $receiptPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($receiptPath, $true)
        if ((Get-Item -LiteralPath $receiptPath).Length -gt 65536 -or
            (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash -ine $OriginalReceiptSha256) {
            throw 'Original installation VM receipt differs from its independently preserved creation digest.'
        }
        $record = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        if ($record.schema -ne 1 -or $record.phase -cne 'original-installation-vm-created' -or
            $record.task_id -cne $context.TaskId -or $record.repository -cne $context.Repository -or
            $record.worktree -cne $context.Worktree -or $record.source_branch -cne $context.Branch -or
            $record.source_commit -cnotmatch '^[0-9a-f]{40}$' -or $record.output_directory -cne $context.OutputDirectory -or
            $record.vmx_path -cne $context.VmxPath -or $record.canonical_name -cne $context.Name -or
            [string]$record.original_identities.directory -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
            [string]$record.original_identities.vmx -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$' -or
            [string]$record.persistent_vm_identity_sha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
            -not [System.IO.Path]::IsPathFullyQualified([string]$record.installation_iso.path) -or
            [string]$record.installation_iso.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [long]$record.installation_iso.size -lt 64MB) {
            throw 'Original installation receipt does not match the admitted task and VM.'
        }
        & git -C $context.Worktree merge-base --is-ancestor ([string]$record.source_commit) ([string]$context.SourceCommit) 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Original installation receipt source is not an ancestor of the admitted checkout.' }
        Assert-AtlasoTestVmCheckoutSource -Context $context
        if ($PSCmdlet.ShouldProcess($context.OutputDirectory, 'Remove receipt-bound installation test VM')) {
            $remover = Join-Path $PSScriptRoot 'remove-atlaso-vm.ps1'
            & $remover -VmxPath $context.VmxPath -VmrunPath $VmrunPath -ExpectedName $context.Name `
                -ExpectedRootIdentity ([string]$record.original_identities.directory) `
                -ExpectedPersistentVmIdentitySha256 ([string]$record.persistent_vm_identity_sha256) -Confirm:$false
            if (Test-Path -LiteralPath $context.OutputDirectory) { throw 'VM cleanup returned while the owned artifact directory still exists.' }
        }
    }
    finally {
        if ($receiptPin) { $receiptPin.Dispose() }
        $evidencePin.Dispose()
        if ($context.PSObject.Properties['CheckoutSourcePin'] -and $context.CheckoutSourcePin) {
            $context.CheckoutSourcePin.Dispose()
        }
    }
    return
}

if (($PullRequestNumber -gt 0) -eq [bool]$LocalBuilder) { throw 'Choose exactly one of -PullRequestNumber or -LocalBuilder.' }
if ($IsoSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Creation requires the independently verified installation ISO SHA-256.' }
Assert-InstallationSerialPipePath -Path $SerialPipePath
$isoResolved = (Resolve-Path -LiteralPath $IsoPath -ErrorAction Stop).Path
$isoPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($isoResolved, $true)
$outputPin = $null
try {
    $isoItem = Get-Item -LiteralPath $isoResolved
    if ($isoItem.Length -lt 64MB -or [IO.Path]::GetExtension($isoResolved) -ine '.iso' -or
        (Get-FileHash -LiteralPath $isoResolved -Algorithm SHA256).Hash -ine $IsoSha256) {
        throw 'Installation ISO type, minimum size, or pinned SHA-256 validation failed.'
    }
    $iso = [ordered]@{ path = $isoResolved; filesystem_identity = [Atlaso.WorkstationFileIdentity]::Get($isoResolved); size = $isoItem.Length; sha256 = $IsoSha256.ToLowerInvariant() }
    if (-not $PSCmdlet.ShouldProcess($resolvedOutput, 'Create isolated receipt-bound installation ISO test VM')) { return }

    Assert-AtlasoTestVmCheckoutSource -Context $context
    $context | Add-Member -NotePropertyName InvocationId -NotePropertyValue ([guid]::NewGuid().ToString('N')) -Force
    $intent = [ordered]@{
        schema = 1; phase = 'installation-pending'; task_id = $context.TaskId; repository = $context.Repository
        source_branch = $context.Branch; source_commit = $context.SourceCommit; worktree = $context.Worktree
        pull_request_number = $context.PullRequestNumber; local_builder = $context.LocalBuilder; canonical_name = $context.Name
        output_directory = $context.OutputDirectory; vmx_path = $context.VmxPath; invocation_id = $context.InvocationId
        installation_iso = $iso; cleanup_tool = 'scripts/windows/vmware/test-installation-iso.ps1 -Mode Cleanup'
        created_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $intentPublication = Publish-AtlasoTestVmOwnershipRecord -Context $context -Record $intent -Kind intent
    $context | Add-Member -NotePropertyName IntentPath -NotePropertyValue $intentPublication.Path -Force
    $context | Add-Member -NotePropertyName IntentSha256 -NotePropertyValue $intentPublication.Sha256 -Force
    $outputPin = New-AtlasoTestVmPreparedOutput -Context $context

    $cleanupIdentity = [guid]::NewGuid().ToString('N')
    $targetDisk = Join-Path $resolvedOutput 'target-64g.vmdk'
    $unselectedDisk = Join-Path $resolvedOutput 'unselected-4g.vmdk'
    $vmxLines = New-InstallationVmConfiguration -Name $context.Name -Iso $isoResolved -TargetDisk $targetDisk `
        -UnselectedDisk $unselectedDisk -SerialPipe $SerialPipePath -CleanupIdentity $cleanupIdentity
    $vmxBytes = [Text.UTF8Encoding]::new($false).GetBytes(($vmxLines -join "`n") + "`n")
    $vmxStream = [IO.File]::Open($context.VmxPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try {
        $vmxStream.Write($vmxBytes, 0, $vmxBytes.Length)
        $vmxStream.Flush($true)
        $original = Publish-InstallationVmOriginalReceipt -Context $context -CleanupIdentity $cleanupIdentity -Iso $iso -VmxStream $vmxStream
    }
    finally { $vmxStream.Dispose() }
    Write-Host ("Original installation VM receipt: path={0} sha256={1}" -f $original.Path, $original.Sha256)

    Assert-AtlasoTestVmCheckoutSource -Context $context
    $diskTool = Resolve-InstallationVmTool -Path $VdiskManagerPath -FileName 'vmware-vdiskmanager.exe'
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $diskTool -ArgumentList @('-c', '-s', '64GB', '-a', 'lsilogic', '-t', '0', $targetDisk) `
        -TimeoutSeconds 300 -Action 'Create receipt-bound installation target disk' -DiscardOutput
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $diskTool -ArgumentList @('-c', '-s', '4GB', '-a', 'lsilogic', '-t', '0', $unselectedDisk) `
        -TimeoutSeconds 300 -Action 'Create receipt-bound unselected disk' -DiscardOutput
    $qemuImg = Resolve-InstallationVmTool -Path $QemuImgPath -FileName 'qemu-img.exe'
    $baseline = Publish-InstallationDiskBaseline -Context $context -Original $original -DiskTool $qemuImg `
        -TargetDisk $targetDisk -UnselectedDisk $unselectedDisk
    Write-Host ("Installation disk baseline receipt: path={0} sha256={1}" -f $baseline.Path, $baseline.Sha256)
    $vmrun = Resolve-InstallationVmTool -Path $VmrunPath -FileName 'vmrun.exe'
    if (-not $NoStart) {
        $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $vmrun -ArgumentList @('-T', 'ws', 'start', $context.VmxPath, 'nogui') `
            -TimeoutSeconds 120 -Action 'Start isolated installation ISO test VM' -DiscardOutput
    }
    [pscustomobject]@{
        ReceiptPath = $original.Path
        ReceiptSha256 = $original.Sha256
        BaselineReceiptPath = $baseline.Path
        BaselineReceiptSha256 = $baseline.Sha256
        VmxPath = $context.VmxPath
        DirectoryIdentity = [string]$original.Record.original_identities.directory
        PersistentVmIdentitySha256 = [string]$original.Record.persistent_vm_identity_sha256
    }
}
finally {
    if ($outputPin) { $outputPin.Dispose() }
    if ($context.PSObject.Properties['CheckoutSourcePin'] -and $context.CheckoutSourcePin) {
        $context.CheckoutSourcePin.Dispose()
    }
    $isoPin.Dispose()
}
