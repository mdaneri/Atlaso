<#
.SYNOPSIS
Source-pinned private NTP acceptance fixture helpers for run-lifecycle-test.ps1.
.DESCRIPTION
This separate mode retains the lifecycle's original VM/LAN ownership and cleanup.
It never relaxes CertificateDhcpPeer's PR 871 guard or adopts ISO/certificate labs.
#>

if (-not $NtpColdStartOnly) { throw 'NTP fixture helpers require their explicit lifecycle mode.' }
if ($CertificatePeerCidr -cne '192.168.77.1/24' -or $CertificateLeaseAddress -cne '192.168.77.10') {
    throw 'NTP cold-start acceptance currently admits only its documented private IPv4 /24 fixture.'
}
$ntpBaselineAddress = '192.168.77.30'
$ntpCandidateAddress = '192.168.77.40'
$ntpNegativeAddress = '192.168.77.11'
$ntpConsoleReceipts = @{}
$ntpRetainedWheel = $null

<#
.SYNOPSIS
Admit the peer disk from its original, external creation and prepared receipts.
#>
function Assert-NtpPeerSourceOwnership {
    $references = @(
        @{ Path = $NtpPeerSourceReceiptPath; Sha = $NtpPeerSourceReceiptSha256 },
        @{ Path = $NtpPeerPreparedReceiptPath; Sha = $NtpPeerPreparedReceiptSha256 }
    )
    foreach ($reference in $references) {
        # Keep source leaves read-only and every ancestor pinned against replacement,
        # while sibling roots can still publish original ownership receipts.
        $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $reference.Path), $false, $true))
        $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($reference.Path, $true))
        if ((Get-FileHash -LiteralPath $reference.Path -Algorithm SHA256).Hash -ine $reference.Sha) {
            throw 'NTP peer original source receipt digest mismatch.'
        }
        $resolvedReceipt = [IO.Path]::GetFullPath($reference.Path)
        $configuredPrefix = [IO.Path]::GetFullPath($durableOwnershipRoot).TrimEnd('\') + '\'
        # The lifecycle has already independently admitted its durable ownership root.
        # Receipts must remain outside the removable lab and source directories.
        if ($resolvedReceipt.StartsWith(([string]$repoRoot).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not $resolvedReceipt.StartsWith($configuredPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'NTP source provenance must be durable beneath the admitted root and outside the lab.'
        }
    }
    $original = Get-Content -LiteralPath $NtpPeerSourceReceiptPath -Raw | ConvertFrom-Json
    $prepared = Get-Content -LiteralPath $NtpPeerPreparedReceiptPath -Raw | ConvertFrom-Json
    if ($original.schema -ne 1 -or $prepared.schema -ne 1 -or
        $original.task_id -cne $lifecycleTaskId -or $prepared.task_id -cne $lifecycleTaskId -or
        $original.repository -cne 'mdaneri/Atlaso' -or $original.pr -ne $PullRequestNumber -or $prepared.pr -ne $PullRequestNumber -or
        $original.source_commit -cne $prepared.source_commit -or $original.source_commit -notmatch '^[0-9a-f]{40}$' -or
        $prepared.path -cne [IO.Path]::GetFullPath($ClientVmdkPath) -or
        -not $original.path.StartsWith((Join-Path ([string]$repoRoot) 'test-results') + '\', [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Parent $prepared.path) -cne $original.path -or
        $prepared.original_root_receipt -cne (Split-Path -Leaf $NtpPeerSourceReceiptPath) -or
        $prepared.prepared_before_use -ne $true -or @($prepared.consumer_vms).Count -ne 0 -or
        $prepared.format -cne 'monolithicSparse' -or $prepared.parent_cid -ne 4294967295 -or
        $prepared.virtual_size_bytes -ne 2GB -or $prepared.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'NTP peer source ownership or original preparation binding is invalid.'
    }
    & git -C $repoRoot merge-base --is-ancestor $original.source_commit $sourceCommit
    if ($LASTEXITCODE -ne 0) { throw 'NTP peer creation source is not an ancestor of the reviewed harness.' }
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($original.path, $false, $true))
    $identity = @($original.root_identity)
    if ($identity.Count -ne 3 -or (Get-AtlasoPathIdentity -Path $original.path -Description 'original NTP peer source') -cne
        ('{0:X8}:{1:X8}{2:X8}' -f [uint32]$identity[0], [uint32]$identity[1], [uint32]$identity[2])) {
        throw 'NTP peer source directory original identity changed.'
    }
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($ClientVmdkPath, $true))
    if ((Get-FileHash -LiteralPath $ClientVmdkPath -Algorithm SHA256).Hash -ine $prepared.sha256) {
        throw 'NTP peer source disk changed since original preparation.'
    }
}

<#
.SYNOPSIS
Verify the original peer receipts, directory identity and VMX bindings.
#>
function Assert-NtpPeerBootstrapOwnership {
    $peerDirectoryPath = [IO.Path]::GetFullPath($certificatePeerDirectory)
    $peerVmxPath = [IO.Path]::GetFullPath($certificatePeerVmx)
    $ownerHashes = @{}
    foreach ($entry in @(
            @{ Path = $peerDirectoryPath; Kind = 'vm-directory' },
            @{ Path = $peerVmxPath; Kind = 'vm' }
        )) {
        $ownershipMatches = @($originalOwnershipRecords | Where-Object {
                $_.resource -and [IO.Path]::GetFullPath([string]$_.resource) -ieq $entry.Path
            })
        if ($ownershipMatches.Count -ne 1 -or -not $ownershipMatches[0].path -or
            $ownershipMatches[0].sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'NTP peer original lifecycle ownership record is missing or ambiguous.'
        }
        $recordPath = [IO.Path]::GetFullPath($ownershipMatches[0].path)
        $recordItem = Get-Item -LiteralPath $recordPath -Force -ErrorAction Stop
        if ($recordItem.PSIsContainer -or ($recordItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'NTP peer original lifecycle ownership receipt is not an ordinary file.'
        }
        $recordPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($recordPath, $true)
        $runtimeConsumerPins.Add($recordPin)
        if ((Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $ownershipMatches[0].sha256.ToLowerInvariant()) {
            throw 'NTP peer original lifecycle ownership receipt changed.'
        }
        $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $resourceItem = Get-Item -LiteralPath $entry.Path -Force -ErrorAction Stop
        if (($entry.Kind -eq 'vm-directory') -ne [bool]$resourceItem.PSIsContainer -or
            ($resourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'NTP peer original VMX or root changed type.'
        }
        $identity = [Atlaso.WorkstationFileIdentity]::Get($entry.Path)
        $identityMatch = [regex]::Match($identity, '^([0-9A-F]{8}):([0-9A-F]{8})([0-9A-F]{8})$')
        if (-not $identityMatch.Success -or @($record.root_identity).Count -ne 3) {
            throw 'NTP peer original VMX or root identity is invalid.'
        }
        $recordIdentity = '{0:X8}:{1:X8}{2:X8}' -f [uint32]$record.root_identity[0],
            [uint32]$record.root_identity[1], [uint32]$record.root_identity[2]
        # VMware rewrites VMX files during normal power transitions, so the VMX
        # file ID in its immutable creation record is historical evidence. The
        # containing VM directory ID remains the stable namespace authority.
        $identityMismatch = $entry.Kind -eq 'vm-directory' -and $recordIdentity -cne $identity
        if ($record.schema -ne 1 -or $record.kind -cne $entry.Kind -or
            $record.task_id -cne $lifecycleTaskId -or $record.repository -cne 'mdaneri/Atlaso' -or
            $record.pr -ne $PullRequestNumber -or $record.source_commit -cne $sourceCommit -or
            [IO.Path]::GetFullPath([string]$record.path) -ine $entry.Path -or
            [IO.Path]::GetFullPath([string]$record.worktree) -ine [IO.Path]::GetFullPath($repoRoot) -or
            [IO.Path]::GetFullPath([string]$record.lab_root) -ine [IO.Path]::GetFullPath($resultRoot) -or
            $identityMismatch) {
            throw 'NTP peer original lifecycle ownership binding no longer matches its VMX or root.'
        }
        $ownerHashes[$entry.Kind] = $ownershipMatches[0].sha256.ToLowerInvariant()
        if ($entry.Kind -eq 'vm') { $ownerHashes['vmx_birth_identity'] = $recordIdentity }
    }

    $owner = $ntpConsoleReceipts['peer'].Ownership
    if (-not $owner -or -not $owner.Path -or $owner.Sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'NTP peer original owner receipt binding is missing.'
    }
    $ownerPath = [IO.Path]::GetFullPath($owner.Path)
    $ownerItem = Get-Item -LiteralPath $ownerPath -Force -ErrorAction Stop
    if ($ownerItem.PSIsContainer -or ($ownerItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'NTP peer original owner receipt is not an ordinary file.'
    }
    $ownerPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($ownerPath, $true)
    $runtimeConsumerPins.Add($ownerPin)
    if ((Get-FileHash -LiteralPath $ownerPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $owner.Sha256.ToLowerInvariant()) {
        throw 'NTP peer original owner receipt changed.'
    }
    $ownerRecord = Get-Content -LiteralPath $ownerPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $rootIdentity = [Atlaso.WorkstationFileIdentity]::Get($peerDirectoryPath)
    $rootIdentityMatch = [regex]::Match($rootIdentity, '^([0-9A-F]{8}):([0-9A-F]{8})([0-9A-F]{8})$')
    if (-not $rootIdentityMatch.Success -or @($ownerRecord.root_identity).Count -ne 3) {
        throw 'NTP peer original owner directory identity is invalid.'
    }
    $ownerRootIdentity = '{0:X8}:{1:X8}{2:X8}' -f [uint32]$ownerRecord.root_identity[0],
        [uint32]$ownerRecord.root_identity[1], [uint32]$ownerRecord.root_identity[2]
    if ($ownerRecord.schema -ne 1 -or $ownerRecord.kind -cne 'vm' -or
        $ownerRecord.task_id -cne $lifecycleTaskId -or $ownerRecord.repository -cne 'mdaneri/Atlaso' -or
        $ownerRecord.pr -ne $PullRequestNumber -or $ownerRecord.source_commit -cne $sourceCommit -or
        [IO.Path]::GetFullPath([string]$ownerRecord.path) -ine $peerVmxPath -or
        [IO.Path]::GetFullPath([string]$ownerRecord.root_path) -ine $peerDirectoryPath -or
        $ownerRootIdentity -cne $rootIdentity -or $ownerRecord.intent_sha256 -cne $peerIntent.Sha256 -or
        [IO.Path]::GetFullPath([string]$ownerRecord.lab_root) -ine [IO.Path]::GetFullPath($resultRoot)) {
        throw 'NTP peer original owner receipt no longer matches its VMX or directory.'
    }
    Assert-NtpPeerVmConfigBindings
    return [ordered]@{
        vm_directory_identity = $rootIdentity
        vmx_birth_identity = $ownerHashes['vmx_birth_identity']
        vmx_observed_identity = [Atlaso.WorkstationFileIdentity]::Get($peerVmxPath)
        vm_directory_receipt_sha256 = $ownerHashes['vm-directory']
        vmx_receipt_sha256 = $ownerHashes['vm']
        owner_receipt_sha256 = $owner.Sha256.ToLowerInvariant()
    }
}

<#
.SYNOPSIS
Validate the original peer disk, console, clock, display, and network bindings.
#>
function Assert-NtpPeerVmConfigBindings {
    $peerVmxPath = [IO.Path]::GetFullPath($certificatePeerVmx)
    $peerDiskPath = [IO.Path]::GetFullPath($certificatePeerDiskPath)
    $expectedDiskPath = [IO.Path]::GetFullPath((Join-Path $certificatePeerDirectory "$clientAName.vmdk"))
    if ($peerDiskPath -ine $expectedDiskPath -or -not (Test-Path -LiteralPath $peerDiskPath -PathType Leaf) -or
        [Atlaso.WorkstationFileIdentity]::Get($peerDiskPath) -cne $certificatePeerDiskIdentity) {
        throw 'NTP peer copied disk identity changed.'
    }
    $peerDiskName = Split-Path -Leaf $peerDiskPath
    $managementNetwork = [string]$ManagementNetwork
    if ($managementNetwork -match '^(?i)vmnet(\d+)$') { $managementNetwork = "VMnet$($Matches[1])" }
    if ($managementNetwork -notmatch '^(?i)VMnet\d+$' -or $SiteANetwork -notlike 'lan:?*' -or
        $ownedLanSegments.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$ownedLanSegments[0].Id)) {
        throw 'NTP peer original private LAN binding is unavailable.'
    }
    $expected = @(
        @('displayName', [string]$clientAName),
        @('sata0:0.present', 'TRUE'), @('sata0:0.fileName', $peerDiskName), @('sata0:0.deviceType', 'disk'),
        @('ethernet0.present', 'TRUE'), @('ethernet0.connectionType', 'custom'), @('ethernet0.vnet', $managementNetwork),
        @('ethernet1.present', 'TRUE'), @('ethernet1.connectionType', 'pvn'), @('ethernet1.pvnID', [string]$ownedLanSegments[0].Id),
        @('serial0.present', 'TRUE'), @('serial0.fileType', 'file'),
        @('serial0.fileName', [string]$ntpConsoleReceipts['peer'].Path), @('serial0.startConnected', 'TRUE'),
        @('serial0.yieldOnMsrRead', 'TRUE'), @('rtc.diffFromUTC', '0'), @('tools.syncTime', 'FALSE'),
        @('time.synchronize.continue', 'FALSE'), @('time.synchronize.restore', 'FALSE'),
        @('time.synchronize.resume.disk', 'FALSE'), @('time.synchronize.shrink', 'FALSE'),
        @('time.synchronize.tools.startup', 'FALSE'), @('time.synchronize.tools.enable', 'FALSE'),
        @('time.synchronize.resume.host', 'FALSE')
    )
    $vmxLines = @(Get-Content -LiteralPath $peerVmxPath -ErrorAction Stop)
    foreach ($assignment in $expected) {
        $key = [string]$assignment[0]
        $expectedLine = "$key = $(ConvertTo-VmxString -Value ([string]$assignment[1]))"
        $matchingLines = @($vmxLines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($key) + '\s*=') })
        if ($matchingLines.Count -ne 1 -or $matchingLines[0] -cne $expectedLine) {
            throw 'NTP peer VMX no longer matches its admitted disk, console, time, or network bindings.'
        }
    }
}

<#
.SYNOPSIS
Validate the pinned peer seed and exact original VMX CD-ROM attachment.
.PARAMETER SeedSnapshot
The immutable path, hash, identity, and attachment captured before first boot.
#>
function Assert-NtpPeerSeedSnapshot {
    param([Parameter(Mandatory)][object]$SeedSnapshot)

    $seedPath = [IO.Path]::GetFullPath([string]$SeedSnapshot.path)
    if ($seedPath -ine [IO.Path]::GetFullPath($certificatePeerSeedIso) -or
        -not $SeedSnapshot.Pin -or $SeedSnapshot.Pin.IsClosed -or $SeedSnapshot.Pin.IsInvalid) {
        throw 'NTP peer seed pin or original path is unavailable.'
    }
    $seedItem = Get-Item -LiteralPath $seedPath -Force -ErrorAction Stop
    if ($seedItem.PSIsContainer -or ($seedItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'NTP peer seed is not the original ordinary file.'
    }
    if ((Get-FileHash -LiteralPath $seedPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $SeedSnapshot.sha256 -or [Atlaso.WorkstationFileIdentity]::Get($seedPath) -cne $SeedSnapshot.file_identity) {
        throw 'NTP peer seed content or file identity changed.'
    }
    $expectedAttachment = @(
        "sata0:1.present = $(ConvertTo-VmxString -Value 'TRUE')",
        "sata0:1.fileName = $(ConvertTo-VmxString -Value $seedPath)",
        "sata0:1.deviceType = $(ConvertTo-VmxString -Value 'cdrom-image')",
        "sata0:1.startConnected = $(ConvertTo-VmxString -Value 'TRUE')"
    )
    $vmxLines = @(Get-Content -LiteralPath $certificatePeerVmx -ErrorAction Stop)
    foreach ($expected in $expectedAttachment) {
        $key = ($expected -split ' = ', 2)[0]
        $attachmentLines = @($vmxLines | Where-Object { $_ -match ('^\s*' + [regex]::Escape($key) + '\s*=') })
        if ($attachmentLines.Count -ne 1 -or $attachmentLines[0] -cne $expected) {
            throw 'NTP peer original seed is no longer attached to the original VMX.'
        }
    }
}

<#
.SYNOPSIS
Bind a new VM's public-identity serial console before its first boot.
.PARAMETER Vmx
Exact original task-owned VMX.
.PARAMETER Role
Appliance or peer identity.
#>
function Initialize-NtpFixtureConsole {
    param([Parameter(Mandatory)][string]$Vmx, [Parameter(Mandatory)][ValidateSet('appliance', 'peer')][string]$Role)
    if (Test-WorkstationVmRunning -Path $Vmx) { throw 'NTP console admission requires the original VM powered off.' }
    $serial = Join-Path (Split-Path -Parent $Vmx) 'ntp-public-identity.serial'
    if (Test-Path -LiteralPath $serial) { throw 'NTP public console path already exists; preserve original evidence.' }
    $owner = if ($Role -ceq 'appliance') { $certificateOwnership } else { $peerOwnership }
    $seedSnapshot = $null
    if ($Role -ceq 'peer') {
        if ([IO.Path]::GetFullPath($Vmx) -ine [IO.Path]::GetFullPath($certificatePeerVmx)) {
            throw 'NTP peer console must bind the original lifecycle VMX.'
        }
        $seedPath = [IO.Path]::GetFullPath($certificatePeerSeedIso)
        $seedItem = Get-Item -LiteralPath $seedPath -Force -ErrorAction Stop
        if ($seedItem.PSIsContainer -or ($seedItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'NTP peer seed must be an ordinary file before first boot.'
        }
        $seedPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($seedPath, $true)
        try {
            $seedHash = (Get-FileHash -LiteralPath $seedPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $seedIdentity = [Atlaso.WorkstationFileIdentity]::Get($seedPath)
            $seedEvidence = [ordered]@{
                path = $seedPath; sha256 = $seedHash; file_identity = $seedIdentity
                attachment = [ordered]@{
                    present = 'TRUE'; file_name = $seedPath; device_type = 'cdrom-image'; start_connected = 'TRUE'
                }
            }
            $seedSnapshot = [pscustomobject]@{
                path = $seedPath; sha256 = $seedHash; file_identity = $seedIdentity
                attachment = $seedEvidence.attachment; Pin = $seedPin
            }
            Assert-NtpPeerSeedSnapshot -SeedSnapshot $seedSnapshot
        } catch {
            $seedPin.Dispose()
            throw
        }
    }
    try {
        $intentValue = [ordered]@{
            schema = 1; kind = 'ntp-public-console-intent'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
            pr = $PullRequestNumber; source_commit = $sourceCommit; vmx = $Vmx; vm_ownership_sha256 = $owner.Sha256
            serial_path = $serial; observation = 'original-vmx-bound-public-serial-console'
        }
        if ($Role -ceq 'peer') { $intentValue['seed'] = $seedEvidence }
        $intent = Write-CertificateLabReceipt -Name "$Role-console-intent.json" -Value $intentValue
        foreach ($entry in @(@('serial0.present', 'TRUE'), @('serial0.fileType', 'file'), @('serial0.fileName', $serial),
                @('serial0.startConnected', 'TRUE'), @('serial0.yieldOnMsrRead', 'TRUE'), @('tools.syncTime', 'FALSE'),
                @('time.synchronize.continue', 'FALSE'), @('time.synchronize.restore', 'FALSE'),
                @('time.synchronize.resume.disk', 'FALSE'), @('time.synchronize.shrink', 'FALSE'),
                @('time.synchronize.tools.startup', 'FALSE'), @('time.synchronize.tools.enable', 'FALSE'),
                @('time.synchronize.resume.host', 'FALSE'))) {
            Set-VmxValue -Path $Vmx -Key $entry[0] -Value $entry[1]
        }
        if ($Role -ceq 'peer') {
            # Alpine reads the RTC as UTC before apk verifies HTTPS. Use host UTC
            # at first boot so the host's local offset cannot invalidate TLS.
            Set-VmxValue -Path $Vmx -Key 'rtc.diffFromUTC' -Value '0'
        }
        $ntpConsoleReceipts[$Role] = @{
            Intent = $intent; Vmx = $Vmx; Path = $serial; Ownership = $owner
            Seed = $seedSnapshot
        }
    } catch {
        if ($seedSnapshot -and $seedSnapshot.Pin -and -not $seedSnapshot.Pin.IsClosed) { $seedSnapshot.Pin.Dispose() }
        throw
    }
}

<#
.SYNOPSIS
Release the peer seed identity pin after readiness or before failure cleanup.
#>
function Release-NtpPeerBootstrapSeedPin {
    $consoleVariable = Get-Variable -Name ntpConsoleReceipts -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $consoleVariable) { return }
    $peerConsole = $consoleVariable['peer']
    if (-not $peerConsole) { return }
    $seedSnapshot = $peerConsole.Seed
    if ($seedSnapshot -and $seedSnapshot.Pin -and -not $seedSnapshot.Pin.IsClosed) {
        $seedSnapshot.Pin.Dispose()
    }
}

<#
.SYNOPSIS
Restart the NTP peer once after its first-boot VMware Tools installation.
#>
function Invoke-NtpPeerPostToolsBootstrapRestart {
    if (-not $NtpColdStartOnly) { throw 'NTP peer bootstrap restart requires the NTP-only lifecycle mode.' }
    $console = $ntpConsoleReceipts['peer']
    if (-not $console -or -not $console.Observation -or -not $console.Seed) {
        throw 'NTP peer serial identity and preboot seed evidence are required before bootstrap restart.'
    }
    $evidenceRoot = Join-Path $durableOwnershipRoot "$LabName-ntp-native"
    $intentPath = Join-Path $evidenceRoot 'peer-tools-bootstrap-restart-intent.json'
    $terminalPath = Join-Path $evidenceRoot 'peer-tools-bootstrap-restart-terminal.json'
    if ((Test-Path -LiteralPath $intentPath) -or (Test-Path -LiteralPath $terminalPath)) {
        throw 'NTP peer bootstrap restart journal already exists; retries are refused.'
    }

    $ownerEvidence = Assert-NtpPeerBootstrapOwnership
    Assert-NtpPeerSeedSnapshot -SeedSnapshot $console.Seed
    if (-not (Test-WorkstationVmRunning -Path $certificatePeerVmx)) {
        throw 'NTP peer must be running after first-boot public identity capture.'
    }
    $intent = Write-CertificateLabReceipt -Name 'peer-tools-bootstrap-restart-intent.json' -Value ([ordered]@{
        schema = 1; kind = 'ntp-peer-tools-bootstrap-restart-intent'; task_id = $lifecycleTaskId
        repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber; source_commit = $sourceCommit
        peer_vmx = $certificatePeerVmx; peer_owner_receipt_sha256 = $console.Ownership.Sha256
        peer_directory_identity = $ownerEvidence.vm_directory_identity
        peer_vmx_birth_identity = $ownerEvidence.vmx_birth_identity
        peer_vmx_observed_identity = $ownerEvidence.vmx_observed_identity
        lifecycle_directory_receipt_sha256 = $ownerEvidence.vm_directory_receipt_sha256
        lifecycle_vmx_receipt_sha256 = $ownerEvidence.vmx_receipt_sha256
        console_identity_receipt_sha256 = $console.Observation.Sha256
        seed_path = $console.Seed.path; seed_sha256 = $console.Seed.sha256
        seed_file_identity = $console.Seed.file_identity; seed_attachment = $console.Seed.attachment
        action = 'one-soft-stop-verified-off-one-start'; cloud_init_state = 'not-observed-before-restart'
    })
    $stage = 'soft-stop'
    try {
        if (-not (Stop-WorkstationVmForSeedCleanup -Path $certificatePeerVmx)) {
            throw 'NTP peer was not stopped by the required soft-stop operation.'
        }
        if (Test-WorkstationVmRunning -Path $certificatePeerVmx) {
            throw 'NTP peer exact off-state proof failed after soft stop.'
        }
        $stage = 'post-stop-revalidation'
        $ownerEvidence = Assert-NtpPeerBootstrapOwnership
        Assert-NtpPeerSeedSnapshot -SeedSnapshot $console.Seed
        $stage = 'single-start'
        Start-WorkstationVm -Path $certificatePeerVmx
        if (-not (Test-WorkstationVmRunning -Path $certificatePeerVmx)) {
            throw 'NTP peer did not enter the running state after its single bootstrap restart.'
        }
        $stage = 'terminal-publication'
        $terminal = Write-CertificateLabReceipt -Name 'peer-tools-bootstrap-restart-terminal.json' -Value ([ordered]@{
            schema = 1; kind = 'ntp-peer-tools-bootstrap-restart-terminal'; task_id = $lifecycleTaskId
            repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber; source_commit = $sourceCommit
            restart_intent_sha256 = $intent.Sha256; peer_vmx = $certificatePeerVmx
            peer_directory_identity = $ownerEvidence.vm_directory_identity
            peer_vmx_birth_identity = $ownerEvidence.vmx_birth_identity
            peer_vmx_observed_identity = $ownerEvidence.vmx_observed_identity
            seed_path = $console.Seed.path; seed_sha256 = $console.Seed.sha256
            seed_file_identity = $console.Seed.file_identity; seed_attached = $true
            state = 'awaiting-tools-ssh'; cloud_init_state = 'not-observed'; ready = $false
            next_required_gate = 'vmware-tools-address-strict-pinned-ssh-cloud-init-completion'
        })
        return $terminal
    } catch {
        $restartFailure = $_
        if (-not (Test-Path -LiteralPath $terminalPath)) {
            try {
                $null = Write-CertificateLabReceipt -Name 'peer-tools-bootstrap-restart-terminal.json' -Value ([ordered]@{
                    schema = 1; kind = 'ntp-peer-tools-bootstrap-restart-terminal'; task_id = $lifecycleTaskId
                    repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber; source_commit = $sourceCommit
                    restart_intent_sha256 = $intent.Sha256; peer_vmx = $certificatePeerVmx
                    state = 'failed-no-retry'; failure_stage = $stage; ready = $false
                    cloud_init_state = 'not-observed'
                })
            } catch {
                Write-Warning 'NTP peer restart failure could not publish terminal evidence; its immutable intent remains and retry is refused.'
            }
        }
        throw $restartFailure
    }
}

<#
.SYNOPSIS
Read only a bounded public Ed25519 marker from the exact admitted serial console.
.PARAMETER Role
Appliance or peer original console binding.
#>
function Get-NtpConsolePublicKey {
    param([Parameter(Mandatory)][ValidateSet('appliance', 'peer')][string]$Role)
    $console = $ntpConsoleReceipts[$Role]
    if (-not $console -or -not (Test-WorkstationVmRunning -Path $console.Vmx)) { throw 'NTP original console VM is unavailable.' }
    $deadline = (Get-Date).AddSeconds(300)
    do {
        if (Test-Path -LiteralPath $console.Path -PathType Leaf) {
            $file = Get-Item -LiteralPath $console.Path -Force
            $maximumConsoleBytes = 1MB
            if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'NTP public console is a reparse point.'
            }
            if ($file.Length -gt $maximumConsoleBytes) {
                throw 'NTP public console exceeds its 1 MiB bound.'
            }
            # The serial console can keep growing while the guest boots. Read at
            # most one byte beyond the cap and share writes, but never deletion.
            $buffer = [byte[]]::new($maximumConsoleBytes + 1)
            $stream = [IO.FileStream]::new(
                $console.Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite
            )
            try {
                $bytesRead = 0
                while ($bytesRead -lt $buffer.Length) {
                    $readCount = $stream.Read($buffer, $bytesRead, $buffer.Length - $bytesRead)
                    if ($readCount -eq 0) { break }
                    $bytesRead += $readCount
                }
            } finally {
                $stream.Dispose()
            }
            if ($bytesRead -gt $maximumConsoleBytes) {
                throw 'NTP public console exceeds its 1 MiB bound.'
            }
            $bytes = [Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
            $marker = if ($Role -ceq 'appliance') { 'NTP_APPLIANCE' } else { 'CERTIFICATE_PEER' }
            $keyMatches = [regex]::Matches($bytes, "(?m)^ATLASO_$($marker)_ED25519_HOST_KEY_V1 (ssh-ed25519 [A-Za-z0-9+/]+={0,2})\r?`$")
            if ($keyMatches.Count -gt 0) {
                $keys = @($keyMatches | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
                if ($keys.Count -ne 1) { throw 'NTP console reports conflicting public host keys.' }
                return ConvertTo-AtlasoWorkstationSshHostKeyEvidence -PublicKey $keys[0]
            }
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw 'NTP original public-key console observation timed out.'
}

<#
.SYNOPSIS
Establish the peer host key from its serial console before any SSH connection.
#>
function Initialize-NtpPeerConsolePin {
    $key = Get-NtpConsolePublicKey -Role peer
    $stream = [IO.File]::Open($certificatePeerKnownHostsPath, 'CreateNew', 'Write', 'None')
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes("$clientAName $($key.PublicKey)`n")
        $stream.Write($bytes); $stream.Flush($true)
    } finally { $stream.Dispose() }
    $ntpConsoleReceipts['peer']['Observation'] = Write-CertificateLabReceipt -Name 'peer-console-identity.json' -Value ([ordered]@{
        schema = 1; kind = 'ntp-original-console-identity'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
        pr = $PullRequestNumber; source_commit = $sourceCommit; console_intent_sha256 = $ntpConsoleReceipts['peer'].Intent.Sha256
        vmx = $certificatePeerVmx; ssh_host_key = $key.Fingerprint; ssh_public_key = $key.PublicKey
    })
}

<#
.SYNOPSIS
Publish the appliance public host key through its original VMX-bound console.
#>
function Save-NtpApplianceConsoleIdentity {
    $script = "printf 'ATLASO_NTP_APPLIANCE_ED25519_HOST_KEY_V1 ' > /dev/ttyS0; awk '{print `$1, `$2}' /etc/ssh/ssh_host_ed25519_key.pub > /dev/ttyS0"
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
        '-T', 'ws', '-gu', 'root', '-gp', $RootGuestPassword, 'runScriptInGuest', $applianceVmx, '/bin/sh', $script
    ) -TimeoutSeconds 30 -Action 'Publish original NTP appliance public console identity'
    $key = Get-NtpConsolePublicKey -Role appliance
    $receipt = Write-CertificateLabReceipt -Name 'appliance-console-identity.json' -Value ([ordered]@{
        schema = 1; kind = 'ntp-original-console-identity'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
        pr = $PullRequestNumber; source_commit = $sourceCommit; console_intent_sha256 = $ntpConsoleReceipts['appliance'].Intent.Sha256
        vmx = $applianceVmx; ssh_host_key = $key.Fingerprint; ssh_public_key = $key.PublicKey
    })
    $ntpConsoleReceipts['appliance']['Observation'] = $receipt
}

<#
.SYNOPSIS
Retain the measured public wheel before the required NTP appliance reboot.
#>
function Save-NtpRetainedWheel {
    if (-not $NtpColdStartOnly -or $applianceWheel.Name -notmatch '^atlaso-[A-Za-z0-9_.+-]+\.whl$' -or
        $applianceWheel.Sha256 -notmatch '^[a-fA-F0-9]{64}$') {
        throw 'Retained wheel creation requires the admitted NTP fixture build.'
    }
    Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
    if ((Get-FileHash -LiteralPath $certificateOwnership.Path -Algorithm SHA256).Hash -ine $certificateOwnership.Sha256) {
        throw 'Original NTP appliance ownership receipt changed.'
    }
    $owner = Get-Content -LiteralPath $certificateOwnership.Path -Raw | ConvertFrom-Json
    $identity = @($owner.root_identity)
    if ($owner.task_id -cne $lifecycleTaskId -or $owner.repository -cne 'mdaneri/Atlaso' -or
        $owner.pr -ne $PullRequestNumber -or $owner.source_commit -cne $sourceCommit -or
        $owner.path -cne $applianceVmx -or $identity.Count -ne 3 -or
        (Get-AtlasoPathIdentity -Path $owner.root_path -Description 'original NTP appliance directory') -cne
            ('{0:X8}:{1:X8}{2:X8}' -f [uint32]$identity[0], [uint32]$identity[1], [uint32]$identity[2])) {
        throw 'Retained wheel creation lost original NTP appliance ownership.'
    }
    $sourcePath = "/tmp/$($applianceWheel.Name)"
    $guestPath = "/var/lib/atlaso/ntp-acceptance/$($applianceWheel.Name)"
    $verificationPath = Join-Path $resultRoot 'ntp-retained-wheel-verification.txt'
    if (Test-Path -LiteralPath $verificationPath) { throw 'NTP retained-wheel verification already exists.' }
    $digest = $applianceWheel.Sha256.ToLowerInvariant()
    $intent = Write-CertificateLabReceipt -Name 'ntp-wheel-retention-intent.json' -Value ([ordered]@{
        schema = 1; kind = 'ntp-wheel-retention-intent'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
        pr = $PullRequestNumber; source_commit = $sourceCommit; appliance_vmx = $applianceVmx
        appliance_ownership_sha256 = $certificateOwnership.Sha256.ToLowerInvariant()
        deployed_runtime_sha256 = $certificateRuntime.Sha256.ToLowerInvariant()
        source_path = $sourcePath; guest_path = $guestPath; wheel_name = $applianceWheel.Name; wheel_sha256 = $digest
    })
    # /tmp is cleared by the required appliance reboot. Preserve only the measured
    # public wheel in a new root-only directory; never repair or adopt an old path.
    $script = @'
set -eu
source_wheel=__SOURCE__
retained_wheel=__TARGET__
retained_dir=/var/lib/atlaso/ntp-acceptance
test -d /var/lib/atlaso && test ! -L /var/lib/atlaso
test ! -e "$retained_dir" && test ! -L "$retained_dir"
test -f "$source_wheel" && test ! -L "$source_wheel"
printf '%s  %s\n' '__DIGEST__' "$source_wheel" | sha256sum --check --status
install -d -o 0 -g 0 -m 0700 -- "$retained_dir"
install -o 0 -g 0 -m 0600 -- "$source_wheel" "$retained_wheel"
test ! -L "$retained_wheel"
test "$(stat -c '%u:%g:%a:%h' "$retained_wheel")" = '0:0:600:1'
printf '%s  %s\n' '__DIGEST__' "$retained_wheel" | sha256sum --check --status
printf '%s\n' '__DIGEST__' > "$retained_dir/verified.sha256"
'@
    $script = $script.Replace('__SOURCE__', (ConvertTo-GuestShellSingleQuote -Value $sourcePath)).
        Replace('__TARGET__', (ConvertTo-GuestShellSingleQuote -Value $guestPath)).Replace('__DIGEST__', $digest)
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
        '-T', 'ws', '-gu', 'root', '-gp', $RootGuestPassword, 'runScriptInGuest', $applianceVmx, '/bin/sh', $script
    ) -TimeoutSeconds 30 -Action 'Retain original NTP wheel before appliance reboot'
    # VIX operation completion alone does not prove guest script completion.
    # This fresh marker can exist only after both hashes and ownership checks.
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
        '-T', 'ws', '-gu', 'root', '-gp', $RootGuestPassword, 'copyFileFromGuestToHost', $applianceVmx,
        '/var/lib/atlaso/ntp-acceptance/verified.sha256', $verificationPath
    ) -TimeoutSeconds 30 -Action 'Verify original NTP retained wheel completion'
    if (-not (Test-Path -LiteralPath $verificationPath -PathType Leaf) -or
        (Get-Item -LiteralPath $verificationPath).Length -gt 66 -or
        (Get-Content -LiteralPath $verificationPath -Raw).Trim() -cne $digest) {
        throw 'NTP retained wheel guest completion was not verified.'
    }
    Assert-LifecycleSourcePins -Pins $runtimeConsumerPins
    return Write-CertificateLabReceipt -Name 'ntp-retained-wheel.json' -Value ([ordered]@{
        schema = 1; kind = 'ntp-retained-wheel'; task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'
        pr = $PullRequestNumber; source_commit = $sourceCommit; appliance_vmx = $applianceVmx
        appliance_ownership_sha256 = $certificateOwnership.Sha256.ToLowerInvariant()
        deployed_runtime_sha256 = $certificateRuntime.Sha256.ToLowerInvariant(); retention_intent_sha256 = $intent.Sha256
        guest_path = $guestPath; wheel_name = $applianceWheel.Name; wheel_sha256 = $digest
        owner_uid = 0; owner_gid = 0; mode = '0600'; links = 1; verified_before_reboot = $true
    })
}

<#
.SYNOPSIS
Capture public CA bytes from the original VM channel, then launch the pinned consumer.
#>
function Invoke-NtpColdStartAcceptance {
    Save-NtpApplianceConsoleIdentity
    $caPath = Join-Path $resultRoot 'ntp-public-root-ca.pem'
    if (Test-Path -LiteralPath $caPath) { throw 'NTP public CA observation already exists.' }
    $null = Invoke-AtlasoBoundedStreamingProcess -FilePath $resolvedVmrun -DiscardOutput -ArgumentList @(
        '-T', 'ws', '-gu', 'root', '-gp', $RootGuestPassword, 'copyFileFromGuestToHost', $applianceVmx,
        '/etc/atlaso/ca/root.crt', $caPath
    ) -TimeoutSeconds 30 -Action 'Read original NTP appliance public CA'
    if ((Get-Item -LiteralPath $caPath).Length -gt 16384) { throw 'NTP public CA exceeds its bound.' }
    $runtimeConsumerPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($caPath, $true))
    $peerAddress = ($CertificatePeerCidr -split '/')[0]
    $applianceIdentity = Get-Content -LiteralPath $ntpConsoleReceipts['appliance'].Observation.Path -Raw | ConvertFrom-Json
    $peerIdentity = Get-Content -LiteralPath $ntpConsoleReceipts['peer'].Observation.Path -Raw | ConvertFrom-Json
    if ($peerIdentity.ssh_host_key -cne $peerIdentityReadback.ssh_host_key) { throw 'NTP peer key differs from original console.' }
    $reference = { param($value) @{ path = $value.Path; sha256 = $value.Sha256.ToLowerInvariant() } }
    $hostRoot = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'VMware'
    $nativePlan = [ordered]@{
        schema = 1; kind = 'ntp-cold-start-native-plan'; trust_model = 'trusted-host'
        task_id = $lifecycleTaskId; repository = 'mdaneri/Atlaso'; pr = $PullRequestNumber
        source_commit = $sourceCommit; resource_source_commit = $sourceCommit; worktree = [string]$repoRoot
        appliance_intent = (& $reference $certificateIntent); appliance_ownership = (& $reference $certificateOwnership)
        peer_intent = (& $reference $peerIntent); peer_ownership = (& $reference $peerOwnership)
        peer_fixture = (& $reference $peerFixture); peer_identity = (& $reference $certificatePeerIdentity)
        appliance_console = (& $reference $ntpConsoleReceipts['appliance'].Observation)
        peer_console = (& $reference $ntpConsoleReceipts['peer'].Observation)
        deployed_runtime = (& $reference $certificateRuntime); rewired_runtime = (& $reference $rewiredRuntime)
        retained_wheel = (& $reference $ntpRetainedWheel)
        source_creation = @{ path = $NtpPeerSourceReceiptPath; sha256 = $NtpPeerSourceReceiptSha256.ToLowerInvariant() }
        source_prepared = @{ path = $NtpPeerPreparedReceiptPath; sha256 = $NtpPeerPreparedReceiptSha256.ToLowerInvariant() }
        current_address = $CertificateLeaseAddress; baseline_address = $ntpBaselineAddress; static_candidate_address = $ntpCandidateAddress
        negative_address = $ntpNegativeAddress; peer_address = $peerAddress; private_subnet = '192.168.77.0/24'
        username = $AdminUsername; appliance_user = $ApplianceSshUser; appliance_ssh_host_key = $applianceIdentity.ssh_host_key
        ca_path = $caPath; ca_sha256 = (Get-FileHash -LiteralPath $caPath -Algorithm SHA256).Hash.ToLowerInvariant()
        helper_sha256 = $installedHelperSha256; wheel_sha256 = $applianceWheel.Sha256.ToLowerInvariant()
        wheel_name = $applianceWheel.Name
        deployment_measurement = @{ path = (Join-Path $resultRoot 'deployed-runtime-identity.json')
            sha256 = (Get-FileHash -LiteralPath (Join-Path $resultRoot 'deployed-runtime-identity.json') -Algorithm SHA256).Hash.ToLowerInvariant() }
        peer_transport = @{ host = $peerIdentityReadback.management_address; user = $ClientSshUser; ssh_public_key = $certificatePeerPublicKey
            ssh_host_key = $peerIdentity.ssh_host_key; private_subnet = '192.168.77.0/24' }
        trusted_host = @{ host_administrator_trusted = $true; vmrun_path = $resolvedVmrun
            inventory_path = (Join-Path $hostRoot 'inventory.vmls'); preferences_path = (Join-Path $hostRoot 'preferences.ini')
            segment_name = $SiteANetwork.Substring(4); segment_id = $ownedLanSegments[0].Id
            segment_receipt = @{ path = $ownedLanSegments[0].ReceiptPath; sha256 = $ownedLanSegments[0].ReceiptSha256.ToLowerInvariant() }
            appliance_vmx = $applianceVmx; peer_vmx = $certificatePeerVmx
            appliance_management_mac = $certificateAppliancePeerMac
            appliance_service_mac = (Get-VmxEthernetMacAddress -Path $applianceVmx -Index 1).Replace('-', ':')
            peer_private_mac = (Get-VmxEthernetMacAddress -Path $certificatePeerVmx -Index 1).Replace('-', ':')
            peer_control_mac = (Get-VmxEthernetMacAddress -Path $certificatePeerVmx -Index 0).Replace('-', ':')
            control_network = $ManagementNetwork
        }
    }
    $planReceipt = Write-CertificateLabReceipt -Name 'ntp-native-plan.json' -Value $nativePlan
    $exitCode = Invoke-LifecyclePython -Arguments @((Join-Path $runtimeSourceRoot 'scripts/interop/ntp_cold_start_native.py'),
        '--plan', $planReceipt.Path, '--output', $resultRoot) -SourcePins $runtimeConsumerPins `
        -AdminPassword $adminPasswordSecure -RootPassword $rootPasswordSecure -SshPassword $sshPasswordSecure
    if ($exitCode -ne 0) { throw 'NTP cold-start native acceptance failed; preserve immutable journals and reconcile before another Apply.' }
}
