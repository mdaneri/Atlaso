<#
.SYNOPSIS
Create a new offline, receipt-bound certificate peer for an original ISO or OVA appliance.
.DESCRIPTION
Uses public inputs only. Never clones, starts, rewires, or adopts an appliance.
Preserves the legacy PR-871 lifecycle path. A failed creation preserves every original receipt.
.PARAMETER Plan
Absolute public JSON specification with original appliance receipts and independently verified source references.
.PARAMETER PythonPath
Absolute ordinary Python 3.14 executable with the locked pycdlib dependency.
.PARAMETER Mode
Plan is read-only; Create prepares a powered-off peer; Inspect verifies ownership; Cleanup removes that peer; CleanupPrepared removes only its originally receipted empty preparation directory.
.PARAMETER OriginalReceiptPath
Original peer ownership receipt required by Inspect and Cleanup.
.PARAMETER OriginalReceiptSha256
Independently retained creation-time digest of OriginalReceiptPath.
.PARAMETER QemuImgPath
Absolute ordinary qemu-img executable required for independent disk comparison during Create.
.PARAMETER VmrunPath
Absolute vmrun executable used only by the existing checked peer cleanup owner.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][string]$PythonPath,
    [ValidateSet('Plan', 'Create', 'Inspect', 'Cleanup', 'CleanupPrepared')][string]$Mode = 'Plan',
    [string]$OriginalReceiptPath = '',
    [string]$OriginalReceiptSha256 = '',
    [string]$QemuImgPath = '',
    [string]$VmrunPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareTestIdentity.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
. (Join-Path $PSScriptRoot 'Atlaso.TestVmOwnership.ps1')

<#
.SYNOPSIS
Pin an explicit ordinary public file and every ancestor through the operation.
.PARAMETER Path
Absolute existing input path.
.PARAMETER Pins
Invocation-owned handles released in reverse order.
#>
function Add-CertificatePeerPublicPin {
    param([Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$Pins)
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Path -match '(^|[\\/])\.\.([\\/]|$)') {
        throw 'Certificate peer inputs must be explicit absolute paths without traversal.'
    }
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $Path), $true))
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true))
}

<#
.SYNOPSIS
Run a pinned public-only Python consumer with isolation and a finite process-tree deadline.
.PARAMETER Code
Repository-owned Python entry code.
.PARAMETER Arguments
Individual public arguments, never credentials or shell text.
.PARAMETER Root
Pinned source checkout supplying the scripts package.
#>
function Invoke-CertificatePeerPython {
    param([Parameter(Mandatory)][string]$Code, [string[]]$Arguments = @(),
        [Parameter(Mandatory)][string]$Root)
    $bootstrap = 'import sys; assert sys.version_info[:2] == (3, 14), "Python 3.14 required"; sys.path.insert(0, sys.argv.pop(1)); ' + $Code
    return Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList (@('-I', '-B', '-c', $bootstrap, $Root) + $Arguments) `
        -TimeoutSeconds 120 -Action 'Inspect or prepare public certificate-peer inputs' `
        -ClearEnvironmentVariablePrefixes @('PYTHON', 'ATLASO_NATIVE_', 'OP_', 'ONEPASSWORD_', 'GIT_')
}

<#
.SYNOPSIS
Publish a new factory record outside the peer removal root without replacing earlier evidence.
.PARAMETER Context
Source-guarded original task ownership context.
.PARAMETER Record
Public record captured at this creation boundary.
.PARAMETER Kind
Existing durable-publisher record category.
#>
function Publish-CertificatePeerRecord {
    param([Parameter(Mandatory)][psobject]$Context,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Record,
        [Parameter(Mandatory)][ValidateSet('intent', 'original', 'directory')][string]$Kind)
    $publication = $Context.PSObject.Copy()
    $publication | Add-Member InvocationId ([guid]::NewGuid().ToString('N')) -Force
    return Publish-AtlasoTestVmOwnershipRecord -Context $publication -Record $Record -Kind $Kind
}

<#
.SYNOPSIS
Create and receipt an empty peer directory without claiming clone-process ownership.
.PARAMETER Context
Source-guarded task context containing the durable peer intent.
.PARAMETER PlanSha256
Preserved digest of the public factory plan.
#>
function New-CertificatePeerPreparedOutput {
    param([Parameter(Mandatory)][psobject]$Context,
        [Parameter(Mandatory)][string]$PlanSha256)
    $publish = [System.Action[string, string]]{
        param($CreatedPath, $OriginalIdentity)
        $record = [ordered]@{ schema = 1; kind = 'certificate-peer-directory';
            phase = 'original-certificate-peer-directory'; task_id = $Context.TaskId;
            repository = $Context.Repository; source_commit = $Context.SourceCommit;
            worktree = $Context.Worktree; source_branch = $Context.Branch;
            output_directory = $Context.OutputDirectory; vmx_path = $Context.VmxPath;
            canonical_name = $Context.Name; pull_request_number = $Context.PullRequestNumber;
            local_builder = [bool]$Context.LocalBuilder; path = $CreatedPath; original_identity = $OriginalIdentity;
            intent_path = $Context.IntentPath; intent_sha256 = $Context.IntentSha256; plan_sha256 = $PlanSha256;
            cleanup_tool = 'scripts/windows/vmware/create-certificate-peer.ps1 -Mode CleanupPrepared -OriginalReceiptPath <original> -OriginalReceiptSha256 <digest>' }
        $publishedDirectory = Publish-CertificatePeerRecord -Context $Context -Record $record -Kind directory
        Write-Host ('Certificate peer preparation ownership: ' + ($publishedDirectory | ConvertTo-Json -Compress))
    }
    return [Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath($Context.OutputDirectory, $publish)
}

<#
.SYNOPSIS
Convert the retained original Windows identity to the certificate proof tuple.
.PARAMETER Identity
Canonical volume and file-index identity from the owning creation handle.
#>
function ConvertTo-CertificatePeerNativeIdentity {
    param([Parameter(Mandatory)][ValidatePattern('^[0-9A-F]{8}:[0-9A-F]{16}$')][string]$Identity)
    return @([Convert]::ToUInt32($Identity.Substring(0, 8), 16),
        [Convert]::ToUInt32($Identity.Substring(9, 8), 16), [Convert]::ToUInt32($Identity.Substring(17, 8), 16))
}

<#
.SYNOPSIS
Require an open same-repository PR at the exact admitted branch and head before creation.
.PARAMETER Context
Original clean checkout and task binding.
#>
function Assert-CertificatePeerPullRequest {
    param([Parameter(Mandatory)][psobject]$Context)
    $json = Invoke-AtlasoBoundedProcess -FilePath (Get-Command gh -CommandType Application -ErrorAction Stop).Source `
        -ArgumentList @('pr', 'view', [string]$Context.PullRequestNumber, '--repo', 'mdaneri/Atlaso', '--json',
            'state,isDraft,isCrossRepository,headRefOid,headRefName,headRepositoryOwner') `
        -TimeoutSeconds 30 -Action 'Verify exact certificate-peer PR source'
    $pr = $json | ConvertFrom-Json
    if ($pr.state -cne 'OPEN' -or $pr.isDraft -or $pr.isCrossRepository -or
        $pr.headRefOid -cne $Context.SourceCommit -or $pr.headRefName -cne $Context.Branch -or
        $pr.headRepositoryOwner.login -cne 'mdaneri') {
        throw 'Certificate peer creation requires the exact open same-repository PR head.'
    }
}

$pins = [Collections.Generic.List[object]]::new()
$context = $null
$outputPin = $null
try {
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..')).TrimEnd('\', '/')
    Add-CertificatePeerPublicPin -Path $Plan -Pins $pins
    Add-CertificatePeerPublicPin -Path $PythonPath -Pins $pins
    if ((Get-Item -LiteralPath $Plan).Length -gt 32768) { throw 'Certificate peer plan exceeds its bounded size.' }
    $validation = Invoke-CertificatePeerPython -Root $root -Code `
        'from scripts.interop.certificate_peer_factory import main; raise SystemExit(main())' `
        -Arguments @('--plan', $Plan, '--repository', $root, '--shape-only') | ConvertFrom-Json
    if ($validation.task_id -cne $env:CODEX_THREAD_ID) { throw 'The real active task must own the certificate peer.' }
    $head = ([string](& git -C $root rev-parse HEAD)).Trim()
    $branch = ([string](& git -C $root branch --show-current)).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $branch -or ($Mode -in @('Plan', 'Create') -and $head -cne $validation.source_commit)) {
        throw 'Certificate peer factory requires its exact checked-out source head.'
    }
    & git --no-replace-objects -C $root merge-base --is-ancestor $validation.source_commit $head
    if ($LASTEXITCODE -ne 0) { throw 'The original factory plan source is not an ancestor of this checkout.' }
    $suffix = if ($validation.PSObject.Properties['collision_suffix']) { $validation.collision_suffix } else { '' }
    $identity = New-AtlasoVmwareTestIdentity -PullRequestNumber $validation.pr -Purpose certificate-peer -CollisionSuffix $suffix
    $destination = Join-Path $root ('image/vmware-workstation/test-vms/' + $identity.Name)
    $context = New-AtlasoTestVmOwnershipContext -Worktree $root -OutputDirectory $destination `
        -VmxPath (Join-Path $destination ($identity.Name + '.vmx')) -Name $identity.Name `
        -SourceCommit $head -SourceBranch $branch -PullRequestNumber $validation.pr
    if (-not $context.Enabled) { throw 'Certificate peer factory requires original task ownership.' }
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $ova = $validation.PSObject.Properties['appliance_media'] -and $validation.appliance_media -ceq 'ova'
    $applianceReferences = if ($ova) {
        @('appliance_ova_import_readback', 'appliance_ova_isolation', 'appliance_ova_boot')
    } else { @('appliance_installed_boot') }
    foreach ($name in (@('appliance_intent', 'appliance_ownership', 'peer_source_preparation') + $applianceReferences)) {
        $reference = $validation.$name
        Add-CertificatePeerPublicPin -Path $reference.path -Pins $pins
        if ((Get-FileHash -LiteralPath $reference.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $reference.sha256) {
            throw 'An original certificate peer receipt changed before admission.'
        }
    }
    if ($ova) {
        $ownership = Get-Content -LiteralPath $validation.appliance_ownership.path -Raw | ConvertFrom-Json
        $receiptRoot = Split-Path -Parent $validation.appliance_ownership.path
        $invocation = [string]$ownership.invocation_id
        if ($invocation -cnotmatch '^[0-9a-f]{32}$') { throw 'Original OVA invocation is invalid.' }
        foreach ($name in @('process', 'directory', 'terminal')) {
            $phase = Join-Path $receiptRoot "atlaso-test-vm-ova-import-$name-$invocation.json"
            if ($phase -ine $ownership.$name.Path) { throw 'Original OVA phase selector changed.' }
            Add-CertificatePeerPublicPin -Path $phase -Pins $pins
        }
        $boot = Get-Content -LiteralPath $validation.appliance_ova_boot.path -Raw | ConvertFrom-Json
        $isolation = Get-Content -LiteralPath $validation.appliance_ova_isolation.path -Raw | ConvertFrom-Json
        foreach ($reference in @(
                @{ Parent = $validation.appliance_ova_boot.path; Name = $boot.independent_boot.receipt },
                @{ Parent = $validation.appliance_ova_boot.path; Name = $boot.credential_acl.receipt },
                @{ Parent = $validation.appliance_ova_isolation.path; Name = $isolation.result })) {
            if ($reference.Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*\.json$') {
                throw 'Original OVA evidence filename is invalid.'
            }
            Add-CertificatePeerPublicPin -Path (Join-Path (Split-Path -Parent $reference.Parent) $reference.Name) -Pins $pins
        }
    }
    Add-CertificatePeerPublicPin -Path $validation.appliance_vmx -Pins $pins
    Add-CertificatePeerPublicPin -Path $validation.peer_public_key_path -Pins $pins
    $admission = Invoke-CertificatePeerPython -Root $root -Code `
        'from scripts.interop.certificate_peer_factory import main; raise SystemExit(main())' `
        -Arguments @('--plan', $Plan, '--repository', $root) | ConvertFrom-Json
    Add-CertificatePeerPublicPin -Path $admission.source_disk -Pins $pins
    Add-CertificatePeerPublicPin -Path $admission.source_qcow2 -Pins $pins
    if ((Get-FileHash -LiteralPath $admission.source_disk -Algorithm SHA256).Hash.ToLowerInvariant() -cne $validation.peer_vmdk_sha256 -or
        (Get-FileHash -LiteralPath $admission.source_qcow2 -Algorithm SHA512).Hash.ToLowerInvariant() -cne $admission.source_qcow2_sha512 -or
        (Get-FileHash -LiteralPath $validation.peer_public_key_path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $validation.peer_public_key_sha256) {
        throw 'An independently admitted certificate peer source changed before pinning.'
    }
    $keyFile = Get-Item -LiteralPath $validation.peer_public_key_path
    if ($keyFile.Length -gt 1024) { throw 'Certificate peer requires a bounded public key.' }
    $publicKey = (Get-Content -LiteralPath $keyFile.FullName -Raw).Trim()
    if ($publicKey -cnotmatch '^ssh-ed25519 (?<blob>[A-Za-z0-9+/]+={0,2})(?: [^\r\n]{1,128})?$') {
        throw 'Certificate peer requires one Ed25519 public key.'
    }
    $selectedBlob = $Matches.blob
    $planDigest = (Get-FileHash -LiteralPath $Plan -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Mode -eq 'Plan') {
        if (Test-Path -LiteralPath $destination) { throw 'Certificate peer factory never adopts an existing output.' }
        [pscustomobject]@{ Mode = 'Plan'; Name = $identity.Name; VmxPath = $context.VmxPath;
            OriginalIsoAdmitted = (-not $ova); OriginalOvaAdmitted = [bool]$ova; SourceDiskAdmitted = $true; StartsVm = $false; UsesCredentials = $false }
        return
    }
    if ($Mode -eq 'CleanupPrepared') {
        $preparedDirectory = Read-AtlasoTestVmSealedRecord -Context $context -Path $OriginalReceiptPath `
            -Sha256 $OriginalReceiptSha256 -Phase 'original-certificate-peer-directory'
        $creationIntent = Read-AtlasoTestVmSealedRecord -Context $context -Path $preparedDirectory.intent_path `
            -Sha256 $preparedDirectory.intent_sha256 -Phase 'certificate-peer-pending'
        if ($preparedDirectory.path -cne $destination -or $preparedDirectory.plan_sha256 -cne $planDigest -or
            $creationIntent.plan_sha256 -cne $planDigest -or $creationIntent.source_commit -cne $preparedDirectory.source_commit -or
            $preparedDirectory.source_commit -cne $validation.source_commit -or
            [Atlaso.WorkstationFileIdentity]::Get($destination) -cne $preparedDirectory.original_identity) {
            throw 'Original empty peer preparation binding changed; preserve it.'
        }
        if ($PSCmdlet.ShouldProcess($destination, 'Remove only the originally receipted empty peer preparation directory')) {
            Assert-AtlasoTestVmCheckoutSource -Context $context
            # The owning remover refuses any nonempty root, including a VMX whose VM receipt failed to publish.
            Remove-AtlasoWorkstationVmArtifacts -VmrunPath $VmrunPath -VmxPaths @() -RemovalRoot $destination `
                -ExpectedPreparedDirectoryIdentity $preparedDirectory.original_identity -Confirm:$false
        }
        return
    }
    if ($Mode -in @('Inspect', 'Cleanup')) {
        if (-not $OriginalReceiptPath -or $OriginalReceiptSha256 -cnotmatch '^[0-9a-fA-F]{64}$') {
            throw 'Peer inspection and cleanup require both preserved original selectors.'
        }
        $original = Read-AtlasoTestVmSealedRecord -Context $context -Path $OriginalReceiptPath `
            -Sha256 $OriginalReceiptSha256 -Phase 'original-certificate-peer-created'
        if ($original.phase -cne 'original-certificate-peer-created' -or $original.task_id -cne $context.TaskId -or
            $original.pr -ne $validation.pr -or $original.repository -cne $context.Repository -or
            $original.path -cne $context.VmxPath -or $original.root_path -cne $destination -or
            $original.plan_sha256 -cne $planDigest -or $original.source_commit -cne $validation.source_commit -or
            [Atlaso.WorkstationFileIdentity]::Get($destination) -cne $original.original_identities.directory -or
            (Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value (Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath $context.VmxPath)) -cne
                $original.persistent_vm_identity_sha256) {
            throw 'Peer original ownership changed; preserve the peer and its receipts.'
        }
        if ($Mode -eq 'Inspect') {
            [pscustomobject]@{ Mode = 'Inspect'; OriginalOwnershipVerified = $true; VmxPath = $context.VmxPath }
        } elseif ($PSCmdlet.ShouldProcess($context.VmxPath, 'Remove only the originally receipted certificate peer')) {
            Assert-AtlasoTestVmCheckoutSource -Context $context
            # Admission handles are source-only. The owning remover must acquire its own deletion handles.
            & (Join-Path $PSScriptRoot 'remove-atlaso-vm.ps1') -VmxPath $context.VmxPath -ExpectedName $identity.Name `
                -ExpectedRootIdentity $original.original_identities.directory `
                -ExpectedPersistentVmIdentitySha256 $original.persistent_vm_identity_sha256 -VmrunPath $VmrunPath -Confirm:$false
        }
        return
    }
    if ($OriginalReceiptPath -or $OriginalReceiptSha256) { throw 'Create never accepts an existing peer ownership receipt.' }
    if (Test-Path -LiteralPath $destination) { throw 'Certificate peer creation cannot adopt or replace an existing output.' }
    Add-CertificatePeerPublicPin -Path $QemuImgPath -Pins $pins
    Assert-CertificatePeerPullRequest -Context $context
    $agentKeys = (Invoke-AtlasoBoundedProcess -FilePath (Get-Command ssh-add.exe -CommandType Application -ErrorAction Stop).Source `
        -ArgumentList @('-L') -TimeoutSeconds 15 -Action 'Match the selected public peer identity in the SSH agent') -split '\r?\n'
    if (-not @($agentKeys | Where-Object { ($_ -split ' ')[0] -ceq 'ssh-ed25519' -and ($_ -split ' ')[1] -ceq $selectedBlob }).Count) {
        throw 'The selected certificate peer public key must already be available in the SSH agent.'
    }
    $info = Invoke-AtlasoBoundedProcess -FilePath $QemuImgPath -ArgumentList @('info', '--output=json', '-f', 'vmdk', $admission.source_disk) `
        -TimeoutSeconds 30 -Action 'Inspect independent certificate peer source disk' | ConvertFrom-Json
    if ($info.format -cne 'vmdk' -or $info.'virtual-size' -lt 2GB -or $info.'virtual-size' -gt 8GB -or
        $info.PSObject.Properties['backing-filename']) { throw 'Certificate peer source must be a standalone 2 through 8 GiB VMDK.' }
    $null = Invoke-AtlasoBoundedProcess -FilePath $QemuImgPath -ArgumentList @('compare', '-f', 'qcow2', '-F', 'vmdk',
        $admission.source_qcow2, $admission.source_disk) -TimeoutSeconds 120 -Action 'Compare peer disk with checksum-pinned Alpine release' -DiscardOutput
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($destination))
    if ($drive.AvailableFreeSpace -lt [long]$info.'virtual-size' + 2GB -or
        (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB -lt 2GB) {
        throw 'Certificate peer capacity requires its full sparse-disk maximum plus 2 GiB disk and 2 GiB free RAM.'
    }
    if (Get-Process -Name vmware -ErrorAction SilentlyContinue) {
        throw 'Close the Workstation UI normally before creating the peer LAN; no resource was created.'
    }
    if (-not $PSCmdlet.ShouldProcess($destination, 'Create one new offline certificate peer and private LAN with original receipts')) { return }
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $intent = [ordered]@{ schema = 1; kind = 'vm-creation-intent'; phase = 'certificate-peer-pending';
        task_id = $context.TaskId; repository = $context.Repository; pr = $validation.pr; source_commit = $head;
        worktree = $context.Worktree; source_branch = $context.Branch;
        output_directory = $destination; vmx_path = $context.VmxPath; canonical_name = $identity.Name;
        pull_request_number = $validation.pr; local_builder = [bool]$context.LocalBuilder;
        path = $context.VmxPath; root_path = $destination; plan_sha256 = $planDigest;
        source_disk = $admission.source_disk; source_disk_sha256 = $validation.peer_vmdk_sha256;
        cleanup_tool = 'scripts/windows/vmware/create-certificate-peer.ps1 -Mode Cleanup -OriginalReceiptPath <original> -OriginalReceiptSha256 <digest>' }
    $publishedIntent = Publish-CertificatePeerRecord -Context $context -Record $intent -Kind intent
    $context | Add-Member IntentPath $publishedIntent.Path -Force
    $context | Add-Member IntentSha256 $publishedIntent.Sha256 -Force
    $context | Add-Member InvocationId ([guid]::NewGuid().ToString('N')) -Force
    $outputPin = New-CertificatePeerPreparedOutput -Context $context -PlanSha256 $planDigest
    $context | Add-Member CloneOutputPin $outputPin -Force
    $owner = @{ task_id = $context.TaskId; repository = $context.Repository; source_commit = $head;
        pr = $validation.pr; lab_root = $context.PermittedRoot }
    $segment = Resolve-AtlasoOwnedLanSegment -Name ($identity.Name + '-private') -Owner $owner -PublishReceipt {
        param($Receipt)
        $record = [ordered]@{ schema = 1; kind = 'certificate-peer-lan-binding'; task_id = $context.TaskId;
            repository = $context.Repository; pr = $validation.pr; source_commit = $head;
            receipt_path = $Receipt.ReceiptPath; receipt_sha256 = $Receipt.ReceiptSha256; segment_id = $Receipt.Id }
        $published = Publish-CertificatePeerRecord -Context $context -Record $record -Kind directory
        Write-Host ('Certificate peer LAN ownership: ' + ($published | ConvertTo-Json -Compress))
    }
    if (-not $segment.ReceiptPath -or -not $segment.ReceiptSha256) { throw 'An existing shared LAN cannot be adopted by the certificate peer.' }
    $cleanupIdentity = [guid]::NewGuid().ToString('N')
    $macs = @()
    foreach ($index in 0..1) {
        $bytes = [guid]::NewGuid().ToByteArray()
        $macs += ('00:50:56:{0:x2}:{1:x2}:{2:x2}' -f (0x20 -bor ($bytes[0] -band 0x1f)), $bytes[1], $bytes[2])
    }
    $vmxText = Invoke-CertificatePeerPython -Root $root -Code `
        'import json; from scripts.interop.certificate_peer_factory_config import render_vmx; print(json.dumps(render_vmx(json.load(open(sys.argv[1])),name=sys.argv[2],segment_id=sys.argv[3],cleanup_identity=sys.argv[4],macs=(sys.argv[5],sys.argv[6]))))' `
        -Arguments @($Plan, $identity.Name, $segment.Id, $cleanupIdentity, $macs[0], $macs[1]) | ConvertFrom-Json
    $writer = [IO.FileStream]::new($context.VmxPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($vmxText)
        $writer.Write($bytes); $writer.Flush($true)
        $directoryIdentity = $outputPin.GetRetainedCreatedIdentity($destination)
        $original = [ordered]@{ schema = 1; kind = 'vm'; phase = 'original-certificate-peer-created';
            task_id = $context.TaskId; repository = $context.Repository; pr = $validation.pr; source_commit = $head;
            worktree = $context.Worktree; source_branch = $context.Branch;
            output_directory = $destination; vmx_path = $context.VmxPath; canonical_name = $identity.Name;
            pull_request_number = $validation.pr; local_builder = [bool]$context.LocalBuilder;
            path = $context.VmxPath; root_path = $destination; root_identity = (ConvertTo-CertificatePeerNativeIdentity $directoryIdentity);
            original_identities = @{ directory = $directoryIdentity; vmx = [Atlaso.WorkstationFileIdentity]::Get($context.VmxPath) };
            persistent_vm_identity_sha256 = (Get-AtlasoTestVmOwnershipCleanupIdentityHash $cleanupIdentity);
            intent_sha256 = $publishedIntent.Sha256; intent_path = $publishedIntent.Path; plan_sha256 = $planDigest;
            serial_path = (Join-Path $destination ($identity.Name + '-serial.log'));
            lan_receipt_path = $segment.ReceiptPath; lan_receipt_sha256 = $segment.ReceiptSha256;
            cleanup_tool = $intent.cleanup_tool }
        $publishedOriginal = Publish-CertificatePeerRecord -Context $context -Record $original -Kind original
        Write-Host ('Certificate peer original ownership: ' + ($publishedOriginal | ConvertTo-Json -Compress))
    } finally { $writer.Dispose() }
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $targetDisk = Join-Path $destination ($identity.Name + '.vmdk')
    $sourceStream = [IO.FileStream]::new($admission.source_disk, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $diskWriter = [IO.FileStream]::new($targetDisk, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $sourceStream.CopyTo($diskWriter); $diskWriter.Flush($true) } finally { $diskWriter.Dispose() }
    } finally { $sourceStream.Dispose() }
    if ((Get-FileHash -LiteralPath $targetDisk -Algorithm SHA256).Hash.ToLowerInvariant() -cne $validation.peer_vmdk_sha256) {
        throw 'The new peer disk copy differs from the admitted original; preserve the failed creation.'
    }
    $seedPath = Join-Path $destination ($identity.Name + '-seed.iso')
    $seedArguments = @('--output', $seedPath, '--hostname', $validation.peer_hostname, '--user', $validation.peer_user,
        '--public-key', $publicKey, '--server-cidr', $validation.server_cidr, '--lease-address', $validation.lease_address,
        '--client-mac', $validation.appliance_mac, '--publish-host-key-to-serial', '--instance-id', $context.InvocationId,
        '--serve-ntp', '--vmware-vix', '--retain-instance-cache', '--no-dhcp-router')
    foreach ($address in $validation.management_addresses) { $seedArguments += @('--management-address', $address) }
    $null = Invoke-CertificatePeerPython -Root $root -Code `
        'import runpy; from pathlib import Path; entry=Path(sys.path[0])/"scripts/interop/create_certificate_peer_seed_iso.py"; sys.path.insert(0,str(entry.parent)); sys.argv=[str(entry),*sys.argv[1:]]; runpy.run_path(str(entry),run_name="__main__")' `
        -Arguments $seedArguments
    $prepared = [ordered]@{ schema = 1; kind = 'certificate-dhcp-peer-fixture'; task_id = $context.TaskId;
        repository = $context.Repository; pr = $validation.pr; source_commit = $head; peer_vmx = $context.VmxPath;
        peer_ownership_sha256 = $publishedOriginal.Sha256; appliance_vmx = $validation.appliance_vmx;
        appliance_ownership_sha256 = $validation.appliance_ownership.sha256;
        private_network = ('lan:' + $identity.Name + '-private'); peer_cidr = $validation.server_cidr;
        management_network = $validation.management_vmnet; lease_address = $validation.lease_address;
        appliance_mac = $validation.appliance_mac; ssh_public_key = $publicKey;
        address_ownership_state = 'awaiting-live-readback';
        original_receipt_path = $publishedOriginal.Path; original_receipt_sha256 = $publishedOriginal.Sha256;
        source_preparation = $validation.peer_source_preparation; client_vmdk_source = $admission.source_disk;
        client_vmdk_sha256 = $validation.peer_vmdk_sha256; client_vmdk_copy = $targetDisk;
        client_vmdk_copy_identity = [Atlaso.WorkstationFileIdentity]::Get($targetDisk);
        client_vmdk_copy_preboot_sha256 = $validation.peer_vmdk_sha256; seed_iso = $seedPath;
        seed_iso_sha256 = (Get-FileHash -LiteralPath $seedPath -Algorithm SHA256).Hash.ToLowerInvariant();
        peer_macs = $macs; lan_segment_id = $segment.Id; lan_segment_receipt = $segment.ReceiptPath;
        lan_segment_receipt_sha256 = $segment.ReceiptSha256.ToLowerInvariant(); source_plan_sha256 = $planDigest;
        state = 'offline-prepared-not-native-acceptance' }
    $preparedReceipt = Publish-CertificatePeerRecord -Context $context -Record $prepared -Kind original
    [pscustomobject]@{ Mode = 'Create'; State = $prepared.state; VmxPath = $context.VmxPath;
        OriginalReceiptPath = $publishedOriginal.Path; OriginalReceiptSha256 = $publishedOriginal.Sha256;
        PreparedReceiptPath = $preparedReceipt.Path; PreparedReceiptSha256 = $preparedReceipt.Sha256;
        LanReceiptPath = $segment.ReceiptPath; LanReceiptSha256 = $segment.ReceiptSha256 }
}
finally {
    if ($outputPin) { $outputPin.Dispose() }
    if ($context -and $context.PSObject.Properties['CheckoutSourcePin'] -and $context.CheckoutSourcePin) {
        $context.CheckoutSourcePin.Dispose()
    }
    for ($index = $pins.Count - 1; $index -ge 0; $index--) { $pins[$index].Dispose() }
}
