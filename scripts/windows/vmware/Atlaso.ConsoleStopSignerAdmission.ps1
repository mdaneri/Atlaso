<#
.SYNOPSIS
Prepare a fresh host-v3 signer scope without enabling credentials or signing.
.DESCRIPTION
Descriptor records are public data. Production runtime/provider verification always
refuses. Existing v1/v2 consumers and the signed wire-v2 verifier remain unchanged.
#>

$script:AtlasoSignerScopes = [Runtime.CompilerServices.ConditionalWeakTable[object,object]]::new()
$script:AtlasoSignerAdmissions = [Runtime.CompilerServices.ConditionalWeakTable[object,object]]::new()

<#
.SYNOPSIS
Snapshot original context selectors independently of public descriptor projections.
.PARAMETER Context
Original normal-VM context whose source pin is retained by its existing owner.
#>
function Get-AtlasoConsoleSignerContextSnapshot {
    param([Parameter(Mandatory)][psobject]$Context)
    $result = [ordered]@{}
    foreach ($name in @('Enabled','TaskId','ActiveTaskId','ContinuationReceiptPath','ContinuationReceiptSha256',
            'Worktree','WorktreeDirectoryId','PermittedRoot','Repository','Branch','SourceCommit','PullRequestNumber',
            'LocalBuilder','EvidenceDirectory','EvidenceDirectoryId','ReceiptPath','ReceiptSha256','OutputDirectory','VmxPath','Name')) {
        $member = $Context.PSObject.Properties[$name]
        if ($null -eq $member -or ($null -ne $member.Value -and $member.Value -isnot [string] -and $member.Value -isnot [bool] -and
                $member.Value -isnot [int] -and $member.Value -isnot [long])) {
            throw 'Original signer context selectors refused.'
        }
        $result.Add($name, $member.Value)
    }
    return ($result | ConvertTo-Json -Compress)
}

<#
.SYNOPSIS
Recheck original scoped source, resource, directory and live controller before use.
.PARAMETER Authority
Private original scope state, never a deserialized descriptor or public receipt.
#>
function Assert-AtlasoConsoleSignerScopeState {
    param([Parameter(Mandatory)][psobject]$Authority)
    if ($Authority.Closed -or $Authority.Context.ValidationRootAdmission -or
        $Authority.Context.ContinuationReceiptPath -or
        (Get-AtlasoConsoleSignerContextSnapshot -Context $Authority.Context) -cne $Authority.ContextSnapshot -or
        -not [object]::ReferenceEquals($Authority.Context.CheckoutSourcePin, $Authority.SourcePin) -or
        $Authority.SourcePin.Disposed -or $Authority.SourcePin.Pins.Count -lt 1 -or
        $Authority.SourcePin.Files.Count -lt 1 -or $Authority.SourcePin.Directories.Count -lt 1 -or
        [Atlaso.WorkstationFileIdentity]::Get($Authority.Context.EvidenceDirectory) -cne $Authority.EvidenceIdentity -or
        [DateTimeOffset]::UtcNow -ge $Authority.Deadline) { throw 'Original signer scope changed or expired.' }
    Assert-AtlasoTestVmCheckoutSource -Context $Authority.Context
    $original = Assert-AtlasoTestVmOriginalOwnership -Context $Authority.Context
    if ($original.Record.persistent_vm_identity_sha256 -cne $Authority.PersistentIdentity -or
        (Get-AtlasoWindowsBootIdentity) -cne $Authority.HostBoot -or
        (Get-AtlasoConsoleProcessCreation -Process $Authority.Controller | ConvertTo-Json -Compress) -cne
            $Authority.ControllerSnapshot -or [DateTimeOffset]::UtcNow -ge $Authority.Deadline) {
        throw 'Original signer controller or resource changed.'
    }
}

<#
.SYNOPSIS
Generate an original fresh nonce scope before descriptor, receiver or plan creation.
.PARAMETER Context
Original admitted internal-root normal-VM context with retained clean-source pins.
.PARAMETER RunId
New public run identity; it is not used as the exclusivity key.
.PARAMETER GuestBootId
Independently observed original guest boot identity.
.PARAMETER Deadline
Original finite absolute deadline, never renewed by later admission.
#>
function New-AtlasoConsoleSignerScope {
    param([Parameter(Mandatory)][psobject]$Context, [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$GuestBootId, [Parameter(Mandatory)][DateTimeOffset]$Deadline)
    if ($Context.Enabled -isnot [bool] -or -not $Context.Enabled -or
        ($Context.PSObject.Properties['ContinuationReceiptPath'] -and $Context.ContinuationReceiptPath) -or
        ($Context.PSObject.Properties['ValidationRootAdmission'] -and $Context.ValidationRootAdmission) -or
        $Context.TaskId -cnotmatch '\A[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\z' -or
        $Context.TaskId -cne $env:CODEX_THREAD_ID -or $Context.ActiveTaskId -cne $Context.TaskId -or $RunId -cnotmatch '\A[0-9a-f]{32}\z' -or
        $GuestBootId -cnotmatch '\A[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\z' -or
        $Deadline -le [DateTimeOffset]::UtcNow -or $Deadline -gt [DateTimeOffset]::UtcNow.AddSeconds(420)) {
        throw 'Fresh signer scope selectors refused.'
    }
    $pins = [Collections.Generic.List[IDisposable]]::new()
    $controller = $null
    try {
        $snapshot = Get-AtlasoConsoleSignerContextSnapshot -Context $Context
        $evidence = [IO.Path]::GetFullPath($Context.EvidenceDirectory)
        $output = [IO.Path]::GetFullPath($Context.OutputDirectory).TrimEnd('\','/')
        if ($evidence -cne $Context.EvidenceDirectory -or $evidence.TrimEnd('\','/').Equals($output,
                [StringComparison]::OrdinalIgnoreCase) -or $evidence.StartsWith($output + '\',
                [StringComparison]::OrdinalIgnoreCase)) { throw 'Original evidence scope refused.' }
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($evidence, $true))
        if ([Atlaso.WorkstationFileIdentity]::Get($evidence) -cne $Context.EvidenceDirectoryId) {
            throw 'Original evidence directory identity differs.'
        }
        Assert-AtlasoTestVmCheckoutSource -Context $Context
        $original = Assert-AtlasoTestVmOriginalOwnership -Context $Context
        if (-not $Context.CheckoutSourcePin -or $Context.CheckoutSourcePin.Disposed) {
            throw 'Original retained source pin required.'
        }
        if ($Context.CheckoutSourcePin.Pins.Count -lt 1 -or $Context.CheckoutSourcePin.Files.Count -lt 1 -or
            $Context.CheckoutSourcePin.Directories.Count -lt 1) { throw 'Original source pin inventory is empty.' }
        $controller = [Diagnostics.Process]::GetCurrentProcess()
        $identity = Get-AtlasoConsoleProcessCreation -Process $controller
        $scope = [pscustomobject]@{ HostProtocol = 3; WireProtocol = 2; ReceiverNonce = [guid]::NewGuid().ToString('N');
            RunId = $RunId; GuestBootId = $GuestBootId; DeadlineUtc = $Deadline.ToString('O') }
        $authority = [pscustomobject]@{ Context=$Context; ContextSnapshot=$snapshot; SourcePin=$Context.CheckoutSourcePin;
            EvidenceIdentity=$Context.EvidenceDirectoryId; PersistentIdentity=$original.Record.persistent_vm_identity_sha256;
            HostBoot=(Get-AtlasoWindowsBootIdentity); Controller=$controller; ControllerIdentity=$identity;
            ControllerSnapshot=($identity | ConvertTo-Json -Compress); Pins=$pins; Deadline=$Deadline;
            ScopeSnapshot=($scope | ConvertTo-Json -Compress); Nonce=$scope.ReceiverNonce; RunId=$RunId;
            GuestBootId=$GuestBootId; DeadlineUtc=$scope.DeadlineUtc; Closed=$false; Attempted=$false; Admission=$null; Scope=$scope; ClaimPublishing=$false; ClaimThread=0 }
        Assert-AtlasoConsoleSignerScopeState -Authority $authority
        $script:AtlasoSignerScopes.Add($scope, $authority)
        return $scope
    }
    catch {
        foreach ($pin in $pins) { $pin.Dispose() }
        if ($controller) { $controller.Dispose() }
        throw 'Original signer scope admission failed.'
    }
}

<#
.SYNOPSIS
Read an exact bounded acyclic descriptor as data plus retained read pins only.
.PARAMETER Context
Original evidence directory selector; reading data does not admit its provenance.
.PARAMETER Path
Canonical original public descriptor path beneath that directory.
.PARAMETER Sha256
Independently retained original descriptor digest.
#>
function Read-AtlasoConsoleSignerDescriptor {
    param([Parameter(Mandatory)][psobject]$Context, [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sha256)
    $keys = @('schema','kind','host_protocol','wire_protocol','task_id','source_commit','worktree_identity',
        'evidence_identity','ownership_receipt_sha256','persistent_vm_identity_sha256','run_id','receiver_nonce',
        'guest_boot_id','host_boot_identity','deadline_utc','stop_ack_public_key_hex','stop_ack_signing_key_sha256',
        'signer_source_sha256','host_executable_sha256','runtime_receipt_path','runtime_receipt_sha256',
        'runtime_directory','runtime_directory_identity','runtime_inventory_sha256','runtime_file_count',
        'python_path','python_sha256','provider_contract','codec_contract','protected_provider_evidence_sha256',
        'controller_pid','controller_start_utc','controller_start_filetime_utc','controller_cim_creation_utc','controller_parent_pid')
    $read = Read-AtlasoConsoleTransactionRecord -Context $Context -Path $Path -Sha256 $Sha256 -Keys $keys
    try {
        $d = $read.Value
        $integers = @('schema','host_protocol','wire_protocol','runtime_file_count','controller_pid','controller_parent_pid')
        foreach ($key in $keys) {
            if ($key -cin $integers) {
                if ($d[$key] -isnot [long] -and $d[$key] -isnot [int]) { throw 'Descriptor integer required.' }
            }
            elseif ($d[$key] -isnot [string] -or $d[$key].Length -lt 1 -or $d[$key].Length -gt 1024 -or
                $d[$key] -match '[\x00-\x1f]') { throw 'Descriptor string required.' }
        }
        foreach ($key in @('ownership_receipt_sha256','persistent_vm_identity_sha256','stop_ack_public_key_hex',
                'stop_ack_signing_key_sha256','signer_source_sha256','host_executable_sha256','runtime_receipt_sha256',
                'runtime_inventory_sha256','python_sha256','protected_provider_evidence_sha256')) {
            if ($d[$key] -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Descriptor digest refused.' }
        }
        foreach ($key in @('worktree_identity','evidence_identity','runtime_directory_identity')) {
            if ($d[$key] -cnotmatch '\A[0-9A-F]{8}:[0-9A-F]{16}\z') { throw 'Descriptor native identity refused.' }
        }
        foreach ($key in @('task_id','guest_boot_id')) {
            if ($d[$key] -cnotmatch '\A[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\z') { throw 'Descriptor UUID refused.' }
        }
        foreach ($key in @('run_id','receiver_nonce')) {
            if ($d[$key] -cnotmatch '\A[0-9a-f]{32}\z') { throw 'Descriptor nonce refused.' }
        }
        foreach ($key in @('host_boot_identity','controller_start_filetime_utc')) {
            if ($d[$key] -cnotmatch '\A[0-9]{1,19}\z') { throw 'Descriptor clock refused.' }
        }
        foreach ($key in @('deadline_utc','controller_start_utc','controller_cim_creation_utc')) {
            $stamp = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParseExact($d[$key], 'O', [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$stamp)) { throw 'Descriptor timestamp refused.' }
        }
        foreach ($key in @('runtime_receipt_path','runtime_directory','python_path')) {
            if ([IO.Path]::GetFullPath($d[$key]) -cne $d[$key]) { throw 'Descriptor absolute path required.' }
        }
        if ($d.schema -ne 1 -or $d.kind -cne 'console-signer-admission-descriptor-v1' -or $d.host_protocol -ne 3 -or
            $d.wire_protocol -ne 2 -or $d.source_commit -cnotmatch '\A[0-9a-f]{40}\z' -or
            $d.runtime_file_count -lt 1 -or $d.runtime_file_count -gt 14000 -or
            $d.controller_pid -lt 1 -or $d.controller_pid -gt [int]::MaxValue -or
            $d.controller_parent_pid -lt 0 -or $d.controller_parent_pid -gt [int]::MaxValue -or
            $d.provider_contract -cnotmatch '\A[a-z0-9][a-z0-9.-]{0,95}\z' -or
            $d.codec_contract -cnotmatch '\A[a-z0-9][a-z0-9.-]{0,95}\z') { throw 'Descriptor schema refused.' }
        $fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Convert]::FromHexString($d.stop_ack_public_key_hex))).ToLowerInvariant()
        if ($fingerprint -cne $d.stop_ack_signing_key_sha256) { throw 'Independent key fingerprint differs.' }
        return $read
    }
    catch {
        foreach ($pin in $read.Pins) { $pin.Dispose() }
        throw 'Public signer descriptor data refused.'
    }
}

<#
.SYNOPSIS
Preserve a nonce-only exclusive claim with no replacement or uncertain-result retry.
.PARAMETER Authority
Original in-memory scope with independent evidence identity and source/resource guards.
.PARAMETER DescriptorSha256
Original descriptor digest bound inside, never part of the exclusivity filename.
#>
function Publish-AtlasoConsoleSignerNonceClaim {
    param([Parameter(Mandatory)][psobject]$Authority, [Parameter(Mandatory)][string]$DescriptorSha256)
    $registered = $null
    if (-not $Authority.Scope -or -not $script:AtlasoSignerScopes.TryGetValue($Authority.Scope, [ref]$registered) -or
        -not [object]::ReferenceEquals($registered, $Authority) -or -not $Authority.ClaimPublishing -or
        $Authority.ClaimThread -ne [Threading.Thread]::CurrentThread.ManagedThreadId) {
        throw 'Original private nonce publication phase required.'
    }
    Assert-AtlasoConsoleSignerScopeState -Authority $Authority
    $root = $Authority.Context.EvidenceDirectory
    $path = Join-Path $root ('atlaso-console-signer-nonce-' + $Authority.Nonce + '.json')
    $stage = Join-Path $root ('atlaso-console-signer-nonce-' + $Authority.Nonce + '.pending')
    # The deterministic stage is itself an exclusive consumed-attempt marker.
    # Preserve it if publication is uncertain; a random orphan must not allow retry.
    $writer = $null
    try {
        if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path) -or
            [IO.File]::Exists($stage) -or [IO.Directory]::Exists($stage)) { throw 'Nonce already claimed or ambiguous.' }
        $record = [ordered]@{schema=1;kind='console-signer-nonce-claim';host_protocol=3;wire_protocol=2;
            receiver_nonce=$Authority.Nonce;run_id=$Authority.RunId;descriptor_sha256=$DescriptorSha256;
            task_id=$Authority.Context.TaskId;source_commit=$Authority.Context.SourceCommit;
            evidence_identity=$Authority.EvidenceIdentity;controller=$Authority.ControllerIdentity;deadline_utc=$Authority.DeadlineUtc}
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 5 -Compress) + "`n")
        $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stage)
        $writer.Write($bytes, 0, $bytes.Length)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $path, $false)
        $writer.Dispose(); $writer = $null
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true)
        $Authority.Pins.Add($pin)
        if ((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $hash) { throw 'Claim readback differs.' }
        return [pscustomobject]@{Path=$path;Sha256=$hash}
    }
    finally { if ($writer) { $writer.Dispose() } }
}

<#
.SYNOPSIS
Refuse the unavailable production runtime, protected provider and codec admission.
.PARAMETER Authority
Original post-claim scope; descriptor metadata cannot mint runtime or SDK authority.
.PARAMETER Descriptor
Strict public data only, including an opaque protected-evidence commitment.
#>
function Assert-AtlasoConsoleSignerRuntimeProvider {
    param([Parameter(Mandatory)][psobject]$Authority, [Parameter(Mandatory)][Collections.IDictionary]$Descriptor)
    # No actual original runtime/provider verifier or production codec is admitted.
    # Do not inspect a secret selector, import an SDK, or infer a default backend.
    $null = $Authority, $Descriptor
    throw 'Production signer runtime/provider admission is unavailable.'
}

<#
.SYNOPSIS
Consume an original fresh scope and descriptor attempt before provider admission.
.PARAMETER Scope
Same live source-owned pre-descriptor reference, never a copied or reopened record.
.PARAMETER DescriptorPath
Exact original descriptor path, not a plan or receiver record.
.PARAMETER DescriptorSha256
Independently retained digest of the original descriptor bytes.
#>
function Open-AtlasoConsoleSignerAdmission {
    param([Parameter(Mandatory)][psobject]$Scope, [Parameter(Mandatory)][string]$DescriptorPath,
        [Parameter(Mandatory)][string]$DescriptorSha256)
    $a = $null
    if (-not $script:AtlasoSignerScopes.TryGetValue($Scope, [ref]$a)) { throw 'Original signer scope reference required.' }
    [Threading.Monitor]::Enter($a)
    try {
        if ($a.Closed -or $a.Attempted) { throw 'Signer scope attempt already consumed or closed.' }
        $a.Attempted = $true
        if (($Scope | ConvertTo-Json -Compress) -cne $a.ScopeSnapshot) { throw 'Original scope projection drifted.' }
        Assert-AtlasoConsoleSignerScopeState -Authority $a
        $read = Read-AtlasoConsoleSignerDescriptor -Context $a.Context -Path $DescriptorPath -Sha256 $DescriptorSha256
        foreach ($pin in $read.Pins) { $a.Pins.Add($pin) }
        $d = $read.Value
        $expected = [ordered]@{task_id=$a.Context.TaskId;source_commit=$a.Context.SourceCommit;
            worktree_identity=$a.Context.WorktreeDirectoryId;evidence_identity=$a.EvidenceIdentity;
            ownership_receipt_sha256=$a.Context.ReceiptSha256;persistent_vm_identity_sha256=$a.PersistentIdentity;
            run_id=$a.RunId;receiver_nonce=$a.Nonce;guest_boot_id=$a.GuestBootId;host_boot_identity=$a.HostBoot;
            deadline_utc=$a.DeadlineUtc;controller_pid=$a.ControllerIdentity.pid;
            controller_start_utc=$a.ControllerIdentity.getprocess_start_utc;
            controller_start_filetime_utc=$a.ControllerIdentity.start_filetime_utc;
            controller_cim_creation_utc=$a.ControllerIdentity.cim_creation_utc;controller_parent_pid=$a.ControllerIdentity.parent_pid}
        foreach ($name in $expected.Keys) {
            if ($d[$name] -cne $expected[$name]) { throw 'Descriptor original scope binding differs.' }
        }
        # Exact scoped collision checks are not a lock against unchanged legacy
        # writers. The producer must never forward this fresh nonce to them.
        foreach ($kind in @('intent','process','stop','ack-intent','signing-intent','signer-process','signer-stop')) {
            $legacy = Join-Path $a.Context.EvidenceDirectory ('atlaso-test-vm-console-credential-' + $kind + '-' + $a.Nonce + '.json')
            if (Test-Path -LiteralPath $legacy) { throw 'Exact receiver nonce overlaps an existing consumer.' }
        }
        Assert-AtlasoConsoleSignerScopeState -Authority $a
        $a.ClaimPublishing = $true
        $a.ClaimThread = [Threading.Thread]::CurrentThread.ManagedThreadId
        try { $claim = Publish-AtlasoConsoleSignerNonceClaim -Authority $a -DescriptorSha256 $DescriptorSha256 }
        finally { $a.ClaimPublishing = $false; $a.ClaimThread = 0 }
        # Publication facts are retained even when later verification refuses.
        $a | Add-Member ClaimReceipt ([pscustomobject]@{Path=$claim.Path;Sha256=$claim.Sha256})
        $a | Add-Member DescriptorPath $DescriptorPath
        $a | Add-Member DescriptorSha256 $DescriptorSha256
        $a | Add-Member DescriptorSnapshot ($d | ConvertTo-Json -Depth 4 -Compress)
        $a | Add-Member Descriptor $d
        Assert-AtlasoConsoleSignerRuntimeProvider -Authority $a -Descriptor $d
        Assert-AtlasoConsoleSignerScopeState -Authority $a
        $admission = [pscustomobject]@{HostProtocol=3;WireProtocol=2;ReceiverNonce=$a.Nonce;Status='preplan_no_dispatch'}
        $a.Admission = $admission
        $script:AtlasoSignerAdmissions.Add($admission, $a)
        return $admission
    }
    finally { [Threading.Monitor]::Exit($a) }
}

<#
.SYNOPSIS
Recheck the same live pre-plan reference without dispatching any credential operation.
.PARAMETER Admission
Original returned capability; records, copies and deserialized projections refuse.
#>
function Assert-AtlasoConsoleSignerAdmission {
    param([Parameter(Mandatory)][psobject]$Admission)
    $a = $null
    if (-not $script:AtlasoSignerAdmissions.TryGetValue($Admission, [ref]$a)) { throw 'Original live signer admission required.' }
    [Threading.Monitor]::Enter($a)
    try {
        Assert-AtlasoConsoleSignerScopeState -Authority $a
        $read = Read-AtlasoConsoleSignerDescriptor -Context $a.Context -Path $a.DescriptorPath -Sha256 $a.DescriptorSha256
        try {
            if (($read.Value | ConvertTo-Json -Depth 4 -Compress) -cne $a.DescriptorSnapshot -or
                (Get-FileHash -LiteralPath $a.ClaimReceipt.Path).Hash.ToLowerInvariant() -cne $a.ClaimReceipt.Sha256) {
                throw 'Original descriptor or nonce claim changed.'
            }
        }
        finally { foreach ($pin in $read.Pins) { $pin.Dispose() } }
        Assert-AtlasoConsoleSignerRuntimeProvider -Authority $a -Descriptor $a.Descriptor
        Assert-AtlasoConsoleSignerScopeState -Authority $a
    }
    finally { [Threading.Monitor]::Exit($a) }
}

<#
.SYNOPSIS
Revoke original scope authority before releasing owned pins; preserve every claim.
.PARAMETER Scope
Original scope reference. Repeated close is harmless; copies never acquire authority.
#>
function Close-AtlasoConsoleSignerScope {
    param([Parameter(Mandatory)][psobject]$Scope)
    $a = $null
    if (-not $script:AtlasoSignerScopes.TryGetValue($Scope, [ref]$a)) { throw 'Original signer scope reference required.' }
    [Threading.Monitor]::Enter($a)
    try {
        if ($a.Closed) { return }
        $a.Closed = $true
        if ($a.Admission) { $null = $script:AtlasoSignerAdmissions.Remove($a.Admission) }
        foreach ($pin in $a.Pins) { $pin.Dispose() }
        $a.Pins.Clear()
        $a.Controller.Dispose()
    }
    finally { [Threading.Monitor]::Exit($a) }
}
