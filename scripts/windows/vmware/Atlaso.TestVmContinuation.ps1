<#
.SYNOPSIS
Admit an explicitly authorized successor without changing original VM ownership.
.DESCRIPTION
The trusted Codex controller verifies human authorization and originating-chat quiescence.
This helper binds that evidence to one original receipt; it does not authenticate a hostile host.
#>

<#
.SYNOPSIS
Read bounded immutable JSON while retaining ordinary-file and ancestor pins.
.PARAMETER Path
Absolute public evidence path.
.PARAMETER Sha256
Independently preserved digest.
.PARAMETER Pins
Caller-owned handles retained until the operation completes.
#>
function Read-AtlasoTestVmContinuationJson {
    param([string]$Path, [string]$Sha256, [Collections.Generic.List[object]]$Pins)
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Continuation evidence requires an absolute path and independently preserved digest.'
    }
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath((Split-Path -Parent $Path), $true))
    $Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true))
    if ((Get-Item -LiteralPath $Path).Length -gt 65536 -or
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Sha256) {
        throw 'Continuation evidence changed or exceeds its bounded size.'
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

<#
.SYNOPSIS
Resolve the single immutable successor record for an original VM receipt.
.PARAMETER Context
Exact task, source, resource and original-receipt selectors.
#>
function Get-AtlasoTestVmContinuationPath {
    param([psobject]$Context)
    if (-not $Context.ReceiptPath -or [string]$Context.ReceiptSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Continuation requires the original VM receipt and its creation-time digest.'
    }
    $original = [IO.Path]::GetFullPath([string]$Context.ReceiptPath)
    if ((Split-Path -Parent $original) -cne [string]$Context.EvidenceDirectory) {
        throw 'Continuation requires an original receipt directly inside durable task ownership evidence.'
    }
    return Join-Path $Context.EvidenceDirectory ('atlaso-test-vm-continuation-' + $Context.ReceiptSha256 + '.json')
}

<#
.SYNOPSIS
Verify a successor binding without adopting or rewriting the original resource.
.PARAMETER Context
Exact current source and resource selectors, with the real active chat ID.
.PARAMETER Path
Explicit immutable successor receipt path, or empty for ordinary ownership.
.PARAMETER Sha256
Independently retained successor receipt digest.
.PARAMETER Pins
Handles retained by the source guard through native invocation completion.
#>
function Resolve-AtlasoTestVmContinuation {
    param([psobject]$Context, [string]$Path, [string]$Sha256, [Collections.Generic.List[object]]$Pins)
    if ([bool]$Path -xor [bool]$Sha256) { throw 'Pass both continuation receipt selectors.' }
    if (-not $Context.ReceiptPath) {
        if ($Path -or $Sha256) { throw 'Continuation cannot authorize a new resource.' }
        return [string]$Context.TaskId
    }
    if (-not $Path) {
        $expected = Join-Path $Context.EvidenceDirectory ('atlaso-test-vm-continuation-' + $Context.ReceiptSha256 + '.json')
        if (Test-Path -LiteralPath $expected) { throw 'This retained VM requires its explicit successor receipt selectors.' }
        return [string]$Context.TaskId
    }
    $expected = Get-AtlasoTestVmContinuationPath -Context $Context
    if ([string]$env:CODEX_THREAD_ID -cnotmatch '^[A-Za-z0-9_-]{1,128}$' -or
        [IO.Path]::GetFullPath($Path) -cne $expected) {
        throw 'Continuation requires the real active agent and exact resource-specific receipt path.'
    }
    $record = Read-AtlasoTestVmContinuationJson -Path $Path -Sha256 $Sha256 -Pins $Pins
    $original = Read-AtlasoTestVmContinuationJson -Path $Context.ReceiptPath -Sha256 $Context.ReceiptSha256 -Pins $Pins
    if ($record.schema -ne 1 -or $record.phase -cne 'test-vm-successor-authorized' -or
        $record.successor_task_id -cne [string]$env:CODEX_THREAD_ID -or
        $record.originating_task_id -cnotmatch '^[A-Za-z0-9_-]{1,128}$' -or
        $record.originating_task_id -ceq $record.successor_task_id -or
        $record.originating_task_id -cne $original.task_id -or
        $record.original_receipt_path -cne [IO.Path]::GetFullPath([string]$Context.ReceiptPath) -or
        $record.original_receipt_sha256 -cne $Context.ReceiptSha256 -or
        $record.worktree_directory_identity -cne $Context.WorktreeDirectoryId -or
        $record.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        $original.schema -ne 1 -or $original.phase -cnotin @('original-clone-created', 'original-installation-vm-created')) {
        throw 'Continuation does not match the active successor, original owner or preserved creation evidence.'
    }
    foreach ($field in @('repository', 'worktree', 'source_branch', 'output_directory', 'vmx_path', 'canonical_name', 'pull_request_number', 'local_builder')) {
        $property = @{repository='Repository';worktree='Worktree';source_branch='Branch';output_directory='OutputDirectory';
            vmx_path='VmxPath';canonical_name='Name';pull_request_number='PullRequestNumber';local_builder='LocalBuilder'}[$field]
        if ($record.$field -cne $Context.$property -or $original.$field -cne $Context.$property) {
            throw 'Continuation repository, source or VM scope differs from original ownership.'
        }
    }
    foreach ($commit in @($record.source_commit, $original.source_commit)) {
        if ($commit -cnotmatch '^[0-9a-f]{40}$') { throw 'Continuation source ancestry is malformed.' }
        & git -C $Context.Worktree merge-base --is-ancestor $commit $Context.SourceCommit 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Continuation source is not an ancestor of the admitted checkout.' }
    }
    if ([Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory) -cne $original.original_identities.directory -or
        (Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value (Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath $Context.VmxPath)) -cne
            $original.persistent_vm_identity_sha256) {
        throw 'The original retained VM directory or persistent identity changed.'
    }
    if (-not (Test-AtlasoTestVmStrictDescendantPath -ParentPath $Context.PermittedRoot -ChildPath $record.controller_evidence_path) -or
        (Test-AtlasoTestVmStrictDescendantPath -ParentPath $Context.Worktree -ChildPath $record.controller_evidence_path) -or
        (Test-AtlasoTestVmStrictDescendantPath -ParentPath $Context.OutputDirectory -ChildPath $record.controller_evidence_path)) {
        throw 'Continuation controller evidence escaped its durable non-removal scope.'
    }
    $evidence = Read-AtlasoTestVmContinuationJson -Path $record.controller_evidence_path -Sha256 $record.controller_evidence_sha256 -Pins $Pins
    if ($evidence.source_commit -cne $record.source_commit) { throw 'Continuation controller source binding changed.' }
    Assert-AtlasoTestVmContinuationControllerEvidence -Context $Context -Evidence $evidence -OriginatingTaskId $record.originating_task_id
    return [string]$record.originating_task_id
}

<#
.SYNOPSIS
Validate the trusted controller's exact human and originating-chat evidence binding.
.PARAMETER Context
Exact successor task, source and retained-resource selectors.
.PARAMETER Evidence
Sanitized supported-tool evidence independently captured by the live controller.
.PARAMETER OriginatingTaskId
Owner preserved in the original creation receipt.
#>
function Assert-AtlasoTestVmContinuationControllerEvidence {
    param([psobject]$Context, [psobject]$Evidence, [string]$OriginatingTaskId)
    foreach ($flag in @('human_authorized', 'originating_chat_idle', 'original_native_consumers_terminal', 'exclusive_successor')) {
        if ($Evidence.$flag -isnot [bool] -or -not $Evidence.$flag) { throw 'Continuation controller attestations must be literal true booleans.' }
    }
    if ($Evidence.schema -ne 1 -or $Evidence.successor_task_id -cne [string]$env:CODEX_THREAD_ID -or
        $Evidence.originating_task_id -cne $OriginatingTaskId -or
        $Evidence.original_receipt_path -cne [IO.Path]::GetFullPath([string]$Context.ReceiptPath) -or
        $Evidence.original_receipt_sha256 -cne $Context.ReceiptSha256 -or
        $Evidence.source_commit -cnotmatch '^[0-9a-f]{40}$' -or
        @($Evidence.evidence_refs).Count -lt 2 -or @($Evidence.evidence_refs | Where-Object { $_ -isnot [string] -or -not $_.Trim() }).Count) {
        throw 'Continuation requires exact human authorization and quiescent originating-chat evidence from supported tools.'
    }
}

<#
.SYNOPSIS
Publish a one-resource successor handoff after live controller verification.
.PARAMETER Context
Clean successor-owned source context with the original VM receipt selectors.
.PARAMETER ControllerEvidencePath
Sanitized fresh supported-tool evidence outside the checkout and resource roots.
.PARAMETER ControllerEvidenceSha256
Digest independently preserved when the controller captured its evidence.
#>
function New-AtlasoTestVmContinuation {
    param([psobject]$Context, [string]$ControllerEvidencePath, [string]$ControllerEvidenceSha256)
    if (-not $Context.Enabled -or $Context.TaskId -cne [string]$env:CODEX_THREAD_ID) {
        throw 'Only the real active successor agent can register a continuation.'
    }
    $destination = Get-AtlasoTestVmContinuationPath -Context $Context
    $pins = [Collections.Generic.List[object]]::new()
    $writer = $null
    try {
        if (-not (Test-AtlasoTestVmStrictDescendantPath -ParentPath $Context.PermittedRoot -ChildPath $ControllerEvidencePath) -or
            (Test-AtlasoTestVmStrictDescendantPath -ParentPath $Context.Worktree -ChildPath $ControllerEvidencePath) -or
            (Test-AtlasoTestVmStrictDescendantPath -ParentPath $Context.OutputDirectory -ChildPath $ControllerEvidencePath)) {
            throw 'Controller evidence must remain under the configured durable root, outside source and VM removal roots.'
        }
        Assert-AtlasoTestVmCheckoutSource -Context $Context
        $original = Read-AtlasoTestVmContinuationJson -Path $Context.ReceiptPath -Sha256 $Context.ReceiptSha256 -Pins $pins
        if ($original.task_id -ceq [string]$env:CODEX_THREAD_ID) { throw 'Continuation requires a distinct originating owner.' }
        $evidence = Read-AtlasoTestVmContinuationJson -Path $ControllerEvidencePath -Sha256 $ControllerEvidenceSha256 -Pins $pins
        Assert-AtlasoTestVmContinuationControllerEvidence -Context $Context -Evidence $evidence -OriginatingTaskId $original.task_id
        if ($evidence.source_commit -cne $Context.SourceCommit) { throw 'Controller evidence must bind the exact publication source.' }
        $observed = [DateTimeOffset]::MinValue
        $observedValue = $evidence.observed_at
        $validObserved = $false
        # ConvertFrom-Json can return a UTC DateTime for Z and a local DateTime for
        # numeric offsets. Casting either to string drops its zone and can invent a future instant.
        if ($observedValue -is [DateTime] -and $observedValue.Kind -ne [DateTimeKind]::Unspecified) {
            $observed = [DateTimeOffset]::new($observedValue).ToUniversalTime()
            $validObserved = $true
        }
        elseif ($observedValue -is [DateTimeOffset]) {
            $observed = $observedValue.ToUniversalTime()
            $validObserved = $true
        }
        elseif ($observedValue -is [string] -and $observedValue -cmatch 'T.*(?:Z|[+-][0-9]{2}:[0-9]{2})$') {
            $validObserved = [DateTimeOffset]::TryParse($observedValue, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$observed)
        }
        if (-not $validObserved -or
            $observed -gt [DateTimeOffset]::UtcNow -or ([DateTimeOffset]::UtcNow - $observed).TotalSeconds -gt 300) {
            throw 'Continuation publication requires fresh controller evidence from the last five minutes.'
        }
        $record = [ordered]@{schema=1;phase='test-vm-successor-authorized';originating_task_id=$original.task_id;
            successor_task_id=[string]$env:CODEX_THREAD_ID;repository=$Context.Repository;worktree=$Context.Worktree;
            worktree_directory_identity=$Context.WorktreeDirectoryId;source_branch=$Context.Branch;source_commit=$Context.SourceCommit;
            output_directory=$Context.OutputDirectory;vmx_path=$Context.VmxPath;canonical_name=$Context.Name;
            pull_request_number=$Context.PullRequestNumber;local_builder=$Context.LocalBuilder;
            original_receipt_path=[IO.Path]::GetFullPath([string]$Context.ReceiptPath);original_receipt_sha256=$Context.ReceiptSha256;
            controller_evidence_path=$ControllerEvidencePath;controller_evidence_sha256=$ControllerEvidenceSha256;
            created_at=[DateTimeOffset]::UtcNow.ToString('o')}
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 5 -Compress) + "`n")
        $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        # Retain failed staging as evidence; never overwrite an existing handoff.
        $probe = Join-Path $Context.EvidenceDirectory ('.continuation-' + [guid]::NewGuid().ToString('N') + '.pending')
        $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($probe)
        $writer.Write($bytes, 0, $bytes.Length)
        $validationContext = $Context.PSObject.Copy()
        $validationContext.TaskId = [string]$original.task_id
        $originalPhase = [string]$original.phase
        if ($originalPhase -cnotin @('original-clone-created', 'original-installation-vm-created')) { throw 'Unsupported original VM receipt phase.' }
        $null = Read-AtlasoTestVmSealedRecord -Context $validationContext -Path $Context.ReceiptPath -Sha256 $Context.ReceiptSha256 -Phase $originalPhase
        if ([Atlaso.WorkstationFileIdentity]::Get([string]$Context.OutputDirectory) -cne $original.original_identities.directory -or
            (Get-AtlasoTestVmOwnershipCleanupIdentityHash -Value (Get-AtlasoTestVmOwnershipCleanupIdentity -VmxPath $Context.VmxPath)) -cne $original.persistent_vm_identity_sha256) {
            throw 'Continuation publication refuses a replaced original VM.'
        }
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $destination, $false)
        $writer.Dispose()
        $writer = $null
        $null = Read-AtlasoTestVmContinuationJson -Path $destination -Sha256 $digest -Pins $pins
        return [pscustomobject]@{Path=$destination;Sha256=$digest}
    }
    finally {
        if ($writer) { $writer.Dispose() }
        for ($index=$pins.Count-1; $index -ge 0; $index--) { $pins[$index].Dispose() }
    }
}
