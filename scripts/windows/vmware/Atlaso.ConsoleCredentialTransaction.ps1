<#
.SYNOPSIS
Journal one separately admitted normal-VM console credential transaction.
.DESCRIPTION
Requires the existing original VM/source admission and public concealed-receiver
receipt. It publishes no guest acknowledgement and grants no native acceptance.
The guest receiver and public-launch producer remain separate required interfaces.
#>

<#
.SYNOPSIS
Convert only the exact JSON primitive types used by public transaction records.
.PARAMETER Element
Bounded parsed JSON element; date strings retain their original representation.
#>
function ConvertFrom-AtlasoConsoleJsonElement {
    param([Parameter(Mandatory)][Text.Json.JsonElement]$Element)
    switch ($Element.ValueKind) {
        ([Text.Json.JsonValueKind]::Object) {
            $value = [ordered]@{}
            $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($member in $Element.EnumerateObject()) {
                if (-not $seen.Add($member.Name)) { throw 'Duplicate public record key.' }
                $value.Add($member.Name, (ConvertFrom-AtlasoConsoleJsonElement -Element $member.Value))
            }
            return $value
        }
        ([Text.Json.JsonValueKind]::String) { return $Element.GetString() }
        ([Text.Json.JsonValueKind]::Number) {
            $number = 0L
            if (-not $Element.TryGetInt64([ref]$number)) { throw 'Public record requires an integer.' }
            return $number
        }
        ([Text.Json.JsonValueKind]::True) { return $true }
        ([Text.Json.JsonValueKind]::False) { return $false }
        default { throw 'Public transaction record contains an unsupported value type.' }
    }
}

<#
.SYNOPSIS
Read a pinned bounded public transaction record with exact unique object keys.
.PARAMETER Context
Existing original normal-VM ownership context.
.PARAMETER Path
Canonical public record path within its durable evidence directory.
.PARAMETER Sha256
Independently retained digest, never a digest selected from the record itself.
.PARAMETER Keys
Exact top-level schema members.
#>
function Read-AtlasoConsoleTransactionRecord {
    param([Parameter(Mandatory)][psobject]$Context, [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sha256, [Parameter(Mandatory)][string[]]$Keys)
    $pins = [Collections.Generic.List[IDisposable]]::new()
    $document = $null
    try {
        $full = [IO.Path]::GetFullPath($Path)
        $scope = [IO.Path]::GetFullPath($Context.EvidenceDirectory).TrimEnd('\', '/') + '\'
        if ($full -cne $Path -or -not $full.StartsWith($scope, [StringComparison]::OrdinalIgnoreCase) -or
            $Sha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Record selectors refused.' }
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($full), $true))
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($full, $true))
        if ((Get-Item -LiteralPath $full).Length -gt 16384 -or
            (Get-FileHash -LiteralPath $full).Hash.ToLowerInvariant() -cne $Sha256) { throw 'Record digest refused.' }
        $raw = [IO.File]::ReadAllText($full, [Text.UTF8Encoding]::new($false, $true))
        $document = [Text.Json.JsonDocument]::Parse($raw)
        if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'Object required.' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($member in $document.RootElement.EnumerateObject()) {
            if (-not $seen.Add($member.Name) -or $member.Name -cnotin $Keys) { throw 'Record members refused.' }
        }
        if ($seen.Count -ne $Keys.Count) { throw 'Record members missing.' }
        $value = ConvertFrom-AtlasoConsoleJsonElement -Element $document.RootElement
        return [pscustomobject]@{ Value = $value; Pins = $pins }
    }
    catch {
        foreach ($pin in $pins) { $pin.Dispose() }
        throw 'Public console transaction record admission failed.'
    }
    finally { if ($document) { $document.Dispose() } }
}

<#
.SYNOPSIS
Observe distinct managed/native and CIM creation clocks for one exact process.
.PARAMETER Process
Original process object retained by its creating owner or exact live provider.
#>
function Get-AtlasoConsoleProcessCreation {
    param([Parameter(Mandatory)][Diagnostics.Process]$Process)
    $start = $Process.StartTime.ToUniversalTime()
    $cim = @(Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $Process.Id) -OperationTimeoutSec 10 -ErrorAction Stop)
    if ($cim.Count -ne 1 -or $cim[0].ProcessId -ne $Process.Id -or $Process.HasExited) {
        throw 'Original console transaction process identity is unavailable.'
    }
    return [ordered]@{
        pid = $Process.Id
        getprocess_start_utc = $start.ToString('O')
        start_filetime_utc = $start.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
        cim_creation_utc = $cim[0].CreationDate.ToUniversalTime().ToString('O')
        parent_pid = [int]$cim[0].ParentProcessId
    }
}

<#
.SYNOPSIS
Recheck the exact source, original VM, provider, runtime and frame before use.
.PARAMETER Transaction
Public admission bindings and retained read pins for this one transaction.
#>
function Assert-AtlasoConsoleTransactionBinding {
    param([Parameter(Mandatory)][psobject]$Transaction)
    if ($Transaction.IsClosed -isnot [bool] -or $Transaction.IsClosed) { throw 'Original console transaction is closed.' }
    $context = $Transaction.Context
    $plan = $Transaction.Plan
    $options = $Transaction.Options
    Assert-AtlasoTestVmCheckoutSource -Context $context
    $original = Assert-AtlasoTestVmOriginalOwnership -Context $context
    if ($original.Record.persistent_vm_identity_sha256 -cne $plan.persistent_vm_identity_sha256 -or
        (Get-AtlasoWindowsBootIdentity) -cne $plan.host_boot_identity -or
        [DateTimeOffset]::UtcNow -ge $Transaction.Deadline) { throw 'Console transaction admission changed or expired.' }
    $peer = Get-InstallationVncPeer -VmxPath $context.VmxPath -Port $options.Port
    $provider = Get-Process -Id $peer -ErrorAction Stop
    try {
        if ($peer -ne $plan.provider_pid -or
            $provider.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture) -cne
                $plan.provider_start_filetime_utc) { throw 'Original console provider changed.' }
    }
    finally { $provider.Dispose() }
    if ((Get-Item -LiteralPath $options.ScreenPath).Length -gt 8MB -or
        (Get-FileHash -LiteralPath $options.ScreenPath).Hash.ToLowerInvariant() -cne $plan.screen_sha256 -or
        (Get-FileHash -LiteralPath (Join-Path $context.Worktree 'scripts/installation/vnc_console.py')).Hash.ToLowerInvariant() -cne
            $plan.client_source_sha256) { throw 'Console frame or committed consumer changed.' }
    $venv = [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($options.PythonPath))
    $null = Assert-AtlasoSourceSnapshot -Root (Join-Path $venv 'Lib/site-packages') `
        -ExpectedSha256 $options.RuntimeSha256 -ExpectedFileCount $options.RuntimeFileCount
    if ([DateTimeOffset]::UtcNow -ge $Transaction.Deadline) { throw 'Original admission expired during runtime verification.' }
}

<#
.SYNOPSIS
Open original public plan/receiver bindings without launching or claiming a transaction.
.PARAMETER Context
Existing enabled normal-VM context with the original receipt and clean source.
.PARAMETER Options
Existing public credential-consumer arguments, never credential values.
.PARAMETER PlanPath
Exact original public plan in the admitted durable evidence directory.
.PARAMETER PlanSha256
Independently preserved plan digest.
.PARAMETER ProtocolVersion
Explicit original plan and receiver version; v1 never upgrades to signed-ACK admission.
#>
function Open-AtlasoConsoleCredentialTransaction {
    param([Parameter(Mandatory)][psobject]$Context, [Parameter(Mandatory)][hashtable]$Options,
        [Parameter(Mandatory)][string]$PlanPath, [Parameter(Mandatory)][string]$PlanSha256,
        [ValidateSet(1,2)][int]$ProtocolVersion = 1)
    if (-not $Context.Enabled -or
        ($Context.PSObject.Properties['ContinuationReceiptPath'] -and $Context.ContinuationReceiptPath) -or
        ($Context.PSObject.Properties['ValidationRootAdmission'] -and $Context.ValidationRootAdmission)) {
        throw 'Console transactions require original internal-root normal-VM admission without continuation.'
    }
    $pins = [Collections.Generic.List[IDisposable]]::new()
    try {
        Assert-AtlasoTestVmCheckoutSource -Context $Context
        $original = Assert-AtlasoTestVmOriginalOwnership -Context $Context
        $keys = @('schema', 'kind', 'task_id', 'source_commit', 'run_id', 'receiver_nonce', 'guest_boot_id',
            'host_boot_identity', 'ownership_receipt_sha256', 'persistent_vm_identity_sha256', 'provider_pid',
            'provider_start_filetime_utc', 'screen_sha256', 'runtime_sha256', 'runtime_file_count', 'account',
            'port', 'field_rectangle', 'deadline_utc', 'guest_bundle_sha256', 'receiver_receipt_path',
            'receiver_receipt_sha256', 'client_source_sha256')
        if ($ProtocolVersion -eq 2) {
            $keys += @('stop_ack_public_key_hex', 'stop_ack_signing_key_sha256', 'stop_ack_transport_key')
        }
        $read = Read-AtlasoConsoleTransactionRecord -Context $Context -Path $PlanPath -Sha256 $PlanSha256 -Keys $keys
        foreach ($pin in $read.Pins) { $pins.Add($pin) }
        $plan = $read.Value
        foreach ($key in @($keys | Where-Object { $_ -notin @('schema', 'provider_pid', 'runtime_file_count', 'port') })) {
            if ($plan[$key] -isnot [string]) { throw 'Plan field type refused.' }
        }
        foreach ($key in @('schema', 'provider_pid', 'runtime_file_count', 'port')) {
            if ($plan[$key] -isnot [int] -and $plan[$key] -isnot [long]) { throw 'Plan numeric type refused.' }
        }
        foreach ($key in @('ownership_receipt_sha256', 'persistent_vm_identity_sha256', 'screen_sha256',
                'runtime_sha256', 'guest_bundle_sha256', 'receiver_receipt_sha256', 'client_source_sha256')) {
            if ($plan[$key] -cnotmatch '^[0-9a-f]{64}$') { throw 'Plan digest type refused.' }
        }
        if ($plan.schema -ne $ProtocolVersion -or $plan.kind -cne ('console-credential-transaction-v' + $ProtocolVersion) -or
            $plan.source_commit -cne $Context.SourceCommit -or $plan.task_id -cne $Context.TaskId -or
            $plan.source_commit -cnotmatch '^[0-9a-f]{40}$' -or $plan.run_id -cnotmatch '^[0-9a-f]{32}$' -or
            $plan.receiver_nonce -cnotmatch '^[0-9a-f]{32}$' -or
            $plan.guest_boot_id -cnotmatch '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' -or
            $plan.host_boot_identity -cnotmatch '^[0-9]{1,19}$' -or
            $plan.provider_pid -lt 1 -or $plan.provider_pid -gt [int]::MaxValue -or
            $plan.provider_start_filetime_utc -cnotmatch '^[0-9]{1,19}$' -or
            $plan.account -cne 'admin' -or $plan.account -cne $Options.Account -or
            $plan.port -lt 1024 -or $plan.port -gt 65535 -or $plan.port -ne $Options.Port -or
            $plan.runtime_file_count -lt 1 -or $plan.runtime_file_count -gt 14000 -or
            $plan.runtime_file_count -ne $Options.RuntimeFileCount -or
            $plan.field_rectangle -cnotmatch '^\d{1,4},\d{1,4},\d{1,4},\d{1,4}$' -or
            $plan.field_rectangle -cne $Options.FieldRectangle -or
            $plan.screen_sha256 -cne $Options.ScreenSha256 -or $plan.runtime_sha256 -cne $Options.RuntimeSha256 -or
            $plan.ownership_receipt_sha256 -cne $Context.ReceiptSha256 -or
            $plan.persistent_vm_identity_sha256 -cne $original.Record.persistent_vm_identity_sha256) {
            throw 'Console transaction selectors do not match original admission.'
        }
        if ($ProtocolVersion -eq 2) {
            # The plan digest is independently retained by the host controller.
            # Never adopt either a key or a key fingerprint from the ACK channel.
            if ($plan.stop_ack_public_key_hex -cnotmatch '^[0-9a-f]{64}$' -or
                $plan.stop_ack_signing_key_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $plan.task_id -cnotmatch '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' -or
                $plan.stop_ack_transport_key -cne ('guestinfo.atlaso.pr1084.native.stop-ack.' + $plan.run_id + '.' + $plan.receiver_nonce)) {
                throw 'Signed stop acknowledgement admission refused.'
            }
            $keyBytes = [Convert]::FromHexString($plan.stop_ack_public_key_hex)
            $fingerprint = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($keyBytes)).ToLowerInvariant()
            if ($fingerprint -cne $plan.stop_ack_signing_key_sha256) { throw 'Original stop signing key fingerprint differs.' }
        }
        $deadline = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParseExact($plan.deadline_utc, 'O', [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::None, [ref]$deadline) -or $deadline -le [DateTimeOffset]::UtcNow -or
            $deadline -gt [DateTimeOffset]::UtcNow.AddSeconds(420)) { throw 'Original transaction deadline refused.' }
        $readyKeys = @('schema', 'kind', 'task_id', 'source_commit', 'run_id', 'receiver_nonce', 'guest_boot_id',
            'ownership_receipt_sha256', 'persistent_vm_identity_sha256', 'guest_bundle_sha256', 'screen_sha256', 'echo_off')
        if ($ProtocolVersion -eq 2) { $readyKeys += @('stop_ack_signing_key_sha256', 'stop_ack_algorithm') }
        $readyRead = Read-AtlasoConsoleTransactionRecord -Context $Context -Path $plan.receiver_receipt_path `
            -Sha256 $plan.receiver_receipt_sha256 -Keys $readyKeys
        foreach ($pin in $readyRead.Pins) { $pins.Add($pin) }
        $ready = $readyRead.Value
        if (($ready.schema -isnot [int] -and $ready.schema -isnot [long]) -or $ready.schema -ne $ProtocolVersion -or
            $ready.kind -isnot [string] -or $ready.kind -cne ('console-concealed-receiver-v' + $ProtocolVersion) -or
            $ready.echo_off -isnot [bool] -or -not $ready.echo_off) {
            throw 'Original concealed receiver receipt refused.'
        }
        foreach ($key in @('task_id', 'source_commit', 'run_id', 'receiver_nonce', 'guest_boot_id',
                'ownership_receipt_sha256', 'persistent_vm_identity_sha256', 'guest_bundle_sha256', 'screen_sha256')) {
            if ($ready[$key] -isnot [string] -or $ready[$key] -cne $plan[$key]) { throw 'Concealed receiver binding changed.' }
        }
        if ($ProtocolVersion -eq 2 -and ($ready.stop_ack_signing_key_sha256 -isnot [string] -or
                $ready.stop_ack_signing_key_sha256 -cne $plan.stop_ack_signing_key_sha256 -or
                $ready.stop_ack_algorithm -isnot [string] -or $ready.stop_ack_algorithm -cne 'Ed25519')) {
            throw 'Original concealed receiver signing admission differs.'
        }
        foreach ($path in @($Options.ScreenPath, $Options.PythonPath)) {
            $full = [IO.Path]::GetFullPath($path)
            if ($full -cne $path -or -not $full.StartsWith($Context.Worktree.TrimEnd('\', '/') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Console runtime/frame escaped its original task checkout.'
            }
            & git -C $Context.Worktree check-ignore -q -- $path
            if ($LASTEXITCODE -ne 0) { throw 'Console runtime/frame must be ignored owned resources.' }
            $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($path), $true))
            $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true))
        }
        $Context | Add-Member -NotePropertyName InvocationId -NotePropertyValue $plan.receiver_nonce -Force
        $binding = [ordered]@{
            schema = $ProtocolVersion; task_id = $plan.task_id; source_commit = $plan.source_commit; plan_sha256 = $PlanSha256
            run_id = $plan.run_id; receiver_nonce = $plan.receiver_nonce; guest_boot_id = $plan.guest_boot_id
            host_boot_identity = $plan.host_boot_identity; guest_bundle_sha256 = $plan.guest_bundle_sha256
            original_vm_receipt_path = $Context.ReceiptPath; original_vm_receipt_sha256 = $Context.ReceiptSha256
            original_directory_identity = $original.Record.original_identities.directory
            persistent_vm_identity_sha256 = $plan.persistent_vm_identity_sha256
            provider_pid = $plan.provider_pid; provider_start_filetime_utc = $plan.provider_start_filetime_utc
            screen_path = $Options.ScreenPath; screen_sha256 = $plan.screen_sha256; field_rectangle = $plan.field_rectangle
            python_path = $Options.PythonPath; runtime_sha256 = $plan.runtime_sha256; runtime_file_count = $plan.runtime_file_count
            client_source_sha256 = $plan.client_source_sha256; account = $plan.account; port = $plan.port
            receiver_receipt_path = $plan.receiver_receipt_path; receiver_receipt_sha256 = $plan.receiver_receipt_sha256
            deadline_utc = $plan.deadline_utc
        }
        if ($ProtocolVersion -eq 2) {
            foreach ($key in @('stop_ack_public_key_hex', 'stop_ack_signing_key_sha256', 'stop_ack_transport_key')) {
                $binding.Add($key, $plan[$key])
            }
        }
        $paths = @{}
        foreach ($kind in @('intent', 'process', 'stop')) {
            $paths[$kind] = Join-Path $Context.EvidenceDirectory ('atlaso-test-vm-console-credential-' + $kind + '-' + $plan.receiver_nonce + '.json')
        }
        $transaction = [pscustomobject]@{Context=$Context; Options=$Options; Plan=$plan; Binding=$binding; Paths=$paths;
            PlanReceipt=[pscustomobject]@{Path=$PlanPath; Sha256=$PlanSha256};
            Deadline=$deadline; Pins=$pins; JobName=('Local\Atlaso-ConsoleCredential-' + $plan.receiver_nonce);
            ProtocolVersion=$ProtocolVersion; IsClosed=$false; ControllerIdentity=$null; IntentReceipt=$null;
            RootIdentity=$null; ProcessReceipt=$null; StopReceipt=$null; StopOutcome=$null}
        Assert-AtlasoConsoleTransactionBinding -Transaction $transaction
        return $transaction
    }
    catch {
        foreach ($pin in $pins) { $pin.Dispose() }
        throw
    }
}

<#
.SYNOPSIS
Atomically publish and retain a read pin on one bounded original transaction record.
.PARAMETER Transaction
Original admission, evidence namespace and existing pinned records.
.PARAMETER Kind
Exact intent, process or stop phase; never reused or replaced.
.PARAMETER Details
Public original process facts created by the committed controller.
#>
function Publish-AtlasoConsoleCredentialRecord {
    param([Parameter(Mandatory)][psobject]$Transaction, [Parameter(Mandatory)][ValidateSet('intent','process','stop')][string]$Kind,
        [Parameter(Mandatory)][Collections.IDictionary]$Details)
    if ($Transaction.IsClosed -isnot [bool] -or $Transaction.IsClosed) { throw 'Original console transaction is closed.' }
    $record = [ordered]@{schema=1; phase=('console-credential-' + $Kind); binding=$Transaction.Binding;
        observed_utc=[DateTimeOffset]::UtcNow.ToString('O'); details=$Details}
    if ([Text.Encoding]::UTF8.GetByteCount(($record | ConvertTo-Json -Depth 8 -Compress)) -gt 16384) {
        throw 'Public console transaction record exceeded its bound.'
    }
    $published = Publish-AtlasoTestVmOwnershipRecord -Context $Transaction.Context -Record $record -Kind ('console-credential-' + $Kind)
    if ($published.Path -cne $Transaction.Paths[$Kind]) { throw 'Original console transaction namespace changed.' }
    $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($published.Path, $true)
    try {
        if ((Get-FileHash -LiteralPath $published.Path).Hash.ToLowerInvariant() -cne $published.Sha256) {
            throw 'Published original transaction record changed before its retained read pin.'
        }
        $Transaction.Pins.Add($pin)
    }
    catch { $pin.Dispose(); throw }
    return $published
}

<#
.SYNOPSIS
Claim one receiver and journal its suspended root and proven outer-job stop.
.PARAMETER Transaction
Exact original public plan and native ownership bindings.
.PARAMETER FilePath
Current PowerShell executable for the committed credential child.
.PARAMETER ArgumentList
Public original consumer arguments including its child and transaction selectors.
#>
function Invoke-AtlasoConsoleCredentialTransaction {
    param([Parameter(Mandatory)][psobject]$Transaction, [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList)
    Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
    foreach ($path in $Transaction.Paths.Values) { if (Test-Path -LiteralPath $path) { throw 'Original receiver transaction exists; preserve without replay.' } }
    $controller = [Diagnostics.Process]::GetCurrentProcess()
    try { $controllerIdentity = Get-AtlasoConsoleProcessCreation -Process $controller }
    finally { $controller.Dispose() }
    $Transaction.ControllerIdentity = $controllerIdentity
    $Transaction.IntentReceipt = Publish-AtlasoConsoleCredentialRecord -Transaction $Transaction -Kind intent -Details $controllerIdentity
    $publish = ${function:Publish-AtlasoConsoleCredentialRecord}
    $assert = ${function:Assert-AtlasoConsoleTransactionBinding}
    $creation = ${function:Get-AtlasoConsoleProcessCreation}
    $owner = {
        param($Job)
        & $assert -Transaction $Transaction
        $identity = & $creation -Process $Job.RootProcess
        $identity['job_name'] = $Transaction.JobName
        $Transaction.RootIdentity = $identity
        $Transaction.ProcessReceipt = & $publish -Transaction $Transaction -Kind process -Details $identity
    }.GetNewClosure()
    $stopped = {
        param($Proof)
        if ($null -eq $Transaction.ProcessReceipt -or $null -eq $Transaction.RootIdentity -or
            $Proof.Schema -isnot [int] -or $Proof.Schema -ne 1 -or $Proof.WholeJobEmpty -isnot [bool] -or
            -not $Proof.WholeJobEmpty -or $Proof.ProcessJobName -cne $Transaction.JobName -or
            $Proof.RootProcessId -ne $Transaction.RootIdentity.pid -or
            $Proof.RootStartTimeUtc -cne $Transaction.RootIdentity.getprocess_start_utc -or
            $Proof.DeadlineUtc -cne $Transaction.Deadline.ToUniversalTime().ToString('O') -or
            $Proof.Outcome -isnot [string] -or $Proof.Outcome -cnotin @('succeeded','terminated_failure') -or
            $Proof.RootExitCode -isnot [int] -or ($Proof.Outcome -ceq 'succeeded' -and $Proof.RootExitCode -ne 0)) {
            throw 'Original outer-job quiescence proof is unavailable.'
        }
        $bindingRechecked = $true
        try { & $assert -Transaction $Transaction }
        catch { $bindingRechecked = $false }
        $outcome = if ($bindingRechecked) { $Proof.Outcome } else { 'terminated_failure' }
        $Transaction.StopReceipt = & $publish -Transaction $Transaction -Kind stop -Details ([ordered]@{
            process_receipt_path=$Transaction.ProcessReceipt.Path; process_receipt_sha256=$Transaction.ProcessReceipt.Sha256
            root_pid=$Proof.RootProcessId; getprocess_start_utc=$Proof.RootStartTimeUtc; deadline_utc=$Proof.DeadlineUtc
            whole_job_empty=$true; outer_outcome=$Proof.Outcome; outcome=$outcome; root_exit_code=$Proof.RootExitCode
            original_binding_rechecked=$bindingRechecked
        })
        $Transaction.StopOutcome = $outcome
    }.GetNewClosure()
    Invoke-AtlasoBoundedStreamingProcess -FilePath $FilePath -ArgumentList $ArgumentList -TimeoutSeconds 420 `
        -Action 'Original concealed receiver credential transaction' -ProcessJobName $Transaction.JobName `
        -ProcessOwnershipPublisher $owner -ProcessQuiescencePublisher $stopped -DeadlineUtc $Transaction.Deadline -DiscardOutput
    if ($Transaction.StopOutcome -cne 'succeeded') {
        $failure = [InvalidOperationException]::new('Credential transaction admission failed after proven stop; preserve its original receipt.')
        $failure.Data['AtlasoProcessTreeTerminationProven'] = $true
        $failure.Data['AtlasoConsoleTransactionAdmissionFailed'] = $true
        throw $failure
    }
    return $Transaction.StopReceipt
}

<#
.SYNOPSIS
Verify the original suspended-root handoff before a credential child obtains any secret.
.PARAMETER Transaction
Same pinned plan and original VM/source bindings admitted by the outer controller.
#>
function Assert-AtlasoConsoleCredentialChild {
    param([Parameter(Mandatory)][psobject]$Transaction)
    Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
    $reads = [Collections.Generic.List[object]]::new()
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $job = $null
    try {
        foreach ($kind in @('intent','process')) {
            $path = $Transaction.Paths[$kind]
            # The parent holds original immutable read pins before resuming us.
            # Match that producer to this native process/job instead of treating
            # a caller-supplied SENT string as an original handoff.
            $sha = (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
            $read = Read-AtlasoConsoleTransactionRecord -Context $Transaction.Context -Path $path -Sha256 $sha `
                -Keys @('schema','phase','binding','observed_utc','details')
            $reads.Add($read)
            if (($read.Value.schema -isnot [int] -and $read.Value.schema -isnot [long]) -or $read.Value.schema -ne 1 -or
                $read.Value.phase -isnot [string] -or $read.Value.phase -cne ('console-credential-' + $kind) -or
                $read.Value.observed_utc -isnot [string] -or $read.Value.binding -isnot [Collections.IDictionary] -or
                ($read.Value.binding | ConvertTo-Json -Depth 8 -Compress) -cne ($Transaction.Binding | ConvertTo-Json -Depth 8 -Compress)) {
                throw 'Original credential handoff binding differs.'
            }
        }
        $intent = $reads[0].Value.details
        $root = $reads[1].Value.details
        $clockKeys = @('pid','getprocess_start_utc','start_filetime_utc','cim_creation_utc','parent_pid')
        foreach ($pair in @(@($intent, $clockKeys), @($root, ($clockKeys + 'job_name')))) {
            $detail = $pair[0]; $expected = $pair[1]
            if ($detail -isnot [Collections.IDictionary] -or $detail.Count -ne $expected.Count -or
                @($detail.Keys | Where-Object { $_ -cnotin $expected }).Count) { throw 'Original process-clock schema refused.' }
            foreach ($key in @('pid','parent_pid')) {
                if (($detail[$key] -isnot [int] -and $detail[$key] -isnot [long]) -or
                    $detail[$key] -lt 1 -or $detail[$key] -gt [int]::MaxValue) { throw 'Original process-clock type refused.' }
            }
            foreach ($key in @('getprocess_start_utc','start_filetime_utc','cim_creation_utc')) {
                if ($detail[$key] -isnot [string]) { throw 'Original process-clock type refused.' }
            }
        }
        $self = Get-AtlasoConsoleProcessCreation -Process $process
        if ($root.pid -ne $PID -or $root.start_filetime_utc -cne $self.start_filetime_utc -or
            $root.getprocess_start_utc -cne $self.getprocess_start_utc -or $root.cim_creation_utc -cne $self.cim_creation_utc -or
            $root.job_name -cne $Transaction.JobName -or $root.parent_pid -ne $self.parent_pid -or
            $self.parent_pid -ne $intent.pid) { throw 'Credential child is not the original suspended root.' }
        $parent = Get-Process -Id $intent.pid -ErrorAction Stop
        try {
            if ($parent.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture) -cne
                $intent.start_filetime_utc) { throw 'Original credential controller changed.' }
        }
        finally { $parent.Dispose() }
        $job = Open-AtlasoBoundedProcessJob -ProcessJobName $Transaction.JobName
        if ($null -eq $job -or -not $job.ContainsProcess($process)) { throw 'Credential child escaped original job containment.' }
        if (Test-Path -LiteralPath $Transaction.Paths.stop) { throw 'Stopped credential transaction cannot resume.' }
    }
    finally {
        if ($job) { $job.Dispose() }
        $process.Dispose()
        foreach ($read in $reads) { foreach ($pin in $read.Pins) { $pin.Dispose() } }
    }
}

<#
.SYNOPSIS
Release only this process's retained public read pins; never delete transaction evidence.
.PARAMETER Transaction
Opened original transaction, or null after an admission failure.
#>
function Close-AtlasoConsoleCredentialTransaction {
    param([AllowNull()][object]$Transaction)
    if ($Transaction -and -not $Transaction.IsClosed) {
        $Transaction.IsClosed = $true
        foreach ($pin in $Transaction.Pins) { $pin.Dispose() }
    }
}
