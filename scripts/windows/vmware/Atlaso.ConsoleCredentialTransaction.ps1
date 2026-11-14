<#
.SYNOPSIS
Journal one separately admitted normal-VM console credential transaction.
.DESCRIPTION
Requires the existing original VM/source admission and public concealed-receiver
receipt. It publishes no guest acknowledgement and grants no native acceptance.
The guest receiver and public-launch producer remain separate required interfaces.
#>

# Only the actual synchronous outer invocation can install completion authority.
# Reference identity rejects copied/serialized/historical transactions. This is
# not a sandbox against arbitrary code running as the trusted host controller.
$script:AtlasoConsoleStopAuthorities = [Runtime.CompilerServices.ConditionalWeakTable[object,object]]::new()

<#
.SYNOPSIS
Encode the restricted public stop schema with Python-compatible canonical ASCII JSON.
.PARAMETER Value
Public dictionaries, identifier strings, booleans or exact signed integers; never secrets.
.PARAMETER Depth
Bound the fixed envelope and payload nesting without accepting arbitrary JSON structures.
#>
function ConvertTo-AtlasoConsoleStopCanonicalJson {
    param([Parameter(Mandatory)][AllowNull()][object]$Value, [ValidateRange(0,4)][int]$Depth = 0)
    if ($Value -is [Collections.IDictionary]) {
        $names = [Collections.Generic.List[string]]::new()
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($key in $Value.Keys) {
            if ($key -isnot [string] -or $key -cnotmatch '\A[a-z0-9_]+\z' -or -not $seen.Add($key)) {
                throw 'Canonical stop object key refused.'
            }
            $names.Add($key)
        }
        $names.Sort([StringComparer]::Ordinal)
        $parts = [Collections.Generic.List[string]]::new()
        foreach ($name in $names) {
            $encoded = ConvertTo-AtlasoConsoleStopCanonicalJson -Value $Value[$name] -Depth ($Depth + 1)
            $parts.Add(('"' + $name + '":' + $encoded))
        }
        $result = '{' + [string]::Join(',', $parts) + '}'
    }
    elseif ($Value -is [string]) {
        # All admitted schema text uses this alphabet. No escaping or coercion
        # can silently produce different bytes from the guest verifier.
        if ($Value -cnotmatch '\A[A-Za-z0-9_.:-]+\z') { throw 'Canonical stop identifier refused.' }
        $result = '"' + $Value + '"'
    }
    elseif ($Value -is [bool]) { $result = if ($Value) { 'true' } else { 'false' } }
    elseif ($Value -is [int] -or $Value -is [long]) {
        $result = $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    else { throw 'Canonical stop primitive type refused.' }
    if ($result.Length -gt 3000) { throw 'Canonical stop statement exceeded its public bound.' }
    return $result
}

<#
.SYNOPSIS
Snapshot the public original context and runtime selectors without serializing pins.
.PARAMETER Transaction
Original open transaction whose context/options must remain unchanged.
#>
function Get-AtlasoConsoleSelectorSnapshot {
    param([Parameter(Mandatory)][psobject]$Transaction)
    $context = [ordered]@{}
    foreach ($name in @('Enabled','TaskId','ActiveTaskId','ContinuationReceiptPath','ContinuationReceiptSha256',
            'Repository','Worktree','WorktreeDirectoryId','PermittedRoot','Branch','SourceCommit','PullRequestNumber',
            'LocalBuilder','Name','OutputDirectory','VmxPath','EvidenceDirectory','EvidenceDirectoryId','ReceiptPath',
            'ReceiptSha256','ValidationRootAdmission','InvocationId')) {
        $member = $Transaction.Context.PSObject.Properties[$name]
        if ($null -eq $member) { throw 'Original context selector is missing.' }
        $value = $member.Value
        if ($null -ne $value -and $value -isnot [string] -and $value -isnot [bool] -and
            $value -isnot [int] -and $value -isnot [long]) { throw 'Original context selector type refused.' }
        $context.Add($name, $value)
    }
    $names = @('Account','Port','ScreenPath','ScreenSha256','FieldRectangle','PythonPath','RuntimeSha256','RuntimeFileCount')
    if ($Transaction.Options.Count -ne $names.Count) { throw 'Original runtime selector schema differs.' }
    $options = [ordered]@{}
    foreach ($name in $names) {
        if (-not $Transaction.Options.ContainsKey($name)) { throw 'Original runtime selector is missing.' }
        $value = $Transaction.Options[$name]
        if ($value -isnot [string] -and $value -isnot [int] -and $value -isnot [long]) {
            throw 'Original runtime selector type refused.'
        }
        $options.Add($name, $value)
    }
    return ([ordered]@{context=$context; options=$options} | ConvertTo-Json -Depth 5 -Compress)
}

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
        if ($ProtocolVersion -eq 2) {
            $paths['ack-intent'] = Join-Path $Context.EvidenceDirectory ('atlaso-test-vm-console-credential-ack-intent-' + $plan.receiver_nonce + '.json')
        }
        $transaction = [pscustomobject]@{Context=$Context; Options=$Options; Plan=$plan; Binding=$binding; Paths=$paths;
            PlanReceipt=[pscustomobject]@{Path=$PlanPath; Sha256=$PlanSha256};
            Deadline=$deadline; Pins=$pins; JobName=('Local\Atlaso-ConsoleCredential-' + $plan.receiver_nonce);
            ProtocolVersion=$ProtocolVersion; IsClosed=$false; ControllerIdentity=$null; IntentReceipt=$null; AckIntentReceipt=$null;
            RootIdentity=$null; ProcessReceipt=$null; StopReceipt=$null; StopOutcome=$null}
        Assert-AtlasoConsoleTransactionBinding -Transaction $transaction
        if ($ProtocolVersion -eq 2) {
            $sourcePin = if ($Context.PSObject.Properties['CheckoutSourcePin']) { $Context.CheckoutSourcePin } else { $null }
            $authority = [pscustomobject]@{
                Context=$Context; Options=$Options; SourcePin=$sourcePin
                SelectorsJson=(Get-AtlasoConsoleSelectorSnapshot -Transaction $transaction)
                BindingJson=($binding | ConvertTo-Json -Depth 8 -Compress); PlanJson=($plan | ConvertTo-Json -Depth 8 -Compress)
                PlanPath=$PlanPath; PlanSha256=$PlanSha256; DeadlineUtc=$deadline.ToUniversalTime().ToString('O')
                Lock=[object]::new(); JobName=$transaction.JobName; ControllerJson=$null; RootJson=$null; StopJson=$null
                IntentPath=$null; IntentSha256=$null; ProcessPath=$null; ProcessSha256=$null; StopPath=$null; StopSha256=$null
                Invoked=$false; Completed=$false; AckAttempted=$false; PublishingAck=$false; AckThreadId=0; AckDetailsJson=$null
                AckPrepared=$false; AckPath=$null; AckSha256=$null; AckRecordJson=$null
                UnsignedJson=$null; UnsignedSha256=$null; PublicKeyHex=$null
                SigningAttempted=$false; PublishingSigning=$false; SigningThreadId=0; SigningDetailsJson=$null
                SigningIntentPath=$null; SigningIntentSha256=$null; SigningPrepared=$false
                SignerAttempted=$false; PublishingSigner=$false; SignerThreadId=0; SignerKind=$null; SignerDetailsJson=$null
                SignerProcessPath=$null; SignerProcessSha256=$null; SignerRootJson=$null; SignerRootPid=0; SignerRootStartUtc=$null
                SignerStopPath=$null; SignerStopSha256=$null
            }
            $script:AtlasoConsoleStopAuthorities.Add($transaction, $authority)
        }
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
Exact original phase; ACK and signing intents require their separate private preparation paths.
.PARAMETER Details
Public original process facts created by the committed controller.
#>
function Publish-AtlasoConsoleCredentialRecord {
    param([Parameter(Mandatory)][psobject]$Transaction, [Parameter(Mandatory)][ValidateSet('intent','process','stop','ack-intent','signing-intent','signer-process','signer-stop')][string]$Kind,
        [Parameter(Mandatory)][Collections.IDictionary]$Details)
    if ($Transaction.IsClosed -isnot [bool] -or $Transaction.IsClosed) { throw 'Original console transaction is closed.' }
    $expectedPath = $Transaction.Paths[$Kind]
    if ($Kind -cin @('ack-intent','signing-intent','signer-process','signer-stop')) {
        $authority = $null
        if ($Transaction.ProtocolVersion -ne 2 -or
            -not $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$authority) -or
            -not $authority.Completed -or
            (Get-AtlasoConsoleSelectorSnapshot -Transaction $Transaction) -cne $authority.SelectorsJson -or
            ($Transaction.Binding | ConvertTo-Json -Depth 8 -Compress) -cne $authority.BindingJson) {
            throw 'Console intent requires its original verified preparation path.'
        }
        $threadId = [Threading.Thread]::CurrentThread.ManagedThreadId
        $detailsJson = $Details | ConvertTo-Json -Depth 8 -Compress
        if ($Kind -ceq 'ack-intent') {
            if (-not $authority.PublishingAck -or $authority.AckThreadId -ne $threadId -or
                $detailsJson -cne $authority.AckDetailsJson) { throw 'ACK intent requires private preparation.' }
        }
        elseif ($Kind -ceq 'signing-intent') {
            if (-not $authority.AckPrepared -or -not $authority.SigningAttempted -or
                -not $authority.PublishingSigning -or $authority.SigningThreadId -ne $threadId -or
                $detailsJson -cne $authority.SigningDetailsJson) { throw 'Signing intent requires private preparation.' }
            $expectedPath = $authority.SigningIntentPath
        }
        else {
            if (-not $authority.SigningPrepared -or -not $authority.SignerAttempted -or
                -not $authority.PublishingSigner -or $authority.SignerThreadId -ne $threadId -or
                $authority.SignerKind -cne $Kind -or $detailsJson -cne $authority.SignerDetailsJson) {
                throw 'Signer record requires its original suspended-root or outer-stop publisher.'
            }
            $expectedPath = if ($Kind -ceq 'signer-process') { $authority.SignerProcessPath } else { $authority.SignerStopPath }
        }
    }
    $record = [ordered]@{schema=1; phase=('console-credential-' + $Kind); binding=$Transaction.Binding;
        observed_utc=[DateTimeOffset]::UtcNow.ToString('O'); details=$Details}
    if ([Text.Encoding]::UTF8.GetByteCount(($record | ConvertTo-Json -Depth 8 -Compress)) -gt 16384) {
        throw 'Public console transaction record exceeded its bound.'
    }
    $published = Publish-AtlasoTestVmOwnershipRecord -Context $Transaction.Context -Record $record -Kind ('console-credential-' + $Kind)
    if ($published.Path -cne $expectedPath) { throw 'Original console transaction namespace changed.' }
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
    $authority = $null
    $registered = $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$authority)
    if ($registered -or $Transaction.ProtocolVersion -eq 2) {
        if (-not $registered -or $Transaction.ProtocolVersion -ne 2) { throw 'Original v2 admission reference is unavailable.' }
        [Threading.Monitor]::Enter($authority.Lock)
        try {
            if ($Transaction.IsClosed -or $authority.Invoked -or
                -not [object]::ReferenceEquals($Transaction.Context, $authority.Context) -or
                -not [object]::ReferenceEquals($Transaction.Options, $authority.Options) -or
                $null -eq $authority.SourcePin -or
                -not [object]::ReferenceEquals($Transaction.Context.CheckoutSourcePin, $authority.SourcePin) -or
                $authority.SourcePin.Disposed -or $authority.SourcePin.Pins.Count -eq 0 -or $Transaction.Pins.Count -eq 0 -or
                (Get-AtlasoConsoleSelectorSnapshot -Transaction $Transaction) -cne $authority.SelectorsJson -or
                ($Transaction.Binding | ConvertTo-Json -Depth 8 -Compress) -cne $authority.BindingJson -or
                ($Transaction.Plan | ConvertTo-Json -Depth 8 -Compress) -cne $authority.PlanJson -or
                $Transaction.PlanReceipt.Path -cne $authority.PlanPath -or $Transaction.PlanReceipt.Sha256 -cne $authority.PlanSha256 -or
                $Transaction.Deadline -isnot [DateTimeOffset] -or
                $Transaction.Deadline.ToUniversalTime().ToString('O') -cne $authority.DeadlineUtc -or
                $Transaction.JobName -cne $authority.JobName -or $Transaction.Paths.Count -ne 4) {
                throw 'Original v2 admission changed before invocation.'
            }
            foreach ($kind in @('intent','process','stop','ack-intent')) {
                $expected = Join-Path $authority.Context.EvidenceDirectory (
                    'atlaso-test-vm-console-credential-' + $kind + '-' + $Transaction.Plan.receiver_nonce + '.json')
                if ($Transaction.Paths[$kind] -cne $expected) { throw 'Original v2 phase path differs.' }
            }
            $authority.Invoked = $true
        }
        finally { [Threading.Monitor]::Exit($authority.Lock) }
    }
    Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
    foreach ($path in $Transaction.Paths.Values) { if (Test-Path -LiteralPath $path) { throw 'Original receiver transaction exists; preserve without replay.' } }
    if ($authority) {
        $admitted = Open-AtlasoConsoleCredentialTransaction -Context $Transaction.Context -Options $Transaction.Options `
            -PlanPath $Transaction.PlanReceipt.Path -PlanSha256 $Transaction.PlanReceipt.Sha256 -ProtocolVersion 2
        try {
            if (($Transaction.Binding | ConvertTo-Json -Depth 8 -Compress) -cne
                ($admitted.Binding | ConvertTo-Json -Depth 8 -Compress) -or
                ($Transaction.Plan | ConvertTo-Json -Depth 8 -Compress) -cne
                ($admitted.Plan | ConvertTo-Json -Depth 8 -Compress) -or
                $Transaction.Deadline -isnot [DateTimeOffset] -or $Transaction.Deadline -ne $admitted.Deadline) {
                throw 'Original v2 invocation binding differs.'
            }
        }
        finally { Close-AtlasoConsoleCredentialTransaction -Transaction $admitted }
    }
    $controller = [Diagnostics.Process]::GetCurrentProcess()
    try { $controllerIdentity = Get-AtlasoConsoleProcessCreation -Process $controller }
    finally { $controller.Dispose() }
    $Transaction.ControllerIdentity = $controllerIdentity
    $Transaction.IntentReceipt = Publish-AtlasoConsoleCredentialRecord -Transaction $Transaction -Kind intent -Details $controllerIdentity
    if ($authority) {
        $authority.ControllerJson = $controllerIdentity | ConvertTo-Json -Depth 4 -Compress
        $authority.IntentPath = $Transaction.IntentReceipt.Path; $authority.IntentSha256 = $Transaction.IntentReceipt.Sha256
    }
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
        if ($authority) {
            $authority.RootJson = $identity | ConvertTo-Json -Depth 4 -Compress
            $authority.ProcessPath = $Transaction.ProcessReceipt.Path; $authority.ProcessSha256 = $Transaction.ProcessReceipt.Sha256
        }
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
        $details = [ordered]@{
            process_receipt_path=$Transaction.ProcessReceipt.Path; process_receipt_sha256=$Transaction.ProcessReceipt.Sha256
            root_pid=$Proof.RootProcessId; getprocess_start_utc=$Proof.RootStartTimeUtc; deadline_utc=$Proof.DeadlineUtc
            whole_job_empty=$true; outer_outcome=$Proof.Outcome; outcome=$outcome; root_exit_code=$Proof.RootExitCode
            original_binding_rechecked=$bindingRechecked
        }
        $Transaction.StopReceipt = & $publish -Transaction $Transaction -Kind stop -Details $details
        $Transaction.StopOutcome = $outcome
        if ($authority) {
            $authority.StopJson = $details | ConvertTo-Json -Depth 4 -Compress
            $authority.StopPath = $Transaction.StopReceipt.Path; $authority.StopSha256 = $Transaction.StopReceipt.Sha256
            $authority.Completed = $true
        }
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
Validate the exact original clock schema without reconstructing an exited process.
.PARAMETER Value
Original decoded intent or process details.
.PARAMETER IncludeJob
Require the original named job on a suspended-root record.
#>
function Assert-AtlasoConsoleOriginalClock {
    param([Parameter(Mandatory)][Collections.IDictionary]$Value, [switch]$IncludeJob)
    $keys = @('pid','getprocess_start_utc','start_filetime_utc','cim_creation_utc','parent_pid')
    if ($IncludeJob) { $keys += 'job_name' }
    if ($Value.Count -ne $keys.Count -or @($Value.Keys | Where-Object { $_ -cnotin $keys }).Count) {
        throw 'Original clock schema differs.'
    }
    foreach ($name in @('pid','parent_pid')) {
        if (($Value[$name] -isnot [int] -and $Value[$name] -isnot [long]) -or
            $Value[$name] -lt 1 -or $Value[$name] -gt [int]::MaxValue) { throw 'Original clock PID differs.' }
    }
    if ($Value.start_filetime_utc -isnot [string] -or $Value.start_filetime_utc -cnotmatch '^[1-9][0-9]{0,18}$') {
        throw 'Original native clock differs.'
    }
    foreach ($name in @('getprocess_start_utc','cim_creation_utc')) {
        $time = [DateTimeOffset]::MinValue
        if ($Value[$name] -isnot [string] -or -not [DateTimeOffset]::TryParseExact($Value[$name], 'O',
                [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$time)) {
            throw 'Original UTC clock differs.'
        }
    }
    if ($IncludeJob -and ($Value.job_name -isnot [string] -or -not $Value.job_name)) { throw 'Original job name is missing.' }
}

<#
.SYNOPSIS
Read coherent original credential phase data and retain its read pins, without live authority.
.PARAMETER Transaction
Freshly reopened original v2 plan and receiver binding.
.PARAMETER Selectors
Independently retained exact intent, process and stop paths and digests.
#>
function Read-AtlasoConsoleCredentialStopChain {
    param([Parameter(Mandatory)][psobject]$Transaction, [Parameter(Mandatory)][Collections.IDictionary]$Selectors)
    $keys = @('intent_path','intent_sha256','process_path','process_sha256','stop_path','stop_sha256')
    if ($Selectors.Count -ne $keys.Count -or @($Selectors.Keys | Where-Object { $_ -cnotin $keys }).Count -or
        $Transaction.ProtocolVersion -ne 2) { throw 'Original chain selectors differ.' }
    foreach ($kind in @('intent','process','stop')) {
        $pathKey = $kind + '_path'; $shaKey = $kind + '_sha256'
        $expected = Join-Path $Transaction.Context.EvidenceDirectory (
            'atlaso-test-vm-console-credential-' + $kind + '-' + $Transaction.Plan.receiver_nonce + '.json')
        if ($Selectors[$pathKey] -isnot [string] -or $Selectors[$pathKey] -cne $expected -or
            $Selectors[$shaKey] -isnot [string]) { throw 'Original chain phase path differs.' }
    }
    $bindingJson = $Transaction.Binding | ConvertTo-Json -Depth 8 -Compress
    $deadlineUtc = $Transaction.Deadline.ToUniversalTime().ToString('O')
    $reads = [Collections.Generic.List[object]]::new()
    $pins = [Collections.Generic.List[IDisposable]]::new()
    try {
        $previous = [DateTimeOffset]::MinValue
        $phases = @(
            @{Kind='intent'; Path=$Selectors.intent_path; Sha256=$Selectors.intent_sha256},
            @{Kind='process'; Path=$Selectors.process_path; Sha256=$Selectors.process_sha256},
            @{Kind='stop'; Path=$Selectors.stop_path; Sha256=$Selectors.stop_sha256})
        foreach ($phase in $phases) {
            $kind = $phase.Kind
            $read = Read-AtlasoConsoleTransactionRecord -Context $Transaction.Context -Path $phase.Path -Sha256 $phase.Sha256 `
                -Keys @('schema','phase','binding','observed_utc','details')
            $reads.Add($read)
            $record = $read.Value
            $observed = [DateTimeOffset]::MinValue
            if (($record.schema -isnot [int] -and $record.schema -isnot [long]) -or $record.schema -ne 1 -or
                $record.phase -isnot [string] -or $record.phase -cne ('console-credential-' + $kind) -or
                $record.binding -isnot [Collections.IDictionary] -or
                ($record.binding | ConvertTo-Json -Depth 8 -Compress) -cne $bindingJson -or
                $record.details -isnot [Collections.IDictionary] -or $record.observed_utc -isnot [string] -or
                -not [DateTimeOffset]::TryParseExact($record.observed_utc, 'O', [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$observed) -or $observed -lt $previous -or
                $observed -gt [DateTimeOffset]::UtcNow -or $observed -ge $Transaction.Deadline) {
                throw 'Original phase envelope or ordering differs.'
            }
            $previous = $observed
        }
        $controller = $reads[0].Value.details; $root = $reads[1].Value.details; $stop = $reads[2].Value.details
        Assert-AtlasoConsoleOriginalClock -Value $controller
        Assert-AtlasoConsoleOriginalClock -Value $root -IncludeJob
        if ($root.parent_pid -ne $controller.pid -or $root.job_name -cne $Transaction.JobName) {
            throw 'Original controller/root relationship differs.'
        }
        $keys = @('process_receipt_path','process_receipt_sha256','root_pid','getprocess_start_utc','deadline_utc',
            'whole_job_empty','outer_outcome','outcome','root_exit_code','original_binding_rechecked')
        if ($stop.Count -ne $keys.Count -or @($stop.Keys | Where-Object { $_ -cnotin $keys }).Count -or
            $stop.process_receipt_path -isnot [string] -or $stop.process_receipt_path -cne $Selectors.process_path -or
            $stop.process_receipt_sha256 -isnot [string] -or $stop.process_receipt_sha256 -cne $Selectors.process_sha256 -or
            ($stop.root_pid -isnot [int] -and $stop.root_pid -isnot [long]) -or $stop.root_pid -ne $root.pid -or
            $stop.getprocess_start_utc -isnot [string] -or $stop.getprocess_start_utc -cne $root.getprocess_start_utc -or
            $stop.deadline_utc -isnot [string] -or $stop.deadline_utc -cne $deadlineUtc -or
            $stop.whole_job_empty -isnot [bool] -or -not $stop.whole_job_empty -or
            $stop.original_binding_rechecked -isnot [bool] -or
            $stop.outer_outcome -isnot [string] -or $stop.outer_outcome -cnotin @('succeeded','terminated_failure') -or
            $stop.outcome -isnot [string] -or $stop.outcome -cnotin @('succeeded','terminated_failure') -or
            ($stop.root_exit_code -isnot [int] -and $stop.root_exit_code -isnot [long]) -or
            $stop.root_exit_code -lt [int]::MinValue -or $stop.root_exit_code -gt [int]::MaxValue -or
            ($stop.outer_outcome -ceq 'succeeded' -and $stop.root_exit_code -ne 0) -or
            ($stop.original_binding_rechecked -and $stop.outcome -cne $stop.outer_outcome) -or
            (-not $stop.original_binding_rechecked -and $stop.outcome -cne 'terminated_failure')) { throw 'Original stop facts are incoherent.' }
        foreach ($read in $reads) {
            foreach ($pin in $read.Pins) { $pins.Add($pin) }; $read.Pins.Clear()
        }
        return [pscustomobject]@{Controller=$controller; Root=$root; Stop=$stop; Pins=$pins}
    }
    finally { foreach ($read in $reads) { foreach ($pin in $read.Pins) { $pin.Dispose() } } }
}

<#
.SYNOPSIS
Verify the original live invocation's complete stop chain without granting native acceptance.
.PARAMETER Transaction
Same still-open v2 object completed by the source-pinned outer callback, never a record projection.
#>
function Get-AtlasoVerifiedConsoleCredentialStop {
    param([Parameter(Mandatory)][psobject]$Transaction)
    $authority = $null
    if ($Transaction.ProtocolVersion -ne 2 -or $Transaction.IsClosed -isnot [bool] -or $Transaction.IsClosed -or
        -not $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$authority)) {
        throw 'Original live v2 stop authority is unavailable.'
    }
    [Threading.Monitor]::Enter($authority.Lock)
    $fresh = $null
    $reads = [Collections.Generic.List[object]]::new()
    try {
        $current = $null
        if (-not $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$current) -or
            -not [object]::ReferenceEquals($current, $authority) -or -not $authority.Completed -or $Transaction.IsClosed -or
            -not [object]::ReferenceEquals($Transaction.Context, $authority.Context) -or
            -not [object]::ReferenceEquals($Transaction.Options, $authority.Options) -or
            -not [object]::ReferenceEquals($Transaction.Context.CheckoutSourcePin, $authority.SourcePin) -or
            $authority.SourcePin.Disposed -or $authority.SourcePin.Pins.Count -eq 0 -or $Transaction.Pins.Count -eq 0 -or
            (Get-AtlasoConsoleSelectorSnapshot -Transaction $Transaction) -cne $authority.SelectorsJson -or
            ($Transaction.Binding | ConvertTo-Json -Depth 8 -Compress) -cne $authority.BindingJson -or
            ($Transaction.Plan | ConvertTo-Json -Depth 8 -Compress) -cne $authority.PlanJson -or
            $Transaction.Deadline -isnot [DateTimeOffset] -or
            $Transaction.Deadline.ToUniversalTime().ToString('O') -cne $authority.DeadlineUtc -or
            $Transaction.JobName -cne $authority.JobName -or $Transaction.Paths.Count -ne 4) {
            throw 'Original live invocation selectors or pins changed.'
        }
        foreach ($kind in @('intent','process','stop','ack-intent')) {
            $expected = Join-Path $authority.Context.EvidenceDirectory (
                'atlaso-test-vm-console-credential-' + $kind + '-' + $Transaction.Plan.receiver_nonce + '.json')
            if ($Transaction.Paths[$kind] -cne $expected) { throw 'Original phase path differs.' }
        }
        foreach ($row in @(
                @($Transaction.PlanReceipt, $authority.PlanPath, $authority.PlanSha256),
                @($Transaction.IntentReceipt, $authority.IntentPath, $authority.IntentSha256),
                @($Transaction.ProcessReceipt, $authority.ProcessPath, $authority.ProcessSha256),
                @($Transaction.StopReceipt, $authority.StopPath, $authority.StopSha256))) {
            if ($null -eq $row[0] -or $row[0].Path -cne $row[1] -or $row[0].Sha256 -cne $row[2]) {
                throw 'Original publisher-returned selectors changed.'
            }
        }
        if (($Transaction.ControllerIdentity | ConvertTo-Json -Depth 4 -Compress) -cne $authority.ControllerJson -or
            ($Transaction.RootIdentity | ConvertTo-Json -Depth 4 -Compress) -cne $authority.RootJson) {
            throw 'Original process identity cache changed.'
        }
        $self = [Diagnostics.Process]::GetCurrentProcess()
        try { $live = Get-AtlasoConsoleProcessCreation -Process $self }
        finally { $self.Dispose() }
        if (($live | ConvertTo-Json -Depth 4 -Compress) -cne $authority.ControllerJson) {
            throw 'The original controller is not this live invocation.'
        }
        $fresh = Open-AtlasoConsoleCredentialTransaction -Context $authority.Context -Options $authority.Options `
            -PlanPath $authority.PlanPath -PlanSha256 $authority.PlanSha256 -ProtocolVersion 2
        if (($fresh.Binding | ConvertTo-Json -Depth 8 -Compress) -cne $authority.BindingJson -or
            ($fresh.Plan | ConvertTo-Json -Depth 8 -Compress) -cne $authority.PlanJson -or
            $fresh.Deadline.ToUniversalTime().ToString('O') -cne $authority.DeadlineUtc) {
            throw 'Original plan or receiver changed.'
        }
        $chain = Read-AtlasoConsoleCredentialStopChain -Transaction $fresh -Selectors @{
            intent_path=$authority.IntentPath; intent_sha256=$authority.IntentSha256
            process_path=$authority.ProcessPath; process_sha256=$authority.ProcessSha256
            stop_path=$authority.StopPath; stop_sha256=$authority.StopSha256}
        $reads.Add($chain)
        $controller=$chain.Controller; $root=$chain.Root; $stop=$chain.Stop
        if (($controller | ConvertTo-Json -Depth 4 -Compress) -cne $authority.ControllerJson -or
            ($root | ConvertTo-Json -Depth 4 -Compress) -cne $authority.RootJson -or
            ($stop | ConvertTo-Json -Depth 4 -Compress) -cne $authority.StopJson -or
            $Transaction.StopOutcome -cne $stop.outcome) { throw 'Original controller/root/stop chain differs.' }
        Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
        if ((Get-AtlasoConsoleSelectorSnapshot -Transaction $Transaction) -cne $authority.SelectorsJson -or
            -not [object]::ReferenceEquals($Transaction.Context.CheckoutSourcePin, $authority.SourcePin)) {
            throw 'Original selectors changed during chain validation.'
        }
        # Transfer ownership of the new read handles before disposing the temporary admission.
        foreach ($pin in $fresh.Pins) { $Transaction.Pins.Add($pin) }; $fresh.Pins.Clear()
        foreach ($read in $reads) {
            foreach ($pin in $read.Pins) { $Transaction.Pins.Add($pin) }; $read.Pins.Clear()
        }
        return [pscustomobject]@{Binding=$fresh.Binding; Controller=$controller; Root=$root; Stop=$stop; Deadline=$fresh.Deadline}
    }
    finally {
        try {
            Close-AtlasoConsoleCredentialTransaction -Transaction $fresh
            foreach ($read in $reads) { foreach ($pin in $read.Pins) { $pin.Dispose() } }
        }
        finally { [Threading.Monitor]::Exit($authority.Lock) }
    }
}

<#
.SYNOPSIS
Publish one exclusive original ACK intent and return only an unsigned public statement.
.PARAMETER Transaction
Original still-open v2 invocation; no external outcome or receipt selectors are accepted.
#>
function Prepare-AtlasoConsoleCredentialStopAck {
    param([Parameter(Mandatory)][psobject]$Transaction)
    $authority = $null
    if (-not $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$authority)) {
        throw 'Original live stop authority is unavailable.'
    }
    [Threading.Monitor]::Enter($authority.Lock)
    try {
        if ($authority.AckAttempted) { throw 'Original ACK preparation was already attempted; preserve without replay.' }
        $verified = Get-AtlasoVerifiedConsoleCredentialStop -Transaction $Transaction
        $authority.AckAttempted = $true
        if (Test-Path -LiteralPath $Transaction.Paths['ack-intent']) { throw 'Original ACK intent exists; preserve without adoption.' }
        $binding = $verified.Binding
        $details = [ordered]@{
            status='prepared_unsigned_no_ack'; plan_receipt_path=$authority.PlanPath; plan_receipt_sha256=$authority.PlanSha256
            receiver_receipt_path=$binding.receiver_receipt_path; receiver_receipt_sha256=$binding.receiver_receipt_sha256
            intent_receipt_path=$authority.IntentPath; intent_receipt_sha256=$authority.IntentSha256
            process_receipt_path=$authority.ProcessPath; process_receipt_sha256=$authority.ProcessSha256
            stop_receipt_path=$authority.StopPath; stop_receipt_sha256=$authority.StopSha256
            signing_key_sha256=$binding.stop_ack_signing_key_sha256; transport_key=$binding.stop_ack_transport_key
            deadline_utc=$authority.DeadlineUtc; outcome=$verified.Stop.outcome
        }
        Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
        $authority.AckDetailsJson = $details | ConvertTo-Json -Depth 8 -Compress
        $authority.PublishingAck = $true; $authority.AckThreadId = [Threading.Thread]::CurrentThread.ManagedThreadId
        try { $published = Publish-AtlasoConsoleCredentialRecord -Transaction $Transaction -Kind ack-intent -Details $details }
        finally { $authority.PublishingAck = $false; $authority.AckThreadId = 0 }
        $Transaction.AckIntentReceipt = [pscustomobject]@{Path=$published.Path; Sha256=$published.Sha256}
        Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
        if ((Get-AtlasoConsoleSelectorSnapshot -Transaction $Transaction) -cne $authority.SelectorsJson) {
            throw 'Original selectors changed during ACK preparation; preserve its intent without replay.'
        }
        $payload = [ordered]@{
            task_id=$binding.task_id; source_commit=$binding.source_commit; bundle_sha256=$binding.guest_bundle_sha256
            run_id=$binding.run_id; receiver_nonce=$binding.receiver_nonce; guest_boot_id=$binding.guest_boot_id
            host_boot_identity=$binding.host_boot_identity; original_vm_receipt_sha256=$binding.original_vm_receipt_sha256
            persistent_vm_identity_sha256=$binding.persistent_vm_identity_sha256; plan_sha256=$authority.PlanSha256
            receiver_receipt_sha256=$binding.receiver_receipt_sha256; process_receipt_sha256=$authority.ProcessSha256
            stop_receipt_sha256=$authority.StopSha256; ack_intent_sha256=$published.Sha256
            transport_key=$binding.stop_ack_transport_key; deadline_unix_ms=$verified.Deadline.ToUnixTimeMilliseconds()
            root_pid=$verified.Root.pid; root_start_filetime_utc=$verified.Root.start_filetime_utc
            whole_job_empty=$verified.Stop.whole_job_empty; outcome=$verified.Stop.outcome
            root_exit_code=$verified.Stop.root_exit_code; original_binding_rechecked=$verified.Stop.original_binding_rechecked
        }
        $unsigned = [ordered]@{schema=2; kind='console-sdk-stop-ack-v2'; algorithm='Ed25519';
            signing_key_sha256=$binding.stop_ack_signing_key_sha256; payload=$payload}
        $canonical = ConvertTo-AtlasoConsoleStopCanonicalJson -Value $unsigned
        # The eventual signed envelope must also fit the guest's 3000-byte cap.
        $signatureOverhead = ',"signature_hex":""'.Length + 128
        if ($canonical.Length + $signatureOverhead -gt 3000) { throw 'Unsigned stop statement leaves no signature budget.' }
        $read = Read-AtlasoConsoleTransactionRecord -Context $authority.Context -Path $published.Path -Sha256 $published.Sha256 `
            -Keys @('schema','phase','binding','observed_utc','details')
        try {
            $observed = [DateTimeOffset]::MinValue
            if ($read.Value.schema -ne 1 -or $read.Value.phase -cne 'console-credential-ack-intent' -or
                ($read.Value.binding | ConvertTo-Json -Depth 8 -Compress) -cne $authority.BindingJson -or
                ($read.Value.details | ConvertTo-Json -Depth 8 -Compress) -cne $authority.AckDetailsJson -or
                $read.Value.observed_utc -isnot [string] -or
                -not [DateTimeOffset]::TryParseExact($read.Value.observed_utc, 'O', [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::None, [ref]$observed) -or
                $observed -gt [DateTimeOffset]::UtcNow -or $observed -ge $Transaction.Deadline) {
                throw 'Original ACK intent readback differs.'
            }
            $null = Get-AtlasoVerifiedConsoleCredentialStop -Transaction $Transaction
            foreach ($pin in $read.Pins) { $Transaction.Pins.Add($pin) }; $read.Pins.Clear()
            # Freeze only successfully admitted preparation. Public projections
            # and the transaction's mutable receipt property are never custody.
            $authority.AckPath = $published.Path; $authority.AckSha256 = $published.Sha256
            $authority.AckRecordJson = $read.Value | ConvertTo-Json -Depth 8 -Compress
            $authority.UnsignedJson = $canonical
            $authority.UnsignedSha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
                [Text.Encoding]::ASCII.GetBytes($canonical))).ToLowerInvariant()
            $authority.PublicKeyHex = $binding.stop_ack_public_key_hex
            $authority.AckPrepared = $true
        }
        finally { foreach ($pin in $read.Pins) { $pin.Dispose() } }
        return [pscustomobject]@{status='prepared_unsigned_no_ack'; public_key_hex=$authority.PublicKeyHex;
            ack_intent_receipt=[pscustomobject]@{Path=$authority.AckPath; Sha256=$authority.AckSha256};
            unsigned_envelope=$unsigned; unsigned_canonical_ascii=$canonical; unsigned_sha256=$authority.UnsignedSha256}
    }
    finally { [Threading.Monitor]::Exit($authority.Lock) }
}

<#
.SYNOPSIS
Publish one original signing request without launching a child or choosing a backend.
.PARAMETER Transaction
Same still-open v2 reference with privately retained successful ACK preparation.
#>
function New-AtlasoConsoleStopSigningRequest {
    param([Parameter(Mandatory)][psobject]$Transaction)
    $authority = $null
    if (-not $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$authority)) {
        throw 'Original live signing-request authority is unavailable.'
    }
    [Threading.Monitor]::Enter($authority.Lock)
    $read = $null
    $document = $null
    try {
        if (-not $authority.AckPrepared) { throw 'Original successful ACK preparation is unavailable.' }
        if ($authority.SigningAttempted) { throw 'Original signing request was already attempted; preserve without replay.' }
        $authority.SigningAttempted = $true
        $verified = Get-AtlasoVerifiedConsoleCredentialStop -Transaction $Transaction
        $expectedAck = Join-Path $authority.Context.EvidenceDirectory (
            'atlaso-test-vm-console-credential-ack-intent-' + $verified.Binding.receiver_nonce + '.json')
        if ($authority.AckPath -cne $expectedAck -or $null -eq $Transaction.AckIntentReceipt -or
            $Transaction.AckIntentReceipt.Path -cne $authority.AckPath -or
            $Transaction.AckIntentReceipt.Sha256 -cne $authority.AckSha256 -or
            $authority.PublicKeyHex -cne $verified.Binding.stop_ack_public_key_hex) {
            throw 'Original prepared ACK selectors changed.'
        }
        $read = Read-AtlasoConsoleTransactionRecord -Context $authority.Context -Path $authority.AckPath -Sha256 $authority.AckSha256 `
            -Keys @('schema','phase','binding','observed_utc','details')
        if (($read.Value | ConvertTo-Json -Depth 8 -Compress) -cne $authority.AckRecordJson) {
            throw 'Original prepared ACK record changed.'
        }
        $document = [Text.Json.JsonDocument]::Parse($authority.UnsignedJson)
        $unsigned = ConvertFrom-AtlasoConsoleJsonElement -Element $document.RootElement
        $canonical = ConvertTo-AtlasoConsoleStopCanonicalJson -Value $unsigned
        $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::ASCII.GetBytes($canonical))).ToLowerInvariant()
        if ($canonical -cne $authority.UnsignedJson -or $sha -cne $authority.UnsignedSha256 -or
            $unsigned.payload.ack_intent_sha256 -cne $authority.AckSha256 -or
            $unsigned.signing_key_sha256 -cne $verified.Binding.stop_ack_signing_key_sha256 -or
            $unsigned.payload.deadline_unix_ms -ne $verified.Deadline.ToUnixTimeMilliseconds()) {
            throw 'Original canonical stop statement changed.'
        }
        $authority.SigningIntentPath = Join-Path $authority.Context.EvidenceDirectory (
            'atlaso-test-vm-console-credential-signing-intent-' + $verified.Binding.receiver_nonce + '.json')
        if (Test-Path -LiteralPath $authority.SigningIntentPath) { throw 'Original signing intent exists; preserve without adoption.' }
        $details = [ordered]@{
            status='prepared_signing_request_no_backend'; controller=$verified.Controller
            plan_receipt_path=$authority.PlanPath; plan_receipt_sha256=$authority.PlanSha256
            receiver_receipt_path=$verified.Binding.receiver_receipt_path; receiver_receipt_sha256=$verified.Binding.receiver_receipt_sha256
            intent_receipt_path=$authority.IntentPath; intent_receipt_sha256=$authority.IntentSha256
            process_receipt_path=$authority.ProcessPath; process_receipt_sha256=$authority.ProcessSha256
            stop_receipt_path=$authority.StopPath; stop_receipt_sha256=$authority.StopSha256
            ack_intent_receipt_path=$authority.AckPath; ack_intent_receipt_sha256=$authority.AckSha256
            unsigned_canonical_ascii=$canonical; unsigned_sha256=$sha; public_key_hex=$authority.PublicKeyHex
            signing_key_sha256=$verified.Binding.stop_ack_signing_key_sha256
            transport_key=$verified.Binding.stop_ack_transport_key; deadline_utc=$authority.DeadlineUtc
        }
        Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
        $authority.SigningDetailsJson = $details | ConvertTo-Json -Depth 8 -Compress
        $authority.PublishingSigning = $true; $authority.SigningThreadId = [Threading.Thread]::CurrentThread.ManagedThreadId
        try { $published = Publish-AtlasoConsoleCredentialRecord -Transaction $Transaction -Kind signing-intent -Details $details }
        finally { $authority.PublishingSigning = $false; $authority.SigningThreadId = 0 }
        # Retain actual publication before later checks. Uncertainty never
        # retries, replaces a nonce claim or manufactures a child handoff.
        $authority.SigningIntentSha256 = $published.Sha256
        $null = Get-AtlasoVerifiedConsoleCredentialStop -Transaction $Transaction
        foreach ($pin in $read.Pins) { $Transaction.Pins.Add($pin) }; $read.Pins.Clear()
        $authority.SigningPrepared = $true
        return [pscustomobject]@{status='prepared_signing_request_no_backend'; public_key_hex=$authority.PublicKeyHex;
            signing_intent_receipt=[pscustomobject]@{Path=$authority.SigningIntentPath; Sha256=$authority.SigningIntentSha256};
            ack_intent_receipt=[pscustomobject]@{Path=$authority.AckPath; Sha256=$authority.AckSha256};
            unsigned_canonical_ascii=$authority.UnsignedJson; unsigned_sha256=$authority.UnsignedSha256}
    }
    finally {
        if ($document) { $document.Dispose() }
        if ($read) { foreach ($pin in $read.Pins) { $pin.Dispose() } }
        [Threading.Monitor]::Exit($authority.Lock)
    }
}

<#
.SYNOPSIS
Read the original signing request and coherent chain as data, never parent completion authority.
.PARAMETER Transaction
Fresh original v2 admission with the independently retained plan digest.
.PARAMETER Path
Original controller-published signing request path.
.PARAMETER Sha256
Independently retained publisher-returned request digest.
#>
function Read-AtlasoConsoleStopSigningRequest {
    param([Parameter(Mandatory)][psobject]$Transaction, [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Sha256)
    $reads = [Collections.Generic.List[object]]::new()
    $pins = [Collections.Generic.List[IDisposable]]::new()
    $success = $false
    try {
        $binding = $Transaction.Binding
        $expectedPath = Join-Path $Transaction.Context.EvidenceDirectory (
            'atlaso-test-vm-console-credential-signing-intent-' + $binding.receiver_nonce + '.json')
        if ($Transaction.ProtocolVersion -ne 2 -or $Path -cne $expectedPath) { throw 'Original signing namespace differs.' }
        $request = Read-AtlasoConsoleTransactionRecord -Context $Transaction.Context -Path $Path -Sha256 $Sha256 `
            -Keys @('schema','phase','binding','observed_utc','details')
        $reads.Add($request)
        $d = $request.Value.details
        $keys = @('status','controller','plan_receipt_path','plan_receipt_sha256','receiver_receipt_path','receiver_receipt_sha256',
            'intent_receipt_path','intent_receipt_sha256','process_receipt_path','process_receipt_sha256',
            'stop_receipt_path','stop_receipt_sha256','ack_intent_receipt_path','ack_intent_receipt_sha256',
            'unsigned_canonical_ascii','unsigned_sha256','public_key_hex','signing_key_sha256','transport_key','deadline_utc')
        if ($d -isnot [Collections.IDictionary] -or $d.Count -ne $keys.Count -or
            @($d.Keys | Where-Object { $_ -cnotin $keys }).Count) { throw 'Original signing-request details differ.' }
        foreach ($key in $keys | Where-Object { $_ -cne 'controller' }) {
            if ($d[$key] -isnot [string]) { throw 'Original signing-request detail type differs.' }
        }
        if ($d.status -cne 'prepared_signing_request_no_backend' -or
            $d.plan_receipt_path -cne $Transaction.PlanReceipt.Path -or $d.plan_receipt_sha256 -cne $binding.plan_sha256 -or
            $d.receiver_receipt_path -cne $binding.receiver_receipt_path -or $d.receiver_receipt_sha256 -cne $binding.receiver_receipt_sha256 -or
            $d.public_key_hex -cne $binding.stop_ack_public_key_hex -or $d.signing_key_sha256 -cne $binding.stop_ack_signing_key_sha256 -or
            $d.transport_key -cne $binding.stop_ack_transport_key -or
            $d.deadline_utc -cne $Transaction.Deadline.ToUniversalTime().ToString('O')) {
            throw 'Original signing-request plan/key binding differs.'
        }
        $chain = Read-AtlasoConsoleCredentialStopChain -Transaction $Transaction -Selectors @{
            intent_path=$d.intent_receipt_path; intent_sha256=$d.intent_receipt_sha256
            process_path=$d.process_receipt_path; process_sha256=$d.process_receipt_sha256
            stop_path=$d.stop_receipt_path; stop_sha256=$d.stop_receipt_sha256}
        $reads.Add($chain)
        if (($d.controller | ConvertTo-Json -Depth 4 -Compress) -cne
            ($chain.Controller | ConvertTo-Json -Depth 4 -Compress)) { throw 'Original signing controller differs.' }
        $ackPath = Join-Path $Transaction.Context.EvidenceDirectory (
            'atlaso-test-vm-console-credential-ack-intent-' + $binding.receiver_nonce + '.json')
        if ($d.ack_intent_receipt_path -cne $ackPath) { throw 'Original ACK intent namespace differs.' }
        $ack = Read-AtlasoConsoleTransactionRecord -Context $Transaction.Context -Path $ackPath -Sha256 $d.ack_intent_receipt_sha256 `
            -Keys @('schema','phase','binding','observed_utc','details')
        $reads.Add($ack)
        $expectedAck = [ordered]@{
            status='prepared_unsigned_no_ack'; plan_receipt_path=$d.plan_receipt_path; plan_receipt_sha256=$d.plan_receipt_sha256
            receiver_receipt_path=$d.receiver_receipt_path; receiver_receipt_sha256=$d.receiver_receipt_sha256
            intent_receipt_path=$d.intent_receipt_path; intent_receipt_sha256=$d.intent_receipt_sha256
            process_receipt_path=$d.process_receipt_path; process_receipt_sha256=$d.process_receipt_sha256
            stop_receipt_path=$d.stop_receipt_path; stop_receipt_sha256=$d.stop_receipt_sha256
            signing_key_sha256=$binding.stop_ack_signing_key_sha256; transport_key=$binding.stop_ack_transport_key
            deadline_utc=$Transaction.Deadline.ToUniversalTime().ToString('O'); outcome=$chain.Stop.outcome}
        if (($ack.Value.details | ConvertTo-Json -Depth 8 -Compress) -cne ($expectedAck | ConvertTo-Json -Depth 8 -Compress)) {
            throw 'Original ACK intent chain differs.'
        }
        # The original stop precedes the ACK and signing request; no new deadline is minted.
        $stopRead = Read-AtlasoConsoleTransactionRecord -Context $Transaction.Context -Path $d.stop_receipt_path `
            -Sha256 $d.stop_receipt_sha256 -Keys @('schema','phase','binding','observed_utc','details')
        $reads.Add($stopRead)
        $previous = [DateTimeOffset]::ParseExact($stopRead.Value.observed_utc, 'O', [Globalization.CultureInfo]::InvariantCulture)
        foreach ($phase in @(@{Read=$ack; Name='ack-intent'}, @{Read=$request; Name='signing-intent'})) {
            $r = $phase.Read.Value; $observed = [DateTimeOffset]::MinValue
            if (($r.schema -isnot [int] -and $r.schema -isnot [long]) -or $r.schema -ne 1 -or
                $r.phase -isnot [string] -or $r.phase -cne ('console-credential-' + $phase.Name) -or
                $r.binding -isnot [Collections.IDictionary] -or
                ($r.binding | ConvertTo-Json -Depth 8 -Compress) -cne ($binding | ConvertTo-Json -Depth 8 -Compress) -or
                $r.observed_utc -isnot [string] -or -not [DateTimeOffset]::TryParseExact($r.observed_utc, 'O',
                    [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$observed) -or
                $observed -lt $previous -or $observed -gt [DateTimeOffset]::UtcNow -or $observed -ge $Transaction.Deadline) {
                throw 'Original signing/ACK envelope ordering differs.'
            }
            $previous = $observed
        }
        $payload = [ordered]@{
            task_id=$binding.task_id; source_commit=$binding.source_commit; bundle_sha256=$binding.guest_bundle_sha256
            run_id=$binding.run_id; receiver_nonce=$binding.receiver_nonce; guest_boot_id=$binding.guest_boot_id
            host_boot_identity=$binding.host_boot_identity; original_vm_receipt_sha256=$binding.original_vm_receipt_sha256
            persistent_vm_identity_sha256=$binding.persistent_vm_identity_sha256; plan_sha256=$binding.plan_sha256
            receiver_receipt_sha256=$binding.receiver_receipt_sha256; process_receipt_sha256=$d.process_receipt_sha256
            stop_receipt_sha256=$d.stop_receipt_sha256; ack_intent_sha256=$d.ack_intent_receipt_sha256
            transport_key=$binding.stop_ack_transport_key; deadline_unix_ms=$Transaction.Deadline.ToUnixTimeMilliseconds()
            root_pid=$chain.Root.pid; root_start_filetime_utc=$chain.Root.start_filetime_utc
            whole_job_empty=$chain.Stop.whole_job_empty; outcome=$chain.Stop.outcome
            root_exit_code=$chain.Stop.root_exit_code; original_binding_rechecked=$chain.Stop.original_binding_rechecked}
        $canonical = ConvertTo-AtlasoConsoleStopCanonicalJson -Value ([ordered]@{schema=2; kind='console-sdk-stop-ack-v2';
            algorithm='Ed25519'; signing_key_sha256=$binding.stop_ack_signing_key_sha256; payload=$payload})
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($canonical))).ToLowerInvariant()
        if ($canonical -cne $d.unsigned_canonical_ascii -or $hash -cne $d.unsigned_sha256 -or
            $canonical.Length + 147 -gt 3000) { throw 'Original signing bytes differ from the complete chain.' }
        Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
        foreach ($read in $reads) { foreach ($pin in $read.Pins) { $pins.Add($pin) }; $read.Pins.Clear() }
        $success = $true
        return [pscustomobject]@{Record=$request.Value; Controller=$chain.Controller; CredentialRoot=$chain.Root; Pins=$pins}
    }
    finally {
        foreach ($read in $reads) { foreach ($pin in $read.Pins) { $pin.Dispose() } }
        if (-not $success) { foreach ($pin in $pins) { $pin.Dispose() } }
    }
}

<#
.SYNOPSIS
Derive the single committed refusing signer entrypoint and current PowerShell executable.
.PARAMETER Transaction
Original current-source transaction; no caller command or argument is accepted.
.PARAMETER RequestPath
Privately retained original request path.
.PARAMETER RequestSha256
Privately retained original request digest.
#>
function Get-AtlasoConsoleStopSignerLaunch {
    param([Parameter(Mandatory)][psobject]$Transaction, [Parameter(Mandatory)][string]$RequestPath,
        [Parameter(Mandatory)][string]$RequestSha256)
    $child = Join-Path $Transaction.Context.Worktree 'scripts/windows/vmware/invoke-console-stop-signer-child.ps1'
    $self = [Diagnostics.Process]::GetCurrentProcess()
    try { $exe = $self.MainModule.FileName } finally { $self.Dispose() }
    return [pscustomobject]@{FilePath=$exe; ChildPath=$child; Arguments=@('-NoProfile','-NonInteractive','-File',$child,
        '-VmxPath',$Transaction.Context.VmxPath,'-OwnershipReceiptPath',$Transaction.Context.ReceiptPath,
        '-OwnershipReceiptSha256',$Transaction.Context.ReceiptSha256,'-PullRequestNumber',[string]$Transaction.Context.PullRequestNumber,
        '-RequestPath',$RequestPath,'-RequestSha256',$RequestSha256)}
}

<#
.SYNOPSIS
Launch one distinct contained signer child which has no admitted backend and always refuses.
.PARAMETER Transaction
Only the original still-open v2 reference with successful private signing-request custody.
#>
function Invoke-AtlasoConsoleStopSigner {
    param([Parameter(Mandatory)][psobject]$Transaction)
    $authority = $null
    if (-not $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$authority)) {
        throw 'Original signer invocation authority is unavailable.'
    }
    [Threading.Monitor]::Enter($authority.Lock)
    $read = $null
    try {
        if (-not $authority.SigningPrepared -or $authority.SignerAttempted) {
            throw 'Original successful signing request is unavailable or already consumed.'
        }
        $authority.SignerAttempted = $true
        $null = Get-AtlasoVerifiedConsoleCredentialStop -Transaction $Transaction
        $read = Read-AtlasoConsoleStopSigningRequest -Transaction $Transaction -Path $authority.SigningIntentPath `
            -Sha256 $authority.SigningIntentSha256
        if (($read.Record.details | ConvertTo-Json -Depth 8 -Compress) -cne $authority.SigningDetailsJson -or
            $read.Record.details.unsigned_canonical_ascii -cne $authority.UnsignedJson -or
            $read.Record.details.unsigned_sha256 -cne $authority.UnsignedSha256) { throw 'Original private signing custody changed.' }
        foreach ($pin in $read.Pins) { $Transaction.Pins.Add($pin) }; $read.Pins.Clear()
        $nonce = $Transaction.Plan.receiver_nonce
        $jobName = 'Local\Atlaso-ConsoleStopSigner-' + $nonce
        $authority.SignerProcessPath = Join-Path $authority.Context.EvidenceDirectory ('atlaso-test-vm-console-credential-signer-process-' + $nonce + '.json')
        $authority.SignerStopPath = Join-Path $authority.Context.EvidenceDirectory ('atlaso-test-vm-console-credential-signer-stop-' + $nonce + '.json')
        foreach ($path in @($authority.SignerProcessPath,$authority.SignerStopPath)) {
            if (Test-Path -LiteralPath $path) { throw 'Original signer namespace exists; preserve without replay.' }
        }
        $launch = Get-AtlasoConsoleStopSignerLaunch -Transaction $Transaction -RequestPath $authority.SigningIntentPath `
            -RequestSha256 $authority.SigningIntentSha256
        foreach ($path in @($launch.FilePath,$launch.ChildPath)) {
            $Transaction.Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true))
        }
        $childHash = (Get-FileHash -LiteralPath $launch.ChildPath).Hash.ToLowerInvariant()
        $exeHash = (Get-FileHash -LiteralPath $launch.FilePath).Hash.ToLowerInvariant()
        $publish = ${function:Publish-AtlasoConsoleCredentialRecord}
        $verify = ${function:Get-AtlasoVerifiedConsoleCredentialStop}
        $creation = ${function:Get-AtlasoConsoleProcessCreation}
        $owner = {
            param($Job)
            $null = & $verify -Transaction $Transaction
            $root = & $creation -Process $Job.RootProcess
            $root['job_name'] = $jobName
            $details = [ordered]@{request_path=$authority.SigningIntentPath; request_sha256=$authority.SigningIntentSha256
                controller=$read.Controller; root=$root; child_path=$launch.ChildPath; child_sha256=$childHash
                executable_path=$launch.FilePath; executable_sha256=$exeHash; deadline_utc=$authority.DeadlineUtc; backend='unavailable'}
            $authority.SignerRootJson = $root | ConvertTo-Json -Depth 4 -Compress
            $authority.SignerRootPid=$root.pid; $authority.SignerRootStartUtc=$root.getprocess_start_utc
            $authority.SignerKind='signer-process'; $authority.SignerDetailsJson=$details | ConvertTo-Json -Depth 8 -Compress
            $authority.PublishingSigner=$true; $authority.SignerThreadId=[Threading.Thread]::CurrentThread.ManagedThreadId
            try { $record = & $publish -Transaction $Transaction -Kind signer-process -Details $details }
            finally { $authority.PublishingSigner=$false; $authority.SignerThreadId=0 }
            $authority.SignerProcessSha256=$record.Sha256
        }.GetNewClosure()
        $stopped = {
            param($Proof)
            $root = @{pid=$authority.SignerRootPid; getprocess_start_utc=$authority.SignerRootStartUtc}
            if (-not $authority.SignerProcessSha256 -or $Proof.Schema -isnot [int] -or $Proof.Schema -ne 1 -or
                $Proof.WholeJobEmpty -isnot [bool] -or -not $Proof.WholeJobEmpty -or $Proof.ProcessJobName -cne $jobName -or
                $Proof.RootProcessId -ne $root.pid -or $Proof.RootStartTimeUtc -cne $root.getprocess_start_utc -or
                $Proof.DeadlineUtc -cne $authority.DeadlineUtc -or $Proof.RootExitCode -isnot [int] -or
                $Proof.Outcome -isnot [string] -or $Proof.Outcome -cnotin @('succeeded','terminated_failure')) {
                throw 'Original signer outer-job stop proof is unavailable.'
            }
            $rechecked=$true
            try { $null = & $verify -Transaction $Transaction } catch { $rechecked=$false }
            $details = [ordered]@{request_path=$authority.SigningIntentPath; request_sha256=$authority.SigningIntentSha256
                process_receipt_path=$authority.SignerProcessPath; process_receipt_sha256=$authority.SignerProcessSha256
                root_pid=$root.pid; getprocess_start_utc=$root.getprocess_start_utc; deadline_utc=$authority.DeadlineUtc
                whole_job_empty=$true; outer_outcome=$Proof.Outcome; outcome='terminated_failure'; root_exit_code=$Proof.RootExitCode
                original_binding_rechecked=$rechecked; backend='unavailable'}
            $authority.SignerKind='signer-stop'; $authority.SignerDetailsJson=$details | ConvertTo-Json -Depth 8 -Compress
            $authority.PublishingSigner=$true; $authority.SignerThreadId=[Threading.Thread]::CurrentThread.ManagedThreadId
            try { $record = & $publish -Transaction $Transaction -Kind signer-stop -Details $details }
            finally { $authority.PublishingSigner=$false; $authority.SignerThreadId=0 }
            $authority.SignerStopSha256=$record.Sha256
        }.GetNewClosure()
        $null = Get-AtlasoVerifiedConsoleCredentialStop -Transaction $Transaction
        Invoke-AtlasoBoundedStreamingProcess -FilePath $launch.FilePath -ArgumentList $launch.Arguments -TimeoutSeconds 420 `
            -Action 'Separately admitted refusing console-stop signer' -ProcessJobName $jobName -DeadlineUtc $Transaction.Deadline `
            -ProcessOwnershipPublisher $owner -ProcessQuiescencePublisher $stopped -DiscardOutput
        throw 'Console-stop signing backend is unavailable; no signature or transport is admitted.'
    }
    finally {
        if ($read) { foreach ($pin in $read.Pins) { $pin.Dispose() } }
        [Threading.Monitor]::Exit($authority.Lock)
    }
}

<#
.SYNOPSIS
Authenticate the distinct signer suspended-root handoff without accessing a backend.
.PARAMETER Transaction
Fresh original plan/receiver admission reconstructed inside the signer child.
.PARAMETER RequestPath
Original immutable request selected by the parent before child creation.
.PARAMETER RequestSha256
Independently retained original request digest passed by the live parent.
.PARAMETER EntryPoint
Actual committed child script path, supplied only by its own PSCommandPath.
#>
function Assert-AtlasoConsoleStopSignerChild {
    param([Parameter(Mandatory)][psobject]$Transaction, [Parameter(Mandatory)][string]$RequestPath,
        [Parameter(Mandatory)][string]$RequestSha256, [Parameter(Mandatory)][string]$EntryPoint)
    $read = $null; $processRead = $null; $job = $null; $parent = $null
    $self = [Diagnostics.Process]::GetCurrentProcess()
    $pins = [Collections.Generic.List[IDisposable]]::new()
    try {
        $read = Read-AtlasoConsoleStopSigningRequest -Transaction $Transaction -Path $RequestPath -Sha256 $RequestSha256
        $nonce=$Transaction.Plan.receiver_nonce
        $processPath=Join-Path $Transaction.Context.EvidenceDirectory ('atlaso-test-vm-console-credential-signer-process-' + $nonce + '.json')
        $stopPath=Join-Path $Transaction.Context.EvidenceDirectory ('atlaso-test-vm-console-credential-signer-stop-' + $nonce + '.json')
        $jobName='Local\Atlaso-ConsoleStopSigner-' + $nonce
        $expectedChild=Join-Path $Transaction.Context.Worktree 'scripts/windows/vmware/invoke-console-stop-signer-child.ps1'
        if ($EntryPoint -cne $expectedChild -or (Test-Path -LiteralPath $stopPath)) {
            throw 'Original signer entrypoint or terminal state differs.'
        }
        # Parent pins this actual record before resume. Its digest cannot exist
        # in pre-creation arguments: authenticate the producer through self,
        # the independently pinned request, live parent and exclusive new job.
        $processRead=Read-AtlasoConsoleTransactionRecord -Context $Transaction.Context -Path $processPath `
            -Sha256 (Get-FileHash -LiteralPath $processPath).Hash.ToLowerInvariant() -Keys @('schema','phase','binding','observed_utc','details')
        $r=$processRead.Value; $d=$r.details
        $keys=@('request_path','request_sha256','controller','root','child_path','child_sha256','executable_path','executable_sha256','deadline_utc','backend')
        $observed=[DateTimeOffset]::MinValue
        if (($r.schema -isnot [int] -and $r.schema -isnot [long]) -or $r.schema -ne 1 -or
            $r.phase -isnot [string] -or $r.phase -cne 'console-credential-signer-process' -or
            ($r.binding | ConvertTo-Json -Depth 8 -Compress) -cne ($Transaction.Binding | ConvertTo-Json -Depth 8 -Compress) -or
            $r.observed_utc -isnot [string] -or -not [DateTimeOffset]::TryParseExact($r.observed_utc, 'O',
                [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$observed) -or
            $observed -lt [DateTimeOffset]::ParseExact($read.Record.observed_utc,'O',[Globalization.CultureInfo]::InvariantCulture) -or
            $observed -gt [DateTimeOffset]::UtcNow -or $observed -ge $Transaction.Deadline -or
            $d -isnot [Collections.IDictionary] -or $d.Count -ne $keys.Count -or
            @($d.Keys | Where-Object { $_ -cnotin $keys }).Count) { throw 'Original signer process envelope differs.' }
        foreach ($key in $keys | Where-Object { $_ -cnotin @('controller','root') }) {
            if ($d[$key] -isnot [string]) { throw 'Original signer process selector type differs.' }
        }
        Assert-AtlasoConsoleOriginalClock -Value $d.controller
        Assert-AtlasoConsoleOriginalClock -Value $d.root -IncludeJob
        if ($d.request_path -cne $RequestPath -or $d.request_sha256 -cne $RequestSha256 -or
            $d.child_path -cne $EntryPoint -or $d.executable_path -cne $self.MainModule.FileName -or
            $d.deadline_utc -cne $Transaction.Deadline.ToUniversalTime().ToString('O') -or $d.backend -cne 'unavailable' -or
            ($d.controller | ConvertTo-Json -Depth 4 -Compress) -cne ($read.Controller | ConvertTo-Json -Depth 4 -Compress)) {
            throw 'Original signer request/controller/source selectors differ.'
        }
        foreach ($pair in @(@($EntryPoint,$d.child_sha256),@($self.MainModule.FileName,$d.executable_sha256))) {
            $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($pair[0],$true))
            if ($pair[1] -cnotmatch '\A[0-9a-f]{64}\z' -or (Get-FileHash -LiteralPath $pair[0]).Hash.ToLowerInvariant() -cne $pair[1]) {
                throw 'Original signer executable/source digest differs.'
            }
        }
        $clock=Get-AtlasoConsoleProcessCreation -Process $self
        $clock['job_name']=$jobName
        if (($clock | ConvertTo-Json -Depth 4 -Compress) -cne ($d.root | ConvertTo-Json -Depth 4 -Compress) -or
            $clock.parent_pid -ne $read.Controller.pid -or $clock.pid -eq $read.CredentialRoot.pid) {
            throw 'Signer child is not the new original suspended root.'
        }
        $parent=Get-Process -Id $read.Controller.pid -ErrorAction Stop
        $live=Get-AtlasoConsoleProcessCreation -Process $parent
        if (($live | ConvertTo-Json -Depth 4 -Compress) -cne ($read.Controller | ConvertTo-Json -Depth 4 -Compress)) {
            throw 'Original signer parent is not the same live controller.'
        }
        $job=Open-AtlasoBoundedProcessJob -ProcessJobName $jobName
        if ($null -eq $job -or -not $job.ContainsProcess($self)) { throw 'Signer child is outside its distinct original job.' }
        Assert-AtlasoConsoleTransactionBinding -Transaction $Transaction
        if (Test-Path -LiteralPath $stopPath) { throw 'Stopped signer cannot resume.' }
    }
    finally {
        if ($job) { $job.Dispose() }; if ($parent) { $parent.Dispose() }; $self.Dispose()
        foreach ($pin in $pins) { $pin.Dispose() }
        foreach ($row in @($read,$processRead)) { if ($row) { foreach ($pin in $row.Pins) { $pin.Dispose() } } }
    }
}

<#
.SYNOPSIS
Revoke this live authority and release only its retained public read pins, never evidence.
.PARAMETER Transaction
Opened original transaction, or null after an admission failure.
#>
function Close-AtlasoConsoleCredentialTransaction {
    param([AllowNull()][object]$Transaction)
    if (-not $Transaction) { return }
    $authority = $null
    $locked = $script:AtlasoConsoleStopAuthorities.TryGetValue($Transaction, [ref]$authority)
    if ($locked) { [Threading.Monitor]::Enter($authority.Lock) }
    try {
        $release = $locked -or -not $Transaction.IsClosed
        $Transaction.IsClosed = $true
        $null = $script:AtlasoConsoleStopAuthorities.Remove($Transaction)
        if ($release) {
            foreach ($pin in $Transaction.Pins) { $pin.Dispose() }
            $Transaction.Pins.Clear()
        }
    }
    finally { if ($locked) { [Threading.Monitor]::Exit($authority.Lock) } }
}
