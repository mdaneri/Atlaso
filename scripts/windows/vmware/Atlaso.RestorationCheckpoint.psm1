<#
.SYNOPSIS
Keep an original host-side restoration checkpoint without admitting live capture.
.DESCRIPTION
The stage1 projection is data. This module does not submit an appliance operation.
#>

Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1')
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')

$script:RestorationScopes = [Runtime.CompilerServices.ConditionalWeakTable[object,object]]::new()
$script:MaximumBaselineBytes = 393216
$script:InterfacePattern = '\A[A-Za-z0-9_.-]{1,15}\z'

<#
.SYNOPSIS
Hash the exact bytes held by the original controller.
.PARAMETER Bytes
Exact captured or journal bytes.
#>
function Get-RestorationDigest([byte[]]$Bytes) {
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

<#
.SYNOPSIS
Read an exact JSON object without accepting unknown or duplicate properties.
.PARAMETER Value
Parsed baseline object.
.PARAMETER Names
Complete ordinal property allowlist.
#>
function Get-RestorationMembers([System.Text.Json.JsonElement]$Value, [string[]]$Names) {
    $members = [Collections.Generic.Dictionary[string,System.Text.Json.JsonElement]]::new([StringComparer]::Ordinal)
    foreach ($property in $Value.EnumerateObject()) {
        if ([Array]::IndexOf($Names, $property.Name) -lt 0 -or
            -not $members.TryAdd($property.Name, $property.Value)) {
            throw 'Restoration projection fields refused.'
        }
    }
    if ($members.Count -ne $Names.Count) { throw 'Restoration projection fields missing.' }
    return ,$members
}

<#
.SYNOPSIS
Validate bounded public string fields in one baseline projection.
.PARAMETER Members
Validated property map.
.PARAMETER Names
Exact public string fields to inspect.
.PARAMETER Limit
Maximum field length.
#>
function Assert-RestorationStrings([object]$Members, [string[]]$Names, [int]$Limit) {
    foreach ($name in $Names) {
        $value = $Members[$name].GetString()
        if ($null -eq $value -or $value.Length -gt $Limit -or
            $value -match '-----BEGIN [^-]*PRIVATE KEY-----|[a-z]+://[^\s/]*@') {
            throw 'Restoration projection string refused.'
        }
    }
}

<#
.SYNOPSIS
Require actual JSON booleans in one baseline projection.
.PARAMETER Members
Validated property map.
.PARAMETER Names
Boolean field names.
#>
function Assert-RestorationBooleans([object]$Members, [string[]]$Names) {
    foreach ($name in $Names) { $null = $Members[$name].GetBoolean() }
}

<#
.SYNOPSIS
Bind the original desired interface row and browser projection to the admitted interface.
.PARAMETER Baseline
Exact stage1 projection property map.
.PARAMETER Binding
Frozen original scope selectors.
#>
function Assert-RestorationInterface([object]$Baseline, [object]$Binding) {
    $modes = @('role','mode','ipv4_method')
    $addresses = @('ip_cidr','gateway','ipv6_cidr','ipv6_gateway')
    $flags = @('ipv6_enabled','check_duplicate_ip_addresses','access_management_ui_enabled')
    $common = $modes + $addresses + $flags + @('mtu')
    $ordinal = [StringComparer]::Ordinal
    $row = Get-RestorationMembers $Baseline['original_row'] ($common + @('id','name','mac_address','admin_up'))
    $form = Get-RestorationMembers $Baseline['browser_fields'] ($common + @('admin_state'))
    Assert-RestorationStrings $row ($modes + @('name','mac_address')) 32
    Assert-RestorationBooleans $row ($flags + @('admin_up'))
    if ($row['id'].GetInt64() -lt 1 -or $row['mtu'].GetInt32() -lt 576 -or $row['mtu'].GetInt32() -gt 9000 -or
        -not $ordinal.Equals($row['name'].GetString(), $Binding.interface) -or
        -not $ordinal.Equals($row['mac_address'].GetString().Replace('-', ':').ToLowerInvariant(), $Binding.mac_address) -or
        [Array]::IndexOf(@('management','access','route','unused'), $row['role'].GetString()) -lt 0 -or
        [Array]::IndexOf(@('access','trunk','unused'), $row['mode'].GetString()) -lt 0 -or
        [Array]::IndexOf(@('static','dhcp'), $row['ipv4_method'].GetString()) -lt 0) {
        throw 'Original restoration interface refused.'
    }
    foreach ($name in ($modes + $flags + @('mtu'))) {
        if (-not $ordinal.Equals($row[$name].GetRawText(), $form[$name].GetRawText())) {
            throw 'Restoration browser projection changed.'
        }
    }
    foreach ($name in $addresses) {
        $value = if ($row[$name].ValueKind -eq [System.Text.Json.JsonValueKind]::Null) { '' } else { $row[$name].GetString() }
        # The browser projection requires a JSON string, including for an absent address.
        if ($value.Length -gt 80 -or $form[$name].ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            -not $ordinal.Equals($value, $form[$name].GetString())) {
            throw 'Restoration address projection refused.'
        }
        if (-not $value) { continue }
        $family = if ($name.StartsWith('ipv6', [StringComparison]::Ordinal)) { 6 } else { 4 }
        $parts = $value.Split('/')
        $ip = $null
        if ($value -cnotmatch '\A[0-9a-fA-F.:/]+\z' -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$ip) -or
            ($family -eq 4 -and ($ip.AddressFamily -ne 'InterNetwork' -or -not $ordinal.Equals($ip.ToString(), $parts[0]))) -or
            ($family -eq 6 -and $ip.AddressFamily -ne 'InterNetworkV6')) {
            throw 'Restoration address family refused.'
        }
        $maximumPrefix = if ($family -eq 4) { 32 } else { 128 }
        if ($parts.Count -gt 1 -and ($name -notlike '*_cidr' -or $parts.Count -ne 2 -or
            $parts[1] -cnotmatch '\A[0-9]{1,3}\z' -or [int]$parts[1] -gt $maximumPrefix)) {
            throw 'Restoration address prefix refused.'
        }
    }
    $adminState = if ($row['admin_up'].GetBoolean()) { 'up' } else { 'down' }
    if (-not $ordinal.Equals($form['admin_state'].GetString(), $adminState)) {
        throw 'Restoration admin state refused.'
    }
}

<#
.SYNOPSIS
Validate the current normal DNS Settings projection with its exact supported fields.
.PARAMETER Projection
Stage1 DNS settings JSON object.
#>
function Assert-RestorationDns([System.Text.Json.JsonElement]$Projection) {
    $flags = @('enabled','expand_hosts','authoritative','dnssec_enabled','rebind_protection_enabled')
    $numbers = @('cache_size','authoritative_ttl','authoritative_refresh','authoritative_retry','authoritative_expire')
    $text = @('authoritative_server','authoritative_contact')
    $textAreas = @('upstream_servers','conditional_forwarders','rebind_domain_exemptions')
    $dns = Get-RestorationMembers $Projection ($flags + $numbers + $text + $textAreas +
        @('query_logging_mode','listen_interfaces_present','listen_interfaces'))
    Assert-RestorationBooleans $dns $flags
    Assert-RestorationStrings $dns $text 253
    Assert-RestorationStrings $dns $textAreas 16384
    foreach ($name in $numbers) {
        $minimum = if ($name -ceq 'cache_size') { 0 } else { 1 }
        if ($dns[$name].GetInt32() -lt $minimum) { throw 'Restoration DNS number refused.' }
    }
    if ([Array]::IndexOf(@('off','queries-extra'), $dns['query_logging_mode'].GetString()) -lt 0 -or
        -not [StringComparer]::Ordinal.Equals($dns['listen_interfaces_present'].GetString(), '1') -or
        $dns['listen_interfaces'].GetArrayLength() -gt 256) {
        throw 'Restoration DNS controls refused.'
    }
    $interfaces = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($item in $dns['listen_interfaces'].EnumerateArray()) {
        $name = $item.GetString()
        if ($name -cnotmatch $script:InterfacePattern -or -not $interfaces.Add($name)) {
            throw 'Restoration DNS interface refused.'
        }
    }
}

<#
.SYNOPSIS
Validate bounded stage1 data and all four exact projection digests before publication.
.PARAMETER Bytes
Original ASCII bytes produced by the capture.
.PARAMETER Binding
Frozen original scope selectors.
#>
function Assert-RestorationBaseline([byte[]]$Bytes, [object]$Binding) {
    if ($Bytes.Length -lt 2 -or $Bytes.Length -gt $script:MaximumBaselineBytes -or
        $Bytes[0] -ne 123 -or $Bytes[-1] -ne 125) { throw 'Restoration projection size or framing refused.' }
    $ascii = [Text.Encoding]::GetEncoding('us-ascii', [Text.EncoderExceptionFallback]::new(),
        [Text.DecoderExceptionFallback]::new()).GetString($Bytes)
    $document = [System.Text.Json.JsonDocument]::Parse($ascii)
    try {
        $ordinal = [StringComparer]::Ordinal
        $parts = @('review','original_row','browser_fields','dns_settings')
        $root = Get-RestorationMembers $document.RootElement ($parts +
            @('test_only','consistency_only','native_acceptance','formal_acceptance','projection_sha256'))
        if (-not $root['test_only'].GetBoolean() -or -not $root['consistency_only'].GetBoolean() -or
            $root['native_acceptance'].GetBoolean() -or $root['formal_acceptance'].GetBoolean()) {
            throw 'Restoration evidence classification refused.'
        }
        $review = Get-RestorationMembers $root['review'] @('units','pending_count','execution_count','requested_units',
            'plan_error','initial_apply_required','active_task')
        if ($review['units'].GetArrayLength() -ne 0 -or $review['requested_units'].GetArrayLength() -ne 0 -or
            $review['pending_count'].GetInt32() -ne 0 -or $review['execution_count'].GetInt32() -ne 0 -or
            $review['plan_error'].ValueKind -ne [System.Text.Json.JsonValueKind]::String -or
            -not $ordinal.Equals($review['plan_error'].GetString(), '') -or
            $review['initial_apply_required'].GetBoolean() -or
            $review['active_task'].ValueKind -ne [System.Text.Json.JsonValueKind]::Null) {
            throw 'Restoration review is not clean.'
        }
        Assert-RestorationInterface $root $Binding
        Assert-RestorationDns $root['dns_settings']
        $digests = Get-RestorationMembers $root['projection_sha256'] $parts
        foreach ($part in $parts) {
            $actual = Get-RestorationDigest ([Text.Encoding]::ASCII.GetBytes($root[$part].GetRawText()))
            if (-not $ordinal.Equals($digests[$part].GetString(), $actual)) {
                throw 'Restoration projection digest differs.'
            }
        }
    }
    finally { $document.Dispose() }
}

<#
.SYNOPSIS
Freeze the original scope selectors without retaining the mutable input dictionary.
.PARAMETER Binding
Exact original source, receiver, resource and interface selectors.
#>
function Get-RestorationBinding([System.Collections.IDictionary]$Binding) {
    $digests = @('bundle_sha256','runtime_sha256','resource_receipt_sha256','persistent_vm_identity_sha256',
        'receiver_receipt_sha256')
    $names = $digests + @('task_id','source_commit','source_tree','host_boot_identity','guest_boot_id',
        'controller_identity','provider_identity','run_id','receiver_nonce','role','interface','mac_address','origin')
    if ($Binding.Count -ne $names.Count) { throw 'Original restoration bindings refused.' }
    $snapshot = [ordered]@{}
    foreach ($key in $Binding.Keys) {
        if ($key -cnotin $names -or $Binding[$key] -isnot [string] -or
            $Binding[$key] -cnotmatch '\A[A-Za-z0-9._:/\[\]-]{1,160}\z') {
            throw 'Original restoration binding refused.'
        }
        $snapshot.Add($key, $Binding[$key])
    }
    foreach ($name in $digests) {
        if ($snapshot[$name] -cnotmatch '\A[0-9a-f]{64}\z') { throw 'Original restoration digest refused.' }
    }
    $uuid = '\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z'
    $origin = $null
    if ($snapshot.task_id -cnotmatch $uuid -or $snapshot.guest_boot_id -cnotmatch $uuid -or
        $snapshot.source_commit -cnotmatch '\A[0-9a-f]{40}\z' -or $snapshot.source_tree -cnotmatch '\A[0-9a-f]{40}\z' -or
        $snapshot.run_id -cnotmatch '\A[0-9a-f]{32}\z' -or $snapshot.receiver_nonce -cnotmatch '\A[0-9a-f]{32}\z' -or
        $snapshot.role -cnotin @('main','peer') -or $snapshot.interface -cnotmatch $script:InterfacePattern -or
        $snapshot.mac_address -cnotmatch '\A(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\z' -or
        -not [Uri]::TryCreate($snapshot.origin, [UriKind]::Absolute, [ref]$origin) -or
        $origin.Scheme -cne 'https' -or $origin.HostNameType -notin @('IPv4','IPv6') -or
        $snapshot.origin -cne $origin.GetLeftPart([UriPartial]::Authority)) {
        throw 'Original restoration scope selectors refused.'
    }
    return $snapshot
}

<#
.SYNOPSIS
Sample the Windows boot, raw performance counter and UTC for the private clock fixture.
#>
function Get-RestorationWindowsClockSample {
    if (-not [Diagnostics.Stopwatch]::IsHighResolution) { throw 'Restoration performance counter unavailable.' }
    $boot = Get-AtlasoWindowsBootIdentity
    $counter = [Diagnostics.Stopwatch]::GetTimestamp()
    return [pscustomobject]@{
        BootIdentity=$boot; Counter=$counter; Frequency=[Diagnostics.Stopwatch]::Frequency
        Utc=[DateTimeOffset]::UtcNow
    }
}

<#
.SYNOPSIS
Copy and validate a sample from the original synthetic clock source.
.PARAMETER Source
Original module-owned or fixture-only sampler.
.PARAMETER BootIdentity
Exact boot identity bound by the original journal scope.
#>
function Read-RestorationClockSample([scriptblock]$Source, [string]$BootIdentity) {
    $sample = & $Source
    if ($sample -isnot [pscustomobject] -or
        $sample.BootIdentity -isnot [string] -or $sample.BootIdentity -cne $BootIdentity -or
        $sample.Counter -isnot [long] -or $sample.Counter -lt 0 -or
        $sample.Frequency -isnot [long] -or $sample.Frequency -le 0 -or
        $sample.Utc -isnot [DateTimeOffset] -or $sample.Utc -lt [DateTimeOffset]::UnixEpoch) {
        throw 'Original restoration clock sample refused.'
    }
    return [pscustomobject]@{
        Counter=$sample.Counter; Frequency=$sample.Frequency; Utc=$sample.Utc
    }
}

<#
.SYNOPSIS
Freeze the original synthetic dual deadline before the first admission or pin.
.PARAMETER Deadline
Requested original absolute UTC bound.
.PARAMETER Source
Original clock sampler, retained for the same scope.
.PARAMETER BootIdentity
Exact boot identity bound by the original journal scope.
#>
function New-RestorationSharedClock([DateTimeOffset]$Deadline, [scriptblock]$Source, [string]$BootIdentity) {
    $birth = Read-RestorationClockSample $Source $BootIdentity
    $utcMs = $Deadline.ToUnixTimeMilliseconds()
    $utcEnd = [DateTimeOffset]::FromUnixTimeMilliseconds($utcMs)
    $wallTicks = ($utcEnd - $birth.Utc).Ticks
    if ($wallTicks -le 0 -or $wallTicks -gt 420 * [TimeSpan]::TicksPerSecond) {
        throw 'Original restoration clock budget refused.'
    }
    # The bounded product fits in a decimal. Dividing by ticks per second before flooring
    # preserves the exact counter-tick boundary without rounding the absolute endpoint.
    $delta = [decimal]::Floor(([decimal]$wallTicks * $birth.Frequency) / [TimeSpan]::TicksPerSecond)
    if ($delta -lt 1 -or $delta -gt ([long]::MaxValue - $birth.Counter)) {
        throw 'Original restoration counter deadline refused.'
    }
    return [pscustomobject]@{
        Source=$Source; Previous=$birth; Sampling=$false; UtcEnd=$utcEnd; UtcMilliseconds=$utcMs
        EndCounter=($birth.Counter + [long]$delta); Frequency=$birth.Frequency
        BootSha256=(Get-RestorationDigest ([Text.Encoding]::ASCII.GetBytes($BootIdentity)))
    }
}

<#
.SYNOPSIS
Return the remaining original time budget without refreshing the deadline.
.PARAMETER Authority
Private original capture state.
.PARAMETER Activation
Original invocation token required when the synthetic capture calls back.
#>
function Get-RestorationRemaining([object]$Authority, [object]$Activation) {
    if ($Authority.Phase -in @('Closed','Failed') -or
        $Authority.Thread -ne [Threading.Thread]::CurrentThread.ManagedThreadId) {
        throw 'Original restoration scope is not active on this controller.'
    }
    $shared = $Authority.SharedClock
    if ($null -ne $shared) {
        if ($Authority.Phase -ceq 'Completed' -or $shared.Sampling -or
            ($null -ne $Activation -and -not [object]::ReferenceEquals($Activation, $Authority.ReceiptActivation))) {
            throw 'Original restoration clock is not active for this invocation.'
        }
        $shared.Sampling = $true
        try {
            $sample = Read-RestorationClockSample $shared.Source $Authority.Binding.host_boot_identity
            if ($sample.Frequency -ne $shared.Frequency -or $sample.Counter -lt $shared.Previous.Counter -or
                $sample.Utc -lt $shared.Previous.Utc -or $sample.Counter -ge $shared.EndCounter -or
                $sample.Utc -ge $shared.UtcEnd) {
                throw 'Original restoration clock regressed, changed or elapsed.'
            }
            $shared.Previous = $sample
            return [Math]::Min(
                ($shared.EndCounter - $sample.Counter) / [double]$shared.Frequency,
                ($shared.UtcEnd - $sample.Utc).TotalSeconds)
        }
        catch {
            $Authority.Phase = 'Failed'
            throw
        }
        finally { $shared.Sampling = $false }
    }
    $remaining = [Math]::Min(
        $Authority.Budget - $Authority.Clock.Elapsed.TotalSeconds,
        ($Authority.Deadline - [DateTimeOffset]::UtcNow).TotalSeconds)
    if ($remaining -le 0) { throw 'Original restoration deadline elapsed.' }
    return $remaining
}

<#
.SYNOPSIS
Recheck the same live controller, original evidence root and current admission.
.PARAMETER Authority
Private original capture state.
#>
function Assert-RestorationScope([object]$Authority) {
    $null = Get-RestorationRemaining $Authority
    if ([Atlaso.WorkstationFileIdentity]::Get($Authority.Root) -cne $Authority.RootIdentity) {
        throw 'Original restoration scope changed.'
    }
    $Authority.Verifying = $true
    try { $verified = & $Authority.Verify }
    finally { $Authority.Verifying = $false }
    if ($verified -isnot [bool] -or -not $verified) { throw 'Original restoration admission refused.' }
    $null = Get-RestorationRemaining $Authority
}

<#
.SYNOPSIS
Create an original-reference scope only for synthetic module tests.
.PARAMETER EvidenceDirectory
Absolute already owned journal directory.
.PARAMETER EvidenceIdentity
Recorded identity of the original journal directory.
.PARAMETER Binding
Synthetic exact selectors for the original controller and receiver.
.PARAMETER Deadline
Original bounded absolute capture deadline.
.PARAMETER Verify
Internal synthetic current-admission predicate.
.PARAMETER BeforeReadPin
Internal synthetic observer for the close-to-pin handoff.
.PARAMETER SyntheticClock
Opt in at scope creation to a shared counter and UTC deadline for synthetic qualification.
.PARAMETER SyntheticClockSample
Optional deterministic clock sampler for the private fixture.
#>
function New-RestorationCheckpointTestScope {
    param([string]$EvidenceDirectory, [string]$EvidenceIdentity, [System.Collections.IDictionary]$Binding,
        [DateTimeOffset]$Deadline, [scriptblock]$Verify, [scriptblock]$BeforeReadPin,
        [switch]$SyntheticClock, [scriptblock]$SyntheticClockSample)

    $ErrorActionPreference = 'Stop'
    # Internal tests supply a synthetic origin and capture. No production verifier exists.
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $budget = ($Deadline - [DateTimeOffset]::UtcNow).TotalSeconds
    if (-not $IsWindows -or (-not $SyntheticClock -and ($budget -le 0 -or $budget -gt 420 -or $SyntheticClockSample)) -or
        $null -eq $Verify -or
        [IO.Path]::GetFullPath($EvidenceDirectory) -cne $EvidenceDirectory) {
        throw 'Synthetic restoration scope refused.'
    }
    $snapshot = Get-RestorationBinding $Binding
    $sharedClock = $null
    if ($SyntheticClock) {
        if ($null -eq $SyntheticClockSample) {
            $SyntheticClockSample = (Get-Command Get-RestorationWindowsClockSample -CommandType Function).ScriptBlock
        }
        $sharedClock = New-RestorationSharedClock $Deadline $SyntheticClockSample $snapshot.host_boot_identity
    }
    $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($EvidenceDirectory, $true)
    try {
        $authority = [pscustomobject]@{
            Root=$EvidenceDirectory; RootIdentity=$EvidenceIdentity; RootPin=$pin; Binding=$snapshot
            Thread=[Threading.Thread]::CurrentThread.ManagedThreadId; Phase='Ready'; Clock=$clock
            Deadline=$Deadline; Budget=$budget; Verify=$Verify; BeforeReadPin=$BeforeReadPin; SharedClock=$sharedClock
            Intent=$null; Checkpoint=$null; Baseline=$null; IntentClaimCollision=$false
            UseReceiptDigests=$false; ReceiptActivation=$null; Verifying=$false
            IntentDigestRead=$false; CheckpointDigestRead=$false; CheckpointBaselineSha256=$null
        }
        Assert-RestorationScope $authority
        $scope = [pscustomobject]@{}
        $script:RestorationScopes.Add($scope, $authority)
        return $scope
    }
    catch { $pin.Dispose(); throw }
}

<#
.SYNOPSIS
Verify original identity and bytes using the retained strict read handle.
.PARAMETER Record
Private file identity, expected bytes and retained read stream.
#>
function Assert-RestorationRecord([object]$Record) {
    if ([Atlaso.WorkstationFileIdentity]::GetOrdinaryFileHandleIdentity($Record.Stream.SafeFileHandle) -cne $Record.Identity) {
        throw 'Original restoration receipt identity changed.'
    }
    $bytes = [byte[]]::new($Record.Bytes.Length)
    $Record.Stream.Position = 0
    $Record.Stream.ReadExactly($bytes, 0, $bytes.Length)
    if ($Record.Stream.Length -ne $bytes.Length -or
        -not [Linq.Enumerable]::SequenceEqual[byte]($bytes, $Record.Bytes)) {
        throw 'Original restoration receipt bytes changed.'
    }
}

<#
.SYNOPSIS
Publish an exclusive original phase and retain the verified final file handle.
.PARAMETER Authority
Private original capture state.
.PARAMETER Phase
Intent or checkpoint journal phase.
.PARAMETER Bytes
Exact bounded phase record bytes.
#>
function Publish-RestorationRecord([object]$Authority, [string]$Phase, [byte[]]$Bytes) {
    Assert-RestorationScope $Authority
    $stem = Join-Path $Authority.Root ('atlaso-restoration-' + $Authority.Binding.receiver_nonce + '.' + $Phase)
    $path = $stem + '.json'
    $stage = $stem + '.pending'
    if ((Test-Path -LiteralPath $path) -or (Test-Path -LiteralPath $stage)) {
        if ($Phase -ceq 'intent') { $Authority.IntentClaimCollision = $true }
        throw 'Original restoration phase already exists or is uncertain.'
    }
    $writer = $null
    try {
        $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($stage)
        $identity = [Atlaso.WorkstationFileIdentity]::GetOrdinaryFileHandleIdentity($writer.SafeFileHandle)
        $writer.Write($Bytes, 0, $Bytes.Length)
        [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $path, $false)
    }
    catch {
        $native = $_.Exception.GetBaseException()
        if ($Phase -ceq 'intent' -and $native -is [ComponentModel.Win32Exception] -and
            $native.NativeErrorCode -in @(80,183)) { $Authority.IntentClaimCollision = $true }
        throw
    }
    finally { if ($writer) { $writer.Dispose() } }

    if ($Authority.BeforeReadPin) { $null = & $Authority.BeforeReadPin $Phase $path }
    $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($path, $true)
    $stream = $null
    try {
        $stream = [IO.FileStream]::new($pin, [IO.FileAccess]::Read)
        $record = [pscustomobject]@{ Stream=$stream; Identity=$identity; Bytes=$Bytes; Sha256=(Get-RestorationDigest $Bytes) }
        Assert-RestorationRecord $record
        Sync-AtlasoDirectoryMetadata -DirectoryPath $Authority.Root
        Assert-RestorationScope $Authority
        return $record
    }
    catch {
        if ($stream) { $stream.Dispose() } else { $pin.Dispose() }
        throw
    }
}

<#
.SYNOPSIS
Accept the one synchronous checkpoint from the current capture and freeze its bytes.
.PARAMETER Authority
Private original capture state.
.PARAMETER Baseline
Stage1 data from the original capture.
#>
function Save-RestorationCheckpoint([object]$Authority, [byte[]]$Baseline) {
    if ($Authority.UseReceiptDigests -and
        ($Authority.Thread -ne [Threading.Thread]::CurrentThread.ManagedThreadId -or
        $Authority.Verifying -or $null -eq $Authority.ReceiptActivation -or
        $Authority.Phase -cne 'Capturing' -or -not $Authority.IntentDigestRead)) {
        throw 'Original restoration checkpoint is unavailable.'
    }
    try {
        if ($Authority.Phase -cne 'Capturing') { throw 'Original restoration callback is not available.' }
        $Authority.Phase = 'PublishingCheckpoint'
        Assert-RestorationScope $Authority
        Assert-RestorationRecord $Authority.Intent
        if ($null -eq $Baseline) { throw 'Restoration projection missing.' }
        $frozen = [byte[]]$Baseline.Clone()
        Assert-RestorationBaseline $frozen $Authority.Binding
        $baselineDigest = Get-RestorationDigest $frozen
        $header = [ordered]@{
            schema=1; kind='restoration-baseline-checkpoint'; original_intent_sha256=$Authority.Intent.Sha256
            baseline_sha256=$baselineDigest
        } | ConvertTo-Json -Compress
        $json = $header.Substring(0, $header.Length - 1) + ',"baseline":' + [Text.Encoding]::ASCII.GetString($frozen) + '}' + [char]10
        $Authority.Checkpoint = Publish-RestorationRecord $Authority 'checkpoint' ([Text.Encoding]::ASCII.GetBytes($json))
        $Authority.Baseline = $frozen
        $Authority.CheckpointBaselineSha256 = $baselineDigest
        $Authority.Phase = 'Checkpointed'
    }
    catch {
        if ($Authority.Phase -cne 'Closed') { $Authority.Phase = 'Failed' }
        throw 'Original restoration checkpoint failed or is uncertain.'
    }
}

<#
.SYNOPSIS
Read one verified digest from an original retained receipt during synthetic capture.
.PARAMETER Authority
Private original capture state.
.PARAMETER Activation
Private identity of this capture invocation.
.PARAMETER Checkpoint
Read the durable checkpoint digest after the one original save.
#>
function Read-RestorationReceiptDigest([object]$Authority, [object]$Activation, [switch]$Checkpoint) {
    $phase = if ($Checkpoint) { 'Checkpointed' } else { 'Capturing' }
    $claim = if ($Checkpoint) { 'CheckpointDigestRead' } else { 'IntentDigestRead' }
    if ($Authority.Thread -ne [Threading.Thread]::CurrentThread.ManagedThreadId -or
        $Authority.Verifying -or $null -eq $Activation -or
        -not [object]::ReferenceEquals($Activation, $Authority.ReceiptActivation) -or
        $Authority.Phase -cne $phase -or $Authority.$claim) {
        throw 'Original restoration receipt digest is unavailable.'
    }

    # Claim before calling the synthetic verifier. A reentrant or failed read cannot retry.
    $Authority.$claim = $true
    try {
        Assert-RestorationScope $Authority
        Assert-RestorationRecord $Authority.Intent
        $record = $Authority.Intent
        if ($Checkpoint) {
            Assert-RestorationRecord $Authority.Checkpoint
            if ((Get-RestorationDigest $Authority.Baseline) -cne $Authority.CheckpointBaselineSha256) {
                throw 'Original restoration checkpoint baseline differs.'
            }
            $record = $Authority.Checkpoint
        }
        $digest = Get-RestorationDigest $record.Bytes
        Assert-RestorationScope $Authority
        if ($digest -cne $record.Sha256 -or $Authority.Phase -cne $phase -or
            -not [object]::ReferenceEquals($Activation, $Authority.ReceiptActivation)) {
            throw 'Original restoration receipt changed.'
        }
        return $digest
    }
    catch {
        $Authority.Phase = 'Failed'
        throw 'Original restoration receipt digest failed or is uncertain.'
    }
}

<#
.SYNOPSIS
Consume the original scope and require a matching completed capture after its checkpoint.
.PARAMETER Scope
Original opaque scope from the internal test admission.
.PARAMETER Capture
Internal synthetic capture with checkpoint and remaining-budget callbacks.
.PARAMETER SyntheticReceiptDigests
Provide two additional one-shot digest callbacks only for synthetic qualification.
#>
function Invoke-RestorationCheckpointCapture([object]$Scope, [scriptblock]$Capture, [switch]$SyntheticReceiptDigests) {
    $ErrorActionPreference = 'Stop'
    $authority = $null
    if (-not $script:RestorationScopes.TryGetValue($Scope, [ref]$authority) -or $authority.Phase -cne 'Ready' -or
        $authority.Thread -ne [Threading.Thread]::CurrentThread.ManagedThreadId) {
        throw 'Original restoration capture is unavailable.'
    }
    if ($null -ne $authority.SharedClock -and -not $SyntheticReceiptDigests) {
        throw 'Original synthetic clock requires receipt digest capture.'
    }
    $authority.UseReceiptDigests = $SyntheticReceiptDigests.IsPresent
    $authority.Phase = 'Claiming'
    try {
        Assert-RestorationScope $authority
        $stem = Join-Path $authority.Root ('atlaso-restoration-' + $authority.Binding.receiver_nonce + '.')
        foreach ($extension in @('intent.json','intent.pending','checkpoint.json','checkpoint.pending')) {
            $path = $stem + $extension
            if (-not (Test-Path -LiteralPath $path)) { continue }
            if ($extension -clike 'intent.*' -or (Test-Path -LiteralPath ($stem + 'intent.json')) -or
                (Test-Path -LiteralPath ($stem + 'intent.pending'))) {
                $authority.IntentClaimCollision = $true
                throw 'Original restoration intent already exists.'
            }
            throw 'Original restoration checkpoint already exists.'
        }
        $intentFields = [ordered]@{
            schema=1; kind='restoration-capture-intent'; binding=$authority.Binding
            evidence_identity=$authority.RootIdentity; deadline_utc=$authority.Deadline.ToUniversalTime().ToString('O')
        }
        if ($null -ne $authority.SharedClock) {
            $shared = $authority.SharedClock
            $intentFields.schema = 2
            $intentFields.deadline_utc = $shared.UtcEnd.ToString('O')
            $intentFields.clock = [ordered]@{
                boot_sha256=$shared.BootSha256; deadline_counter=$shared.EndCounter
                frequency=$shared.Frequency; deadline_utc_ms=$shared.UtcMilliseconds
            }
        }
        $intent = $intentFields | ConvertTo-Json -Depth 4 -Compress
        $authority.Intent = Publish-RestorationRecord $authority 'intent' ([Text.Encoding]::UTF8.GetBytes($intent + [char]10))
        $authority.Phase = 'Capturing'
        $save = (Get-Command Save-RestorationCheckpoint -CommandType Function).ScriptBlock
        $remaining = (Get-Command Get-RestorationRemaining -CommandType Function).ScriptBlock
        $checkpointCallback = [Action[byte[]]]({ param([byte[]]$Baseline) & $save $authority $Baseline }.GetNewClosure())
        $remainingCallback = [Func[double]]({ & $remaining $authority }.GetNewClosure())
        if ($SyntheticReceiptDigests) {
            $activation = [object]::new()
            $authority.ReceiptActivation = $activation
            if ($null -ne $authority.SharedClock) {
                $remainingCallback = [Func[double]]({ & $remaining $authority $activation }.GetNewClosure())
            }
            $readDigest = (Get-Command Read-RestorationReceiptDigest -CommandType Function).ScriptBlock
            $readIntent = [Func[string]]({ & $readDigest $authority $activation }.GetNewClosure())
            $readCheckpoint = [Func[string]]({ & $readDigest $authority $activation -Checkpoint }.GetNewClosure())
            try { $result = & $Capture $checkpointCallback $remainingCallback $readIntent $readCheckpoint }
            finally { $authority.ReceiptActivation = $null }
            if (-not $authority.IntentDigestRead -or -not $authority.CheckpointDigestRead) {
                throw 'Original restoration receipt digest sequence is incomplete.'
            }
        }
        else { $result = & $Capture $checkpointCallback $remainingCallback }
        Assert-RestorationScope $authority
        if ($authority.Phase -cne 'Checkpointed' -or $result -isnot [byte[]] -or
            -not [Linq.Enumerable]::SequenceEqual[byte]($result, $authority.Baseline)) {
            throw 'Original restoration capture did not return matching baseline data.'
        }
        Assert-RestorationRecord $authority.Intent
        Assert-RestorationRecord $authority.Checkpoint
        $null = Get-RestorationRemaining $authority
        $authority.Phase = 'Completed'
        return [pscustomobject]@{
            IntentSha256=$authority.Intent.Sha256; CheckpointSha256=$authority.Checkpoint.Sha256
            BaselineSha256=(Get-RestorationDigest $authority.Baseline)
        }
    }
    catch {
        if ($authority.Phase -cne 'Closed') { $authority.Phase = 'Failed' }
        if ($authority.IntentClaimCollision) {
            # HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) identifies only a claim refusal.
            throw [IO.IOException]::new('Original restoration receiver claim already exists.', 0x800700B7)
        }
        throw 'Original restoration capture failed or is uncertain.'
    }
}

<#
.SYNOPSIS
Exercise CHECKPOINT through end-of-buffer on an original synthetic Stage2 scope.
.PARAMETER Scope
Original opaque test scope created with the shared clock.
.PARAMETER Transcript
Stable fixture-owned bytes containing CHECKPOINT followed by COMPLETE.
#>
function Invoke-RestorationCheckpointFrameTest([object]$Scope, [byte[]]$Transcript) {
    $ErrorActionPreference = 'Stop'
    $authority = $null
    if (-not $script:RestorationScopes.TryGetValue($Scope, [ref]$authority) -or
        $authority.Phase -cne 'Ready' -or $null -eq $authority.SharedClock -or
        $authority.Thread -ne [Threading.Thread]::CurrentThread.ManagedThreadId) {
        throw 'Original restoration frame fixture is unavailable.'
    }
    $run = [Convert]::FromHexString($authority.Binding.run_id)
    $nonce = [Convert]::FromHexString($authority.Binding.receiver_nonce)
    $limit = 2 * (10 + $script:MaximumBaselineBytes) + 1
    $codec = Join-Path $PSScriptRoot 'Atlaso.RestorationControlFrames.psm1'
    $observation = [pscustomobject]@{ Ack = $null }
    $capture = {
        param([Action[byte[]]]$Save, [Func[double]]$Remaining, [Func[string]]$ReadIntent, [Func[string]]$ReadCheckpoint)

        $intent = [Convert]::FromHexString($ReadIntent.Invoke())
        $null = $Remaining.Invoke()
        if ($null -eq $Transcript -or $Transcript.Length -gt $limit) {
            throw 'Restoration transcript size refused.'
        }
        $snapshot = [byte[]]$Transcript.Clone()
        Import-Module -Name $codec -Scope Local
        $cursor = [pscustomobject]@{ Offset = 0 }
        $read = [Func[int,byte[]]]({
            param([int]$Count)
            $size = [Math]::Min([Math]::Min($Count, 4096), $snapshot.Length - $cursor.Offset)
            $fragment = [byte[]]::new($size)
            [Buffer]::BlockCopy($snapshot, $cursor.Offset, $fragment, 0, $size)
            $cursor.Offset += $size
            return ,$fragment
        }.GetNewClosure())
        $budget = [Action]({ $null = $Remaining.Invoke() }.GetNewClosure())

        $baseline = [Atlaso.RestorationControlFrames]::ReadData(2, $read, $budget)
        $budget.Invoke()
        [Atlaso.RestorationControlFrames]::RequirePublicData($baseline)
        $budget.Invoke()
        $Save.Invoke($baseline)

        $checkpoint = [Convert]::FromHexString($ReadCheckpoint.Invoke())
        $budget.Invoke()
        $observation.Ack = [Atlaso.RestorationControlFrames]::EncodeAck(
            $run, $nonce, $intent, [Security.Cryptography.SHA256]::HashData($baseline), $checkpoint)
        $budget.Invoke()

        $complete = [Atlaso.RestorationControlFrames]::ReadData(4, $read, $budget)
        $budget.Invoke()
        if (-not [Linq.Enumerable]::SequenceEqual[byte]($baseline, $complete) -or
            $cursor.Offset -ne $snapshot.Length) {
            throw 'Restoration transcript completion refused.'
        }
        $budget.Invoke()
        return ,([byte[]]$baseline.Clone())
    }.GetNewClosure()
    $journal = Invoke-RestorationCheckpointCapture -Scope $Scope -Capture $capture -SyntheticReceiptDigests
    return [pscustomobject]@{ Journal = $journal; Ack = [byte[]]$observation.Ack.Clone() }
}

<#
.SYNOPSIS
Revoke the original scope before disposing its read pins.
.PARAMETER Scope
Original opaque scope from the internal test admission.
#>
function Close-RestorationCheckpointScope([object]$Scope) {
    $authority = $null
    if (-not $script:RestorationScopes.TryGetValue($Scope, [ref]$authority) -or
        $authority.Thread -ne [Threading.Thread]::CurrentThread.ManagedThreadId) {
        throw 'Original restoration scope unavailable.'
    }
    if ($authority.UseReceiptDigests -and
        ($null -ne $authority.ReceiptActivation -or $authority.Phase -notin @('Failed','Completed'))) {
        throw 'Original restoration scope cannot close during capture.'
    }
    $authority.Phase = 'Closed'
    $null = $script:RestorationScopes.Remove($Scope)
    try {
        if ($authority.Checkpoint) { $authority.Checkpoint.Stream.Dispose() }
        if ($authority.Intent) { $authority.Intent.Stream.Dispose() }
    }
    finally { $authority.RootPin.Dispose() }
}

<#
.SYNOPSIS
Refuse live restoration checkpoint capture until an original controller is admitted.
#>
function Invoke-AtlasoRestorationCheckpoint {
    [CmdletBinding()]
    param()

    throw 'Production restoration checkpoint admission is unavailable.'
}

Export-ModuleMember -Function Invoke-AtlasoRestorationCheckpoint
