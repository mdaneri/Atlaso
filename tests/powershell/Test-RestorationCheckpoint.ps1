<#
.SYNOPSIS
Exercise the private restoration checkpoint lifecycle against an admitted test root.
.DESCRIPTION
This focused harness never creates or removes its evidence root. Every generated
intent and checkpoint is preserved under the supplied task-owned root.
.PARAMETER TestRoot
Absolute path to the already-created task-owned test evidence directory.
.PARAMETER TestRootIdentity
Previously recorded native identity of TestRoot; the harness refuses a mismatch.
.PARAMETER ClaimWorker
Internal switch used only by the harness to race two distinct run bindings for one nonce.
.PARAMETER WorkerBindingJson
Exact synthetic binding for one claim-race worker.
.PARAMETER WorkerStartSignal
Path to the already-owned release marker used to start the workers together.
.PARAMETER WorkerResultPath
Unique result path under TestRoot where this worker preserves its outcome.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TestRoot,
    [Parameter(Mandatory = $true)][string]$TestRootIdentity,
    [switch]$ClaimWorker,
    [string]$WorkerBindingJson,
    [string]$WorkerStartSignal,
    [string]$WorkerResultPath
)

$ErrorActionPreference = 'Stop'
$env:TEMP = 'E:\.codex\temp'
$env:TMP = $env:TEMP
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$cleanupModulePath = Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1'
$checkpointModulePath = Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.RestorationCheckpoint.psm1'
Import-Module $cleanupModulePath -Force
$checkpointModule = Import-Module $checkpointModulePath -Force -PassThru
$resolvedTestRoot = [System.IO.Path]::GetFullPath($TestRoot)
if (-not [System.IO.Directory]::Exists($resolvedTestRoot) -or
    [Atlaso.WorkstationFileIdentity]::Get($resolvedTestRoot) -cne $TestRootIdentity) {
    throw 'The pre-created restoration test root identity does not match.'
}

<#
.SYNOPSIS
Fail the focused restoration test when an assertion is false.
.PARAMETER Condition
Boolean condition that must be true.
.PARAMETER Message
Safe diagnostic emitted when the condition is false.
#>
function Assert-RestorationTest([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

<#
.SYNOPSIS
Build a synthetic exact receiver binding for one test case.
.PARAMETER Nonce
Distinct lower-case receiver nonce for the fixture.
.PARAMETER RunId
Distinct lower-case run identifier for the fixture.
#>
function Get-TestBinding([string]$Nonce, [string]$RunId) {
    return [ordered]@{
        task_id = '00112233-4455-6677-8899-aabbccddeeff'
        source_commit = '1111111111111111111111111111111111111111'
        source_tree = '2222222222222222222222222222222222222222'
        bundle_sha256 = 'a111111111111111111111111111111111111111111111111111111111111111'
        runtime_sha256 = 'a222222222222222222222222222222222222222222222222222222222222222'
        resource_receipt_sha256 = 'a333333333333333333333333333333333333333333333333333333333333333'
        persistent_vm_identity_sha256 = 'a444444444444444444444444444444444444444444444444444444444444444'
        receiver_receipt_sha256 = 'a555555555555555555555555555555555555555555555555555555555555555'
        host_boot_identity = '638982378001234567'
        guest_boot_id = '00112233-4455-6677-8899-aabbccddeeff'
        controller_identity = 'process:12345:638982378009876543'
        provider_identity = 'process:23456:638982378009876544'
        run_id = $RunId
        receiver_nonce = $Nonce
        role = 'main'
        interface = 'eth1'
        mac_address = '02:00:00:00:00:01'
        origin = 'https://192.0.2.20'
    }
}

<#
.SYNOPSIS
Serialize a bounded fixture value as compact JSON.
.PARAMETER Value
Fixture object to serialize.
#>
function Get-CanonicalTestJson([object]$Value) {
    return ConvertTo-Json -InputObject $Value -Depth 24 -Compress
}

<#
.SYNOPSIS
Return the SHA-256 digest of exact ASCII fixture JSON.
.PARAMETER Json
Exact JSON text to hash.
#>
function Get-TestDigest([string]$Json) {
    $bytes = [Text.Encoding]::ASCII.GetBytes($Json)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

<#
.SYNOPSIS
Return the SHA-256 digest of exact fixture bytes.
.PARAMETER Bytes
Exact bytes to hash.
#>
function Get-TestDigestBytes([byte[]]$Bytes) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

<#
.SYNOPSIS
Create the exact synthetic stage1 baseline used by lifecycle tests.
#>
function New-TestBaselineBytes {
    $review = [ordered]@{
        active_task = $null
        execution_count = 0
        initial_apply_required = $false
        pending_count = 0
        plan_error = ''
        requested_units = @()
        units = @()
    }
    $row = [ordered]@{
        access_management_ui_enabled = $true
        admin_up = $true
        check_duplicate_ip_addresses = $true
        gateway = $null
        id = 13
        ipv4_method = 'static'
        ip_cidr = '192.0.2.20/24'
        ipv6_cidr = 'fd00:1084::20/64'
        ipv6_enabled = $true
        ipv6_gateway = ''
        mac_address = '02:00:00:00:00:01'
        mode = 'access'
        mtu = 1500
        name = 'eth1'
        role = 'access'
    }
    $browser = [ordered]@{
        access_management_ui_enabled = $true
        admin_state = 'up'
        check_duplicate_ip_addresses = $true
        gateway = ''
        ipv4_method = 'static'
        ip_cidr = '192.0.2.20/24'
        ipv6_cidr = 'fd00:1084::20/64'
        ipv6_enabled = $true
        ipv6_gateway = ''
        mode = 'access'
        mtu = 1500
        role = 'access'
    }
    $dns = [ordered]@{
        authoritative = $true
        authoritative_contact = 'hostmaster.example'
        authoritative_expire = 3600
        authoritative_refresh = 600
        authoritative_retry = 60
        authoritative_server = 'ns.example'
        authoritative_ttl = 120
        cache_size = 150
        conditional_forwarders = 'corp.example=192.0.2.54'
        dnssec_enabled = $true
        enabled = $true
        expand_hosts = $false
        listen_interfaces = @('eth1', 'eth2')
        listen_interfaces_present = '1'
        query_logging_mode = 'off'
        rebind_domain_exemptions = 'example'
        rebind_protection_enabled = $false
        upstream_servers = "192.0.2.53`nfd00:1084::53"
    }
    $parts = [ordered]@{
        review = $review
        original_row = $row
        browser_fields = $browser
        dns_settings = $dns
    }
    $digests = [ordered]@{}
    foreach ($name in $parts.Keys) {
        $digests[$name] = Get-TestDigest (Get-CanonicalTestJson $parts[$name])
    }
    $baseline = [ordered]@{
        browser_fields = $browser
        consistency_only = $true
        dns_settings = $dns
        formal_acceptance = $false
        native_acceptance = $false
        original_row = $row
        projection_sha256 = $digests
        review = $review
        test_only = $true
    }
    return ,([Text.Encoding]::ASCII.GetBytes((Get-CanonicalTestJson $baseline)))
}

<#
.SYNOPSIS
Generate a fresh lower-case nonce for an isolated fixture case.
#>
function New-TestCaseNonce {
    return [Guid]::NewGuid().ToString('N')
}

<#
.SYNOPSIS
Create a private synthetic scope bound to the supplied original test root.
.PARAMETER Nonce
Fresh receiver nonce for the scope.
.PARAMETER RunId
Fresh run identifier for the scope.
.PARAMETER Verify
Synthetic current-admission verifier used by the private test seam.
.PARAMETER BeforeReadPin
Optional synthetic hook invoked between file publication and final read pin.
.PARAMETER Deadline
Original absolute deadline for the scope.
.PARAMETER SyntheticClockSample
Optional deterministic sample source for an opt-in synthetic clock.
#>
function New-TestScope([string]$Nonce, [string]$RunId, [scriptblock]$Verify,
    [scriptblock]$BeforeReadPin, [Nullable[DateTimeOffset]]$Deadline, [scriptblock]$SyntheticClockSample) {
    [DateTimeOffset]$effectiveDeadline = if ($null -eq $Deadline) {
        [DateTimeOffset]::UtcNow.AddSeconds(120)
    } else {
        $Deadline
    }
    $binding = Get-TestBinding -Nonce $Nonce -RunId $RunId
    return & $checkpointModule {
        param($Root, $Identity, $Bound, $Expires, $Verifier, $Hook, $Sample)
        New-RestorationCheckpointTestScope -EvidenceDirectory $Root -EvidenceIdentity $Identity `
            -Binding $Bound -Deadline $Expires -Verify $Verifier -BeforeReadPin $Hook `
            -SyntheticClock:($null -ne $Sample) -SyntheticClockSample $Sample
    } $resolvedTestRoot $TestRootIdentity $binding $effectiveDeadline $Verify $BeforeReadPin $SyntheticClockSample
}

<#
.SYNOPSIS
Invoke the private synchronous checkpoint capture for one scope.
.PARAMETER Scope
Opaque scope returned by New-TestScope.
.PARAMETER Capture
Synthetic capture callback which publishes and returns exact baseline bytes.
.PARAMETER SyntheticReceiptDigests
Enable the private one-shot receipt digest callbacks for this fixture.
#>
function Invoke-TestCapture([object]$Scope, [scriptblock]$Capture, [switch]$SyntheticReceiptDigests) {
    return & $checkpointModule {
        param($OriginalScope, $Runner, $EnableDigests)
        Invoke-RestorationCheckpointCapture -Scope $OriginalScope -Capture $Runner -SyntheticReceiptDigests:$EnableDigests
    } $Scope $Capture $SyntheticReceiptDigests.IsPresent
}

<#
.SYNOPSIS
Revoke a private synthetic scope and release its retained pins.
.PARAMETER Scope
Opaque scope returned by New-TestScope.
#>
function Close-TestScope([object]$Scope) {
    & $checkpointModule {
        param($OriginalScope)
        Close-RestorationCheckpointScope -Scope $OriginalScope
    } $Scope
}

if ($ClaimWorker) {
    if (-not $WorkerBindingJson -or -not $WorkerStartSignal -or -not $WorkerResultPath) {
        throw 'Restoration claim worker arguments are incomplete.'
    }
    $startWait = [Diagnostics.Stopwatch]::StartNew()
    while (-not [System.IO.File]::Exists($WorkerStartSignal) -and $startWait.Elapsed.TotalSeconds -lt 10) {
        Start-Sleep -Milliseconds 5
    }
    if (-not [System.IO.File]::Exists($WorkerStartSignal)) {
        [System.IO.File]::WriteAllText($WorkerResultPath, '{"outcome":"worker_setup_error"}', [Text.Encoding]::ASCII)
        exit 2
    }
    $workerBinding = ConvertFrom-Json -InputObject $WorkerBindingJson -AsHashtable
    $workerScope = $null
    $workerProgress = @{ CaptureStarted = $false }
    try {
        $workerScope = & $checkpointModule {
            param($Root, $Identity, $Bound)
            New-RestorationCheckpointTestScope -EvidenceDirectory $Root -EvidenceIdentity $Identity `
                -Binding $Bound -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(120)) -Verify { $true }
        } $resolvedTestRoot $TestRootIdentity $workerBinding
        $workerBaseline = New-TestBaselineBytes
        $workerCapture = {
            param($Checkpoint, $Remaining)
            $workerProgress.CaptureStarted = $true
            $null = $Checkpoint.Invoke($workerBaseline)
            return ,$workerBaseline
        }.GetNewClosure()
        try { $workerResult = Invoke-TestCapture -Scope $workerScope -Capture $workerCapture }
        finally { Close-TestScope $workerScope }
        $result = [ordered]@{ outcome = 'success'; checkpoint_sha256 = $workerResult.CheckpointSha256 }
        [System.IO.File]::WriteAllText($WorkerResultPath, (Get-CanonicalTestJson $result), [Text.Encoding]::ASCII)
        exit 0
    }
    catch {
        $intentPath = Join-Path $resolvedTestRoot ('atlaso-restoration-' + $workerBinding.receiver_nonce + '.intent.json')
        $pendingPath = Join-Path $resolvedTestRoot ('atlaso-restoration-' + $workerBinding.receiver_nonce + '.intent.pending')
        $collisionObserved = $workerScope -and -not $workerProgress.CaptureStarted -and
            $_.Exception -is [IO.IOException] -and $_.Exception.HResult -eq 0x800700B7 -and
            ([System.IO.File]::Exists($intentPath) -or [System.IO.File]::Exists($pendingPath))
        $result = [ordered]@{ outcome = if ($collisionObserved) { 'refused' } else { 'worker_error' }
            hresult = $_.Exception.HResult; capture_started = $workerProgress.CaptureStarted }
        if (-not $collisionObserved) { $result.error_id = $_.FullyQualifiedErrorId }
        [System.IO.File]::WriteAllText($WorkerResultPath, (Get-CanonicalTestJson $result), [Text.Encoding]::ASCII)
        if ($collisionObserved) { exit 1 }
        exit 2
    }
}

<#
.SYNOPSIS
Require a test action to fail closed.
.PARAMETER Action
Action expected to throw.
.PARAMETER Message
Safe diagnostic emitted when the action unexpectedly succeeds.
#>
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-RestorationTest $threw $Message
}

<#
.SYNOPSIS
Require the public live capture entry point to refuse before any capture callback.
#>
function Assert-NoPublicExecutionAdmission {
    $called = $false
    Assert-Throws {
        & $checkpointModule { Invoke-AtlasoRestorationCheckpoint }
        $called = $true
    } 'Production restoration checkpoint entry point must refuse.'
    Assert-RestorationTest (-not $called) 'Production refusal must occur before any capture callback.'
}

$initialRootEntries = @(Get-ChildItem -LiteralPath $resolvedTestRoot -Force | ForEach-Object Name)
if ($ClaimWorker) { throw 'Claim workers are entered only through the direct worker branch.' }

Assert-NoPublicExecutionAdmission

$successNonce = New-TestCaseNonce
$successState = [hashtable]::Synchronized(@{ VerifyCalls = 0; CallbackCalls = 0 })
$successVerify = { $successState.VerifyCalls++; return $true }.GetNewClosure()
$successScope = New-TestScope -Nonce $successNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify $successVerify -BeforeReadPin $null -Deadline $null
$copyScope = $successScope | ConvertTo-Json -Compress | ConvertFrom-Json
$copyProgress = @{ Called = $false }
Assert-Throws { Invoke-TestCapture $copyScope { $copyProgress.Called = $true } } `
    'A serialized copy must not acquire the original unused scope.'
Assert-RestorationTest (-not $copyProgress.Called -and
    -not [IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$successNonce.intent.json"))) `
    'A copied scope must refuse before intent or capture.'
$baselineBytes = New-TestBaselineBytes
$successCapture = {
    param($Checkpoint, $Remaining)
    $successState.CallbackCalls++
    if (-not [System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$successNonce.intent.json"))) {
        throw 'The exclusive durable intent must exist before capture starts.'
    }
    if ($Remaining.Invoke() -le 0) { throw 'Original capture deadline should have remaining time.' }
    $Checkpoint.Invoke($baselineBytes)
    return ,$baselineBytes
}.GetNewClosure()
$successResult = Invoke-TestCapture -Scope $successScope -Capture $successCapture
Assert-RestorationTest ($successState.CallbackCalls -eq 1) 'Capture callback should run once.'
Assert-RestorationTest ($successState.VerifyCalls -ge 3) 'Original admission should be checked around capture and publication.'
Assert-RestorationTest ($successResult.BaselineSha256 -eq (Get-TestDigestBytes $baselineBytes)) `
    'Successful result should expose a SHA-256 baseline digest.'
$intentPath = Join-Path $resolvedTestRoot "atlaso-restoration-$successNonce.intent.json"
$checkpointPath = Join-Path $resolvedTestRoot "atlaso-restoration-$successNonce.checkpoint.json"
Assert-RestorationTest ([System.IO.File]::Exists($intentPath)) 'Successful intent should be preserved.'
Assert-RestorationTest ([System.IO.File]::Exists($checkpointPath)) 'Successful checkpoint should be preserved.'
$checkpointJson = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
Assert-RestorationTest ($checkpointJson.kind -ceq 'restoration-baseline-checkpoint') 'Checkpoint kind is fixed.'
Assert-RestorationTest ($checkpointJson.original_intent_sha256 -eq $successResult.IntentSha256) 'Checkpoint binds its original intent.'
Assert-RestorationTest ($checkpointJson.baseline_sha256 -eq $successResult.BaselineSha256) 'Checkpoint binds the exact baseline.'
Close-TestScope $successScope

$reopenProgress = @{ Called = $false }
$reopenScope = New-TestScope -Nonce $successNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify { $true } -BeforeReadPin $null -Deadline $null
Assert-Throws { Invoke-TestCapture $reopenScope { $reopenProgress.Called = $true } } `
    'A different run must not reopen a used receiver after its original scope closes.'
Assert-RestorationTest (-not $reopenProgress.Called -and
    (Get-FileHash -LiteralPath $intentPath).Hash.ToLowerInvariant() -ceq $successResult.IntentSha256 -and
    (Get-FileHash -LiteralPath $checkpointPath).Hash.ToLowerInvariant() -ceq $successResult.CheckpointSha256) `
    'The reopened scope must leave both original receipts untouched.'
Close-TestScope $reopenScope

$expiredNonce = New-TestCaseNonce
$expiredState = [hashtable]::Synchronized(@{ VerifyCalls = 0 })
$expiredDeadline = [DateTimeOffset]::UtcNow.AddMilliseconds(250)
$expiredVerify = { $expiredState.VerifyCalls++; return $true }.GetNewClosure()
$expiredScope = New-TestScope -Nonce $expiredNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify $expiredVerify -BeforeReadPin $null -Deadline $expiredDeadline
Start-Sleep -Milliseconds 350
$verifyCallsBeforeExpiredCapture = $expiredState.VerifyCalls
Assert-Throws { Invoke-TestCapture $expiredScope { throw 'Expired capture must not invoke its producer.' } } `
    'Expired original deadline must refuse capture.'
Assert-RestorationTest ($expiredState.VerifyCalls -eq $verifyCallsBeforeExpiredCapture) `
    'An expired capture must stop before another admission check or UI read.'
Assert-RestorationTest (-not [System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$expiredNonce.intent.json"))) `
    'Expired preflight must not publish an intent.'
Close-TestScope $expiredScope

$badNonce = New-TestCaseNonce
$badScope = New-TestScope -Nonce $badNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify { $true } -BeforeReadPin $null -Deadline $null
$badBytes = [Text.Encoding]::ASCII.GetBytes('{"unexpected":true}')
Assert-Throws { Invoke-TestCapture $badScope { param($Checkpoint, $Remaining); $Checkpoint.Invoke($badBytes); return ,$badBytes } } `
    'Malformed public baseline must refuse.'
Assert-RestorationTest (-not [System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$badNonce.checkpoint.json"))) `
    'Invalid baseline must not publish a checkpoint.'
Close-TestScope $badScope

$secretNonce = New-TestCaseNonce
$secretScope = New-TestScope -Nonce $secretNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify { $true } -BeforeReadPin $null -Deadline $null
$secretJson = [Text.Encoding]::ASCII.GetString($baselineBytes).Replace('"native_acceptance":false', '"native_acceptance":true')
$secretBytes = [Text.Encoding]::ASCII.GetBytes($secretJson)
Assert-Throws {
    Invoke-TestCapture $secretScope {
        param($Checkpoint, $Remaining)
        $Checkpoint.Invoke($secretBytes)
        return ,$secretBytes
    }
} 'A baseline claiming native acceptance must refuse.'
Assert-RestorationTest (-not [System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$secretNonce.checkpoint.json"))) `
    'A forbidden acceptance control must not publish a checkpoint.'
Close-TestScope $secretScope

$driftNonce = New-TestCaseNonce
$driftState = [hashtable]::Synchronized(@{ Allowed = $true })
$driftVerify = { return [bool]$driftState.Allowed }.GetNewClosure()
$driftScope = New-TestScope -Nonce $driftNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify $driftVerify -BeforeReadPin $null -Deadline $null
Assert-Throws {
    Invoke-TestCapture $driftScope {
        param($Checkpoint, $Remaining)
        $Checkpoint.Invoke($baselineBytes)
        $driftState.Allowed = $false
        return ,$baselineBytes
    }
} 'Admission drift after checkpoint must refuse successful completion.'
Assert-RestorationTest ([System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$driftNonce.checkpoint.json"))) `
    'A published checkpoint must be preserved after later drift.'
Close-TestScope $driftScope

$unknownNonce = New-TestCaseNonce
$unknownState = @{ Renamed = $false; Acknowledged = $false }
$unknownHook = {
    param($Phase, $Path)
    if ($Phase -ceq 'checkpoint') {
        $unknownState.Renamed = [IO.File]::Exists($Path)
        throw 'Synthetic interruption after checkpoint rename.'
    }
}.GetNewClosure()
$unknownScope = New-TestScope -Nonce $unknownNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify { $true } -BeforeReadPin $unknownHook -Deadline $null
Assert-Throws {
    Invoke-TestCapture $unknownScope {
        param($Checkpoint, $Remaining)
        $Checkpoint.Invoke($baselineBytes)
        $unknownState.Acknowledged = $true
        return ,$baselineBytes
    }
} 'A checkpoint renamed before a synthetic interruption must not acknowledge or complete.'
$unknownIntent = Join-Path $resolvedTestRoot "atlaso-restoration-$unknownNonce.intent.json"
$unknownCheckpoint = Join-Path $resolvedTestRoot "atlaso-restoration-$unknownNonce.checkpoint.json"
Assert-RestorationTest ($unknownState.Renamed -and -not $unknownState.Acknowledged -and
    [IO.File]::Exists($unknownIntent) -and [IO.File]::Exists($unknownCheckpoint)) `
    'Both actual original files must remain after the uncertain checkpoint publication.'
Close-TestScope $unknownScope
$unknownReopen = New-TestScope -Nonce $unknownNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify { $true } -BeforeReadPin $null -Deadline $null
$unknownReopenState = @{ Called = $false }
Assert-Throws { Invoke-TestCapture $unknownReopen { $unknownReopenState.Called = $true } } `
    'An uncertain published checkpoint must consume the original receiver across scopes.'
Assert-RestorationTest (-not $unknownReopenState.Called -and [IO.File]::Exists($unknownIntent) -and
    [IO.File]::Exists($unknownCheckpoint)) 'Reopening cannot adopt or remove uncertain evidence.'
Close-TestScope $unknownReopen

$replacementNonce = New-TestCaseNonce
$replacementState = [hashtable]::Synchronized(@{ IdentityBefore = $null; IdentityAfter = $null })
$replacementHook = {
    param($Phase, $Path)
    if ($Phase -cne 'intent') { return }
    $originalBytes = [System.IO.File]::ReadAllBytes($Path)
    $originalCopy = $Path + '.replacement-original.json'
    $originalPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true)
    try {
        $replacementState.IdentityBefore = [Atlaso.WorkstationFileIdentity]::GetOrdinaryFileHandleIdentity($originalPin)
    }
    finally { $originalPin.Dispose() }
    [System.IO.File]::Move($Path, $originalCopy)
    $replacementStage = $Path + '.replacement.pending'
    [System.IO.File]::WriteAllBytes($replacementStage, $originalBytes)
    [System.IO.File]::Move($replacementStage, $Path)
    $replacementPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Path, $true)
    try {
        $replacementState.IdentityAfter = [Atlaso.WorkstationFileIdentity]::GetOrdinaryFileHandleIdentity($replacementPin)
    }
    finally { $replacementPin.Dispose() }
}.GetNewClosure()
$replacementScope = New-TestScope -Nonce $replacementNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify { $true } -BeforeReadPin $replacementHook -Deadline $null
Assert-Throws {
    Invoke-TestCapture $replacementScope {
        param($Checkpoint, $Remaining)
        $Checkpoint.Invoke($baselineBytes)
        return ,$baselineBytes
    }
} 'An equal-byte replacement at the close-to-pin boundary must refuse.'
Assert-RestorationTest ($replacementState.IdentityBefore -and $replacementState.IdentityAfter -and
    $replacementState.IdentityBefore -cne $replacementState.IdentityAfter) `
    'The identity-replacement fixture must replace the file identity.'
Assert-RestorationTest ([System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$replacementNonce.intent.json.replacement-original.json"))) `
    'The pre-replacement original bytes must remain preserved.'
Assert-RestorationTest ([Linq.Enumerable]::SequenceEqual[byte](
    [System.IO.File]::ReadAllBytes((Join-Path $resolvedTestRoot "atlaso-restoration-$replacementNonce.intent.json.replacement-original.json")),
    [System.IO.File]::ReadAllBytes((Join-Path $resolvedTestRoot "atlaso-restoration-$replacementNonce.intent.json")))) `
    'Equal-byte identity substitution must preserve the exact original intent bytes.'
Assert-RestorationTest (-not [System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$replacementNonce.checkpoint.json"))) `
    'Identity substitution must consume the intent without producing a checkpoint.'
Close-TestScope $replacementScope

$lifecycleNonce = New-TestCaseNonce
$lifecycleScope = New-TestScope -Nonce $lifecycleNonce -RunId ([Guid]::NewGuid().ToString('N')) `
    -Verify { $true } -BeforeReadPin $null -Deadline $null
$lifecycleState = [hashtable]::Synchronized(@{ DuplicateCallbacks = 0 })
$duplicateCapture = {
    param($Checkpoint, $Remaining)
    $lifecycleState.DuplicateCallbacks++
    $Checkpoint.Invoke($baselineBytes)
    $Checkpoint.Invoke($baselineBytes)
    return ,$baselineBytes
}.GetNewClosure()
Assert-Throws {
    Invoke-TestCapture $lifecycleScope $duplicateCapture
} 'A duplicate checkpoint callback must refuse.'
Assert-RestorationTest ($lifecycleState.DuplicateCallbacks -eq 1) 'The capture callback itself should run once.'
Assert-Throws { Invoke-TestCapture $lifecycleScope { throw 'A consumed scope must not re-enter.' } } `
    'A consumed scope must refuse re-entry.'
Close-TestScope $lifecycleScope
Assert-Throws { Invoke-TestCapture $lifecycleScope { throw 'A closed scope must not capture.' } } `
    'A closed scope must remain revoked.'

$digestNonce = New-TestCaseNonce
$digestState = @{ Intent=$null; Checkpoint=$null; ReadIntent=$null; ReadCheckpoint=$null; Reenter=$false; Rejected=$false }
$digestVerifier = {
    if ($digestState.Reenter) {
        $digestState.Reenter = $false
        try { $null = $digestState.ReadIntent.Invoke() }
        catch { $digestState.Rejected = $_.Exception.GetBaseException().Message -ceq 'Original restoration receipt digest is unavailable.' }
    }
    $true
}.GetNewClosure()
$digestScope = New-TestScope $digestNonce (New-TestCaseNonce) $digestVerifier $null $null
$digestCapture = {
    param($Save, $Remaining, $ReadIntent, $ReadCheckpoint)
    $digestState.ReadIntent = $ReadIntent
    $digestState.ReadCheckpoint = $ReadCheckpoint
    Assert-Throws { $null = $ReadCheckpoint.Invoke() } 'The checkpoint digest must refuse before publication.'
    Assert-Throws { $Save.Invoke($baselineBytes) } 'Save must wait for the original intent digest.'
    Assert-Throws { Close-TestScope $digestScope } 'The active original scope must retain its pins.'

    $runspace = [RunspaceFactory]::CreateRunspace()
    $runspace.ThreadOptions = 'ReuseThread'
    $runspace.Open()
    $worker = [PowerShell]::Create()
    try {
        $worker.Runspace = $runspace
        $null = $worker.AddScript({
            param($Reader)
            $rejected = $false
            try { $null = $Reader.Invoke() }
            catch { $rejected = $_.Exception.GetBaseException().Message -ceq 'Original restoration receipt digest is unavailable.' }
            [pscustomobject]@{ Thread=[Threading.Thread]::CurrentThread.ManagedThreadId; Rejected=$rejected }
        }).AddArgument($ReadIntent)
        $other = $worker.Invoke()
        Assert-RestorationTest ($other.Count -eq 1 -and $other[0].Rejected -and
            $other[0].Thread -ne [Threading.Thread]::CurrentThread.ManagedThreadId) `
            'A different managed thread must reach the original digest guard and refuse.'
    }
    finally { $worker.Dispose(); $runspace.Dispose() }

    $digestState.Reenter = $true
    $digestState.Intent = $ReadIntent.Invoke()
    Assert-RestorationTest $digestState.Rejected 'The admission predicate must not reenter a claimed digest.'
    Assert-Throws { $null = $ReadIntent.Invoke() } 'The original intent digest is available once.'
    $Save.Invoke($baselineBytes)
    $digestState.Checkpoint = $ReadCheckpoint.Invoke()
    Assert-Throws { $null = $ReadCheckpoint.Invoke() } 'The original checkpoint digest is available once.'
    return ,$baselineBytes
}.GetNewClosure()
try {
    $digestResult = Invoke-TestCapture $digestScope $digestCapture -SyntheticReceiptDigests
    foreach ($phase in @('intent','checkpoint')) {
        $file = Join-Path $resolvedTestRoot "atlaso-restoration-$digestNonce.$phase.json"
        $expected = (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()
        Assert-RestorationTest ($digestState[$phase] -ceq $expected) 'The callback must hash the exact retained receipt bytes.'
    }
    Assert-RestorationTest ($digestResult.IntentSha256 -ceq $digestState.Intent -and
        $digestResult.CheckpointSha256 -ceq $digestState.Checkpoint) 'Completion must agree with both original receipt digests.'
    Assert-Throws { $null = $digestState.ReadCheckpoint.Invoke() } 'The original callback is stale after capture returns.'
}
finally { Close-TestScope $digestScope }
Assert-Throws { $null = $digestState.ReadIntent.Invoke() } 'The original callback is stale after close.'

$digestDrift = @{ Arm=$false; Checks=0; Refused=$false; Escaped=$false }
$digestDriftVerifier = {
    if ($digestDrift.Arm) { return (++$digestDrift.Checks -eq 1) }
    $true
}.GetNewClosure()
$digestDriftScope = New-TestScope (New-TestCaseNonce) (New-TestCaseNonce) $digestDriftVerifier $null $null
$digestDriftCapture = {
    param($Save, $Remaining, $ReadIntent, $ReadCheckpoint)
    $null = $ReadIntent.Invoke()
    $Save.Invoke($baselineBytes)
    $digestDrift.Arm = $true
    try { $null = $ReadCheckpoint.Invoke(); $digestDrift.Escaped = $true }
    catch { $digestDrift.Refused = $_.Exception.GetBaseException().Message -ceq 'Original restoration receipt digest failed or is uncertain.' }
    Assert-Throws { $null = $ReadCheckpoint.Invoke() } 'A failed digest access cannot retry.'
    return ,$baselineBytes
}.GetNewClosure()
try {
    Assert-Throws { Invoke-TestCapture $digestDriftScope $digestDriftCapture -SyntheticReceiptDigests } `
        'Admission drift after checking the pins must consume the capture.'
    Assert-RestorationTest ($digestDrift.Checks -eq 2 -and $digestDrift.Refused -and -not $digestDrift.Escaped) `
        'The second guard must refuse before returning a checkpoint digest.'
}
finally { Close-TestScope $digestDriftScope }

$clockUtc = [DateTimeOffset]::FromUnixTimeMilliseconds(1700000000000)
$clockDeadline = $clockUtc.AddSeconds(2).AddTicks(9900)
$clockState = @{
    Counter=[long]100; Utc=$clockUtc.AddTicks(2500); Frequency=[long]1000
    Boot='638982378001234567'; Reads=0; Remaining=$null
}
$sampleClock = {
    $clockState.Reads++
    [pscustomobject]@{
        Counter=$clockState.Counter; Frequency=$clockState.Frequency
        Utc=$clockState.Utc; BootIdentity=$clockState.Boot
    }
}.GetNewClosure()
$clockNonce = New-TestCaseNonce
$clockScope = New-TestScope $clockNonce (New-TestCaseNonce) { $true } $null $clockDeadline $sampleClock
$clockCapture = {
    param($Save, $Remaining, $ReadIntent, $ReadCheckpoint)
    $clockState.Remaining = $Remaining
    Assert-RestorationTest ($Remaining.Invoke() -eq 1.999) 'The raw counter must round down from the exact UTC birth.'
    $null = $ReadIntent.Invoke()
    $Save.Invoke($baselineBytes)
    $null = $ReadCheckpoint.Invoke()
    return ,$baselineBytes
}.GetNewClosure()
try {
    $clockResult = Invoke-TestCapture $clockScope $clockCapture -SyntheticReceiptDigests
    $intentPath = Join-Path $resolvedTestRoot "atlaso-restoration-$clockNonce.intent.json"
    $clockIntent = Get-Content -LiteralPath $intentPath -Raw | ConvertFrom-Json
    $bootDigest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($clockState.Boot))).ToLowerInvariant()
    Assert-RestorationTest ($clockIntent.schema -eq 2 -and $clockIntent.clock.deadline_counter -eq 2099 -and
        $clockIntent.clock.frequency -eq 1000 -and $clockIntent.clock.deadline_utc_ms -eq 1700000002000 -and
        $clockIntent.clock.boot_sha256 -ceq $bootDigest -and
        $clockResult.IntentSha256 -ceq (Get-FileHash -LiteralPath $intentPath).Hash.ToLowerInvariant()) `
        'The frozen boot and deadline must be part of the original intent digest.'
    $beforeStale = $clockState.Reads
    Assert-Throws { $null = $clockState.Remaining.Invoke() } 'The original clock callback expires with its invocation.'
    Assert-RestorationTest ($clockState.Reads -eq $beforeStale) 'A stale callback cannot sample or mutate the clock.'
}
finally { Close-TestScope $clockScope }

foreach ($clockFault in @(
    @{ Key='Counter'; Value=[long]99 }, @{ Key='Utc'; Value=$clockUtc },
    @{ Key='Frequency'; Value=[long]999 }, @{ Key='Boot'; Value='different-boot' },
    @{ Key='Counter'; Value=[long]2099 }, @{ Key='Utc'; Value=$clockUtc.AddSeconds(2) }
)) {
    $scope = New-TestScope (New-TestCaseNonce) (New-TestCaseNonce) { $true } $null $clockDeadline $sampleClock
    $faultState = @{ Rejected=$false; Sticky=$false }
    $faultCapture = {
        param($Save, $Remaining, $ReadIntent, $ReadCheckpoint)
        $null = $ReadIntent.Invoke()
        $Save.Invoke($baselineBytes)
        $old = $clockState[$clockFault.Key]
        try {
            $clockState[$clockFault.Key] = $clockFault.Value
            try { $null = $Remaining.Invoke() }
            catch { $faultState.Rejected = $true }
        }
        finally { $clockState[$clockFault.Key] = $old }
        try { $null = $ReadCheckpoint.Invoke() }
        catch { $faultState.Sticky = $true }
        return ,$baselineBytes
    }.GetNewClosure()
    try {
        Assert-Throws { Invoke-TestCapture $scope $faultCapture -SyntheticReceiptDigests } `
            'A caught clock fault must prevent successful capture.'
        Assert-RestorationTest ($faultState.Rejected -and $faultState.Sticky) 'The original clock refusal must be sticky.'
    }
    finally { Close-TestScope $scope }
}

$verifyClock = { $clockState.Counter = [long]2099; $true }.GetNewClosure()
try {
    Assert-Throws {
        New-TestScope (New-TestCaseNonce) (New-TestCaseNonce) $verifyClock $null $clockDeadline $sampleClock
    } 'The original cap must include time spent in admission.'
}
finally { $clockState.Counter = [long]100 }
Assert-Throws {
    New-TestScope (New-TestCaseNonce) (New-TestCaseNonce) { $true } $null $clockUtc.AddTicks(9000) $sampleClock
} 'The rounded UTC deadline must be after the exact birth sample.'
$clockState.Counter = [long]::MaxValue
try {
    Assert-Throws {
        New-TestScope (New-TestCaseNonce) (New-TestCaseNonce) { $true } $null $clockDeadline $sampleClock
    } 'The absolute counter deadline cannot overflow.'
}
finally { $clockState.Counter = [long]100 }

$nativeClockBinding = Get-TestBinding -Nonce (New-TestCaseNonce) -RunId (New-TestCaseNonce)
$nativeClockScope = & $checkpointModule {
    param($Root, $Identity, $Bound)
    $Bound.host_boot_identity = Get-AtlasoWindowsBootIdentity
    New-RestorationCheckpointTestScope -EvidenceDirectory $Root -EvidenceIdentity $Identity -Binding $Bound `
        -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(30)) -Verify { $true } -SyntheticClock
} $resolvedTestRoot $TestRootIdentity $nativeClockBinding
Close-TestScope $nativeClockScope

$raceNonce = New-TestCaseNonce
$barrier = Join-Path $resolvedTestRoot ("restoration-claim-$raceNonce.release")
$workers = @()
foreach ($run in @('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'cccccccccccccccccccccccccccccccc')) {
    $bindingJson = Get-CanonicalTestJson (Get-TestBinding $raceNonce $run)
    $resultPath = Join-Path $resolvedTestRoot ("restoration-claim-$raceNonce-$run.result.json")
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    foreach ($argument in @('-NoLogo','-NoProfile','-NonInteractive','-File',$PSCommandPath,
        '-TestRoot',$resolvedTestRoot,'-TestRootIdentity',$TestRootIdentity,'-ClaimWorker',
        '-WorkerBindingJson',$bindingJson,'-WorkerStartSignal',$barrier,'-WorkerResultPath',$resultPath)) {
        $process.StartInfo.ArgumentList.Add($argument)
    }
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    if (-not $process.Start()) { throw 'Could not start the restoration claim worker.' }
    $workers += [pscustomobject]@{ Process = $process; Result = $resultPath; Run = $run }
}
[System.IO.File]::WriteAllText($barrier, 'release', [Text.Encoding]::ASCII)
foreach ($worker in $workers) {
    if (-not $worker.Process.WaitForExit(30000)) { throw 'A restoration claim worker exceeded its fixed deadline.' }
    if (-not [System.IO.File]::Exists($worker.Result)) { throw 'A claim worker did not publish its result.' }
}
$workerResults = @($workers | ForEach-Object {
    $record = Get-Content -LiteralPath $_.Result -Raw | ConvertFrom-Json
    [pscustomobject]@{ Outcome = $record.outcome; ExitCode = $_.Process.ExitCode
        HResult = $record.hresult; CaptureStarted = $record.capture_started }
})
$outcomes = @($workerResults | ForEach-Object Outcome)
Assert-RestorationTest (@($outcomes | Where-Object { $_ -ceq 'success' }).Count -eq 1) `
    'Exactly one concurrent receiver attempt should succeed.'
Assert-RestorationTest (@($outcomes | Where-Object { $_ -ceq 'refused' }).Count -eq 1) `
    'The colliding concurrent receiver attempt should refuse.'
Assert-RestorationTest (@($workerResults | Where-Object { $_.Outcome -ceq 'success' -and $_.ExitCode -eq 0 }).Count -eq 1 -and
    @($workerResults | Where-Object { $_.Outcome -ceq 'refused' -and $_.ExitCode -eq 1 -and -not $_.CaptureStarted -and
        $_.HResult -eq 0x800700B7 }).Count -eq 1 -and
    @($workerResults | Where-Object { $_.ExitCode -notin @(0,1) -or $_.Outcome -notin @('success','refused') }).Count -eq 0) `
    'Claim worker result classifications must agree with their actual process exits.'
Assert-RestorationTest ([System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$raceNonce.intent.json"))) `
    'The winning original capture intent remains.'
Assert-RestorationTest ([System.IO.File]::Exists((Join-Path $resolvedTestRoot "atlaso-restoration-$raceNonce.checkpoint.json"))) `
    'The winning checkpoint remains.'
foreach ($worker in $workers) { $worker.Process.Dispose() }

Assert-RestorationTest (@(Get-ChildItem -LiteralPath $resolvedTestRoot -Force | ForEach-Object Name).Count -gt $initialRootEntries.Count) `
    'The focused run should leave its original evidence in the supplied root.'
Write-Output 'Restoration checkpoint focused tests passed; all generated evidence remains under TestRoot.'
