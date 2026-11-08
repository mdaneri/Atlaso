"""Exercise receipt-bound console credential transactions with synthetic Windows inputs."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONSUMER = ROOT / "scripts/windows/vmware/invoke-test-vm-console-credential.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows process boundary")


def _ps(value: str | Path) -> str:
    """Quote a public PowerShell string literal.

    Args:
        value: Public path or fixture value to quote.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _fixture(tmp_path: Path) -> tuple[str, Path, Path, Path]:
    """Prepare a synthetic context and public plan without acquiring credentials.

    Args:
        tmp_path: Pytest-owned ignored directory for all fixture files and receipts.
    """
    evidence = tmp_path / "evidence"
    output = tmp_path / "vm"
    evidence.mkdir()
    output.mkdir()
    screen = tmp_path / "screen.bin"
    python = tmp_path / "venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    screen.write_bytes(b"synthetic empty concealed frame")
    python.write_bytes(b"synthetic interpreter placeholder")
    plan_path = evidence / "plan.json"
    receiver_path = evidence / "receiver.json"
    plan_sha_path = tmp_path / "plan.sha256"
    setup = rf"""
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$repo={_ps(ROOT)}
Import-Module (Join-Path $repo 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $repo 'scripts/windows/vmware/Atlaso.SourceSnapshot.psm1') -Force
. (Join-Path $repo 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
. (Join-Path $repo 'scripts/windows/vmware/Atlaso.TestVmOwnership.ps1')
. (Join-Path $repo 'scripts/windows/vmware/Atlaso.ConsoleCredentialTransaction.ps1')
$evidence={_ps(evidence)}
$output={_ps(output)}
$vmx=Join-Path $output 'synthetic.vmx'
[IO.File]::WriteAllText($vmx,'public synthetic VMX')
$receipt=Join-Path $evidence 'original.json'
[IO.File]::WriteAllText($receipt,'public synthetic original receipt')
$receiptSha=(Get-FileHash -LiteralPath $receipt).Hash.ToLowerInvariant()
$screen={_ps(screen)}
$python={_ps(python)}
$screenSha=(Get-FileHash -LiteralPath $screen).Hash.ToLowerInvariant()
$runtimeSha='b'*64
$runtimeCount=3
$sourceSha=(Get-FileHash -LiteralPath (Join-Path $repo 'scripts/installation/vnc_console.py')).Hash.ToLowerInvariant()
$evidenceId=[Atlaso.WorkstationFileIdentity]::Get($evidence)
$taskId='synthetic-console-transaction'
$commit='a'*40
$script:expectedCommit=$commit
$script:providerMismatch=$false
$persistent='c'*64
$context=[pscustomobject]@{{ Enabled=$true; ContinuationReceiptPath=''; ValidationRootAdmission=$null;
    EvidenceDirectory=$evidence; EvidenceDirectoryId=$evidenceId; Worktree=$repo; SourceCommit=$commit;
    TaskId=$taskId; ReceiptSha256=$receiptSha; ReceiptPath=$receipt; OutputDirectory=$output; VmxPath=$vmx;
    Name='synthetic'; InvocationId=''; Branch='synthetic'; PullRequestNumber=1084 }}
$script:syntheticOriginal=[pscustomobject]@{{ Record=[pscustomobject]@{{
    persistent_vm_identity_sha256=$persistent; original_identities=[pscustomobject]@{{directory='synthetic-directory-id'}} }} }}
function Assert-AtlasoTestVmCheckoutSource {{ param($Context) if($Context.SourceCommit -cne $script:expectedCommit){{throw 'Synthetic source binding changed'}} }}
function Assert-AtlasoTestVmOriginalOwnership {{ param($Context) $script:syntheticOriginal }}
function Get-InstallationVncPeer {{ param($VmxPath,$Port) if($script:providerMismatch){{return ($PID+1)}}; return $PID }}
function Assert-AtlasoSourceSnapshot {{ param($Root,$ExpectedSha256,$ExpectedFileCount) $null }}
function Get-AtlasoWindowsBootIdentity {{ '638000000000000000' }}
$provider=Get-Process -Id $PID
$providerStart=$provider.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
$provider.Dispose()
$run=[guid]::NewGuid().ToString('N')
$nonce=[guid]::NewGuid().ToString('N')
$boot=[guid]::NewGuid().ToString('D')
$deadline=[DateTimeOffset]::UtcNow.AddSeconds(90).ToString('O')
$plan=[ordered]@{{ schema=1; kind='console-credential-transaction-v1'; task_id=$taskId; source_commit=$commit;
    run_id=$run; receiver_nonce=$nonce; guest_boot_id=$boot; host_boot_identity='638000000000000000';
    ownership_receipt_sha256=$receiptSha; persistent_vm_identity_sha256=$persistent; provider_pid=$PID;
    provider_start_filetime_utc=$providerStart; screen_sha256=$screenSha; runtime_sha256=$runtimeSha;
    runtime_file_count=$runtimeCount; account='admin'; port=5901; field_rectangle='10,20,300,40'; deadline_utc=$deadline;
    guest_bundle_sha256=('d'*64); receiver_receipt_path={_ps(receiver_path)}; receiver_receipt_sha256='';
    client_source_sha256=$sourceSha }}
$ready=[ordered]@{{ schema=1; kind='console-concealed-receiver-v1'; task_id=$taskId; source_commit=$commit;
    run_id=$run; receiver_nonce=$nonce; guest_boot_id=$boot; ownership_receipt_sha256=$receiptSha;
    persistent_vm_identity_sha256=$persistent; guest_bundle_sha256=('d'*64); screen_sha256=$screenSha; echo_off=$true }}
$readyJson=$ready | ConvertTo-Json -Depth 5 -Compress
[IO.File]::WriteAllText({_ps(receiver_path)},$readyJson,[Text.UTF8Encoding]::new($false))
$plan.receiver_receipt_sha256=(Get-FileHash -LiteralPath {_ps(receiver_path)}).Hash.ToLowerInvariant()
$options=@{{ Account='admin'; Port=5901; ScreenPath=$screen; ScreenSha256=$screenSha; FieldRectangle='10,20,300,40';
    PythonPath=$python; RuntimeSha256=$runtimeSha; RuntimeFileCount=$runtimeCount }}
"""
    digest_writer = rf"""
$planJson=$plan | ConvertTo-Json -Depth 8 -Compress
[IO.File]::WriteAllText({_ps(plan_path)},$planJson,[Text.UTF8Encoding]::new($false))
$planSha=(Get-FileHash -LiteralPath {_ps(plan_path)}).Hash.ToLowerInvariant()
[IO.File]::WriteAllText({_ps(plan_sha_path)},$planSha,[Text.Encoding]::ASCII)
"""
    return setup + digest_writer, plan_path, receiver_path, plan_sha_path


def _run(script: str, directory: Path, *, timeout: int = 30) -> str:
    """Run a bounded synthetic PowerShell fixture with no credential interface.

    Args:
        script: PowerShell setup and assertions using public synthetic values.
        directory: Pytest-owned fixture directory used as the process working directory.
        timeout: Maximum wall-clock duration for this synthetic process.
    """
    fixture = directory / "parent-fixture.ps1"
    with fixture.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(script)
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(fixture)],
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=directory,
        env={**os.environ, "CODEX_THREAD_ID": "synthetic-console-transaction"},
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_open_valid_plan_and_atomic_intent_publication_is_immutable(tmp_path: Path) -> None:
    """Admit exact public bindings and refuse a second write to the same intent.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and evidence root.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    script = setup + rf"""
$sha=[IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim()
$transaction=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
    -PlanPath {_ps(plan_path)} -PlanSha256 $sha
try {{
    if($transaction.Plan.account -cne 'admin' -or $transaction.Plan.task_id -cne $taskId -or
       $transaction.Plan.receiver_nonce -notmatch '^[0-9a-f]{{32}}$'){{ throw 'Admitted binding differs' }}
    $details=[ordered]@{{ pid=$PID; getprocess_start_utc='synthetic'; start_filetime_utc='123'; cim_creation_utc='synthetic'; parent_pid=1 }}
    $first=Publish-AtlasoConsoleCredentialRecord -Transaction $transaction -Kind intent -Details $details
    $firstBytes=[IO.File]::ReadAllBytes($first.Path)
    $refused=$false
    try {{ $null=Publish-AtlasoConsoleCredentialRecord -Transaction $transaction -Kind intent -Details $details }} catch {{ $refused=$true }}
    if(-not $refused -or [Convert]::ToHexString($firstBytes) -cne [Convert]::ToHexString([IO.File]::ReadAllBytes($first.Path))){{
        throw 'Existing intent was overwritten or replayed'
    }}
    Write-Output 'valid-plan-and-immutable-intent'
}} finally {{ Close-AtlasoConsoleCredentialTransaction -Transaction $transaction }}
"""
    assert "valid-plan-and-immutable-intent" in _run(script, tmp_path)


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "duplicate",
        "nested",
        "wrong-type",
        "private-marker",
        "bad-source",
        "bad-nonce",
        "bad-clock",
        "bad-receipt",
        "bad-address",
    ],
)
def test_invalid_public_plan_refuses_before_transaction_intent(tmp_path: Path, mutation: str) -> None:
    """Reject malformed or mismatched public records before creating an intent.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and evidence root.
        mutation: Public schema or binding defect injected into one fresh fixture.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    script = setup + rf"""
$value=[ordered]@{{}}
foreach($key in $plan.Keys){{ $value.Add($key,$plan[$key]) }}
switch ({_ps(mutation)}) {{
    'unknown' {{ $value.unexpected='public' }}
    'nested' {{ $value.account=@{{ value='admin' }} }}
    'wrong-type' {{ $value.provider_pid='123' }}
    'private-marker' {{ $value.account='DEFAULT_ADMIN_PASSWORD' }}
    'bad-source' {{ $value.source_commit='b'*40 }}
    'bad-nonce' {{ $value.receiver_nonce='not-a-nonce' }}
    'bad-clock' {{ $value.deadline_utc=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('O') }}
    'bad-receipt' {{ $value.receiver_receipt_sha256='0'*64 }}
    'bad-address' {{ $value.receiver_receipt_path=Join-Path $output 'outside-receiver.json' }}
}}
$json=$value | ConvertTo-Json -Depth 8 -Compress
if ({_ps(mutation)} -ceq 'duplicate') {{ $json=$json.Replace('"schema":1,','"schema":1,"schema":1,') }}
[IO.File]::WriteAllText({_ps(plan_path)},$json,[Text.UTF8Encoding]::new($false))
$sha=(Get-FileHash -LiteralPath {_ps(plan_path)}).Hash.ToLowerInvariant()
$failed=$false
try {{ $null=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
    -PlanPath {_ps(plan_path)} -PlanSha256 $sha }} catch {{ $failed=$true }}
if(-not $failed){{ throw 'Malformed or mismatched plan unexpectedly admitted' }}
if(@(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-test-vm-console-credential-intent-*.json').Count -ne 0){{
    throw 'Intent was written before public plan admission'
}}
Write-Output 'invalid-plan-refused-before-intent'
"""
    assert "invalid-plan-refused-before-intent" in _run(script, tmp_path)


@pytest.mark.parametrize("mutation", ["echo-on", "echo-string", "schema-bool", "wrong-boot", "unknown", "duplicate"])
def test_invalid_receiver_receipt_never_claims_transaction(tmp_path: Path, mutation: str) -> None:
    """Require exact concealed-receiver types and bindings before any intent.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and original synthetic receiver record.
        mutation: Receiver type, binding or uniqueness defect to inject.
    """
    setup, plan_path, receiver_path, _ = _fixture(tmp_path)
    script = setup + rf"""
switch({_ps(mutation)}){{
 'echo-on' {{$ready.echo_off=$false}}
 'echo-string' {{$ready.echo_off='true'}}
 'schema-bool' {{$ready.schema=$true}}
 'wrong-boot' {{$ready.guest_boot_id=[guid]::NewGuid().ToString('D')}}
 'unknown' {{$ready.unexpected='public sentinel'}}
}}
$raw=$ready|ConvertTo-Json -Depth 5 -Compress
if({_ps(mutation)} -ceq 'duplicate'){{$raw=$raw.Replace('"echo_off":true','"echo_off":true,"echo_off":true')}}
[IO.File]::WriteAllText({_ps(receiver_path)},$raw,[Text.UTF8Encoding]::new($false))
$plan.receiver_receipt_sha256=(Get-FileHash -LiteralPath {_ps(receiver_path)}).Hash.ToLowerInvariant()
[IO.File]::WriteAllText({_ps(plan_path)},($plan|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
$refused=$false
try{{$null=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 (Get-FileHash -LiteralPath {_ps(plan_path)}).Hash.ToLowerInvariant()}}catch{{$refused=$true}}
if(-not $refused -or @(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-test-vm-console-credential-intent-*.json').Count){{
 throw 'Invalid receiver receipt claimed a transaction'
}}
Write-Output 'invalid-receiver-before-claim'
"""
    assert "invalid-receiver-before-claim" in _run(script, tmp_path)


@pytest.mark.parametrize(("command", "expected"), [("Write-Output 'synthetic child marker'", "succeeded"), ("exit 7", "terminated_failure")])
def test_outer_job_publishes_process_before_resume_and_stop_after_empty(
    tmp_path: Path, command: str, expected: str
) -> None:
    """Bind durable process and stop receipts to an actually empty synthetic child job.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and evidence root.
        command: Public synthetic child action with no credential or VM behavior.
        expected: Expected success or terminated-failure classification.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    marker = tmp_path / "child-resumed.json"
    script = setup + rf"""
$sha=[IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim()
$transaction=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
    -PlanPath {_ps(plan_path)} -PlanSha256 $sha
$childCommand={_ps(command)}
$childProbe="`$process=@(Get-ChildItem -LiteralPath { _ps(tmp_path / 'evidence') } -Filter 'atlaso-test-vm-console-credential-process-*.json'); " +
    "if(`$process.Count -ne 1){{exit 81}}; " +
    "if(@(Get-ChildItem -LiteralPath {_ps(tmp_path / 'evidence')} -Filter 'atlaso-test-vm-console-credential-stop-*.json').Count){{exit 82}}; " +
    "`$original=Get-Content -LiteralPath `$process[0].FullName -Raw | ConvertFrom-Json; if(`$original.details.pid -ne `$PID){{exit 83}}; " +
    "[IO.File]::WriteAllText({_ps(marker)},'process receipt preceded child resume')"
$failure=$null
try {{ $null=Invoke-AtlasoConsoleCredentialTransaction -Transaction $transaction -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoProfile','-NonInteractive','-Command',$childProbe + ';' + $childCommand) }} catch {{ $failure=$_.Exception.Message }}
try {{
    if(-not (Test-Path -LiteralPath {_ps(marker)})){{ throw 'Child resumed without the original process receipt' }}
    if($null -eq $transaction.IntentReceipt -or $null -eq $transaction.ProcessReceipt -or
       $null -eq $transaction.StopReceipt){{ throw 'Original phase receipt missing' }}
    if($transaction.ControllerIdentity.pid -ne $PID -or
       $transaction.IntentReceipt.Path -cne $transaction.Paths.intent -or
       $transaction.IntentReceipt.Sha256 -cne (Get-FileHash -LiteralPath $transaction.Paths.intent).Hash.ToLowerInvariant()){{
        throw 'Original publisher-returned intent selectors were not retained'
    }}
    $processRecord=Get-Content -LiteralPath $transaction.ProcessReceipt.Path -Raw | ConvertFrom-Json
    $stopRecord=Get-Content -LiteralPath $transaction.StopReceipt.Path -Raw | ConvertFrom-Json
    if($processRecord.phase -cne 'console-credential-process' -or $stopRecord.phase -cne 'console-credential-stop' -or
       $stopRecord.details.whole_job_empty -ne $true -or $stopRecord.details.outcome -cne {_ps(expected)} -or
       $stopRecord.details.process_receipt_sha256 -cne $transaction.ProcessReceipt.Sha256){{ throw 'Outer job receipt binding differs' }}
    foreach($key in @('getprocess_start_utc','start_filetime_utc','cim_creation_utc')){{
       if(-not $processRecord.details.$key){{ throw 'Original process creation clock missing' }}
    }}
    if({_ps(expected)} -ceq 'succeeded' -and $failure){{ throw 'Successful synthetic child failed the runner' }}
    if({_ps(expected)} -ceq 'terminated_failure' -and -not $failure){{ throw 'Nonzero synthetic child was not reported failed' }}
    $stopHash=(Get-FileHash -LiteralPath $transaction.StopReceipt.Path).Hash
    $replayFailure=$null
    try {{ $null=Invoke-AtlasoConsoleCredentialTransaction -Transaction $transaction -FilePath 'must-not-start' -ArgumentList @('synthetic') }}
    catch {{ $replayFailure=$_.Exception.Message }}
    if($replayFailure -notmatch 'exists; preserve without replay' -or
       (Get-FileHash -LiteralPath $transaction.StopReceipt.Path).Hash -cne $stopHash){{ throw 'Existing receiver transaction was replayed' }}
    Write-Output 'outer-job-receipt-order-and-outcome'
}} finally {{ Close-AtlasoConsoleCredentialTransaction -Transaction $transaction }}
"""
    assert "outer-job-receipt-order-and-outcome" in _run(script, tmp_path, timeout=35)


def test_manual_child_without_original_job_receipts_refuses_before_sdk_spy(tmp_path: Path) -> None:
    """Refuse a manual child before a synthetic credential-access spy can run.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and evidence root.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    script = setup + rf"""
$sha=[IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim()
$transaction=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
    -PlanPath {_ps(plan_path)} -PlanSha256 $sha
$script:sdkCalled=$false
$refused=$false
try {{
    Assert-AtlasoConsoleCredentialChild -Transaction $transaction
    $script:sdkCalled=$true
}} catch {{ $refused=$true }}
if(-not $refused -or $script:sdkCalled){{ throw 'Manual child reached the credential boundary without original job receipts' }}
Write-Output 'manual-child-refused-before-sdk-spy'
Close-AtlasoConsoleCredentialTransaction -Transaction $transaction
"""
    assert "manual-child-refused-before-sdk-spy" in _run(script, tmp_path)


@pytest.mark.parametrize("changed_binding", ["source", "provider", "persistent-vm"])
def test_changed_source_provider_or_original_vm_refuses_before_sdk_spy(
    tmp_path: Path, changed_binding: str
) -> None:
    """Recheck each original binding before a synthetic credential boundary.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and evidence root.
        changed_binding: Original source, provider, or persistent VM identity changed after admission.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    script = setup + rf"""
$sha=[IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim()
$transaction=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
    -PlanPath {_ps(plan_path)} -PlanSha256 $sha
switch ({_ps(changed_binding)}) {{
    'source' {{ $context.SourceCommit='b'*40 }}
    'provider' {{ $script:providerMismatch=$true }}
    'persistent-vm' {{ $script:syntheticOriginal.Record.persistent_vm_identity_sha256='e'*64 }}
}}
$script:sdkCalled=$false
$refused=$false
try {{
    Assert-AtlasoConsoleTransactionBinding -Transaction $transaction
    $script:sdkCalled=$true
}} catch {{ $refused=$true }}
if(-not $refused -or $script:sdkCalled){{ throw 'Changed original binding reached the credential boundary' }}
Write-Output 'changed-binding-refused-before-sdk-spy'
Close-AtlasoConsoleCredentialTransaction -Transaction $transaction
"""
    assert "changed-binding-refused-before-sdk-spy" in _run(script, tmp_path)


def test_consumer_checks_transaction_child_binding_before_sdk_boundary() -> None:
    """Keep transaction handoff selectors and child guard ahead of credential access.
    """
    source = CONSUMER.read_text(encoding="utf-8")
    assert "'-TransactionPlanPath', $TransactionPlanPath, '-TransactionPlanSha256', $TransactionPlanSha256" in source
    guard = source.index("Assert-AtlasoConsoleCredentialChild -Transaction $transaction")
    credential_boundary = source.index("Get-AtlasoOnePasswordCredentialPair")
    assert guard < credential_boundary


def test_original_contained_child_reaches_only_public_sdk_spy(tmp_path: Path) -> None:
    """Exercise the genuine child handoff and native job check without an SDK.

    Args:
        tmp_path: Pytest-owned ignored fixture directory containing all public synthetic files.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    child_path = tmp_path / "public-child.ps1"
    marker = tmp_path / "public-spy.txt"
    # These explicit endpoint mocks admit synthetic metadata only. The original
    # journal writer, child verifier, process clocks and Windows jobs remain real.
    child = rf"""
$ErrorActionPreference='Stop'
$repo={_ps(ROOT)}
Import-Module (Join-Path $repo 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $repo 'scripts/windows/vmware/Atlaso.SourceSnapshot.psm1') -Force
. (Join-Path $repo 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
. (Join-Path $repo 'scripts/windows/vmware/Atlaso.TestVmOwnership.ps1')
. (Join-Path $repo 'scripts/windows/vmware/Atlaso.ConsoleCredentialTransaction.ps1')
$originalPlan=Get-Content -LiteralPath {_ps(plan_path)} -Raw | ConvertFrom-Json
$context=[pscustomobject]@{{Enabled=$true;ContinuationReceiptPath='';ValidationRootAdmission=$null;
 EvidenceDirectory={_ps(tmp_path / 'evidence')};EvidenceDirectoryId=[Atlaso.WorkstationFileIdentity]::Get({_ps(tmp_path / 'evidence')});
 Worktree=$repo;SourceCommit=('a'*40);TaskId='synthetic-console-transaction';ReceiptSha256=$originalPlan.ownership_receipt_sha256;
 ReceiptPath={_ps(tmp_path / 'evidence' / 'original.json')};OutputDirectory={_ps(tmp_path / 'vm')};
 VmxPath={_ps(tmp_path / 'vm' / 'synthetic.vmx')};Name='synthetic';Branch='synthetic';PullRequestNumber=1084}}
$options=@{{Account='admin';Port=5901;ScreenPath={_ps(tmp_path / 'screen.bin')};ScreenSha256=$originalPlan.screen_sha256;
 FieldRectangle='10,20,300,40';PythonPath={_ps(tmp_path / 'venv' / 'Scripts' / 'python.exe')};
 RuntimeSha256=('b'*64);RuntimeFileCount=3}}
function Assert-AtlasoTestVmCheckoutSource {{param($Context) if($Context.SourceCommit -cne ('a'*40)){{throw 'Synthetic source changed'}}}}
function Assert-AtlasoTestVmOriginalOwnership {{param($Context)
 [pscustomobject]@{{Record=[pscustomobject]@{{persistent_vm_identity_sha256=('c'*64);original_identities=[pscustomobject]@{{directory='synthetic-directory-id'}}}}}}}}
function Get-InstallationVncPeer {{param($VmxPath,$Port) return $originalPlan.provider_pid}}
function Get-AtlasoWindowsBootIdentity {{'638000000000000000'}}
function Assert-AtlasoSourceSnapshot {{param($Root,$ExpectedSha256,$ExpectedFileCount)}}
$tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 ([IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim())
try {{ Assert-AtlasoConsoleCredentialChild -Transaction $tx; [IO.File]::WriteAllText({_ps(marker)},'public spy only') }}
finally {{ Close-AtlasoConsoleCredentialTransaction -Transaction $tx }}
"""
    child_path.write_text(child, encoding="utf-8")
    script = setup + rf"""
$tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 ([IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim())
try {{
 $null=Invoke-AtlasoConsoleCredentialTransaction -Transaction $tx -FilePath (Get-Process -Id $PID).Path `
  -ArgumentList @('-NoProfile','-NonInteractive','-File',{_ps(child_path)})
 if(-not (Test-Path -LiteralPath {_ps(marker)}) -or $null -eq $tx.StopReceipt){{throw 'Original child failed handoff verification'}}
 Write-Output 'original-child-guard-reached-public-spy'
}} finally {{Close-AtlasoConsoleCredentialTransaction -Transaction $tx}}
"""
    assert "original-child-guard-reached-public-spy" in _run(script, tmp_path, timeout=45)


def test_forged_clock_receipts_without_original_job_refuse_before_sdk_spy(tmp_path: Path) -> None:
    """Require actual named-job membership even when public clock fields match.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and synthetic journal.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    script = setup + rf"""
$transaction=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
 -PlanPath {_ps(plan_path)} -PlanSha256 ([IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim())
try {{
 $selfProcess=[Diagnostics.Process]::GetCurrentProcess()
 try {{ $self=Get-AtlasoConsoleProcessCreation -Process $selfProcess }} finally {{ $selfProcess.Dispose() }}
 $parent=Get-Process -Id $self.parent_pid
 try {{ $parentClock=Get-AtlasoConsoleProcessCreation -Process $parent }} finally {{ $parent.Dispose() }}
 $null=Publish-AtlasoConsoleCredentialRecord -Transaction $transaction -Kind intent -Details $parentClock
 $self['job_name']=$transaction.JobName
 $null=Publish-AtlasoConsoleCredentialRecord -Transaction $transaction -Kind process -Details $self
 $failure=$null;$spy=$false
 try {{ Assert-AtlasoConsoleCredentialChild -Transaction $transaction; $spy=$true }} catch {{ $failure=$_.Exception.Message }}
 if($spy -or $failure -notmatch 'original job containment'){{ throw 'Forged public clock records bypassed native job containment' }}
 Write-Output 'forged-clock-without-job-refused'
}} finally {{ Close-AtlasoConsoleCredentialTransaction -Transaction $transaction }}
"""
    assert "forged-clock-without-job-refused" in _run(script, tmp_path)


@pytest.mark.parametrize("defect", ["root", "deadline", "not-empty"])
def test_mismatched_outer_proof_never_publishes_stop(tmp_path: Path, defect: str) -> None:
    """Refuse an injected incorrect callback proof without emitting a stop receipt.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and synthetic journal.
        defect: Wrong root, deadline or missing job-empty proof to inject.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    script = setup + rf"""
$transaction=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
 -PlanPath {_ps(plan_path)} -PlanSha256 ([IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim())
$script:proofDefect={_ps(defect)}
function Invoke-AtlasoBoundedStreamingProcess {{
 param($FilePath,$ArgumentList,$TimeoutSeconds,$Action,$ProcessJobName,$ProcessOwnershipPublisher,
       $ProcessQuiescencePublisher,$DeadlineUtc,[switch]$DiscardOutput)
 $selfProcess=[Diagnostics.Process]::GetCurrentProcess()
 try {{
  & $ProcessOwnershipPublisher ([pscustomobject]@{{RootProcess=$selfProcess}})
  $proof=[pscustomobject]@{{Schema=1;WholeJobEmpty=$true;ProcessJobName=$ProcessJobName;
   RootProcessId=$selfProcess.Id;RootStartTimeUtc=$selfProcess.StartTime.ToUniversalTime().ToString('O');
   DeadlineUtc=$DeadlineUtc.ToUniversalTime().ToString('O');Outcome='succeeded';RootExitCode=0}}
  switch($script:proofDefect){{
   'root' {{$proof.RootProcessId++}}
   'deadline' {{$proof.DeadlineUtc=[DateTimeOffset]::UtcNow.ToString('O')}}
   'not-empty' {{$proof.WholeJobEmpty=$false}}
  }}
  & $ProcessQuiescencePublisher $proof
 }} finally {{ $selfProcess.Dispose() }}
}}
try {{
 $failure=$null
 try {{ $null=Invoke-AtlasoConsoleCredentialTransaction -Transaction $transaction -FilePath 'synthetic' -ArgumentList @('synthetic') }}
 catch {{ $failure=$_.Exception.Message }}
 if($failure -notmatch 'quiescence proof is unavailable' -or (Test-Path -LiteralPath $transaction.Paths.stop)){{
  throw 'Mismatched callback proof produced a stop receipt'
 }}
 Write-Output 'mismatched-stop-proof-refused'
}} finally {{ Close-AtlasoConsoleCredentialTransaction -Transaction $transaction }}
"""
    assert "mismatched-stop-proof-refused" in _run(script, tmp_path)


@pytest.mark.parametrize("refusal", ["runtime", "snapshot", "frame"])
def test_real_consumer_admission_prefix_refuses_before_any_sdk_access(tmp_path: Path, refusal: str) -> None:
    """Execute the real legacy admission statements with public guard failures.

    Args:
        tmp_path: Pytest-owned ignored fixture directory with a public frame and placeholder runtime.
        refusal: Runtime, inventory or frame admission failure injected before credential retrieval.
    """
    setup, _, _, _ = _fixture(tmp_path)
    script = setup + rf"""
$transaction=$null
$worktree=$repo
$PythonPath=$python
$ScreenPath=$screen
$ScreenSha256=if({_ps(refusal)} -ceq 'frame'){{'0'*64}}else{{$screenSha}}
$RuntimeSha256=$runtimeSha
$RuntimeFileCount=$runtimeCount
$commit='a'*40
$script:sdkCalled=$false
$script:failureMode={_ps(refusal)}
function New-AtlasoCertificateInspectorSnapshot {{param($RepositoryRoot,$EvidenceRoot,$SourceCommit,$TaskId,$Purpose)
 [pscustomobject]@{{Root=$repo;Pins=@()}} }}
function Protect-AtlasoCertificatePythonRuntime {{param($PythonPath,$EvidenceRoot,$RequiredModules)
 if($script:failureMode -ceq 'runtime'){{throw 'Synthetic runtime admission refusal'}}
 [pscustomobject]@{{Pins=@()}} }}
function Assert-AtlasoCertificatePythonImportPaths {{param($Runtime)}}
function Assert-AtlasoSourceSnapshot {{param($Root,$ExpectedSha256,$ExpectedFileCount)
 if($script:failureMode -ceq 'snapshot'){{throw 'Synthetic inventory admission refusal'}} }}
# Even if a future edit moves SDK code earlier, these fixed spies cannot access
# an actual Environment, token, credential runtime or private VNC consumer.
function Import-Module {{param($Name,[switch]$Force)}}
function Resolve-AtlasoOnePasswordEnvironmentId {{param($RepositoryRoot) 'synthetic selector'}}
function Resolve-AtlasoOnePasswordServiceAccountTokenFile {{param($RepositoryRoot,$TokenFile) 'synthetic token selector'}}
function Get-AtlasoOnePasswordCredentialPair {{param($RepositoryRoot,$EnvironmentId,$OnePasswordServiceAccountTokenFile,$TimeoutSeconds,$ConsumerDescription)
 $script:sdkCalled=$true;throw 'Synthetic forbidden SDK spy reached' }}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'scripts/windows/vmware/invoke-test-vm-console-credential.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){{throw 'Consumer AST refused'}}
$start=@($ast.FindAll({{param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -ceq '$ownedPrefix'}},$true))
$end=@($ast.FindAll({{param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -ceq 'Get-AtlasoOnePasswordCredentialPair'}},$true))
if($start.Count -ne 1 -or $end.Count -ne 1){{throw 'Consumer admission sequence is ambiguous'}}
$text=[IO.File]::ReadAllText((Join-Path $repo 'scripts/windows/vmware/invoke-test-vm-console-credential.ps1'))
$prefix=$text.Substring($start[0].Extent.StartOffset,$end[0].Extent.EndOffset-$start[0].Extent.StartOffset)
$framePin=$null;$frameDirectoryPin=$null;$failure=$null
try {{ . ([scriptblock]::Create($prefix)) }} catch {{ $failure=$_.Exception.Message }}
finally {{if($framePin){{$framePin.Dispose()}};if($frameDirectoryPin){{$frameDirectoryPin.Dispose()}}}}
if($script:sdkCalled -or -not $failure){{throw 'Real consumer reached SDK access before admission refusal'}}
$expected=@{{runtime='runtime admission refusal';snapshot='inventory admission refusal';frame='Observed console frame differs'}}
if($failure -notmatch $expected[{_ps(refusal)}]){{throw 'Fixture failed before its intended consumer admission guard'}}
Write-Output 'real-consumer-guard-before-sdk'
"""
    assert "real-consumer-guard-before-sdk" in _run(script, tmp_path)


def test_binding_loss_after_root_success_records_failure_and_refuses_success(tmp_path: Path) -> None:
    """Retain empty-job proof while failing closed when final admission is lost.

    Args:
        tmp_path: Pytest-owned ignored fixture directory and original synthetic journal.
    """
    setup, plan_path, _, plan_sha_path = _fixture(tmp_path)
    drift = tmp_path / "synthetic-binding-lost.txt"
    script = setup + rf"""
$script:driftMarker={_ps(drift)}
function Assert-AtlasoTestVmCheckoutSource {{param($Context)
 if($Context.SourceCommit -cne $script:expectedCommit -or (Test-Path -LiteralPath $script:driftMarker)){{throw 'Synthetic admission lost'}}}}
$tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 ([IO.File]::ReadAllText({_ps(plan_sha_path)}).Trim())
try {{
 $failure=$null
 try {{ $null=Invoke-AtlasoConsoleCredentialTransaction -Transaction $tx -FilePath (Get-Process -Id $PID).Path `
  -ArgumentList @('-NoProfile','-NonInteractive','-Command',"[IO.File]::WriteAllText({_ps(drift)},'public drift marker')") }}
 catch {{$failure=$_.Exception}}
 if($null -eq $failure -or $failure.Data['AtlasoConsoleTransactionAdmissionFailed'] -ne $true -or
    $failure.Data['AtlasoProcessTreeTerminationProven'] -ne $true -or $null -eq $tx.StopReceipt){{throw 'Lost admission was accepted as successful'}}
 $stop=Get-Content -LiteralPath $tx.StopReceipt.Path -Raw | ConvertFrom-Json
 if($stop.details.outer_outcome -cne 'succeeded' -or $stop.details.root_exit_code -ne 0 -or
    $stop.details.outcome -cne 'terminated_failure' -or $stop.details.original_binding_rechecked -ne $false -or
    $stop.details.whole_job_empty -ne $true){{throw 'Failed admission erased or relabeled the actual stop facts'}}
 Write-Output 'post-stop-binding-loss-failed-closed'
}} finally {{Close-AtlasoConsoleCredentialTransaction -Transaction $tx}}
"""
    assert "post-stop-binding-loss-failed-closed" in _run(script, tmp_path, timeout=35)


def _v2_fixture(tmp_path: Path) -> tuple[str, Path, Path]:
    """Prepare a new signed-protocol admission using a public test-vector key.

    Args:
        tmp_path: Fresh pytest-owned public fixture namespace.
    """
    setup, plan_path, receiver_path, _ = _fixture(tmp_path)
    setup += rf"""
$taskId='00000000-0000-4000-8000-000000001077'
$context.TaskId=$taskId;$plan.task_id=$taskId;$ready.task_id=$taskId
$plan.schema=2;$plan.kind='console-credential-transaction-v2'
$ready.schema=2;$ready.kind='console-concealed-receiver-v2'
# RFC8032 public test vector only; no private key exists in this fixture.
$plan.stop_ack_public_key_hex='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
$publicKey=[Convert]::FromHexString($plan.stop_ack_public_key_hex)
$fingerprint=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($publicKey)).ToLowerInvariant()
$plan.stop_ack_signing_key_sha256=$fingerprint
$plan.stop_ack_transport_key='guestinfo.atlaso.pr1084.native.stop-ack.'+$run+'.'+$nonce
$ready.stop_ack_signing_key_sha256=$fingerprint;$ready.stop_ack_algorithm='Ed25519'
[IO.File]::WriteAllText({_ps(receiver_path)},($ready|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
$plan.receiver_receipt_sha256=(Get-FileHash -LiteralPath {_ps(receiver_path)}).Hash.ToLowerInvariant()
[IO.File]::WriteAllText({_ps(plan_path)},($plan|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
$planSha=(Get-FileHash -LiteralPath {_ps(plan_path)}).Hash.ToLowerInvariant()
"""
    return setup, plan_path, receiver_path


def test_explicit_v2_admission_binds_public_key_and_receiver_without_execution(tmp_path: Path) -> None:
    """Admit a separate original v2 definition without creating any journal phase.

    Args:
        tmp_path: Fresh public admission fixtures, not native receipts.
    """
    setup, plan_path, _ = _v2_fixture(tmp_path)
    script = setup + rf"""
$tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 $planSha -ProtocolVersion 2
try {{
 if($tx.ProtocolVersion -ne 2 -or $tx.Binding.schema -ne 2 -or
    $tx.PlanReceipt.Path -cne {_ps(plan_path)} -or $tx.PlanReceipt.Sha256 -cne $planSha -or
    $tx.Binding.stop_ack_signing_key_sha256 -cne $fingerprint -or
    $tx.Binding.stop_ack_public_key_hex -cne $plan.stop_ack_public_key_hex -or
    $tx.Binding.stop_ack_transport_key -cne ('guestinfo.atlaso.pr1084.native.stop-ack.'+$run+'.'+$nonce)){{
  throw 'Signed protocol admission did not bind the independently pinned key'
 }}
 if($tx.IntentReceipt -or $tx.ProcessReceipt -or $tx.StopReceipt -or
    @(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-test-vm-console-credential-*.json').Count){{
  throw 'Admission definition unexpectedly claimed or executed a transaction'
 }}
 Write-Output 'v2-admission-only-no-execution'
}} finally {{Close-AtlasoConsoleCredentialTransaction -Transaction $tx}}
"""
    assert "v2-admission-only-no-execution" in _run(script, tmp_path)


@pytest.mark.parametrize("direction", ["v2-with-default-v1", "v1-with-explicit-v2"])
def test_protocol_versions_never_upgrade_or_adopt_old_receipts(tmp_path: Path, direction: str) -> None:
    """An explicit version mismatch refuses before any transaction is claimed.

    Args:
        tmp_path: Fresh version-specific original fixture files.
        direction: Schema-adoption direction to reject.
    """
    if direction == "v2-with-default-v1":
        setup, plan_path, _ = _v2_fixture(tmp_path)
        version = ""
    else:
        setup, plan_path, _, _ = _fixture(tmp_path)
        setup += "$planSha=(Get-FileHash -LiteralPath " + _ps(plan_path) + ").Hash.ToLowerInvariant()\n"
        version = "-ProtocolVersion 2"
    script = setup + rf"""
$refused=$false
try {{$null=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 $planSha {version}}} catch {{$refused=$true}}
if(-not $refused -or @(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-test-vm-console-credential-*.json').Count){{
 throw 'A different protocol version was adopted or claimed'
}}
Write-Output 'version-adoption-refused'
"""
    assert "version-adoption-refused" in _run(script, tmp_path)


@pytest.mark.parametrize("defect", [
    "key-uppercase", "key-length", "key-type", "key-hash", "fingerprint-type", "replayed-key",
    "plan-version", "plan-kind", "receiver-version", "receiver-kind", "receiver-key", "algorithm",
    "algorithm-type", "receiver-key-type", "receiver-duplicate", "receiver-extra",
])
def test_v2_key_and_receiver_admission_refuse_before_claim(tmp_path: Path, defect: str) -> None:
    """Reject wrong pins, schemas, algorithms and namespaces before publication.

    Args:
        tmp_path: Fresh synthetic public v2 admission files.
        defect: Exact defect injected before the module reads its original digest.
    """
    setup, plan_path, receiver_path = _v2_fixture(tmp_path)
    script = setup + rf"""
switch({_ps(defect)}){{
 'key-uppercase' {{$plan.stop_ack_public_key_hex=$plan.stop_ack_public_key_hex.ToUpperInvariant()}}
 'key-length' {{$plan.stop_ack_public_key_hex='a'*62}}
 'key-type' {{$plan.stop_ack_public_key_hex=$true}}
 'key-hash' {{$plan.stop_ack_signing_key_sha256='0'*64}}
 'fingerprint-type' {{$plan.stop_ack_signing_key_sha256=123}}
 'replayed-key' {{$plan.stop_ack_transport_key='guestinfo.atlaso.pr1084.native.stop-ack.'+$run+'.'+('0'*32)}}
 'plan-version' {{$plan.schema=1}}
 'plan-kind' {{$plan.kind='console-credential-transaction-v1'}}
 'receiver-version' {{$ready.schema=1}}
 'receiver-kind' {{$ready.kind='console-concealed-receiver-v1'}}
 'receiver-key' {{$ready.stop_ack_signing_key_sha256='0'*64}}
 'algorithm' {{$ready.stop_ack_algorithm='none'}}
 'algorithm-type' {{$ready.stop_ack_algorithm=@{{value='Ed25519'}}}}
 'receiver-key-type' {{$ready.stop_ack_signing_key_sha256=$true}}
 'receiver-extra' {{$ready.channel_key='untrusted public key'}}
}}
$json=$ready|ConvertTo-Json -Depth 5 -Compress
if({_ps(defect)} -ceq 'receiver-duplicate'){{$json=$json.Replace('"schema":2,','"schema":2,"schema":2,')}}
[IO.File]::WriteAllText({_ps(receiver_path)},$json,[Text.UTF8Encoding]::new($false))
$plan.receiver_receipt_sha256=(Get-FileHash -LiteralPath {_ps(receiver_path)}).Hash.ToLowerInvariant()
[IO.File]::WriteAllText({_ps(plan_path)},($plan|ConvertTo-Json -Depth 5 -Compress),[Text.UTF8Encoding]::new($false))
$sha=(Get-FileHash -LiteralPath {_ps(plan_path)}).Hash.ToLowerInvariant()
$refused=$false
try {{$null=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 $sha -ProtocolVersion 2}} catch {{$refused=$true}}
if(-not $refused -or @(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-test-vm-console-credential-*.json').Count){{
 throw 'Invalid signed protocol admission reached a transaction claim'
}}
Write-Output 'invalid-v2-admission-refused'
"""
    assert "invalid-v2-admission-refused" in _run(script, tmp_path)


def test_closed_v2_transaction_cannot_claim_or_reopen_historical_pins(tmp_path: Path) -> None:
    """Closing admission ends its live authority even if record bytes still exist.

    Args:
        tmp_path: Fresh public versioned admission fixture.
    """
    setup, plan_path, _ = _v2_fixture(tmp_path)
    script = setup + rf"""
$tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 $planSha -ProtocolVersion 2
Close-AtlasoConsoleCredentialTransaction -Transaction $tx
Close-AtlasoConsoleCredentialTransaction -Transaction $tx
$publicationRefused=$false
try {{$null=Publish-AtlasoConsoleCredentialRecord -Transaction $tx -Kind intent -Details ([ordered]@{{pid=$PID}})}}
catch {{$publicationRefused=$true}}
$refused=$false
try {{$null=Invoke-AtlasoConsoleCredentialTransaction -Transaction $tx -FilePath (Get-Process -Id $PID).Path `
 -ArgumentList @('-NoProfile','-NonInteractive','-Command','exit 0')}} catch {{$refused=$true}}
if(-not $tx.IsClosed -or -not $refused -or -not $publicationRefused -or
 @(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-test-vm-console-credential-*.json').Count){{
 throw 'Closed transaction was reused as live authority'
}}
Write-Output 'closed-v2-authority-refused'
"""
    assert "closed-v2-authority-refused" in _run(script, tmp_path)
