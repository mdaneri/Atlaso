"""Real Windows invocation/receipt boundaries with explicit synthetic VM endpoints."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.test_console_credential_transaction import _ps, _run, _v2_fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.interop.certificate_dual_stack_guest import GuestRefusal  # noqa: E402 - Local checked-in module.
from scripts.interop.certificate_dual_stack_stop import verify_stop_ack  # noqa: E402 - Local checked-in module.

pytestmark = pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows process boundary")
PUBLIC_VECTOR = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def _chain_fixture(tmp_path: Path, *, exit_code: int = 0) -> str:
    """Complete a real bounded fake child with source/VM/provider endpoints mocked.

    Args:
        tmp_path: Fresh pytest-owned public fixture namespace.
        exit_code: Original fake child's actual terminal result.
    """
    setup, plan_path, _ = _v2_fixture(tmp_path, disable_name_checking=True)
    return setup + rf"""
# Explicit synthetic source context; this read handle exercises retention only,
# and is never presented as admission of the real checkout or a native VM.
$sourceHolder=[pscustomobject]@{{Disposed=$false;Pins=[Collections.Generic.List[object]]::new()}}
$sourceHolder.Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($receipt,$true))
$context|Add-Member CheckoutSourcePin $sourceHolder
$tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 $planSha -ProtocolVersion 2
$invokeFailure=$null
try {{$null=Invoke-AtlasoConsoleCredentialTransaction -Transaction $tx -FilePath (Get-Process -Id $PID).Path `
 -ArgumentList @('-NoProfile','-NonInteractive','-Command','exit {exit_code}')}} catch {{$invokeFailure=$_}}
if(({exit_code} -eq 0 -and $invokeFailure) -or ({exit_code} -ne 0 -and -not $invokeFailure) -or
 $null -eq $tx.StopReceipt){{throw 'Actual fake-child transaction did not reach its intended terminal result'}}
"""


def _close_fixture() -> str:
    """Dispose only fixture-owned read pins, retaining all public files."""
    return r"""
Close-AtlasoConsoleCredentialTransaction -Transaction $tx
foreach($pin in $sourceHolder.Pins){$pin.Dispose()};$sourceHolder.Pins.Clear();$sourceHolder.Disposed=$true
"""


@pytest.mark.parametrize("exit_code", [0, 17])
def test_actual_original_chain_prepares_only_unsigned_contract(tmp_path: Path, exit_code: int) -> None:
    """Match the cross-language contract while preserving actual success/failure.

    Args:
        tmp_path: Owned public fixture files and real Windows receipts.
        exit_code: Original real fake-child exit under a native Windows job.
    """
    script = _chain_fixture(tmp_path, exit_code=exit_code) + r"""
try {
 $before=$tx.Pins.Count
 $verified=Get-AtlasoVerifiedConsoleCredentialStop -Transaction $tx
 if($verified.Root.parent_pid -ne $PID -or $verified.Controller.pid -ne $PID -or $tx.Pins.Count -le $before){
  throw 'Original controller/root relationship or transferred pins differ'
 }
 # Verification may observe only the live controller, never reconstruct an exited root.
 $realClock=${function:Get-AtlasoConsoleProcessCreation}
 function Get-AtlasoConsoleProcessCreation {param($Process)
  if($Process.Id -ne $PID){throw 'Exited root was re-queried'}
  & $realClock -Process $Process
 }
 $prepared=Prepare-AtlasoConsoleCredentialStopAck -Transaction $tx
 if($prepared.status -cne 'prepared_unsigned_no_ack' -or $prepared.unsigned_envelope.Contains('signature_hex') -or
    $prepared.ack_intent_receipt.Path -cne $tx.Paths['ack-intent']){throw 'Unsigned preparation granted another phase'}
 $hash=(Get-FileHash -LiteralPath $tx.Paths['ack-intent']).Hash.ToLowerInvariant()
 if($hash -cne $prepared.ack_intent_receipt.Sha256){throw 'Original ACK intent digest differs'}
 $ack=Read-AtlasoConsoleTransactionRecord -Context $context -Path $prepared.ack_intent_receipt.Path `
  -Sha256 $hash -Keys @('schema','phase','binding','observed_utc','details')
 try {
  if($ack.Value.phase -cne 'console-credential-ack-intent' -or $ack.Value.details.Contains('ack_intent_sha256') -or
   $ack.Value.details.stop_receipt_sha256 -cne $tx.StopReceipt.Sha256){throw 'ACK intent adopted a self-hash or wrong stop'}
 }finally{foreach($pin in $ack.Pins){$pin.Dispose()}}
 $tx.Plan.run_id=[guid]::NewGuid().ToString('N')
 $refused=$false;try{$null=Prepare-AtlasoConsoleCredentialStopAck -Transaction $tx}catch{$refused=$true}
 if(-not $refused -or (Get-FileHash -LiteralPath $tx.Paths['ack-intent']).Hash.ToLowerInvariant() -cne $hash){
  throw 'ACK preparation replayed under another run'
 }
 $tx.Plan.run_id=$run
 [ordered]@{prepared=$prepared;plan=$plan;plan_sha256=$planSha;root=$verified.Root;original_receipt_sha256=$receiptSha;
  process_sha256=$tx.ProcessReceipt.Sha256;stop_sha256=$tx.StopReceipt.Sha256}|ConvertTo-Json -Depth 12 -Compress
}finally{
""" + _close_fixture() + "}\n"
    data = json.loads(_run(script, tmp_path, timeout=60))
    prepared, plan = data["prepared"], data["plan"]
    unsigned = prepared["unsigned_envelope"]
    payload = unsigned["payload"]
    assert payload["outcome"] == ("succeeded" if exit_code == 0 else "terminated_failure")
    assert payload["root_exit_code"] == exit_code
    assert payload["whole_job_empty"] is True
    deadline = datetime.fromisoformat(plan["deadline_utc"]) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    expected = {
        "task_id": plan["task_id"], "source_commit": plan["source_commit"],
        "bundle_sha256": plan["guest_bundle_sha256"], "run_id": plan["run_id"],
        "receiver_nonce": plan["receiver_nonce"], "guest_boot_id": plan["guest_boot_id"],
        "host_boot_identity": plan["host_boot_identity"],
        "original_vm_receipt_sha256": data["original_receipt_sha256"],
        "persistent_vm_identity_sha256": plan["persistent_vm_identity_sha256"],
        "plan_sha256": data["plan_sha256"],
        "receiver_receipt_sha256": plan["receiver_receipt_sha256"],
        "process_receipt_sha256": data["process_sha256"], "stop_receipt_sha256": data["stop_sha256"],
        "ack_intent_sha256": prepared["ack_intent_receipt"]["Sha256"],
        "transport_key": f"guestinfo.atlaso.pr1084.native.stop-ack.{plan['run_id']}.{plan['receiver_nonce']}",
        "deadline_unix_ms": (deadline.days * 86_400 + deadline.seconds) * 1_000 + deadline.microseconds // 1_000,
        "root_pid": data["root"]["pid"], "root_start_filetime_utc": data["root"]["start_filetime_utc"],
    }
    # There is no signer: a forged zero signature must reach signature rejection,
    # proving the exact canonical envelope/fact schema agrees with the verifier.
    raw = json.dumps({**unsigned, "signature_hex": "0" * 128}, ensure_ascii=True,
                     allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(GuestRefusal, match="stop_ack_signature_invalid"):
        verify_stop_ack(raw, public_key_hex=PUBLIC_VECTOR,
                        signing_key_sha256=hashlib.sha256(bytes.fromhex(PUBLIC_VECTOR)).hexdigest(),
                        expected_binding=expected, now_unix_ms=expected["deadline_unix_ms"] - 1)


@pytest.mark.parametrize("kind", ["copied", "reopened"])
def test_identical_receipts_do_not_transfer_live_reference_authority(tmp_path: Path, kind: str) -> None:
    """A copied object or separately opened original plan cannot adopt completion.

    Args:
        tmp_path: Owned original fixtures and real bounded fake-child receipts.
        kind: A distinct transaction reference with equivalent public metadata.
    """
    script = _chain_fixture(tmp_path) + rf"""
$candidate=$null
try {{
 if({_ps(kind)} -ceq 'copied'){{$candidate=$tx.PSObject.Copy()}}
 else {{$candidate=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options `
  -PlanPath $tx.PlanReceipt.Path -PlanSha256 $tx.PlanReceipt.Sha256 -ProtocolVersion 2}}
 $refused=$false;try{{$null=Get-AtlasoVerifiedConsoleCredentialStop -Transaction $candidate}}catch{{$refused=$true}}
 if(-not $refused){{throw 'A distinct object adopted original completion'}}
 if({_ps(kind)} -ceq 'reopened'){{Close-AtlasoConsoleCredentialTransaction -Transaction $candidate}}
 $null=Get-AtlasoVerifiedConsoleCredentialStop -Transaction $tx
 Write-Output 'reference-authority-not-transferable'
}}finally{{
""" + _close_fixture() + "}\n"
    assert "reference-authority-not-transferable" in _run(script, tmp_path, timeout=60)


@pytest.mark.parametrize("defect", [
    "plan-selector", "intent-selector", "process-selector", "stop-selector", "root-cache", "controller-cache",
    "binding", "options", "context", "phase-path", "deadline-renewal", "source-pin-replaced", "source-pin-disposed",
    "source-drift", "provider-drift", "vm-drift", "closed",
])
def test_live_original_chain_refuses_drift_without_ack_publication(tmp_path: Path, defect: str) -> None:
    """Reject selector, process, pin or fresh endpoint drift before any ACK intent.

    Args:
        tmp_path: Fresh public original chain fixture.
        defect: Exact post-completion defect before verification.
    """
    script = _chain_fixture(tmp_path) + rf"""
try {{
 switch({_ps(defect)}){{
  'plan-selector' {{$tx.PlanReceipt.Sha256='0'*64}}
  'intent-selector' {{$tx.IntentReceipt.Sha256='0'*64}}
  'process-selector' {{$tx.ProcessReceipt.Path=$tx.PlanReceipt.Path}}
  'stop-selector' {{$tx.StopReceipt.Sha256='0'*64}}
  'root-cache' {{$tx.RootIdentity.pid+=1}}
  'controller-cache' {{$tx.ControllerIdentity.pid+=1}}
  'binding' {{$tx.Binding.stop_ack_signing_key_sha256='0'*64}}
  'options' {{$options.FieldRectangle='11,20,300,40'}}
  'context' {{$context.EvidenceDirectoryId='replacement-identity'}}
  'phase-path' {{$tx.Paths.stop=$tx.PlanReceipt.Path}}
  'deadline-renewal' {{$tx.Deadline=$tx.Deadline.AddSeconds(1)}}
  'source-pin-replaced' {{$context.CheckoutSourcePin=$sourceHolder.PSObject.Copy()}}
  'source-pin-disposed' {{$sourceHolder.Disposed=$true}}
  'source-drift' {{$script:expectedCommit='b'*40}}
  'provider-drift' {{$script:providerMismatch=$true}}
  'vm-drift' {{$script:syntheticOriginal.Record.persistent_vm_identity_sha256='e'*64}}
  'closed' {{Close-AtlasoConsoleCredentialTransaction -Transaction $tx}}
 }}
 $refused=$false;try{{$null=Get-AtlasoVerifiedConsoleCredentialStop -Transaction $tx}}catch{{$refused=$true}}
 if(-not $refused -or (Test-Path -LiteralPath $tx.Paths['ack-intent'])){{throw 'Drift supplied ACK authority'}}
 Write-Output 'live-chain-drift-refused'
}}finally{{
""" + _close_fixture() + "}\n"
    assert "live-chain-drift-refused" in _run(script, tmp_path, timeout=60)


def test_standalone_stopped_fields_and_direct_ack_publication_cannot_claim_authority(tmp_path: Path) -> None:
    """Caller-provided success and job-empty fields are not an outer callback.

    Args:
        tmp_path: Owned uninvoked public v2 fixture.
    """
    setup, plan_path, _ = _v2_fixture(tmp_path)
    script = setup + rf"""
$tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $options -PlanPath {_ps(plan_path)} `
 -PlanSha256 $planSha -ProtocolVersion 2
try {{
 $tx.StopOutcome='succeeded';$tx.StopReceipt=[pscustomobject]@{{Path={_ps(plan_path)};Sha256=$planSha}}
 $getter=$false;$publisher=$false;$prepare=$false
 try{{$null=Get-AtlasoVerifiedConsoleCredentialStop -Transaction $tx}}catch{{$getter=$true}}
 try{{$null=Publish-AtlasoConsoleCredentialRecord -Transaction $tx -Kind ack-intent `
  -Details ([ordered]@{{whole_job_empty=$true;outcome='succeeded'}})}}catch{{$publisher=$true}}
 try{{$null=Prepare-AtlasoConsoleCredentialStopAck -Transaction $tx}}catch{{$prepare=$true}}
 if(-not $getter -or -not $publisher -or -not $prepare -or (Test-Path -LiteralPath $tx.Paths['ack-intent'])){{
  throw 'Standalone facts supplied completion authority'
 }}
 Write-Output 'standalone-stop-facts-refused'
}}finally{{Close-AtlasoConsoleCredentialTransaction -Transaction $tx}}
"""
    assert "standalone-stop-facts-refused" in _run(script, tmp_path)


@pytest.mark.parametrize("mode", ["publication-uncertain", "post-publication-drift"])
def test_ack_preparation_failure_preserves_one_shot_state_and_original_intent(tmp_path: Path, mode: str) -> None:
    """A failed or uncertain publication never retries or yields signed output.

    Args:
        tmp_path: Owned original chain and evidence directory.
        mode: Publication uncertainty or admission loss after actual publication.
    """
    script = _chain_fixture(tmp_path) + rf"""
$originalPublisher=${{function:Publish-AtlasoTestVmOwnershipRecord}}
$script:ackCalls=0
function Publish-AtlasoTestVmOwnershipRecord {{param($Context,$Record,$Kind)
 if($Kind -ceq 'console-credential-ack-intent'){{
  $script:ackCalls+=1
  if({_ps(mode)} -ceq 'publication-uncertain'){{throw 'Synthetic unknown publication result'}}
  $result=& $originalPublisher -Context $Context -Record $Record -Kind $Kind
  $options.FieldRectangle='11,20,300,40'
  return $result
 }}
 & $originalPublisher -Context $Context -Record $Record -Kind $Kind
}}
try {{
 $result=$null;$failed=$false
 try{{$result=Prepare-AtlasoConsoleCredentialStopAck -Transaction $tx}}catch{{$failed=$true}}
 if(-not $failed -or $null -ne $result -or $script:ackCalls -ne 1){{throw 'Failed preparation returned output or retried'}}
 $exists=Test-Path -LiteralPath $tx.Paths['ack-intent']
 if($exists -ne ({_ps(mode)} -ceq 'post-publication-drift')){{throw 'Original publication facts were relabeled'}}
 $hash=if($exists){{(Get-FileHash -LiteralPath $tx.Paths['ack-intent']).Hash}}else{{''}}
 $options.FieldRectangle='10,20,300,40'
 $again=$false;try{{$null=Prepare-AtlasoConsoleCredentialStopAck -Transaction $tx}}catch{{$again=$true}}
 if(-not $again -or $script:ackCalls -ne 1 -or
  ($exists -and (Get-FileHash -LiteralPath $tx.Paths['ack-intent']).Hash -cne $hash)){{throw 'Failed preparation was replayed'}}
 Write-Output 'one-shot-failure-preserved'
}}finally{{
""" + _close_fixture() + "}\n"
    assert "one-shot-failure-preserved" in _run(script, tmp_path, timeout=60)
