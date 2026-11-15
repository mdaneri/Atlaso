"""Real signer jobs and child guards with explicit synthetic VM/source endpoints."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from tests.test_console_credential_stop_chain import _chain_fixture, _close_fixture
from tests.test_console_credential_transaction import ROOT, _ps, _run

pytestmark = pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows process boundary")


def _signer_fixture(tmp_path: Path) -> str:
    """Prepare original request custody and a child with explicit synthetic endpoints.

    Args:
        tmp_path: Fresh owned fixture namespace beneath the admitted validation root.
    """
    child = tmp_path / "synthetic-signer-child.ps1"
    state = tmp_path / "synthetic-signer-state.json"
    child.write_text(r"""param($Fixture,$RequestPath,$RequestSha256)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$f=Get-Content -LiteralPath $Fixture -Raw | ConvertFrom-Json -AsHashtable
Import-Module (Join-Path $f.repo 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $f.repo 'scripts/windows/vmware/Atlaso.SourceSnapshot.psm1') -Force -DisableNameChecking
. (Join-Path $f.repo 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
. (Join-Path $f.repo 'scripts/windows/vmware/Atlaso.TestVmOwnership.ps1')
. (Join-Path $f.repo 'scripts/windows/vmware/Atlaso.ConsoleCredentialTransaction.ps1')
$context=[pscustomobject]$f.context
$context|Add-Member CheckoutSourcePin ([pscustomobject]@{Disposed=$false;Pins=[Collections.Generic.List[object]]::new()})
$context.CheckoutSourcePin.Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($context.ReceiptPath,$true))
# Only VM/source/provider/runtime interfaces are synthetic. Native process
# clocks, immutable file readers, job membership and the child guard are real.
function Assert-AtlasoTestVmCheckoutSource {param($Context)
 if($Context.SourceCommit -cne $f.context.SourceCommit){throw 'Synthetic source changed'}
}
function Assert-AtlasoTestVmOriginalOwnership {param($Context)
 [pscustomobject]@{Record=[pscustomobject]@{persistent_vm_identity_sha256=$f.persistent;
 original_identities=[pscustomobject]@{directory='synthetic-directory-id'}}}
}
function Get-InstallationVncPeer {param($VmxPath,$Port) $f.provider_pid}
function Assert-AtlasoSourceSnapshot {param($Root,$ExpectedSha256,$ExpectedFileCount) $null}
function Get-AtlasoWindowsBootIdentity {'638000000000000000'}
$tx=$null
try {
 $tx=Open-AtlasoConsoleCredentialTransaction -Context $context -Options $f.options -PlanPath $f.plan_path `
  -PlanSha256 $f.plan_sha256 -ProtocolVersion 2
 Assert-AtlasoConsoleStopSignerChild -Transaction $tx -RequestPath $RequestPath -RequestSha256 $RequestSha256 `
  -EntryPoint (Join-Path $f.repo 'scripts/windows/vmware/invoke-console-stop-signer-child.ps1')
}catch{[IO.File]::WriteAllText($Fixture+'.failure',($_|Out-String));exit 77}
finally{
 Close-AtlasoConsoleCredentialTransaction -Transaction $tx
 foreach($pin in $context.CheckoutSourcePin.Pins){$pin.Dispose()}
}
# Dedicated no-backend refusal is reachable only after the actual child guard.
exit 78
""", encoding="utf-8", newline="\n")
    return _chain_fixture(tmp_path) + rf"""
$prepared=Prepare-AtlasoConsoleCredentialStopAck -Transaction $tx
$request=New-AtlasoConsoleStopSigningRequest -Transaction $tx
$snapshot=Get-AtlasoConsoleSelectorSnapshot -Transaction $tx | ConvertFrom-Json -AsHashtable
[ordered]@{{repo=$repo;context=$snapshot.context;options=$snapshot.options;persistent=$persistent;provider_pid=$PID;
 plan_path=$tx.PlanReceipt.Path;plan_sha256=$tx.PlanReceipt.Sha256}}|ConvertTo-Json -Depth 8 -Compress|
 Set-Content -LiteralPath {_ps(state)} -Encoding utf8NoBOM -NoNewline
$realLaunch=${{function:Get-AtlasoConsoleStopSignerLaunch}}
# Explicit synthetic launch seam: exercise the committed guard in a real child
# without pretending that the production ownership/bootstrap CLI was admitted.
function Get-AtlasoConsoleStopSignerLaunch {{param($Transaction,$RequestPath,$RequestSha256)
 $original=& $realLaunch -Transaction $Transaction -RequestPath $RequestPath -RequestSha256 $RequestSha256
 $original.Arguments=@('-NoProfile','-NonInteractive','-File',{_ps(child)},'-Fixture',{_ps(state)},
  '-RequestPath',$RequestPath,'-RequestSha256',$RequestSha256)
 $original
}}
$signerProcess=Join-Path $evidence ('atlaso-test-vm-console-credential-signer-process-'+$nonce+'.json')
$signerStop=Join-Path $evidence ('atlaso-test-vm-console-credential-signer-stop-'+$nonce+'.json')
"""


def test_distinct_real_signer_job_reaches_only_fixed_backend_refusal(tmp_path: Path) -> None:
    """Prove successful child admission reaches 78, with actual failed whole-job closeout.

    Args:
        tmp_path: Original synthetic request, process and stop receipts.
    """
    script = _signer_fixture(tmp_path) + r"""
try {
 # Returned projections cannot choose child bytes, key, original deadline or request.
 $request.signing_intent_receipt.Sha256='0'*64
 $request.unsigned_canonical_ascii='caller-replacement'
 $failed=$false;try{$null=Invoke-AtlasoConsoleStopSigner -Transaction $tx}catch{$failed=$true}
 if(-not $failed -or -not (Test-Path -LiteralPath $signerStop)){throw 'Refusing signer omitted terminal proof'}
 $pr=Read-AtlasoConsoleTransactionRecord -Context $context -Path $signerProcess `
  -Sha256 (Get-FileHash -LiteralPath $signerProcess).Hash.ToLowerInvariant() -Keys @('schema','phase','binding','observed_utc','details')
 $sr=Read-AtlasoConsoleTransactionRecord -Context $context -Path $signerStop `
  -Sha256 (Get-FileHash -LiteralPath $signerStop).Hash.ToLowerInvariant() -Keys @('schema','phase','binding','observed_utc','details')
 $p=$pr.Value; $s=$sr.Value
 foreach($pin in $pr.Pins){$pin.Dispose()};foreach($pin in $sr.Pins){$pin.Dispose()}
 if($p.details.root.pid -eq $tx.RootIdentity.pid -or $p.details.root.parent_pid -ne $PID -or
  $p.details.root.job_name -cne ('Local\Atlaso-ConsoleStopSigner-'+$nonce) -or
  $s.details.root_exit_code -ne 78 -or -not $s.details.whole_job_empty -or
  $s.details.outcome -cne 'terminated_failure' -or $s.details.outer_outcome -cne 'terminated_failure' -or
  -not $s.details.original_binding_rechecked -or $s.details.backend -cne 'unavailable' -or $tx.Paths.Count -ne 4 -or
  $s.details.getprocess_start_utc -isnot [string] -or $s.details.getprocess_start_utc -cne $p.details.root.getprocess_start_utc){
  throw 'Signer guard did not reach its dedicated no-backend refusal under the distinct native job'
 }
 $hash=(Get-FileHash -LiteralPath $signerStop).Hash
 $again=$false;try{$null=Invoke-AtlasoConsoleStopSigner -Transaction $tx}catch{$again=$true}
 if(-not $again -or (Get-FileHash -LiteralPath $signerStop).Hash -cne $hash){throw 'Consumed signer invocation replayed'}
 [ordered]@{process=$p;stop=$s}|ConvertTo-Json -Depth 12 -Compress
}finally{
""" + _close_fixture() + "}\n"
    data = json.loads(_run(script, tmp_path, timeout=90))
    assert data["stop"]["details"]["root_exit_code"] == 78
    assert data["process"]["details"]["root"]["pid"] != data["process"]["details"]["controller"]["pid"]


@pytest.mark.parametrize("defect", ["copied", "closed", "source", "deadline", "existing-process", "existing-stop"])
def test_signer_parent_refuses_before_launch_and_consumes_uncertainty(tmp_path: Path, defect: str) -> None:
    """Reject invalid original authority or preexisting phase namespaces before a child.

    Args:
        tmp_path: Fresh original synthetic chain and successful request custody.
        defect: Exact authority or namespace defect before signer invocation.
    """
    script = _signer_fixture(tmp_path) + rf"""
$candidate=$tx
try {{
 switch({_ps(defect)}){{
  'copied' {{$candidate=$tx.PSObject.Copy()}}
  'closed' {{Close-AtlasoConsoleCredentialTransaction -Transaction $tx}}
  'source' {{$script:expectedCommit='b'*40}}
  'deadline' {{$tx.Deadline=$tx.Deadline.AddSeconds(1)}}
  'existing-process' {{[IO.File]::WriteAllText($signerProcess,'preserved-original')}}
  'existing-stop' {{[IO.File]::WriteAllText($signerStop,'preserved-original')}}
 }}
 $script:launches=0
 function Get-AtlasoConsoleStopSignerLaunch {{param($Transaction,$RequestPath,$RequestSha256) $script:launches++;throw 'Must not launch'}}
 $failed=$false;try{{$null=Invoke-AtlasoConsoleStopSigner -Transaction $candidate}}catch{{$failed=$true}}
 if(-not $failed -or $script:launches -ne 0){{throw 'Invalid original authority reached child creation'}}
 Write-Output 'original-signer-admission-refused'
}}finally{{
""" + _close_fixture() + "}\n"
    assert "original-signer-admission-refused" in _run(script, tmp_path, timeout=60)


@pytest.mark.parametrize("defect", ["root", "parent", "job", "source", "executable", "request", "deadline"])
def test_child_rejects_corrupted_original_handoff_before_backend_refusal(tmp_path: Path, defect: str) -> None:
    """A nonzero admission failure cannot masquerade as the positive fixed-78 result.

    Args:
        tmp_path: Real Windows child/job with synthetic source and VM endpoints.
        defect: Exact pre-resume process-record corruption in an explicit publisher seam.
    """
    script = _signer_fixture(tmp_path) + rf"""
$realPublisher=${{function:Publish-AtlasoTestVmOwnershipRecord}}
function Publish-AtlasoTestVmOwnershipRecord {{param($Context,$Record,$Kind)
 if($Kind -ceq 'console-credential-signer-process'){{
  switch({_ps(defect)}){{
   'root' {{$Record.details.root.pid+=1}}
   'parent' {{$Record.details.controller.start_filetime_utc='1'}}
   'job' {{$Record.details.root.job_name='Localwrong-job'}}
   'source' {{$Record.details.child_sha256='0'*64}}
   'executable' {{$Record.details.executable_sha256='0'*64}}
   'request' {{$Record.details.request_sha256='0'*64}}
   'deadline' {{$Record.details.deadline_utc=[DateTimeOffset]::UtcNow.AddSeconds(300).ToString('O')}}
  }}
 }}
 & $realPublisher -Context $Context -Record $Record -Kind $Kind
}}
try {{
 $failed=$false;try{{$null=Invoke-AtlasoConsoleStopSigner -Transaction $tx}}catch{{$failed=$true}}
 $s=Get-Content -LiteralPath $signerStop -Raw|ConvertFrom-Json -AsHashtable
 if(-not $failed -or $s.details.root_exit_code -ne 77 -or -not $s.details.whole_job_empty -or
  $s.details.outcome -cne 'terminated_failure'){{throw 'Corrupted signer handoff reached backend boundary'}}
 Write-Output 'child-handoff-refused-before-backend'
}}finally{{
""" + _close_fixture() + "}\n"
    assert "child-handoff-refused-before-backend" in _run(script, tmp_path, timeout=90)


def test_committed_child_has_only_admission_and_fixed_refusal() -> None:
    """Keep production child bootstrap free of key access, signing or transport APIs."""
    source = (ROOT / "scripts/windows/vmware/invoke-console-stop-signer-child.ps1").read_text(encoding="utf-8")
    assert "-EntryPoint $PSCommandPath" in source
    assert source.index("Assert-AtlasoConsoleStopSignerChild -Transaction") < source.index("exit 78")
    assert "exit 77" in source
    for forbidden in ("Get-AtlasoOnePassword", "Client.authenticate", "vmrun_write_variable", "signature_hex", "Send-InstallationConsoleSecret"):
        assert forbidden not in source


@pytest.mark.parametrize("mode", ["unprepared", "publication-uncertain", "post-publication-drift"])
def test_failed_request_never_grants_signer_launch_authority(tmp_path: Path, mode: str) -> None:
    """A retained request digest after drift is a fact, never successful preparation.

    Args:
        tmp_path: Original synthetic credential chain and ACK intent.
        mode: Missing, uncertain or post-publication failed request preparation.
    """
    script = _chain_fixture(tmp_path) + rf"""
try {{
 $null=Prepare-AtlasoConsoleCredentialStopAck -Transaction $tx
 $realPublisher=${{function:Publish-AtlasoTestVmOwnershipRecord}}
 function Publish-AtlasoTestVmOwnershipRecord {{param($Context,$Record,$Kind)
  if($Kind -ceq 'console-credential-signing-intent'){{
   if({_ps(mode)} -ceq 'publication-uncertain'){{throw 'Synthetic uncertain request publication'}}
   $r=& $realPublisher -Context $Context -Record $Record -Kind $Kind
   $script:expectedCommit='b'*40
   return $r
  }}
  & $realPublisher -Context $Context -Record $Record -Kind $Kind
 }}
 if({_ps(mode)} -cne 'unprepared'){{
  $failed=$false;try{{$null=New-AtlasoConsoleStopSigningRequest -Transaction $tx}}catch{{$failed=$true}}
  if(-not $failed){{throw 'Synthetic failed request returned success'}}
 }}
 $script:expectedCommit=$commit
 $script:launches=0
 function Get-AtlasoConsoleStopSignerLaunch {{param($Transaction,$RequestPath,$RequestSha256) $script:launches++;throw 'No launch'}}
 $refused=$false;try{{$null=Invoke-AtlasoConsoleStopSigner -Transaction $tx}}catch{{$refused=$true}}
 if(-not $refused -or $script:launches -ne 0){{throw 'Failed request acquired signer authority'}}
 $path=Join-Path $evidence ('atlaso-test-vm-console-credential-signing-intent-'+$nonce+'.json')
 if((Test-Path -LiteralPath $path) -ne ({_ps(mode)} -ceq 'post-publication-drift')){{throw 'Publication facts were relabeled'}}
 Write-Output 'failed-request-cannot-launch'
}}finally{{
""" + _close_fixture() + "}\n"
    assert "failed-request-cannot-launch" in _run(script, tmp_path, timeout=60)


@pytest.mark.parametrize("mode", ["before-publication", "after-publication"])
def test_unknown_signer_publication_never_resumes_or_retries_child(tmp_path: Path, mode: str) -> None:
    """Consume a failed original suspended-root publication without adopting its file.

    Args:
        tmp_path: Fresh original public chain and real suspended child namespace.
        mode: Explicit uncertainty before or after the atomic publisher returns.
    """
    marker = tmp_path / "must-not-resume.txt"
    command = f"[IO.File]::WriteAllText({_ps(marker)},'resumed');exit 78"
    script = _signer_fixture(tmp_path) + rf"""
function Get-AtlasoConsoleStopSignerLaunch {{param($Transaction,$RequestPath,$RequestSha256)
 $original=& $realLaunch -Transaction $Transaction -RequestPath $RequestPath -RequestSha256 $RequestSha256
 $original.Arguments=@('-NoProfile','-NonInteractive','-Command',{_ps(command)})
 $original
}}
$realPublisher=${{function:Publish-AtlasoTestVmOwnershipRecord}}
$script:publicationCalls=0
function Publish-AtlasoTestVmOwnershipRecord {{param($Context,$Record,$Kind)
 if($Kind -ceq 'console-credential-signer-process'){{
  $script:publicationCalls++
  if({_ps(mode)} -ceq 'after-publication'){{$null=& $realPublisher -Context $Context -Record $Record -Kind $Kind}}
  throw 'Synthetic original signer publication uncertainty'
 }}
 & $realPublisher -Context $Context -Record $Record -Kind $Kind
}}
try {{
 $failed=$false;try{{$null=Invoke-AtlasoConsoleStopSigner -Transaction $tx}}catch{{$failed=$true}}
 if(-not $failed -or $script:publicationCalls -ne 1 -or (Test-Path -LiteralPath {_ps(marker)}) -or
  (Test-Path -LiteralPath $signerStop) -or
  (Test-Path -LiteralPath $signerProcess) -ne ({_ps(mode)} -ceq 'after-publication')){{
  throw 'Uncertain original handoff resumed a child or relabeled publication'
 }}
 $again=$false;try{{$null=Invoke-AtlasoConsoleStopSigner -Transaction $tx}}catch{{$again=$true}}
 if(-not $again -or $script:publicationCalls -ne 1 -or (Test-Path -LiteralPath {_ps(marker)})){{
  throw 'Uncertain signer handoff replayed'
 }}
 Write-Output 'uncertain-signer-handoff-preserved'
}}finally{{
""" + _close_fixture() + "}\n"
    assert "uncertain-signer-handoff-preserved" in _run(script, tmp_path, timeout=90)


def test_signer_records_require_their_private_publication_callbacks(tmp_path: Path) -> None:
    """Reject direct signer record publication despite a valid original request.

    Args:
        tmp_path: Original successful source-only request with no child invocation.
    """
    script = _signer_fixture(tmp_path) + r"""
try {
 foreach($kind in @('signer-process','signer-stop')){
  $refused=$false
  try{$null=Publish-AtlasoConsoleCredentialRecord -Transaction $tx -Kind $kind -Details ([ordered]@{backend='unavailable'})}
  catch{$refused=$true}
  if(-not $refused){throw 'Direct publication adopted original callback authority'}
 }
 if((Test-Path -LiteralPath $signerProcess) -or (Test-Path -LiteralPath $signerStop)){throw 'Direct signer file was published'}
 Write-Output 'private-signer-publication-only'
}finally{
""" + _close_fixture() + "}\n"
    assert "private-signer-publication-only" in _run(script, tmp_path, timeout=60)
