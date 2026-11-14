"""Synthetic Windows tests for signer descriptor and nonce-claim boundaries."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_console_credential_transaction import _fixture

pytestmark = pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Windows file identity boundary")
TASK_ID = "00112233-4455-6677-8899-aabbccddeeff"


def _ps(value: str | Path) -> str:
    """Quote a public PowerShell literal.

    Args:
        value: Public path or identifier.
    """
    return "'" + str(value).replace("'", "''") + "'"


def _setup(tmp_path: Path) -> tuple[str, Path]:
    """Prepare synthetic original context with real local file identity pins.

    Args:
        tmp_path: Fresh pytest-owned fixture directory.
    """
    setup, _, _, _ = _fixture(tmp_path)
    evidence = tmp_path / "evidence"
    setup += rf"""
. (Join-Path $repo 'scripts/windows/vmware/Atlaso.ConsoleStopSignerAdmission.ps1')
$taskId='{TASK_ID}'
$context.TaskId=$taskId
$context | Add-Member ActiveTaskId $taskId -Force
$context | Add-Member PermittedRoot $repo -Force
$context | Add-Member ContinuationReceiptPath '' -Force
$context | Add-Member ContinuationReceiptSha256 '' -Force
$context | Add-Member LocalBuilder $false -Force
$context | Add-Member Repository 'mdaneri/Atlaso' -Force
$context.Branch='codex/1077-ipv4ll-fallback'
$context | Add-Member WorktreeDirectoryId ([Atlaso.WorkstationFileIdentity]::Get($repo)) -Force
$sourceHolder=[pscustomobject]@{{
 Pins=[Collections.Generic.List[IDisposable]]::new()
 Files=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 Directories=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 Disposed=$false
}}
$sourceHolder.Pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($repo,$true))
$sourceHolder.Directories.Add($repo)|Out-Null
$sourceHolder.Files.Add((Join-Path $repo 'scripts/windows/vmware/Atlaso.ConsoleStopSignerAdmission.ps1'))|Out-Null
$context | Add-Member CheckoutSourcePin $sourceHolder -Force
$script:expectedCommit=$commit
$script:syntheticSdkCalls=0
"""
    return setup, evidence


def _run(script: str, directory: Path, *, timeout: int = 45) -> str:
    """Run a bounded synthetic PowerShell file fixture.

    Args:
        script: Public fixture and fail-closed assertions.
        directory: Fresh pytest-owned fixture working directory.
        timeout: Maximum fixture duration in seconds.
    """
    fixture = directory / "signer-admission-fixture.ps1"
    with fixture.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(script)
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(fixture)],
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=directory,
        env={**os.environ, "CODEX_THREAD_ID": TASK_ID},
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def _scope() -> str:
    """Create one original source-owned scope for a synthetic case.

    Args:
        None.
    """
    return """
$scope=New-AtlasoConsoleSignerScope -Context $context -RunId ([guid]::NewGuid().ToString('N')) -GuestBootId ([guid]::NewGuid().ToString('D')) -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(90))
"""


def _descriptor() -> str:
    """Write a synthetic descriptor bound to the original scope.

    Args:
        None.
    """
    return r"""
$authority=$null
if(-not $script:AtlasoSignerScopes.TryGetValue($scope,[ref]$authority)){throw 'fresh scope missing'}
$pub='11'*32
$fingerprint=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Convert]::FromHexString($pub))).ToLowerInvariant()
$d=[ordered]@{
 schema=1;kind='console-signer-admission-descriptor-v1';host_protocol=3;wire_protocol=2
 task_id=$authority.Context.TaskId;source_commit=$authority.Context.SourceCommit
 worktree_identity=$authority.Context.WorktreeDirectoryId;evidence_identity=$authority.EvidenceIdentity
 ownership_receipt_sha256=$authority.Context.ReceiptSha256;persistent_vm_identity_sha256=$authority.PersistentIdentity
 run_id=$authority.RunId;receiver_nonce=$authority.Nonce;guest_boot_id=$authority.GuestBootId
 host_boot_identity=$authority.HostBoot;deadline_utc=$authority.DeadlineUtc
 stop_ack_public_key_hex=$pub;stop_ack_signing_key_sha256=$fingerprint
 signer_source_sha256=('a'*64);host_executable_sha256=('b'*64)
 runtime_receipt_path=[IO.Path]::GetFullPath((Join-Path $evidence 'runtime-receipt.json'))
 runtime_receipt_sha256=('c'*64);runtime_directory=[IO.Path]::GetFullPath((Join-Path $evidence 'runtime'))
 runtime_directory_identity='F496DB94:0000000000000001';runtime_inventory_sha256=('d'*64);runtime_file_count=2
 python_path=[IO.Path]::GetFullPath((Join-Path $evidence 'python.exe'));python_sha256=('e'*64)
 provider_contract='refusing-v1';codec_contract='refusing-v1';protected_provider_evidence_sha256=('f'*64)
 controller_pid=$authority.ControllerIdentity.pid;controller_start_utc=$authority.ControllerIdentity.getprocess_start_utc
 controller_start_filetime_utc=$authority.ControllerIdentity.start_filetime_utc
 controller_cim_creation_utc=$authority.ControllerIdentity.cim_creation_utc
 controller_parent_pid=$authority.ControllerIdentity.parent_pid
}
$descriptorPath=Join-Path $evidence 'signer-descriptor.json'
$json=$d | ConvertTo-Json -Depth 5 -Compress
[IO.File]::WriteAllText($descriptorPath,$json,[Text.UTF8Encoding]::new($false))
$descriptorSha=(Get-FileHash -LiteralPath $descriptorPath).Hash.ToLowerInvariant()
"""


def test_descriptor_reader_returns_only_data_and_pins(tmp_path: Path) -> None:
    """A valid descriptor read returns pins and cannot mint authority.

    Args:
        tmp_path: Fresh pytest-owned fixture directory.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + r"""
$read=Read-AtlasoConsoleSignerDescriptor -Context $context -Path $descriptorPath -Sha256 $descriptorSha
try {
 $expected=@('schema','kind','host_protocol','wire_protocol','task_id','source_commit','worktree_identity','evidence_identity','ownership_receipt_sha256','persistent_vm_identity_sha256','run_id','receiver_nonce','guest_boot_id','host_boot_identity','deadline_utc','stop_ack_public_key_hex','stop_ack_signing_key_sha256','signer_source_sha256','host_executable_sha256','runtime_receipt_path','runtime_receipt_sha256','runtime_directory','runtime_directory_identity','runtime_inventory_sha256','runtime_file_count','python_path','python_sha256','provider_contract','codec_contract','protected_provider_evidence_sha256','controller_pid','controller_start_utc','controller_start_filetime_utc','controller_cim_creation_utc','controller_parent_pid')
 if((($read.Value.Keys|Sort-Object)-join ',') -cne (($expected|Sort-Object)-join ',')){throw 'descriptor schema differs'}
 if($read.Pins.Count -ne 2){throw 'reader omitted pins'}
 $failure='';try{$null=Assert-AtlasoConsoleSignerAdmission -Admission $read.Value}catch{$failure=$_.Exception.Message}
 if($failure -cne 'Original live signer admission required.'){throw 'descriptor data was not refused as authority'}
 'descriptor-data-only'
}finally{foreach($pin in $read.Pins){$pin.Dispose()};Close-AtlasoConsoleSignerScope -Scope $scope}
"""
    assert "descriptor-data-only" in _run(script, tmp_path)


@pytest.mark.parametrize(
    ("mutation", "description", "expected_error"),
    [
        ("extra", "extra member", "Public console transaction record admission failed."),
        ("missing", "missing member", "Public console transaction record admission failed."),
        ("schema", "unsupported schema", "Public signer descriptor data refused."),
        ("number", "wrong primitive type", "Public signer descriptor data refused."),
        ("digest", "uppercase digest", "Public signer descriptor data refused."),
        ("fingerprint", "key fingerprint mismatch", "Public signer descriptor data refused."),
        ("path", "relative path", "Public signer descriptor data refused."),
        ("selfhash", "self hash", "Public console transaction record admission failed."),
    ],
)
def test_descriptor_reader_refuses_schema_drift(
    tmp_path: Path, mutation: str, description: str, expected_error: str
) -> None:
    """Malformed descriptor schemas fail before publishing a nonce claim.

    Args:
        tmp_path: Fresh pytest-owned fixture directory.
        mutation: Exact malformed descriptor mutation.
        description: Case label for assertion diagnostics.
        expected_error: Exact expected production refusal.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + rf"""
switch('{mutation}') {{
 'extra' {{$d.extra='bad'}}
 'missing' {{$d.Remove('codec_contract')}}
 'schema' {{$d.schema=2}}
 'number' {{$d.controller_pid='1'}}
 'digest' {{$d.signer_source_sha256='A'*64}}
 'fingerprint' {{$d.stop_ack_signing_key_sha256='0'*64}}
 'path' {{$d.python_path='relative/python.exe'}}
 'selfhash' {{$d.descriptor_sha256='0'*64}}
}}
$json=$d|ConvertTo-Json -Depth 5 -Compress
[IO.File]::WriteAllText($descriptorPath,$json,[Text.UTF8Encoding]::new($false))
$badSha=(Get-FileHash -LiteralPath $descriptorPath).Hash.ToLowerInvariant()
$failure=''
try{{$null=Read-AtlasoConsoleSignerDescriptor -Context $context -Path $descriptorPath -Sha256 $badSha}}catch{{$failure=$_.Exception.Message}}
if($failure -cne '{expected_error}'){{throw 'Malformed descriptor missed its specific refusal: {description}'}}
$claim=Join-Path $evidence ('atlaso-console-signer-nonce-'+$scope.ReceiverNonce+'.json')
if(Test-Path -LiteralPath $claim){{throw 'Malformed descriptor reached claim'}}
Close-AtlasoConsoleSignerScope -Scope $scope
'descriptor-refused'
"""
    assert "descriptor-refused" in _run(script, tmp_path)


def test_production_provider_refuses_and_consumes_nonce(tmp_path: Path) -> None:
    """Production provider refusal preserves the consumed claim and forbids replay.

    Args:
        tmp_path: Fresh pytest-owned fixture directory.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + r"""
$failure='';try{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}catch{$failure=$_.Exception.Message}
if($failure -cne 'Production signer runtime/provider admission is unavailable.' -or $script:syntheticSdkCalls -ne 0){throw 'Production provider did not reach its fixed pre-SDK refusal'}
$claimPath=Join-Path $evidence ('atlaso-console-signer-nonce-'+$scope.ReceiverNonce+'.json')
if(-not (Test-Path -LiteralPath $claimPath -PathType Leaf)){throw 'Claim missing after refusal'}
$claim=Get-Content -LiteralPath $claimPath -Raw|ConvertFrom-Json
if($claim.receiver_nonce -cne $scope.ReceiverNonce -or $claim.run_id -cne $scope.RunId -or
   $claim.descriptor_sha256 -cne $descriptorSha -or $claim.host_protocol -ne 3 -or $claim.wire_protocol -ne 2){throw 'Claim binding differs'}
$claimHash=(Get-FileHash -LiteralPath $claimPath).Hash
$retry=$false;try{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}catch{$retry=$true}
if(-not $retry -or (Get-FileHash -LiteralPath $claimPath).Hash -cne $claimHash){throw 'Claim retried or replaced'}
$copy=$scope.PSObject.Copy();$copyRefused=$false;try{$null=Open-AtlasoConsoleSignerAdmission -Scope $copy -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}catch{$copyRefused=$true}
if(-not $copyRefused){throw 'Copied scope adopted authority'}
Close-AtlasoConsoleSignerScope -Scope $scope
'provider-refusal-consumed'
"""
    assert "provider-refusal-consumed" in _run(script, tmp_path)


def test_mocked_synthetic_verifier_lifetime_requires_original_reference(tmp_path: Path) -> None:
    """An internal synthetic verifier can exercise only same-reference lifecycle checks.

    Args:
        tmp_path: Fresh pytest-owned synthetic fixture directory.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + r"""
$script:providerCalls=0
function Assert-AtlasoConsoleSignerRuntimeProvider {param($Authority,$Descriptor)
 $script:providerCalls++
 if($Descriptor.protected_provider_evidence_sha256 -cne ('f'*64)){throw 'synthetic verifier binding mismatch'}
}
$admission=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha
Assert-AtlasoConsoleSignerAdmission -Admission $admission
if($script:providerCalls -lt 2 -or $admission.Status -cne 'preplan_no_dispatch'){throw 'synthetic lifecycle or refusing status differs'}
$copy=$admission.PSObject.Copy()
$failure='';try{Assert-AtlasoConsoleSignerAdmission -Admission $copy}catch{$failure=$_.Exception.Message}
if($failure -cne 'Original live signer admission required.'){throw 'copied capability adopted authority'}
$serialized=$admission|ConvertTo-Json -Compress|ConvertFrom-Json
$failure='';try{Assert-AtlasoConsoleSignerAdmission -Admission $serialized}catch{$failure=$_.Exception.Message}
if($failure -cne 'Original live signer admission required.'){throw 'serialized capability adopted authority'}
$context.Repository='changed/owner'
$failure='';try{Assert-AtlasoConsoleSignerAdmission -Admission $admission}catch{$failure=$_.Exception.Message}
if($failure -cne 'Original signer scope changed or expired.'){throw 'source context drift missed refusal'}
$context.Repository='mdaneri/Atlaso'
Close-AtlasoConsoleSignerScope -Scope $scope
$failure='';try{Assert-AtlasoConsoleSignerAdmission -Admission $admission}catch{$failure=$_.Exception.Message}
if($failure -cne 'Original live signer admission required.'){throw 'closed scope retained capability'}
'synthetic-lifecycle-only'
"""
    assert "synthetic-lifecycle-only" in _run(script, tmp_path)


def test_unknown_claim_ack_preserves_original_record_and_consumes_attempt(tmp_path: Path) -> None:
    """Lost publication acknowledgement keeps the written claim and forbids retry.

    Args:
        tmp_path: Fresh pytest-owned synthetic fixture directory.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + r"""
$realPublisher=(Get-Item Function:Publish-AtlasoConsoleSignerNonceClaim).ScriptBlock
function Publish-AtlasoConsoleSignerNonceClaim {param($Authority,$DescriptorSha256)
 $null=& $realPublisher -Authority $Authority -DescriptorSha256 $DescriptorSha256
 throw 'synthetic publication acknowledgement lost'
}
$failure='';try{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}catch{$failure=$_.Exception.Message}
if($failure -cne 'synthetic publication acknowledgement lost'){throw 'uncertain publication error was masked'}
$claimPath=Join-Path $evidence ('atlaso-console-signer-nonce-'+$scope.ReceiverNonce+'.json')
if(-not (Test-Path -LiteralPath $claimPath)){throw 'written claim was not preserved after unknown acknowledgement'}
$bytes=[IO.File]::ReadAllBytes($claimPath)
$hash=(Get-FileHash -LiteralPath $claimPath).Hash
$retry=$false;try{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}catch{$retry=$true}
if(-not $retry -or (Get-FileHash -LiteralPath $claimPath).Hash -cne $hash -or
   [Convert]::ToBase64String([IO.File]::ReadAllBytes($claimPath)) -cne [Convert]::ToBase64String($bytes)){throw 'uncertain claim was retried or replaced'}
Close-AtlasoConsoleSignerScope -Scope $scope
'unknown-claim-preserved'
"""
    assert "unknown-claim-preserved" in _run(script, tmp_path)


def test_scope_drift_and_legacy_collision_refuse_before_claim(tmp_path: Path) -> None:
    """Original context drift and exact legacy overlap refuse before claim publication.

    Args:
        tmp_path: Fresh pytest-owned fixture directory.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + r"""
$context.Repository='changed/owner'
$failure='';try{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}catch{$failure=$_.Exception.Message}
if($failure -cne 'Original signer scope changed or expired.'){throw 'Context drift missed its exact preclaim refusal'}
$claim=Join-Path $evidence ('atlaso-console-signer-nonce-'+$scope.ReceiverNonce+'.json')
if(Test-Path -LiteralPath $claim){throw 'Context drift reached claim'}
Close-AtlasoConsoleSignerScope -Scope $scope
$context.Repository='mdaneri/Atlaso'
$scope2=New-AtlasoConsoleSignerScope -Context $context -RunId ([guid]::NewGuid().ToString('N')) -GuestBootId ([guid]::NewGuid().ToString('D')) -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(90))
$scope=$scope2
""" + _descriptor() + r"""
$legacy=Join-Path $evidence ('atlaso-test-vm-console-credential-intent-'+$scope2.ReceiverNonce+'.json')
[IO.File]::WriteAllText($legacy,'preserve')
$before=(Get-FileHash -LiteralPath $legacy).Hash
$overlapError='';try{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope2 -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}catch{$overlapError=$_.Exception.Message}
if($overlapError -cne 'Exact receiver nonce overlaps an existing consumer.' -or (Get-FileHash -LiteralPath $legacy).Hash -cne $before){throw 'Legacy overlap did not hit its refusal or changed the original'}
if(Test-Path -LiteralPath (Join-Path $evidence ('atlaso-console-signer-nonce-'+$scope2.ReceiverNonce+'.json'))){throw 'Overlap reached claim'}
Close-AtlasoConsoleSignerScope -Scope $scope2
'preclaim-guards-refused'
"""
    assert "preclaim-guards-refused" in _run(script, tmp_path)


def test_nonce_claim_has_one_atomic_winner_across_run_ids(tmp_path: Path) -> None:
    """Concurrent claimants cannot win one nonce under different run IDs.

    Args:
        tmp_path: Fresh pytest-owned fixture directory containing synthetic claim files.
    """
    setup, _ = _setup(tmp_path)
    script = setup + r"""
$nonce=[guid]::NewGuid().ToString('N')
$race=@'
param($Repo,$Root,$Nonce,$Run,$Barrier)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $Repo 'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1') -Force
. (Join-Path $Repo 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
. (Join-Path $Repo 'scripts/windows/vmware/Atlaso.ConsoleCredentialTransaction.ps1')
. (Join-Path $Repo 'scripts/windows/vmware/Atlaso.ConsoleStopSignerAdmission.ps1')
$scope=[pscustomobject]@{HostProtocol=3;WireProtocol=2;ReceiverNonce=$Nonce;RunId=$Run;GuestBootId='00112233-4455-6677-8899-aabbccddeeff';DeadlineUtc='2030-01-01T00:00:00.0000000+00:00'}
$a=[pscustomobject]@{Context=[pscustomobject]@{EvidenceDirectory=$Root;TaskId='00112233-4455-6677-8899-aabbccddeeff';SourceCommit=('a'*40)};Nonce=$Nonce;RunId=$Run;EvidenceIdentity='F496DB94:0000000000000001';ControllerIdentity=[ordered]@{pid=$PID;start_filetime_utc='1'};DeadlineUtc='2030-01-01T00:00:00.0000000+00:00';Pins=[Collections.Generic.List[IDisposable]]::new();Scope=$scope;ClaimPublishing=$true;ClaimThread=[Threading.Thread]::CurrentThread.ManagedThreadId}
$script:AtlasoSignerScopes.Add($scope,$a)
function Assert-AtlasoConsoleSignerScopeState {param($Authority)}
if(-not $Barrier.SignalAndWait(10000)){throw 'Claim race barrier timed out'}
try{$null=Publish-AtlasoConsoleSignerNonceClaim -Authority $a -DescriptorSha256 ('b'*64);'won'}catch{
 $base=$_.Exception.GetBaseException()
 if($_.Exception.Message -eq 'Nonce already claimed or ambiguous.' -or
    ($base -is [ComponentModel.Win32Exception] -and $base.NativeErrorCode -in @(80,183))){'refused'}
 else {throw}
}
'@
$pool=[RunspaceFactory]::CreateRunspacePool(1,2);$pool.Open()
$barrier=[Threading.Barrier]::new(2)
$left=[PowerShell]::Create();$left.RunspacePool=$pool
$right=[PowerShell]::Create();$right.RunspacePool=$pool
try {
 $null=$left.AddScript($race).AddArgument($repo).AddArgument($evidence).AddArgument($nonce).AddArgument(([guid]::NewGuid().ToString('N'))).AddArgument($barrier)
 $null=$right.AddScript($race).AddArgument($repo).AddArgument($evidence).AddArgument($nonce).AddArgument(([guid]::NewGuid().ToString('N'))).AddArgument($barrier)
 $lh=$left.BeginInvoke();$rh=$right.BeginInvoke()
 if(-not $lh.AsyncWaitHandle.WaitOne(30000) -or -not $rh.AsyncWaitHandle.WaitOne(30000)){throw 'Claim race timed out'}
 $results=@((@($left.EndInvoke($lh))-join ''),(@($right.EndInvoke($rh))-join ''))
 $proof=[ordered]@{left_had_errors=$left.HadErrors;right_had_errors=$right.HadErrors;left_errors=@($left.Streams.Error|ForEach-Object{$_.Exception.Message});right_errors=@($right.Streams.Error|ForEach-Object{$_.Exception.Message});results=$results}
 [IO.File]::WriteAllText((Join-Path $evidence 'atomic-race-proof.json'),($proof|ConvertTo-Json -Depth 5 -Compress))
 if($left.Streams.Error.Count -or $right.Streams.Error.Count){throw ('Concurrent claim fixture had unclassified error: '+($proof|ConvertTo-Json -Depth 5 -Compress))}
 if(@($results|Where-Object{$_ -eq 'won'}).Count -ne 1 -or @($results|Where-Object{$_ -eq 'refused'}).Count -ne 1){throw 'Claim did not have one winner'}
 if(-not (Test-Path -LiteralPath (Join-Path $evidence ('atlaso-console-signer-nonce-'+$nonce+'.json')))){throw 'Winning claim missing'}
 'atomic-single-winner'
} finally {$left.Dispose();$right.Dispose();$pool.Dispose();$barrier.Dispose()}
"""
    assert "atomic-single-winner" in _run(script, tmp_path)


def test_nonce_publication_requires_original_private_phase(tmp_path: Path) -> None:
    """Reject original-state and copied-state direct publication outside Open's phase.

    Args:
        tmp_path: Fresh pytest-owned synthetic fixture directory.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + r"""
foreach($candidate in @($authority,$authority.PSObject.Copy())) {
 $failure='';try{$null=Publish-AtlasoConsoleSignerNonceClaim -Authority $candidate -DescriptorSha256 $descriptorSha}catch{$failure=$_.Exception.Message}
 if($failure -cne 'Original private nonce publication phase required.'){throw 'Standalone state acquired publication authority'}
}
if(@(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-console-signer-nonce-*').Count){throw 'Direct publisher wrote before original phase'}
Close-AtlasoConsoleSignerScope -Scope $scope
'private-phase-refused'
"""
    assert "private-phase-refused" in _run(script, tmp_path)


@pytest.mark.parametrize("existing", ["pending", "older-protocol", "directory"])
def test_existing_nonce_is_consumed_across_run_and_protocol(tmp_path: Path, existing: str) -> None:
    """Preserve exact nonce collisions independently of recorded run or protocol.

    Args:
        tmp_path: Fresh pytest-owned synthetic fixture directory.
        existing: Existing deterministic stage, prior-version claim or ambiguous directory.
    """
    setup, _ = _setup(tmp_path)
    script = setup + _scope() + _descriptor() + rf"""
$path=Join-Path $evidence ('atlaso-console-signer-nonce-'+$scope.ReceiverNonce+'.json')
if('{existing}' -eq 'pending'){{$path=[IO.Path]::ChangeExtension($path,'pending')}}
if('{existing}' -eq 'directory'){{[IO.Directory]::CreateDirectory($path)|Out-Null;$before=[Atlaso.WorkstationFileIdentity]::Get($path)}}
else {{[IO.File]::WriteAllText($path,'{{"host_protocol":2,"run_id":"older-original"}}');$before=(Get-FileHash -LiteralPath $path).Hash}}
$script:providerCalls=0
function Assert-AtlasoConsoleSignerRuntimeProvider {{param($Authority,$Descriptor) $script:providerCalls++;throw 'Must not reach provider'}}
$failure='';try{{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}}catch{{$failure=$_.Exception.Message}}
if($failure -cne 'Nonce already claimed or ambiguous.' -or $script:providerCalls -ne 0){{throw 'Nonce collision missed its exact preprovider guard'}}
$after=if('{existing}' -eq 'directory'){{[Atlaso.WorkstationFileIdentity]::Get($path)}}else{{(Get-FileHash -LiteralPath $path).Hash}}
if($after -cne $before){{throw 'Original nonce collision was replaced'}}
Close-AtlasoConsoleSignerScope -Scope $scope
$failure='';try{{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}}catch{{$failure=$_.Exception.Message}}
if($failure -cne 'Signer scope attempt already consumed or closed.'){{throw 'Closed attempt reopened'}}
'original-collision-preserved'
"""
    assert "original-collision-preserved" in _run(script, tmp_path)


@pytest.mark.parametrize("drift", ["source", "evidence", "controller", "late-attachment", "source-pin"])
def test_original_scope_binding_drift_precedes_claim(tmp_path: Path, drift: str) -> None:
    """Refuse source, evidence, controller and late-attachment drift before a claim.

    Args:
        tmp_path: Fresh pytest-owned synthetic fixture directory.
        drift: Exact original reference or independent binding changed after scope creation.
    """
    setup, _ = _setup(tmp_path)
    expected = (
        "Original signer controller or resource changed."
        if drift == "controller"
        else "Original signer scope changed or expired."
    )
    script = setup + _scope() + _descriptor() + rf"""
switch('{drift}') {{
 'source' {{$context.SourceCommit='b'*40}}
 'evidence' {{$context.EvidenceDirectoryId='F496DB94:0000000000000000'}}
 'controller' {{
  $realClock=(Get-Item Function:Get-AtlasoConsoleProcessCreation).ScriptBlock
  function Get-AtlasoConsoleProcessCreation {{param($Process) $clock=& $realClock -Process $Process;$clock.cim_creation_utc='2000-01-01T00:00:00.0000000Z';return $clock}}
 }}
 'late-attachment' {{$context.ValidationRootAdmission=[pscustomobject]@{{Disposed=$false}}}}
 'source-pin' {{$context.CheckoutSourcePin=$sourceHolder.PSObject.Copy()}}
}}
$failure='';try{{$null=Open-AtlasoConsoleSignerAdmission -Scope $scope -DescriptorPath $descriptorPath -DescriptorSha256 $descriptorSha}}catch{{$failure=$_.Exception.Message}}
if($failure -cne '{expected}'){{throw ('Original binding drift missed its guard: '+$failure)}}
if(@(Get-ChildItem -LiteralPath $evidence -Filter 'atlaso-console-signer-nonce-*').Count){{throw 'Drift published a claim'}}
Close-AtlasoConsoleSignerScope -Scope $scope
'original-binding-refused'
"""
    assert "original-binding-refused" in _run(script, tmp_path)


@pytest.mark.parametrize("defect", ["plan-hash", "receiver-hash", "duplicate", "oversize", "digest", "final-lf"])
def test_independent_descriptor_digest_and_acyclic_bounds(tmp_path: Path, defect: str) -> None:
    """Reject circular schemas, duplicate bytes, oversized data and independent digest drift.

    Args:
        tmp_path: Fresh pytest-owned synthetic fixture directory.
        defect: Exact forbidden descriptor representation or independently retained selector.
    """
    setup, _ = _setup(tmp_path)
    expected = (
        "Public signer descriptor data refused."
        if defect == "final-lf"
        else "Public console transaction record admission failed."
    )
    script = setup + _scope() + _descriptor() + rf"""
switch('{defect}') {{
 'plan-hash' {{$d.plan_sha256='a'*64}}
 'receiver-hash' {{$d.receiver_receipt_sha256='a'*64}}
 'oversize' {{$d.codec_contract='a'*17000}}
 'final-lf' {{$d.source_commit+= [char]10}}
}}
$json=$d|ConvertTo-Json -Depth 5 -Compress
if('{defect}' -eq 'duplicate'){{$json='{{"schema":1,'+$json.Substring(1)}}
[IO.File]::WriteAllText($descriptorPath,$json,[Text.UTF8Encoding]::new($false))
$hash=(Get-FileHash -LiteralPath $descriptorPath).Hash.ToLowerInvariant()
if('{defect}' -eq 'digest'){{$hash='0'*64}}
$failure='';try{{$null=Read-AtlasoConsoleSignerDescriptor -Context $context -Path $descriptorPath -Sha256 $hash}}catch{{$failure=$_.Exception.Message}}
if($failure -cne '{expected}'){{throw ('Descriptor missed exact refusal: '+$failure)}}
Close-AtlasoConsoleSignerScope -Scope $scope
'independent-descriptor-refused'
"""
    assert "independent-descriptor-refused" in _run(script, tmp_path)
