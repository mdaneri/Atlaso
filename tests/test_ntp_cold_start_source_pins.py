"""Keep NTP source pins compatible with sibling durable ownership publication."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.completed_task_files import WindowsFiles

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "nt" or not shutil.which("pwsh"), reason="Windows ownership primitives")


def ps_literal(value: Path | str) -> str:
    """Quote a test-owned path or public fixture value for PowerShell.

    Args:
        value: Non-secret path or public fixture value.
    """
    return "'" + str(value).replace("'", "''") + "'"


def test_ntp_source_pins_allow_durable_sibling_publication_and_block_replacement(tmp_path: Path) -> None:
    """Hold the real NTP source pins while publishing lifecycle ownership beside them.

    Args:
        tmp_path: Pytest-owned validation directory beneath the original test-results root.
    """
    source_dir = tmp_path / "peer-source"
    receipt_dir = tmp_path / "peer-provenance"
    lab_root = tmp_path / "checkout" / "lab"
    source_dir.mkdir()
    receipt_dir.mkdir()
    lab_root.mkdir(parents=True)
    source_disk = source_dir / "peer.vmdk"
    source_disk.write_bytes(b"synthetic public disk fixture")
    source_commit = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    source_receipt = receipt_dir / "source.json"
    prepared_receipt = receipt_dir / "prepared.json"
    original = {
        "schema": 1,
        "task_id": "synthetic-ntp-pin-task",
        "repository": "mdaneri/Atlaso",
        "pr": 1121,
        "source_commit": source_commit,
        "path": str(source_dir.resolve()),
        "root_identity": WindowsFiles().snapshot(source_dir)["."]["identity"],
    }
    prepared = {
        "schema": 1,
        "task_id": original["task_id"],
        "pr": original["pr"],
        "source_commit": source_commit,
        "path": str(source_disk.resolve()),
        "original_root_receipt": source_receipt.name,
        "prepared_before_use": True,
        "consumer_vms": [],
        "format": "monolithicSparse",
        "parent_cid": 4294967295,
        "virtual_size_bytes": 2147483648,
        "sha256": hashlib.sha256(source_disk.read_bytes()).hexdigest(),
    }
    source_receipt.write_text(json.dumps(original), encoding="utf-8")
    prepared_receipt.write_text(json.dumps(prepared), encoding="utf-8")
    source_receipt_sha = hashlib.sha256(source_receipt.read_bytes()).hexdigest()
    prepared_receipt_sha = hashlib.sha256(prepared_receipt.read_bytes()).hexdigest()
    module = ROOT / "scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1"
    ownership = ROOT / "scripts/windows/vmware/Atlaso.LifecycleOwnership.ps1"
    ntp = ROOT / "scripts/windows/vmware/Atlaso.NtpColdStart.ps1"
    program = f"""
$ErrorActionPreference='Stop'
Import-Module {ps_literal(module)} -Force
. {ps_literal(ownership)}
$NtpColdStartOnly=$true
$CertificatePeerCidr='192.168.77.1/24'; $CertificateLeaseAddress='192.168.77.10'
$NtpPeerSourceReceiptPath={ps_literal(source_receipt)}
$NtpPeerPreparedReceiptPath={ps_literal(prepared_receipt)}
$NtpPeerSourceReceiptSha256='{source_receipt_sha}'
$NtpPeerPreparedReceiptSha256='{prepared_receipt_sha}'
$ClientVmdkPath={ps_literal(source_disk)}
$durableOwnershipRoot={ps_literal(tmp_path)}
$repoRoot={ps_literal(ROOT)}
$sourceCommit='{source_commit}'
$lifecycleTaskId='synthetic-ntp-pin-task'; $PullRequestNumber=1121
$runtimeConsumerPins=[Collections.Generic.List[IDisposable]]::new()
. {ps_literal(ntp)}
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(ntp)},[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){{throw 'NTP helper parse failed.'}}
$definition=$ast.Find({{param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
 $node.Name -eq 'Assert-NtpPeerSourceOwnership'
}},$true)
$directoryCalls=@($definition.Body.FindAll({{param($node)
 $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
 $node.Member.Extent.Text -eq 'PinOrdinaryDirectoryPath'
}},$true) | Sort-Object {{$_.Extent.StartOffset}})
$fileCalls=@($definition.Body.FindAll({{param($node)
 $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and
 $node.Member.Extent.Text -eq 'PinOrdinaryReadFile'
}},$true) | Sort-Object {{$_.Extent.StartOffset}})
if($directoryCalls.Count -ne 2 -or $fileCalls.Count -ne 2){{throw 'NTP original source pin contract changed.'}}
try {{
 $reference=@{{Path=$NtpPeerSourceReceiptPath}}
 $runtimeConsumerPins.Add(([scriptblock]::Create($directoryCalls[0].Extent.Text)).InvokeReturnAsIs())
 $original=@{{path={ps_literal(source_dir)}}}
 $runtimeConsumerPins.Add(([scriptblock]::Create($directoryCalls[1].Extent.Text)).InvokeReturnAsIs())
 foreach($receipt in @($NtpPeerSourceReceiptPath,$NtpPeerPreparedReceiptPath)) {{
  $reference=@{{Path=$receipt}}
  $runtimeConsumerPins.Add(([scriptblock]::Create($fileCalls[0].Extent.Text)).InvokeReturnAsIs())
 }}
 $runtimeConsumerPins.Add(([scriptblock]::Create($fileCalls[1].Extent.Text)).InvokeReturnAsIs())
 $published=$false; $manifestExists=$false
 try {{
  $record=New-AtlasoLifecycleOwnershipRecord -DurableRoot $durableOwnershipRoot -Worktree (Join-Path $durableOwnershipRoot 'checkout') -LabRoot (Join-Path $durableOwnershipRoot 'checkout/lab') -ResourcePath (Join-Path $durableOwnershipRoot 'checkout/lab') -Kind vm-directory -TaskId $lifecycleTaskId -SourceCommit $sourceCommit -PullRequestNumber 1121 -RequireEmpty
  $published=$true
  $manifestExists=[IO.File]::Exists($record.Path)
 }} catch {{}}
 function Test-DirectoryMoveBlocked([string]$Path) {{
  try {{ [IO.Directory]::Move($Path,$Path+'.moved'); return $false }} catch {{ return $true }}
 }}
 function Test-FileMoveBlocked([string]$Path) {{
  try {{ [IO.File]::Move($Path,$Path+'.moved'); return $false }} catch {{ return $true }}
 }}
 $evidence=[pscustomobject]@{{
  published=$published; manifest_exists=$manifestExists
  receipt_dir_move_blocked=(Test-DirectoryMoveBlocked {ps_literal(receipt_dir)})
  source_dir_move_blocked=(Test-DirectoryMoveBlocked {ps_literal(source_dir)})
  ancestor_move_blocked=(Test-DirectoryMoveBlocked {ps_literal(tmp_path)})
  source_receipt_move_blocked=(Test-FileMoveBlocked {ps_literal(source_receipt)})
  prepared_receipt_move_blocked=(Test-FileMoveBlocked {ps_literal(prepared_receipt)})
  source_disk_move_blocked=(Test-FileMoveBlocked {ps_literal(source_disk)})
 }}
 $evidence | ConvertTo-Json -Compress
}} finally {{
 foreach($pin in $runtimeConsumerPins){{$pin.Dispose()}}
 $runtimeConsumerPins.Clear()
}}
"""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert json.loads(result.stdout) == {
        "published": True,
        "manifest_exists": True,
        "receipt_dir_move_blocked": True,
        "source_dir_move_blocked": True,
        "ancestor_move_blocked": True,
        "source_receipt_move_blocked": True,
        "prepared_receipt_move_blocked": True,
        "source_disk_move_blocked": True,
    }
