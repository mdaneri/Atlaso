"""Exercise bounded NTP serial-console public-key extraction."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "nt" or not shutil.which("pwsh"), reason="Windows PowerShell file semantics")


def ps_literal(value: Path | str) -> str:
    """Quote one test-owned path or public fixture value for PowerShell.

    Args:
        value: Non-secret test path or public key marker.
    """
    return "'" + str(value).replace("'", "''") + "'"


def test_console_reader_bounds_growing_files_and_returns_only_role_bound_public_evidence(tmp_path: Path) -> None:
    """Read synthetic boot consoles through the actual AST-extracted function.

    Args:
        tmp_path: Pytest-owned validation directory beneath the original test-results root.
    """
    appliance_key = "ssh-ed25519 " + "A" * 44
    peer_key = "ssh-ed25519 " + "B" * 44
    appliance_marker = f"ATLASO_NTP_APPLIANCE_ED25519_HOST_KEY_V1 {appliance_key}"
    peer_marker = f"ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1 {peer_key}"
    appliance_console = tmp_path / "appliance.serial"
    peer_console = tmp_path / "peer.serial"
    duplicate_console = tmp_path / "peer-duplicate.serial"
    conflict_console = tmp_path / "peer-conflict.serial"
    malformed_console = tmp_path / "peer-malformed.serial"
    partial_console = tmp_path / "peer-partial.serial"
    oversized_console = tmp_path / "peer-oversized.serial"
    reparse_console = tmp_path / "peer-reparse.serial"
    boot_noise = b"boot output before public identity\n" * 3000
    peer_boot_noise = b"peer boot output before public identity\n" * 3000
    assert len(boot_noise) > 8192 and len(peer_boot_noise) > 8192
    appliance_console.write_bytes(boot_noise + appliance_marker.encode("ascii") + b"\n")
    peer_console.write_bytes(peer_boot_noise + peer_marker.encode("ascii") + b"\n")
    duplicate_console.write_text(peer_marker + "\n" + peer_marker + "\n", encoding="ascii")
    conflict_console.write_text(peer_marker + "\n" + peer_marker.replace("B" * 44, "C" * 44) + "\n", encoding="ascii")
    malformed_console.write_text("ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1 ssh-ed25519 !!!\n", encoding="ascii")
    partial_console.write_text("ATLASO_CERTIFICATE_PEER_ED25519_HOST_KEY_V1 ssh-ed25519 ", encoding="ascii")
    oversized_console.write_bytes(b"console noise\n" * (1024 * 1024 // 14 + 200))
    reparse_console.write_text(peer_marker + "\n", encoding="ascii")

    module = ROOT / "scripts/windows/vmware/Atlaso.NtpColdStart.ps1"
    program = f"""
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile({ps_literal(module)},[ref]$tokens,[ref]$errors)
if($errors.Count){{throw 'NTP helper parse failed.'}}
$definition=$ast.Find({{param($node)
 $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-NtpConsolePublicKey'
}},$true)
if(-not $definition){{throw 'Original console reader is missing.'}}
. ([scriptblock]::Create($definition.Extent.Text))
$script:ntpConsoleReceipts=@{{
 appliance=@{{Vmx='original-appliance.vmx';Path={ps_literal(appliance_console)} }}
 peer=@{{Vmx='original-peer.vmx';Path={ps_literal(peer_console)} }}
}}
$script:metadataMode=''
$script:observedVmx=''
$script:converterCalls=0
$script:convertedKey=''
$script:clock=[DateTime]::UtcNow
function Test-WorkstationVmRunning {{
 param([string]$Path)
 $script:observedVmx=$Path
 return $true
}}
function ConvertTo-AtlasoWorkstationSshHostKeyEvidence {{
 param([string]$PublicKey)
 $script:converterCalls++
 $script:convertedKey=$PublicKey
 return [pscustomobject]@{{PublicKey=$PublicKey;Fingerprint='SHA256:synthetic-public-key'}}
}}
function Get-Item {{
 [CmdletBinding()]
 param([string]$LiteralPath,[switch]$Force)
 $item=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $LiteralPath -Force
 $attributes=$item.Attributes
 $length=$item.Length
 if($script:metadataMode -ceq 'reparse'){{$attributes=$attributes -bor [IO.FileAttributes]::ReparsePoint}}
 if($script:metadataMode -ceq 'stale-length'){{$length=0}}
 return [pscustomobject]@{{Attributes=$attributes;Length=$length}}
}}
function Get-Date {{
 $script:clock=$script:clock.AddSeconds(301)
 return $script:clock
}}
function Start-Sleep {{ param([int]$Seconds) }}
function Invoke-Read {{
 param([string]$Role,[string]$Path,[string]$ExpectedKey,[string]$Metadata='')
 if($Role -ceq 'appliance'){{$script:ntpConsoleReceipts.appliance.Path=$Path}}
 else{{$script:ntpConsoleReceipts.peer.Path=$Path}}
 $script:metadataMode=$Metadata
 $script:clock=[DateTime]::UtcNow
 $script:observedVmx=''; $script:converterCalls=0; $script:convertedKey=''
 try {{
  $evidence=Get-NtpConsolePublicKey -Role $Role
  $names=@($evidence.PSObject.Properties.Name | Sort-Object)
  return [pscustomobject]@{{
   accepted=$true
   role_vm_matches=($script:observedVmx -ceq $(if($Role -ceq 'appliance'){{'original-appliance.vmx'}}else{{'original-peer.vmx'}}))
   parsed_key_matches=($script:convertedKey -ceq $evidence.PublicKey)
   expected_key_matches=($script:convertedKey -ceq $ExpectedKey)
   parsed_public_key=$script:convertedKey
   fingerprint_only=($evidence.Fingerprint -ceq 'SHA256:synthetic-public-key')
   evidence_fields=($names -join ',')
   converter_calls=$script:converterCalls
  }}
 }} catch {{
  return [pscustomobject]@{{accepted=$false;role_vm_matches=($script:observedVmx -ceq $(if($Role -ceq 'appliance'){{'original-appliance.vmx'}}else{{'original-peer.vmx'}}));converter_calls=$script:converterCalls}}
 }}
}}
$appliance=Invoke-Read -Role appliance -Path {ps_literal(appliance_console)} -ExpectedKey {ps_literal(appliance_key)}
$peer=Invoke-Read -Role peer -Path {ps_literal(peer_console)} -ExpectedKey {ps_literal(peer_key)}
$duplicate=Invoke-Read -Role peer -Path {ps_literal(duplicate_console)} -ExpectedKey {ps_literal(peer_key)}
$conflict=Invoke-Read -Role peer -Path {ps_literal(conflict_console)} -ExpectedKey {ps_literal(peer_key)}
$malformed=Invoke-Read -Role peer -Path {ps_literal(malformed_console)} -ExpectedKey {ps_literal(peer_key)}
$partial=Invoke-Read -Role peer -Path {ps_literal(partial_console)} -ExpectedKey {ps_literal(peer_key)}
$oversized=Invoke-Read -Role peer -Path {ps_literal(oversized_console)} -ExpectedKey {ps_literal(peer_key)} -Metadata stale-length
$reparse=Invoke-Read -Role peer -Path {ps_literal(reparse_console)} -ExpectedKey {ps_literal(peer_key)} -Metadata reparse
$sourceText=$definition.Extent.Text
$boundedSource=($sourceText.Contains('[byte[]]::new($maximumConsoleBytes + 1)') -and
 $sourceText.Contains('[IO.FileShare]::ReadWrite') -and
 $sourceText.Contains('$stream.Read($buffer, $bytesRead, $buffer.Length - $bytesRead)') -and
 -not $sourceText.Contains('ReadAllText'))
[pscustomobject]@{{
 appliance=$appliance; peer=$peer; duplicate=$duplicate; conflict=$conflict; malformed=$malformed
 partial=$partial; oversized=$oversized; reparse=$reparse; bounded_source=$boundedSource
}} | ConvertTo-Json -Compress -Depth 4
"""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    output = json.loads(result.stdout)
    for scenario, expected_key in (("appliance", appliance_key), ("peer", peer_key), ("duplicate", peer_key)):
        assert output[scenario]["accepted"] is True
        assert output[scenario]["role_vm_matches"] is True
        assert output[scenario]["parsed_key_matches"] is True
        assert output[scenario]["expected_key_matches"] is True
        assert output[scenario]["parsed_public_key"] == expected_key
        assert output[scenario]["fingerprint_only"] is True
        assert output[scenario]["evidence_fields"] == "Fingerprint,PublicKey"
        assert output[scenario]["converter_calls"] == 1
    for scenario in ("conflict", "malformed", "partial", "oversized", "reparse"):
        assert output[scenario]["accepted"] is False
        assert output[scenario]["role_vm_matches"] is True
    assert output["conflict"]["converter_calls"] == 0
    assert output["malformed"]["converter_calls"] == 0
    assert output["partial"]["converter_calls"] == 0
    assert output["oversized"]["converter_calls"] == 0
    assert output["reparse"]["converter_calls"] == 0
    assert output["bounded_source"] is True
