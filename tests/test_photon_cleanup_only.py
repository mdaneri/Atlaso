"""Fail-closed admission tests for Photon staging-only recovery."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path("scripts/windows/vmware/build-photon-image.ps1").resolve()


@pytest.mark.parametrize(
    "arguments",
    [
        ["-CleanupOnly"],
        ["-Cleanup"],
        ["-WhatIf"],
        ["-CleanupOnly", "-LocalBuilder"],
        ["-CleanupOnly", "-CleanupRepositoryRoot", "relative", "-CleanupRootIdentity", "invalid"],
    ],
)
def test_cleanup_entry_rejects_ambiguous_inputs(arguments: list[str]) -> None:
    """Recovery cannot accidentally admit a build or an unbound target.

    Args:
        arguments: Invalid public command selection.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is unavailable")
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(WRAPPER), *arguments],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert result.returncode != 0
    assert "Cleanup" in result.stderr
    assert "PowerCLI refresh" not in result.stdout


@pytest.mark.parametrize("case", ["preview", "wrong_identity", "process_unproven"])
def test_retained_marker_requires_identity_and_process_proofs(tmp_path: Path, case: str) -> None:
    """Preview preserves state; mismatches and unproven descendants block retirement.

    Args:
        tmp_path: Isolated task-owned fixture directory.
        case: Recovery boundary to exercise.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is unavailable")
    root = tmp_path / "credentials" / ("atlaso-photon-build-credentials-" + "a" * 32)
    root.mkdir(parents=True)
    marker_path = tmp_path / "marker.json"
    marker = {
        "Schema": 3,
        "RootPath": str(root),
        "RootIdentity": "original",
        "BootIdentity": "current",
        "Phase": "active",
        "OwnerProcessId": 123,
        "OwnerProcessStartFileTimeUtc": 456,
        "ProcessJobName": "Local\\Atlaso-Photon-" + "a" * 32,
        "ChildProcessId": 789,
        "ChildProcessStartFileTimeUtc": 101112,
        "ProcessOwnershipPhase": "assigned",
    }
    marker_bytes = json.dumps(marker).encode()
    marker_path.write_bytes(marker_bytes)
    script = tmp_path / "probe.ps1"
    script.write_text(
        r"""
param($Wrapper, $Repository, $MarkerPath, $Case)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Wrapper, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Wrapper parse failed' }
$function = $ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-AtlasoPhotonBuildCleanupRecovery'}, $true)
Invoke-Expression $function.Extent.Text
function Assert-AtlasoStrictDescendantPath { param($ParentPath, $ChildPath, $FailureMessage) }
function Get-AtlasoPathIdentity { param($Path, $Description) return 'original' }
function Get-AtlasoWindowsBootIdentityState { param($BootIdentity) return 'current' }
function Complete-AtlasoPhotonSameBootProcessRecovery { param($Marker) throw 'Descendant quiescence unproven' }
function Complete-AtlasoPhotonBuildCleanup { throw 'Retirement must not be reached' }
$expected = if ($Case -eq 'wrong_identity') { 'replacement' } else { 'original' }
try {
    Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $MarkerPath -RepositoryRoot $Repository `
        -AllowedParentRoots @(Join-Path $Repository 'credentials') -ExpectedRootIdentity $expected `
        -Preview:($Case -eq 'preview') | ConvertTo-Json -Compress
    if ($Case -ne 'preview') { throw 'Unsafe recovery unexpectedly succeeded' }
} catch {
    if ($Case -eq 'preview') { throw }
    if ($_.Exception.InnerException.Message -notmatch 'original task-recorded|quiescence unproven') { throw }
    'preserved'
}
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [pwsh, "-NoProfile", "-File", str(script), str(WRAPPER), str(tmp_path), str(marker_path), case],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert marker_path.read_bytes() == marker_bytes
    assert root.is_dir()
    if case == "preview":
        assert json.loads(result.stdout)["Status"] == "inspected"
    else:
        assert result.stdout.strip() == "preserved"
