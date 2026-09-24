"""Keep the signed lifecycle example aligned with its PowerShell entry point."""

import re
from pathlib import Path


def test_signed_lifecycle_example_uses_declared_parameters() -> None:
    """Reject unsupported parameters in the published signed-fixture command."""
    guide = Path("docs/operate/appliance-update.md").read_text(encoding="utf-8")
    section = re.search(r"## Signed lifecycle fixture\n(.*?)(?=\n## |\Z)", guide, re.DOTALL)
    assert section is not None
    example = re.search(r"```powershell\n(.*?)\n```", section.group(1), re.DOTALL)
    assert example is not None
    command = example.group(1)
    target = re.search(r"(?m)^\s*(scripts/windows/vmware/[\w-]+\.ps1)\b", command)
    assert target is not None
    script = Path(target.group(1)).read_text(encoding="utf-8")
    parameter_block = script.split("$ErrorActionPreference", 1)[0]
    declared = set(re.findall(r"\]\s*\$([A-Za-z][A-Za-z0-9]*)\b", parameter_block))
    used = set(re.findall(r"(?m)^\s*-([A-Za-z][A-Za-z0-9]*)\b", command))
    assert used
    assert used <= declared, f"Undeclared parameters in signed lifecycle example: {used - declared}"


def test_signed_lifecycle_fixture_url_reaches_python_checker() -> None:
    """Keep the documented URL wired through both PowerShell entry points."""
    wrapper = Path("scripts/windows/vmware/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    runner = Path("scripts/windows/vmware/run-lifecycle-test.ps1").read_text(encoding="utf-8")
    checker = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")
    assert "@('-SignedReleaseRepositoryUrl', $SignedReleaseRepositoryUrl)" in wrapper
    assert "@('--signed-release-repository-url', $SignedReleaseRepositoryUrl)" in runner
    guard = "if ($SignedReleaseRepositoryUrl -and ($OidcOnly -or $RoutingWanOnly))"
    assert guard in wrapper
    assert guard in runner
    assert wrapper.index(guard) < wrapper.index("if (-not $SkipClientPrepare")
    assert runner.index(guard) < runner.index("$sourceCommit =")
    assert "signed_release_update_check = [bool]$SignedReleaseRepositoryUrl" in runner
    assert "preview availability check and upgrade, development availability check and rollback, and two audited appliance reboots" in runner
    assert runner.index("$initialPythonArgs =") < runner.index("@('--signed-release-repository-url', $SignedReleaseRepositoryUrl)")
    assert runner.index("@('--signed-release-repository-url', $SignedReleaseRepositoryUrl)") < runner.index("$restoredPythonArgs =")
    assert '"--signed-release-repository-url"' in checker
