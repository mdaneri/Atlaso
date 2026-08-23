"""Test incremental PowerShell comment-help policy enforcement."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_powershell_help_policy_is_wired_to_exact_base_ci() -> None:
    """Keep the incremental checker and documented authoring contract in canonical CI."""
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    contributing = Path("CONTRIBUTING.md").read_text(encoding="utf-8")
    agent_policies = Path("docs/contribute/agent-policies.md").read_text(encoding="utf-8")

    assert "path: .powershell-base" in workflow
    assert "inputs.base_sha || github.event.pull_request.base.sha" in workflow
    assert "./scripts/check_powershell_help.ps1 -BaseRoot .powershell-base" in workflow
    repository_job = workflow.split("  repository-checks:", maxsplit=1)[1].split(
        "  deployment-packer:", maxsplit=1
    )[0]
    base_checkout = repository_job.index("- name: Check out repository-check base")
    powershell_check = repository_job.index(
        "- name: Enforce changed PowerShell comment help"
    )
    for whole_tree_check in (
        "npm run lint:markdown",
        "python scripts/check_repo.py",
        "python scripts/check_python_static_analysis.py",
        "python scripts/check_deployment_assets.py --mode linux",
    ):
        assert repository_job.index(whole_tree_check) < base_checkout
    assert base_checkout < powershell_check
    assert "Every new or changed `.ps1` or `.psm1` file" in contributing
    assert "comment-based help and rationale-focused comments" in agent_policies


def _initialize_checkout(path: Path, script_text: str) -> None:
    """Create one minimal tracked PowerShell checkout.

    Args:
        path: Checkout root to create.
        script_text: PowerShell source stored in the checkout.
    """
    path.mkdir()
    (path / "sample.ps1").write_text(script_text, encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=path, check=True)
    subprocess.run(["git", "add", "sample.ps1"], cwd=path, check=True)


def _run_help_check(candidate: Path, base: Path) -> subprocess.CompletedProcess[str]:
    """Run the repository PowerShell help checker against two test checkouts.

    Args:
        candidate: Candidate checkout root.
        base: Base checkout root.

    Returns:
        Completed checker process.
    """
    checker = Path("scripts/check_powershell_help.ps1").resolve()
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(checker),
            "-Root",
            str(candidate),
            "-BaseRoot",
            str(base),
        ],
        check=False,
        text=True,
        capture_output=True,
    )


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
def test_powershell_help_policy_checks_only_changed_files(tmp_path: Path) -> None:
    """Permit unchanged legacy code while requiring complete help after an edit.

    Args:
        tmp_path: Isolated filesystem root.
    """
    legacy = "param([string]$Name)\nfunction Invoke-Sample { param([string]$Value) }\n"
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _initialize_checkout(base, legacy)
    _initialize_checkout(candidate, legacy)

    unchanged = _run_help_check(candidate, base)
    assert unchanged.returncode == 0, unchanged.stderr
    assert "0 added or changed file(s)" in unchanged.stdout

    (candidate / "sample.ps1").write_text(f"{legacy}# changed\n", encoding="utf-8")
    missing_help = _run_help_check(candidate, base)
    assert missing_help.returncode != 0
    assert "sample.ps1 has no comment-based .SYNOPSIS header" in missing_help.stderr
    assert "function Invoke-Sample has no comment-based .SYNOPSIS header" in missing_help.stderr


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
def test_powershell_help_policy_requires_parameter_entries(tmp_path: Path) -> None:
    """Require parameter documentation in otherwise valid script and function help.

    Args:
        tmp_path: Isolated filesystem root.
    """
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _initialize_checkout(base, "Write-Host 'base'\n")
    documented = """<#
.SYNOPSIS
Run the sample script.

.PARAMETER Name
Name consumed by the sample.
#>
param([string]$Name)

<#
.SYNOPSIS
Run one sample function.

.PARAMETER Value
Value consumed by the sample function.
#>
function Invoke-Sample { param([string]$Value) }
"""
    _initialize_checkout(candidate, documented)

    valid = _run_help_check(candidate, base)
    assert valid.returncode == 0, valid.stderr

    undocumented = documented.replace(".PARAMETER Value\nValue consumed", "Value consumed")
    (candidate / "sample.ps1").write_text(undocumented, encoding="utf-8")
    invalid = _run_help_check(candidate, base)
    assert invalid.returncode != 0
    assert "function Invoke-Sample parameter" in invalid.stderr
    assert "'Value' has no .PARAMETER entry" in invalid.stderr


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed")
def test_powershell_help_policy_checks_signature_style_parameters(tmp_path: Path) -> None:
    """Require help for parameters declared in a function signature.

    Args:
        tmp_path: Isolated filesystem root.
    """
    base = tmp_path / "base"
    candidate = tmp_path / "candidate"
    _initialize_checkout(base, "Write-Host 'base'\n")
    signature_style = """<#
.SYNOPSIS
Run the sample script.
#>

<#
.SYNOPSIS
Run one signature-style function.
#>
function Invoke-Sample([string]$Value) {}
"""
    _initialize_checkout(candidate, signature_style)

    invalid = _run_help_check(candidate, base)
    assert invalid.returncode != 0
    assert "function Invoke-Sample parameter" in invalid.stderr
    assert "'Value' has no .PARAMETER entry" in invalid.stderr
