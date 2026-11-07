"""Exercise the canonical Windows VMware hostname-generation and preflight boundary."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_vmware_hostname_limit_before_clone(tmp_path: Path) -> None:
    """Keep generated identities observable and refuse oversized overrides before cloning.

    Args:
        tmp_path: Isolated synthetic VMX and preserved-output directory.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required")
    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoWorkstationHostnameLimit.ps1",
            "-RepositoryRoot",
            str(Path.cwd()),
            "-OutputDirectory",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Atlaso Workstation hostname-limit tests passed." in result.stdout
