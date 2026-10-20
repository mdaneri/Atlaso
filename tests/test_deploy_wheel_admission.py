"""Exercise the actual embedded deployment admission against filesystem fixtures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SOURCE = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
ADMISSION = SOURCE.split("<<'ATLASO_DEPLOY_ADMISSION'\n", 1)[1].split(
    "\nATLASO_DEPLOY_ADMISSION", 1
)[0]


def _layout(home: Path, name: str = "bootstrap-0.9.426") -> Path:
    """Create a real linked environment and original bootstrap metadata.

    Args:
        home: Isolated appliance root.
        name: Release directory name.
    """
    release = home / "releases" / name
    (release / ".venv").mkdir(parents=True)
    (release / "bundle-metadata.json").write_text(json.dumps({
        "schema_version": 1, "bootstrap": True,
        "version": name.removeprefix("bootstrap-"),
    }), encoding="utf-8")
    (home / "current").symlink_to(release, target_is_directory=True)
    (home / ".venv").symlink_to(Path("current") / ".venv", target_is_directory=True)
    return release


def _admit(home: Path) -> subprocess.CompletedProcess[str]:
    """Execute the shipped admission with only the installation root relocated.

    Args:
        home: Isolated appliance root.
    """
    return subprocess.run(
        [sys.executable, "-I", "-B", "-S", "-c",
         ADMISSION.replace('Path("/opt/atlaso")', f"Path({str(home)!r})")],
        capture_output=True, text=True, check=False, timeout=30,
    )


def test_development_destinations_are_admitted(tmp_path):
    """Accept bootstrap links and legacy direct environments without changing them.

    Args:
        tmp_path: Receipted test resource root.
    """
    bootstrap = tmp_path / "bootstrap"
    release = _layout(bootstrap)
    result = _admit(bootstrap)
    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()) == release / ".venv"
    legacy = tmp_path / "legacy"
    (legacy / ".venv").mkdir(parents=True)
    result = _admit(legacy)
    assert result.returncode == 0, result.stderr
    assert Path(result.stdout.strip()) == legacy / ".venv"


@pytest.mark.parametrize("receipt", [None, "{}", "not-json", '{"version":"0.9.426"}'])
def test_signed_release_is_refused_even_without_valid_receipt(tmp_path, receipt):
    """Fail closed without modifying release bytes or trusting a receipt's version.

    Args:
        tmp_path: Receipted test resource root.
        receipt: Optional retained receipt bytes, including malformed evidence.
    """
    home = tmp_path / "atlaso"
    release = _layout(home, "0.9.426")
    path = release / ".release-manifest.json"
    if receipt is not None:
        path.write_text(receipt, encoding="utf-8")
    result = _admit(home)
    assert result.returncode == 2
    assert "signed Appliance Update" in result.stderr
    assert not result.stdout
    if receipt is not None:
        assert path.read_text(encoding="utf-8") == receipt
    else:
        assert not path.exists()
    assert (home / "current").resolve() == release


@pytest.mark.parametrize("fault", ["receipt", "dangling-receipt", "metadata", "version", "current", "external", "direct-link"])
def test_ambiguous_bootstrap_is_refused(tmp_path, fault):
    """Reject signed receipts, malformed metadata and inconsistent link destinations.

    Args:
        tmp_path: Receipted test resource root.
        fault: Filesystem inconsistency introduced into the fixture.
    """
    home = tmp_path / "atlaso"
    release = _layout(home)
    if fault == "receipt":
        (release / ".release-manifest.json").write_text("{}", encoding="utf-8")
    elif fault == "dangling-receipt":
        (release / ".release-manifest.json").symlink_to(release / "absent")
    elif fault == "metadata":
        (release / "bundle-metadata.json").write_text("[]", encoding="utf-8")
    elif fault == "version":
        (release / "bundle-metadata.json").write_text(
            '{"schema_version":1,"bootstrap":true,"version":"0.9.425"}', encoding="utf-8"
        )
    elif fault == "current":
        (home / ".venv").unlink()
        (home / ".venv").mkdir()
    elif fault == "direct-link":
        (home / ".venv").unlink()
        (home / ".venv").symlink_to(release / ".venv", target_is_directory=True)
    else:
        (home / ".venv").unlink()
        outside = tmp_path / "external"
        outside.mkdir()
        (home / ".venv").symlink_to(outside, target_is_directory=True)
    result = _admit(home)
    assert result.returncode == 2
    assert "Wheel deployment refused" in result.stderr


@pytest.mark.parametrize("guard", ["signed", "maintenance", "status", "restart", "finalizer", "durable-status"])
@pytest.mark.parametrize("wheel_version", ["0.9.425", "0.9.426", "0.9.427"])
def test_remote_shell_refuses_before_any_mutation(tmp_path, guard, wheel_version):
    """Run the admission stage with mutation tripwires and a relocated installation.

    Args:
        tmp_path: Receipted test resource root.
        guard: Retained state that must refuse deployment before mutation.
        wheel_version: Older, matching or newer proposed application wheel version.
    """
    shell = shutil.which("sh")
    if os.name == "nt":
        shell = str(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe")
    if not shell or not Path(shell).is_file():
        pytest.skip("A POSIX shell is required")
    home = tmp_path / "atlaso"
    _layout(home, "0.9.426" if guard == "signed" else "bootstrap-0.9.426")
    markers = tmp_path / "markers"
    markers.mkdir()
    paths = {
        "maintenance": "/run/atlaso-update-maintenance",
        "status": "/run/atlaso-appliance-update-status",
        "restart": "/run/atlaso-release-restart-gate",
        "finalizer": "/var/lib/atlaso/apply/appliance-update/finalizer-status.json",
        "durable-status": "/var/lib/atlaso-privileged/appliance-update-status/status.json",
    }
    if guard != "signed":
        (markers / guard).write_text("retained", encoding="utf-8")
    script = SOURCE.split("$deployScript = @'\n", 1)[1].split("\n'@", 1)[0]
    # Native POSIX locking is exercised separately against the actual kernel in
    # test_deploy_wheel_locking.py. Git Bash lacks flock and /proc/self/fd.
    lock_start = script.index("# Lock-capable installed helpers")
    lock_end = script.index("# Refuse before RPM")
    script = script[:lock_start] + script[lock_end:]
    script = script.replace("/opt/atlaso", home.as_posix())
    script = script.replace('python="$venv/bin/python"', f'python="{Path(sys.executable).as_posix()}"', 1)
    for key, path in paths.items():
        script = script.replace(path, (markers / key).as_posix())
    # Any fallthrough to package/service/asset/database mutation fails the test.
    tripwires = "\n".join(
        f'{command}() {{ echo MUTATION >&2; return 99; }}'
        for command in ("tdnf", "systemctl", "install", "find", "sqlite3", "ln", "groupadd", "usermod")
    )
    script = script.replace("set -eu", "set -eu\n" + tripwires, 1)
    result = subprocess.run(
        [shell, "-s", "--", f"atlaso-{wheel_version}-py3-none-any.whl", "60", "2",
         "", "", "", "", "", "web", "worker", "web-dropin", "nginx-dropin", "dependencies", "keys"],
        input=script, capture_output=True, text=True, check=False, timeout=30,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"},
    )
    assert result.returncode == 2, result.stderr
    assert "Wheel deployment refused" in result.stderr
    assert "MUTATION" not in result.stderr
    if guard != "signed":
        assert (markers / guard).read_text(encoding="utf-8") == "retained"
