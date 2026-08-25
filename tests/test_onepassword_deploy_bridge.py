"""Focused execution tests for the bounded Windows 1Password SDK child."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def _embedded_child() -> str:
    source = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    start_marker = "$pythonDeploySource = @'\n"
    end_marker = "\n'@\n"
    start = source.index(start_marker) + len(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def _run_child(tmp_path: Path, mode: str) -> subprocess.CompletedProcess[str]:
    """Run the extracted deployment child against synthetic dependencies.

    Args:
        tmp_path: Isolated directory for the extracted child and fake packages.
        mode: Synthetic SDK response scenario to exercise.
    """
    dependency_path = tmp_path / "dependencies"
    package_path = dependency_path / "onepassword"
    package_path.mkdir(parents=True)
    fake_secret = "unit-test-secret-sentinel"
    (package_path / "__init__.py").write_text(
        f'''import asyncio

class DesktopAuth:
    def __init__(self, account_name):
        self.account_name = account_name

class Variable:
    def __init__(self, name, value, masked):
        self.name = name
        self.value = value
        self.masked = masked

class Environments:
    async def get_variables(self, environment_id):
        if "{mode}" == "hang-environment":
            await asyncio.sleep(3600)
        if environment_id != "atlaso-environment-id":
            raise RuntimeError("wrong environment")
        variables = []
        if "{mode}" == "success":
            variables = [Variable("DEFAULT_ADMIN_PASSWORD", "{fake_secret}", True)]
        elif "{mode}" == "unmasked":
            variables = [Variable("DEFAULT_ADMIN_PASSWORD", "{fake_secret}", False)]
        return type("Response", (), {{"variables": variables}})()

class Client:
    @staticmethod
    async def authenticate(**kwargs):
        if "{mode}" == "hang-auth":
            await asyncio.sleep(3600)
        if "{mode}" == "denied":
            raise RuntimeError("authorization denied")
        return type("Sdk", (), {{"environments": Environments()}})()
''',
        encoding="utf-8",
    )
    (dependency_path / "paramiko.py").write_text(
        '''def SSHClient():
    raise SystemExit("bridge-success")
''',
        encoding="utf-8",
    )
    child_path = tmp_path / "child.py"
    child_path.write_text(_embedded_child(), encoding="utf-8")
    args = [
        sys.executable,
        "-I",
        "-S",
        str(child_path),
        "--dependency-path",
        str(dependency_path),
        "--onepassword-account",
        mode,
        "--onepassword-environment-id",
        "atlaso-environment-id" if mode != "wrong-environment" else "wrong-environment-id",
        "--host",
        "192.0.2.10",
        "--user",
        "admin",
        "--local-wheel",
        "wheel",
        "--local-runtime-dependency",
        "runtime",
        "--local-trust-key",
        "trust",
        "--local-atlaso-service",
        "atlaso-service",
        "--local-worker-service",
        "worker-service",
        "--local-atlaso-service-drop-in",
        "atlaso-drop-in",
        "--local-nginx-service-drop-in",
        "nginx-drop-in",
        "--local-script",
        "deploy",
        "--remote-dir",
        "/tmp",
        "--remote-wheel",
        "/tmp/wheel",
        "--remote-runtime-dependency",
        "/tmp/runtime",
        "--remote-trust-key",
        "/tmp/trust",
        "--remote-atlaso-service",
        "/tmp/atlaso-service",
        "--remote-worker-service",
        "/tmp/worker-service",
        "--remote-atlaso-service-drop-in",
        "/tmp/atlaso-drop-in",
        "--remote-nginx-service-drop-in",
        "/tmp/nginx-drop-in",
        "--remote-script",
        "/tmp/deploy",
        "--timeout",
        "1",
        "--readiness-timeout",
        "1",
        "--poll",
        "1",
    ]
    return subprocess.run(args, check=False, capture_output=True, text=True)


@pytest.mark.parametrize("mode", ["denied", "wrong-environment", "hang-auth", "hang-environment"])
def test_sdk_authorization_and_environment_fail_closed(tmp_path: Path, mode: str) -> None:
    """Reject unavailable authorization and an inaccessible Environment.

    Args:
        tmp_path: Isolated directory for the extracted child and fake packages.
        mode: Synthetic SDK failure scenario to exercise.
    """
    result = _run_child(tmp_path, mode)
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "authorization or exact Environment access failed" in output
    assert "unit-test-secret-sentinel" not in output


@pytest.mark.parametrize("mode", ["missing", "unmasked"])
def test_expected_concealed_variable_is_required(tmp_path: Path, mode: str) -> None:
    """Require exactly one masked deployment-password variable.

    Args:
        tmp_path: Isolated directory for the extracted child and fake packages.
        mode: Synthetic variable-contract failure scenario to exercise.
    """
    result = _run_child(tmp_path, mode)
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "must contain one concealed DEFAULT_ADMIN_PASSWORD" in output
    assert "unit-test-secret-sentinel" not in output


def test_success_keeps_value_out_of_process_output(tmp_path: Path) -> None:
    """Keep the synthetic value out of all child-process output.

    Args:
        tmp_path: Isolated directory for the extracted child and fake packages.
    """
    result = _run_child(tmp_path, "success")
    output = result.stdout + result.stderr
    assert result.returncode != 0
    assert "bridge-success" in output
    assert "unit-test-secret-sentinel" not in output
