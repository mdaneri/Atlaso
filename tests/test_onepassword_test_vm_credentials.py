"""Focused tests for normal VMware test-VM 1Password default retrieval."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _embedded_child() -> str:
    source = Path(
        "scripts/windows/vmware/Invoke-AtlasoTestVmCredentials.ps1"
    ).read_text(encoding="utf-8")
    start_marker = "$pythonSource = @'\n"
    end_marker = "\n'@\n"
    start = source.index(start_marker) + len(start_marker)
    end = source.index(end_marker, start)
    child = source[start:end]
    protect_start = child.index("def protect_password(value):")
    protect_end = child.index("\n\n\ndef password_is_valid", protect_start)
    # Linux CI cannot call Windows DPAPI. Replace only the platform primitive;
    # the PowerShell-focused test exercises a real current-user DPAPI round trip.
    return (
        child[:protect_start]
        + 'def protect_password(value):\n    return f"protected-{len(value)}"'
        + child[protect_end:]
    )


def _run_child(
    tmp_path: Path,
    mode: str,
    *,
    admin_override: bool = False,
    root_override: bool = False,
    authentication: str = "desktop",
) -> tuple[subprocess.CompletedProcess[str], dict[str, str]]:
    """Run the extracted SDK child against a synthetic Environment.

    Args:
        tmp_path: Isolated test directory.
        mode: Synthetic SDK response scenario.
        admin_override: Whether the administrator value is already DPAPI protected.
        root_override: Whether the root value is already DPAPI protected.
        authentication: SDK authentication mode to exercise.

    Returns:
        Completed process and any protected output document.
    """
    dependency_path = tmp_path / "dependencies"
    package_path = dependency_path / "onepassword"
    package_path.mkdir(parents=True)
    secret = "unit-test-secret-sentinel-123"
    valid_admin = secret + "-admin"
    valid_root = secret + "-root"
    (package_path / "__init__.py").write_text(
        f'''import asyncio
import os

class DesktopAuth:
    def __init__(self, account_name):
        if "{authentication}" == "service-account":
            raise RuntimeError("DesktopAuth must not be invoked")
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
        variables = [
            Variable("DEFAULT_ADMIN_PASSWORD", "{valid_admin}", True),
            Variable("DEFAULT_ROOT_PASSWORD", "{valid_root}", True),
        ]
        if "{mode}" == "missing-admin":
            variables = [item for item in variables if item.name != "DEFAULT_ADMIN_PASSWORD"]
        elif "{mode}" == "missing-root":
            variables = [item for item in variables if item.name != "DEFAULT_ROOT_PASSWORD"]
        elif "{mode}" == "duplicate-admin":
            variables.append(Variable("DEFAULT_ADMIN_PASSWORD", "{valid_admin}", True))
        elif "{mode}" == "duplicate-root":
            variables.append(Variable("DEFAULT_ROOT_PASSWORD", "{valid_root}", True))
        elif "{mode}" == "unmasked-admin":
            variables[0].masked = False
        elif "{mode}" == "unmasked-root":
            variables[1].masked = False
        elif "{mode}" == "invalid-admin":
            variables[0].value = "too-short"
        elif "{mode}" == "invalid-root":
            variables[1].value = "bad\\npassword-value"
        return type("Response", (), {{"variables": variables}})()

class Client:
    @staticmethod
    async def authenticate(**kwargs):
        if "{authentication}" == "service-account" and kwargs.get("auth") != "ops_{'A' * 100}":
            raise RuntimeError("wrong service-account token")
        if os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"):
            raise RuntimeError("service-account token remained in the environment")
        if "{mode}" == "hang-auth":
            await asyncio.sleep(3600)
        if "{mode}" == "denied":
            raise RuntimeError("authorization denied")
        return type("Sdk", (), {{"environments": Environments()}})()
''',
        encoding="utf-8",
    )
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "output.json"
    request_path.write_text(
        json.dumps(
            {
                "AdminPasswordCiphertext": "explicit-admin-dpapi"
                if admin_override
                else "",
                "RootPasswordCiphertext": "explicit-root-dpapi"
                if root_override
                else "",
            }
        ),
        encoding="utf-8",
    )
    child_path = tmp_path / "child.py"
    child_path.write_text(_embedded_child(), encoding="utf-8")
    environment = os.environ.copy()
    environment["DEFAULT_ADMIN_PASSWORD"] = "caller-admin-must-not-be-used"
    environment["DEFAULT_ROOT_PASSWORD"] = "caller-root-must-not-be-used"
    if authentication == "service-account":
        environment["OP_SERVICE_ACCOUNT_TOKEN"] = "ops_" + "A" * 100
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(child_path),
            "--dependency-path",
            str(dependency_path),
            "--onepassword-authentication",
            authentication,
            "--onepassword-account",
            "atlaso-test-account",
            "--onepassword-environment-id",
            "atlaso-environment-id" if mode != "wrong-environment" else "wrong-id",
            "--request",
            str(request_path),
            "--output",
            str(output_path),
            "--timeout",
            "1",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    output = json.loads(output_path.read_text(encoding="utf-8")) if output_path.exists() else {}
    assert secret not in result.stdout + result.stderr
    assert "caller-admin-must-not-be-used" not in result.stdout + result.stderr
    assert "caller-root-must-not-be-used" not in result.stdout + result.stderr
    return result, output


@pytest.mark.parametrize("mode", ["denied", "wrong-environment", "hang-auth", "hang-environment"])
def test_sdk_access_failures_are_bounded_and_secret_free(tmp_path: Path, mode: str) -> None:
    """Reject unavailable desktop authorization or exact Environment access.

    Args:
        tmp_path: Isolated test directory.
        mode: Synthetic SDK failure scenario.
    """
    result, output = _run_child(tmp_path, mode)
    assert result.returncode == 20
    assert not output


@pytest.mark.parametrize(
    ("mode", "expected_code"),
    [
        ("missing-admin", 21),
        ("duplicate-admin", 21),
        ("unmasked-admin", 21),
        ("missing-root", 22),
        ("duplicate-root", 22),
        ("unmasked-root", 22),
    ],
)
def test_each_omitted_variable_must_be_unique_and_concealed(
    tmp_path: Path, mode: str, expected_code: int
) -> None:
    """Require one concealed variable for each omitted credential.

    Args:
        tmp_path: Isolated test directory.
        mode: Synthetic variable-contract failure.
        expected_code: Safe machine-readable child exit code.
    """
    result, output = _run_child(tmp_path, mode)
    assert result.returncode == expected_code
    assert not output


@pytest.mark.parametrize(("mode", "expected_code"), [("invalid-admin", 23), ("invalid-root", 24)])
def test_retrieved_password_policy_is_enforced(
    tmp_path: Path, mode: str, expected_code: int
) -> None:
    """Reject policy-invalid retrieved values before emitting a bundle.

    Args:
        tmp_path: Isolated test directory.
        mode: Synthetic invalid-password scenario.
        expected_code: Safe machine-readable child exit code.
    """
    result, output = _run_child(tmp_path, mode)
    assert result.returncode == expected_code
    assert not output


@pytest.mark.parametrize(
    ("admin_override", "root_override", "expected_fields"),
    [
        (False, False, {"AdminPasswordCiphertext", "RootPasswordCiphertext"}),
        (True, False, {"RootPasswordCiphertext"}),
        (False, True, {"AdminPasswordCiphertext"}),
    ],
)
def test_explicit_overrides_remain_independently_authoritative(
    tmp_path: Path,
    admin_override: bool,
    root_override: bool,
    expected_fields: set[str],
) -> None:
    """Retrieve only the credential whose SecureString parameter was omitted.

    Args:
        tmp_path: Isolated test directory.
        admin_override: Whether the administrator override is explicit.
        root_override: Whether the root override is explicit.
        expected_fields: Defaults that the child must return.
    """
    result, output = _run_child(
        tmp_path,
        "success",
        admin_override=admin_override,
        root_override=root_override,
    )
    assert result.returncode == 0
    assert set(output) == expected_fields
    assert all(value.startswith("protected-") for value in output.values())


def test_service_account_authentication_avoids_desktop_auth_and_clears_environment(
    tmp_path: Path,
) -> None:
    """Authenticate directly with the service token and remove its environment copy."""
    result, output = _run_child(
        tmp_path,
        "success",
        authentication="service-account",
    )

    assert result.returncode == 0
    assert set(output) == {"AdminPasswordCiphertext", "RootPasswordCiphertext"}
    assert "ops_" not in result.stdout + result.stderr


@pytest.mark.parametrize("mode", ["denied", "wrong-environment"])
def test_service_account_revocation_or_environment_denial_fails_closed(
    tmp_path: Path, mode: str
) -> None:
    """Reject a revoked token or missing exact-Environment grant without output."""
    result, output = _run_child(
        tmp_path,
        mode,
        authentication="service-account",
    )

    assert result.returncode == 20
    assert not output
    assert "ops_" not in result.stdout + result.stderr
