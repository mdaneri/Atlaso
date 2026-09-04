"""Focused contracts for non-interactive 1Password service-account authentication."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_dpapi_setup_rotation_acl_and_child_environment_isolation() -> None:
    """Exercise the Windows-only setup helper and token-scoped child launcher."""
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
            "tests/powershell/Test-AtlasoOnePasswordServiceAccount.ps1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "service-account tests passed" in result.stdout
    assert "ops_" not in result.stdout + result.stderr


def test_token_contract_is_never_transportable_as_plaintext() -> None:
    """Keep service tokens out of public parameters, generated arguments, and files."""
    root = Path("scripts/windows/vmware")
    module = (root / "Atlaso.OnePasswordCredentials.psm1").read_text(encoding="utf-8")
    sdk_child = (root / "Invoke-AtlasoOnePasswordCredentials.ps1").read_text(
        encoding="utf-8"
    )
    test_vm_child = (root / "Invoke-AtlasoTestVmCredentials.ps1").read_text(
        encoding="utf-8"
    )
    launcher = (root / "Invoke-AtlasoServiceAccountCommand.ps1").read_text(
        encoding="utf-8"
    )

    assert "[SecureString]$Token" in (
        root / "initialize-onepassword-service-account.ps1"
    ).read_text(encoding="utf-8")
    assert "OP_SERVICE_ACCOUNT_TOKEN must not be supplied by the caller" in module
    assert "--onepassword-service-account-token" not in sdk_child + test_vm_child
    assert "OP_SERVICE_ACCOUNT_TOKEN'] = $serviceAccountTokenText" in sdk_child
    assert "OP_SERVICE_ACCOUNT_TOKEN'] = $serviceAccountTokenText" in test_vm_child
    assert 'os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)' in sdk_child
    assert 'os.environ.pop("OP_SERVICE_ACCOUNT_TOKEN", None)' in test_vm_child
    assert "TokenFile" in launcher
    assert "PlainTextToken" not in launcher
    assert "ReparsePoint" in module
    assert "ConvertTo-SecureString -String $tokenCiphertext" in sdk_child


def test_all_requested_entry_points_expose_the_dpapi_token_file() -> None:
    """Keep the service-account selector available across every VMware workflow."""
    entry_points = [
        "build-photon-image.ps1",
        "create-atlaso-test-vm.ps1",
        "deploy-wheel.ps1",
        "export-ovf.ps1",
    ]
    for name in entry_points:
        source = Path("scripts/windows/vmware", name).read_text(encoding="utf-8")
        assert ".PARAMETER OnePasswordServiceAccountTokenFile" in source
        assert "[string]$OnePasswordServiceAccountTokenFile = ''" in source


def test_setup_destination_and_deploy_preflight_order_fail_closed() -> None:
    """Restrict durable storage and admit the SDK wheel before account discovery."""
    root = Path("scripts/windows/vmware")
    setup = (root / "initialize-onepassword-service-account.ps1").read_text(
        encoding="utf-8"
    )
    deploy = (root / "deploy-wheel.ps1").read_text(encoding="utf-8")

    assert "$atlasoLocalPrefix" in setup
    assert "must be stored beneath this checkout''s .atlaso-local" in setup
    assert "must not traverse a reparse point" in setup
    wheel_stage = deploy.index("if ($UsePasswordDeploy) {", deploy.index("$onePasswordAuthentication"))
    authentication = deploy.index(
        "$onePasswordAuthentication = Resolve-AtlasoOnePasswordAuthentication `",
        wheel_stage,
    )
    vmware_discovery = deploy.index("$resolvedVmrun = ''", authentication)
    assert wheel_stage < authentication < vmware_discovery


def test_virtualization_prerelease_rejects_inherited_service_tokens_first() -> None:
    """Keep inherited service tokens away from Git and GitHub subprocesses."""
    source = Path(
        "scripts/windows/virtualization/Atlaso.VirtualizationRelease.psm1"
    ).read_text(encoding="utf-8")
    prerelease = source.index("function Invoke-AtlasoVirtualizationPrerelease")
    guard = source.index("if ($env:OP_SERVICE_ACCOUNT_TOKEN)", prerelease)
    first_subprocess_helper = source.index(
        "$repository = Get-AtlasoReleaseRepository", prerelease
    )

    assert guard < first_subprocess_helper


def test_service_account_access_depends_only_on_the_exact_environment() -> None:
    """Do not introduce a vault lookup into service-account authentication."""
    sources = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "scripts/windows/vmware/Invoke-AtlasoOnePasswordCredentials.ps1",
            "scripts/windows/vmware/Invoke-AtlasoTestVmCredentials.ps1",
            "scripts/windows/vmware/deploy-wheel.ps1",
        )
    )

    assert ".environments.get_variables(" in sources
    assert ".vaults." not in sources
    assert "--onepassword-environment-id" in sources
