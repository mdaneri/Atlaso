"""Static contract checks for durable installation refresh selectors."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts/windows/vmware/invoke-installation-iso-test.ps1"
NATIVE = ROOT / "scripts/windows/vmware/test-installation-iso.ps1"
HELPER = ROOT / "scripts/windows/vmware/Atlaso.InstallationRefreshReceipt.psm1"


@pytest.mark.skipif(os.name != "nt" or shutil.which("pwsh") is None, reason="Native PowerShell module scopes")
def test_selector_import_preserves_the_callers_cleanup_commands(tmp_path: Path) -> None:
    """Keep post-install stop and disk verification available after receipt publication.

    Args:
        tmp_path: Owned temporary directory for the isolated PowerShell process.
    """
    script = r"""
$ErrorActionPreference='Stop'
$vmware=Join-Path $env:ISO_RECEIPT_REPOSITORY 'scripts/windows/vmware'
Import-Module (Join-Path $vmware 'Atlaso.WorkstationCleanup.psm1') -Force
$before=Get-Command Confirm-AtlasoWorkstationVmInactive -ErrorAction Stop
Import-Module (Join-Path $vmware 'Atlaso.InstallationRefreshReceipt.psm1') -Force
$after=Get-Command Confirm-AtlasoWorkstationVmInactive -ErrorAction Stop
if ($before.Module -ne $after.Module) { throw 'Caller cleanup module was replaced' }
Get-Command Get-AtlasoPathIdentity -ErrorAction Stop | Out-Null
Get-Command Publish-AtlasoInstallationRefreshSelector -ErrorAction Stop | Out-Null
"""
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", script], capture_output=True, encoding="utf-8", timeout=60,
        env={**os.environ, "ISO_RECEIPT_REPOSITORY": str(ROOT), "TEMP": str(tmp_path), "TMP": str(tmp_path)},
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_receipt_directory_is_validated_before_child_or_vm_work() -> None:
    source = HARNESS.read_text(encoding="utf-8")

    validation = source.index("Assert-AtlasoInstallationRefreshReceiptDirectory")
    child_branch = source.index("if (-not $Child)")
    ownership_context = source.index("New-AtlasoTestVmOwnershipContext")
    assert validation < child_branch < ownership_context
    assert "'-ReceiptDirectory', $ReceiptDirectory" in source


def test_selector_publisher_pins_and_durably_publishes_bounded_json() -> None:
    source = HELPER.read_text(encoding="utf-8")

    assert "Get-AtlasoLifecycleDurableRoot" in source
    assert "PinOrdinaryDirectoryPath($directory, $true)" in source
    assert "PinOrdinaryDirectoryPath([string]$Directory.Path, $true)" in source
    assert "PinOrdinaryReadFile($path, $true)" in source
    assert "if ($bytes.Length -gt 65536)" in source
    assert "PublishDurableFile($writer, $path, $false)" in source
    assert "ValidateSet('vm-original-selectors.json', 'vm-selectors.json', 'boot-selectors.json')" in source


def test_vm_and_boot_selectors_use_original_returned_objects_and_receipts() -> None:
    source = NATIVE.read_text(encoding="utf-8")
    vm_return = source.index("$original = Publish-InstallationVmOriginalReceipt")
    vm_publish = source.index("-Filename 'vm-selectors.json'", vm_return)
    vm_console_wait = source.index("Start-InstallationIsoVm", vm_return)
    assert vm_return < vm_publish < vm_console_wait
    assert "OriginalReceiptPath = $original.Path" in source[vm_return:vm_publish]
    assert "OriginalReceiptSha256 = $original.Sha256" in source[vm_return:vm_publish]
    original_publish = source.index("-Filename 'vm-original-selectors.json'", vm_return)
    first_disk = source.index("'Create receipt-bound installation target disk'", vm_return)
    assert vm_return < original_publish < first_disk < vm_publish
    boot_return = source.index("$published = Publish-AtlasoTestVmOwnershipRecord -Context $context -Record $transition -Kind installation-boot")
    boot_publish = source.index("-Filename 'boot-selectors.json'", boot_return)
    assert boot_return < boot_publish
    boot_write = source.index("$writer.Write($after", boot_return)
    assert boot_publish < boot_write
    assert "BootReceiptPath = $published.Path" in source[boot_publish:boot_write]
    assert "BootReceiptSha256 = $published.Sha256" in source[boot_publish:boot_write]


def test_selector_payload_binds_task_source_and_media_without_fallback_scans() -> None:
    source = NATIVE.read_text(encoding="utf-8")

    assert source.count("task_id = $context.TaskId") >= 2
    assert source.count("source_commit = $context.SourceCommit") >= 2
    assert "media = $original.installation_iso" in source
    assert "media = $iso" in source
