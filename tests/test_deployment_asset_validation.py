"""Test the protected declarative deployment validation contract."""

import re
import shutil
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest

from scripts.check_deployment_assets import (
    PACKER_CHECKSUM,
    PACKER_TEMPLATES,
    SYSTEMD_ASSETS,
    inventory_assets,
    validate_manager_dropins,
    validate_packer,
    validate_sudoers,
    validate_systemd,
)


def write_inventory(root: Path) -> None:
    """Create the minimum complete deployment inventory under a test root."""
    for relative in PACKER_TEMPLATES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('source "example" "test" {}\n', encoding="utf-8")

    for relative in SYSTEMD_ASSETS:
        systemd = root / relative
        systemd.parent.mkdir(parents=True, exist_ok=True)
        contents = (
            "[Manager]\nShowStatus=no\n"
            if systemd.suffix == ".conf"
            else "[Service]\nExecStart=/bin/true\n"
        )
        systemd.write_text(contents, encoding="utf-8")

    for platform in ("hyperv", "vmware-workstation"):
        sudoers = root / f"image/{platform}/sudoers.d/atlaso-helper"
        sudoers.parent.mkdir(parents=True, exist_ok=True)
        sudoers.write_text(
            "atlaso ALL=(root) /opt/atlaso/bin/atlaso-helper *\n",
            encoding="utf-8",
        )


def test_inventory_covers_packer_systemd_and_extensionless_sudoers(tmp_path: Path) -> None:
    """Verify that the complete supported inventory is deterministic and non-empty."""
    write_inventory(tmp_path)

    inventory, findings = inventory_assets(tmp_path)

    assert findings == []
    assert len(inventory.packer) == 2
    assert len(inventory.systemd) == len(SYSTEMD_ASSETS)
    assert [path.name for path in inventory.sudoers] == ["atlaso-helper", "atlaso-helper"]


def test_inventory_rejects_missing_canonical_packer_target(tmp_path: Path) -> None:
    """Verify that removing one required platform template fails closed."""
    write_inventory(tmp_path)
    (tmp_path / PACKER_TEMPLATES[0]).unlink()

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == tmp_path / PACKER_TEMPLATES[0]
        and finding.message == "required Packer template is missing"
        for finding in findings
    )


def test_inventory_rejects_unclassified_systemd_file_type(tmp_path: Path) -> None:
    """Verify that a new deployment type requires an explicit validator decision."""
    write_inventory(tmp_path)
    unsupported = tmp_path / "image/common/systemd/atlaso.timer"
    unsupported.write_text("[Timer]\nOnBootSec=1m\n", encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == unsupported
        and "add a validator or reviewed exclusion" in finding.message
        for finding in findings
    )


def test_inventory_rejects_nested_packer_asset(tmp_path: Path) -> None:
    """Verify that nested Packer HCL cannot fall outside the target inventory."""
    write_inventory(tmp_path)
    nested = tmp_path / "image/hyperv/modules/example.pkr.hcl"
    nested.parent.mkdir()
    nested.write_text('source "example" "nested" {}\n', encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == nested and finding.message.startswith("unsupported nested Packer asset")
        for finding in findings
    )


def test_pre_commit_selector_covers_inventory_wide_packer_assets() -> None:
    """Verify that direct future targets and nested rejected HCL enter the deployment hook."""
    repository = Path(__file__).resolve().parents[1]
    config = (repository / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    hook = config.split("- id: atlaso-deployment-asset-check", maxsplit=1)[1]
    match = re.search(r"^\s*files:\s*'([^']+)'", hook, flags=re.MULTILINE)

    assert match is not None
    selector = re.compile(match.group(1))
    assert selector.search("image/kvm/atlaso-photon.pkr.hcl")
    assert selector.search("image/hyperv/modules/example.pkr.hcl")
    assert selector.search("image/common/systemd/atlaso-worker.service")
    assert selector.search("image/vmware-workstation/sudoers.d/atlaso-helper")
    assert selector.search("image/inventory-linux/wsl-build-contract.json") is None


def test_inventory_rejects_common_platform_systemd_collision(tmp_path: Path) -> None:
    """Verify that a platform unit cannot shadow a common unit during native validation."""
    write_inventory(tmp_path)
    collision = tmp_path / "image/hyperv/systemd/atlaso-worker.service"
    collision.write_text("[Service]\nDefinitelyNotARealSetting=yes\n", encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == collision and "basename collides with a common asset" in finding.message
        for finding in findings
    )


def test_inventory_rejects_missing_canonical_systemd_asset(tmp_path: Path) -> None:
    """Verify that renaming a provisioned unit cannot bypass the filename contract."""
    write_inventory(tmp_path)
    required = tmp_path / "image/common/systemd/atlaso-console.service"
    required.rename(required.with_name("renamed-console.service"))

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == required and finding.message == "required systemd asset is missing"
        for finding in findings
    )


@pytest.mark.parametrize(
    "relative",
    (
        Path("image/common/systemd/atlaso.service.d"),
        Path("image/hyperv/sudoers.d/nested"),
    ),
)
def test_inventory_rejects_nested_managed_entries(tmp_path: Path, relative: Path) -> None:
    """Verify that managed directories cannot hide nested deployment assets."""
    write_inventory(tmp_path)
    nested = tmp_path / relative
    nested.mkdir()
    (nested / "ignored.conf").write_text("ignored\n", encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == nested and "managed asset directories require direct regular files" in finding.message
        for finding in findings
    )


def test_inventory_rejects_missing_canonical_sudoers_fragment(tmp_path: Path) -> None:
    """Verify that a renamed valid fragment cannot bypass the provisioning filename contract."""
    write_inventory(tmp_path)
    required = tmp_path / "image/vmware-workstation/sudoers.d/atlaso-helper"
    required.rename(required.with_name("renamed-helper"))

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == required
        and finding.message == "required sudoers fragment is missing"
        for finding in findings
    )


def test_inventory_rejects_suffixed_sudoers_fragment(tmp_path: Path) -> None:
    """Verify that backup or other suffixed sudoers files cannot enter validation."""
    write_inventory(tmp_path)
    unsupported = tmp_path / "image/hyperv/sudoers.d/atlaso-helper.bak"
    unsupported.write_text("atlaso ALL=(root) /bin/true\n", encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == unsupported and "extensionless filenames" in finding.message
        for finding in findings
    )


def test_inventory_rejects_symlinked_managed_asset(tmp_path: Path) -> None:
    """Verify that a symlink cannot masquerade as a direct regular deployment file."""
    write_inventory(tmp_path)
    target = tmp_path / "outside.service"
    target.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    link = tmp_path / "image/hyperv/systemd/linked.service"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == link and "unsupported symbolic link" in finding.message
        for finding in findings
    )


def test_packer_validation_uses_wrapper_guard_and_template_directory(tmp_path: Path) -> None:
    """Verify that full validation mirrors the wrapper's required values and working directory."""
    template = tmp_path / "image/hyperv/atlaso-photon.pkr.hcl"
    template.parent.mkdir(parents=True)
    template.write_text("packer {}\n", encoding="utf-8")
    completed = Mock(returncode=0, stdout="", stderr="")

    with patch("scripts.check_deployment_assets.subprocess.run", return_value=completed) as run:
        findings = validate_packer((template,), "packer")

    assert findings == []
    assert run.call_args_list == [
        call(
            ["packer", "init", "."],
            cwd=template.parent,
            capture_output=True,
            text=True,
            check=False,
        ),
        call(
            ["packer", "fmt", "-check", "-diff", template.name],
            cwd=template.parent,
            capture_output=True,
            text=True,
            check=False,
        ),
        call(
            [
                "packer",
                "validate",
                "-var",
                "iso_url=https://example.invalid/atlaso-photon.iso",
                "-var",
                f"iso_checksum={PACKER_CHECKSUM}",
                "-var",
                "iso_contains_kickstart=true",
                ".",
            ],
            cwd=template.parent,
            capture_output=True,
            text=True,
            check=False,
        ),
    ]


def write_systemd_fixture(root: Path, service_text: str) -> None:
    """Create both platform unit sets and a valid manager drop-in."""
    common = root / "image/common/systemd"
    common.mkdir(parents=True)
    (common / "atlaso-worker.service").write_text(service_text, encoding="utf-8")
    (common / "atlaso-console-manager.conf").write_text(
        "[Manager]\nShowStatus=no\n",
        encoding="utf-8",
    )
    for platform in ("hyperv", "vmware-workstation"):
        directory = root / f"image/{platform}/systemd"
        directory.mkdir(parents=True)
        (directory / "atlaso.service").write_text(
            "[Service]\nExecStart=/bin/true\n",
            encoding="utf-8",
        )


def test_systemd_validation_rejects_malformed_manager_dropin(tmp_path: Path) -> None:
    """Verify that an unknown manager directive fails even when cat-config accepts it."""
    manager = tmp_path / "atlaso-console-manager.conf"
    manager.write_text("[Manager]\nDefinitelyNotARealSetting=yes\n", encoding="utf-8")

    findings = validate_manager_dropins((manager,))

    assert findings
    assert "unsupported [Manager] directive DefinitelyNotARealSetting" in findings[0].message


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="requires systemd-analyze")
def test_systemd_validation_rejects_malformed_unit(tmp_path: Path) -> None:
    """Verify that native systemd parsing rejects an invalid section header."""
    write_systemd_fixture(tmp_path, "[Service\nExecStart=/bin/true\n")

    findings = validate_systemd(shutil.which("systemd-analyze") or "", tmp_path)

    assert findings
    assert "systemd-analyze verify failed" in findings[0].message


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="requires systemd-analyze")
def test_systemd_validation_rejects_ignored_unit_directive(tmp_path: Path) -> None:
    """Verify that native systemd diagnostics fail even when verify exits successfully."""
    write_systemd_fixture(
        tmp_path,
        "[Service]\nExecStart=/bin/true\nDefinitelyNotARealSetting=yes\n",
    )

    findings = validate_systemd(shutil.which("systemd-analyze") or "", tmp_path)

    assert findings
    assert "systemd-analyze verify failed" in findings[0].message


@pytest.mark.skipif(shutil.which("visudo") is None, reason="requires visudo")
def test_sudoers_validation_rejects_malformed_rule(tmp_path: Path) -> None:
    """Verify that native sudoers parsing rejects malformed command syntax."""
    sudoers = tmp_path / "image/hyperv/sudoers.d/atlaso-helper"
    sudoers.parent.mkdir(parents=True)
    sudoers.write_text("atlaso ALL=(root) NOPASSWD:\n", encoding="utf-8")

    findings = validate_sudoers(
        (sudoers,),
        shutil.which("visudo") or "",
        tmp_path,
    )

    assert findings
    assert "visudo -cf failed" in findings[0].message
