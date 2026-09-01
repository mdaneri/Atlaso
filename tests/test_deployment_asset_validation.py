"""Test the protected declarative deployment validation contract."""

import re
import shutil
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest

from scripts.check_deployment_assets import (
    ATLASO_DATA_DISK_DROPIN,
    NGINX_DATA_DISK_DROPIN,
    PACKER_CHECKSUM,
    PACKER_TEMPLATES,
    SYSTEMD_ASSETS,
    inventory_assets,
    validate_manager_dropins,
    validate_packer,
    validate_sudoers,
    validate_systemd,
)
from scripts.check_packer_plugins import validate_packer_plugins

SYSTEMD_ANALYZE = shutil.which("systemd-analyze")
VISUDO = shutil.which("visudo")


def write_inventory(root: Path) -> None:
    """Create the minimum complete deployment inventory under a test root.

    Args:
        root: Temporary repository root to populate.
    """
    for relative in PACKER_TEMPLATES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('source "example" "test" {}\n', encoding="utf-8")

    for relative in SYSTEMD_ASSETS:
        systemd = root / relative
        systemd.parent.mkdir(parents=True, exist_ok=True)
        if relative in {ATLASO_DATA_DISK_DROPIN, NGINX_DATA_DISK_DROPIN}:
            contents = "[Unit]\nRequires=atlaso-data-disks.service\n"
        elif systemd.suffix == ".conf":
            contents = "[Manager]\nShowStatus=no\n"
        else:
            contents = "[Service]\nExecStart=/bin/true\n"
        systemd.write_text(contents, encoding="utf-8")

    for relative in (Path("image/common/sudoers.d/atlaso-helper"),):
        sudoers = root / relative
        sudoers.parent.mkdir(parents=True, exist_ok=True)
        sudoers.write_text(
            "atlaso ALL=(root) /opt/atlaso/bin/atlaso-helper *\n",
            encoding="utf-8",
        )


def test_inventory_covers_packer_systemd_and_extensionless_sudoers(tmp_path: Path) -> None:
    """Verify that the complete supported inventory is deterministic and non-empty.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)

    inventory, findings = inventory_assets(tmp_path)

    assert findings == []
    assert len(inventory.packer) == 1
    assert len(inventory.systemd) == len(SYSTEMD_ASSETS)
    assert [path.name for path in inventory.sudoers] == ["atlaso-helper"]


def test_inventory_rejects_missing_canonical_packer_target(tmp_path: Path) -> None:
    """Verify that removing one required platform template fails closed.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    (tmp_path / PACKER_TEMPLATES[0]).unlink()

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == tmp_path / PACKER_TEMPLATES[0]
        and finding.message == "required Packer template is missing"
        for finding in findings
    )


def test_inventory_rejects_unclassified_systemd_file_type(tmp_path: Path) -> None:
    """Verify that a new deployment type requires an explicit validator decision.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
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
    """Verify that nested Packer HCL cannot fall outside the target inventory.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    nested = tmp_path / "image/vmware-workstation/modules/example.pkr.hcl"
    nested.parent.mkdir()
    nested.write_text('source "example" "nested" {}\n', encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == nested and finding.message.startswith("unsupported nested Packer asset")
        for finding in findings
    )


def test_pre_commit_selector_covers_inventory_wide_packer_assets() -> None:
    """Verify that future and nested Packer targets enter the deployment hook."""
    repository = Path(__file__).resolve().parents[1]
    config = (repository / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    hook = config.split("- id: atlaso-deployment-asset-check", maxsplit=1)[1]
    match = re.search(r"^\s*files:\s*'([^']+)'", hook, flags=re.MULTILINE)

    assert match is not None
    selector = re.compile(match.group(1))
    assert selector.search("image/kvm/atlaso-photon.pkr.hcl")
    assert selector.search("image/vmware-workstation/modules/example.pkr.hcl")
    assert selector.search("image/common/systemd/atlaso-worker.service")
    assert selector.search("image/common/sudoers.d/atlaso-helper")
    assert selector.search("image/inventory-linux/wsl-build-contract.json") is None
    assert re.search(r"^\s*always_run:\s*true\s*$", hook, flags=re.MULTILINE)


def test_inventory_rejects_unrecognized_platform_deployment_tree(tmp_path: Path) -> None:
    """Verify that a future platform requires one explicit platform-wide policy update.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    packer = tmp_path / "image/kvm/atlaso-photon.pkr.hcl"
    packer.parent.mkdir()
    packer.write_text('source "example" "kvm" {}\n', encoding="utf-8")
    systemd = tmp_path / "image/kvm/systemd"
    systemd.mkdir()
    (systemd / "atlaso.service").write_text("[Service]\nUnknown=yes\n", encoding="utf-8")
    sudoers = tmp_path / "image/kvm/sudoers.d"
    sudoers.mkdir()
    (sudoers / "atlaso-helper").write_text("invalid\n", encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(finding.path == packer and "supported platform allowlist" in finding.message for finding in findings)
    assert any(finding.path == systemd and "unsupported platform systemd directory" in finding.message for finding in findings)
    assert any(finding.path == sudoers and "unsupported platform sudoers directory" in finding.message for finding in findings)


def test_inventory_rejects_common_platform_systemd_collision(tmp_path: Path) -> None:
    """Verify that a platform unit cannot shadow a common unit during native validation.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    collision = tmp_path / "image/vmware-workstation/systemd/atlaso-worker.service"
    collision.write_text("[Service]\nDefinitelyNotARealSetting=yes\n", encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == collision and "basename collides with a common asset" in finding.message
        for finding in findings
    )


@pytest.mark.parametrize(
    ("relative", "contents", "expected"),
    (
        (
            Path("image/vmware-workstation/systemd/extra.service"),
            "[Service]\nExecStart=/bin/true\n",
            "systemd asset is absent from the provisioning allowlist",
        ),
        (
            Path("image/common/sudoers.d/extra-helper"),
            "atlaso ALL=(root) /bin/true\n",
            "sudoers asset is absent from the provisioning allowlist",
        ),
    ),
)
def test_inventory_rejects_assets_absent_from_provisioning_allowlist(
    tmp_path: Path,
    relative: Path,
    contents: str,
    expected: str,
) -> None:
    """Verify that validated files cannot be silently omitted from image provisioning.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
        relative: Extra deployment asset path relative to the repository.
        contents: Valid-looking contents for the extra asset.
        expected: Expected allowlist-failure prefix.
    """
    write_inventory(tmp_path)
    extra = tmp_path / relative
    extra.write_text(contents, encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(finding.path == extra and finding.message.startswith(expected) for finding in findings)


def test_inventory_rejects_missing_canonical_systemd_asset(tmp_path: Path) -> None:
    """Verify that renaming a provisioned unit cannot bypass the filename contract.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
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
        Path("image/common/sudoers.d/nested"),
    ),
)
def test_inventory_rejects_nested_managed_entries(tmp_path: Path, relative: Path) -> None:
    """Verify that managed directories cannot hide nested deployment assets.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
        relative: Managed-directory-relative nested entry under test.
    """
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
    """Verify that a renamed valid fragment cannot bypass the provisioning filename contract.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    required = tmp_path / "image/common/sudoers.d/atlaso-helper"
    required.rename(required.with_name("renamed-helper"))

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == required
        and finding.message == "required sudoers fragment is missing"
        for finding in findings
    )


def test_inventory_rejects_suffixed_sudoers_fragment(tmp_path: Path) -> None:
    """Verify that backup or other suffixed sudoers files cannot enter validation.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    unsupported = tmp_path / "image/common/sudoers.d/atlaso-helper.bak"
    unsupported.write_text("atlaso ALL=(root) /bin/true\n", encoding="utf-8")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == unsupported and "extensionless filenames" in finding.message
        for finding in findings
    )


def test_inventory_rejects_symlinked_managed_asset(tmp_path: Path) -> None:
    """Verify that a symlink cannot masquerade as a direct regular deployment file.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    target = tmp_path / "outside.service"
    target.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    link = tmp_path / "image/vmware-workstation/systemd/linked.service"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")

    _, findings = inventory_assets(tmp_path)

    assert any(
        finding.path == link and "unsupported symbolic link" in finding.message
        for finding in findings
    )


def test_inventory_rejects_symlinked_required_asset_parent(tmp_path: Path) -> None:
    """Verify that required paths cannot hide behind a symlinked platform directory.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_inventory(tmp_path)
    platform = tmp_path / "image/vmware-workstation"
    external = tmp_path / "external-vmware"
    platform.rename(external)
    try:
        platform.symlink_to(external, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symbolic links are unavailable: {error}")

    _, findings = inventory_assets(tmp_path)

    required = platform / "atlaso-photon.pkr.hcl"
    assert any(
        finding.path == required and finding.message == "required Packer template is missing"
        for finding in findings
    )


def test_packer_validation_uses_wrapper_guard_and_template_directory(tmp_path: Path) -> None:
    """Verify that full validation mirrors the wrapper's required values and working directory.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    template = tmp_path / "image/vmware-workstation/atlaso-photon.pkr.hcl"
    template.parent.mkdir(parents=True)
    template.write_text("packer {}\n", encoding="utf-8")
    plugin = tmp_path / "packer-plugin-vmware_v2.1.5_x5.0_windows_amd64.exe"
    plugin.touch()
    completed = [
        Mock(returncode=0, stdout="", stderr=""),
        Mock(
            returncode=0,
            stdout=f'vmware github.com/vmware/vmware "= 2.1.5" {plugin}\n',
            stderr="",
        ),
        Mock(returncode=0, stdout="", stderr=""),
        Mock(returncode=0, stdout="", stderr=""),
    ]

    with patch("scripts.check_deployment_assets.subprocess.run", side_effect=completed) as run:
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
            ["packer", "plugins", "required", "."],
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
                "-var",
                "vm_name=Atlaso-PR-1-Photon-Builder-VMware",
                "-var",
                "output_directory=C:/atlaso-validation/Atlaso-PR-1-Photon-Builder-VMware",
                ".",
            ],
            cwd=template.parent,
            capture_output=True,
            text=True,
            check=False,
        ),
    ]


@pytest.mark.parametrize(
    ("constraint", "selected_version", "expected"),
    (
        (">= 1.1.3", "1.1.5", "must use one exact X.Y.Z version"),
        ("= 1.1.5", "1.1.3", "requires 1.1.5 but Packer selected"),
    ),
)
def test_packer_plugin_resolution_rejects_ranges_and_mismatched_binaries(
    tmp_path: Path,
    constraint: str,
    selected_version: str,
    expected: str,
) -> None:
    """Verify that validation binds the declared version to the selected executable.

    Args:
        tmp_path: Temporary directory supplied by pytest.
        constraint: Required-plugin constraint reported by Packer.
        selected_version: Version encoded in the selected plugin filename.
        expected: Expected validation finding fragment.
    """
    plugin = tmp_path / f"packer-plugin-vmware_v{selected_version}_x5.0_windows_amd64.exe"
    plugin.touch()
    completed = Mock(
        returncode=0,
        stdout=f'vmware github.com/vmware/vmware "{constraint}" {plugin}\n',
        stderr="",
    )

    with patch("scripts.check_packer_plugins.subprocess.run", return_value=completed):
        findings = validate_packer_plugins(tmp_path, "packer")

    assert len(findings) == 1
    assert expected in findings[0]


def test_supported_packer_templates_pin_reviewed_exact_plugins() -> None:
    """Verify that the canonical image target retains its reviewed exact plugin."""
    repository = Path(__file__).resolve().parents[1]
    expected = {
        "image/vmware-workstation/atlaso-photon.pkr.hcl": (
            'version = "= 2.1.5"',
            'source  = "github.com/vmware/vmware"',
        ),
    }

    for relative, markers in expected.items():
        template = (repository / relative).read_text(encoding="utf-8")
        for marker in markers:
            assert marker in template

    wrapper = (repository / "scripts/windows/common/Atlaso.PhotonImage.psm1").read_text(
        encoding="utf-8"
    )
    init = "& packer init ."
    verify = (
        "& python $pluginCheckScript --packer "
        "(Get-Command packer -ErrorAction Stop).Source $packerDir"
    )
    execute = "& packer @packerArgs"
    assert "..\\..\\check_packer_plugins.py" in wrapper
    assert wrapper.index(init) < wrapper.index(verify) < wrapper.index(execute)


def write_systemd_fixture(root: Path, service_text: str) -> None:
    """Create the canonical unit set and a valid manager drop-in.

    Args:
        root: Temporary repository root to populate.
        service_text: Common worker service contents under test.
    """
    common = root / "image/common/systemd"
    common.mkdir(parents=True)
    (common / "atlaso-worker.service").write_text(service_text, encoding="utf-8")
    (common / "atlaso-console-manager.conf").write_text(
        "[Manager]\nShowStatus=no\n",
        encoding="utf-8",
    )
    (common / NGINX_DATA_DISK_DROPIN.name).write_text(
        "[Unit]\nAfter=atlaso-data-disks.service\nRequires=atlaso-data-disks.service\n",
        encoding="utf-8",
    )
    (common / ATLASO_DATA_DISK_DROPIN.name).write_text(
        "[Unit]\nAfter=atlaso-data-disks.service\nRequires=atlaso-data-disks.service\n",
        encoding="utf-8",
    )
    (common / "atlaso.service").write_text(
        "[Service]\nExecStart=/bin/true\n",
        encoding="utf-8",
    )
    platform = root / "image/vmware-workstation/systemd"
    platform.mkdir(parents=True)
    (platform / "atlaso-vmware-ovf-customize.service").write_text(
        "[Service]\nExecStart=/bin/true\n",
        encoding="utf-8",
    )


def test_systemd_validation_rejects_malformed_manager_dropin(tmp_path: Path) -> None:
    """Verify that an unknown manager directive fails even when cat-config accepts it.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    manager = tmp_path / "atlaso-console-manager.conf"
    manager.write_text("[Manager]\nDefinitelyNotARealSetting=yes\n", encoding="utf-8")

    findings = validate_manager_dropins((manager,))

    assert findings
    assert "unsupported [Manager] directive DefinitelyNotARealSetting" in findings[0].message


@pytest.mark.skipif(SYSTEMD_ANALYZE is None, reason="requires systemd-analyze")
def test_systemd_validation_rejects_malformed_unit(tmp_path: Path) -> None:
    """Verify that native systemd parsing rejects an invalid section header.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_systemd_fixture(tmp_path, "[Service\nExecStart=/bin/true\n")

    findings = validate_systemd(SYSTEMD_ANALYZE or "", tmp_path)

    assert findings
    assert "systemd-analyze verify failed" in findings[0].message


@pytest.mark.skipif(SYSTEMD_ANALYZE is None, reason="requires systemd-analyze")
def test_systemd_validation_rejects_ignored_unit_directive(tmp_path: Path) -> None:
    """Verify that native systemd diagnostics fail even when verify exits successfully.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    write_systemd_fixture(
        tmp_path,
        "[Service]\nExecStart=/bin/true\nDefinitelyNotARealSetting=yes\n",
    )

    findings = validate_systemd(SYSTEMD_ANALYZE or "", tmp_path)

    assert findings
    assert "systemd-analyze verify failed" in findings[0].message


@pytest.mark.skipif(VISUDO is None, reason="requires visudo")
def test_sudoers_validation_rejects_malformed_rule(tmp_path: Path) -> None:
    """Verify that native sudoers parsing rejects malformed command syntax.

    Args:
        tmp_path: Temporary repository root supplied by pytest.
    """
    sudoers = tmp_path / "image/common/sudoers.d/atlaso-helper"
    sudoers.parent.mkdir(parents=True)
    sudoers.write_text("atlaso ALL=(root) NOPASSWD:\n", encoding="utf-8")

    findings = validate_sudoers(
        (sudoers,),
        VISUDO or "",
        tmp_path,
    )

    assert findings
    assert "visudo -cf failed" in findings[0].message
