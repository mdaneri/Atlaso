"""Test Photon package cleanup runtime verification."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


def load_verifier():
    """Load the image-time Photon package-state verifier."""

    path = Path("image/common/scripts/verify-photon-package-state.py")
    spec = importlib.util.spec_from_file_location("verify_photon_package_state", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_photon_package_state"] = module
    spec.loader.exec_module(module)
    return module


def write_release_state(root: Path) -> tuple[Path, Path, Path]:
    """Write one valid isolated Photon release and TDNF configuration."""

    etc = root / "etc"
    (etc / "tdnf").mkdir(parents=True)
    os_release = etc / "os-release"
    photon_release = etc / "photon-release"
    tdnf_config = etc / "tdnf" / "tdnf.conf"
    os_release.write_text(
        'NAME="VMware Photon OS"\nID=photon\nVERSION_ID="5.0"\n',
        encoding="utf-8",
    )
    photon_release.write_text(
        "VMware Photon OS 5.0\nPHOTON_BUILD_NUMBER=isolated-test\n",
        encoding="utf-8",
    )
    tdnf_config.write_text(
        "[main]\nclean_requirements_on_remove=1\n"
        "distroverpkg=photon-release-5.0-6.ph5.noarch\n",
        encoding="utf-8",
    )
    return os_release, photon_release, tdnf_config


def test_package_cleanup_transaction_preserves_runtime_with_noautoremove(
    tmp_path: Path,
) -> None:
    """Execute an isolated package transaction and retain the runtime closure."""

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "open-vm-tools",
        "rpm-build",
        "glib-devel",
        "systemd-devel",
        "pkg-config",
    }

    def remove_build_packages(*, noautoremove: bool) -> None:
        installed.difference_update(
            {"rpm-build", "glib-devel", "systemd-devel", "pkg-config"}
        )
        if not noautoremove:
            installed.difference_update({"rpm", "tdnf", "photon-release"})
            os_release.unlink()
            photon_release.unlink()

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        package = command[-1]
        return subprocess.CompletedProcess(
            command,
            0 if package in installed else 1,
            stdout=f"{package}\n" if package in installed else "",
            stderr="" if package in installed else "not installed\n",
        )

    remove_build_packages(noautoremove=True)
    distroverpkg = verifier.verify_photon_package_state(
        os_release_path=os_release,
        photon_release_path=photon_release,
        tdnf_config_path=tdnf_config,
        guest_platform="vmware",
        runner=fake_rpm,
    )
    assert distroverpkg == "photon-release-5.0-6.ph5.noarch"
    assert not {"rpm-build", "glib-devel", "systemd-devel", "pkg-config"} & installed


def test_package_cleanup_transaction_rejects_autoremoved_release_identity(
    tmp_path: Path,
) -> None:
    """Reject the regression produced by Photon's automatic dependency removal."""

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    os_release.unlink()
    photon_release.unlink()

    with pytest.raises(ValueError, match="release identity file is missing or empty"):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
        )


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        ("[main]\n", "photon-release"),
        (
            "[main]\ndistroverpkg=photon-release-5.0-6.ph5.noarch\n",
            "photon-release-5.0-6.ph5.noarch",
        ),
    ],
)
def test_package_cleanup_resolves_effective_distroverpkg(
    tmp_path: Path, config: str, expected: str
) -> None:
    """Resolve an explicit package or Photon's shipped default."""

    verifier = load_verifier()
    _, _, tdnf_config = write_release_state(tmp_path)
    tdnf_config.write_text(config, encoding="utf-8")

    assert verifier.read_distroverpkg(tdnf_config) == expected


def test_package_cleanup_rejects_unsafe_distroverpkg(tmp_path: Path) -> None:
    """Reject an explicit package identity that cannot be queried safely."""

    verifier = load_verifier()
    _, _, tdnf_config = write_release_state(tmp_path)
    tdnf_config.write_text("[main]\ndistroverpkg=../../unsafe\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a valid RPM package identity"):
        verifier.read_distroverpkg(tdnf_config)
