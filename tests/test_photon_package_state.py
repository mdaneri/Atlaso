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
    """Write one valid isolated Photon release and TDNF configuration.

    Args:
        root: Temporary filesystem root for the release files.
    """

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
    """Execute an isolated package transaction and retain the runtime closure.

    Args:
        tmp_path: Temporary filesystem root for the package transaction.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
        "rpm-build",
        "glib-devel",
        "systemd-devel",
        "pkg-config",
    }

    def remove_build_packages(*, noautoremove: bool) -> None:
        """Remove the simulated build closure.

        Args:
            noautoremove: Whether to preserve runtime dependency packages.
        """
        installed.difference_update(
            {"rpm-build", "glib-devel", "systemd-devel", "pkg-config"}
        )
        if not noautoremove:
            installed.difference_update({"rpm", "tdnf", "photon-release"})
            os_release.unlink()
            photon_release.unlink()

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """
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
        image_root=tmp_path,
        runner=fake_rpm,
    )
    assert distroverpkg == "photon-release-5.0-6.ph5.noarch"
    assert not {"rpm-build", "glib-devel", "systemd-devel", "pkg-config"} & installed


@pytest.mark.parametrize("missing_package", ["ntpsec", "python3-ntp"])
def test_package_cleanup_rejects_missing_ntpsec_runtime(
    tmp_path: Path, missing_package: str
) -> None:
    """Reject an image that lost either required NTPsec runtime package.

    Args:
        tmp_path: Temporary filesystem root for the package transaction.
        missing_package: Required NTPsec package omitted from the image.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
    }
    installed.remove(missing_package)

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """
        package = command[-1]
        return subprocess.CompletedProcess(
            command,
            0 if package in installed else 1,
            stdout=f"{package}\n" if package in installed else "",
            stderr="" if package in installed else "not installed\n",
        )

    with pytest.raises(
        ValueError,
        match=f"Required Photon runtime package is not installed: {missing_package}",
    ):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
            image_root=tmp_path,
            runner=fake_rpm,
        )


def test_package_cleanup_rejects_installed_cloud_init(tmp_path: Path) -> None:
    """Reject an image that retains the unsupported cloud-init lifecycle.

    Args:
        tmp_path: Temporary filesystem root for the package transaction.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
        "cloud-init",
    }

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """

        package = command[-1]
        return subprocess.CompletedProcess(command, 0 if package in installed else 1)

    with pytest.raises(
        ValueError,
        match="Unsupported Photon runtime package is installed: cloud-init",
    ):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
            image_root=tmp_path,
            runner=fake_rpm,
        )


@pytest.mark.parametrize(
    "relative_path",
    (
        "usr/lib/systemd/system-generators/cloud-init-generator",
        "usr/lib/systemd/system/cloud-config.service",
    ),
)
def test_package_cleanup_rejects_cloud_init_runtime_path(
    tmp_path: Path, relative_path: str
) -> None:
    """Reject a stale cloud-init runtime path after package removal.

    Args:
        tmp_path: Temporary filesystem root for the simulated runtime path.
        relative_path: Unsupported path retained beneath the image root.
    """

    verifier = load_verifier()
    os_release, photon_release, tdnf_config = write_release_state(tmp_path)
    runtime_path = tmp_path / relative_path
    runtime_path.parent.mkdir(parents=True)
    runtime_path.write_text("stale", encoding="utf-8")
    installed = {
        "photon-release-5.0-6.ph5.noarch",
        "photon-release",
        "rpm",
        "tdnf",
        "python3",
        "powershell",
        "ntpsec",
        "python3-ntp",
        "open-vm-tools",
    }

    def fake_rpm(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        """Return simulated RPM query results.

        Args:
            command: RPM command and queried package identity.
            **_: Unused subprocess keyword arguments.
        """

        package = command[-1]
        return subprocess.CompletedProcess(command, 0 if package in installed else 1)

    with pytest.raises(ValueError, match="cloud-init runtime path remains"):
        verifier.verify_photon_package_state(
            os_release_path=os_release,
            photon_release_path=photon_release,
            tdnf_config_path=tdnf_config,
            guest_platform="vmware",
            image_root=tmp_path,
            runner=fake_rpm,
        )


def test_package_cleanup_rejects_dangling_cloud_init_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject a dangling symlink at a forbidden cloud-init runtime path.

    Args:
        tmp_path: Temporary filesystem root for the simulated runtime path.
        monkeypatch: Pytest helper used to simulate link-aware metadata.
    """

    verifier = load_verifier()
    runtime_path = tmp_path / "usr/lib/cloud-init"
    original_lstat = Path.lstat

    def fake_lstat(path: Path):
        """Report the forbidden path as a dangling link directory entry.

        Args:
            path: Filesystem path inspected by the verifier.
        """

        if path == runtime_path:
            return original_lstat(tmp_path)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(ValueError, match="cloud-init runtime path remains"):
        verifier.verify_paths_absent((runtime_path,))


def test_package_cleanup_transaction_rejects_autoremoved_release_identity(
    tmp_path: Path,
) -> None:
    """Reject the regression produced by Photon's automatic dependency removal.

    Args:
        tmp_path: Temporary filesystem root for the regressed release state.
    """

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
            image_root=tmp_path,
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
    """Resolve an explicit package or Photon's shipped default.

    Args:
        tmp_path: Temporary filesystem root for the TDNF configuration.
        config: TDNF configuration content to inspect.
        expected: Expected effective distro version package.
    """

    verifier = load_verifier()
    _, _, tdnf_config = write_release_state(tmp_path)
    tdnf_config.write_text(config, encoding="utf-8")

    assert verifier.read_distroverpkg(tdnf_config) == expected


def test_package_cleanup_rejects_unsafe_distroverpkg(tmp_path: Path) -> None:
    """Reject an explicit package identity that cannot be queried safely.

    Args:
        tmp_path: Temporary filesystem root for the unsafe configuration.
    """

    verifier = load_verifier()
    _, _, tdnf_config = write_release_state(tmp_path)
    tdnf_config.write_text("[main]\ndistroverpkg=../../unsafe\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a valid RPM package identity"):
        verifier.read_distroverpkg(tdnf_config)
