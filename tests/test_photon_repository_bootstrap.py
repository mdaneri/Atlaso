"""Focused tests for Photon image-build repository preparation."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path("image/common/scripts/configure_photon_repositories.py")
PINNED_GPG_KEY = Path("image/common/photon-rpm-gpg/VMWARE-RPM-GPG-KEY-4096")
PINNED_SOURCE_KEY_SHA256 = (
    "88b2e118c08f0a7c2acc172ac9b8557a30677ffaff5060d304697bee75028bc7"
)
PINNED_GA_INSTALLED_KEY_SHA256 = (
    "8f4cb443e17f533a78c72f1f7f7d7e1b739622bb8c2d2ac8444ac3fcf85e8307"
)


def load_configurator() -> ModuleType:
    """Load the image-build repository configurator as a test module."""

    spec = importlib.util.spec_from_file_location(
        "configure_photon_repositories", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_repository(
    path: Path,
    *,
    baseurl: str,
    gpgcheck: str = "1",
    gpgkey: str = "file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY-4096",
) -> None:
    """Write one stock-shaped Photon updates repository.

    Args:
        path: Temporary repository path.
        baseurl: Repository base URL under test.
        gpgcheck: GPG verification flag under test.
        gpgkey: Space-separated RPM signing key URI set under test.
    """

    path.write_text(
        "[photon-updates]\n"
        "name=VMware Photon Linux $releasever ($basearch) Updates\n"
        f"baseurl={baseurl}\n"
        f"gpgkey={gpgkey}\n"
        f"gpgcheck={gpgcheck}\n"
        "enabled=1\n"
        "skip_if_unavailable=1\n",
        encoding="utf-8",
    )


def test_legacy_ga_updates_repository_is_canonicalized_before_refresh(
    tmp_path: Path,
) -> None:
    """Replace the retired GA layout only after trust and reachability pass.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """

    configurator = load_configurator()
    repository = tmp_path / "photon-updates.repo"
    write_repository(
        repository,
        baseurl=(
            "https://packages.vmware.com/photon/updates/$releasever/"
            "photon_updates_$releasever_$basearch"
        ),
        gpgkey=(
            "file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY "
            "file:///etc/pki/rpm-gpg/VMWARE-RPM-GPG-KEY-4096"
        ),
    )
    observed: dict[str, str | int] = {}

    def run_probe(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        payload = Path(command[command.index("--output") + 1])
        payload.write_text(
            '<repomd xmlns="http://linux.duke.edu/metadata/repo" />',
            encoding="utf-8",
        )
        observed["url"] = command[-1]
        observed["curl_timeout"] = command[command.index("--max-time") + 1]
        observed["process_timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=f"200\n{configurator.CANONICAL_METADATA_URL}",
            stderr="",
        )

    assert configurator.configure_photon_updates_repository(
        repository, PINNED_GPG_KEY, run_probe
    )
    canonical = repository.read_text(encoding="utf-8")
    assert f"baseurl={configurator.CANONICAL_BASEURL}\n" in canonical
    assert "gpgcheck=1\n" in canonical
    assert f"gpgkey={configurator.CANONICAL_GPG_KEY_URI}\n" in canonical
    assert "packages.vmware.com" not in canonical
    assert observed == {
        "url": configurator.CANONICAL_METADATA_URL,
        "curl_timeout": str(configurator.PROBE_TIMEOUT_SECONDS),
        "process_timeout": (
            configurator.PROBE_TIMEOUT_SECONDS
            + configurator.PROBE_PROCESS_GRACE_SECONDS
        ),
    }


def test_trusts_upstream_source_and_ga_installed_key_serializations() -> None:
    """Pin both approved byte representations of the same Photon signing key."""

    configurator = load_configurator()

    assert configurator.TRUSTED_GPG_KEY_SHA256S == {
        PINNED_SOURCE_KEY_SHA256,
        PINNED_GA_INSTALLED_KEY_SHA256,
    }


def test_provisioner_prepares_repository_before_first_tdnf_refresh() -> None:
    """Keep the trusted repository gate ahead of every TDNF transaction."""

    provisioner = Path("image/common/scripts/provision-atlaso.sh").read_text(
        encoding="utf-8"
    )
    preparation = provisioner.index('python3 "$PHOTON_REPOSITORY_CONFIGURATOR"')
    first_tdnf = provisioner.index(
        'run_tdnf "Photon package metadata refresh" makecache'
    )
    assert preparation < first_tdnf
    assert "--nogpgcheck" not in provisioner


@pytest.mark.parametrize(
    ("baseurl", "gpgcheck", "message"),
    [
        (
            "https://mirror.example/photon/5.0/updates",
            "1",
            "not an approved Photon 5 layout",
        ),
        (
            "https://packages.broadcom.com/photon/$releasever/"
            "photon_updates_$releasever_$basearch",
            "0",
            "must enforce GPG checks",
        ),
    ],
)
def test_untrusted_repository_configuration_fails_closed(
    tmp_path: Path, baseurl: str, gpgcheck: str, message: str
) -> None:
    """Reject an unexpected source or disabled package signatures.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
        baseurl: Repository URL under test.
        gpgcheck: GPG verification setting under test.
        message: Expected sanitized diagnostic fragment.
    """

    configurator = load_configurator()
    repository = tmp_path / "photon-updates.repo"
    write_repository(repository, baseurl=baseurl, gpgcheck=gpgcheck)

    with pytest.raises(configurator.PhotonRepositoryError, match=message):
        configurator.configure_photon_updates_repository(
            repository,
            PINNED_GPG_KEY,
            lambda *_args, **_kwargs: pytest.fail("probe must not run"),
        )


def test_unreachable_canonical_metadata_fails_before_repository_rewrite(
    tmp_path: Path,
) -> None:
    """Keep the legacy file intact when the trusted endpoint is unreachable.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """

    configurator = load_configurator()
    repository = tmp_path / "photon-updates.repo"
    legacy = (
        "https://packages.vmware.com/photon/updates/$releasever/"
        "photon_updates_$releasever_$basearch"
    )
    write_repository(repository, baseurl=legacy)
    original = repository.read_bytes()

    def fail_probe(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("curl", configurator.PROBE_TIMEOUT_SECONDS)

    with pytest.raises(
        configurator.PhotonRepositoryError,
        match="Canonical Photon 5 updates metadata is unreachable",
    ):
        configurator.configure_photon_updates_repository(
            repository, PINNED_GPG_KEY, fail_probe
        )
    assert repository.read_bytes() == original


def test_substituted_signing_key_fails_before_repository_probe(tmp_path: Path) -> None:
    """Reject a regular, permission-safe file with the wrong key identity.

    Args:
        tmp_path: Pytest-provided isolated filesystem root.
    """

    configurator = load_configurator()
    repository = tmp_path / "photon-updates.repo"
    substituted_key = tmp_path / "VMWARE-RPM-GPG-KEY-4096"
    write_repository(repository, baseurl=configurator.CANONICAL_BASEURL)
    substituted_key.write_text("substituted public key\n", encoding="utf-8")

    with pytest.raises(
        configurator.PhotonRepositoryError,
        match="does not match the pinned upstream identity",
    ):
        configurator.configure_photon_updates_repository(
            repository,
            substituted_key,
            lambda *_args, **_kwargs: pytest.fail("probe must not run"),
        )
