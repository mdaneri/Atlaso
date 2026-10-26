"""Tests for the offline installer release-version resolver."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

PROVISIONER = Path("image/common/scripts/provision-atlaso.sh")
RESOLVER_START = "# ATLASO_OFFLINE_VERSION_RESOLVER_START"
RESOLVER_END = "# ATLASO_OFFLINE_VERSION_RESOLVER_END"
DEVELOPMENT_KEY_ID = "atlaso-installation-development-public-test"


def test_bootstrap_bytecode_cleanup_follows_all_venv_checks() -> None:
    """The final import checks cannot regenerate caches after package cleanup."""
    source = PROVISIONER.read_text(encoding="utf-8")
    cleanup = source.index('find "$ATLASO_SITE_PACKAGES" -type f -name \'*.pyc\' -delete')
    assert source.rindex('"$ATLASO_HOME/.venv/bin/python"') < cleanup
    assert source.rindex("write_third_party_notices\n") < cleanup
    assert source.rindex("write_build_info\n") < cleanup
    assert source.index('python3 "$BOOTSTRAP_VENV_VALIDATOR"') < cleanup
    assert source.index('find "$ATLASO_SITE_PACKAGES" -depth -type d -name __pycache__ -empty -delete') > cleanup


def _resolver():
    """Load the exact Python resolver embedded in the shared provisioner."""
    source = PROVISIONER.read_text(encoding="utf-8")
    body = source.split(RESOLVER_START, maxsplit=1)[1].split(RESOLVER_END, maxsplit=1)[0]
    module = ast.parse(body.strip())
    namespace = {"json": json, "re": re, "Path": Path}
    exec(compile(module, str(PROVISIONER), "exec"), namespace)
    return namespace["resolve_offline_release_version"]


def test_offline_media_version_drives_bootstrap_release_selection() -> None:
    """The shared provisioner uses media version only in its offline branch."""
    source = PROVISIONER.read_text(encoding="utf-8")
    assert re.search(
        r'if \[ -n "\$ATLASO_INSTALLATION_MEDIA" \]; then\s+'
        r'ATLASO_RELEASE_VERSION="\$ATLASO_OFFLINE_RELEASE_VERSION"\s+'
        r'else\s+if ! ATLASO_RELEASE_VERSION="\$\(',
        source,
    )
    assert 'ATLASO_RELEASE_DIR="$ATLASO_HOME/releases/bootstrap-$ATLASO_RELEASE_VERSION"' in source


def _manifest(media: Path, value: dict) -> None:
    """Write public test manifest metadata under an installation-media root.

    Args:
        media: Temporary media directory.
        value: Manifest data to serialize.
    """
    media.mkdir()
    (media / "payload-manifest.json").write_text(json.dumps(value), encoding="utf-8")


def _development_manifest(version: str = "0.9.455") -> dict:
    """Build a development identity with independent source commits.

    Args:
        version: Development software release version.
    """
    return {
        "schema": 1,
        "version": version,
        "source_commit": "a" * 40,
        "signing_key_id": DEVELOPMENT_KEY_ID,
        "development": {
            "schema": 1,
            "software_source_commit": "b" * 40,
            "non_production": True,
        },
    }


def test_development_manifest_version_may_differ_from_pr_source_version(tmp_path: Path) -> None:
    """Development media selects its separately bound software release version.

    Args:
        tmp_path: Pytest-owned fixture directory.
    """
    media = tmp_path / "media"
    _manifest(media, _development_manifest())

    assert _resolver()(media, "0.9.453", "VMware, Inc.") == "0.9.455"


@pytest.mark.parametrize("vendor", ["QEMU", "Microsoft Corporation", ""], ids=["qemu", "hyperv", "missing"])
def test_development_manifest_is_rejected_outside_vmware(
    tmp_path: Path, vendor: str
) -> None:
    """Development trust identity is restricted to VMware hardware.

    Args:
        tmp_path: Pytest-owned fixture directory.
        vendor: Mocked DMI sys_vendor value.
    """
    media = tmp_path / "media"
    _manifest(media, _development_manifest())

    with pytest.raises(ValueError, match="restricted to VMware"):
        _resolver()(media, "0.9.453", vendor)


def test_production_manifest_keeps_staged_project_version(tmp_path: Path) -> None:
    """Production release selection still comes from staged project metadata.

    Args:
        tmp_path: Pytest-owned fixture directory.
    """
    media = tmp_path / "media"
    _manifest(
        media,
        {
            "schema": 1,
            "version": "0.9.453",
            "source_commit": "a" * 40,
            "signing_key_id": "atlaso-release-2026-01",
        },
    )

    assert _resolver()(media, "0.9.453", "unobserved") == "0.9.453"


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(development={"schema": 1}),
        lambda value: value.update(non_production=True),
        lambda value: value.update(signing_key_id=DEVELOPMENT_KEY_ID),
    ],
    ids=["development-field", "non-production-field", "development-key-id"],
)
def test_production_manifest_rejects_development_identity_fields(
    tmp_path: Path, change
) -> None:
    """Production manifests cannot carry a development trust marker.

    Args:
        tmp_path: Pytest-owned fixture directory.
        change: Manifest mutation that introduces a development identity.
    """
    media = tmp_path / "media"
    value = {
        "schema": 1,
        "version": "0.9.453",
        "source_commit": "a" * 40,
        "signing_key_id": "atlaso-release-2026-01",
    }
    change(value)
    _manifest(media, value)

    with pytest.raises(ValueError, match="identity"):
        _resolver()(media, "0.9.453", "VMware, Inc.")


@pytest.mark.parametrize(
    "version",
    ["0.9", "dev", "0.9.455-rc.1"],
    ids=["missing-patch", "nonnumeric", "prerelease"],
)
def test_development_manifest_requires_stable_semver(
    tmp_path: Path, version: str
) -> None:
    """Reject malformed development software versions before provisioning.

    Args:
        tmp_path: Pytest-owned fixture directory.
        version: Invalid version placed in development media metadata.
    """
    media = tmp_path / "media"
    _manifest(media, _development_manifest(version))

    with pytest.raises(ValueError, match="identity is invalid"):
        _resolver()(media, "0.9.453", "VMware, Inc.")
