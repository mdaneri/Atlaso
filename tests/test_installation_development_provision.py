"""Offline regressions for signed software installation during provisioning."""

from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import json
import os
import re
import shlex
import subprocess
import venv
from pathlib import Path
from zipfile import ZipFile

import pytest

PROVISIONER = Path("image/common/scripts/provision-atlaso.sh")
RESOLVER_START = "# ATLASO_OFFLINE_VERSION_RESOLVER_START"
RESOLVER_END = "# ATLASO_OFFLINE_VERSION_RESOLVER_END"
DEVELOPMENT_KEY_ID = "atlaso-installation-development-public-test"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PROVISION_SCRIPT = REPOSITORY_ROOT / "image/common/scripts/provision-atlaso.sh"


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


def _signed_wheel(path: Path, value: str) -> tuple[str, str]:
    """Write one small valid wheel and return its requirement/hash identity."""
    name = "atlaso_seed_probe"
    version = "1.0.0"
    dist_info = f"{name}-{version}.dist-info"
    members = {
        f"{name}/__init__.py": f"VALUE = {value!r}\n".encode(),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            "Name: atlaso-seed-probe\n"
            f"Version: {version}\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
    }
    rows = []
    for member, content in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        rows.append((member, f"sha256={digest}", str(len(content))))
    record_name = f"{dist_info}/RECORD"
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows([*rows, (record_name, "", "")])
    with ZipFile(path, "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)
        archive.writestr(record_name, output.getvalue())
    requirement = f"atlaso-seed-probe=={version}"
    return requirement, hashlib.sha256(path.read_bytes()).hexdigest()


def _signed_dependency_install_tokens() -> list[str]:
    """Extract the signed lock install command from shared provisioning source."""
    lines = PROVISION_SCRIPT.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if not line.strip().startswith("PIP_CONFIG_FILE=/dev/null ") or "-m pip install" not in line:
            continue
        command_lines = []
        current = index
        while True:
            part = lines[current].rstrip()
            continued = part.endswith("\\")
            command_lines.append(part[:-1] if continued else part)
            if not continued:
                break
            current += 1
        tokens = shlex.split(" ".join(command_lines), posix=True)
        requirement = tokens.index("--requirement") if "--requirement" in tokens else -1
        if requirement >= 0 and "requirements-wheelhouse.lock" in tokens[requirement + 1]:
            return tokens
    raise AssertionError("signed wheelhouse dependency install command was not found")


def test_signed_provisioning_install_replaces_same_version_seed_wheel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The signed locked wheel must replace a different preinstalled same-version wheel."""
    atlaso_home = tmp_path / "atlaso"
    environment = atlaso_home / ".venv"
    environment_python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    cache = tmp_path / "pip-cache"
    monkeypatch.setenv("PIP_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.setenv("PIP_CACHE_DIR", str(cache))
    venv.EnvBuilder(with_pip=True).create(environment)

    seed_wheel = tmp_path / "atlaso_seed_probe-1.0.0-py3-none-any.whl"
    seed_requirement, _seed_digest = _signed_wheel(seed_wheel, "seed")
    subprocess.run(
        [
            str(environment_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            str(seed_wheel),
        ],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PIP_CACHE_DIR": str(cache)},
    )

    wheelhouse = tmp_path / "wheelhouse" / "cp314"
    wheelhouse.mkdir(parents=True)
    locked_wheel = wheelhouse / "atlaso_seed_probe-1.0.0-py3-none-any.whl"
    locked_requirement, locked_digest = _signed_wheel(locked_wheel, "locked")
    assert locked_requirement == seed_requirement
    lock = wheelhouse / "requirements-wheelhouse.lock"
    lock.write_text(
        f"{locked_requirement} --hash=sha256:{locked_digest}\n",
        encoding="utf-8",
    )

    tokens = _signed_dependency_install_tokens()
    assert tokens[0] == "PIP_CONFIG_FILE=/dev/null"
    arguments = tokens[1:]
    arguments[0] = str(environment_python)
    arguments[arguments.index("--find-links") + 1] = str(wheelhouse)
    arguments[arguments.index("--requirement") + 1] = str(lock)
    subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PIP_CACHE_DIR": str(cache)},
    )

    observed = subprocess.run(
        [
            str(environment_python),
            "-c",
            "import importlib.metadata, atlaso_seed_probe; "
            "print(importlib.metadata.version('atlaso-seed-probe')); "
            "print(atlaso_seed_probe.VALUE)",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert observed == ["1.0.0", "locked"]
