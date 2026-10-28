"""Tests for ISO-bound read-only installed identity and payload inspection."""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pycdlib
import pytest

from scripts.installation import inspection
from scripts.installation.inspection import (
    expected_inputs,
    guest_program,
    validate_report,
)


def _add(iso: pycdlib.PyCdlib, iso_path: str, rr_name: str, content: bytes) -> None:
    """Add public bytes to a synthetic Rock Ridge ISO.

    Args:
        iso: Synthetic open ISO fixture.
        iso_path: ISO9660 member path.
        rr_name: Public Rock Ridge member name.
        content: Public member bytes.
    """
    stream = io.BytesIO(content)
    iso.add_fp(stream, len(content), iso_path=iso_path, rr_name=rr_name)


def _iso(path: Path, *, development: bool = True) -> str:
    """Create minimal development or production media and return its digest.

    Args:
        path: Task-owned output file.
        development: Whether to include the explicit non-production marker.
    """
    version = "0.9.453"
    commit = "b" * 40
    release = json.dumps({"version": version, "git_commit": commit}).encode()
    wheel_name = f"atlaso-{version}-py3-none-any.whl"
    wheel = b"wheel bytes"
    software_source = {
        "version": version,
        "source_commit": commit,
        "release_manifest_sha256": hashlib.sha256(release).hexdigest(),
        "application_wheel": f"packages/{wheel_name}",
        "application_wheel_sha256": hashlib.sha256(wheel).hexdigest(),
    }
    inventory = {
        "software/release-manifest.json": release,
        "software/virtualization-source.json": json.dumps(software_source).encode(),
        f"software/packages/{wheel_name}": wheel,
        "source/image/common/scripts/verify-template-software.py": b"verifier source",
        "source/scripts/interop/routing_deployment_inspection.py": b"inspector source",
    }
    files = [
        {"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        for name, content in sorted(inventory.items())
    ]
    manifest = {
        "schema": 1,
        "version": version,
        "source_commit": "c" * 40,
        "files": files,
    }
    if development:
        manifest["development"] = {"schema": 1, "software_source_commit": commit, "non_production": True}
    media = pycdlib.PyCdlib()
    media.new(interchange_level=3, rock_ridge="1.09")
    media.add_directory("/ATLASO", rr_name="atlaso")
    media.add_directory("/ATLASO/SOFTWARE", rr_name="software")
    media.add_directory("/ATLASO/SOFTWARE/PACKAGES", rr_name="packages")
    media.add_directory("/ATLASO/SOURCE", rr_name="source")
    media.add_directory("/ATLASO/SOURCE/IMAGE", rr_name="image")
    media.add_directory("/ATLASO/SOURCE/IMAGE/COMMON", rr_name="common")
    media.add_directory("/ATLASO/SOURCE/IMAGE/COMMON/SCRIPTS", rr_name="scripts")
    media.add_directory("/ATLASO/SOURCE/SCRIPTS", rr_name="scripts")
    media.add_directory("/ATLASO/SOURCE/SCRIPTS/INTEROP", rr_name="interop")
    _add(media, "/ATLASO/PAYLOAD_MANIFEST.JSON;1", "payload-manifest.json", json.dumps(manifest).encode())
    for name, content in inventory.items():
        iso_member_path = "/ATLASO/" + name.upper().replace(".", "_").replace("-", "_") + ";1"
        _add(media, iso_member_path, name.split("/")[-1], content)
    media.write(str(path))
    media.close()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_expected_inputs_bind_dev_manifest_and_helper_hashes(tmp_path: Path) -> None:
    """Bind the report expectations to the exact synthetic media.

    Args:
        tmp_path: Task-owned isolated fixture directory.
    """
    image = tmp_path / "test.iso"
    digest = _iso(image)

    expected = expected_inputs(image, digest)

    assert expected["version"] == "0.9.453"
    assert expected["source_commit"] == "b" * 40
    assert expected["software_verifier_sha256"] == hashlib.sha256(b"verifier source").hexdigest()
    assert expected["payload_inspector_sha256"] == hashlib.sha256(b"inspector source").hexdigest()
    assert expected["wheel_sha256"] == hashlib.sha256(b"wheel bytes").hexdigest()


def test_expected_inputs_reject_digest_or_production_media(tmp_path: Path) -> None:
    """Reject changed media and the production signing domain.

    Args:
        tmp_path: Task-owned isolated fixture directory.
    """
    image = tmp_path / "test.iso"
    _iso(image)
    with pytest.raises(ValueError, match="differs from its admitted digest"):
        expected_inputs(image, "0" * 64)
    production = tmp_path / "production.iso"
    production_digest = _iso(production, development=False)
    with pytest.raises(ValueError, match="development media"):
        expected_inputs(production, production_digest)


def test_guest_program_hides_marker_and_stays_inside_console_limit() -> None:
    """Keep command echo distinct from the bounded output proof."""
    expected = {
        "schema": 1,
        "iso_sha256": "a" * 64,
        "version": "0.9.453",
        "source_commit": "b" * 40,
        "release_manifest_sha256": "c" * 64,
        "software_verifier_sha256": "d" * 64,
        "payload_inspector_sha256": "e" * 64,
        "wheel_sha256": "f" * 64,
    }
    command = guest_program(expected)

    assert len(command) <= 3500
    assert command.startswith("/opt/atlaso/.venv/bin/python -B -I -c '")
    assert "ATLASO-INSPECTION" not in command
    assert "host_key_sha256" not in command
    with pytest.raises(ValueError, match="expectations"):
        guest_program({**expected, "extra": "field"})


def _expected() -> dict[str, object]:
    """Return a complete public expectation fixture."""
    return {
        "schema": 1,
        "iso_sha256": "a" * 64,
        "version": "0.9.453",
        "source_commit": "b" * 40,
        "release_manifest_sha256": "c" * 64,
        "software_verifier_sha256": "d" * 64,
        "payload_inspector_sha256": "e" * 64,
        "wheel_sha256": "f" * 64,
    }


def test_default_guest_paths_stay_posix_on_windows_hosts() -> None:
    """Host path conventions must not redirect authenticated guest helper reads."""
    command = guest_program(_expected())
    encoded = re.search(r'b64decode\("([A-Za-z0-9+/=]+)"\)', command)
    assert encoded is not None
    program = zlib.decompress(base64.b64decode(encoded.group(1))).decode()
    strings = {node.value for node in ast.walk(ast.parse(program))
               if isinstance(node, ast.Constant) and isinstance(node.value, str)}

    assert {"/opt/atlaso", "/var/lib/atlaso/installation-inspection/software", "/"} <= strings
    assert not any(value.startswith("\\") for value in strings)


def _report(expected: dict[str, object]) -> bytes:
    """Encode one schema-conforming public guest record.

    Args:
        expected: Complete public ISO expectation fixture.
    """
    return json.dumps({
        "schema": 1,
        "machine_id_sha256": "1" * 64,
        "host_key_sha256": "SHA256:" + "A" * 43,
        "version": expected["version"],
        "source_commit": expected["source_commit"],
        "wheel_sha256": expected["wheel_sha256"],
        "wheel_payload_sha256": "2" * 64,
        "installed_payload_sha256": "2" * 64,
        "verified_payload_files": 73,
    }, separators=(",", ":")).encode()


def test_validate_report_returns_only_allowlisted_public_identity() -> None:
    """Return only validated identity and application measurements."""
    expected = _expected()
    result = validate_report(_report(expected), expected)

    assert result["machine_id_sha256"] == "1" * 64
    assert result["verified_payload_files"] == 73
    assert set(result) == {
        "schema", "machine_id_sha256", "host_key_sha256", "version", "source_commit",
        "wheel_sha256", "wheel_payload_sha256", "installed_payload_sha256", "verified_payload_files",
    }


@pytest.mark.parametrize("change", [
    {"password_hash": "must never be emitted"},
    {"installed_payload_sha256": "3" * 64},
    {"verified_payload_files": True},
    {"host_key_sha256": "not-a-public-key-fingerprint"},
    {"source_commit": "c" * 40},
])
def test_validate_report_rejects_unsafe_or_mismatched_data(change: dict[str, object]) -> None:
    """Refuse unknown fields, invalid types and software mismatches.

    Args:
        change: Independent malformed report field.
    """
    expected = _expected()
    value = json.loads(_report(expected))
    value.update(change)

    with pytest.raises(ValueError):
        validate_report(json.dumps(value).encode(), expected)


def test_validate_report_enforces_size_bound() -> None:
    """Refuse oversized reports before JSON parsing."""
    with pytest.raises(ValueError, match="bound"):
        validate_report(b" " * 4097, {})


def _write_wheel(path: Path, version: str) -> bytes:
    """Create a small application wheel and return its bytes.

    Args:
        path: Task-owned output file.
        version: Synthetic application version.
    """
    payload = {
        "atlaso/__init__.py": b"__version__ = '0.9.453'\n",
        f"atlaso-{version}.dist-info/METADATA": f"Name: atlaso\nVersion: {version}\n".encode(),
        f"atlaso-{version}.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"atlaso-{version}.dist-info/RECORD": b"",
    }
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in payload.items():
            archive.writestr(name, content)
    return path.read_bytes()


def _prepare_guest_tree(root: Path, *, staged: bool = True) -> tuple[dict[str, object], Path]:
    """Stage existing verifier helpers and a matching application fixture.

    Args:
        root: Task-owned guest fixture root.
        staged: Whether to preserve signed software staging.
    """
    version = "0.9.453"
    commit = "b" * 40
    software = root / "software"
    atlaso = root / "atlaso"
    site = root / "site"
    software.mkdir(parents=True)
    (atlaso / "image/common/scripts").mkdir(parents=True)
    (atlaso / "scripts/interop").mkdir(parents=True)
    shutil.copyfile("image/common/scripts/verify-template-software.py", atlaso / "image/common/scripts/verify-template-software.py")
    shutil.copyfile("scripts/interop/routing_deployment_inspection.py", atlaso / "scripts/interop/routing_deployment_inspection.py")
    (site / "atlaso").mkdir(parents=True)
    (site / "atlaso-0.9.453.dist-info").mkdir()
    app_wheel = software / "packages/atlaso-0.9.453-py3-none-any.whl"
    app_wheel.parent.mkdir()
    wheel_bytes = _write_wheel(app_wheel, version)
    with zipfile.ZipFile(app_wheel) as archive:
        for item in archive.infolist():
            if item.filename.endswith("RECORD"):
                continue
            target = site / item.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(item.filename))
    (site / "atlaso" / "__init__.py").write_bytes(b"__version__ = '0.9.453'\n")
    (site / "atlaso-0.9.453.dist-info/METADATA").write_bytes(b"Name: atlaso\nVersion: 0.9.453\n")
    (site / "atlaso-0.9.453.dist-info/WHEEL").write_bytes(b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    dependency = b"dependency wheel"
    dependency_path = software / "wheelhouse/cp314/dependency-1.0-py3-none-any.whl"
    dependency_path.parent.mkdir(parents=True)
    dependency_path.write_bytes(dependency)
    requirements_lock = b"dep==1.0 --hash=sha256:" + hashlib.sha256(dependency).hexdigest().encode() + b"\n"
    (dependency_path.parent / "requirements-wheelhouse.lock").write_bytes(requirements_lock)
    (software / "requirements-appliance.lock").write_bytes(b"locked\n")
    (software / "bundle-metadata.json").write_bytes(b"{}\n")
    release_hashes = {}
    for item in software.rglob("*"):
        if item.is_file():
            release_hashes[item.relative_to(software).as_posix()] = hashlib.sha256(item.read_bytes()).hexdigest()
    release = {
        "version": version,
        "git_commit": commit,
        "supported_python_abis": ["cp314"],
        "content_hashes": release_hashes,
        "bundle": {"sha256": "7" * 64},
    }
    release_bytes = json.dumps(release).encode()
    manifest_digest = hashlib.sha256(release_bytes).hexdigest()
    (software / "release-manifest.json").write_bytes(release_bytes)
    (software / "release-manifest.json.sig").write_bytes(b"signature\n")
    source = {
        "schema_version": 1,
        "kind": "atlaso-virtualization-source",
        "version": version,
        "source_commit": commit,
        "source_software_tag": f"v{version}",
        "release_manifest_sha256": manifest_digest,
        "release_bundle_sha256": "7" * 64,
        "application_wheel": "packages/atlaso-0.9.453-py3-none-any.whl",
        "application_wheel_sha256": hashlib.sha256(wheel_bytes).hexdigest(),
        "python_abi": "cp314",
    }
    (software / "virtualization-source.json").write_text(json.dumps(source), encoding="utf-8")
    (root / "machine-id").write_text("1234567890abcdef1234567890abcdef\n", encoding="ascii")
    key_blob = (11).to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + bytes(range(32))
    (root / "ssh_host_ed25519_key.pub").write_text(
        "ssh-ed25519 " + base64.b64encode(key_blob).decode() + " fixture\n", encoding="ascii"
    )
    expected = {
        "schema": 1,
        "iso_sha256": "a" * 64,
        "version": version,
        "source_commit": commit,
        "release_manifest_sha256": manifest_digest,
        "software_verifier_sha256": hashlib.sha256((atlaso / "image/common/scripts/verify-template-software.py").read_bytes()).hexdigest(),
        "payload_inspector_sha256": hashlib.sha256((atlaso / "scripts/interop/routing_deployment_inspection.py").read_bytes()).hexdigest(),
        "wheel_sha256": hashlib.sha256(wheel_bytes).hexdigest(),
    }
    if staged:
        (root / "etc/ssh").mkdir(parents=True)
        shutil.copyfile(root / "ssh_host_ed25519_key.pub", root / "etc/ssh/ssh_host_ed25519_key.pub")
        (root / "etc/machine-id").write_text("1234567890abcdef1234567890abcdef\n", encoding="ascii")
    else:
        shutil.rmtree(software)
    return expected, site


def test_guest_program_executes_existing_verified_helpers(tmp_path: Path) -> None:
    """Execute both existing helpers and validate their public evidence.

    Args:
        tmp_path: Task-owned isolated fixture directory.
    """
    expected, site = _prepare_guest_tree(tmp_path)
    source_root = tmp_path / "atlaso"
    software_root = tmp_path / "software"
    command = guest_program(expected, atlaso_root=source_root, software_root=software_root, identity_root=tmp_path)
    encoded = re.search(r'b64decode\("([A-Za-z0-9+/=]+)"\)', command)
    assert encoded is not None
    program = zlib.decompress(base64.b64decode(encoded.group(1)))
    # Windows cannot model Linux O_NOFOLLOW. Keep this portable fixture on
    # ordinary task-owned files; the real Linux guest retains its native flag.
    runner = "import os,sys;os.O_NOFOLLOW=getattr(os,'O_NOFOLLOW',0);sys.path.insert(0," + repr(str(site)) + ");exec(" + repr(program.decode()) + ")"
    result = subprocess.run([sys.executable, "-B", "-I", "-c", runner], capture_output=True, check=False, timeout=15)

    assert result.returncode == 0
    marker = result.stdout.decode("ascii").strip()
    assert marker.startswith("ATLASO-INSPECTION:") and marker.endswith(":END")
    report_bytes = base64.b64decode(marker.removeprefix("ATLASO-INSPECTION:").removesuffix(":END"))
    report = validate_report(report_bytes, expected)
    assert report["machine_id_sha256"] == hashlib.sha256(b"1234567890abcdef1234567890abcdef").hexdigest()


def test_guest_refuses_missing_staged_software_without_detail(tmp_path: Path) -> None:
    """Refuse missing software without exposing raw exception details.

    Args:
        tmp_path: Task-owned isolated fixture directory.
    """
    expected, site = _prepare_guest_tree(tmp_path, staged=False)
    command = guest_program(expected, atlaso_root=tmp_path / "atlaso", software_root=tmp_path / "software")
    encoded = re.search(r'b64decode\("([A-Za-z0-9+/=]+)"\)', command)
    assert encoded is not None
    program = zlib.decompress(base64.b64decode(encoded.group(1)))
    runner = "import os,sys;os.O_NOFOLLOW=getattr(os,'O_NOFOLLOW',0);sys.path.insert(0," + repr(str(site)) + ");exec(" + repr(program.decode()) + ")"
    result = subprocess.run([sys.executable, "-B", "-I", "-c", runner], capture_output=True, check=False, timeout=15)

    assert result.returncode == 0
    assert result.stdout.decode("ascii").strip() == "ATLASO-INSPECTION-FAILED:software-staging"
    assert result.stderr == b""


@pytest.mark.parametrize("corruption", ["helper", "payload", "machine-id", "host-key"])
def test_guest_rejects_changed_payload_helpers_and_invalid_public_identity(tmp_path: Path, corruption: str) -> None:
    """Refuse changed inputs without executing a changed helper or revealing bytes.

    Args:
        tmp_path: Task-owned isolated guest filesystem fixture.
        corruption: One independently modified inspection input.
    """
    expected, site = _prepare_guest_tree(tmp_path)
    if corruption == "helper":
        (tmp_path / "atlaso/scripts/interop/routing_deployment_inspection.py").write_text(
            "raise RuntimeError('changed helper must never execute')", encoding="ascii"
        )
    elif corruption == "payload":
        (site / "atlaso/__init__.py").write_bytes(b"changed application bytes")
    elif corruption == "machine-id":
        (tmp_path / "etc/machine-id").write_bytes(b"0" * 32)
    else:
        (tmp_path / "etc/ssh/ssh_host_ed25519_key.pub").write_bytes(b"ssh-ed25519 malformed fixture")
    command = guest_program(expected, atlaso_root=tmp_path / "atlaso", software_root=tmp_path / "software", identity_root=tmp_path)
    encoded = re.search(r'b64decode\("([A-Za-z0-9+/=]+)"\)', command)
    assert encoded is not None
    program = zlib.decompress(base64.b64decode(encoded.group(1)))
    runner = "import os,sys;os.O_NOFOLLOW=getattr(os,'O_NOFOLLOW',0);sys.path.insert(0," + repr(str(site)) + ");exec(" + repr(program.decode()) + ")"
    result = subprocess.run([sys.executable, "-B", "-I", "-c", runner], capture_output=True, check=False, timeout=15)
    assert result.returncode == 0
    phase = {"helper": "source-helpers", "payload": "application-payload",
             "machine-id": "public-identities", "host-key": "public-identities"}[corruption]
    assert result.stdout.strip() == ("ATLASO-INSPECTION-FAILED:" + phase).encode()
    assert result.stderr == b""


def test_network_preparation_preserves_complete_iso_admission(tmp_path, monkeypatch, capsys):
    """Network observation commands require the original complete media check.

    Args:
        tmp_path: Owned synthetic ISO fixture directory.
        monkeypatch: Set bounded public CLI arguments.
        capsys: Capture only admitted preparation or the fixed refusal.
    """
    media = tmp_path / "network.iso"
    digest = _iso(media)
    monkeypatch.setattr(sys, "argv", ["inspection", "prepare", "--iso", str(media), "--iso-sha256", digest, "--network"])
    assert inspection.main() == 0
    captured = capsys.readouterr()
    prepared = json.loads(captured.out)
    assert prepared["expected"]["iso_sha256"] == digest
    assert 1 <= len(prepared["network_command"]) <= 3500 and "ATLASO-INSPECTION" not in prepared["network_command"]
    assert captured.err == ""
    with media.open("ab") as stream:
        stream.write(b"changed media")
    assert inspection.main() == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "Installed inspection could not validate its bounded inputs.\n"
