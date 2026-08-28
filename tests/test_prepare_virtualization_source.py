"""Focused tests for consuming the exact automatic software release."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import prepare_virtualization_source as source_preparer

VERSION = "0.9.237"
COMMIT = "a" * 40
KEY_ID = "test-release-key"


def _canonical(value: object) -> bytes:
    """Return canonical signed JSON bytes."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _release_fixture(
    tmp_path: Path, *, unsafe_member: str = ""
) -> tuple[Path, Path, Path, Path]:
    """Create one minimal valid signed software Release fixture."""

    members = {
        f"packages/atlaso-{VERSION}-py3-none-any.whl": b"exact-application-wheel",
        "wheelhouse/cp314/requirements-wheelhouse.lock": b"atlaso==0.9.237 --hash=sha256:"
        + b"b" * 64,
        "wheelhouse/cp314/dependency-1-py3-none-any.whl": b"exact-dependency-wheel",
        "requirements-appliance.lock": b"dependency==1 --hash=sha256:" + b"c" * 64,
        "bundle-metadata.json": b"{}\n",
    }
    if unsafe_member:
        members[unsafe_member] = b"unsafe"
    bundle = tmp_path / f"atlaso-appliance-{VERSION}.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    key = Ed25519PrivateKey.generate()
    trust = tmp_path / KEY_ID
    trust = trust.with_suffix(".pem")
    trust.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    manifest_value = {
        "schema_version": 2,
        "kind": "atlaso-release",
        "version": VERSION,
        "git_commit": COMMIT,
        "built_at": "2026-08-28T00:00:00Z",
        "signing_key_id": KEY_ID,
        "updater_protocol": 2,
        "database_schema_version": 1,
        "supported_python_abis": ["cp314"],
        "bundle": {
            "url": f"https://github.com/mdaneri/Atlaso/releases/download/v{VERSION}/{bundle.name}",
            "size": bundle.stat().st_size,
            "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        },
        "content_hashes": {
            name: hashlib.sha256(content).hexdigest()
            for name, content in members.items()
        },
    }
    manifest = tmp_path / "release-manifest.json"
    manifest.write_bytes(_canonical(manifest_value))
    signature = tmp_path / "release-manifest.json.sig"
    signature.write_bytes(
        _canonical(
            {
                "schema_version": 1,
                "key_id": KEY_ID,
                "signature": base64.b64encode(key.sign(manifest.read_bytes())).decode(),
            }
        )
    )
    return manifest, signature, bundle, trust


def test_extracts_exact_signed_cp314_inputs_and_records_digests(tmp_path: Path) -> None:
    """The producer consumes the published wheel and wheelhouse without rebuilding."""

    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    output = tmp_path / "verified"
    result = source_preparer.prepare(
        manifest_path=manifest,
        signature_path=signature,
        bundle_path=bundle,
        trust_key_path=trust,
        output=output,
        expected_version=VERSION,
        expected_commit=COMMIT,
    )
    source = json.loads(
        (output / "virtualization-source.json").read_text(encoding="utf-8")
    )
    wheel = Path(result["application_wheel"])
    assert wheel.read_bytes() == b"exact-application-wheel"
    assert (output / "wheelhouse/cp314/requirements-wheelhouse.lock").is_file()
    assert source["source_software_tag"] == f"v{VERSION}"
    assert (
        source["release_bundle_sha256"]
        == hashlib.sha256(bundle.read_bytes()).hexdigest()
    )
    assert (
        source["application_wheel_sha256"]
        == hashlib.sha256(wheel.read_bytes()).hexdigest()
    )


def test_rejects_changed_bundle_and_nonempty_resume_destination(tmp_path: Path) -> None:
    """Digest mismatches and ambiguous local recovery fail before extraction."""

    manifest, signature, bundle, trust = _release_fixture(tmp_path)
    bundle.write_bytes(bundle.read_bytes() + b"changed")
    with pytest.raises(SystemExit, match="size and digest"):
        source_preparer.prepare(
            manifest_path=manifest,
            signature_path=signature,
            bundle_path=bundle,
            trust_key_path=trust,
            output=tmp_path / "verified",
            expected_version=VERSION,
            expected_commit=COMMIT,
        )
    output = tmp_path / "occupied"
    output.mkdir()
    (output / "unexpected").write_text("stale", encoding="utf-8")
    fresh_root = tmp_path / "fresh"
    fresh_root.mkdir()
    manifest, signature, bundle, trust = _release_fixture(fresh_root)
    with pytest.raises(SystemExit, match="empty ordinary directory"):
        source_preparer.prepare(
            manifest_path=manifest,
            signature_path=signature,
            bundle_path=bundle,
            trust_key_path=trust,
            output=output,
            expected_version=VERSION,
            expected_commit=COMMIT,
        )


def test_rejects_signed_unsafe_archive_member(tmp_path: Path) -> None:
    """A valid signature cannot authorize path traversal during extraction."""

    manifest, signature, bundle, trust = _release_fixture(
        tmp_path, unsafe_member="../escape.whl"
    )
    with pytest.raises(ValueError, match="unsafe path"):
        source_preparer.prepare(
            manifest_path=manifest,
            signature_path=signature,
            bundle_path=bundle,
            trust_key_path=trust,
            output=tmp_path / "verified",
            expected_version=VERSION,
            expected_commit=COMMIT,
        )
