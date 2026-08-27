"""Focused tests for the signed virtualization artifact index."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import build_virtualization_artifact_index as builder
from scripts import publish_release
from scripts import verify_virtualization_artifact_index as verifier


def test_operator_verification_bootstraps_with_standard_tools() -> None:
    """The operator guide authenticates the index without executing fetched code."""

    guide = Path("docs/reference/virtualization-artifacts.md").read_text(encoding="utf-8")
    assert "verify-from-source.py" not in guide
    assert "openssl pkeyutl -verify -pubin -rawin" in guide
    assert guide.index("sha256sum --check --strict") < guide.index("openssl pkeyutl -verify")


def _key(path: Path) -> Ed25519PrivateKey:
    """Write and return one test-only Ed25519 signing key.

    Args:
        path: Private-key destination.
    """

    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key


def _assets(path: Path, version: str = "0.9.217") -> None:
    """Write the complete minimum named artifact set.

    Args:
        path: Asset-set directory.
        version: Atlaso semantic version used in asset names.
    """

    path.mkdir()
    for name in (
        f"atlaso-v{version}.ova",
        f"atlaso-v{version}.ovf",
        f"atlaso-v{version}.mf",
        f"atlaso-v{version}-photon.vmdk",
        f"atlaso-v{version}-system.vmdk",
        f"atlaso-v{version}-provenance.json",
        f"atlaso-v{version}-hyperv-x86_64.zip",
        "import-atlaso-proxmox.sh",
        "import-atlaso-kvm.sh",
        "validate_ova.py",
        "normalize_libvirt.py",
        "verify_virtualization_artifact_index.py",
    ):
        (path / name).write_bytes(f"asset:{name}\n".encode())


def test_builds_verifiable_index_covering_complete_release_set(tmp_path: Path) -> None:
    """Every release asset is hashed and the canonical JSON is signed.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    key = _key(tmp_path / "key.pem")

    assert (
        builder.main(
            [
                "--assets",
                str(assets),
                "--version",
                "0.9.217",
                "--commit",
                "a" * 40,
                "--built-at",
                "2026-08-26T00:00:00Z",
                "--signing-key",
                str(tmp_path / "key.pem"),
                "--signing-key-id",
                "test-key",
            ]
        )
        == 0
    )

    index_bytes = (assets / builder.INDEX_NAME).read_bytes()
    index = json.loads(index_bytes)
    signature = json.loads((assets / builder.SIGNATURE_NAME).read_text(encoding="utf-8"))
    key.public_key().verify(base64.b64decode(signature["signature"], validate=True), index_bytes)
    assert index["source_commit"] == "a" * 40
    assert len(index["assets"]) == 12
    assert {record["role"] for record in index["assets"]} >= {
        "canonical_ova",
        "hyperv_package",
        "proxmox_import_helper",
        "kvm_import_helper",
        "artifact_index_verifier",
    }

    trust_key = tmp_path / "test-key.pem"
    trust_key.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    result = verifier.verify(
        index_path=assets / builder.INDEX_NAME,
        signature_path=assets / builder.SIGNATURE_NAME,
        trust_key_path=trust_key,
        asset_directory=assets,
        expected_version="0.9.217",
        expected_commit="a" * 40,
    )
    assert result["assets_verified"] == 12

    (assets / "import-atlaso-kvm.sh").write_bytes(b"tampered")
    with pytest.raises(SystemExit, match="size, hash, or role"):
        verifier.verify(
            index_path=assets / builder.INDEX_NAME,
            signature_path=assets / builder.SIGNATURE_NAME,
            trust_key_path=trust_key,
            asset_directory=assets,
        )


def test_publisher_verifies_signed_exact_coverage_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Publication trusts only an exact, signed artifact set for the expected release identity.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to replace repository trust roots.
    """

    root = tmp_path / "root"
    assets = root / "assets"
    trust = root / "image" / "common" / "update-trust"
    trust.mkdir(parents=True)
    _assets(assets)
    key = _key(tmp_path / "key.pem")
    (trust / "test-key.pem").write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert (
        builder.main(
            [
                "--assets",
                str(assets),
                "--version",
                "0.9.217",
                "--commit",
                "a" * 40,
                "--built-at",
                "2026-08-26T00:00:00Z",
                "--signing-key",
                str(tmp_path / "key.pem"),
                "--signing-key-id",
                "test-key",
            ]
        )
        == 0
    )
    monkeypatch.setattr(publish_release, "ROOT", root)
    # The application release manifest is validated by the ordinary release
    # bundle contract and must not be pulled into the virtualization index.
    (assets / "release-manifest.json").write_bytes(b"{}\n")
    names = {path.name for path in assets.iterdir()}
    publish_release.verify_virtualization_artifact_index(
        assets,
        names,
        expected_version="0.9.217",
        expected_commit="a" * 40,
    )

    (assets / "import-atlaso-kvm.sh").write_bytes(b"tampered")
    with pytest.raises(SystemExit, match="size, hash, or role"):
        publish_release.verify_virtualization_artifact_index(
            assets,
            names,
            expected_version="0.9.217",
            expected_commit="a" * 40,
        )


def test_refuses_incomplete_or_oversized_artifact_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing helper or asset at the GitHub limit blocks index publication.

    Args:
        tmp_path: Temporary directory provided by pytest.
        monkeypatch: Pytest fixture used to simulate an oversized asset.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    (assets / "import-atlaso-kvm.sh").unlink()
    _key(tmp_path / "key.pem")
    arguments = [
        "--assets",
        str(assets),
        "--version",
        "0.9.217",
        "--commit",
        "a" * 40,
        "--signing-key",
        str(tmp_path / "key.pem"),
        "--signing-key-id",
        "test-key",
    ]
    with pytest.raises(SystemExit, match="missing import-atlaso-kvm.sh"):
        builder.main(arguments)

    (assets / "import-atlaso-kvm.sh").write_bytes(b"helper")
    ova = assets / "atlaso-v0.9.217.ova"
    real_stat = Path.stat

    def fake_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        """Return a synthetic oversized stat for the OVA.

        Args:
            path: File being inspected.
            follow_symlinks: Whether the underlying stat follows symlinks.
        """

        result = real_stat(path, follow_symlinks=follow_symlinks)
        if path == ova:
            values = list(result)
            values[6] = builder.MAXIMUM_GITHUB_ASSET_BYTES
            return type(result)(values)
        return result

    monkeypatch.setattr(Path, "stat", fake_stat)
    with pytest.raises(SystemExit, match="size limit"):
        builder.main(arguments)
