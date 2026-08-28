"""Focused tests for the signed virtualization artifact index."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import build_virtualization_artifact_index as builder
from scripts import verify_virtualization_artifact_index as verifier
from tests.test_virtualization_ova import _members, _write_ova

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _trusted_release_source(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use repository helper bytes and deterministic VHDX metadata in fixtures.

    Args:
        monkeypatch: Pytest fixture used to isolate external git and qemu tooling.
    """

    monkeypatch.setattr(
        builder,
        "_git_blob",
        lambda _commit, repository_path: (ROOT / repository_path).read_bytes(),
    )
    sizes = {
        "photon-os.vhdx": 40 * 1024**3,
        "atlaso-system.vhdx": 20 * 1024**3,
        "vcf-offline-depot.vhdx": builder.HYPERV_DATA_DISK_BYTES,
        "vcf-backups.vhdx": builder.HYPERV_DATA_DISK_BYTES,
    }
    monkeypatch.setattr(
        builder,
        "_inspect_vhdx",
        lambda path: {"format": "vhdx", "virtual-size": sizes[path.name]},
    )


def test_operator_verification_bootstraps_with_standard_tools() -> None:
    """The operator guide authenticates the index without executing fetched code."""

    guide = Path("docs/reference/virtualization-artifacts.md").read_text(
        encoding="utf-8"
    )
    assert "verify-from-source.py" not in guide
    assert "openssl pkeyutl -verify -pubin -rawin" in guide
    assert guide.index("sha256sum --check --strict") < guide.index(
        "openssl pkeyutl -verify"
    )


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
    source = {
        "schema_version": 1,
        "kind": "atlaso-virtualization-source",
        "version": version,
        "source_commit": "a" * 40,
        "source_software_tag": f"v{version}",
        "release_manifest_sha256": "b" * 64,
        "release_bundle_sha256": "d" * 64,
        "application_wheel": f"packages/atlaso-{version}-py3-none-any.whl",
        "application_wheel_sha256": "c" * 64,
        "python_abi": "cp314",
    }
    members = _members()
    provenance = json.loads(members.pop("atlaso-provenance.json"))
    provenance["product_version"] = version
    provenance["software_release_source"] = {
        "tag": source["source_software_tag"],
        "release_manifest_sha256": source["release_manifest_sha256"],
        "release_bundle_sha256": source["release_bundle_sha256"],
        "application_wheel_sha256": source["application_wheel_sha256"],
        "python_abi": source["python_abi"],
    }
    members["atlaso-provenance.json"] = (
        json.dumps(provenance, sort_keys=True) + "\n"
    ).encode()
    manifest_lines = [
        f"SHA256({name})= {hashlib.sha256(content).hexdigest()}\n"
        for name, content in sorted(members.items())
        if not name.endswith(".mf")
    ]
    members["atlaso.mf"] = "".join(manifest_lines).encode()
    for name, content in members.items():
        (path / name).write_bytes(content)
    _write_ova(path / f"atlaso-v{version}.ova", members)
    for name, repository_path in builder.RELEASE_HELPERS.items():
        (path / name).write_bytes((ROOT / repository_path).read_bytes())
    (path / "virtualization-source.json").write_text(
        json.dumps(source), encoding="utf-8"
    )
    ova = path / f"atlaso-v{version}.ova"
    hyperv = path / f"atlaso-v{version}-hyperv-x86_64.zip"
    hyperv_members = {
        "Import-Atlaso.ps1": (
            ROOT / "scripts/windows/virtualization/templates/Import-Atlaso.ps1"
        ).read_bytes(),
        "photon-os.vhdx": b"test-photon-vhdx",
        "atlaso-system.vhdx": b"test-system-vhdx",
        "vcf-offline-depot.vhdx": b"test-depot-vhdx",
        "vcf-backups.vhdx": b"test-backups-vhdx",
    }
    roles = {
        "photon-os.vhdx": ("photon_os", 0, 40 * 1024**3),
        "atlaso-system.vhdx": ("atlaso_system", 1, 20 * 1024**3),
        "vcf-offline-depot.vhdx": (
            "vcf_offline_depot",
            2,
            builder.HYPERV_DATA_DISK_BYTES,
        ),
        "vcf-backups.vhdx": (
            "vcf_backups",
            3,
            builder.HYPERV_DATA_DISK_BYTES,
        ),
    }
    manifest = {
        "schema_version": 1,
        "kind": "atlaso-hyperv-artifact",
        "product_version": version,
        "source": {
            "kind": "atlaso-validated-ova",
            "commit": "a" * 40,
            "ova_name": ova.name,
            "ova_sha256": hashlib.sha256(ova.read_bytes()).hexdigest(),
            "ova_validator": 1,
        },
        "machine": {
            "firmware": "uefi",
            "secure_boot": False,
            "cpu_count": 4,
            "memory_mib": 4096,
            "nic_count": 2,
            "disk_bus": "scsi",
        },
        "disks": [
            {
                "role": role,
                "scsi_slot": slot,
                "file": name,
                "format": "vhdx",
                "virtual_size_bytes": virtual_size,
                "bytes": len(hyperv_members[name]),
                "sha256": hashlib.sha256(hyperv_members[name]).hexdigest(),
            }
            for name, (role, slot, virtual_size) in roles.items()
        ],
    }
    hyperv_members["manifest.json"] = (json.dumps(manifest) + "\n").encode()
    hyperv_members["checksums.sha256"] = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in sorted(hyperv_members.items())
    ).encode()
    with zipfile.ZipFile(hyperv, mode="w") as archive:
        for name, content in hyperv_members.items():
            archive.writestr(name, content)
    windows = {
        "schema_version": 1,
        "kind": "atlaso-windows-virtualization-smoke",
        "version": version,
        "source_commit": "a" * 40,
        "ova_sha256": hashlib.sha256(ova.read_bytes()).hexdigest(),
        "hyperv_sha256": hashlib.sha256(hyperv.read_bytes()).hexdigest(),
        "vmware": "success",
        "hyperv": "success",
    }
    (path / "windows-smoke-evidence.json").write_text(
        json.dumps(windows), encoding="utf-8"
    )


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
                "--classification",
                "prerelease",
                "--release-tag",
                "virtualization-v0.9.217-rc.1",
                "--source-release-manifest-sha256",
                "b" * 64,
                "--application-wheel-sha256",
                "c" * 64,
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
    signature = json.loads(
        (assets / builder.SIGNATURE_NAME).read_text(encoding="utf-8")
    )
    key.public_key().verify(
        base64.b64decode(signature["signature"], validate=True), index_bytes
    )
    assert index["source_commit"] == "a" * 40
    assert index["classification"] == "prerelease"
    assert index["release_tag"] == "virtualization-v0.9.217-rc.1"
    assert len(index["assets"]) == 14
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
        expected_classification="prerelease",
        expected_release_tag="virtualization-v0.9.217-rc.1",
    )
    assert result["assets_verified"] == 14

    (assets / "import-atlaso-kvm.sh").write_bytes(b"tampered")
    with pytest.raises(SystemExit, match="size, hash, or role"):
        verifier.verify(
            index_path=assets / builder.INDEX_NAME,
            signature_path=assets / builder.SIGNATURE_NAME,
            trust_key_path=trust_key,
            asset_directory=assets,
        )


def test_rejects_unknown_assets_and_signed_role_mismatches(tmp_path: Path) -> None:
    """Only the canonical named asset set and its exact roles may be signed.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    key = _key(tmp_path / "key.pem")
    arguments = [
        "--assets",
        str(assets),
        "--version",
        "0.9.217",
        "--commit",
        "a" * 40,
        "--classification",
        "prerelease",
        "--release-tag",
        "virtualization-v0.9.217-rc.1",
        "--source-release-manifest-sha256",
        "b" * 64,
        "--application-wheel-sha256",
        "c" * 64,
        "--built-at",
        "2026-08-26T00:00:00Z",
        "--signing-key",
        str(tmp_path / "key.pem"),
        "--signing-key-id",
        "test-key",
    ]
    unexpected = assets / "manually-uploaded.txt"
    unexpected.write_text("unexpected", encoding="utf-8")
    with pytest.raises(SystemExit, match="unsupported virtualization release asset"):
        builder.main(arguments)
    unexpected.unlink()
    assert builder.main(arguments) == 0

    index_path = assets / builder.INDEX_NAME
    index = json.loads(index_path.read_text(encoding="utf-8"))
    ova_record = next(
        record for record in index["assets"] if record["role"] == "canonical_ova"
    )
    ova_record["role"] = "hyperv_package"
    index_bytes = (
        json.dumps(index, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()
    index_path.write_bytes(index_bytes)
    signature = {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": "test-key",
        "signature": base64.b64encode(key.sign(index_bytes)).decode("ascii"),
    }
    signature_bytes = (
        json.dumps(signature, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()
    (assets / builder.SIGNATURE_NAME).write_bytes(signature_bytes)
    trust_key = tmp_path / "test-key.pem"
    trust_key.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(SystemExit, match="size, hash, or role"):
        verifier.verify(
            index_path=index_path,
            signature_path=assets / builder.SIGNATURE_NAME,
            trust_key_path=trust_key,
            asset_directory=assets,
        )


def test_rejects_ova_provenance_not_bound_to_software_source(tmp_path: Path) -> None:
    """Signing fails when OVA provenance disagrees with the signed source sidecar.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    _key(tmp_path / "key.pem")
    provenance_path = assets / "atlaso-provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["software_release_source"]["application_wheel_sha256"] = "e" * 64
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

    with pytest.raises(SystemExit, match="manifest verification"):
        builder.main(
            [
                "--assets",
                str(assets),
                "--version",
                "0.9.217",
                "--commit",
                "a" * 40,
                "--classification",
                "prerelease",
                "--release-tag",
                "virtualization-v0.9.217-rc.1",
                "--source-release-manifest-sha256",
                "b" * 64,
                "--application-wheel-sha256",
                "c" * 64,
                "--signing-key",
                str(tmp_path / "key.pem"),
                "--signing-key-id",
                "test-key",
            ]
        )


def test_rejects_tampered_ova_even_when_smoke_digest_is_updated(tmp_path: Path) -> None:
    """Protected signing opens the OVA instead of trusting producer evidence.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    _key(tmp_path / "key.pem")
    ova = assets / "atlaso-v0.9.217.ova"
    ova.write_bytes(b"producer-controlled invalid archive")
    evidence_path = assets / "windows-smoke-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["ova_sha256"] = hashlib.sha256(ova.read_bytes()).hexdigest()
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(SystemExit, match="valid tar archive"):
        builder.main(
            [
                "--assets",
                str(assets),
                "--version",
                "0.9.217",
                "--commit",
                "a" * 40,
                "--classification",
                "prerelease",
                "--release-tag",
                "virtualization-v0.9.217-rc.1",
                "--source-release-manifest-sha256",
                "b" * 64,
                "--application-wheel-sha256",
                "c" * 64,
                "--signing-key",
                str(tmp_path / "key.pem"),
                "--signing-key-id",
                "test-key",
            ]
        )


def test_rejects_tampered_hyperv_even_when_smoke_digest_is_updated(
    tmp_path: Path,
) -> None:
    """Protected signing opens the Hyper-V ZIP instead of trusting producer evidence.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    _key(tmp_path / "key.pem")
    hyperv = assets / "atlaso-v0.9.217-hyperv-x86_64.zip"
    hyperv.write_bytes(b"producer-controlled invalid archive")
    evidence_path = assets / "windows-smoke-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["hyperv_sha256"] = hashlib.sha256(hyperv.read_bytes()).hexdigest()
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(SystemExit, match="valid ZIP archive"):
        builder.main(
            [
                "--assets",
                str(assets),
                "--version",
                "0.9.217",
                "--commit",
                "a" * 40,
                "--classification",
                "prerelease",
                "--release-tag",
                "virtualization-v0.9.217-rc.1",
                "--source-release-manifest-sha256",
                "b" * 64,
                "--application-wheel-sha256",
                "c" * 64,
                "--signing-key",
                str(tmp_path / "key.pem"),
                "--signing-key-id",
                "test-key",
            ]
        )


def test_rejects_release_helper_not_from_admitted_commit(tmp_path: Path) -> None:
    """Protected signing does not trust producer-supplied executable helpers.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    _key(tmp_path / "key.pem")
    (assets / "import-atlaso-kvm.sh").write_bytes(b"producer-controlled helper")

    with pytest.raises(SystemExit, match="does not match admitted source commit"):
        builder.main(
            [
                "--assets",
                str(assets),
                "--version",
                "0.9.217",
                "--commit",
                "a" * 40,
                "--classification",
                "prerelease",
                "--release-tag",
                "virtualization-v0.9.217-rc.1",
                "--source-release-manifest-sha256",
                "b" * 64,
                "--application-wheel-sha256",
                "c" * 64,
                "--signing-key",
                str(tmp_path / "key.pem"),
                "--signing-key-id",
                "test-key",
            ]
        )


def test_rejects_hyperv_import_helper_not_from_admitted_commit(tmp_path: Path) -> None:
    """A self-consistent ZIP cannot replace the admitted Hyper-V import helper.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    _key(tmp_path / "key.pem")
    hyperv = assets / "atlaso-v0.9.217-hyperv-x86_64.zip"
    with zipfile.ZipFile(hyperv) as archive:
        members = {
            member.filename: archive.read(member.filename)
            for member in archive.infolist()
            if member.filename != "checksums.sha256"
        }
    members["Import-Atlaso.ps1"] = b"producer-controlled import helper"
    members["checksums.sha256"] = "".join(
        f"{hashlib.sha256(content).hexdigest()}  {name}\n"
        for name, content in sorted(members.items())
    ).encode()
    with zipfile.ZipFile(hyperv, mode="w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    evidence_path = assets / "windows-smoke-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["hyperv_sha256"] = hashlib.sha256(hyperv.read_bytes()).hexdigest()
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    with pytest.raises(SystemExit, match="Hyper-V import helper"):
        builder.main(
            [
                "--assets",
                str(assets),
                "--version",
                "0.9.217",
                "--commit",
                "a" * 40,
                "--classification",
                "prerelease",
                "--release-tag",
                "virtualization-v0.9.217-rc.1",
                "--source-release-manifest-sha256",
                "b" * 64,
                "--application-wheel-sha256",
                "c" * 64,
                "--signing-key",
                str(tmp_path / "key.pem"),
                "--signing-key-id",
                "test-key",
            ]
        )


def test_stable_index_requires_both_linux_platform_proofs(tmp_path: Path) -> None:
    """Stable classification fails closed until Proxmox and KVM evidence exists.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """

    assets = tmp_path / "assets"
    _assets(assets)
    _key(tmp_path / "key.pem")
    arguments = [
        "--assets",
        str(assets),
        "--version",
        "0.9.217",
        "--commit",
        "a" * 40,
        "--classification",
        "stable",
        "--release-tag",
        "virtualization-v0.9.217",
        "--source-release-manifest-sha256",
        "b" * 64,
        "--application-wheel-sha256",
        "c" * 64,
        "--signing-key",
        str(tmp_path / "key.pem"),
        "--signing-key-id",
        "test-key",
    ]
    with pytest.raises(SystemExit, match="missing evidence"):
        builder.main(arguments)
    (assets / "proxmox-smoke-evidence.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-proxmox-smoke",
                "ova_sha256": hashlib.sha256(
                    (assets / "atlaso-v0.9.217.ova").read_bytes()
                ).hexdigest(),
                "schema_version": 1,
                "source_commit": "a" * 40,
                "status": "success",
            }
        ),
        encoding="utf-8",
    )
    (assets / "kvm-smoke-evidence.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-kvm-smoke",
                "ova_sha256": hashlib.sha256(
                    (assets / "atlaso-v0.9.217.ova").read_bytes()
                ).hexdigest(),
                "schema_version": 1,
                "source_commit": "a" * 40,
                "status": "success",
            }
        ),
        encoding="utf-8",
    )
    assert builder.main(arguments) == 0


def test_refuses_incomplete_or_oversized_artifact_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
        "--classification",
        "prerelease",
        "--release-tag",
        "virtualization-v0.9.217-rc.1",
        "--source-release-manifest-sha256",
        "b" * 64,
        "--application-wheel-sha256",
        "c" * 64,
        "--signing-key",
        str(tmp_path / "key.pem"),
        "--signing-key-id",
        "test-key",
    ]
    with pytest.raises(SystemExit, match="missing import-atlaso-kvm.sh"):
        builder.main(arguments)

    (assets / "import-atlaso-kvm.sh").write_bytes(
        (ROOT / builder.RELEASE_HELPERS["import-atlaso-kvm.sh"]).read_bytes()
    )
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
