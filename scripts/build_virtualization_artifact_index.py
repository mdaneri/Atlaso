#!/usr/bin/env python3
"""Build a signed index for one complete Atlaso virtualization release set."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if not __package__:
    sys.path.insert(0, str(ROOT))

from scripts.publish_release import (  # noqa: E402 - Script path bootstrap precedes the local import.
    verify_vmware_release_assets,
)

MAXIMUM_GITHUB_ASSET_BYTES = 2_147_483_647
INDEX_NAME = "virtualization-artifact-index.json"
SIGNATURE_NAME = f"{INDEX_NAME}.sig"
SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PRERELEASE_TAG_PATTERN = re.compile(
    r"^virtualization-v([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]*)$"
)
STABLE_TAG_PATTERN = re.compile(r"^virtualization-v([0-9]+\.[0-9]+\.[0-9]+)$")
HYPERV_DATA_DISK_BYTES = 536_870_912_000
MAXIMUM_HYPERV_METADATA_BYTES = 1_048_576
RELEASE_HELPERS = {
    "import-atlaso-proxmox.sh": "scripts/virtualization/templates/import-atlaso-proxmox.sh",
    "import-atlaso-kvm.sh": "scripts/virtualization/templates/import-atlaso-kvm.sh",
    "validate_ova.py": "scripts/virtualization/validate_ova.py",
    "normalize_libvirt.py": "scripts/virtualization/normalize_libvirt.py",
    "verify_virtualization_artifact_index.py": "scripts/verify_virtualization_artifact_index.py",
}


def _sha256(path: Path) -> str:
    """Return the SHA-256 digest of one release asset.

    Args:
        path: Release asset to hash.
    """

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON with one trailing newline.

    Args:
        value: JSON-compatible value to serialize.
    """

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _load_signing_key(path: Path) -> Ed25519PrivateKey:
    """Load one unencrypted Ed25519 release signing key.

    Args:
        path: PEM private-key path.
    """

    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("artifact-index signing key must be an Ed25519 private key")
    return key


def _asset_role(name: str) -> str:
    """Return the stable release role for one indexed asset name.

    Args:
        name: Flat release asset name.
    """

    lower = name.lower()
    if lower.endswith("-hyperv-x86_64.zip"):
        return "hyperv_package"
    if lower.endswith(".ova"):
        return "canonical_ova"
    if lower.endswith(".ovf"):
        return "canonical_ovf"
    if lower.endswith(".mf"):
        return "ovf_manifest"
    if lower.endswith(".vmdk"):
        return "ova_payload_disk"
    if lower.endswith("-provenance.json"):
        return "ova_provenance"
    if lower == "import-atlaso-proxmox.sh":
        return "proxmox_import_helper"
    if lower == "import-atlaso-kvm.sh":
        return "kvm_import_helper"
    if lower == "validate_ova.py":
        return "ova_validator"
    if lower == "normalize_libvirt.py":
        return "libvirt_normalizer"
    if lower == "verify_virtualization_artifact_index.py":
        return "artifact_index_verifier"
    if lower == "virtualization-source.json":
        return "software_release_source"
    if lower == "windows-smoke-evidence.json":
        return "windows_smoke_evidence"
    if lower == "proxmox-smoke-evidence.json":
        return "proxmox_smoke_evidence"
    if lower == "kvm-smoke-evidence.json":
        return "kvm_smoke_evidence"
    raise SystemExit(f"unsupported virtualization release asset: {name}")


def _require_virtualization_set(
    names: set[str], version: str, classification: str
) -> None:
    """Require every canonical and target-specific virtualization asset.

    Args:
        names: Exact flat asset-name set.
        version: Atlaso semantic version embedded in versioned names.
        classification: Prerelease or stable publication class.
    """

    canonical_vmware = {
        f"atlaso-v{version}.ova",
        "atlaso.ovf",
        "atlaso.mf",
        "atlaso-provenance.json",
        "photon.vmdk",
        "system.vmdk",
    }
    actual_vmware = {
        name
        for name in names
        if name.lower().endswith((".ova", ".ovf", ".mf", ".vmdk", "-provenance.json"))
    }
    if actual_vmware != canonical_vmware:
        raise SystemExit(
            "virtualization release requires canonical VMware asset names; "
            f"expected {sorted(canonical_vmware)}, found {sorted(actual_vmware)}"
        )
    expected_hyperv = {f"atlaso-v{version}-hyperv-x86_64.zip"}
    actual_hyperv = {
        name for name in names if name.lower().endswith("-hyperv-x86_64.zip")
    }
    if actual_hyperv != expected_hyperv:
        raise SystemExit(
            "virtualization release requires the exact canonical Hyper-V asset set; "
            f"expected {sorted(expected_hyperv)}, found {sorted(actual_hyperv)}"
        )
    for helper in (
        "import-atlaso-proxmox.sh",
        "import-atlaso-kvm.sh",
        "validate_ova.py",
        "normalize_libvirt.py",
        "verify_virtualization_artifact_index.py",
    ):
        if helper not in names:
            raise SystemExit(f"virtualization release is missing {helper}")
    required_evidence = {"virtualization-source.json", "windows-smoke-evidence.json"}
    if classification == "stable":
        required_evidence |= {"proxmox-smoke-evidence.json", "kvm-smoke-evidence.json"}
    missing_evidence = required_evidence - names
    if missing_evidence:
        raise SystemExit(
            f"virtualization release is missing evidence: {sorted(missing_evidence)}"
        )


def _json_object(path: Path, label: str) -> dict[str, Any]:
    """Load one bounded evidence JSON object.

    Args:
        path: Evidence document path.
        label: Human-readable evidence role.
    """

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{label} is unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{label} must be a JSON object")
    return value


def _git_blob(commit: str, repository_path: str) -> bytes:
    """Read one non-executable reference blob from the admitted source commit.

    Args:
        commit: Exact admitted source commit.
        repository_path: POSIX repository-relative path to read.
    """

    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{commit}:{repository_path}"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"could not read trusted release helper {repository_path} at {commit}"
        )
    return result.stdout


def _verify_release_helpers(asset_root: Path, commit: str) -> None:
    """Require shipped executable helpers to equal the admitted source blobs.

    Args:
        asset_root: Flat candidate asset directory.
        commit: Exact admitted source commit.
    """

    for asset_name, repository_path in RELEASE_HELPERS.items():
        if (asset_root / asset_name).read_bytes() != _git_blob(
            commit, repository_path
        ):
            raise SystemExit(
                f"release helper {asset_name} does not match admitted source commit"
            )


def _inspect_vhdx(path: Path) -> dict[str, Any]:
    """Return qemu-img's independent format and virtual-capacity inspection.

    Args:
        path: Extracted VHDX member to inspect.
    """

    qemu_img = shutil.which("qemu-img")
    if qemu_img is None:
        raise SystemExit("qemu-img is required to validate the Hyper-V archive")
    result = subprocess.run(
        [qemu_img, "info", "--output=json", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"qemu-img rejected Hyper-V disk {path.name}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"qemu-img returned invalid metadata for Hyper-V disk {path.name}"
        ) from exc
    if not isinstance(value, dict):
        raise SystemExit(f"qemu-img returned invalid metadata for Hyper-V disk {path.name}")
    return value


def _compare_virtual_disks(
    source: Path,
    source_format: str,
    target: Path,
    target_format: str,
    label: str,
) -> None:
    """Require two virtual disks to expose identical guest-visible bytes.

    Args:
        source: Trusted source disk.
        source_format: Explicit qemu-img format for the source disk.
        target: Candidate disk to compare.
        target_format: Explicit qemu-img format for the candidate disk.
        label: Bounded disk identity used in failure diagnostics.
    """

    qemu_img = shutil.which("qemu-img")
    if qemu_img is None:
        raise SystemExit("qemu-img is required to validate the Hyper-V archive")
    result = subprocess.run(
        [
            qemu_img,
            "compare",
            "-q",
            "-f",
            source_format,
            "-F",
            target_format,
            str(source),
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 1:
        raise SystemExit(f"Hyper-V disk content does not match {label}")
    if result.returncode != 0:
        raise SystemExit(f"qemu-img could not compare Hyper-V disk {label}")


def _create_blank_raw_disk(path: Path) -> None:
    """Create one sparse all-zero raw disk with the Hyper-V data-disk capacity.

    Args:
        path: Invocation-owned reference disk path.
    """

    qemu_img = shutil.which("qemu-img")
    if qemu_img is None:
        raise SystemExit("qemu-img is required to validate the Hyper-V archive")
    result = subprocess.run(
        [
            qemu_img,
            "create",
            "-f",
            "raw",
            str(path),
            str(HYPERV_DATA_DISK_BYTES),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit("qemu-img could not create the blank data-disk reference")


def _validate_hyperv_archive(
    archive_path: Path,
    *,
    ova_payload_root: Path,
    version: str,
    commit: str,
    ova_sha256: str,
    ova_payloads: list[dict[str, Any]],
) -> None:
    """Open and independently validate the complete Hyper-V package contract.

    Args:
        archive_path: Candidate Hyper-V ZIP.
        ova_payload_root: Directory containing the independently verified OVA payloads.
        version: Expected Atlaso version.
        commit: Exact admitted source commit.
        ova_sha256: Digest of the admitted canonical OVA.
        ova_payloads: Verified payload topology from OVA provenance.
    """

    disk_contract: dict[str, tuple[str, int, Any]] = {
        "photon-os.vhdx": ("photon_os", 0, None),
        "atlaso-system.vhdx": ("atlaso_system", 1, None),
        "vcf-offline-depot.vhdx": (
            "vcf_offline_depot",
            2,
            HYPERV_DATA_DISK_BYTES,
        ),
        "vcf-backups.vhdx": ("vcf_backups", 3, HYPERV_DATA_DISK_BYTES),
    }
    payload_sizes = {
        str(item.get("role")): item.get("virtual_size_bytes") for item in ova_payloads
    }
    payload_files = {
        str(item.get("role")): str(item.get("file")) for item in ova_payloads
    }
    disk_contract["photon-os.vhdx"] = (
        "photon_os",
        0,
        payload_sizes.get("photon_os"),
    )
    disk_contract["atlaso-system.vhdx"] = (
        "atlaso_system",
        1,
        payload_sizes.get("atlaso_system"),
    )
    if set(payload_files) != {"photon_os", "atlaso_system"}:
        raise SystemExit("OVA provenance does not contain the exact payload disk roles")
    expected_names = set(disk_contract) | {
        "Import-Atlaso.ps1",
        "manifest.json",
        "checksums.sha256",
    }
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"Hyper-V package is not a valid ZIP archive: {exc}") from exc
    with archive, tempfile.TemporaryDirectory(prefix="atlaso-hyperv-verify-") as temporary:
        members = archive.infolist()
        names = [member.filename for member in members]
        if len(names) != len(set(names)) or set(names) != expected_names:
            raise SystemExit("Hyper-V ZIP does not contain the exact package member set")
        for member in members:
            unix_mode = member.external_attr >> 16
            if (
                member.is_dir()
                or member.filename != Path(member.filename).name
                or "\\" in member.filename
                or member.flag_bits & 0x1
                or (unix_mode and (unix_mode & 0o170000) not in (0, 0o100000))
                or member.file_size <= 0
                or member.file_size >= MAXIMUM_GITHUB_ASSET_BYTES
                or (
                    member.filename not in disk_contract
                    and member.file_size > MAXIMUM_HYPERV_METADATA_BYTES
                )
            ):
                raise SystemExit(f"Hyper-V ZIP contains an unsafe member: {member.filename}")
        try:
            manifest = json.loads(archive.read("manifest.json"))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
            raise SystemExit(f"Hyper-V manifest is unreadable: {exc}") from exc
        if not isinstance(manifest, dict):
            raise SystemExit("Hyper-V manifest must be a JSON object")
        expected_source = {
            "kind": "atlaso-validated-ova",
            "commit": commit,
            "ova_name": archive_path.name.replace("-hyperv-x86_64.zip", ".ova"),
            "ova_sha256": ova_sha256,
            "ova_validator": 1,
        }
        expected_machine = {
            "firmware": "uefi",
            "secure_boot": False,
            "cpu_count": 4,
            "memory_mib": 4096,
            "nic_count": 2,
            "disk_bus": "scsi",
        }
        if (
            set(manifest)
            != {
                "schema_version",
                "kind",
                "product_version",
                "source",
                "machine",
                "disks",
            }
            or manifest.get("schema_version") != 1
            or manifest.get("kind") != "atlaso-hyperv-artifact"
            or manifest.get("product_version") != version
            or manifest.get("source") != expected_source
            or manifest.get("machine") != expected_machine
            or not isinstance(manifest.get("disks"), list)
        ):
            raise SystemExit("Hyper-V manifest does not match the admitted release")
        records = manifest["disks"]
        if len(records) != len(disk_contract):
            raise SystemExit("Hyper-V manifest does not contain the exact disk topology")
        records_by_name = {
            str(record.get("file")): record
            for record in records
            if isinstance(record, dict)
        }
        if set(records_by_name) != set(disk_contract) or len(records_by_name) != len(
            records
        ):
            raise SystemExit("Hyper-V manifest does not contain the exact disk topology")
        checksum_lines = archive.read("checksums.sha256").decode("utf-8").splitlines()
        checksums: dict[str, str] = {}
        for line in checksum_lines:
            match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
            if match is None or match.group(2) in checksums:
                raise SystemExit("Hyper-V checksum manifest contains an invalid entry")
            checksums[match.group(2)] = match.group(1)
        if set(checksums) != expected_names - {"checksums.sha256"}:
            raise SystemExit("Hyper-V checksum manifest does not cover the exact package")
        if archive.read("Import-Atlaso.ps1") != _git_blob(
            commit, "scripts/windows/virtualization/templates/Import-Atlaso.ps1"
        ):
            raise SystemExit(
                "Hyper-V import helper does not match admitted source commit"
            )
        extraction_root = Path(temporary)
        for name in sorted(expected_names - {"checksums.sha256"}):
            digest = hashlib.sha256()
            destination = extraction_root / name
            with archive.open(name) as source, destination.open("wb") as output:
                while block := source.read(1024 * 1024):
                    digest.update(block)
                    output.write(block)
            if digest.hexdigest() != checksums[name]:
                raise SystemExit(f"Hyper-V package failed checksum verification: {name}")
        for name, (role, slot, virtual_size) in disk_contract.items():
            record = records_by_name[name]
            member = archive.getinfo(name)
            if (
                virtual_size is None
                or record
                != {
                    "role": role,
                    "scsi_slot": slot,
                    "file": name,
                    "format": "vhdx",
                    "virtual_size_bytes": virtual_size,
                    "bytes": member.file_size,
                    "sha256": checksums[name],
                }
            ):
                raise SystemExit(f"Hyper-V disk manifest is invalid for {name}")
            inspected = _inspect_vhdx(extraction_root / name)
            if (
                inspected.get("format") != "vhdx"
                or inspected.get("virtual-size") != virtual_size
            ):
                raise SystemExit(f"Hyper-V disk topology is invalid for {name}")
        for name, role in (
            ("photon-os.vhdx", "photon_os"),
            ("atlaso-system.vhdx", "atlaso_system"),
        ):
            source_name = payload_files[role]
            if Path(source_name).name != source_name:
                raise SystemExit("OVA provenance contains an unsafe payload file name")
            _compare_virtual_disks(
                ova_payload_root / source_name,
                "vmdk",
                extraction_root / name,
                "vhdx",
                role,
            )
        # The OVA models data disks as fileless declarations. A sparse raw file
        # therefore provides an independent all-zero reference without consuming
        # the declared 500 GiB on the hosted runner.
        blank_reference = extraction_root / "blank-data-disk.raw"
        _create_blank_raw_disk(blank_reference)
        for name, role in (
            ("vcf-offline-depot.vhdx", "vcf_offline_depot"),
            ("vcf-backups.vhdx", "vcf_backups"),
        ):
            _compare_virtual_disks(
                blank_reference,
                "raw",
                extraction_root / name,
                "vhdx",
                role,
            )


def _validate_evidence(
    asset_root: Path,
    version: str,
    commit: str,
    classification: str,
    release_manifest_sha256: str,
    application_wheel_sha256: str,
) -> None:
    """Bind signed source and smoke evidence to the exact release assets.

    Args:
        asset_root: Flat candidate asset directory.
        version: Expected Atlaso version.
        commit: Expected full source commit.
        classification: Prerelease or stable publication class.
        release_manifest_sha256: Expected signed software manifest digest.
        application_wheel_sha256: Expected embedded Atlaso wheel digest.
    """

    vmware_names = {
        path.name
        for path in asset_root.iterdir()
        if path.name.lower().endswith((".ova", ".ovf", ".mf", ".vmdk", "-provenance.json"))
    }
    # The protected signer independently opens the OVA, validates its manifest,
    # topology, payload digests, and embedded provenance, and requires every
    # archived member to match the loose candidate bytes before trusting the
    # producer-supplied smoke evidence or provenance sidecar below.
    verify_vmware_release_assets(
        asset_root,
        vmware_names,
        expected_version=version,
        expected_commit=commit,
    )
    source = _json_object(
        asset_root / "virtualization-source.json", "software-release source evidence"
    )
    if (
        source.get("schema_version") != 1
        or source.get("kind") != "atlaso-virtualization-source"
        or source.get("version") != version
        or source.get("source_commit") != commit
        or source.get("source_software_tag") != f"v{version}"
        or source.get("python_abi") != "cp314"
        or source.get("release_manifest_sha256") != release_manifest_sha256
        or source.get("application_wheel_sha256") != application_wheel_sha256
        or DIGEST_PATTERN.fullmatch(str(source.get("release_manifest_sha256", "")))
        is None
        or DIGEST_PATTERN.fullmatch(str(source.get("release_bundle_sha256", "")))
        is None
        or DIGEST_PATTERN.fullmatch(str(source.get("application_wheel_sha256", "")))
        is None
    ):
        raise SystemExit(
            "software-release source evidence does not match the release identity"
        )
    provenance_paths = sorted(asset_root.glob("*-provenance.json"))
    if len(provenance_paths) != 1:
        raise SystemExit("virtualization release requires one OVA provenance document")
    provenance = _json_object(provenance_paths[0], "OVA provenance")
    if (
        provenance.get("schema_version") != 1
        or provenance.get("kind") != "atlaso-vmware-ova-provenance"
        or provenance.get("product_version") != version
        or provenance.get("source_commit") != commit
        or provenance.get("software_release_source")
        != {
            "tag": source["source_software_tag"],
            "release_manifest_sha256": source["release_manifest_sha256"],
            "release_bundle_sha256": source["release_bundle_sha256"],
            "application_wheel_sha256": source["application_wheel_sha256"],
            "python_abi": source["python_abi"],
        }
    ):
        raise SystemExit(
            "OVA provenance does not bind the exact software-release source evidence"
        )
    ova = next(asset_root.glob("*.ova"))
    hyperv = asset_root / f"atlaso-v{version}-hyperv-x86_64.zip"
    _verify_release_helpers(asset_root, commit)
    _validate_hyperv_archive(
        hyperv,
        ova_payload_root=asset_root,
        version=version,
        commit=commit,
        ova_sha256=_sha256(ova),
        ova_payloads=provenance.get("payloads", []),
    )
    windows = _json_object(
        asset_root / "windows-smoke-evidence.json", "Windows smoke evidence"
    )
    if (
        windows.get("schema_version") != 1
        or windows.get("kind") != "atlaso-windows-virtualization-smoke"
        or windows.get("version") != version
        or windows.get("source_commit") != commit
        or windows.get("vmware") != "success"
        or windows.get("hyperv") != "success"
        or windows.get("ova_sha256") != _sha256(ova)
        or windows.get("hyperv_sha256") != _sha256(hyperv)
    ):
        raise SystemExit(
            "Windows smoke evidence does not bind the exact virtualization assets"
        )
    if classification == "stable":
        for provider in ("proxmox", "kvm"):
            evidence = _json_object(
                asset_root / f"{provider}-smoke-evidence.json",
                f"{provider} smoke evidence",
            )
            if evidence != {
                "kind": f"atlaso-{provider}-smoke",
                "ova_sha256": _sha256(ova),
                "schema_version": 1,
                "source_commit": commit,
                "status": "success",
            }:
                raise SystemExit(
                    f"{provider} smoke evidence does not match the release identity"
                )


def main(argv: list[str] | None = None) -> int:
    """Build and sign the artifact index command-line entry point.

    Args:
        argv: Optional command-line argument sequence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument(
        "--classification", choices=("prerelease", "stable"), required=True
    )
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-release-manifest-sha256", required=True)
    parser.add_argument("--application-wheel-sha256", required=True)
    parser.add_argument("--built-at", default="")
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--signing-key-id", required=True)
    args = parser.parse_args(argv)
    if SEMVER_PATTERN.fullmatch(args.version) is None:
        parser.error("--version must be a dotted semantic version")
    if COMMIT_PATTERN.fullmatch(args.commit) is None:
        parser.error("--commit must be a full lowercase hexadecimal commit")
    tag_match = (
        PRERELEASE_TAG_PATTERN.fullmatch(args.release_tag)
        if args.classification == "prerelease"
        else STABLE_TAG_PATTERN.fullmatch(args.release_tag)
    )
    if tag_match is None or tag_match.group(1) != args.version:
        parser.error("--release-tag does not match the classification and version")
    for value, option in (
        (args.source_release_manifest_sha256, "--source-release-manifest-sha256"),
        (args.application_wheel_sha256, "--application-wheel-sha256"),
    ):
        if DIGEST_PATTERN.fullmatch(value) is None:
            parser.error(f"{option} must be a lowercase SHA-256 digest")
    asset_root = args.assets.resolve(strict=True)
    if not asset_root.is_dir() or asset_root.is_symlink():
        parser.error("--assets must be an ordinary directory")
    output_names = {INDEX_NAME, SIGNATURE_NAME}
    assets = sorted(
        path for path in asset_root.iterdir() if path.name not in output_names
    )
    names = {path.name for path in assets}
    if len(names) != len(assets):
        parser.error("artifact names must be unique")
    _require_virtualization_set(names, args.version, args.classification)
    _validate_evidence(
        asset_root,
        args.version,
        args.commit,
        args.classification,
        args.source_release_manifest_sha256,
        args.application_wheel_sha256,
    )
    records = []
    for path in assets:
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"release asset must be an ordinary file: {path.name}")
        size = path.stat().st_size
        if size <= 0 or size >= MAXIMUM_GITHUB_ASSET_BYTES:
            raise SystemExit(
                f"release asset is empty or exceeds the GitHub size limit: {path.name}"
            )
        records.append(
            {
                "name": path.name,
                "role": _asset_role(path.name),
                "size": size,
                "sha256": _sha256(path),
            }
        )
    built_at = args.built_at.strip() or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    index = {
        "schema_version": 2,
        "kind": "atlaso-virtualization-artifacts",
        "classification": args.classification,
        "release_tag": args.release_tag,
        "version": args.version,
        "source_commit": args.commit,
        "source_software_tag": f"v{args.version}",
        "source_release_manifest_sha256": args.source_release_manifest_sha256,
        "application_wheel_sha256": args.application_wheel_sha256,
        "built_at": built_at,
        "signing_key_id": args.signing_key_id,
        "assets": records,
    }
    index_bytes = _canonical_json(index)
    key = _load_signing_key(args.signing_key)
    (asset_root / INDEX_NAME).write_bytes(index_bytes)
    signature = {
        "schema_version": 1,
        "algorithm": "ed25519",
        "key_id": args.signing_key_id,
        "signature": base64.b64encode(key.sign(index_bytes)).decode("ascii"),
    }
    (asset_root / SIGNATURE_NAME).write_bytes(_canonical_json(signature))
    print(
        json.dumps(
            {"index": INDEX_NAME, "assets": len(records), "version": args.version},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
