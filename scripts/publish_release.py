#!/usr/bin/env python3
"""Idempotently publish a versioned GitHub Release for one exact commit."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
GIT_RELEASE_USER_NAME = "github-actions[bot]"
GIT_RELEASE_USER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
MAXIMUM_GITHUB_ASSET_BYTES = 2_147_483_647
VMWARE_MANIFEST_PATTERN = re.compile(r"^SHA256\(([^/\\]+)\)= ([0-9a-f]{64})$")
OVF_NAMESPACE = "http://schemas.dmtf.org/ovf/envelope/1"
RASD_NAMESPACE = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
VIRTUALIZATION_INDEX_NAME = "virtualization-artifact-index.json"
VIRTUALIZATION_SIGNATURE_NAME = f"{VIRTUALIZATION_INDEX_NAME}.sig"


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run operation.

    Args:
        command: Command and arguments to execute.
        check: Whether a nonzero command status raises an exception.


    Returns:
        The run result.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"{command[0]} failed")
    return result


def sha256(path: Path) -> str:
    """Return sha256.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def version() -> str:
    """Return version."""
    result = run(["python", "scripts/version.py", "get"])
    return result.stdout.strip()


def verify_vmware_ovf_topology(path: Path, asset_names: set[str]) -> None:
    """Validate vmware ovf topology.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        asset_names: Asset names supplied by the caller.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    namespaces = {"ovf": OVF_NAMESPACE, "rasd": RASD_NAMESPACE}
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        raise SystemExit(f"VMware OVF descriptor is not valid XML: {exc}") from exc

    files = {
        element.get(f"{{{OVF_NAMESPACE}}}id"): element.get(f"{{{OVF_NAMESPACE}}}href")
        for element in root.findall("./ovf:References/ovf:File", namespaces)
    }
    definitions = {
        element.get(f"{{{OVF_NAMESPACE}}}diskId"): element
        for element in root.findall("./ovf:DiskSection/ovf:Disk", namespaces)
    }
    hardware_disks: dict[str, ET.Element] = {}
    for item in root.findall(".//ovf:VirtualHardwareSection/ovf:Item", namespaces):
        resource_type = item.findtext("rasd:ResourceType", default="", namespaces=namespaces)
        if resource_type != "17":
            continue
        unit = item.findtext("rasd:AddressOnParent", default="", namespaces=namespaces)
        if unit in hardware_disks:
            raise SystemExit(f"VMware OVF contains duplicate disk hardware at SCSI unit {unit}")
        hardware_disks[unit] = item
    if len(definitions) != 4 or set(hardware_disks) != {"0", "1", "2", "3"}:
        raise SystemExit("VMware OVF must contain exactly four disks at SCSI units 0 through 3")

    disk_assets = {name for name in asset_names if name.lower().endswith(".vmdk")}
    payload_assets: set[str] = set()
    disk_format = ""
    for unit, expected_name in (("0", "Hard disk 1 - Photon OS"), ("1", "Hard disk 2 - Atlaso System Content")):
        item = hardware_disks[unit]
        if item.findtext("rasd:ElementName", default="", namespaces=namespaces) != expected_name:
            raise SystemExit(f"VMware OVF payload disk at SCSI unit {unit} has the wrong identity")
        host_resource = item.findtext("rasd:HostResource", default="", namespaces=namespaces)
        if not host_resource.startswith("ovf:/disk/"):
            raise SystemExit(f"VMware OVF payload disk at SCSI unit {unit} has no disk definition")
        definition = definitions.get(host_resource.removeprefix("ovf:/disk/"))
        if definition is None:
            raise SystemExit(f"VMware OVF payload disk at SCSI unit {unit} has no disk definition")
        file_ref = definition.get(f"{{{OVF_NAMESPACE}}}fileRef")
        href = files.get(file_ref)
        if not href or href not in disk_assets:
            raise SystemExit(f"VMware OVF payload disk at SCSI unit {unit} has no release VMDK")
        payload_assets.add(href)
        payload_format = definition.get(f"{{{OVF_NAMESPACE}}}format", "")
        if not payload_format or (disk_format and payload_format != disk_format):
            raise SystemExit("VMware OVF payload disks must declare one consistent disk format")
        disk_format = payload_format
    if payload_assets != disk_assets:
        raise SystemExit("VMware OVF payload references do not match the two release VMDKs")

    for unit, disk_id, expected_name in (
        ("2", "atlaso-depot", "Hard disk 3 - VCF Offline Depot"),
        ("3", "atlaso-backups", "Hard disk 4 - VCF Backups"),
    ):
        item = hardware_disks[unit]
        if item.findtext("rasd:ElementName", default="", namespaces=namespaces) != expected_name:
            raise SystemExit(f"VMware OVF empty disk at SCSI unit {unit} has the wrong identity")
        if item.findtext("rasd:HostResource", default="", namespaces=namespaces) != f"ovf:/disk/{disk_id}":
            raise SystemExit(f"VMware OVF empty disk at SCSI unit {unit} has the wrong disk definition")
        definition = definitions.get(disk_id)
        if (
            definition is None
            or definition.get(f"{{{OVF_NAMESPACE}}}fileRef") is not None
            or definition.get(f"{{{OVF_NAMESPACE}}}capacity") != "500"
            or definition.get(f"{{{OVF_NAMESPACE}}}capacityAllocationUnits") != "byte * 2^30"
            or definition.get(f"{{{OVF_NAMESPACE}}}format") != disk_format
        ):
            raise SystemExit(f"VMware OVF empty disk {disk_id} is not an empty 500 GiB disk")


def verify_vmware_release_assets(
    directory: Path,
    names: set[str],
    *,
    expected_version: str | None = None,
    expected_commit: str | None = None,
) -> None:
    """Validate vmware release assets.

    Args:
        directory: Filesystem path associated with directory.
        names: Names consumed by verify vmware release assets.
        expected_version: Optional strict portable-artifact version contract.
        expected_commit: Optional strict portable-artifact provenance commit.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    manifests = sorted(name for name in names if name.lower().endswith(".mf"))
    descriptors = sorted(name for name in names if name.lower().endswith(".ovf"))
    disks = sorted(name for name in names if name.lower().endswith(".vmdk"))
    archives = sorted(name for name in names if name.lower().endswith(".ova"))
    provenance = sorted(name for name in names if name.lower().endswith("-provenance.json"))
    allowed = set(manifests + descriptors + disks + archives + provenance)
    strict_identity = expected_version is not None or expected_commit is not None
    if strict_identity and (expected_version is None or expected_commit is None):
        raise SystemExit("strict VMware release verification requires both version and commit")
    if (
        names != allowed
        or len(manifests) != 1
        or len(descriptors) != 1
        or len(disks) != 2
        or len(archives) > 1
        or len(provenance) > 1
        or (strict_identity and (len(archives) != 1 or len(provenance) != 1))
    ):
        raise SystemExit(f"release contains an invalid VMware appliance asset set: {sorted(names)}")

    for name in names:
        path = directory / name
        if not path.is_file() or path.stat().st_size > MAXIMUM_GITHUB_ASSET_BYTES:
            raise SystemExit(f"VMware release asset is missing or too large: {name}")

    expected_hashes: dict[str, str] = {}
    for line in (directory / manifests[0]).read_text(encoding="utf-8").splitlines():
        match = VMWARE_MANIFEST_PATTERN.fullmatch(line)
        if match is None or match.group(1) in expected_hashes:
            raise SystemExit(f"VMware release manifest contains an invalid entry: {line}")
        expected_hashes[match.group(1)] = match.group(2)
    payload_names = set(descriptors + disks + provenance)
    if set(expected_hashes) != payload_names:
        raise SystemExit("VMware release manifest does not cover the OVF descriptor, provenance, and both payload VMDKs")
    mismatches = [name for name, expected in expected_hashes.items() if sha256(directory / name) != expected]
    if mismatches:
        raise SystemExit(f"VMware release assets failed manifest verification: {', '.join(sorted(mismatches))}")
    verify_vmware_ovf_topology(directory / descriptors[0], names)
    expected_members = set(manifests + descriptors + disks + provenance)
    if archives:
        try:
            with tarfile.open(directory / archives[0], mode="r:") as archive:
                members = [member for member in archive.getmembers() if member.isfile()]
                member_names = {member.name for member in members}
                if member_names != expected_members or len(members) != len(expected_members):
                    raise SystemExit("VMware OVA does not contain exactly the OVF package assets")
                for member in members:
                    stream = archive.extractfile(member)
                    digest = hashlib.sha256()
                    if stream is not None:
                        while block := stream.read(1024 * 1024):
                            digest.update(block)
                    if stream is None or digest.hexdigest() != sha256(directory / member.name):
                        raise SystemExit(f"VMware OVA contains different bytes for {member.name}")
        except tarfile.TarError as exc:
            raise SystemExit(f"VMware OVA is not a valid tar archive: {exc}") from exc
    if strict_identity:
        with tempfile.TemporaryDirectory(prefix="atlaso-ova-release-") as extraction_value:
            try:
                result = run(
                    [
                        "python",
                        "scripts/virtualization/validate_ova.py",
                        str(directory / archives[0]),
                        "--extract-directory",
                        str(Path(extraction_value) / "members"),
                    ]
                )
                contract = json.loads(result.stdout)
            except (json.JSONDecodeError, SystemExit) as exc:
                raise SystemExit(f"VMware OVA failed the portable machine contract: {exc}") from exc
        if contract["product_version"] != expected_version:
            raise SystemExit("VMware OVA provenance version does not match the release version")
        if contract["source_commit"] != expected_commit:
            raise SystemExit("VMware OVA provenance commit does not match the release commit")


def verify_virtualization_artifact_index(
    directory: Path,
    names: set[str],
    *,
    expected_version: str,
    expected_commit: str,
) -> None:
    """Verify the signed exact-coverage virtualization artifact index.

    Args:
        directory: Release asset directory.
        names: Exact asset names selected for publication.
        expected_version: Repository version associated with the release.
        expected_commit: Full source commit associated with the release.

    Raises:
        SystemExit: If the index, signature, trust key, or indexed assets are invalid.
    """

    required_index_files = {VIRTUALIZATION_INDEX_NAME, VIRTUALIZATION_SIGNATURE_NAME}
    missing_index_files = required_index_files - names
    if missing_index_files:
        raise SystemExit(f"release is missing the signed virtualization index: {sorted(missing_index_files)}")
    index_path = directory / VIRTUALIZATION_INDEX_NAME
    signature_path = directory / VIRTUALIZATION_SIGNATURE_NAME
    try:
        index_bytes = index_path.read_bytes()
        index = json.loads(index_bytes)
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"virtualization artifact index is unreadable: {exc}") from exc
    if not isinstance(index, dict) or not isinstance(signature, dict):
        raise SystemExit("virtualization artifact index and signature must be JSON objects")
    canonical_index = (json.dumps(index, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    if index_bytes != canonical_index:
        raise SystemExit("virtualization artifact index is not canonical JSON")
    if (
        index.get("schema_version") != 1
        or index.get("kind") != "atlaso-virtualization-artifacts"
        or index.get("version") != expected_version
        or index.get("source_commit") != expected_commit
    ):
        raise SystemExit("virtualization artifact index does not match the release identity")
    key_id = index.get("signing_key_id")
    if not isinstance(key_id, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", key_id) is None:
        raise SystemExit("virtualization artifact index has an unsafe signing key identifier")
    if (
        signature.get("schema_version") != 1
        or signature.get("algorithm") != "ed25519"
        or signature.get("key_id") != key_id
        or set(signature) != {"schema_version", "algorithm", "key_id", "signature"}
    ):
        raise SystemExit("virtualization artifact index signature metadata is invalid")
    trust_key_path = ROOT / "image" / "common" / "update-trust" / f"{key_id}.pem"
    if not trust_key_path.is_file() or trust_key_path.is_symlink():
        raise SystemExit(f"virtualization artifact index trust key is unavailable: {key_id}")
    try:
        trust_key = serialization.load_pem_public_key(trust_key_path.read_bytes())
        signature_bytes = base64.b64decode(str(signature["signature"]), validate=True)
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(f"virtualization artifact index signature is invalid: {exc}") from exc
    if not isinstance(trust_key, Ed25519PublicKey):
        raise SystemExit("virtualization artifact index trust key must be Ed25519")
    try:
        trust_key.verify(signature_bytes, index_bytes)
    except InvalidSignature as exc:
        raise SystemExit("virtualization artifact index signature verification failed") from exc

    records = index.get("assets")
    if not isinstance(records, list) or not records:
        raise SystemExit("virtualization artifact index contains no asset records")
    indexed_names: set[str] = set()
    required_names = {
        f"atlaso-v{expected_version}-hyperv-x86_64.zip",
        "import-atlaso-proxmox.sh",
        "import-atlaso-kvm.sh",
        "validate_ova.py",
        "normalize_libvirt.py",
        "verify_virtualization_artifact_index.py",
    }
    for record in records:
        if not isinstance(record, dict) or set(record) != {"name", "role", "size", "sha256"}:
            raise SystemExit("virtualization artifact index contains an invalid asset record")
        name = record["name"]
        if (
            not isinstance(name, str)
            or name in indexed_names
            or Path(name).name != name
            or name in required_index_files
        ):
            raise SystemExit("virtualization artifact index contains an unsafe or duplicate asset name")
        indexed_names.add(name)
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"indexed release asset is unavailable or unsafe: {name}")
        size = path.stat().st_size
        if (
            not isinstance(record["size"], int)
            or record["size"] != size
            or size <= 0
            or size >= MAXIMUM_GITHUB_ASSET_BYTES
            or not isinstance(record["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or sha256(path) != record["sha256"]
            or not isinstance(record["role"], str)
            or not record["role"]
        ):
            raise SystemExit(f"indexed release asset failed size, hash, or role verification: {name}")
    vmware_names = {
        name
        for name in names
        if name.lower().endswith((".ovf", ".mf", ".vmdk", ".ova", "-provenance.json"))
    }
    expected_indexed_names = required_names | vmware_names
    if indexed_names != expected_indexed_names:
        raise SystemExit("virtualization artifact index does not cover the exact release asset set")
    missing_required_names = required_names - indexed_names
    if missing_required_names:
        raise SystemExit(f"virtualization release is incomplete: {sorted(missing_required_names)}")


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Command-line arguments to parse, or ``None`` to use the process arguments.


    Returns:
        The main result.

    Raises:
        SystemExit: If the operation encounters an invalid state.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--commit", required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument(
        "--require-virtualization-assets",
        action="store_true",
        help="Require and validate the canonical OVA release asset set.",
    )
    args = parser.parse_args(argv)
    if re.fullmatch(r"[0-9a-f]{40}", args.commit) is None:
        raise SystemExit("release commit must be a full lowercase hexadecimal commit")
    assets = sorted(path.resolve() for path in args.assets.iterdir() if path.is_file())
    if not assets:
        raise SystemExit("release assets directory is empty")
    release_version = version()
    tag = f"v{release_version}"
    asset_names = {path.name for path in assets}
    vmware_names = {
        name
        for name in asset_names
        if name.lower().endswith((".ovf", ".mf", ".vmdk", ".ova", "-provenance.json"))
    }
    if args.require_virtualization_assets and not vmware_names:
        raise SystemExit("release is missing the required canonical OVA assets")
    if vmware_names:
        verify_vmware_release_assets(
            args.assets.resolve(),
            vmware_names,
            expected_version=release_version,
            expected_commit=args.commit,
        )
    if args.require_virtualization_assets:
        verify_virtualization_artifact_index(
            args.assets.resolve(),
            asset_names,
            expected_version=release_version,
            expected_commit=args.commit,
        )

    remote_tag = run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"]).stdout.strip()
    if remote_tag:
        tagged_commit = remote_tag.split()[0]
        peeled = run(["git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}^{{}}"]).stdout.strip()
        if peeled:
            tagged_commit = peeled.split()[0]
        if tagged_commit != args.commit:
            raise SystemExit(f"{tag} already identifies {tagged_commit}, not {args.commit}")
    else:
        run(
            [
                "git",
                "-c",
                f"user.name={GIT_RELEASE_USER_NAME}",
                "-c",
                f"user.email={GIT_RELEASE_USER_EMAIL}",
                "tag",
                "-a",
                tag,
                args.commit,
                "-m",
                f"Atlaso {tag}",
            ]
        )
        run(["git", "push", "origin", f"refs/tags/{tag}"])

    existing = run(["gh", "release", "view", tag, "--json", "tagName,targetCommitish,assets"], check=False)
    if existing.returncode == 0:
        release = json.loads(existing.stdout)
        if release.get("tagName") != tag:
            raise SystemExit(f"GitHub Release lookup returned the wrong tag for {tag}")
        expected_names = {path.name for path in assets}
        actual_names = {item["name"] for item in release.get("assets", [])}
        missing_names = expected_names - actual_names
        extra_names = actual_names - expected_names
        if missing_names:
            raise SystemExit(
                f"{tag} is missing expected assets: {sorted(missing_names)}; found {sorted(actual_names)}"
            )
        with tempfile.TemporaryDirectory(prefix="atlaso-release-verify-") as temp_value:
            temp = Path(temp_value)
            run(["gh", "release", "download", tag, "--dir", str(temp)])
            mismatches = [
                path.name
                for path in assets
                if not (temp / path.name).is_file() or sha256(path) != sha256(temp / path.name)
            ]
            if mismatches:
                raise SystemExit(f"{tag} already contains mismatched assets: {', '.join(mismatches)}")
            if extra_names:
                verify_vmware_release_assets(temp, extra_names)
        print(json.dumps({"tag": tag, "commit": args.commit, "result": "already-published"}, sort_keys=True))
        return 0

    run(
        [
            "gh",
            "release",
            "create",
            tag,
            *[str(path) for path in assets],
            "--verify-tag",
            "--title",
            f"Atlaso {tag}",
            "--generate-notes",
            "--notes",
            (
                f"Signed appliance release built from `{args.commit}`.\n\n"
                "Virtualization assets are covered by `virtualization-artifact-index.json` and its detached Ed25519 "
                "signature. Verify them with `verify_virtualization_artifact_index.py` and the "
                "`atlaso-release-2026-01` public key (SHA-256 "
                "`b0bb5614342c4f432a01c53fc4c9aae54c1eeffb12806539a92babbcda74b58e`) before import; "
                f"the [portable virtualization artifact guide](https://github.com/mdaneri/Atlaso/blob/{tag}/docs/"
                "reference/virtualization-artifacts.md) contains the exact command sequence."
            ),
        ]
    )
    print(json.dumps({"tag": tag, "commit": args.commit, "result": "published"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
