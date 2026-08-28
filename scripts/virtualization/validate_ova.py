"""Validate and safely extract the canonical Atlaso VMware OVA contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, cast

OVF = "http://schemas.dmtf.org/ovf/envelope/1"
RASD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
VMW = "http://www.vmware.com/schema/ovf"
MANIFEST_PATTERN = re.compile(r"^SHA256\(([^/\\]+)\)= ([0-9a-f]{64})$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAXIMUM_GITHUB_ASSET_BYTES = 2_147_483_647
EXPECTED_MACHINE = {
    "firmware": "uefi",
    "secure_boot": False,
    "cpu_count": 4,
    "memory_mib": 4096,
    "nic_count": 2,
    "disk_bus": "scsi",
}
EXPECTED_PAYLOADS = {
    0: ("photon_os", "Hard disk 1 - Photon OS", 40 * 1024**3),
    1: ("atlaso_system", "Hard disk 2 - Atlaso System Content", 20 * 1024**3),
}
EXPECTED_EMPTY_DISKS = {
    2: ("atlaso-depot", "Hard disk 3 - VCF Offline Depot"),
    3: ("atlaso-backups", "Hard disk 4 - VCF Backups"),
}
EXPECTED_NETWORKS = ("Atlaso Management Network", "Atlaso Services Network")
SECURE_BOOT_CONFIG_KEYS = (
    "bootOptions.efiSecureBootEnabled",
    "uefi.secureBoot.enabled",
)


class OvaValidationError(ValueError):
    """Report one bounded canonical OVA contract failure."""


def _sha256(path: Path) -> str:
    """Return the SHA-256 digest of one file without loading it into memory.

    Args:
        path: File to hash.
    """

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_member(member: tarfile.TarInfo) -> None:
    """Reject archive entries that could escape or mutate an extraction root.

    Args:
        member: Candidate tar member.
    """

    if not member.isfile():
        raise OvaValidationError(f"OVA member is not a regular file: {member.name}")
    if member.name != Path(member.name).name or member.name in {"", ".", ".."}:
        raise OvaValidationError(f"OVA member has an unsafe path: {member.name}")


def _extract_members(ova_path: Path, destination: Path) -> list[str]:
    """Safely copy flat regular OVA members into an empty destination.

    Args:
        ova_path: Canonical OVA archive.
        destination: Empty extraction directory.
    """

    if destination.exists():
        if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
            raise OvaValidationError(f"OVA extraction destination must be an empty ordinary directory: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    with tarfile.open(ova_path, mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != 5:
            raise OvaValidationError(f"OVA must contain exactly five flat regular members; found {len(members)}.")
        for member in members:
            _validate_member(member)
            if member.name in names:
                raise OvaValidationError(f"OVA contains a duplicate member: {member.name}")
            if member.size <= 0 or member.size >= MAXIMUM_GITHUB_ASSET_BYTES:
                raise OvaValidationError(f"OVA member is empty or exceeds the GitHub asset limit: {member.name}")
            names.append(member.name)
        for member in members:
            source = archive.extractfile(member)
            if source is None:
                raise OvaValidationError(f"OVA member could not be read: {member.name}")
            with source, (destination / member.name).open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
    return names


def _read_manifest(path: Path) -> dict[str, str]:
    """Parse the strict SHA-256 OVF manifest format.

    Args:
        path: OVF manifest path.
    """

    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = MANIFEST_PATTERN.fullmatch(line)
        if match is None or match.group(1) in entries:
            raise OvaValidationError(f"OVA manifest contains an invalid entry: {line}")
        entries[match.group(1)] = match.group(2)
    return entries


def _child_text(item: ET.Element, name: str) -> str:
    """Return one trimmed RASD child value.

    Args:
        item: OVF hardware item.
        name: RASD child element name.
    """

    return (item.findtext(f"{{{RASD}}}{name}") or "").strip()


def _capacity_bytes(disk: ET.Element) -> int:
    """Normalize one OVF capacity declaration to bytes.

    Args:
        disk: OVF disk definition.
    """

    capacity = disk.get(f"{{{OVF}}}capacity", "")
    try:
        value = int(capacity)
    except ValueError as exc:
        raise OvaValidationError(f"OVF disk has an invalid capacity: {capacity}") from exc
    units = disk.get(f"{{{OVF}}}capacityAllocationUnits", "byte").strip()
    if units == "byte":
        return value
    if units == "byte * 2^30":
        return value * 1024**3
    raise OvaValidationError(f"OVF disk has unsupported capacity units: {units}")


def _validate_machine(items: list[ET.Element], root: ET.Element) -> None:
    """Validate firmware, CPU, memory, NIC, and SCSI-controller topology.

    Args:
        items: OVF virtual hardware items.
        root: Parsed OVF document root.
    """

    resources: dict[str, list[ET.Element]] = {}
    for item in items:
        resources.setdefault(_child_text(item, "ResourceType"), []).append(item)
    if len(resources.get("3", [])) != 1 or _child_text(resources["3"][0], "VirtualQuantity") != "4":
        raise OvaValidationError("OVF must declare exactly 4 virtual CPUs.")
    if (
        len(resources.get("4", [])) != 1
        or _child_text(resources["4"][0], "VirtualQuantity") != "4096"
        or _child_text(resources["4"][0], "AllocationUnits") != "byte * 2^20"
    ):
        raise OvaValidationError("OVF must declare exactly 4096 MiB of memory.")
    if len(resources.get("10", [])) != 2:
        raise OvaValidationError("OVF must declare exactly two network adapters.")
    network_names = [
        element.get(f"{{{OVF}}}name", "")
        for element in root.findall(f"./{{{OVF}}}NetworkSection/{{{OVF}}}Network")
    ]
    network_connections = [_child_text(item, "Connection") for item in resources["10"]]
    if network_names != list(EXPECTED_NETWORKS) or network_connections != list(EXPECTED_NETWORKS):
        raise OvaValidationError("OVF network roles must be ordered as Atlaso management and services.")
    controllers = resources.get("6", [])
    if (
        len(controllers) != 1
        or _child_text(controllers[0], "ResourceSubType") != "VirtualSCSI"
        or not _child_text(controllers[0], "InstanceID")
    ):
        raise OvaValidationError("OVF must declare one VMware Paravirtual SCSI controller.")

    configs: dict[str, list[str]] = {}
    for element in root.findall(f".//{{{VMW}}}Config"):
        key = element.get(f"{{{VMW}}}key", "")
        configs.setdefault(key, []).append(element.get(f"{{{VMW}}}value", ""))
    if configs.get("firmware") != ["efi"]:
        raise OvaValidationError("OVF must require UEFI firmware.")
    secure_boot_values = [
        value.lower()
        for key in SECURE_BOOT_CONFIG_KEYS
        for value in configs.get(key, [])
    ]
    if not secure_boot_values:
        raise OvaValidationError("OVF must explicitly disable Secure Boot.")
    if any(value not in {"false", "0"} for value in secure_boot_values):
        raise OvaValidationError("OVF Secure Boot must be disabled.")


def _validate_topology(ovf_path: Path) -> dict[int, dict[str, Any]]:
    """Validate the complete four-disk Atlaso OVF topology.

    Args:
        ovf_path: Extracted OVF descriptor.
    """

    try:
        root = ET.parse(ovf_path).getroot()
    except ET.ParseError as exc:
        raise OvaValidationError("OVA contains invalid OVF XML.") from exc
    items = root.findall(f".//{{{OVF}}}VirtualHardwareSection/{{{OVF}}}Item")
    _validate_machine(items, root)
    disk_definitions = root.findall(f"./{{{OVF}}}DiskSection/{{{OVF}}}Disk")
    definition_ids = [disk.get(f"{{{OVF}}}diskId", "") for disk in disk_definitions]
    if len(disk_definitions) != 4 or "" in definition_ids or len(set(definition_ids)) != 4:
        raise OvaValidationError("OVF must contain exactly four uniquely identified disk definitions.")
    definitions = dict(zip(definition_ids, disk_definitions, strict=True))

    file_definitions = root.findall(f"./{{{OVF}}}References/{{{OVF}}}File")
    file_ids = [item.get(f"{{{OVF}}}id", "") for item in file_definitions]
    file_names = [item.get(f"{{{OVF}}}href", "") for item in file_definitions]
    if (
        len(file_definitions) != 2
        or "" in file_ids
        or "" in file_names
        or len(set(file_ids)) != 2
        or len(set(file_names)) != 2
        or any(name != Path(name).name for name in file_names)
    ):
        raise OvaValidationError("OVF must reference exactly two uniquely identified flat payload files.")
    files = dict(zip(file_ids, file_names, strict=True))
    disk_items = [item for item in items if _child_text(item, "ResourceType") == "17"]
    if len(disk_items) != 4:
        raise OvaValidationError("OVF must contain exactly four disk definitions and four disk hardware items.")
    controller_id = _child_text(
        next(item for item in items if _child_text(item, "ResourceType") == "6"),
        "InstanceID",
    )
    by_slot: dict[int, dict[str, Any]] = {}
    for item in disk_items:
        try:
            slot = int(_child_text(item, "AddressOnParent"))
        except ValueError as exc:
            raise OvaValidationError("OVF disk slot is not an integer.") from exc
        host_resource = _child_text(item, "HostResource")
        if (
            not host_resource.startswith("ovf:/disk/")
            or slot in by_slot
            or _child_text(item, "Parent") != controller_id
        ):
            raise OvaValidationError("OVF disk hardware contains a duplicate or invalid role binding.")
        disk_id = host_resource.removeprefix("ovf:/disk/")
        definition = definitions.get(disk_id)
        if definition is None:
            raise OvaValidationError(f"OVF disk slot {slot} references a missing definition.")
        by_slot[slot] = {
            "disk_id": disk_id,
            "element_name": _child_text(item, "ElementName"),
            "file": files.get(definition.get(f"{{{OVF}}}fileRef", ""), ""),
            "capacity_bytes": _capacity_bytes(definition),
            "format": definition.get(f"{{{OVF}}}format", ""),
            "file_ref": definition.get(f"{{{OVF}}}fileRef", ""),
            "parent_ref": definition.get(f"{{{OVF}}}parentRef", ""),
            "populated_size": definition.get(f"{{{OVF}}}populatedSize", ""),
        }
    if set(by_slot) != {0, 1, 2, 3}:
        raise OvaValidationError("OVF disks must occupy SCSI slots 0 through 3 without gaps.")

    payload_format = ""
    for slot, (_role, name, capacity) in EXPECTED_PAYLOADS.items():
        disk = by_slot[slot]
        if disk["element_name"] != name or not disk["file"] or disk["capacity_bytes"] != capacity:
            raise OvaValidationError(f"OVF payload disk at SCSI slot {slot} has the wrong role, file, or capacity.")
        if not disk["format"]:
            raise OvaValidationError(f"OVF payload disk at SCSI slot {slot} has no format declaration.")
        payload_format = payload_format or str(disk["format"])
        if disk["format"] != payload_format:
            raise OvaValidationError("OVF payload disks must use one disk format.")
    for slot, (disk_id, name) in EXPECTED_EMPTY_DISKS.items():
        disk = by_slot[slot]
        if (
            disk["disk_id"] != disk_id
            or disk["element_name"] != name
            or disk["file_ref"]
            or disk["parent_ref"]
            or disk["populated_size"]
            or disk["capacity_bytes"] != 500 * 1024**3
            or disk["format"] != payload_format
        ):
            raise OvaValidationError(f"OVF empty data disk at SCSI slot {slot} violates the 500 GiB role contract.")
    return by_slot


def validate_ovf(ovf_path: Path) -> dict[str, Any]:
    """Validate one canonical OVF descriptor before provenance is written.

    Args:
        ovf_path: Canonical OVF descriptor emitted by the supported OVF Tool.
    """

    if not ovf_path.is_file() or ovf_path.is_symlink():
        raise OvaValidationError("OVF source must be a regular file and not a symlink.")
    ovf_path = ovf_path.resolve(strict=True)
    topology = _validate_topology(ovf_path)
    return {
        "schema_version": 1,
        "kind": "atlaso-validated-ovf",
        "ovf": ovf_path.name,
        "machine": EXPECTED_MACHINE,
        "payload_files": [str(topology[slot]["file"]) for slot in EXPECTED_PAYLOADS],
    }


def _validate_provenance(path: Path, topology: dict[int, dict[str, Any]], directory: Path) -> dict[str, Any]:
    """Validate provenance against the extracted payload bytes and OVF roles.

    Args:
        path: Extracted provenance JSON path.
        topology: Validated disk topology by SCSI slot.
        directory: Extracted OVA member directory.
    """

    try:
        provenance = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OvaValidationError("OVA provenance is unreadable or invalid JSON.") from exc
    if not isinstance(provenance, dict):
        raise OvaValidationError("OVA provenance must be a JSON object.")
    if provenance.get("schema_version") != 1 or provenance.get("kind") != "atlaso-vmware-ova-provenance":
        raise OvaValidationError("OVA provenance has an unsupported identity or schema.")
    if not VERSION_PATTERN.fullmatch(str(provenance.get("product_version", ""))):
        raise OvaValidationError("OVA provenance has an invalid product version.")
    if not COMMIT_PATTERN.fullmatch(str(provenance.get("source_commit", ""))):
        raise OvaValidationError("OVA provenance has an invalid source commit.")
    if provenance.get("machine") != EXPECTED_MACHINE:
        raise OvaValidationError("OVA provenance machine topology does not match the Atlaso contract.")
    payloads = provenance.get("payloads")
    if not isinstance(payloads, list) or len(payloads) != 2:
        raise OvaValidationError("OVA provenance must bind exactly two payload disks.")
    by_slot = {record.get("scsi_slot"): record for record in payloads if isinstance(record, dict)}
    if set(by_slot) != {0, 1}:
        raise OvaValidationError("OVA provenance payload slots must be exactly 0 and 1.")
    for slot, (role, _name, capacity) in EXPECTED_PAYLOADS.items():
        record = by_slot[slot]
        disk = topology[slot]
        file_name = str(record.get("file", ""))
        file_path = directory / file_name
        if (
            record.get("role") != role
            or file_name != disk["file"]
            or record.get("virtual_size_bytes") != capacity
            or not file_path.is_file()
            or record.get("sha256") != _sha256(file_path)
        ):
            raise OvaValidationError(f"OVA provenance does not bind the payload at SCSI slot {slot}.")
    return cast(dict[str, Any], provenance)


def validate_ova(ova_path: Path, *, extraction_directory: Path) -> dict[str, Any]:
    """Validate one OVA and return its normalized immutable contract.

    Args:
        ova_path: Canonical OVA archive.
        extraction_directory: Empty verified-member destination.
    """

    if ova_path.is_symlink() or not ova_path.is_file():
        raise OvaValidationError("OVA source must be an existing ordinary file, not a symlink.")
    if ova_path.stat().st_size <= 0 or ova_path.stat().st_size >= MAXIMUM_GITHUB_ASSET_BYTES:
        raise OvaValidationError("OVA source is empty or exceeds the GitHub asset limit.")
    ova_path = ova_path.resolve(strict=True)
    names = _extract_members(ova_path, extraction_directory)
    ovf_names = [name for name in names if name.lower().endswith(".ovf")]
    manifest_names = [name for name in names if name.lower().endswith(".mf")]
    vmdk_names = [name for name in names if name.lower().endswith(".vmdk")]
    provenance_names = [name for name in names if name == "atlaso-provenance.json"]
    if len(ovf_names) != 1 or len(manifest_names) != 1 or len(vmdk_names) != 2 or len(provenance_names) != 1:
        raise OvaValidationError("OVA must contain one OVF, one manifest, one provenance record, and two payload VMDKs.")
    if set(names) != set(ovf_names + manifest_names + vmdk_names + provenance_names):
        raise OvaValidationError("OVA contains an unexpected member.")
    manifest = _read_manifest(extraction_directory / manifest_names[0])
    covered = set(ovf_names + vmdk_names + provenance_names)
    if set(manifest) != covered:
        raise OvaValidationError("OVA manifest does not cover exactly the OVF, provenance, and two payload VMDKs.")
    mismatches = [name for name in sorted(covered) if _sha256(extraction_directory / name) != manifest[name]]
    if mismatches:
        raise OvaValidationError(f"OVA manifest verification failed: {', '.join(mismatches)}")
    topology = _validate_topology(extraction_directory / ovf_names[0])
    referenced_payloads = {str(topology[slot]["file"]) for slot in EXPECTED_PAYLOADS}
    if referenced_payloads != set(vmdk_names):
        raise OvaValidationError("OVF payload references must identify exactly the two VMDKs carried by the OVA.")
    provenance = _validate_provenance(
        extraction_directory / provenance_names[0],
        topology,
        extraction_directory,
    )
    return {
        "schema_version": 1,
        "kind": "atlaso-validated-ova",
        "ova": ova_path.name,
        "ova_sha256": _sha256(ova_path),
        "ovf": ovf_names[0],
        "manifest": manifest_names[0],
        "provenance": provenance_names[0],
        "product_version": provenance["product_version"],
        "source_commit": provenance["source_commit"],
        "machine": EXPECTED_MACHINE,
        "payloads": provenance["payloads"],
    }


def main(argv: list[str] | None = None) -> int:
    """Run the OVA validator command-line interface.

    Args:
        argv: Optional command-line argument sequence.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ova", nargs="?", type=Path, help="Canonical Atlaso OVA to verify.")
    parser.add_argument("--ovf", type=Path, help="Canonical OVF descriptor to verify before provenance is written.")
    parser.add_argument(
        "--extract-directory",
        type=Path,
        help="Empty destination that receives verified flat OVA members.",
    )
    args = parser.parse_args(argv)
    if (args.ova is None) == (args.ovf is None):
        parser.error("provide exactly one OVA path or --ovf descriptor path.")
    try:
        if args.ovf is not None:
            if args.extract_directory is not None:
                parser.error("--extract-directory cannot be used with --ovf.")
            result = validate_ovf(args.ovf)
        else:
            if args.extract_directory is None:
                parser.error("--extract-directory is required when validating an OVA.")
            result = validate_ova(args.ova, extraction_directory=args.extract_directory)
    except (OSError, tarfile.TarError, OvaValidationError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
