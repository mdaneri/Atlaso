"""Create and validate an Atlaso OVF package from two prepared payload disks."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from scripts.virtualization.validate_ova import (
    EXPECTED_EMPTY_DISK_BYTES,
    EXPECTED_EMPTY_DISKS,
    EXPECTED_MACHINE,
    EXPECTED_NETWORKS,
    EXPECTED_PAYLOADS,
    MAXIMUM_GITHUB_ASSET_BYTES,
    OVF,
    RASD,
    VMW,
    validate_ova,
)

VSSD = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
VMDK_FORMAT = "http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"
VMDK_NAMES = ("atlaso-photon.vmdk", "atlaso-system.vmdk")
PROPERTIES = (
    ("Management network", (
        ("cidr", "Management IPv4 CIDR", "Static IPv4 address with prefix. Leave blank for DHCPv4.", "string"),
        ("gateway", "Management IPv4 gateway", "Required with static IPv4 addressing.", "string"),
        ("ipv6_enabled", "Enable management IPv6", "Use SLAAC when static IPv6 addressing is blank.", "boolean"),
        ("ipv6_cidr", "Management IPv6 CIDR", "Optional static IPv6 address with prefix.", "string"),
        ("ipv6_gateway", "Management IPv6 gateway", "Optional IPv6 default gateway.", "string"),
        ("dns_servers", "DNS servers", "Optional resolver IP addresses.", "string"),
    )),
    ("Appliance identity", (
        ("fqdn", "Appliance FQDN", "Fully qualified hostname for the deployed appliance.", "string"),
    )),
    ("Initial credentials", (
        ("admin_password", "Atlaso admin password", "Initial Atlaso web password.", "password"),
        ("root_password", "Photon root password", "Initial root console password.", "password"),
        ("root_ssh_enabled", "Enable Photon root SSH", "Allow root password authentication over SSH.", "boolean"),
    )),
)


def digest(path: Path, algorithm: str = "sha256") -> str:
    """Hash one file without loading its payload into memory.

    Args:
        path: File to hash.
        algorithm: Hash algorithm accepted by hashlib.
    """
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def disk_info(path: Path, image_format: str) -> dict[str, Any]:
    """Read the explicit image format and virtual capacity through QEMU.

    Args:
        path: Disk image to inspect.
        image_format: Explicit QEMU image format.
    """
    return json.loads(subprocess.check_output(
        ["qemu-img", "info", "--output=json", "-f", image_format, str(path)], timeout=60,
    ))


def require_stream_vmdk(path: Path, size: int) -> None:
    """Accept only a standalone stream-optimized disk of the expected capacity.

    Args:
        path: VMDK to admit.
        size: Required virtual capacity in bytes.
    """
    info = disk_info(path, "vmdk")
    details = info["format-specific"]["data"]
    extents = details["extents"]
    if (
        info["virtual-size"] != size
        or info.get("backing-filename")
        or details["parent-cid"] != 0xFFFFFFFF
        or details["create-type"] != "streamOptimized"
        or len(extents) != 1
        or not extents[0]["compressed"]
        or Path(extents[0]["filename"]).resolve() != path.resolve()
    ):
        raise ValueError("VMDK is not a standalone stream-optimized disk of the expected size")


def ovf_element(parent: ET.Element, tag: str, text: str = "", **attrs: str) -> ET.Element:
    """Append an OVF element with namespaced attributes.

    Args:
        parent: Parent in the descriptor tree.
        tag: Local OVF element name.
        text: Optional element text.
        **attrs: OVF attribute names and values.
    """
    elem = ET.SubElement(parent, f"{{{OVF}}}{tag}", {f"{{{OVF}}}{key}": val for key, val in attrs.items()})
    elem.text = text or None
    return elem


def hardware_item(hardware: ET.Element, **fields: str) -> None:
    """Write one RASD item in schema order.

    Args:
        hardware: Virtual hardware section receiving the item.
        **fields: RASD field names and values.
    """
    item = ovf_element(hardware, "Item")
    for name, value in sorted(fields.items()):
        ET.SubElement(item, f"{{{RASD}}}{name}").text = value


def write_ovf(path: Path, sizes: tuple[int, int]) -> None:
    """Write the four-disk Atlaso descriptor and deployment properties.

    Args:
        path: Destination OVF descriptor.
        sizes: Stored VMDK lengths in Photon and System Content order.
    """
    for prefix, namespace in (("ovf", OVF), ("rasd", RASD), ("vssd", VSSD), ("vmw", VMW)):
        ET.register_namespace(prefix, namespace)
    root = ET.Element(f"{{{OVF}}}Envelope")
    refs = ovf_element(root, "References")
    disks = ovf_element(root, "DiskSection")
    ovf_element(disks, "Info", "Atlaso virtual disks")
    for slot, (filename, size) in enumerate(zip(VMDK_NAMES, sizes, strict=True)):
        ref = f"file{slot}"
        ovf_element(refs, "File", id=ref, href=filename, size=str(size))
        role, _, capacity = EXPECTED_PAYLOADS[slot]
        ovf_element(disks, "Disk", diskId=role, fileRef=ref, capacity=str(capacity), format=VMDK_FORMAT)
    for disk_id, _ in EXPECTED_EMPTY_DISKS.values():
        ovf_element(disks, "Disk", diskId=disk_id, capacity=str(EXPECTED_EMPTY_DISK_BYTES), format=VMDK_FORMAT)

    networks = ovf_element(root, "NetworkSection")
    ovf_element(networks, "Info", "Atlaso management and service networks")
    for network_name in EXPECTED_NETWORKS:
        ovf_element(ovf_element(networks, "Network", name=network_name), "Description", network_name)

    system = ovf_element(root, "VirtualSystem", id="atlaso")
    ovf_element(system, "Info", "Atlaso Photon Appliance")
    ovf_element(system, "Name", "Atlaso Photon Appliance")
    os_section = ovf_element(system, "OperatingSystemSection", id="36")
    os_section.set(f"{{{VMW}}}osType", "vmwarePhoton64Guest")
    ovf_element(os_section, "Info", "Guest operating system")
    ovf_element(os_section, "Description", "Photon OS 5.0 x86_64")
    product = ovf_element(system, "ProductSection", **{"class": "atlaso"})
    ovf_element(product, "Info", "Atlaso deployment properties")
    ovf_element(product, "Product", "Atlaso Photon Appliance")
    for category, properties in PROPERTIES:
        ovf_element(product, "Category", category)
        for key, label, description, kind in properties:
            attributes = {"key": key, "type": kind, "userConfigurable": "true",
                          "required": str(kind == "password" or key == "fqdn").lower()}
            if kind == "password":
                attributes["qualifiers"] = "MinLen(12)"
            if kind == "boolean":
                attributes["value"] = "false"
            prop = ovf_element(product, "Property", **attributes)
            ovf_element(prop, "Label", label)
            ovf_element(prop, "Description", description)

    hardware = ovf_element(system, "VirtualHardwareSection", transport="com.vmware.guestInfo")
    ovf_element(hardware, "Info", "Atlaso virtual hardware")
    hardware_system = ovf_element(hardware, "System")
    for name, value in (("ElementName", "Virtual Hardware Family"), ("InstanceID", "0"),
                        ("VirtualSystemIdentifier", "atlaso"), ("VirtualSystemType", "vmx-21")):
        ET.SubElement(hardware_system, f"{{{VSSD}}}{name}").text = value
    hardware_item(hardware, ElementName="4 virtual CPUs", InstanceID="1", ResourceType="3",
                  AllocationUnits="hertz * 10^6", VirtualQuantity="4")
    hardware_item(hardware, ElementName="4096 MiB of memory", InstanceID="2", ResourceType="4",
                  AllocationUnits="byte * 2^20", VirtualQuantity="4096")
    hardware_item(hardware, Address="0", ElementName="SCSI controller 0", InstanceID="3",
                  ResourceType="6", ResourceSubType="VirtualSCSI")
    for index, network in enumerate(EXPECTED_NETWORKS, start=1):
        hardware_item(hardware, AutomaticAllocation="true", Connection=network,
                      ElementName=f"Network adapter {index}", InstanceID=str(3 + index),
                      ResourceType="10", ResourceSubType="VmxNet3")
    disk_roles = [(role, label) for role, label, _ in EXPECTED_PAYLOADS.values()]
    disk_roles.extend(EXPECTED_EMPTY_DISKS.values())
    for slot, (disk_id, label) in enumerate(disk_roles):
        hardware_item(hardware, AddressOnParent=str(slot), ElementName=label, InstanceID=str(6 + slot),
                      HostResource=f"ovf:/disk/{disk_id}", Parent="3", ResourceType="17")
    for key, value in (("firmware", "efi"), ("bootOptions.efiSecureBootEnabled", "false"), ("disk.EnableUUID", "true")):
        ET.SubElement(hardware, f"{{{VMW}}}Config",
                      {f"{{{OVF}}}required": "false", f"{{{VMW}}}key": key, f"{{{VMW}}}value": value})
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def package(output: Path, version: str, commit: str, build: dict[str, Any], extraction: Path) -> Path:
    """Assemble, size-check and independently validate the five-member OVA.

    Args:
        output: Directory containing both named payload VMDKs.
        version: Synchronized Atlaso product version.
        commit: Full Atlaso source commit.
        build: Trial builder and guest provenance.
        extraction: Empty destination for independent validation.
    """
    payload_sizes = tuple((output / filename).stat().st_size for filename in VMDK_NAMES)
    if any(not 0 < size <= MAXIMUM_GITHUB_ASSET_BYTES for size in payload_sizes):
        raise ValueError("A payload exceeds the GitHub release asset limit")
    ovf = output / "atlaso.ovf"
    write_ovf(ovf, (payload_sizes[0], payload_sizes[1]))
    provenance_path = output / "atlaso-provenance.json"
    payloads = []
    for slot, filename in enumerate(VMDK_NAMES):
        role, _, capacity = EXPECTED_PAYLOADS[slot]
        require_stream_vmdk(output / filename, capacity)
        payloads.append({
            "role": role, "scsi_slot": slot, "file": filename,
            "virtual_size_bytes": capacity, "sha256": digest(output / filename),
        })
    provenance = {
        "kind": "atlaso-vmware-ova-provenance", "schema_version": 1,
        "product_version": version, "source_commit": commit, "machine": EXPECTED_MACHINE,
        "payloads": payloads, "trial_build": build,
    }
    provenance_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    vmdks = [output / filename for filename in VMDK_NAMES]
    manifest = output / "atlaso.mf"
    manifest.write_text(
        "".join(f"SHA256({file.name})= {digest(file)}\n" for file in (ovf, provenance_path, *vmdks)),
        encoding="ascii",
    )
    members = [ovf, manifest, *vmdks, provenance_path]
    tar_size = sum(512 + (file.stat().st_size + 511) // 512 * 512 for file in members) + 1024
    tar_size = (tar_size + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE * tarfile.RECORDSIZE
    if tar_size > MAXIMUM_GITHUB_ASSET_BYTES:
        raise ValueError("The assembled OVA would exceed the GitHub release asset limit")
    ova = output / f"Atlaso-{version}-photon-ova-trial.ova"
    with tarfile.open(ova, "x", format=tarfile.USTAR_FORMAT) as archive:
        for member in members:
            entry = tarfile.TarInfo(member.name)
            entry.size = member.stat().st_size
            entry.mode = 0o644
            with member.open("rb") as stream:
                archive.addfile(entry, stream)
    validate_ova(ova, extraction_directory=extraction)
    return ova
