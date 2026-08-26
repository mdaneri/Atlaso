"""Normalize and verify the Atlaso libvirt domain contract after virt-v2v."""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path


class LibvirtContractError(ValueError):
    """Report one unsafe or conflicting libvirt domain definition."""


def _require(parent: ET.Element | None, path: str, message: str) -> ET.Element:
    """Return one required child element."""

    if parent is None:
        raise LibvirtContractError(message)
    element = parent.find(path)
    if element is None:
        raise LibvirtContractError(message)
    return element


def normalize_domain(root: ET.Element, *, management_network: str, service_network: str) -> ET.Element:
    """Return the exact four-disk, two-NIC Atlaso libvirt definition."""

    normalized = deepcopy(root)
    if normalized.tag != "domain":
        raise LibvirtContractError("Libvirt XML root must be a domain.")
    memory = _require(normalized, "memory", "Libvirt domain has no memory declaration.")
    memory.text = "4194304"
    memory.set("unit", "KiB")
    current_memory = normalized.find("currentMemory")
    if current_memory is not None:
        current_memory.text = "4194304"
        current_memory.set("unit", "KiB")
    vcpu = _require(normalized, "vcpu", "Libvirt domain has no vCPU declaration.")
    vcpu.text = "4"

    os_element = _require(normalized, "os", "Libvirt domain has no OS declaration.")
    machine = _require(os_element, "type", "Libvirt domain has no machine type.")
    if "q35" not in machine.get("machine", ""):
        raise LibvirtContractError("virt-v2v output must use a q35 machine type.")
    loader = _require(os_element, "loader", "virt-v2v output must preserve UEFI pflash firmware.")
    if loader.get("type") != "pflash" or not (loader.text or "").strip():
        raise LibvirtContractError("virt-v2v output must preserve one explicit UEFI pflash loader.")
    loader_path = (loader.text or "").strip().lower()
    if "secboot" in loader_path or "secureboot" in loader_path:
        raise LibvirtContractError("virt-v2v selected a Secure Boot OVMF loader.")
    loader.set("secure", "no")
    for boot in os_element.findall("boot"):
        os_element.remove(boot)
    ET.SubElement(os_element, "boot", {"dev": "hd"})

    devices = _require(normalized, "devices", "Libvirt domain has no device collection.")
    disks = [disk for disk in devices.findall("disk") if disk.get("device") == "disk"]
    if len(disks) != 4:
        raise LibvirtContractError("Libvirt domain must contain exactly four disks before normalization.")
    for index, disk in enumerate(disks):
        target = _require(disk, "target", f"Libvirt disk {index} has no target.")
        target.set("bus", "scsi")
        target.set("dev", f"sd{chr(ord('a') + index)}")
        address = disk.find("address")
        if address is None:
            address = ET.SubElement(disk, "address")
        address.attrib.clear()
        address.attrib.update(
            {"type": "drive", "controller": "0", "bus": "0", "target": "0", "unit": str(index)}
        )
    controllers = [controller for controller in devices.findall("controller") if controller.get("type") == "scsi"]
    if len(controllers) > 1:
        raise LibvirtContractError("Libvirt domain contains conflicting SCSI controllers.")
    if not controllers:
        controllers = [ET.SubElement(devices, "controller", {"type": "scsi"})]
    controllers[0].set("model", "virtio-scsi")
    controllers[0].set("index", "0")

    interfaces = devices.findall("interface")
    if len(interfaces) != 2:
        raise LibvirtContractError("Libvirt domain must contain exactly two network interfaces.")
    for interface, network in zip(interfaces, (management_network, service_network), strict=True):
        interface.set("type", "network")
        source = interface.find("source")
        if source is None:
            source = ET.SubElement(interface, "source")
        source.attrib.clear()
        source.set("network", network)
        model = interface.find("model")
        if model is None:
            model = ET.SubElement(interface, "model")
        model.set("type", "virtio")

    agent_channels = []
    for channel in devices.findall("channel"):
        channel_target = channel.find("target")
        if channel_target is not None and channel_target.get("name") == "org.qemu.guest_agent.0":
            agent_channels.append(channel)
    if len(agent_channels) > 1:
        raise LibvirtContractError("Libvirt domain contains duplicate QEMU guest-agent channels.")
    if not agent_channels:
        channel = ET.SubElement(devices, "channel", {"type": "unix"})
        ET.SubElement(channel, "target", {"type": "virtio", "name": "org.qemu.guest_agent.0"})
    else:
        target = _require(agent_channels[0], "target", "QEMU guest-agent channel has no target.")
        target.set("type", "virtio")
    return normalized


def assert_normalized(root: ET.Element, *, management_network: str, service_network: str) -> None:
    """Require an input definition to already equal the normalized contract."""

    normalized = normalize_domain(root, management_network=management_network, service_network=service_network)
    if ET.tostring(root, encoding="unicode") != ET.tostring(normalized, encoding="unicode"):
        raise LibvirtContractError("Libvirt domain does not match the normalized Atlaso machine contract.")


def disk_source_paths(root: ET.Element) -> list[str]:
    """Return the four ordered local disk paths from a libvirt definition."""

    devices = _require(root, "devices", "Libvirt domain has no device collection.")
    disks = [disk for disk in devices.findall("disk") if disk.get("device") == "disk"]
    if len(disks) != 4:
        raise LibvirtContractError("Libvirt domain must contain exactly four disks.")
    paths: list[str] = []
    for index, disk in enumerate(disks):
        source = _require(disk, "source", f"Libvirt disk {index} has no source.")
        path = source.get("file") or source.get("dev")
        if not path or not Path(path).is_absolute():
            raise LibvirtContractError(f"Libvirt disk {index} has no absolute local source path.")
        paths.append(path)
    return paths


def main(argv: list[str] | None = None) -> int:
    """Run the libvirt normalizer command-line interface."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Input libvirt domain XML.")
    parser.add_argument("--management-network", required=True)
    parser.add_argument("--service-network", required=True)
    parser.add_argument("--output", type=Path, help="Destination for normalized XML.")
    parser.add_argument("--check", action="store_true", help="Require the input to already be normalized.")
    parser.add_argument(
        "--print-disk-sources",
        action="store_true",
        help="Print the four ordered absolute disk source paths.",
    )
    args = parser.parse_args(argv)
    try:
        root = ET.parse(args.input).getroot()
        if args.check and args.print_disk_sources:
            parser.error("--check and --print-disk-sources are mutually exclusive.")
        if args.print_disk_sources:
            for path in disk_source_paths(root):
                print(path)
        elif args.check:
            assert_normalized(
                root,
                management_network=args.management_network,
                service_network=args.service_network,
            )
        else:
            if args.output is None:
                parser.error("--output is required unless --check is used.")
            normalized = normalize_domain(
                root,
                management_network=args.management_network,
                service_network=args.service_network,
            )
            ET.ElementTree(normalized).write(args.output, encoding="utf-8", xml_declaration=True)
    except (OSError, ET.ParseError, LibvirtContractError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
