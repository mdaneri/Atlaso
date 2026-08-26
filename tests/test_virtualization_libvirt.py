"""Focused tests for the post-virt-v2v libvirt contract."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts.virtualization import normalize_libvirt as normalizer


def _domain(tmp_path: Path, *, disk_count: int = 4) -> ET.Element:
    """Return a representative inactive virt-v2v domain definition."""

    disks = "".join(
        f"""
        <disk type="file" device="disk">
          <source file="{tmp_path / f'disk-{index}.qcow2'}"/>
          <target dev="vd{chr(ord('a') + index)}" bus="virtio"/>
        </disk>
        """
        for index in range(disk_count)
    )
    return ET.fromstring(
        f"""
        <domain type="kvm">
          <name>atlaso</name>
          <memory unit="MiB">1024</memory>
          <currentMemory unit="MiB">1024</currentMemory>
          <vcpu>1</vcpu>
          <os>
            <type arch="x86_64" machine="pc-q35-9.2">hvm</type>
            <loader readonly="yes" type="pflash">/usr/share/OVMF/OVMF_CODE.fd</loader>
            <nvram>/var/lib/libvirt/qemu/nvram/atlaso_VARS.fd</nvram>
          </os>
          <devices>
            {disks}
            <controller type="scsi" model="lsilogic"/>
            <interface type="bridge"><source bridge="old0"/><model type="e1000"/></interface>
            <interface type="bridge"><source bridge="old1"/><model type="e1000"/></interface>
          </devices>
        </domain>
        """,
    )


def test_normalizes_exact_machine_network_disk_and_agent_contract(tmp_path: Path) -> None:
    """Normalization produces an idempotent four-disk UEFI libvirt definition."""

    root = normalizer.normalize_domain(
        _domain(tmp_path),
        management_network="atlaso-management",
        service_network="atlaso-services",
    )

    normalizer.assert_normalized(
        root,
        management_network="atlaso-management",
        service_network="atlaso-services",
    )
    assert root.find("memory").text == "4194304"  # type: ignore[union-attr]
    assert root.find("vcpu").text == "4"  # type: ignore[union-attr]
    assert root.find("os/loader").get("secure") == "no"  # type: ignore[union-attr]
    assert [element.get("dev") for element in root.findall("os/boot")] == ["hd"]
    assert [disk.find("target").get("dev") for disk in root.findall("devices/disk")] == [  # type: ignore[union-attr]
        "sda",
        "sdb",
        "sdc",
        "sdd",
    ]
    assert [disk.find("address").attrib for disk in root.findall("devices/disk")] == [  # type: ignore[union-attr]
        {"type": "drive", "controller": "0", "bus": "0", "target": "0", "unit": str(index)}
        for index in range(4)
    ]
    assert [interface.find("source").get("network") for interface in root.findall("devices/interface")] == [  # type: ignore[union-attr]
        "atlaso-management",
        "atlaso-services",
    ]
    assert root.find("devices/channel/target").get("name") == "org.qemu.guest_agent.0"  # type: ignore[union-attr]
    assert normalizer.disk_source_paths(root) == [str(tmp_path / f"disk-{index}.qcow2") for index in range(4)]


def test_rejects_secure_boot_ovmf_loader(tmp_path: Path) -> None:
    """A secure-code OVMF path cannot be normalized by changing only XML metadata."""

    root = _domain(tmp_path)
    loader = root.find("os/loader")
    assert loader is not None
    loader.text = "/usr/share/OVMF/OVMF_CODE.secboot.fd"

    with pytest.raises(normalizer.LibvirtContractError, match="Secure Boot OVMF"):
        normalizer.normalize_domain(root, management_network="management", service_network="services")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing_loader", "UEFI pflash"),
        ("wrong_disk_count", "exactly four disks"),
        ("wrong_machine", "q35"),
        ("duplicate_controller", "conflicting SCSI controllers"),
    ],
)
def test_rejects_unsafe_or_conflicting_virt_v2v_output(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    """Contradictory firmware and topology cannot be silently normalized."""

    root = _domain(tmp_path, disk_count=3 if mutation == "wrong_disk_count" else 4)
    if mutation == "missing_loader":
        os_element = root.find("os")
        loader = root.find("os/loader")
        assert os_element is not None and loader is not None
        os_element.remove(loader)
    elif mutation == "wrong_machine":
        root.find("os/type").set("machine", "pc-i440fx-9.2")  # type: ignore[union-attr]
    elif mutation == "duplicate_controller":
        ET.SubElement(root.find("devices"), "controller", {"type": "scsi"})  # type: ignore[arg-type]

    with pytest.raises(normalizer.LibvirtContractError, match=message):
        normalizer.normalize_domain(root, management_network="management", service_network="services")


def test_rejects_duplicate_guest_agent_channel(tmp_path: Path) -> None:
    """Only one well-known QEMU guest-agent channel may be present."""

    root = _domain(tmp_path)
    devices = root.find("devices")
    for _ in range(2):
        channel = ET.SubElement(devices, "channel", {"type": "unix"})  # type: ignore[arg-type]
        ET.SubElement(channel, "target", {"type": "virtio", "name": "org.qemu.guest_agent.0"})

    with pytest.raises(normalizer.LibvirtContractError, match="duplicate QEMU guest-agent"):
        normalizer.normalize_domain(root, management_network="management", service_network="services")
