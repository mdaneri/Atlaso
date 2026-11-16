"""Inspect the four disk attachments of a locally imported Atlaso OVA."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from contextlib import ExitStack
from pathlib import Path

from scripts.completed_task_files import FileRefusal, WindowsFiles
from scripts.interop.certificate_peer_factory import Refusal, standalone_disk
from scripts.virtualization.validate_ova import (
    EXPECTED_EMPTY_DISK_BYTES,
    EXPECTED_EMPTY_DISKS,
    EXPECTED_PAYLOADS,
)

_VMX_ASSIGNMENT = re.compile(r'\s*([A-Za-z0-9_.:-]+)\s*=\s*"([^"\r\n]*)"\s*')
_DISK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]*\.vmdk", re.IGNORECASE)
_VMX_MAX_BYTES = 1024 * 1024


def _read_assignments(data: bytes) -> dict[str, str]:
    """Parse one bounded VMX without accepting duplicate assignments.

    Args:
        data: VMX bytes read under the original file pin.
    """
    if len(data) > _VMX_MAX_BYTES:
        raise Refusal("imported_ova_vmx_too_large")
    values: dict[str, str] = {}
    for line in data.decode("utf-8-sig").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _VMX_ASSIGNMENT.fullmatch(line)
        if match is None or match[1].lower() in values:
            raise Refusal("imported_ova_vmx_assignment_invalid")
        values[match[1].lower()] = match[2]
    return values


def inspect_disks(vmx: Path) -> dict[str, object]:
    """Bind the expected disk roles to four distinct standalone backings.

    The owning controller is responsible for process quiescence and directory
    custody before calling this reader. The result is an observation of pinned
    files and carries no boot authority.

    Args:
        vmx: Absolute VMX path returned by the owning import controller.
    """
    if not vmx.is_absolute() or ".." in vmx.parts or vmx.suffix.lower() != ".vmx":
        raise Refusal("imported_ova_vmx_path_invalid")
    files = WindowsFiles()
    with ExitStack() as pins:
        pins.enter_context(files.ancestors(vmx))
        _, vmx_identity, _ = pins.enter_context(files.opened(vmx))
        with vmx.open("rb") as stream:
            data = stream.read(_VMX_MAX_BYTES + 1)
        values = _read_assignments(data)
        if values.get("scsi0.present", "").upper() != "TRUE" or values.get("scsi0.virtualdev", "").lower() != "pvscsi":
            raise Refusal("imported_ova_controller_invalid")

        contracts = {slot: (role, capacity) for slot, (role, _, capacity) in EXPECTED_PAYLOADS.items()}
        contracts.update({slot: (role, EXPECTED_EMPTY_DISK_BYTES) for slot, (role, _) in EXPECTED_EMPTY_DISKS.items()})
        expected_devices = {f"scsi0:{slot}" for slot in contracts}
        actual_devices = {
            key.removesuffix(".present")
            for key, value in values.items()
            if re.fullmatch(r"(?:scsi|sata|ide|nvme)\d+:\d+\.present", key) and value.upper() == "TRUE"
        }
        if actual_devices != expected_devices:
            raise Refusal("imported_ova_disk_slots_invalid")

        disks: list[dict[str, object]] = []
        seen: set[tuple[int, int, int]] = set()
        for slot, (role, expected_capacity) in sorted(contracts.items()):
            device = f"scsi0:{slot}"
            name = values.get(f"{device}.filename", "")
            device_type = values.get(f"{device}.devicetype", "scsi-harddisk")
            if not _DISK_NAME.fullmatch(name) or device_type.lower() not in {"disk", "scsi-harddisk"}:
                raise Refusal("imported_ova_disk_backing_invalid")
            disk = vmx.parent / name
            _, identity, _ = pins.enter_context(files.opened(disk))
            if identity in seen or standalone_disk(disk) != expected_capacity:
                raise Refusal("imported_ova_disk_identity_or_capacity_invalid")
            seen.add(identity)
            disks.append({
                "slot": slot,
                "role": role,
                "file": name,
                "identity": list(identity),
                "virtual_size_bytes": expected_capacity,
            })
        return {"vmx_identity": list(vmx_identity), "vmx_sha256": hashlib.sha256(data).hexdigest(), "disks": disks}


def main() -> int:
    """Print the observed disk layout or a fixed refusal."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vmx", type=Path)
    args = parser.parse_args()
    try:
        result = inspect_disks(args.vmx)
    except (OSError, ValueError, FileRefusal):
        print(json.dumps({"success": False, "reason": "imported_ova_disk_inspection_failed"}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
