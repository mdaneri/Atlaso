"""Observe appliance hardware without reconciling desired state or owning devices."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from atlaso.app.services.networking import (
    HostPhysicalInterface,
    parse_linux_ip_interfaces,
)


def _text(path: Path) -> str:
    """Read a bounded, optional native hardware attribute.

    Args:
        path: Fixed procfs or sysfs attribute to observe.
    """
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            return stream.read(16384).strip()
    except OSError:
        return ""


def observed_interfaces() -> list[HostPhysicalInterface]:
    """Validate native JSON before reusing the physical-interface observation parser."""
    result = subprocess.run(["ip", "-j", "address", "show"], capture_output=True, text=True, timeout=15, check=True)
    if len(result.stdout) > 1024 * 1024:
        raise ValueError("Interface observation exceeded its bound")
    payload = json.loads(result.stdout)
    if not isinstance(payload, list) or len(payload) > 512 or any(not isinstance(row, dict) for row in payload):
        raise ValueError("Invalid interface observation")
    return parse_linux_ip_interfaces(result.stdout)


def _disk_usage(row: dict[str, Any]) -> tuple[str, str]:
    """Associate filesystem and mount observations from descendants with their disk.

    Args:
        row: One observed disk or optical device and its lsblk child tree.
    """
    pending = [row]
    filesystems: dict[str, None] = {}
    mounts: dict[str, None] = {}
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > 512:
            raise ValueError("Disk child observation exceeded its bound")
        filesystem = node.get("fstype")
        if filesystem:
            if not isinstance(filesystem, str):
                raise ValueError("Invalid filesystem observation")
            filesystems[filesystem] = None
        mountpoints = node.get("mountpoints") or []
        children = node.get("children") or []
        if not isinstance(mountpoints, list) or any(value is not None and not isinstance(value, str) for value in mountpoints):
            raise ValueError("Invalid mount observation")
        if not isinstance(children, list) or any(not isinstance(child, dict) for child in children):
            raise ValueError("Invalid disk child observation")
        for mount in mountpoints:
            if mount:
                mounts[mount] = None
        pending.extend(reversed(children))
    return ", ".join(filesystems), ", ".join(mounts)


def hardware_inventory() -> dict[str, Any]:
    """Return independent summary, disk and NIC observations with failure states."""
    result: dict[str, Any] = {
        "status": "unsupported", "reason": "Hardware observation requires the Linux appliance.",
        "manufacturer": "", "model": "", "architecture": platform.machine(),
        "cpu": "", "cpu_count": os.cpu_count(), "memory_bytes": None,
        "kernel": platform.release(), "disks": [], "interfaces": [],
        "disks_state": "unknown", "interfaces_state": "unknown",
    }
    if platform.system() != "Linux":
        return result
    dmi = Path("/sys/class/dmi/id")
    result.update(status="available", reason="", manufacturer=_text(dmi / "sys_vendor"),
                  model=_text(dmi / "product_name"))
    for line in _text(Path("/proc/cpuinfo")).splitlines():
        key, _, value = line.partition(":")
        if key.strip() in {"model name", "Hardware"}:
            result["cpu"] = value.strip()
            break
    for line in _text(Path("/proc/meminfo")).splitlines():
        if line.startswith("MemTotal:"):
            try:
                result["memory_bytes"] = int(line.split()[1]) * 1024
            except (ValueError, IndexError):
                pass
    try:
        observation = subprocess.run(
            ["lsblk", "--json", "--bytes", "--output", "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,FSTYPE,MOUNTPOINTS"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        if len(observation.stdout) > 1024 * 1024:
            raise ValueError("Disk observation exceeded its bound")
        payload = json.loads(observation.stdout)
        disks = payload["blockdevices"]
        if not isinstance(disks, list) or len(disks) > 512:
            raise ValueError("Invalid disk observation")
        disk_rows = []
        for row in disks:
            if not isinstance(row, dict) or row.get("type") not in {"disk", "rom"}:
                continue
            filesystem, mounts = _disk_usage(row)
            disk_rows.append({
                "device_path": row.get("path") or row.get("name") or "",
                "model": row.get("model") or "", "serial": row.get("serial") or "",
                "size_bytes": row.get("size"), "transport": row.get("tran") or "",
                "filesystem_type": filesystem, "mount_path": mounts,
            })
        result["disks"] = disk_rows
        result["disks_state"] = "available"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result["disks_reason"] = "Disk inventory could not be read. Check lsblk availability and retry."
    try:
        interfaces = observed_interfaces()
        result["interfaces"] = [
            {"name": row.name, "mac": row.mac_address, "driver": row.driver or "",
             "link_state": row.oper_state, "speed_mbps": (row.speed or "").removesuffix(" Mbps"),
             "addresses": [*row.host_ip_cidrs, *row.host_ipv6_cidrs]}
            for row in interfaces
        ]
        result["interfaces_state"] = "available"
    except (OSError, ValueError, RuntimeError, TypeError, AttributeError, subprocess.SubprocessError):
        result["interfaces_reason"] = "Network-adapter inventory could not be read. Retry the hardware check."
    return result
