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
        result["disks"] = [
            {"device_path": row.get("path") or row.get("name") or "",
             "model": row.get("model") or "", "serial": row.get("serial") or "",
             "size_bytes": row.get("size"), "transport": row.get("tran") or "",
             "filesystem_type": row.get("fstype") or "",
             "mount_path": ", ".join(str(value) for value in row.get("mountpoints") or [] if value)}
            for row in disks if isinstance(row, dict) and row.get("type") in {"disk", "rom"}
        ]
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
