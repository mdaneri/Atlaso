"""Bounded Photon observations shared by Monitor and its listener helper."""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import time
from ipaddress import ip_address
from pathlib import Path
from typing import Any

NATIVE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT = 1_048_576
MAX_ROWS = 2048

# Unit names and destinations are server-owned.
SERVICE_UNITS = {
    "atlaso.service": ("Atlaso", "/dashboard"),
    "atlaso-worker.service": ("Atlaso worker", "/tasks"),
    "nginx.service": ("nginx", "/services"),
    "systemd-networkd.service": ("Network", "/physical-interfaces"),
    "systemd-resolved.service": ("System resolver", "/dns"),
    "dnsmasq.service": ("DNS / DHCP", "/dhcp"),
    "atlaso-dns-authoritative.service": ("Authoritative DNS", "/dns"),
    "ntpd.service": ("NTP / NTS", "/ntp"),
    "slapd.service": ("Managed LDAP", "/ldap"),
    "atlaso-kmip.service": ("KMIP", "/vsphere-key-providers"),
    "nfs-server.service": ("NFS", "/esx-storage"),
}


class ObservationUnavailable(ValueError):
    """A bounded native observation could not be completed."""


def run_native(args: list[str], deadline: float) -> tuple[int, str]:
    """Run one native command using a fixed search path and bounded output."""
    executable = shutil.which(args[0], path=NATIVE_PATH) if os.name == "posix" else None
    if not executable or time.monotonic() >= deadline:
        raise ObservationUnavailable
    try:
        with subprocess.Popen(
            [executable, *args[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env={"PATH": NATIVE_PATH, "LC_ALL": "C"},
        ) as process:
            assert process.stdout is not None
            output = bytearray()
            try:
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))
                    if not ready:
                        break
                    block = os.read(process.stdout.fileno(), 65536)
                    if not block:
                        return process.wait(timeout=max(0.01, deadline - time.monotonic())), output.decode("utf-8")
                    output.extend(block)
                    if len(output) > MAX_OUTPUT:
                        break
                raise ObservationUnavailable
            finally:
                if process.poll() is None:
                    process.kill()
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise ObservationUnavailable from exc


def listener_endpoint(endpoint: str, family: int) -> tuple[str, int]:
    """Normalize a numeric ss endpoint while preserving a valid IPv6 zone."""
    address, port = endpoint.rsplit(":", 1)
    address = address.removeprefix("[").removesuffix("]")
    if address == "*":
        address = "0.0.0.0" if family == 4 else "::"
    parsed = ip_address(address)
    number = int(port)
    if parsed.version != family or not 0 < number <= 65535:
        raise ValueError("Invalid listener endpoint")
    return str(parsed), number


def socket_unit(pid: str, fd: str, inode: str) -> str | None:
    """Verify the observed socket still belongs to the same systemd cgroup."""
    process = Path("/proc") / pid
    try:
        first = (process / "cgroup").read_text(encoding="utf-8")
        if os.readlink(process / "fd" / fd) != f"socket:[{inode}]":
            return None
        if first != (process / "cgroup").read_text(encoding="utf-8"):
            return None
    except OSError:
        return None
    for entry in first.splitlines():
        hierarchy, _, path = entry.partition("::")
        if hierarchy == "0":
            return path
    return None


def collect_listeners() -> dict[str, Any]:
    """Return only numeric endpoints verified in the fixed packaged cgroups."""
    units = {"/system.slice/" + name: name for name in SERVICE_UNITS}
    rows: set[tuple[str, str, str, int]] = set()
    state = "ok"
    deadline = time.monotonic() + 4
    for family in (4, 6):
        try:
            code, output = run_native(["ss", "-H", "-lntupe", f"-{family}"], deadline)
        except ObservationUnavailable:
            state = "partial"
            continue
        if code:
            state = "partial"
            continue
        lines = output.splitlines()
        if len(lines) > MAX_ROWS:
            state = "partial"
        for line in lines[:MAX_ROWS]:
            if time.monotonic() >= deadline:
                state = "partial"
                break
            parts = line.split()
            if len(parts) < 6 or parts[0] not in {"tcp", "udp"}:
                state = "partial"
                continue
            try:
                address, port = listener_endpoint(parts[4], family)
            except ValueError:
                state = "partial"
                continue
            inode = re.search(r"\bino:(\d{1,20})\b", line)
            owners = re.findall(r"\bpid=(\d{1,10}),fd=(\d{1,10})\b", line)
            if inode is None or not owners:
                state = "partial"
                continue
            for pid, fd in owners:
                owner = socket_unit(pid, fd, inode[1])
                if owner is None:
                    state = "partial"
                if unit := units.get(owner or ""):
                    rows.add((unit, parts[0], address, port))
    return {
        "state": "unavailable" if state == "partial" and not rows else state,
        "rows": [
            {"unit": unit, "protocol": protocol, "address": address, "port": port}
            for unit, protocol, address, port in sorted(rows)
        ],
    }


if __name__ == "__main__":
    print(json.dumps(collect_listeners(), separators=(",", ":")))
