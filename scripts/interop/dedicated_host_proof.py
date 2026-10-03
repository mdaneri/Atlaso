"""Collect bounded Workstation observations for an explicitly reserved host.

The cooperative host reservation excludes human and other controller activity.
This is a bracketed observation contract, not an atomic switch-port inventory.
Command lines stay inside the collector and never enter receipts or diagnostics.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import threading
from contextlib import ExitStack
from pathlib import Path
from typing import Any

from scripts.completed_task_files import FileRefusal, WindowsFiles
from scripts.completed_task_process import contained_child
from scripts.interop.dedicated_host_contract import (
    Refusal,
    assert_unchanged,
    validate_snapshot,
)


def bounded_command(arguments: list[str]) -> str:
    """Read one public provider response without returning private diagnostics.

    Args:
        arguments: Fixed executable and allowlisted noncredential arguments.
    """
    output = bytearray()
    failed = threading.Event()
    env = {key: value for key, value in os.environ.items() if key not in {"ATLASO_NATIVE_ADMIN", "OP_SERVICE_ACCOUNT_TOKEN"}}
    try:
        with contained_child(arguments, Path(__file__).resolve().parents[2], env) as process:
            def drain(stream: Any, keep: bool, limit: int) -> None:
                """Keep neither stream unbounded and never expose child error text.

                Args:
                    stream: Contained child's output pipe.
                    keep: Whether bytes are public provider stdout.
                    limit: Independent stream byte limit.
                """
                count = 0
                try:
                    with stream:
                        while chunk := stream.read(65536):
                            count += len(chunk)
                            if count > limit:
                                failed.set()
                                process.kill()
                                return
                            if keep:
                                output.extend(chunk)
                except OSError:
                    failed.set()

            readers = [threading.Thread(target=drain, args=(stream, keep, limit), daemon=True)
                       for stream, keep, limit in ((process.stdout, True, 262144), (process.stderr, False, 65536))]
            for reader in readers:
                reader.start()
            process.wait(timeout=20)
            for reader in readers:
                reader.join(timeout=1)
            if process.returncode or failed.is_set() or any(reader.is_alive() for reader in readers):
                raise Refusal("host_provider_read_refused")
    except (OSError, subprocess.TimeoutExpired, FileRefusal):
        raise Refusal("host_provider_unavailable") from None
    try:
        return output.decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        raise Refusal("host_provider_encoding_invalid") from None


def windows_arguments(command_line: str) -> list[str]:
    """Parse the operating system's VMX process command line in memory only.

    Args:
        command_line: Native process command line, never published.
    """
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise Refusal("host_process_identity_unavailable")
    count = ctypes.c_int()
    shell = loader("shell32", use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    pointer = shell.CommandLineToArgvW(command_line, ctypes.byref(count))
    if not pointer:
        raise Refusal("host_process_identity_unavailable")
    kernel = loader("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    try:
        return [pointer[index] for index in range(count.value)]
    finally:
        kernel.LocalFree(pointer)


def process_inventory(powershell: Path) -> list[dict[str, Any]]:
    """Require readable identity for every host VMware VM process.

    Args:
        powershell: Pinned trusted PowerShell 7 executable.
    """
    script = "$ErrorActionPreference='Stop'; $p=Get-CimInstance Win32_Process -Filter \"Name LIKE 'vmware-vmx%'\"; ConvertTo-Json -InputObject @($p | Select-Object ProcessId,CreationDate,ExecutablePath,CommandLine) -Depth 3 -Compress"
    # WMI's complete host census must succeed; an inaccessible process is not absence.
    raw = json.loads(bounded_command([str(powershell), "-NoProfile", "-NonInteractive", "-Command", script]))
    if not isinstance(raw, list) or len(raw) > 64:
        raise Refusal("host_process_inventory_invalid")
    rows = []
    for row in raw:
        if not isinstance(row, dict) or not row.get("CommandLine") or not row.get("ExecutablePath"):
            raise Refusal("host_process_identity_unavailable")
        arguments = windows_arguments(row["CommandLine"])
        paths = [argument for argument in arguments[1:] if argument.lower().endswith(".vmx")]
        if len(paths) != 1:
            raise Refusal("host_process_vmx_ambiguous")
        rows.append({"pid": row["ProcessId"], "creation_time": row["CreationDate"],
                     "vmx_path": paths[0], "executable": row["ExecutablePath"]})
    return sorted(rows, key=lambda row: row["pid"])


def runtime_value(vmrun: Path, vmx: str, key: str) -> str:
    """Read a runtime configuration scalar, refusing ambiguous VMX quoting.

    Args:
        vmrun: Pinned installed provider executable.
        vmx: Independently enrolled absolute VMX path.
        key: Fixed ethernet configuration key.
    """
    value = bounded_command([str(vmrun), "-T", "ws", "readVariable", vmx, "runtimeConfig", key])
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        value = value[1:-1]
    if '"' in value or "\n" in value or "\r" in value or value == key:
        raise Refusal("runtime_adapter_value_ambiguous")
    return value


def collect_snapshot(expected: dict[str, list[dict[str, Any]]], vmrun: Path, powershell: Path) -> dict[str, Any]:
    """Bracket live runtime reads with complete identity-bound host inventories.

    Args:
        expected: Original fixture VMX paths and exact enrolled adapters.
        vmrun: Pinned installed provider executable.
        powershell: Pinned trusted host census executable.
    """
    before = process_inventory(powershell)
    inventory = bounded_command([str(vmrun), "-T", "ws", "list"]).splitlines()
    if not inventory or not re.fullmatch(r"Total running VMs: [0-9]+", inventory[0]):
        raise Refusal("running_vm_inventory_invalid")
    running = inventory[1:]
    if int(inventory[0].split(": ")[1]) != len(running):
        raise Refusal("running_vm_inventory_incomplete")
    if len({path.casefold() for path in running}) != len(running) or {path.casefold() for path in running} != {path.casefold() for path in expected}:
        raise Refusal("unexpected_running_vm")
    if {str(row["vmx_path"]).casefold() for row in before} != {path.casefold() for path in expected}:
        raise Refusal("unexpected_running_vm")
    adapters: dict[str, list[dict[str, Any]]] = {}
    for vmx, enrolled in expected.items():
        text = Path(vmx).read_text(encoding="utf-8")
        keys = re.findall(r"^\s*ethernet([0-9]+)\.", text, re.MULTILINE | re.IGNORECASE)
        if any(int(index) >= 10 or str(int(index)) != index for index in keys):
            raise Refusal("adapter_limit_unsupported")
        rows: list[dict[str, Any]] = []
        for index in range(10):
            prefix = f"ethernet{index}."
            present = runtime_value(vmrun, vmx, prefix + "present").upper()
            if present not in {"", "TRUE", "FALSE"}:
                raise Refusal("runtime_adapter_presence_invalid")
            if present != "TRUE":
                if any(row["index"] == index for row in enrolled):
                    raise Refusal("runtime_expected_adapter_unavailable")
                # Canonical appliance clones retain disabled adapter configuration.
                # Such a slot needs an explicit FALSE from both pinned VMX and runtime;
                # missing/duplicate saved presence or a blank runtime is ambiguous.
                if str(index) in keys:
                    saved = re.findall(rf'^\s*ethernet{index}\.present\s*=\s*"([^"\r\n]*)"\s*$',
                                       text, re.MULTILINE | re.IGNORECASE)
                    if present != "FALSE" or len(saved) != 1 or saved[0].upper() != "FALSE":
                        raise Refusal("runtime_expected_adapter_unavailable")
                rows.append({"index": index, "present": False, "start_connected": False,
                             "connection_type": None, "network_id": None, "mac": None})
                continue
            kind = runtime_value(vmrun, vmx, prefix + "connectionType")
            network_key = "pvnID" if kind == "pvn" else "vnet"
            rows.append({"index": index, "present": True, "connection_type": kind,
                         "network_id": runtime_value(vmrun, vmx, prefix + network_key),
                         "mac": runtime_value(vmrun, vmx, prefix + "address"),
                         "start_connected": runtime_value(vmrun, vmx, prefix + "startConnected").upper() == "TRUE"})
        adapters[vmx] = rows
    after = process_inventory(powershell)
    if before != after:
        raise Refusal("host_process_inventory_changed")
    return validate_snapshot(expected, {"processes": before, "running_vm_paths": running, "adapters": adapters})


class DedicatedHostProof:
    """Keep provider and VMX files pinned across an explicitly reserved host run."""

    def __init__(self, expected: dict[str, list[dict[str, Any]]], vmrun: Path, powershell: Path):
        """Retain independent enrollment; no observation or mutation occurs yet.

        Args:
            expected: Original task-owned fixture VMX paths and adapters.
            vmrun: Explicit installed provider executable.
            powershell: Explicit host census executable.
        """
        self.expected, self.vmrun, self.powershell = expected, vmrun, powershell
        self.stack = ExitStack()
        self.baseline: dict[str, Any] | None = None

    def __enter__(self) -> DedicatedHostProof:
        """Admit two matching host observations before guest credential use."""
        if os.name != "nt":
            raise Refusal("dedicated_host_requires_windows")
        try:
            files = WindowsFiles()
            for path in (self.vmrun, self.powershell, *(Path(vmx) for vmx in self.expected)):
                self.stack.enter_context(files.ancestors(path))
                self.stack.enter_context(files.opened(path))
            self.baseline = collect_snapshot(self.expected, self.vmrun, self.powershell)
            self.check()
            return self
        except Exception:
            self.stack.close()
            raise

    def check(self) -> dict[str, Any]:
        """Reject changes since admission before the next guarded operation."""
        if self.baseline is None:
            raise Refusal("dedicated_host_not_admitted")
        current = collect_snapshot(self.expected, self.vmrun, self.powershell)
        assert_unchanged(self.baseline, current)
        return current

    def __exit__(self, *_exc: object) -> None:
        """Release read pins; no process, VM, guest, or configuration is removed.

        Args:
            *_exc: Context manager exception information, never published.
        """
        self.stack.close()
