"""Collect bounded Workstation observations for explicitly enrolled VMXs.

Provider inventory and runtime adapter reads are bracketed for the fixture.
Unrelated host VMs are outside this evidence contract. Command output stays
inside the collector and never enters receipts or diagnostics.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
from contextlib import ExitStack
from pathlib import Path, PureWindowsPath
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


def _running_fixture_paths(expected: dict[str, list[dict[str, Any]]], vmrun: Path) -> list[str]:
    """Read provider inventory and return only enrolled running VMX paths.

    Args:
        expected: Independently enrolled VMX paths.
        vmrun: Pinned installed provider executable.
    """
    expected_by_key = {
        str(PureWindowsPath(vmx.replace("/", "\\"))).casefold(): vmx for vmx in expected
    }
    inventory = bounded_command([str(vmrun), "-T", "ws", "list"]).splitlines()
    if not inventory or not re.fullmatch(r"Total running VMs: [0-9]+", inventory[0]):
        raise Refusal("running_vm_inventory_invalid")
    running = inventory[1:]
    if int(inventory[0].split(": ")[1]) != len(running):
        raise Refusal("running_vm_inventory_incomplete")
    matched: dict[str, list[str]] = {key: [] for key in expected_by_key}
    for raw_path in running:
        key = str(PureWindowsPath(raw_path.replace("/", "\\"))).casefold()
        if key in matched:
            matched[key].append(raw_path)
    if any(len(paths) != 1 for paths in matched.values()):
        raise Refusal("enrolled_vm_not_running")
    return [matched[key][0] for key in sorted(matched)]


def collect_snapshot(expected: dict[str, list[dict[str, Any]]], vmrun: Path, powershell: Path) -> dict[str, Any]:
    """Bracket runtime reads with provider inventories for enrolled VMXs.

    Args:
        expected: Original fixture VMX paths and exact enrolled adapters.
        vmrun: Pinned installed provider executable.
        powershell: Retained temporarily for caller compatibility; it is not invoked.
    """
    before = _running_fixture_paths(expected, vmrun)
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
    after = _running_fixture_paths(expected, vmrun)
    if {path.casefold() for path in before} != {path.casefold() for path in after}:
        raise Refusal("enrolled_vm_inventory_changed")
    return validate_snapshot(expected, {"running_vm_paths": after, "adapters": adapters})


class DedicatedHostProof:
    """Keep the provider and enrolled VMX files pinned during a fixture run."""

    def __init__(self, expected: dict[str, list[dict[str, Any]]], vmrun: Path, powershell: Path):
        """Retain independent enrollment; no observation or mutation occurs yet.

        Args:
            expected: Original task-owned fixture VMX paths and adapters.
            vmrun: Explicit installed provider executable.
            powershell: Retained temporarily for caller compatibility; it is not invoked.
        """
        self.expected, self.vmrun, self.powershell = expected, vmrun, powershell
        self.stack = ExitStack()
        self.baseline: dict[str, Any] | None = None

    def __enter__(self) -> DedicatedHostProof:
        """Admit matching fixture observations before guest credential use."""
        if os.name != "nt":
            raise Refusal("dedicated_host_requires_windows")
        try:
            files = WindowsFiles()
            for path in (self.vmrun, *(Path(vmx) for vmx in self.expected)):
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
