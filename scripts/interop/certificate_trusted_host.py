"""Observe a receipt-bound certificate lab on an explicitly trusted VMware host.

This module reports the current registration and adapter configuration for
one appliance, one peer, and one private VMware LAN segment. It does not claim
the host is protected from its administrator or other administrators.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any


class Refusal(Exception):
    """Fixed, non-secret reason to refuse trusted-host admission."""


_SEGMENT_ID = re.compile(r"(?:[0-9a-fA-F]{2} ){7}[0-9a-fA-F]{2}-(?:[0-9a-fA-F]{2} ){7}[0-9a-fA-F]{2}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
_VMX_FIELD = re.compile(r'^\s*(ethernet\d+)\.([A-Za-z][A-Za-z0-9]*)\s*=\s*"([^"\r\n]*)"\s*(?:#.*)?\Z')
_INVENTORY_PATH = re.compile(r'^\s*vmlist(\d+)\.config\s*=\s*"([^"\r\n]+)"\s*\Z', re.IGNORECASE)
_INVENTORY_KEY = re.compile(r'^\s*vmlist[^.\s]*\.config\s*=', re.IGNORECASE)
_SEGMENT_NAME = re.compile(r'^\s*pref\.namedPVNs(\d+)\.name\s*=\s*"([^"\r\n]+)"\s*\Z')
_SEGMENT_ID_FIELD = re.compile(r'^\s*pref\.namedPVNs(\d+)\.pvnID\s*=\s*"([^"\r\n]+)"\s*\Z')
_SEGMENT_COUNT = re.compile(r'^\s*pref\.namedPVNs\.count\s*=\s*"(0|[1-9]\d*)\s*"\s*\Z')
_ALLOWED_FIELDS = {
    "present",
    "connectiontype",
    "pvnid",
    "vnet",
    "address",
    "generatedaddress",
    "startconnected",
}
_MAX_FILE = 4 * 1024 * 1024
_MAX_PROCESS_OUTPUT = 1024 * 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ordinary_file(value: Any, reason: str, *, limit: int = _MAX_FILE) -> tuple[Path, bytes]:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise Refusal(reason)
    path = Path(value)
    try:
        _reject_reparse_components(path, reason)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Refusal(reason)
        payload = path.read_bytes()
        after = path.stat()
    except (OSError, ValueError):
        raise Refusal(reason) from None
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(payload) != after.st_size:
        raise Refusal(reason)
    return path.resolve(strict=True), payload


def _ordinary_vm_path(value: Any) -> Path:
    if not isinstance(value, str) or not value or Path(value).suffix.lower() != ".vmx":
        raise Refusal("trusted_host_plan_invalid")
    try:
        original = Path(value)
        _reject_reparse_components(original, "trusted_host_vm_path_invalid")
        resolved = original.resolve(strict=True)
        if not resolved.is_file():
            raise Refusal("trusted_host_vm_path_invalid")
    except (OSError, ValueError):
        raise Refusal("trusted_host_vm_path_invalid") from None
    return resolved


def _reject_reparse_components(path: Path, reason: str) -> None:
    current = path
    for ancestor in (current, *current.parents):
        if ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction()):
            raise Refusal(reason)


def _normalized_path(path: str | Path) -> str:
    return os.path.normcase(os.path.normpath(str(path))).casefold()


def _decode_config(payload: bytes, reason: str) -> list[str]:
    try:
        text = payload.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        try:
            text = payload.decode("cp1252", errors="strict")
        except UnicodeDecodeError:
            raise Refusal(reason) from None
    return text.splitlines()


def _parse_inventory(payload: bytes) -> tuple[list[Path], int]:
    lines = _decode_config(payload, "trusted_host_inventory_invalid")
    entries: dict[int, Path] = {}
    for line in lines:
        path_match = _INVENTORY_PATH.fullmatch(line)
        if _INVENTORY_KEY.match(line):
            if path_match is None:
                raise Refusal("trusted_host_inventory_invalid")
            index = int(path_match.group(1))
            candidate = Path(path_match.group(2))
            if index in entries or not candidate.is_absolute() or candidate.suffix.lower() != ".vmx":
                raise Refusal("trusted_host_inventory_invalid")
            entries[index] = candidate
    if not entries:
        raise Refusal("trusted_host_inventory_invalid")
    paths: dict[str, Path] = {}
    stale_count = 0
    for path in entries.values():
        _reject_reparse_components(path, "trusted_host_inventory_invalid")
        try:
            actual = _ordinary_vm_path(str(path))
        except Refusal:
            # Workstation may retain stale registrations after a VM is removed.
            # A missing VMX cannot attach a virtual NIC; all extant registrations
            # and every running VM remain subject to full parsing and readback.
            try:
                path.stat()
            except FileNotFoundError:
                stale_count += 1
                continue
            except OSError:
                raise Refusal("trusted_host_inventory_unreadable") from None
            raise Refusal("trusted_host_inventory_invalid") from None
        normalized = _normalized_path(actual)
        if normalized in paths:
            raise Refusal("trusted_host_inventory_duplicate_vm")
        paths[normalized] = actual
    if not paths:
        raise Refusal("trusted_host_inventory_invalid")
    return [paths[key] for key in sorted(paths)], stale_count


def _parse_vmrun_output(payload: bytes) -> list[Path]:
    lines = _decode_config(payload, "trusted_host_running_inventory_invalid")
    if not lines or not (match := re.fullmatch(r"Total running VMs:\s*(0|[1-9]\d*)\s*", lines[0])):
        raise Refusal("trusted_host_running_inventory_invalid")
    expected_count = int(match.group(1))
    raw_paths = [line.strip() for line in lines[1:] if line.strip()]
    if len(raw_paths) != expected_count:
        raise Refusal("trusted_host_running_inventory_invalid")
    paths: dict[str, Path] = {}
    for raw_path in raw_paths:
        if raw_path.startswith('"') and raw_path.endswith('"') and len(raw_path) > 1:
            raw_path = raw_path[1:-1]
        elif '"' in raw_path:
            raise Refusal("trusted_host_running_inventory_invalid")
        candidate = _ordinary_vm_path(raw_path)
        normalized = _normalized_path(candidate)
        if normalized in paths:
            raise Refusal("trusted_host_running_inventory_duplicate_vm")
        paths[normalized] = candidate
    return [paths[key] for key in sorted(paths)]


def _read_vmx(path: Path) -> list[dict[str, str]]:
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_FILE:
            raise Refusal("trusted_host_vmx_invalid")
        payload = path.read_bytes()
        after = path.stat()
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or len(payload) != after.st_size:
            raise Refusal("trusted_host_vmx_changed_during_read")
    except OSError:
        raise Refusal("trusted_host_vmx_unreadable") from None
    values: dict[int, dict[str, str]] = {}
    for line in _decode_config(payload, "trusted_host_vmx_invalid"):
        if not re.match(r"^\s*ethernet\d+\.", line, re.IGNORECASE):
            continue
        match = _VMX_FIELD.fullmatch(line)
        if match is None:
            raise Refusal("trusted_host_vmx_adapter_field_invalid")
        name, field, value = match.groups()
        adapter_index = int(name.removeprefix("ethernet"))
        field = field.casefold()
        if field not in _ALLOWED_FIELDS:
            continue
        if field in {"present", "startconnected"} and value.casefold() not in {"true", "false"}:
            raise Refusal("trusted_host_vmx_adapter_field_invalid")
        adapter = values.setdefault(adapter_index, {})
        if field in adapter:
            raise Refusal("trusted_host_vmx_adapter_duplicate_field")
        adapter[field] = value
    return [{"index": index, **fields} for index, fields in sorted(values.items())]


def _parse_segments(payload: bytes) -> dict[str, str]:
    names: dict[int, str] = {}
    ids: dict[int, str] = {}
    declared_count: int | None = None
    for line in _decode_config(payload, "trusted_host_preferences_invalid"):
        count_match = _SEGMENT_COUNT.fullmatch(line)
        name_match = _SEGMENT_NAME.fullmatch(line)
        id_match = _SEGMENT_ID_FIELD.fullmatch(line)
        if count_match:
            if declared_count is not None:
                raise Refusal("trusted_host_preferences_invalid")
            declared_count = int(count_match.group(1))
        elif name_match:
            index, name = int(name_match.group(1)), name_match.group(2)
            if index in names:
                raise Refusal("trusted_host_preferences_invalid")
            names[index] = name
        elif id_match:
            index, identifier = int(id_match.group(1)), id_match.group(2)
            if index in ids:
                raise Refusal("trusted_host_preferences_invalid")
            ids[index] = identifier
    if declared_count is None or declared_count != len(names) or declared_count != len(ids):
        raise Refusal("trusted_host_preferences_invalid")
    if set(names) != set(range(declared_count)) or set(ids) != set(range(declared_count)):
        raise Refusal("trusted_host_preferences_invalid")
    if len(set(names.values())) != len(names) or len(set(ids.values())) != len(ids):
        raise Refusal("trusted_host_preferences_ambiguous")
    return dict(zip(names.values(), ids.values(), strict=True))


def _run_vmrun(executable: Path) -> tuple[list[Path], str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "PROCESSOR_ARCHITECTURE"}
    }
    try:
        result = subprocess.run(
            [str(executable), "-T", "ws", "list"],
            check=False,
            capture_output=True,
            timeout=15,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Refusal("trusted_host_vmrun_unavailable") from None
    if (result.returncode != 0 or len(result.stdout) > _MAX_PROCESS_OUTPUT
            or len(result.stderr) > _MAX_PROCESS_OUTPUT):
        raise Refusal("trusted_host_vmrun_failed")
    paths = _parse_vmrun_output(result.stdout)
    return paths, _sha256(result.stdout)


def _validate_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("schema") != 1:
        raise Refusal("trusted_host_plan_invalid")
    if (not isinstance(plan.get("task_id"), str) or not plan["task_id"]
            or plan.get("repository") != "mdaneri/Atlaso"
            or not isinstance(plan.get("pr"), int) or isinstance(plan.get("pr"), bool) or plan["pr"] <= 0
            or not isinstance(plan.get("source_commit"), str) or _COMMIT.fullmatch(plan["source_commit"]) is None):
        raise Refusal("trusted_host_plan_invalid")
    host = plan.get("trusted_host")
    if not isinstance(host, dict) or host.get("host_administrator_trusted") is not True:
        raise Refusal("trusted_host_explicit_trust_required")
    return host


def inspect_trusted_host(plan: dict[str, Any]) -> dict[str, Any]:
    """Collect one bounded, allowlisted readback of the trusted VMware host.

    The host administrator is the explicit trust root. This function verifies
    current Workstation registration, running state, LAN identity, and NIC
    bindings. It does not prove that the host administrator cannot change
    those bindings or that an address has no adversarial claimant.

    Args:
        plan: Original task and VM ownership references plus trusted-host
            selectors. It never accepts secrets or guest credentials.
    """
    host = _validate_plan(plan)
    required = ("vmrun_path", "inventory_path", "preferences_path", "segment_name", "segment_id", "appliance_vmx", "peer_vmx")
    if any(not host.get(key) for key in required):
        raise Refusal("trusted_host_plan_invalid")

    vmrun_path, _ = _ordinary_file(host["vmrun_path"], "trusted_host_vmrun_path_invalid")
    inventory_path, inventory = _ordinary_file(host["inventory_path"], "trusted_host_inventory_invalid")
    preferences_path, preferences = _ordinary_file(host["preferences_path"], "trusted_host_preferences_invalid")
    appliance_path = _ordinary_vm_path(host["appliance_vmx"])
    peer_path = _ordinary_vm_path(host["peer_vmx"])
    if _normalized_path(appliance_path) == _normalized_path(peer_path):
        raise Refusal("trusted_host_vm_identity_ambiguous")

    receipt = host.get("segment_receipt")
    if not isinstance(receipt, dict):
        raise Refusal("trusted_host_segment_receipt_missing")
    receipt_path, receipt_bytes = _ordinary_file(receipt.get("path"), "trusted_host_segment_receipt_invalid", limit=262144)
    expected_receipt_sha = receipt.get("sha256")
    if not isinstance(expected_receipt_sha, str) or _sha256(receipt_bytes) != expected_receipt_sha:
        raise Refusal("trusted_host_segment_receipt_digest_mismatch")
    try:
        receipt_value = json.loads(receipt_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise Refusal("trusted_host_segment_receipt_invalid") from None
    if (not isinstance(receipt_value, dict) or receipt_value.get("schema") != 1
            or receipt_value.get("task_id") != plan["task_id"]
            or receipt_value.get("repository") != plan["repository"]
            or receipt_value.get("pr") != plan["pr"]
            or receipt_value.get("source_commit") != plan.get("resource_source_commit", plan["source_commit"])
            or receipt_value.get("name") != host["segment_name"]
            or receipt_value.get("pvn_id") != host["segment_id"]):
        raise Refusal("trusted_host_segment_receipt_binding_mismatch")

    segment_id = host["segment_id"]
    if not isinstance(segment_id, str) or _SEGMENT_ID.fullmatch(segment_id) is None:
        raise Refusal("trusted_host_segment_id_invalid")
    segments = _parse_segments(preferences)
    registered_id = next((value for name, value in segments.items() if name.casefold() == str(host["segment_name"]).casefold()), None)
    if registered_id != segment_id:
        raise Refusal("trusted_host_segment_registration_changed")

    registered, stale_registration_count = _parse_inventory(inventory)
    running, running_digest = _run_vmrun(vmrun_path)
    registered_by_path = {_normalized_path(path): path for path in registered}
    running_by_path = {_normalized_path(path): path for path in running}
    observed_by_path = {**registered_by_path, **running_by_path}
    appliance_key = _normalized_path(appliance_path)
    peer_key = _normalized_path(peer_path)
    if appliance_key not in observed_by_path or peer_key not in observed_by_path:
        raise Refusal("trusted_host_vm_not_observed")
    if appliance_key not in running_by_path or peer_key not in running_by_path:
        raise Refusal("trusted_host_vm_not_running")

    private_members: list[str] = []
    all_member_facts: list[dict[str, Any]] = []
    for vmx_key, path in sorted(observed_by_path.items()):
        adapters = _read_vmx(path)
        active = [adapter for adapter in adapters if adapter.get("present", "true").casefold() == "true"
                  and adapter.get("startconnected", "true").casefold() == "true"]
        for adapter in active:
            if adapter.get("connectiontype", "").casefold() == "pvn" and adapter.get("pvnid", "").casefold() == segment_id.casefold():
                private_members.append(vmx_key)
        if vmx_key in (appliance_key, peer_key):
            all_member_facts.append({
                "vmx": vmx_key,
                "running": vmx_key in running_by_path,
                "adapters": [_public_adapter(adapter) for adapter in active],
            })
    if sorted(private_members) != sorted((appliance_key, peer_key)):
        raise Refusal("trusted_host_private_membership_changed")

    appliance = next(item for item in all_member_facts if item["vmx"] == appliance_key)
    peer = next(item for item in all_member_facts if item["vmx"] == peer_key)
    _check_expected_adapter(appliance, host.get("appliance_private_adapter"), segment_id, require_only=True)
    _check_expected_adapter(peer, host.get("peer_private_adapter"), segment_id, require_only=False)
    _check_peer_control(peer, host.get("peer_control_adapter"))

    public = {
        "schema": 1,
        "kind": "certificate-trusted-host-topology",
        "trust_model": "trusted-host",
        "host_administrator_trusted": True,
        "task_id": plan["task_id"],
        "repository": plan["repository"],
        "pr": plan["pr"],
        "source_commit": plan["source_commit"],
        "segment_name": host["segment_name"],
        "segment_id": segment_id,
        "segment_receipt_sha256": expected_receipt_sha,
        "inventory_sha256": _sha256(inventory),
        "preferences_sha256": _sha256(preferences),
        "running_inventory_sha256": running_digest,
        "registered_vm_count": len(registered_by_path),
        "stale_registration_count": stale_registration_count,
        "running_vm_count": len(running_by_path),
        "observed_vm_count": len(observed_by_path),
        "private_members": sorted(private_members),
        "lab_vms": sorted(all_member_facts, key=lambda item: item["vmx"]),
        "address_exclusivity_claim": "not-established",
        "host_administrator_exclusion_claim": "not-established",
    }
    canonical = json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")
    public["topology_sha256"] = _sha256(canonical)
    public["receipt_path"] = str(receipt_path)
    return public


def assert_same_topology(before: dict[str, Any], after: dict[str, Any]) -> None:
    """Refuse when any trusted-host registration or lab NIC readback changed.

    Args:
        before: Trusted-host snapshot captured before the protected phase.
        after: Trusted-host snapshot captured after that phase.

    Raises:
        Refusal: Either snapshot is malformed or the observed topology drifted.
    """
    if any(not isinstance(value, dict) or value.get("trust_model") != "trusted-host"
           or value.get("kind") != "certificate-trusted-host-topology"
           for value in (before, after)):
        raise Refusal("trusted_host_snapshot_invalid")
    for snapshot in (before, after):
        digest = snapshot.get("topology_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise Refusal("trusted_host_snapshot_invalid")
        unsigned = {key: value for key, value in snapshot.items() if key not in {"topology_sha256", "receipt_path"}}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if _sha256(canonical) != digest:
            raise Refusal("trusted_host_snapshot_invalid")
    bound_fields = (
        "task_id",
        "repository",
        "pr",
        "source_commit",
        "segment_name",
        "segment_id",
        "segment_receipt_sha256",
    )
    if any(before.get(field) != after.get(field) for field in bound_fields):
        raise Refusal("trusted_host_admission_binding_changed")
    if before["topology_sha256"] != after["topology_sha256"]:
        raise Refusal("trusted_host_topology_changed")


class TrustedHostMonitor:
    """Retain any sampled topology drift until the bounded scenario exits.

    Sampling supplements the mandatory synchronous checks around operations.
    Host administration remains the disclosed trust boundary.
    """

    def __init__(self, plan: dict[str, Any], original: dict[str, Any]):
        self.plan = plan
        self.original = original
        self.stop_event = threading.Event()
        self.failed = threading.Event()
        self.observations: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._watch, daemon=True)

    def start(self) -> None:
        """Check original admission before starting background observation."""
        self.check()
        self.thread.start()

    def check(self) -> None:
        """Refuse current or previously sampled drift before another action."""
        if self.failed.is_set():
            raise Refusal("trusted_host_topology_changed")
        try:
            observed = inspect_trusted_host(self.plan)
            assert_same_topology(self.original, observed)
        except (Refusal, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            self.failed.set()
            raise Refusal("trusted_host_topology_changed") from None
        with self.lock:
            if len(self.observations) >= 4096:
                self.failed.set()
                raise Refusal("trusted_host_observation_limit")
            self.observations.append({"observed_utc_seconds": time.time(), "topology_sha256": observed["topology_sha256"]})

    def _watch(self) -> None:
        while not self.stop_event.wait(1):
            try:
                self.check()
            except Refusal:
                return

    def stop(self) -> None:
        """Terminate observation and preserve a failed shutdown as drift."""
        self.stop_event.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=20)
            if self.thread.is_alive():
                self.failed.set()


def _public_adapter(adapter: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": adapter["index"],
        "connection_type": adapter.get("connectiontype", ""),
        "pvn_id": adapter.get("pvnid", ""),
        "vnet": adapter.get("vnet", ""),
        "mac": adapter.get("address", adapter.get("generatedaddress", "")).lower(),
        "start_connected": adapter.get("startconnected", "true").casefold() == "true",
    }


def _check_expected_adapter(vm: dict[str, Any], expected: Any, segment_id: str, *, require_only: bool) -> None:
    if not isinstance(expected, dict) or not isinstance(expected.get("index"), int) or isinstance(expected.get("index"), bool):
        raise Refusal("trusted_host_adapter_plan_invalid")
    mac = expected.get("mac")
    if not isinstance(mac, str) or _MAC.fullmatch(mac) is None:
        raise Refusal("trusted_host_adapter_plan_invalid")
    matches = [adapter for adapter in vm["adapters"] if adapter["index"] == expected["index"]]
    if len(matches) != 1:
        raise Refusal("trusted_host_private_adapter_missing")
    actual = matches[0]
    if (actual["connection_type"].casefold() != "pvn" or actual["pvn_id"].casefold() != segment_id.casefold()
            or actual["mac"].casefold() != mac.casefold() or not actual["start_connected"]):
        raise Refusal("trusted_host_private_adapter_changed")
    if require_only and len(vm["adapters"]) != 1:
        raise Refusal("trusted_host_appliance_extra_adapter")
    if not require_only and len(vm["adapters"]) > 2:
        raise Refusal("trusted_host_peer_extra_adapter")


def _check_peer_control(vm: dict[str, Any], expected: Any) -> None:
    if not isinstance(expected, dict) or not isinstance(expected.get("index"), int) or isinstance(expected.get("index"), bool):
        raise Refusal("trusted_host_adapter_plan_invalid")
    matches = [adapter for adapter in vm["adapters"] if adapter["index"] == expected["index"]]
    if len(matches) != 1:
        raise Refusal("trusted_host_peer_control_adapter_missing")
    adapter = matches[0]
    if (adapter["connection_type"].casefold() in {"pvn", "bridged", "nat"}
            or adapter["connection_type"].casefold() != str(expected.get("connection_type", "")).casefold()
            or adapter["vnet"] != expected.get("vnet")
            or adapter["mac"].casefold() != str(expected.get("mac", "")).casefold()):
        raise Refusal("trusted_host_peer_control_adapter_changed")
