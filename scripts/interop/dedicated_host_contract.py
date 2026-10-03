"""Validate bounded, bracketed VMware dedicated-host observations.

This module validates observations supplied by a native collector. It does not
enumerate VMware state itself and never promotes a stable bracket into proof of
atomic or continuously exclusive network membership.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import PureWindowsPath
from typing import NoReturn, TypeAlias, cast

JsonObject: TypeAlias = dict[str, object]

CONTRACT = "dedicated-host-stable-observation-v1"
MAX_ADAPTERS = 10
_MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_ALLOWED_CONNECTION_TYPES = {"pvn", "custom"}


class Refusal(ValueError):
    """A fixed, non-sensitive refusal reason for malformed host evidence."""


def _refuse(reason: str) -> NoReturn:
    """Raise a fixed non-sensitive refusal.

    Args:
        reason: Public refusal category, never caller-provided secret data.
    """
    raise Refusal(reason)


def _object(value: object, reason: str) -> dict[str, object]:
    """Require a string-keyed mapping.

    Args:
        value: Untrusted value to validate as an object.
        reason: Fixed refusal category for a malformed object.
    """
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _refuse(reason)
    return cast(dict[str, object], value)


def _absolute_windows_path(value: object, reason: str) -> str:
    """Normalize a non-UNC absolute Windows path lexically.

    Args:
        value: Untrusted path value.
        reason: Fixed refusal category for an invalid path.
    """
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        _refuse(reason)
    raw = value.replace("/", "\\")
    if raw.startswith("\\\\"):
        _refuse(reason)
    parts = raw.split("\\")
    if any(part in {".", ".."} for part in parts):
        _refuse(reason)
    path = PureWindowsPath(raw)
    if not path.is_absolute() or not path.drive or path.drive.startswith("\\"):
        _refuse(reason)
    return str(path)


def _absolute_vmx_path(value: object, reason: str) -> str:
    """Require an absolute Windows path with a VMX suffix.

    Args:
        value: Untrusted VMX path value.
        reason: Fixed refusal category for an invalid path.
    """
    path = _absolute_windows_path(value, reason)
    if PureWindowsPath(path).suffix.casefold() != ".vmx":
        _refuse(reason)
    return path


def _path_key(value: object, reason: str) -> tuple[str, str]:
    """Return a case-insensitive key and canonical Windows VMX path.

    Args:
        value: Untrusted VMX path value.
        reason: Fixed refusal category for an invalid path.
    """
    path = _absolute_vmx_path(value, reason)
    return path.casefold(), path


def _mac(value: object, reason: str) -> str:
    """Validate and normalize a unicast Ethernet MAC address.

    Args:
        value: Untrusted MAC address value.
        reason: Fixed refusal category for an invalid address.
    """
    if not isinstance(value, str) or not _MAC_PATTERN.fullmatch(value):
        _refuse(reason)
    normalized = value.replace("-", ":").lower()
    octets = bytes.fromhex(normalized.replace(":", ""))
    if octets == bytes(6) or octets == b"\xff" * 6 or octets[0] & 1:
        _refuse(reason)
    return normalized


def _creation_time(value: object) -> str:
    """Normalize a bounded process creation-time identity.

    Args:
        value: Untrusted process creation-time value.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        _refuse("process_identity_invalid")
    result = str(value)
    if not result or len(result) > 128 or any(ord(char) < 32 for char in result):
        _refuse("process_identity_invalid")
    return result


def _index(value: object, reason: str) -> int:
    """Validate an adapter index within the supported range.

    Args:
        value: Untrusted adapter index.
        reason: Fixed refusal category for an invalid index.
    """
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < MAX_ADAPTERS:
        _refuse(reason)
    return value


def _connection_type(value: object, reason: str) -> str:
    """Require a supported VMware network connection type.

    Args:
        value: Untrusted connection type.
        reason: Fixed refusal category for an unsupported type.
    """
    if not isinstance(value, str) or value.casefold() not in _ALLOWED_CONNECTION_TYPES:
        _refuse(reason)
    return value.casefold()


def _network_id(value: object, reason: str) -> str:
    """Require a bounded nonempty VMware network identifier.

    Args:
        value: Untrusted provider network identifier.
        reason: Fixed refusal category for an invalid identifier.
    """
    if not isinstance(value, str) or not value or len(value) > 256 or any(ord(char) < 32 for char in value):
        _refuse(reason)
    return value


def _normalize_expected(expected: dict[str, list[dict[str, object]]]) -> tuple[dict[str, list[dict[str, object]]], dict[str, str]]:
    """Validate and canonicalize the independent enrollment allowlist.

    Args:
        expected: VMX paths mapped to their exact enrolled adapter rows.
    """
    if not isinstance(expected, dict) or not expected:
        _refuse("expected_allowlist_invalid")
    normalized: dict[str, list[dict[str, object]]] = {}
    paths: dict[str, str] = {}
    all_macs: set[str] = set()
    for raw_path, raw_rows in expected.items():
        key, path = _path_key(raw_path, "expected_path_invalid")
        if key in paths or not isinstance(raw_rows, list) or not raw_rows:
            _refuse("expected_allowlist_invalid")
        rows: list[dict[str, object]] = []
        indexes: set[int] = set()
        for raw_row in raw_rows:
            row = _object(raw_row, "expected_adapter_invalid")
            if not {"index", "connection_type", "network_id", "mac"}.issubset(row):
                _refuse("expected_adapter_invalid")
            adapter_index = _index(row["index"], "expected_adapter_invalid")
            adapter_type = _connection_type(row["connection_type"], "expected_adapter_invalid")
            network = _network_id(row["network_id"], "expected_adapter_invalid")
            mac = _mac(row["mac"], "expected_adapter_invalid")
            if adapter_index in indexes or mac in all_macs:
                _refuse("expected_adapter_duplicate")
            indexes.add(adapter_index)
            all_macs.add(mac)
            rows.append({"index": adapter_index, "connection_type": adapter_type,
                         "network_id": network, "mac": mac})
        normalized[key] = sorted(rows, key=lambda row: _index(row["index"], "expected_adapter_invalid"))
        paths[key] = path
    return normalized, paths


def _normalize_snapshot(snapshot: dict[str, object]) -> JsonObject:
    """Validate and canonicalize one raw host snapshot.

    Args:
        snapshot: Process, running-VM, and adapter inventories from the collector.
    """
    root = _object(snapshot, "snapshot_invalid")
    if not {"processes", "running_vm_paths", "adapters"}.issubset(root):
        _refuse("snapshot_incomplete")

    raw_processes = root["processes"]
    raw_running = root["running_vm_paths"]
    raw_adapters = root["adapters"]
    if not isinstance(raw_processes, list) or not isinstance(raw_running, list):
        _refuse("process_inventory_invalid")
    if not isinstance(raw_adapters, dict):
        _refuse("adapter_inventory_invalid")

    processes: list[JsonObject] = []
    pids: set[int] = set()
    process_paths: set[str] = set()
    process_identities: set[tuple[int, str]] = set()
    for raw_process in raw_processes:
        process = _object(raw_process, "process_row_invalid")
        if not {"pid", "creation_time", "vmx_path", "executable"}.issubset(process):
            _refuse("process_row_incomplete")
        pid = process["pid"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            _refuse("process_identity_invalid")
        creation_time = _creation_time(process["creation_time"])
        process_key, vmx_path = _path_key(process["vmx_path"], "process_vmx_path_invalid")
        executable = _absolute_windows_path(process["executable"], "process_executable_invalid")
        if PureWindowsPath(executable).name.casefold() != "vmware-vmx.exe":
            _refuse("process_executable_invalid")
        identity = (pid, creation_time)
        if pid in pids or process_key in process_paths or identity in process_identities:
            _refuse("process_duplicate")
        pids.add(pid)
        process_paths.add(process_key)
        process_identities.add(identity)
        processes.append({"pid": pid, "creation_time": creation_time,
                          "vmx_path": vmx_path, "executable": executable})

    running_paths: dict[str, str] = {}
    for raw_path in raw_running:
        key, path = _path_key(raw_path, "running_vm_path_invalid")
        if key in running_paths:
            _refuse("running_vm_duplicate")
        running_paths[key] = path
    if set(running_paths) != process_paths:
        _refuse("process_inventory_disagrees")

    adapter_map: dict[str, list[JsonObject]] = {}
    adapter_paths: dict[str, str] = {}
    present_macs: set[str] = set()
    for raw_path, raw_rows in raw_adapters.items():
        key, path = _path_key(raw_path, "adapter_vmx_path_invalid")
        if key in adapter_paths or not isinstance(raw_rows, list):
            _refuse("adapter_inventory_invalid")
        indexes: set[int] = set()
        rows: list[JsonObject] = []
        for raw_row in raw_rows:
            row = _object(raw_row, "adapter_row_invalid")
            required = {"index", "present", "connection_type", "network_id", "mac", "start_connected"}
            if not required.issubset(row):
                _refuse("adapter_row_incomplete")
            index = _index(row["index"], "adapter_index_invalid")
            if index in indexes:
                _refuse("adapter_duplicate_index")
            indexes.add(index)
            present = row["present"]
            start_connected = row["start_connected"]
            if not isinstance(present, bool) or not isinstance(start_connected, bool):
                _refuse("adapter_presence_invalid")
            if not present:
                # The collector must establish absence from the runtime FALSE
                # value or from the pinned VMX when no runtime key exists.
                if start_connected or any(row[field] not in (None, "") for field in
                                    ("connection_type", "network_id", "mac")):
                    _refuse("adapter_absence_ambiguous")
                rows.append({"index": index, "present": False, "start_connected": False,
                             "connection_type": None, "network_id": None, "mac": None})
                continue
            connection = _connection_type(row["connection_type"], "adapter_configuration_invalid")
            network = _network_id(row["network_id"], "adapter_configuration_invalid")
            mac = _mac(row["mac"], "adapter_mac_invalid")
            if mac in present_macs:
                _refuse("adapter_mac_duplicate")
            present_macs.add(mac)
            rows.append({"index": index, "present": True, "start_connected": start_connected,
                         "connection_type": connection, "network_id": network, "mac": mac})
        if indexes != set(range(MAX_ADAPTERS)):
            _refuse("adapter_inventory_incomplete")
        adapter_map[key] = sorted(rows, key=lambda row: _index(row["index"], "adapter_index_invalid"))
        adapter_paths[key] = path

    if set(adapter_map) != process_paths:
        _refuse("adapter_inventory_disagrees")
    return {
        "processes": sorted(processes, key=lambda row: cast(int, row["pid"])),
        "running_vm_paths": [running_paths[key] for key in sorted(running_paths)],
        "adapters": {adapter_paths[key]: adapter_map[key] for key in sorted(adapter_paths)},
    }


def validate_snapshot(expected: dict[str, list[dict[str, object]]], snapshot: dict[str, object]) -> dict[str, object]:
    """Validate a complete host snapshot against an independently enrolled allowlist.

    Args:
        expected: VMX paths mapped to their exact enrolled adapter rows.
        snapshot: Complete process, running-VM, and runtime adapter observation.

    Paths are compared case-insensitively using Windows lexical path rules.
    The collector remains responsible for filesystem/reparse checks and for
    obtaining each row. The returned evidence means only that the supplied
    bracket was internally consistent and stable; it does not claim an atomic
    snapshot or continuous exclusive LAN membership.
    """
    expected_rows, expected_paths = _normalize_expected(expected)
    observed = _normalize_snapshot(snapshot)
    process_rows = observed["processes"]
    if not isinstance(process_rows, list):
        _refuse("snapshot_invalid")
    process_paths = {str(row["vmx_path"]).casefold() for row in process_rows}
    if process_paths != set(expected_paths):
        _refuse("unexpected_running_vm")
    raw_adapters = observed["adapters"]
    if not isinstance(raw_adapters, dict):
        _refuse("snapshot_invalid")
    adapters = {str(path).casefold(): rows for path, rows in raw_adapters.items()}
    if set(adapters) != set(expected_paths):
        _refuse("unexpected_adapter_vm")

    canonical_adapters: list[JsonObject] = []
    for path_key in sorted(expected_paths):
        raw_rows = adapters[path_key]
        if not isinstance(raw_rows, list):
            _refuse("snapshot_invalid")
        observed_rows = {cast(int, row["index"]): row for row in raw_rows}
        expected_by_index = {cast(int, row["index"]): row for row in expected_rows[path_key]}
        present_indexes = {index for index, row in observed_rows.items() if row["present"] is True}
        if present_indexes != set(expected_by_index):
            _refuse("adapter_set_mismatch")
        for _, actual in sorted(observed_rows.items()):
            canonical_adapters.append({"vmx_path": expected_paths[path_key], **actual})
        for index, wanted in expected_by_index.items():
            actual = observed_rows[index]
            if actual["start_connected"] is not True:
                _refuse("expected_adapter_not_start_connected")
            if any(actual[field] != wanted[field] for field in
                   ("connection_type", "network_id", "mac")):
                _refuse("expected_adapter_mismatch")

    return {
        "contract": CONTRACT,
        "claim": "validated-observation-only",
        "atomic_snapshot": False,
        "exclusive_membership": False,
        "processes": observed["processes"],
        "running_vm_paths": observed["running_vm_paths"],
        "adapters": canonical_adapters,
    }


def _normalize_evidence(evidence: dict[str, object]) -> JsonObject:
    """Validate canonical evidence before using it in a stability comparison.

    Args:
        evidence: Previously returned dedicated-host contract evidence.
    """
    root = _object(evidence, "evidence_invalid")
    if (root.get("contract") != CONTRACT or
            root.get("claim") != "validated-observation-only" or
            root.get("atomic_snapshot") is not False or
            root.get("exclusive_membership") is not False):
        _refuse("evidence_invalid")
    if not {"processes", "running_vm_paths", "adapters"}.issubset(root):
        _refuse("evidence_incomplete")
    raw_adapters = root["adapters"]
    if not isinstance(raw_adapters, list):
        _refuse("evidence_adapter_inventory_invalid")
    adapter_map: dict[str, list[JsonObject]] = {}
    for raw_row in raw_adapters:
        row = dict(_object(raw_row, "evidence_adapter_row_invalid"))
        if "vmx_path" not in row:
            _refuse("evidence_adapter_row_incomplete")
        path = _absolute_vmx_path(row.pop("vmx_path"), "evidence_adapter_path_invalid")
        adapter_map.setdefault(path, []).append(row)
    normalized = _normalize_snapshot({
        "processes": root["processes"],
        "running_vm_paths": root["running_vm_paths"],
        "adapters": adapter_map,
    })
    canonical_rows: list[JsonObject] = []
    normalized_adapters = normalized["adapters"]
    if not isinstance(normalized_adapters, dict):
        _refuse("evidence_adapter_inventory_invalid")
    for path in sorted(normalized_adapters, key=str.casefold):
        rows = normalized_adapters[path]
        if not isinstance(rows, list):
            _refuse("evidence_adapter_inventory_invalid")
        for row in rows:
            canonical_rows.append({"vmx_path": path, **row})
    if root["adapters"] != canonical_rows:
        _refuse("evidence_not_canonical")
    return normalized


def _normalize_observation(value: dict[str, object]) -> JsonObject:
    """Normalize raw host data or previously validated contract evidence.

    Args:
        value: Raw snapshot or canonical observation evidence.
    """
    if isinstance(value, dict) and "contract" in value:
        return _normalize_evidence(value)
    return _normalize_snapshot(value)


def assert_unchanged(before: dict[str, object], after: dict[str, object]) -> None:
    """Refuse a bracket when process, VM, or adapter observations changed.

    Args:
        before: First raw snapshot or canonical evidence value.
        after: Second raw snapshot or canonical evidence value.
    """
    if _normalize_observation(before) != _normalize_observation(after):
        _refuse("host_snapshot_changed")


def validate_guest_addresses(
    expected_macs: dict[str, list[str]],
    guests: dict[str, list[dict[str, object]]],
    candidate_addresses: list[str],
    appliance_role: str = "appliance",
) -> dict[str, object]:
    """Check every enrolled guest interface for candidate IPv4/IPv6 claims.

    Args:
        expected_macs: Exact ordered interface MAC allowlist for every guest role.
        guests: Complete per-role non-loopback interface and address observations.
        candidate_addresses: IPv4/IPv6 addresses checked for conflicting claims.
        appliance_role: Role whose first enrolled MAC is the management interface.

    ``guests`` must contain every non-loopback interface from each pinned
    guest's authoritative link and address readback. This checks address
    ownership only; it does not establish guest forwarding or provider
    membership.
    """
    if (not isinstance(expected_macs, dict) or not expected_macs or
            not isinstance(guests, dict) or not isinstance(candidate_addresses, list) or
            not candidate_addresses or appliance_role not in expected_macs):
        _refuse("guest_inventory_invalid")
    if set(guests) != set(expected_macs):
        _refuse("guest_role_set_mismatch")

    normalized_expected: dict[str, list[str]] = {}
    all_expected_macs: set[str] = set()
    for role, raw_macs in expected_macs.items():
        if (not isinstance(role, str) or not role or not isinstance(raw_macs, list) or
                not raw_macs):
            _refuse("guest_expected_macs_invalid")
        macs = [_mac(value, "guest_expected_macs_invalid") for value in raw_macs]
        if len(set(macs)) != len(macs) or any(mac in all_expected_macs for mac in macs):
            _refuse("guest_expected_macs_duplicate")
        all_expected_macs.update(macs)
        normalized_expected[role] = macs

    candidates: list[str] = []
    for raw_address in candidate_addresses:
        if not isinstance(raw_address, str):
            _refuse("candidate_address_invalid")
        try:
            address = str(ipaddress.ip_address(raw_address))
        except ValueError:
            _refuse("candidate_address_invalid")
        if address in candidates:
            _refuse("candidate_address_duplicate")
        candidates.append(address)

    appliance_management_mac = normalized_expected[appliance_role][0]
    seen_macs: set[str] = set()
    seen_addresses: dict[str, tuple[str, str]] = {}
    for role, raw_interfaces in guests.items():
        if not isinstance(raw_interfaces, list):
            _refuse("guest_interface_inventory_invalid")
        role_macs: list[str] = []
        for raw_interface in raw_interfaces:
            interface = _object(raw_interface, "guest_interface_invalid")
            if not {"mac", "addresses", "flags", "linkinfo", "link_type"}.issubset(interface):
                _refuse("guest_interface_incomplete")
            if interface["link_type"] != "ether":
                _refuse("guest_interface_not_ethernet")
            flags = interface["flags"]
            if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
                _refuse("guest_interface_flags_invalid")
            mac = _mac(interface["mac"], "guest_interface_mac_invalid")
            management_or_client = role != appliance_role or mac == appliance_management_mac
            if (management_or_client and
                    not {"UP", "LOWER_UP"}.issubset({flag.upper() for flag in flags})):
                _refuse("guest_interface_not_up")
            master = interface.get("master")
            if master not in (None, ""):
                _refuse("guest_interface_master_present")
            linkinfo = interface["linkinfo"]
            if linkinfo is not None:
                link = _object(linkinfo, "guest_interface_linkinfo_invalid")
                kind = link.get("info_kind")
                if kind not in (None, ""):
                    if not isinstance(kind, str):
                        _refuse("guest_interface_linkinfo_invalid")
                    _refuse("guest_virtual_interface_present")
            if mac in seen_macs:
                _refuse("guest_interface_mac_duplicate")
            seen_macs.add(mac)
            role_macs.append(mac)
            raw_addresses = interface["addresses"]
            if not isinstance(raw_addresses, list):
                _refuse("guest_address_inventory_invalid")
            for raw_record in raw_addresses:
                record = _object(raw_record, "guest_address_record_invalid")
                local = record.get("local")
                prefix = record.get("prefixlen")
                if (not isinstance(local, str) or isinstance(prefix, bool) or
                        not isinstance(prefix, int)):
                    _refuse("guest_address_record_invalid")
                try:
                    parsed = ipaddress.ip_interface(f"{local}/{prefix}")
                except ValueError:
                    _refuse("guest_address_record_invalid")
                address = str(parsed.ip)
                identity = (role, mac)
                if address in seen_addresses:
                    _refuse("guest_address_duplicate")
                seen_addresses[address] = identity
        if set(role_macs) != set(normalized_expected[role]) or len(role_macs) != len(normalized_expected[role]):
            _refuse("guest_interface_set_mismatch")

    candidate_claims: dict[str, dict[str, str]] = {}
    for address in candidates:
        candidate_identity = seen_addresses.get(address)
        if candidate_identity is None:
            continue
        role, mac = candidate_identity
        if role != appliance_role or mac != appliance_management_mac:
            _refuse("candidate_address_conflict")
        candidate_claims[address] = {"role": role, "mac": mac}

    return {
        "claim": "candidate-claims-checked-on-enrolled-guest-interfaces",
        "candidate_addresses": sorted(candidates),
        "candidate_claims": candidate_claims,
        "guest_macs": {role: sorted(macs) for role, macs in sorted(normalized_expected.items())},
    }
