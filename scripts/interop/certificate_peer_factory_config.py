"""Validate and render the non-secret inputs for a certificate peer VM."""

from __future__ import annotations

import copy
import ipaddress
import re
from pathlib import Path, PureWindowsPath
from typing import Any

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_LINUX_USER = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_HOSTNAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_COLLISION_SUFFIX = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
_SEGMENT_ID = re.compile(r"52(?: [0-9a-f]{2}){7}-[0-9a-f]{2}(?: [0-9a-f]{2}){7}\Z")
_MANAGEMENT_VMNET = re.compile(r"vmnet[1-9][0-9]*\Z")

_REFERENCE_KEYS = (
    "appliance_intent",
    "appliance_ownership",
    "appliance_installed_boot",
    "peer_source_preparation",
)
_SPEC_KEYS = frozenset(
    {
        "schema",
        "trust_model",
        "repository",
        "pr",
        "task_id",
        "source_commit",
        "server_cidr",
        "lease_address",
        "management_addresses",
        "management_vmnet",
        "peer_user",
        "peer_hostname",
        "collision_suffix",
        *_REFERENCE_KEYS,
        "appliance_vmx",
        "peer_public_key_path",
        "peer_vmdk_sha256",
        "peer_public_key_sha256",
        "appliance_mac",
    }
)


def _require_string(value: Any, field: str) -> str:
    """Require a non-empty string for one specification field.

    Args:
        value: Supplied field value to validate.
        field: Specification field name used in refusal messages.
    """
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string.")
    return value


def _require_absolute_path(value: Any, field: str) -> str:
    """Require a non-empty absolute path for one specification field.

    Args:
        value: Supplied path value to validate.
        field: Specification field name used in refusal messages.
    """
    path = _require_string(value, field)
    if not (Path(path).is_absolute() or PureWindowsPath(path).is_absolute()):
        raise ValueError(f"{field} must be an absolute path.")
    return path


def _is_private_unicast(address: ipaddress.IPv4Address) -> bool:
    """Accept RFC1918 unicast addresses, excluding special-purpose ranges.

    Args:
        address: Parsed IPv4 address used for the peer or appliance network.
    """
    return (
        any(
            address in ipaddress.IPv4Network(network)
            for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _parse_unicast_mac(value: Any, field: str) -> str:
    """Normalize a six-octet unicast MAC address.

    Args:
        value: Supplied hardware address to validate.
        field: Specification field name used in refusal messages.
    """
    if not isinstance(value, str) or not _MAC.fullmatch(value):
        raise ValueError(f"{field} must be six exact hexadecimal MAC octets.")
    normalized = value.lower()
    if int(normalized[:2], 16) & 1:
        raise ValueError(f"{field} must be a unicast MAC address.")
    return normalized


def validate_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized, validated copy of a factory specification.

    This validates value shape and cross-field consistency only. It does not
    read reference files or establish path, file, VM, or receipt ownership.
    Those checks belong to the factory orchestration layer.

    Args:
        spec: Untrusted peer-factory fields supplied by the caller.
    """
    if not isinstance(spec, dict):
        raise ValueError("The peer factory specification must be an object.")
    if any(not isinstance(key, str) for key in spec):
        raise ValueError("Specification field names must be strings.")
    unexpected = set(spec) - _SPEC_KEYS
    missing = _SPEC_KEYS - {"collision_suffix"} - set(spec)
    if unexpected:
        raise ValueError(f"Unexpected specification fields: {', '.join(sorted(unexpected))}.")
    if missing:
        raise ValueError(f"Missing specification fields: {', '.join(sorted(missing))}.")

    result = copy.deepcopy(spec)
    if type(result["schema"]) is not int or result["schema"] != 1:
        raise ValueError("schema must be integer 1.")
    if result["trust_model"] != "trusted-host":
        raise ValueError("trust_model must be trusted-host.")
    if result["repository"] != "mdaneri/Atlaso":
        raise ValueError("repository must be mdaneri/Atlaso.")
    if type(result["pr"]) is not int or result["pr"] <= 0:
        raise ValueError("pr must be a positive integer.")
    if not isinstance(result["task_id"], str) or not _TASK_ID.fullmatch(result["task_id"]):
        raise ValueError("task_id has an invalid shape.")
    if not isinstance(result["source_commit"], str) or not _HEX40.fullmatch(result["source_commit"]):
        raise ValueError("source_commit must be a lowercase 40-character commit ID.")

    try:
        interface = ipaddress.IPv4Interface(_require_string(result["server_cidr"], "server_cidr"))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise ValueError("server_cidr must be an IPv4 interface.") from exc
    network = interface.network
    server = interface.ip
    if not 24 <= network.prefixlen <= 29:
        raise ValueError("server_cidr must use a /24 through /29 prefix.")
    if not _is_private_unicast(server) or server in (network.network_address, network.broadcast_address):
        raise ValueError("server_cidr must contain a usable private peer address.")
    result["server_cidr"] = str(interface)

    try:
        lease = ipaddress.IPv4Address(_require_string(result["lease_address"], "lease_address"))
    except ipaddress.AddressValueError as exc:
        raise ValueError("lease_address must be an IPv4 address.") from exc
    if (
        lease not in network
        or lease in (network.network_address, network.broadcast_address, server)
        or not _is_private_unicast(lease)
    ):
        raise ValueError("lease_address must be a distinct usable private address in the peer subnet.")
    result["lease_address"] = str(lease)

    addresses = result["management_addresses"]
    if not isinstance(addresses, list) or len(addresses) != 3:
        raise ValueError("management_addresses must contain exactly three addresses.")
    normalized_addresses: list[str] = []
    for value in addresses:
        try:
            address = ipaddress.IPv4Address(_require_string(value, "management_addresses entry"))
        except ipaddress.AddressValueError as exc:
            raise ValueError("management_addresses entries must be IPv4 addresses.") from exc
        if (
            address not in network
            or address in (network.network_address, network.broadcast_address, server)
            or not _is_private_unicast(address)
        ):
            raise ValueError("management_addresses must be usable private addresses in the peer subnet.")
        normalized_addresses.append(str(address))
    if len(set(normalized_addresses)) != 3 or str(lease) not in normalized_addresses:
        raise ValueError("management_addresses must be unique and include lease_address.")
    result["management_addresses"] = normalized_addresses

    if not isinstance(result["management_vmnet"], str) or not _MANAGEMENT_VMNET.fullmatch(
        result["management_vmnet"]
    ):
        raise ValueError("management_vmnet must match vmnet[1-9][0-9]*.")
    if not isinstance(result["peer_user"], str) or not _LINUX_USER.fullmatch(result["peer_user"]):
        raise ValueError("peer_user is not a safe Linux user name.")
    if not isinstance(result["peer_hostname"], str) or not _HOSTNAME.fullmatch(result["peer_hostname"]):
        raise ValueError("peer_hostname is not a DNS-safe hostname.")
    if "collision_suffix" in result and (
        not isinstance(result["collision_suffix"], str)
        or not _COLLISION_SUFFIX.fullmatch(result["collision_suffix"])
    ):
        raise ValueError("collision_suffix has an invalid shape.")

    for field in _REFERENCE_KEYS:
        reference = result[field]
        if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
            raise ValueError(f"{field} must contain exactly path and sha256.")
        reference["path"] = _require_absolute_path(reference["path"], f"{field}.path")
        if not isinstance(reference["sha256"], str) or not _HEX64.fullmatch(reference["sha256"]):
            raise ValueError(f"{field}.sha256 must be a lowercase SHA-256 digest.")

    result["appliance_vmx"] = _require_absolute_path(result["appliance_vmx"], "appliance_vmx")
    result["peer_public_key_path"] = _require_absolute_path(
        result["peer_public_key_path"], "peer_public_key_path"
    )
    for field in ("peer_vmdk_sha256", "peer_public_key_sha256"):
        if not isinstance(result[field], str) or not _HEX64.fullmatch(result[field]):
            raise ValueError(f"{field} must be a lowercase SHA-256 digest.")
    result["appliance_mac"] = _parse_unicast_mac(result["appliance_mac"], "appliance_mac")
    return result


def render_vmx(
    spec: dict[str, Any],
    *,
    name: str,
    segment_id: str,
    cleanup_identity: str,
    macs: tuple[str, str],
) -> str:
    """Render an offline two-NIC Alpine peer VMX with only validated values.

    Args:
        spec: Peer-factory fields that pass the configuration validator.
        name: Exact VM display name bound to the task and pull request.
        segment_id: Provider LAN segment identity for the isolated peer.
        cleanup_identity: Original durable identity used for ownership cleanup.
        macs: Peer NIC identities for the management and isolated networks.
    """
    validated = validate_spec(spec)
    suffix = validated.get("collision_suffix")
    expected_name = f"Atlaso-PR-{validated['pr']}-certificate-peer"
    if suffix:
        expected_name += f"-{suffix}"
    if not isinstance(name, str) or name != expected_name:
        raise ValueError("name must match the canonical PR-owned certificate peer identity.")
    if not isinstance(segment_id, str) or not _SEGMENT_ID.fullmatch(segment_id):
        raise ValueError("segment_id must be an exact VMware private LAN identifier.")
    if not isinstance(cleanup_identity, str) or not re.fullmatch(r"[0-9a-f]{32}\Z", cleanup_identity):
        raise ValueError("cleanup_identity must be a lowercase 32-character identity.")
    if not isinstance(macs, tuple) or len(macs) != 2:
        raise ValueError("macs must contain exactly two unicast MAC addresses.")
    management_mac = _parse_unicast_mac(macs[0], "macs[0]")
    private_mac = _parse_unicast_mac(macs[1], "macs[1]")
    if len({management_mac, private_mac, validated["appliance_mac"]}) != 3:
        raise ValueError("Peer MAC addresses and appliance_mac must all be distinct.")

    lines = [
        '.encoding = "UTF-8"',
        'config.version = "8"',
        'virtualHW.version = "21"',
        'pciBridge0.present = "TRUE"',
        'firmware = "efi"',
        'uefi.secureBoot.enabled = "FALSE"',
        f'displayName = "{name}"',
        'guestOS = "other5xlinux-64"',
        'memsize = "1024"',
        'numvcpus = "1"',
        'tools.syncTime = "FALSE"',
        'sata0.present = "TRUE"',
        'sata0:0.present = "TRUE"',
        f'sata0:0.fileName = "{name}.vmdk"',
        'sata0:0.deviceType = "disk"',
        'sata0:1.present = "TRUE"',
        f'sata0:1.fileName = "{name}-seed.iso"',
        'sata0:1.deviceType = "cdrom-image"',
        'sata0:1.startConnected = "TRUE"',
        'serial0.present = "TRUE"',
        'serial0.fileType = "file"',
        f'serial0.fileName = "{name}-serial.log"',
        'serial0.startConnected = "TRUE"',
        'serial0.append = "TRUE"',
        'guestinfo.atlaso.test_vm_cleanup_identity = "' + cleanup_identity + '"',
    ]
    for index, (network_kind, network_id, mac) in enumerate(
        (("custom", validated["management_vmnet"], management_mac), ("pvn", segment_id, private_mac))
    ):
        prefix = f"ethernet{index}"
        lines.extend(
            [
                f'{prefix}.present = "TRUE"',
                f'{prefix}.connectionType = "{network_kind}"',
                f'{prefix}.virtualDev = "e1000"',
                f'{prefix}.addressType = "static"',
                f'{prefix}.address = "{mac}"',
                f'{prefix}.startConnected = "TRUE"',
            ]
        )
        key = "vnet" if network_kind == "custom" else "pvnID"
        lines.append(f'{prefix}.{key} = "{network_id}"')
    return "\n".join(lines) + "\n"
