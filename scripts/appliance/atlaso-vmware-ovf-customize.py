#!/usr/bin/env python3
"""Apply Atlaso VMware OVF deployment properties on first boot."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import datetime, timezone
from ipaddress import ip_interface
from pathlib import Path
from uuid import UUID

from atlaso.app.management_network import (
    ManagementNetworkValidationError,
    validate_management_network,
)

PROPERTY_PREFIX = "atlaso."
PROPERTY_MANAGEMENT_MODE = f"{PROPERTY_PREFIX}management_mode"
PROPERTY_CIDR = f"{PROPERTY_PREFIX}cidr"
PROPERTY_GATEWAY = f"{PROPERTY_PREFIX}gateway"
PROPERTY_IPV6_ENABLED = f"{PROPERTY_PREFIX}ipv6_enabled"
PROPERTY_IPV6_CIDR = f"{PROPERTY_PREFIX}ipv6_cidr"
PROPERTY_IPV6_GATEWAY = f"{PROPERTY_PREFIX}ipv6_gateway"
PROPERTY_FQDN = f"{PROPERTY_PREFIX}fqdn"
PROPERTY_DNS = f"{PROPERTY_PREFIX}dns_servers"
PROPERTY_ADMIN_PASSWORD = f"{PROPERTY_PREFIX}admin_password"
PROPERTY_ROOT_PASSWORD = f"{PROPERTY_PREFIX}root_password"
PROPERTY_ROOT_SSH_ENABLED = f"{PROPERTY_PREFIX}root_ssh_enabled"
PROPERTY_DEVELOPMENT_ADMIN_SSH_PUBLIC_KEY = f"{PROPERTY_PREFIX}development_admin_ssh_public_key"
PROPERTY_DEVELOPMENT_TEST_VM = f"{PROPERTY_PREFIX}development_test_vm"
PROPERTY_NORMAL_TEST_VM = f"{PROPERTY_PREFIX}normal_test_vm"
PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE = f"{PROPERTY_PREFIX}development_root_ca_certificate"
PROPERTY_DEPLOYMENT_ID = f"{PROPERTY_PREFIX}deployment_id"
TEST_VM_SSH_HOST_KEY_GUESTINFO = "guestinfo.atlaso.test_vm_ssh_host_ed25519_public_key"
TEST_VM_HOSTNAME_GUESTINFO = "guestinfo.atlaso.test_vm_hostname"
DEVELOPMENT_ROOT_CA_PRIVATE_KEY_GUESTINFO = (
    "guestinfo.atlaso.test_vm_development_root_ca_private_key"
)
FIRST_BOOT_STAGE_GUESTINFO = "guestinfo.atlaso.test_vm_first_boot_stage"
MINIMUM_PASSWORD_LENGTH = 12
REQUIRED_PROPERTIES = {
    PROPERTY_FQDN,
    PROPERTY_ADMIN_PASSWORD,
    PROPERTY_ROOT_PASSWORD,
}

ENV_PATH = Path("/etc/atlaso/atlaso.env")
NETWORKD_PATH = Path("/etc/systemd/network/00-atlaso-mgmt.network")
RESOLV_CONF_PATH = Path("/etc/resolv.conf")
NGINX_MANAGEMENT_PATH = Path("/etc/atlaso/nginx/sites.d/management.conf")
FIREWALL_CONFIG_PATH = Path("/etc/atlaso/nftables.d/atlaso.nft")
SSHD_ROOT_LOGIN_CONFIG_PATH = Path("/etc/ssh/sshd_config.d/atlaso-root-login.conf")
DEVELOPMENT_ADMIN_SUDOERS_PATH = Path("/etc/sudoers.d/atlaso-test-vm-admin")
SSH_HOST_ED25519_PUBLIC_KEY_PATH = Path("/etc/ssh/ssh_host_ed25519_key.pub")
MARKER_PATH = Path("/var/lib/atlaso/vmware-ovf-customization.applied")
PENDING_MARKER_PATH = Path("/var/lib/atlaso/vmware-ovf-customization.pending")
NO_OVF_MARKER_PATH = Path("/var/lib/atlaso/vmware-no-ovf-initialization.applied")
GUEST_AGENT_MARKER_PATH = Path("/var/lib/atlaso-privileged/guest-agent/guest-agent.applied")
INITIALIZATION_LOCK_PATH = Path("/var/lib/atlaso/vmware-ovf-initializing")
NETWORK_REVIEW_PATH = Path("/var/lib/atlaso/vmware-ovf-network-review.json")
NETWORK_CORRECTION_PATH = Path("/var/lib/atlaso/vmware-ovf-network-correction.json")
DEVELOPMENT_ROOT_CA_STAGING_PATH = Path(
    "/var/lib/atlaso/apply/ca/first-boot-development-root-ca.json"
)
LOG_PATH = Path("/var/log/atlaso/vmware-ovf-customize.log")
DEFAULT_INTERFACE = "eth0"
NETWORK_REVIEW_POLL_SECONDS = 1.0
OVF_ENVIRONMENT_POLL_SECONDS = 1.0
PENDING_EMPTY_CONFIRMATION_READS = 30
FQDN_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class OvfCustomizationError(ValueError):
    """Report a ovf customization error."""
    pass


class OvfManagementNetworkError(OvfCustomizationError):
    """Report recoverable OVF management-network validation failure."""

    pass


class OvfFinalizationError(OvfCustomizationError):
    """Report retryable credential-scrub or marker finalization failure."""

    pass


def utc_now() -> str:
    """Return utc now."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def log(message: str) -> None:
    """Handle log.

    Args:
        message: Human-readable message associated with the operation.
    """
    line = f"{utc_now()} {message}\n"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass
    print(message)


def attr_value(element: ET.Element, local_name: str) -> str:
    """Return attr value.

    Args:
        element: Element consumed by attr value.
        local_name: Local name consumed by attr value.
    """
    for key, value in element.attrib.items():
        if key == local_name or key.endswith(f"}}{local_name}"):
            return value
    return ""


def parse_ovf_environment(xml_text: str) -> dict[str, str]:
    """Parse ovf environment.

    Args:
        xml_text: Candidate xml text to parse.


    Returns:
        The parsed ovf environment.
    """
    if not xml_text.strip():
        return {}
    root = ET.fromstring(xml_text)
    properties: dict[str, str] = {}
    for element in root.iter():
        if not element.tag.endswith("Property"):
            continue
        key = attr_value(element, "key")
        if not key.startswith(PROPERTY_PREFIX):
            continue
        value = attr_value(element, "value")
        properties[key] = value if key in {PROPERTY_ADMIN_PASSWORD, PROPERTY_ROOT_PASSWORD} else value.strip()
    return properties


def validate_fqdn(value: str) -> str:
    """Validate fqdn.

    Args:
        value: Candidate value consumed by validate FQDN.


    Returns:
        The validate fqdn result.

    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    fqdn = value.strip().lower().rstrip(".")
    if not fqdn or "." not in fqdn or not FQDN_PATTERN.match(fqdn):
        raise OvfCustomizationError("atlaso.fqdn must be a fully qualified DNS name")
    if fqdn.endswith(".local"):
        raise OvfCustomizationError("atlaso.fqdn must not use .local")
    return fqdn


def parse_boolean_property(properties: dict[str, str], key: str, *, default: bool = False) -> bool:
    """Parse boolean property.

    Args:
        properties: Candidate properties to parse.
        key: Stable key identifying the setting, secret, or mapping entry.
        default: Whether default applies to the operation.


    Returns:
        The parsed boolean property.

    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    value = properties.get(key, "").strip().lower()
    if not value:
        return default
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise OvfCustomizationError(f"{key} must be true or false")


def validate_ed25519_public_key(
    value: str,
    *,
    field_name: str = PROPERTY_DEVELOPMENT_ADMIN_SSH_PUBLIC_KEY,
) -> str:
    """Validate and normalize one bounded OpenSSH Ed25519 public key.

    Args:
        value: Candidate OpenSSH public-key line.
        field_name: Non-secret field identifier used in validation errors.

    Returns:
        The normalized public-key line, or an empty string when omitted.

    Raises:
        OvfCustomizationError: If the key is not one canonical Ed25519 public key.
    """
    if not value:
        return ""
    if (
        len(value) > 4096
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OvfCustomizationError(
            f"{field_name} must be one bounded OpenSSH line"
        )
    parts = value.split(maxsplit=2)
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise OvfCustomizationError(
            f"{field_name} must use ssh-ed25519"
        )
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OvfCustomizationError(
            f"{field_name} payload is not valid base64"
        ) from exc
    if base64.b64encode(blob).decode("ascii") != parts[1]:
        raise OvfCustomizationError(
            f"{field_name} payload is not canonical base64"
        )

    def read_ssh_string(offset: int) -> tuple[bytes, int]:
        """Read one length-prefixed string from the decoded SSH blob.

        Args:
            offset: Zero-based offset of the string length.

        Returns:
            The decoded string and the offset immediately after it.

        Raises:
            OvfCustomizationError: If the string is truncated.
        """
        if offset + 4 > len(blob):
            raise OvfCustomizationError(
                f"{field_name} payload is truncated"
            )
        length = int.from_bytes(blob[offset : offset + 4], "big")
        start = offset + 4
        end = start + length
        if end > len(blob):
            raise OvfCustomizationError(
                f"{field_name} payload is truncated"
            )
        return blob[start:end], end

    algorithm, offset = read_ssh_string(0)
    public_bytes, offset = read_ssh_string(offset)
    if algorithm != b"ssh-ed25519" or len(public_bytes) != 32 or offset != len(blob):
        raise OvfCustomizationError(
            f"{field_name} payload is not one complete Ed25519 key"
        )
    normalized = f"ssh-ed25519 {parts[1]}"
    if len(parts) == 3 and parts[2]:
        normalized += f" {parts[2]}"
    return normalized


def publish_test_vm_ssh_host_key() -> None:
    """Publish the normal test VM's public Ed25519 host key through VMware guest-info.

    Raises:
        OvfCustomizationError: If the host key is unavailable, invalid, or cannot be published.
    """
    try:
        public_key = SSH_HOST_ED25519_PUBLIC_KEY_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise OvfCustomizationError("The test VM SSH host public key is unavailable") from exc
    # OpenSSH public-key files conventionally contain one final newline. Remove
    # only that terminator so embedded or repeated line breaks still fail closed.
    if public_key.endswith("\r\n"):
        public_key = public_key[:-2]
    elif public_key.endswith("\n"):
        public_key = public_key[:-1]
    normalized = validate_ed25519_public_key(
        public_key,
        field_name="test_vm_ssh_host_ed25519_public_key",
    )
    if not normalized:
        raise OvfCustomizationError("test_vm_ssh_host_ed25519_public_key must not be empty")
    # Comments are not part of host-key identity. Omitting them keeps the VMware
    # RPC value canonical and avoids interpreting arbitrary ssh-keygen comments.
    public_key_without_comment = " ".join(normalized.split(maxsplit=2)[:2])
    rpc_argument = f'info-set {TEST_VM_SSH_HOST_KEY_GUESTINFO} "{public_key_without_comment}"'
    commands = [
        ["vmware-rpctool", rpc_argument],
        ["vmtoolsd", "--cmd", rpc_argument],
    ]
    for command in commands:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        result = subprocess.run(
            [executable, *command[1:]],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            return
    raise OvfCustomizationError("VMware Tools could not publish the test VM SSH host public key")


def publish_test_vm_hostname() -> None:
    """Publish the normal test VM's actual first-boot hostname through VMware guest-info.

    Raises:
        OvfCustomizationError: If the hostname is invalid or cannot be published.
    """
    hostname = validate_fqdn(socket.gethostname())
    rpc_argument = f'info-set {TEST_VM_HOSTNAME_GUESTINFO} "{hostname}"'
    commands = [
        ["vmware-rpctool", rpc_argument],
        ["vmtoolsd", "--cmd", rpc_argument],
    ]
    for command in commands:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        result = subprocess.run(
            [executable, *command[1:]],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            return
    raise OvfCustomizationError("VMware Tools could not publish the test VM hostname")


def validate_non_network_properties(properties: dict[str, str]) -> dict[str, object]:
    """Validate OVF fields that the network-only console flow cannot correct.

    Args:
        properties: Candidate OVF properties to validate.

    Returns:
        The validated non-network customization values.

    Raises:
        OvfCustomizationError: If a non-network property is invalid.
    """
    missing = sorted(key for key in REQUIRED_PROPERTIES if not properties.get(key, "").strip())
    if missing:
        raise OvfCustomizationError(f"Missing required OVF properties: {', '.join(missing)}")
    for password_key in (PROPERTY_ADMIN_PASSWORD, PROPERTY_ROOT_PASSWORD):
        if len(properties[password_key]) < MINIMUM_PASSWORD_LENGTH:
            raise OvfCustomizationError(
                f"{password_key} must be at least {MINIMUM_PASSWORD_LENGTH} characters"
            )
    deployment_id = properties.get(PROPERTY_DEPLOYMENT_ID, "").strip()
    if deployment_id:
        try:
            deployment_id = str(UUID(deployment_id))
        except ValueError as exc:
            raise OvfCustomizationError(f"{PROPERTY_DEPLOYMENT_ID} must be a UUID") from exc
    development_admin_ssh_public_key = validate_ed25519_public_key(
        properties.get(PROPERTY_DEVELOPMENT_ADMIN_SSH_PUBLIC_KEY, "")
    )
    development_test_vm = parse_boolean_property(properties, PROPERTY_DEVELOPMENT_TEST_VM)
    normal_test_vm = parse_boolean_property(properties, PROPERTY_NORMAL_TEST_VM)
    development_root_ca_certificate = properties.get(
        PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE, ""
    ).strip()
    if development_root_ca_certificate and not development_test_vm:
        raise OvfCustomizationError(
            f"{PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE} is restricted to the normal test wrapper"
        )
    decoded_development_root_ca_certificate = ""
    if development_root_ca_certificate:
        if len(development_root_ca_certificate) > 32768:
            raise OvfCustomizationError(
                f"{PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE} exceeds the bounded size"
            )
        try:
            certificate_bytes = base64.b64decode(
                development_root_ca_certificate,
                validate=True,
            )
            if (
                base64.b64encode(certificate_bytes).decode("ascii")
                != development_root_ca_certificate
            ):
                raise ValueError
            decoded_development_root_ca_certificate = certificate_bytes.decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            raise OvfCustomizationError(
                f"{PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE} is not canonical base64 PEM"
            ) from exc
        if (
            decoded_development_root_ca_certificate.count(
                "-----BEGIN CERTIFICATE-----"
            )
            != 1
            or "PRIVATE KEY" in decoded_development_root_ca_certificate
        ):
            raise OvfCustomizationError(
                f"{PROPERTY_DEVELOPMENT_ROOT_CA_CERTIFICATE} is not one public certificate"
            )
    return {
        "fqdn": validate_fqdn(properties[PROPERTY_FQDN]),
        "admin_password": properties[PROPERTY_ADMIN_PASSWORD],
        "root_password": properties[PROPERTY_ROOT_PASSWORD],
        "root_ssh_enabled": parse_boolean_property(properties, PROPERTY_ROOT_SSH_ENABLED),
        "development_admin_ssh_public_key": development_admin_ssh_public_key,
        "development_test_vm": development_test_vm,
        "normal_test_vm": normal_test_vm,
        "development_root_ca_certificate_pem": decoded_development_root_ca_certificate,
        "deployment_id": deployment_id,
    }


def validate_properties(
    properties: dict[str, str],
    *,
    non_network: dict[str, object] | None = None,
) -> dict[str, object]:
    """Validate properties.

    Args:
        properties: Candidate properties to validate.
        non_network: Previously validated non-network values, when available.


    Returns:
        The validate properties result.

    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    validated_non_network = non_network or validate_non_network_properties(properties)

    _legacy_management_mode = properties.get(PROPERTY_MANAGEMENT_MODE, "").strip().lower()
    # Kept parse-compatible for existing deployment automation; address presence now owns IPv4 behavior.
    cidr_value = properties.get(PROPERTY_CIDR, "").strip()
    gateway_value = properties.get(PROPERTY_GATEWAY, "").strip()
    management_mode = "static" if cidr_value or gateway_value else "dhcp"

    try:
        ipv6_enabled = parse_boolean_property(properties, PROPERTY_IPV6_ENABLED)
    except OvfCustomizationError as exc:
        raise OvfManagementNetworkError(str(exc)) from exc
    ipv6_cidr_value = properties.get(PROPERTY_IPV6_CIDR, "").strip()
    ipv6_gateway_value = properties.get(PROPERTY_IPV6_GATEWAY, "").strip()
    ipv6_mode = (
        "static"
        if ipv6_cidr_value or ipv6_gateway_value
        else ("automatic" if ipv6_enabled else "disabled")
    )

    try:
        network = validate_management_network(
            ipv4_method=management_mode,
            ipv4_cidr=cidr_value,
            ipv4_gateway=gateway_value,
            ipv6_mode=ipv6_mode if ipv6_enabled else "disabled",
            ipv6_cidr=ipv6_cidr_value,
            ipv6_gateway=ipv6_gateway_value,
            dns_servers=properties.get(PROPERTY_DNS, ""),
            require_static_ipv4_gateway=True,
        )
    except ManagementNetworkValidationError as exc:
        raise OvfManagementNetworkError(str(exc)) from exc

    management_source_cidr = (
        str(ip_interface(network.ipv4_cidr).network) if network.ipv4_cidr else ""
    )
    management_source_ipv6_cidr = (
        str(ip_interface(network.ipv6_cidr).network) if network.ipv6_cidr else ""
    )
    return {
        "management_mode": network.ipv4_method,
        "cidr": network.ipv4_cidr or "dhcp",
        "gateway": network.ipv4_gateway,
        "ipv6_enabled": ipv6_enabled,
        "ipv6_mode": "auto" if network.ipv6_mode == "automatic" else network.ipv6_mode,
        "ipv6_cidr": network.ipv6_cidr,
        "ipv6_gateway": network.ipv6_gateway,
        "fqdn": validated_non_network["fqdn"],
        "dns_servers": list(network.dns_servers),
        "admin_password": validated_non_network["admin_password"],
        "root_password": validated_non_network["root_password"],
        "root_ssh_enabled": validated_non_network["root_ssh_enabled"],
        "development_admin_ssh_public_key": validated_non_network[
            "development_admin_ssh_public_key"
        ],
        "development_test_vm": validated_non_network["development_test_vm"],
        "normal_test_vm": validated_non_network["normal_test_vm"],
        "development_root_ca_certificate_pem": validated_non_network[
            "development_root_ca_certificate_pem"
        ],
        "deployment_id": validated_non_network["deployment_id"],
        "management_source_cidr": management_source_cidr,
        "management_source_ipv6_cidr": management_source_ipv6_cidr,
    }


def _bounded_review_value(value: object, limit: int = 512) -> str:
    """Return one bounded non-secret OVF value for local console review.

    Args:
        value: Candidate scalar review value.
        limit: Maximum returned character count.

    Returns:
        The bounded display value.
    """
    return str(value or "").strip()[:limit]


def network_review_state(properties: dict[str, str], error: str) -> dict[str, object]:
    """Build the non-secret first-boot network review state.

    Args:
        properties: Original OVF properties containing deployment values.
        error: Safe management-network validation message.

    Returns:
        A bounded non-secret review document.
    """
    cidr = _bounded_review_value(properties.get(PROPERTY_CIDR, ""))
    gateway = _bounded_review_value(properties.get(PROPERTY_GATEWAY, ""))
    ipv6_cidr = _bounded_review_value(properties.get(PROPERTY_IPV6_CIDR, ""))
    ipv6_gateway = _bounded_review_value(properties.get(PROPERTY_IPV6_GATEWAY, ""))
    ipv6_enabled = properties.get(PROPERTY_IPV6_ENABLED, "").strip().lower() in {
        "true",
        "1",
        "yes",
        "on",
    }
    return {
        "version": 1,
        "state": "network_review",
        "error": _bounded_review_value(error, 1024),
        "ipv4_method": "static" if cidr or gateway else "dhcp",
        "ipv4_cidr": cidr,
        "ipv4_gateway": gateway,
        "ipv6_mode": (
            "static"
            if ipv6_cidr or ipv6_gateway
            else ("automatic" if ipv6_enabled else "disabled")
        ),
        "ipv6_cidr": ipv6_cidr,
        "ipv6_gateway": ipv6_gateway,
        "dns_servers": _bounded_review_value(properties.get(PROPERTY_DNS, "")),
        "fqdn": _bounded_review_value(properties.get(PROPERTY_FQDN, ""), 253),
        "updated_at": utc_now(),
    }


def write_json_atomic(path: Path, payload: dict[str, object], *, mode: int = 0o640) -> None:
    """Persist bounded JSON without exposing a partially written state file.

    Args:
        path: Destination path for the JSON document.
        payload: JSON-compatible document to persist.
        mode: Filesystem mode for the completed document.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        # mkstemp creates the inode as 0600. Set the requested final mode before
        # any bytes are written so signer staging is never temporarily broader.
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        fsync_parent_directory(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def fsync_parent_directory(path: Path) -> None:
    """Make a preceding atomic rename durable on supported filesystems.

    Args:
        path: Renamed destination whose parent directory must be synchronized.
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(path.parent, flags)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(directory_fd)
    except OSError:
        if os.name != "nt":
            raise
    finally:
        os.close(directory_fd)


def promote_pending_marker() -> None:
    """Atomically and durably promote the redacted pending state to applied."""
    PENDING_MARKER_PATH.replace(MARKER_PATH)
    fsync_parent_directory(MARKER_PATH)


def sync_customized_host_state() -> None:
    """Flush successful first-boot mutations before recording pending success."""
    sync = getattr(os, "sync", None)
    if sync is None:
        if os.name == "nt":
            return
        raise OSError("The platform does not expose a filesystem synchronization primitive.")
    sync()


def invalidate_pending_marker() -> None:
    """Durably remove an earlier attempt's pending-success record."""
    if not PENDING_MARKER_PATH.exists():
        return
    PENDING_MARKER_PATH.unlink()
    fsync_parent_directory(PENDING_MARKER_PATH)


def invalidate_no_ovf_marker() -> None:
    """Durably remove a prior image-default deployment classification."""
    if not NO_OVF_MARKER_PATH.exists():
        return
    NO_OVF_MARKER_PATH.unlink()
    fsync_parent_directory(NO_OVF_MARKER_PATH)


def write_network_review(properties: dict[str, str], error: str) -> None:
    """Persist recoverable, non-secret first-boot review state.

    Args:
        properties: Original or corrected OVF properties requiring review.
        error: Safe management-network validation or recovery message.
    """
    write_json_atomic(NETWORK_REVIEW_PATH, network_review_state(properties, error))


def read_network_correction() -> dict[str, str] | None:
    """Read one console-supplied, non-secret management-network correction."""
    if not NETWORK_CORRECTION_PATH.exists():
        return None
    try:
        payload = json.loads(NETWORK_CORRECTION_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OvfManagementNetworkError("The console network correction could not be read; review it again.") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise OvfManagementNetworkError("The console network correction has an unsupported format.")
    allowed = {
        "ipv4_method",
        "ipv4_cidr",
        "ipv4_gateway",
        "ipv6_mode",
        "ipv6_cidr",
        "ipv6_gateway",
        "dns_servers",
    }
    unexpected = sorted(set(payload) - allowed - {"version"})
    if unexpected:
        raise OvfManagementNetworkError(
            "The console network correction contains unsupported fields; review it again."
        )
    return {key: _bounded_review_value(payload.get(key, "")) for key in allowed}


def properties_with_network_correction(
    properties: dict[str, str], correction: dict[str, str]
) -> dict[str, str]:
    """Merge only the allowlisted network fields into the original OVF properties.

    Args:
        properties: Original OVF properties, including in-memory credentials.
        correction: Validated allowlisted console network fields.

    Returns:
        The OVF properties with only management-network values replaced.
    """
    corrected = dict(properties)
    ipv4_method = correction.get("ipv4_method", "").strip().lower()
    if ipv4_method == "dhcp":
        corrected.pop(PROPERTY_CIDR, None)
        corrected.pop(PROPERTY_GATEWAY, None)
    else:
        corrected[PROPERTY_CIDR] = correction.get("ipv4_cidr", "")
        corrected[PROPERTY_GATEWAY] = correction.get("ipv4_gateway", "")
    ipv6_mode = correction.get("ipv6_mode", "").strip().lower()
    corrected[PROPERTY_IPV6_ENABLED] = "true" if ipv6_mode != "disabled" else "false"
    if ipv6_mode == "static":
        corrected[PROPERTY_IPV6_CIDR] = correction.get("ipv6_cidr", "")
        corrected[PROPERTY_IPV6_GATEWAY] = correction.get("ipv6_gateway", "")
    else:
        corrected.pop(PROPERTY_IPV6_CIDR, None)
        corrected.pop(PROPERTY_IPV6_GATEWAY, None)
    corrected[PROPERTY_DNS] = correction.get("dns_servers", "")
    return corrected


def clear_network_review() -> None:
    """Remove the non-secret first-boot review handshake."""
    NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
    NETWORK_REVIEW_PATH.unlink(missing_ok=True)


def complete_first_boot_initialization() -> None:
    """Unlock tty1 after success or recover cleanup from an applied marker."""
    clear_network_review()
    PENDING_MARKER_PATH.unlink(missing_ok=True)
    INITIALIZATION_LOCK_PATH.unlink(missing_ok=True)


def complete_no_ovf_initialization() -> int:
    """Record image-default initialization and release the ordinary console.

    Returns:
        Zero after the durable non-OVF marker is written and tty1 is unlocked.
    """
    write_json_atomic(
        NO_OVF_MARKER_PATH,
        {
            "completed_at": utc_now(),
            "source": "image_defaults",
        },
    )
    complete_first_boot_initialization()
    log("No OVF deployment properties supplied; using image defaults.")
    return 0


def recover_pending_customization() -> int:
    """Finish a crash-interrupted credential scrub and applied-marker promotion.

    Returns:
        Zero after the pending state is durably promoted and tty1 is unlocked.
    """
    clear_network_review()
    logged_failure = False
    while not MARKER_PATH.exists():
        try:
            clear_ovf_environment()
            promote_pending_marker()
        except (OvfCustomizationError, OSError, subprocess.CalledProcessError):
            if not logged_failure:
                log(
                    "VMware OVF first-time initialization is retrying the credential scrub and applied-marker "
                    "finalization."
                )
                logged_failure = True
            time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)
    complete_first_boot_initialization()
    log("Recovered completed Atlaso VMware OVF customization after an interrupted credential scrub.")
    return 0


def scrub_applied_ovf_environment() -> None:
    """Remove newly injected properties when a source disk was already customized."""
    logged_failure = False
    empty_reads = 0
    while True:
        answered, content = try_read_ovf_environment()
        if not answered:
            empty_reads = 0
            if not logged_failure:
                log(
                    "VMware OVF customization is retrying an inconclusive deployment-property read from an already "
                    "initialized appliance."
                )
                logged_failure = True
            time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)
            continue
        if not content.strip():
            empty_reads += 1
            if empty_reads >= PENDING_EMPTY_CONFIRMATION_READS:
                return
            if not logged_failure:
                log(
                    "VMware OVF customization is confirming that an already initialized appliance has no newly "
                    "injected deployment properties."
                )
                logged_failure = True
            time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)
            continue
        try:
            clear_ovf_environment()
            return
        except (OvfCustomizationError, OSError, subprocess.CalledProcessError):
            if not logged_failure:
                log(
                    "VMware OVF customization is retrying removal of deployment properties from an already "
                    "initialized appliance."
                )
                logged_failure = True
            time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)


def pending_marker_matches_current_deployment(ovf_env_file: str) -> bool:
    """Return whether pending state belongs to the currently injected deployment.

    Args:
        ovf_env_file: Optional filesystem path supplied by the command line.

    Returns:
        ``True`` when restart recovery may promote the pending marker. A
        different raw-clone deployment identifier or malformed nonempty input
        requires a fresh apply instead.
    """
    logged_failure = False
    empty_reads = 0
    while True:
        if ovf_env_file:
            try:
                content = Path(ovf_env_file).read_text(encoding="utf-8")
            except OSError:
                return False
        else:
            answered, content = try_read_ovf_environment()
            if not answered:
                empty_reads = 0
                if not logged_failure:
                    log(
                        "VMware OVF first-time initialization is retrying an inconclusive deployment-property read "
                        "before pending-state recovery."
                    )
                    logged_failure = True
                time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)
                continue
        if content.strip():
            break
        empty_reads += 1
        if empty_reads >= PENDING_EMPTY_CONFIRMATION_READS:
            return True
        if not logged_failure:
            log(
                "VMware OVF first-time initialization is confirming that deployment properties remain empty "
                "before pending-state recovery."
            )
            logged_failure = True
        time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)
    try:
        properties = parse_ovf_environment(content)
        pending = json.loads(PENDING_MARKER_PATH.read_text(encoding="utf-8"))
    except (OSError, ET.ParseError, json.JSONDecodeError):
        return False
    if not isinstance(pending, dict):
        return False
    current_deployment_id = properties.get(PROPERTY_DEPLOYMENT_ID, "").strip().lower()
    pending_deployment_id = str(pending.get("deployment_id", "")).strip().lower()
    return bool(
        current_deployment_id
        and pending_deployment_id
        and current_deployment_id == pending_deployment_id
    )


def wait_for_network_review(properties: dict[str, str], error: str) -> int:
    """Wait visibly for tty1 to provide a valid first-boot network correction.

    Args:
        properties: Original OVF properties retained in process memory.
        error: Initial safe management-network validation message.

    Returns:
        Zero after corrected customization succeeds.
    """
    write_network_review(properties, error)
    log("VMware OVF management network requires review on the Atlaso tty1 console.")
    while True:
        try:
            correction = read_network_correction()
        except OvfManagementNetworkError as exc:
            write_network_review(properties, str(exc))
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            time.sleep(NETWORK_REVIEW_POLL_SECONDS)
            continue
        if correction is None:
            time.sleep(NETWORK_REVIEW_POLL_SECONDS)
            continue
        corrected_properties = properties_with_network_correction(properties, correction)
        try:
            config = validate_properties(corrected_properties)
        except OvfManagementNetworkError as exc:
            write_network_review(corrected_properties, str(exc))
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            continue
        except OvfCustomizationError as exc:
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            log(
                "VMware OVF customization stopped after an uncorrectable console validation: "
                f"{type(exc).__name__}"
            )
            return 2
        try:
            run_initialization_layer("pending success marker invalidation", invalidate_pending_marker)
            summary = apply_customization(config)
        except OvfFinalizationError as exc:
            log(f"VMware OVF customization is retrying first-boot finalization: {exc}")
            return recover_pending_customization()
        except OvfCustomizationError as exc:
            write_network_review(
                corrected_properties,
                "The corrected management network validated, but first-time initialization did not finish. "
                "Resolve the condition reported in the customization log, then submit the network review again.",
            )
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            log(f"VMware OVF customization could not finish after console correction: {exc}")
            continue
        except (OSError, subprocess.CalledProcessError) as exc:
            write_network_review(
                corrected_properties,
                "The corrected management network could not be applied. Review the values and retry.",
            )
            NETWORK_CORRECTION_PATH.unlink(missing_ok=True)
            log(f"VMware OVF customization could not apply the console correction: {type(exc).__name__}")
            continue
        complete_first_boot_initialization()
        log("Applied corrected Atlaso VMware OVF customization: " + json.dumps(summary, sort_keys=True))
        return 0


def redacted_summary(config: dict[str, object]) -> dict[str, object]:
    """Return redacted summary.

    Args:
        config: Validated configuration consumed by the operation.
    """
    return {
        "applied_at": utc_now(),
        "management_mode": config["management_mode"],
        "cidr": config["cidr"],
        "gateway": config["gateway"],
        "ipv6_enabled": config["ipv6_enabled"],
        "ipv6_mode": config["ipv6_mode"],
        "ipv6_cidr": config["ipv6_cidr"],
        "ipv6_gateway": config["ipv6_gateway"],
        "fqdn": config["fqdn"],
        "dns_server_count": len(config["dns_servers"]),
        "admin_password_set": bool(config["admin_password"]),
        "root_password_set": bool(config["root_password"]),
        "root_ssh_enabled": config["root_ssh_enabled"],
        "development_admin_ssh_key_set": bool(config["development_admin_ssh_public_key"]),
        "development_admin_passwordless_sudo": bool(
            config["development_admin_ssh_public_key"]
        ),
        "normal_test_vm": bool(config["normal_test_vm"]),
        "development_root_ca_staged": bool(
            config["development_root_ca_certificate_pem"]
        ),
        "deployment_id": config["deployment_id"],
    }


def try_read_ovf_environment() -> tuple[bool, str]:
    """Return whether VMware Tools answered and the current OVF environment."""
    commands = [
        ["vmware-rpctool", "info-get guestinfo.ovfEnv"],
        ["vmtoolsd", "--cmd", "info-get guestinfo.ovfEnv"],
    ]
    for command in commands:
        if shutil.which(command[0]) is None:
            continue
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if result.returncode == 0:
            content = result.stdout
            if content.strip() == '""':
                content = ""
            return True, content
    return False, ""


def detect_virtualization_platform() -> str:
    """Return the platform selected by the prerequisite guest-agent service."""

    if GUEST_AGENT_MARKER_PATH.exists():
        try:
            marker = GUEST_AGENT_MARKER_PATH.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise OvfCustomizationError("Guest-agent platform marker could not be read") from exc
        match = re.fullmatch(r"platform=(vmware|qemu|hyperv|baremetal)", marker)
        if match is None:
            raise OvfCustomizationError("Guest-agent platform marker is invalid")
        return match.group(1)
    executable = shutil.which("systemd-detect-virt")
    if executable is None:
        return ""
    result = subprocess.run(
        [executable, "--vm"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip().lower()


def read_ovf_environment() -> str:
    """Return OVF XML, collapsing an inconclusive read for the normal polling path."""
    _answered, content = try_read_ovf_environment()
    return content


def clear_ovf_environment() -> None:
    """Remove secret-bearing deployment properties from the VMware guest channel.

    Raises:
        OvfCustomizationError: If no available VMware Tools command accepts the scrub.
    """
    commands = [
        ["vmware-rpctool", 'info-set guestinfo.ovfEnv ""'],
        ["vmtoolsd", "--cmd", 'info-set guestinfo.ovfEnv ""'],
    ]
    for command in commands:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        result = subprocess.run(
            [executable, *command[1:]],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            return
    raise OvfCustomizationError("VMware Tools could not clear the consumed OVF deployment properties")


def try_read_guestinfo_value(name: str) -> tuple[bool, str]:
    """Return whether VMware Tools answered and one exact guest-info value.

    Args:
        name: Fixed guest-info key selected by the caller.

    Returns:
        Whether a supported VMware Tools command answered and its value.
    """
    commands = [
        ["vmware-rpctool", f"info-get {name}"],
        ["vmtoolsd", "--cmd", f"info-get {name}"],
    ]
    for command in commands:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        result = subprocess.run(
            [executable, *command[1:]],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            value = result.stdout.strip()
            return True, "" if value == '""' else value
    return False, ""


def clear_guestinfo_value(name: str) -> None:
    """Clear and verify one fixed secret-bearing VMware guest-info value.

    Args:
        name: Fixed guest-info key selected by the caller.

    Raises:
        OvfCustomizationError: If VMware Tools cannot clear and verify the value.
    """
    commands = [
        ["vmware-rpctool", f'info-set {name} ""'],
        ["vmtoolsd", "--cmd", f'info-set {name} ""'],
    ]
    for command in commands:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        result = subprocess.run(
            [executable, *command[1:]],
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            continue
        answered, value = try_read_guestinfo_value(name)
        if answered and not value:
            return
    raise OvfCustomizationError("VMware Tools could not prove a secret guest-info value was cleared")


def publish_first_boot_stage(stage: str) -> None:
    """Best-effort publish one bounded non-secret normal-test-VM stage.

    Args:
        stage: Stable lowercase stage identifier.
    """
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", stage):
        return
    commands = (
        ["vmware-rpctool", f"info-set {FIRST_BOOT_STAGE_GUESTINFO} {stage}"],
        ["vmtoolsd", "--cmd", f"info-set {FIRST_BOOT_STAGE_GUESTINFO} {stage}"],
    )
    for command in commands:
        executable = shutil.which(command[0])
        if executable is None:
            continue
        try:
            result = subprocess.run(
                [executable, *command[1:]],
                check=False,
                text=True,
                capture_output=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return


def stage_development_root_ca(config: dict[str, object]) -> None:
    """Stage and scrub the normal test VM's shared development signing key.

    Args:
        config: Validated normal-test-VM configuration containing the public root.

    Raises:
        OvfCustomizationError: If staging is unsafe, incomplete, or cannot be scrubbed.
    """
    certificate_pem = str(config.get("development_root_ca_certificate_pem", ""))
    if not certificate_pem:
        return

    if DEVELOPMENT_ROOT_CA_STAGING_PATH.exists():
        try:
            path_stat = DEVELOPMENT_ROOT_CA_STAGING_PATH.lstat()
            if (
                DEVELOPMENT_ROOT_CA_STAGING_PATH.is_symlink()
                or not DEVELOPMENT_ROOT_CA_STAGING_PATH.is_file()
                or path_stat.st_mode & 0o777 != 0o600
                or path_stat.st_size > 65536
            ):
                raise ValueError
            staged = json.loads(
                DEVELOPMENT_ROOT_CA_STAGING_PATH.read_text(encoding="utf-8")
            )
            if (
                staged.get("certificate_pem") != certificate_pem
                or not str(staged.get("private_key_pem", "")).startswith(
                    ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")
                )
            ):
                raise ValueError
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OvfCustomizationError(
                "The staged development root CA material is unsafe or inconsistent"
            ) from exc
    else:
        answered, encoded_private_key = try_read_guestinfo_value(
            DEVELOPMENT_ROOT_CA_PRIVATE_KEY_GUESTINFO
        )
        if not answered or not encoded_private_key or len(encoded_private_key) > 16384:
            raise OvfCustomizationError(
                "The normal test VM development signing key guest-info value is unavailable"
            )
        try:
            private_key_bytes = base64.b64decode(encoded_private_key, validate=True)
            if base64.b64encode(private_key_bytes).decode("ascii") != encoded_private_key:
                raise ValueError
            private_key_pem = private_key_bytes.decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            raise OvfCustomizationError(
                "The normal test VM development signing key guest-info value is invalid"
            ) from exc
        if (
            len(private_key_pem) > 16384
            or not private_key_pem.startswith(
                ("-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----")
            )
        ):
            raise OvfCustomizationError(
                "The normal test VM development signing key PEM is invalid"
            )
        write_json_atomic(
            DEVELOPMENT_ROOT_CA_STAGING_PATH,
            {
                "certificate_pem": certificate_pem,
                "private_key_pem": private_key_pem,
            },
            mode=0o600,
        )

    clear_guestinfo_value(DEVELOPMENT_ROOT_CA_PRIVATE_KEY_GUESTINFO)


def read_ovf_environment_source(ovf_env_file: str) -> str:
    """Read OVF XML from an explicit test file or the VMware guest channel.

    Args:
        ovf_env_file: Optional filesystem path supplied by the command line.

    Returns:
        The current OVF environment XML text.
    """
    return Path(ovf_env_file).read_text(encoding="utf-8") if ovf_env_file else read_ovf_environment()


def try_read_ovf_environment_source(ovf_env_file: str) -> tuple[bool, str]:
    """Preserve whether the selected deployment-property source answered.

    Args:
        ovf_env_file: Optional filesystem path supplied by the command line.

    Returns:
        Whether the source answered and its current OVF environment text.
    """
    if ovf_env_file:
        return True, Path(ovf_env_file).read_text(encoding="utf-8")
    return try_read_ovf_environment()


def wait_for_ovf_properties(
    ovf_env_file: str,
) -> tuple[dict[str, str], dict[str, object]] | None:
    """Wait fail-closed for a complete, valid non-network OVF property set.

    Args:
        ovf_env_file: Optional filesystem path supplied by the command line.

    Returns:
        The complete raw properties and validated non-network values, or
        ``None`` after a stable answered-empty source confirms a non-OVF boot.
    """
    last_state = ""
    messages = {
        "unavailable": "Atlaso VMware OVF deployment properties are unavailable; waiting with tty1 locked.",
        "empty": (
            "Atlaso VMware OVF deployment properties are empty; confirming whether image defaults should be used."
        ),
        "unreadable": "Atlaso VMware OVF deployment properties are unreadable; waiting with tty1 locked.",
        "incomplete": (
            "Atlaso VMware OVF deployment properties are incomplete or invalid; "
            "waiting with tty1 locked."
        ),
    }
    empty_reads = 0
    while True:
        try:
            answered, content = try_read_ovf_environment_source(ovf_env_file)
        except (OSError, ET.ParseError):
            empty_reads = 0
            state = "unreadable"
        else:
            if not answered:
                empty_reads = 0
                state = "unavailable"
            elif not content.strip():
                empty_reads += 1
                if empty_reads >= PENDING_EMPTY_CONFIRMATION_READS:
                    return None
                state = "empty"
            else:
                empty_reads = 0
                try:
                    properties = parse_ovf_environment(content)
                except ET.ParseError:
                    state = "unreadable"
                else:
                    if not properties:
                        state = "incomplete"
                    else:
                        try:
                            non_network = validate_non_network_properties(properties)
                        except OvfCustomizationError:
                            state = "incomplete"
                        else:
                            log("Atlaso VMware OVF deployment properties are complete; continuing initialization.")
                            return properties, non_network
        if state != last_state:
            log(messages[state])
            last_state = state
        time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)


def quote_env_value(value: object) -> str:
    """Return quote env value.

    Args:
        value: Candidate value consumed by quote env value.
    """
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def generate_secret_key() -> str:
    """Build secret key.

    Returns:
        The generate secret key result.
    """
    return secrets.token_urlsafe(48)


def read_env_file(path: Path) -> dict[str, str]:
    """Return env file.

    Args:
        path: Filesystem or URL path to read, validate, or update.
    """
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def write_env_file(path: Path, updates: dict[str, object]) -> None:
    """Persist env file.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        updates: Updates supplied by the caller.
    """
    values = read_env_file(path)
    values.update({key: str(value) for key, value in updates.items()})
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{key}={quote_env_value(values[key])}" for key in sorted(values)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(path, 0o640)
    try:
        shutil.chown(path, user="root", group="atlaso")
    except (LookupError, PermissionError):
        pass


def write_networkd_config(config: dict[str, object]) -> None:
    """Persist networkd config.

    Args:
        config: Validated configuration consumed by the operation.
    """
    lines = ["[Match]", f"Name={DEFAULT_INTERFACE}", "", "[Network]"]
    if config["management_mode"] == "dhcp":
        lines.append("DHCP=ipv4")
    else:
        lines.append(f"Address={config['cidr']}")
        lines.append(f"Gateway={config['gateway']}")
    if config["ipv6_mode"] == "disabled":
        lines.extend(["IPv6AcceptRA=no", "LinkLocalAddressing=no"])
    elif config["ipv6_mode"] == "auto":
        lines.extend(["IPv6AcceptRA=yes", "LinkLocalAddressing=ipv6"])
    else:
        lines.extend(["IPv6AcceptRA=no", "LinkLocalAddressing=ipv6", f"Address={config['ipv6_cidr']}"])
        if config["ipv6_gateway"]:
            lines.append(f"Gateway={config['ipv6_gateway']}")
    lines.extend(f"DNS={server}" for server in config["dns_servers"])
    content = "\n".join(lines).strip() + "\n"
    NETWORKD_PATH.parent.mkdir(parents=True, exist_ok=True)
    NETWORKD_PATH.write_text(content, encoding="utf-8")
    os.chmod(NETWORKD_PATH, 0o644)


def write_resolv_conf(config: dict[str, object]) -> None:
    """Persist resolv conf.

    Args:
        config: Validated configuration consumed by the operation.
    """
    if not config["dns_servers"]:
        return
    RESOLV_CONF_PATH.write_text("".join(f"nameserver {server}\n" for server in config["dns_servers"]), encoding="utf-8")
    os.chmod(RESOLV_CONF_PATH, 0o644)


def write_nginx_management_server_name(config: dict[str, object]) -> None:
    """Persist nginx management server name.

    Args:
        config: Validated configuration consumed by the operation.
    """
    if not NGINX_MANAGEMENT_PATH.exists():
        return
    text = NGINX_MANAGEMENT_PATH.read_text(encoding="utf-8")
    text = re.sub(r"server_name\s+[^;]+;", f"server_name {config['fqdn']} _;", text, count=1)
    NGINX_MANAGEMENT_PATH.write_text(text, encoding="utf-8")
    os.chmod(NGINX_MANAGEMENT_PATH, 0o644)


def write_initial_firewall_config(config: dict[str, object]) -> None:
    """Persist initial firewall config.

    Args:
        config: Validated configuration consumed by the operation.
    """
    management_rules = []
    source_cidr = str(config["management_source_cidr"])
    management_rules.append(
        f'ip saddr {source_cidr} tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv4 management access"'
        if source_cidr
        else f'iifname "{DEFAULT_INTERFACE}" meta nfproto ipv4 tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv4 management access"'
    )
    if config["ipv6_mode"] == "auto":
        management_rules.append(
            f'iifname "{DEFAULT_INTERFACE}" meta nfproto ipv6 tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv6 management access"'
        )
    elif config["ipv6_mode"] == "static":
        management_rules.append(
            f'ip6 saddr {config["management_source_ipv6_cidr"]} tcp dport {{ 22, 80, 443 }} accept comment "Atlaso IPv6 management access"'
        )
    rendered_management_rules = "\n    ".join(management_rules)
    content = f"""# Managed by Atlaso. Local changes may be overwritten.
# nftables firewall state for Photon OS appliance images.
flush ruleset
table inet atlaso {{
  chain input {{
    type filter hook input priority filter; policy drop;
    iifname "lo" accept comment "Atlaso loopback"
    ct state established,related accept comment "Atlaso established traffic"
    {rendered_management_rules}
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }}
  chain forward {{
    type filter hook forward priority filter; policy drop;
    ct state established,related accept comment "Atlaso established traffic"
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }}
  chain output {{
    type filter hook output priority filter; policy accept;
    ct state established,related accept comment "Atlaso established traffic"
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }}
}}
"""
    FIREWALL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIREWALL_CONFIG_PATH.write_text(content, encoding="utf-8")
    os.chmod(FIREWALL_CONFIG_PATH, 0o644)


def set_password(username: str, password: str) -> None:
    """Update password.

    Args:
        username: Account name used for authentication or lookup.
        password: Password supplied for the immediate authenticated operation.
    """
    subprocess.run(["chpasswd"], input=f"{username}:{password}\n", text=True, check=True)


def set_hostname(fqdn: str) -> None:
    """Update hostname.

    Args:
        fqdn: Fqdn consumed by set hostname.
    """
    hostnamectl = shutil.which("hostnamectl")
    if hostnamectl:
        subprocess.run([hostnamectl, "set-hostname", fqdn], check=True)
        return
    Path("/etc/hostname").write_text(f"{fqdn}\n", encoding="utf-8")
    hostname = shutil.which("hostname")
    if hostname:
        subprocess.run([hostname, fqdn], check=True)


def configure_root_ssh(enabled: bool) -> None:
    """Update root ssh.

    Args:
        enabled: Whether the associated resource or behavior is enabled.


    Raises:
        OvfCustomizationError: If the operation encounters an invalid state.
    """
    SSHD_ROOT_LOGIN_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    previous = SSHD_ROOT_LOGIN_CONFIG_PATH.read_text(encoding="utf-8") if SSHD_ROOT_LOGIN_CONFIG_PATH.exists() else None
    lines = [
        "# Managed by Atlaso. Local changes may be overwritten by Appliance Settings apply.",
        f"PermitRootLogin {'yes' if enabled else 'no'}",
    ]
    if enabled:
        lines.extend(["PasswordAuthentication yes", "KbdInteractiveAuthentication yes"])
    SSHD_ROOT_LOGIN_CONFIG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(SSHD_ROOT_LOGIN_CONFIG_PATH, 0o644)
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    try:
        subprocess.run([sshd, "-t"], check=True, text=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        if previous is None:
            SSHD_ROOT_LOGIN_CONFIG_PATH.unlink(missing_ok=True)
        else:
            SSHD_ROOT_LOGIN_CONFIG_PATH.write_text(previous, encoding="utf-8")
            os.chmod(SSHD_ROOT_LOGIN_CONFIG_PATH, 0o644)
        raise OvfCustomizationError("Photon sshd configuration validation failed") from exc


def resolve_os_account(username: str) -> object:
    """Resolve one local operating-system account without importing pwd on Windows.

    Args:
        username: Exact local account name.

    Returns:
        The platform account record.
    """
    import pwd

    return pwd.getpwnam(username)


def chown_path(path: Path, uid: int, gid: int) -> None:
    """Assign Linux ownership through a testable platform boundary.

    Args:
        path: Exact file-system path whose ownership changes.
        uid: Final owner user ID.
        gid: Final owner group ID.
    """
    os.chown(path, uid, gid)


def chmod_path(path: Path, mode: int) -> None:
    """Assign a POSIX mode through a testable platform boundary.

    Args:
        path: Exact file-system path whose mode changes.
        mode: Final POSIX mode.
    """
    os.chmod(path, mode)


def replace_path_atomic(source: Path, destination: Path) -> None:
    """Atomically replace one destination through a testable platform boundary.

    Args:
        source: Prepared file in the destination directory.
        destination: Exact path to replace.
    """
    source.replace(destination)


def unlink_path(path: Path) -> None:
    """Remove one file when present through a testable platform boundary.

    Args:
        path: Exact file to remove.
    """
    path.unlink(missing_ok=True)


def _write_owned_file_atomic(
    path: Path,
    content: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    """Atomically replace one owned file and synchronize its parent.

    Args:
        path: Exact destination path.
        content: Bytes to write.
        mode: Final file mode.
        uid: Final owner user ID.
        gid: Final owner group ID.
    """
    if path.is_symlink():
        raise OvfCustomizationError(f"Refusing symlink-backed development SSH path: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        chmod_path(temporary, mode)
        chown_path(temporary, uid, gid)
        replace_path_atomic(temporary, path)
        fsync_parent_directory(path)
    finally:
        unlink_path(temporary)


def configure_development_admin_ssh(username: str, public_key: str) -> None:
    """Install test-VM-only administrator key access and passwordless sudo.

    Args:
        username: Bootstrap administrator account name.
        public_key: Validated Ed25519 OpenSSH public key.

    Raises:
        OvfCustomizationError: If account, path, ownership, or sudoers validation fails.
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", username):
        raise OvfCustomizationError("Bootstrap administrator account name is not safe for sudoers")
    key = validate_ed25519_public_key(public_key)
    if not key:
        return
    try:
        account = resolve_os_account(username)
    except (KeyError, ImportError) as exc:
        raise OvfCustomizationError("Bootstrap administrator operating-system account was not found") from exc
    home = Path(str(account.pw_dir))
    if not home.is_absolute() or not home.exists() or not home.is_dir() or home.is_symlink():
        raise OvfCustomizationError("Bootstrap administrator home is not a safe existing directory")
    ssh_directory = home / ".ssh"
    if ssh_directory.exists() and (not ssh_directory.is_dir() or ssh_directory.is_symlink()):
        raise OvfCustomizationError("Bootstrap administrator SSH directory is not a safe directory")
    ssh_directory.mkdir(mode=0o700, exist_ok=True)
    chmod_path(ssh_directory, 0o700)
    chown_path(ssh_directory, int(account.pw_uid), int(account.pw_gid))
    authorized_keys = ssh_directory / "authorized_keys"
    if authorized_keys.is_symlink():
        raise OvfCustomizationError("Bootstrap administrator authorized_keys is not a safe file")

    sudoers_directory = DEVELOPMENT_ADMIN_SUDOERS_PATH.parent
    if (
        not sudoers_directory.exists()
        or not sudoers_directory.is_dir()
        or sudoers_directory.is_symlink()
        or DEVELOPMENT_ADMIN_SUDOERS_PATH.is_symlink()
    ):
        raise OvfCustomizationError("Development sudoers directory is not a safe existing directory")
    visudo = shutil.which("visudo")
    if visudo is None:
        raise OvfCustomizationError("visudo is required for development passwordless sudo validation")

    previous_authorized_keys = authorized_keys.read_bytes() if authorized_keys.exists() else None
    previous_stat = authorized_keys.stat() if authorized_keys.exists() else None
    previous_sudoers = (
        DEVELOPMENT_ADMIN_SUDOERS_PATH.read_bytes()
        if DEVELOPMENT_ADMIN_SUDOERS_PATH.exists()
        else None
    )
    previous_sudoers_stat = (
        DEVELOPMENT_ADMIN_SUDOERS_PATH.stat()
        if DEVELOPMENT_ADMIN_SUDOERS_PATH.exists()
        else None
    )
    sudoers_content = (
        "# Development-only access provisioned by create-atlaso-test-vm.ps1.\n"
        f"{username} ALL=(ALL) NOPASSWD: ALL\n"
    ).encode("utf-8")
    temporary_sudoers = DEVELOPMENT_ADMIN_SUDOERS_PATH.with_name(
        f".{DEVELOPMENT_ADMIN_SUDOERS_PATH.name}.{os.getpid()}.tmp"
    )
    sudoers_replaced = False
    try:
        _write_owned_file_atomic(
            authorized_keys,
            f"{key}\n".encode("utf-8"),
            mode=0o600,
            uid=int(account.pw_uid),
            gid=int(account.pw_gid),
        )
        with temporary_sudoers.open("xb") as handle:
            handle.write(sudoers_content)
            handle.flush()
            os.fsync(handle.fileno())
        chmod_path(temporary_sudoers, 0o440)
        chown_path(temporary_sudoers, 0, 0)
        subprocess.run(
            [visudo, "-cf", str(temporary_sudoers)],
            check=True,
            text=True,
            capture_output=True,
        )
        replace_path_atomic(temporary_sudoers, DEVELOPMENT_ADMIN_SUDOERS_PATH)
        sudoers_replaced = True
        fsync_parent_directory(DEVELOPMENT_ADMIN_SUDOERS_PATH)
    except (OSError, OvfCustomizationError, subprocess.CalledProcessError) as exc:
        try:
            if sudoers_replaced:
                if previous_sudoers is None:
                    unlink_path(DEVELOPMENT_ADMIN_SUDOERS_PATH)
                    fsync_parent_directory(DEVELOPMENT_ADMIN_SUDOERS_PATH)
                elif previous_sudoers_stat is not None:
                    _write_owned_file_atomic(
                        DEVELOPMENT_ADMIN_SUDOERS_PATH,
                        previous_sudoers,
                        mode=previous_sudoers_stat.st_mode & 0o7777,
                        uid=previous_sudoers_stat.st_uid,
                        gid=previous_sudoers_stat.st_gid,
                    )
            if previous_authorized_keys is None:
                unlink_path(authorized_keys)
                fsync_parent_directory(authorized_keys)
            elif previous_stat is not None:
                _write_owned_file_atomic(
                    authorized_keys,
                    previous_authorized_keys,
                    mode=previous_stat.st_mode & 0o7777,
                    uid=previous_stat.st_uid,
                    gid=previous_stat.st_gid,
                )
        except (OSError, OvfCustomizationError) as rollback_exc:
            raise OvfCustomizationError(
                "Development sudoers validation failed and authorized_keys rollback was incomplete"
            ) from rollback_exc
        raise OvfCustomizationError("Development passwordless sudo validation failed") from exc
    finally:
        unlink_path(temporary_sudoers)


def restart_console() -> None:
    """Restart tty1 so it reloads the newly applied appliance secrets."""
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        if os.name == "nt":
            return
        raise OvfCustomizationError("systemctl is required to refresh the Atlaso console")
    subprocess.run(
        [systemctl, "restart", "atlaso-console.service"],
        check=True,
        text=True,
        capture_output=True,
    )


def run_initialization_layer(
    label: str,
    operation: Callable[[], None],
    *,
    stage_reporter: Callable[[str], None] | None = None,
) -> None:
    """Run one mutation while exposing only its bounded non-secret layer name.

    Args:
        label: Stable operator-facing name for the initialization layer.
        operation: Mutation to execute.
        stage_reporter: Optional bounded non-secret progress publisher.

    Raises:
        OvfCustomizationError: If the layer cannot finish.
    """
    stage = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:56]
    if stage_reporter is not None:
        stage_reporter(stage)
    try:
        operation()
    except (OvfCustomizationError, OSError, subprocess.CalledProcessError) as exc:
        if stage_reporter is not None:
            stage_reporter(f"failed-{stage}")
        raise OvfCustomizationError(f"First-time initialization failed in the {label} layer.") from exc


def run_finalization_layer(
    label: str,
    operation: Callable[[], None],
    *,
    stage_reporter: Callable[[str], None] | None = None,
) -> None:
    """Run a retryable OVF credential-scrub or marker operation.

    Args:
        label: Stable operator-facing name for the finalization layer.
        operation: Mutation to execute.
        stage_reporter: Optional bounded non-secret progress publisher.

    Raises:
        OvfFinalizationError: If finalization must retry without network review.
    """
    stage = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:56]
    if stage_reporter is not None:
        stage_reporter(stage)
    try:
        operation()
    except (OvfCustomizationError, OSError, subprocess.CalledProcessError) as exc:
        if stage_reporter is not None:
            stage_reporter(f"failed-{stage}")
        raise OvfFinalizationError(f"First-time initialization failed in the {label} layer.") from exc


def appliance_environment_values(config: dict[str, object]) -> dict[str, object]:
    """Return Atlaso environment values for validated management customization.

    Args:
        config: Validated OVF customization values.

    Returns:
        Environment values that seed the first Atlaso desired state.
    """
    return {
        "ATLASO_BOOTSTRAP_ADMIN_PASSWORD": config["admin_password"],
        "ATLASO_SECRET_KEY": generate_secret_key(),
        "ATLASO_SECRETS_KEY": generate_secret_key(),
        "ATLASO_APPLIANCE_FQDN": config["fqdn"],
        "ATLASO_APPLIANCE_MANAGEMENT_CIDR": config["cidr"],
        "ATLASO_APPLIANCE_MANAGEMENT_GATEWAY": config["gateway"],
        "ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED": str(config["ipv6_enabled"]).lower(),
        "ATLASO_APPLIANCE_MANAGEMENT_IPV6_CIDR": config["ipv6_cidr"],
        "ATLASO_APPLIANCE_MANAGEMENT_IPV6_GATEWAY": config["ipv6_gateway"],
        "ATLASO_APPLIANCE_ROOT_SSH_ENABLED": str(config["root_ssh_enabled"]).lower(),
        "ATLASO_APPLIANCE_EXTERNAL_DNS_SERVERS": ",".join(config["dns_servers"]),
        "ATLASO_MANAGEMENT_SOURCE_CIDR": config["management_source_cidr"],
    }


def apply_customization(config: dict[str, object], *, dry_run: bool = False) -> dict[str, object]:
    """Update customization.

    Args:
        config: Validated configuration consumed by the operation.
        dry_run: Whether to report planned actions without mutating host state.


    Returns:
        The apply customization result.
    """
    summary = redacted_summary(config)
    if dry_run:
        return summary

    stage_reporter = publish_first_boot_stage if config["normal_test_vm"] else None

    def run_layer(label: str, operation: Callable[[], None]) -> None:
        """Run one initialization layer with normal-test-VM stage reporting.

        Args:
            label: Human-readable layer name published for normal test VMs.
            operation: Initialization operation to execute.
        """
        run_initialization_layer(label, operation, stage_reporter=stage_reporter)

    def run_final_layer(label: str, operation: Callable[[], None]) -> None:
        """Run one finalization layer with normal-test-VM stage reporting.

        Args:
            label: Human-readable layer name published for normal test VMs.
            operation: Finalization operation to execute.
        """
        run_finalization_layer(label, operation, stage_reporter=stage_reporter)

    run_layer("management network", lambda: write_networkd_config(config))
    run_layer("resolver", lambda: write_resolv_conf(config))
    run_layer("management web server", lambda: write_nginx_management_server_name(config))
    run_layer("firewall", lambda: write_initial_firewall_config(config))
    run_layer("hostname", lambda: set_hostname(str(config["fqdn"])))
    run_layer("root password", lambda: set_password("root", str(config["root_password"])))
    run_layer("root SSH", lambda: configure_root_ssh(bool(config["root_ssh_enabled"])))
    try:
        bootstrap_user = read_env_file(ENV_PATH).get("ATLASO_BOOTSTRAP_ADMIN_USERNAME", "admin").strip('"') or "admin"
    except OSError as exc:
        raise OvfCustomizationError(
            "First-time initialization failed in the bootstrap administrator lookup layer."
        ) from exc
    run_layer(
        "bootstrap administrator password",
        lambda: set_password(bootstrap_user, str(config["admin_password"])),
    )
    # Every imported appliance regenerated its host identity before networking;
    # publish that exact public key for authenticated deployment automation.
    run_layer("SSH host key", publish_test_vm_ssh_host_key)
    if config["development_admin_ssh_public_key"]:
        run_layer(
            "development administrator SSH",
            lambda: configure_development_admin_ssh(
                bootstrap_user,
                str(config["development_admin_ssh_public_key"]),
            ),
        )
        # Despite this module's historical OVF name, it is also the guest-side
        # first-boot customizer for raw Workstation clones. Only the normal test
        # wrapper injects this development-key property; lifecycle and exported
        # appliances therefore never publish this convenience-channel value.
    if config["normal_test_vm"]:
        # The explicit normal-test marker survives password-only clone creation;
        # do not infer this trust boundary from optional SSH key provisioning.
        run_layer("test VM hostname", publish_test_vm_hostname)
    run_layer(
        "appliance environment",
        lambda: write_env_file(ENV_PATH, appliance_environment_values(config)),
    )
    run_layer(
        "development root CA staging and guest-info scrub",
        lambda: stage_development_root_ca(config),
    )
    run_layer("console credential refresh", restart_console)
    run_layer("host state durability", sync_customized_host_state)
    run_layer(
        "pending success marker",
        lambda: write_json_atomic(PENDING_MARKER_PATH, summary),
    )
    run_final_layer("OVF credential scrub", clear_ovf_environment)
    run_final_layer("applied marker", promote_pending_marker)
    if stage_reporter is not None:
        stage_reporter("vmware-customization-complete")
    return summary


def main(argv: list[str] | None = None) -> int:
    """Run the command-line entry point.

    Args:
        argv: Command-line arguments to parse, or ``None`` to use the process arguments.


    Returns:
        The main result.
    """
    parser = argparse.ArgumentParser(description="Apply Atlaso VMware OVF deployment properties.")
    parser.add_argument("--ovf-env-file", default="", help="Read OVF environment XML from a file instead of VMware Tools.")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the redacted summary without changing the host.")
    args = parser.parse_args(argv)

    if not args.dry_run and not args.ovf_env_file:
        try:
            virtualization_platform = detect_virtualization_platform()
        except OvfCustomizationError as exc:
            log(f"Portable artifact initialization failed closed: {exc}")
            return 2
        if virtualization_platform and virtualization_platform != "vmware":
            if MARKER_PATH.exists() or PENDING_MARKER_PATH.exists():
                log(
                    "Portable artifact initialization rejected VMware deployment state from a previously booted template."
                )
                return 2
            result = complete_no_ovf_initialization()
            if result == 0:
                log(
                    f"Portable {virtualization_platform} artifact initialized from image defaults; "
                    "VMware OVF properties do not apply."
                )
            return result

    if MARKER_PATH.exists() and not args.dry_run:
        scrub_applied_ovf_environment()
        complete_first_boot_initialization()
        log("VMware OVF customization already applied; leaving appliance state unchanged.")
        return 0
    if NO_OVF_MARKER_PATH.exists() and not args.dry_run:
        logged_unanswered = False
        while True:
            try:
                answered, content = try_read_ovf_environment_source(args.ovf_env_file)
            except OSError as exc:
                log(f"VMware non-OVF initialization could not inspect a replacement deployment: {type(exc).__name__}")
                return 2
            if answered:
                break
            if not logged_unanswered:
                log(
                    "VMware non-OVF initialization is retrying an inconclusive deployment-property read before "
                    "using image defaults."
                )
                logged_unanswered = True
            time.sleep(OVF_ENVIRONMENT_POLL_SECONDS)
        if not content.strip():
            complete_first_boot_initialization()
            log("VMware non-OVF initialization already completed; using image defaults.")
            return 0
        try:
            run_initialization_layer("non-OVF marker invalidation", invalidate_no_ovf_marker)
        except OvfCustomizationError as exc:
            log(f"VMware non-OVF initialization could not inspect a replacement deployment: {exc}")
            return 2
    if PENDING_MARKER_PATH.exists() and not args.dry_run:
        if pending_marker_matches_current_deployment(args.ovf_env_file):
            return recover_pending_customization()
        try:
            run_initialization_layer("pending success marker invalidation", invalidate_pending_marker)
        except OvfCustomizationError as exc:
            log(f"VMware OVF customization could not inspect a replacement deployment: {exc}")
            return 2

    if args.dry_run:
        try:
            properties = parse_ovf_environment(read_ovf_environment_source(args.ovf_env_file))
        except (OSError, ET.ParseError):
            log("VMware OVF customization failed validation: the OVF environment XML is unreadable.")
            return 2
        if not properties:
            log("No Atlaso VMware OVF properties found; image defaults remain unchanged.")
            return 0
        try:
            non_network = validate_non_network_properties(properties)
        except OvfCustomizationError as exc:
            log(f"VMware OVF customization failed validation: {exc}")
            return 2
    else:
        ovf_properties = wait_for_ovf_properties(args.ovf_env_file)
        if ovf_properties is None:
            return complete_no_ovf_initialization()
        properties, non_network = ovf_properties

    try:
        config = validate_properties(properties, non_network=non_network)
    except OvfManagementNetworkError as exc:
        if args.dry_run:
            log(f"VMware OVF customization failed validation: {exc}")
            return 2
        return wait_for_network_review(properties, str(exc))
    except OvfCustomizationError as exc:
        log(f"VMware OVF customization failed validation: {exc}")
        return 2

    try:
        summary = apply_customization(config, dry_run=args.dry_run)
    except OvfFinalizationError as exc:
        log(f"VMware OVF customization is retrying first-boot finalization: {exc}")
        return recover_pending_customization()
    except (OvfCustomizationError, OSError, subprocess.CalledProcessError) as exc:
        log(f"VMware OVF customization could not finish after validation: {exc}")
        if args.dry_run:
            return 2
        return wait_for_network_review(
            properties,
            "The management network validated, but first-time initialization did not finish. "
            "Resolve the condition reported in the customization log, then submit the network review to retry.",
        )

    if not args.dry_run:
        complete_first_boot_initialization()
    log("Applied Atlaso VMware OVF customization: " + json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
