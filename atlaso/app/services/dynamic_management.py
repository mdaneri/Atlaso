"""Admit native DHCP/IPv4LL management observations without widening service inventory."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.models import PhysicalInterface, Setting

PUBLICATION_PATH = Path("/run/atlaso-dynamic-management/publication.json")
BASELINES_KEY = "appliance_apply.baselines.v1"
MAX_AGE_SECONDS = 20


def snapshot_digest(value: Any) -> str:
    """Bind a publication to exact applied inputs, independent of JSON formatting.

    Args:
        value: Public applied snapshot or bootstrap identity.
    """
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def applied_snapshots(db: Session) -> dict[str, Any]:
    """Read baselines without initializing desired state or committing a transaction.

    Args:
        db: Caller-owned read or admitted writer transaction.
    """
    row = db.scalar(select(Setting).where(Setting.key == BASELINES_KEY).execution_options(populate_existing=True))
    value = json.loads(row.value) if row else {}
    return value if isinstance(value, dict) else {}


def native_management_addresses(row: dict[str, str], observation: dict[str, Any]) -> dict[str, Any]:
    """Require applied MAC, carrier, complete native provenance and a usable address.

    Args:
        row: Applied dedicated-management DHCPv4 identity and fallback policy.
        observation: Bounded native helper observation, never a caller-supplied probe target.
    """
    empty: dict[str, Any] = {"addresses": [], "apipa_addresses": [], "ipv4_state": "unknown"}
    if (row.get("role") != "management" or row.get("ipv4_method") != "dhcp"
            or row.get("admin_state") != "up" or row.get("mode") != "access" or not row.get("mac")):
        return empty
    links = [link for link in observation.get("links", []) if link.get("name") == row.get("name")]
    if not observation.get("complete") or len(links) != 1:
        return empty
    link = links[0]
    if (str(link.get("mac", "")).lower() != row["mac"].lower()
            or not link.get("ethernet") or not link.get("address_inventory_complete")):
        return empty
    if not link.get("up") or not link.get("carrier"):
        return {**empty, "ipv4_state": "no-carrier"}
    records = [item for item in link.get("addresses", []) if item.get("state") == "assigned"]
    leases, fallback, ipv6 = [], [], []
    for item in records:
        address = ip_address(item["address"])
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            continue
        if address.version == 4 and not address.is_link_local and (
                item.get("source") == "DHCPv4" or item.get("dhcp4_lease") is True):
            leases.append(str(address))
        elif (address.version == 4 and item.get("source") == "IPv4LL"
              and item.get("scope") == "link"
              and item.get("cidr") == f"{address}/16"
              and int(ip_address("169.254.1.0")) <= int(address) <= int(ip_address("169.254.254.255"))):
            fallback.append(str(address))
        elif address.version == 6 and not address.is_link_local and row.get("ipv6_enabled") == "true":
            if item.get("source") in {"DHCPv6", "NDisc"} or item.get("cidr") == row.get("ipv6_cidr"):
                ipv6.append(str(address))
    # Never select arbitrarily between conflicting/native duplicate leases.
    if len(set(leases)) > 1 or len(set(fallback)) > 1:
        return empty
    for candidate in leases + fallback + ipv6:
        owners = [other for other in observation.get("links", []) for item in other.get("addresses", [])
                  if item.get("address") == candidate and item.get("state") == "assigned"]
        if len(owners) != 1:
            return empty
    if leases:
        return {"addresses": sorted(set(leases + ipv6)), "apipa_addresses": [], "ipv4_state": "dhcp-ready"}
    if fallback and row.get("ipv4_link_local_fallback_enabled", "true") == "true":
        return {"addresses": sorted(set(fallback + ipv6)), "apipa_addresses": fallback, "ipv4_state": "apipa"}
    return {"addresses": sorted(set(ipv6)), "apipa_addresses": [], "ipv4_state": "waiting-dhcp"}


def read_publication(db: Session, *, max_age_seconds: int = MAX_AGE_SECONDS) -> dict[str, Any]:
    """Read only a fresh root-published, applied-snapshot-bound management receipt.

    Args:
        db: Read-only database transaction authorizing the applied identity.
        max_age_seconds: Bounded handoff callers may retain proof while native ownership is rechecked.
    """
    try:
        parent_metadata = PUBLICATION_PATH.parent.lstat()
        if (not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != 0
                or parent_metadata.st_mode & 0o022):
            return {}
        descriptor = os.open(PUBLICATION_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 16384
                    or getattr(metadata, "st_uid", -1) != 0 or metadata.st_mode & 0o022):
                return {}
            value = json.loads(stream.read(16385))
        now = datetime.now(timezone.utc)
        age = (now - datetime.fromisoformat(value["observed_at"])).total_seconds()
        if not 0 <= age <= min(max_age_seconds, 120) or value.get("phase") != "ready":
            return {}
        baselines = applied_snapshots(db)
        if value.get("network_digest") != snapshot_digest(baselines.get("network")):
            return {}
        if value.get("settings_digest") != snapshot_digest(baselines.get("appliance_settings")):
            return {}
        identity = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == value["interface"]))
        if identity is None or identity.mac_address.lower() != value["mac"].lower():
            return {}
        addresses = [str(ip_address(address)) for address in value["addresses"]]
        apipa = [str(ip_address(address)) for address in value["apipa_addresses"]]
        if not addresses or not set(apipa) <= set(addresses):
            return {}
        for address in addresses:
            parsed = ip_address(address)
            if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
                return {}
            if parsed.is_link_local and (parsed.version != 4 or address not in apipa
                    or not int(ip_address("169.254.1.0")) <= int(parsed) <= int(ip_address("169.254.254.255"))):
                return {}
        return {**value, "addresses": addresses, "apipa_addresses": apipa}
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return {}


def publication_bindings(db: Session) -> list[dict[str, str]]:
    """Project controlled management endpoints without adding general service targets.

    Args:
        db: Session used to verify the publication's applied identity.
    """
    value = read_publication(db)
    return [{"interface": value["interface"], "role": "management", "address": address,
             "management_ui": "true", "local_setup": "true" if address in value["apipa_addresses"] else "false"}
            for address in value.get("addresses", [])]
