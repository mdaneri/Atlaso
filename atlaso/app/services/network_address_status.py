"""Retain bounded native address evidence separately from network desired state."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.models import PhysicalInterface, Setting, VlanInterface

STATUS_KEY = "network.address_status.v1"
MAX_RECORDS = 256


def _event_after_identity_change(event: dict[str, Any], identity_since: str) -> bool:
    """Reject unbound journal history predating a detected link replacement.

    Args:
        event: Name-only native conflict event without a stable hardware identity.
        identity_since: First observation of the replacement identity, retained across polls.
    """
    if not identity_since:
        return True
    try:
        return datetime.fromisoformat(event["detected_at"]) > datetime.fromisoformat(identity_since)
    except (KeyError, TypeError, ValueError):
        return False


def read_status(db: Session) -> dict[str, Any]:
    """Read operational evidence without reconciling desired state or touching the host.

    Args:
        db: Session used only to read the bounded evidence record.
    """
    saved = db.scalar(select(Setting).where(Setting.key == STATUS_KEY))
    try:
        value = json.loads(saved.value) if saved else {}
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def project_status(
    observation: dict[str, Any], previous: dict[str, Any], resources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Associate observations with stable resource identities and retain failed attempts.

    Args:
        observation: Sanitized helper response with native addresses and conflict events.
        previous: Prior bounded observation, independent of desired/applied baselines.
        resources: Current resource identities and desired addresses, never arbitrary probe targets.
    """
    now = observation.get("observed_at", "")
    links = {item["name"]: item for item in observation.get("links", [])}
    result: dict[str, Any] = {"observed_at": now, "rows": {}}
    for resource in resources[:MAX_RECORDS]:
        key = resource["key"]
        link = links.get(resource["name"], {})
        identity = resource["identity"]
        if resource.get("physical") and link.get("mac") != identity:
            link = {}
        elif not resource.get("physical"):
            parent = links.get(resource.get("parent", ""), {})
            expected = f"{parent.get('mac', '')}:{link.get('vlan_id', '')}"
            parent_matches = link.get("parent") == resource.get("parent") or (
                link.get("parent_index") and link.get("parent_index") == parent.get("ifindex"))
            if link.get("kind") != "vlan" or expected != identity or not parent_matches:
                link = {}
        previous_rows = previous.get("rows", {})
        prior = previous_rows.get(key, {})
        same_name: dict[str, Any] = next((row for row in previous_rows.values()
                                          if row.get("name") == resource["name"]), {})
        identity_since = prior.get("identity_since", same_name.get("identity_since", ""))
        if any(row and row.get("identity") != identity for row in (prior, same_name)):
            identity_since = now
        if prior.get("identity") != identity:
            prior = {}
        records = link.get("addresses", [])
        assigned = [row["address"] for row in records if row["state"] == "assigned"]
        dhcp4_addresses = [row["address"] for row in records
                           if row["state"] == "assigned" and row.get("source") == "DHCPv4"]
        lease_evidence = bool(link and observation.get("complete"))
        events = [item for item in observation.get("conflicts", []) if item["name"] == resource["name"]
                  and (item.get("identity") == identity or (
                      link and not item.get("identity") and _event_after_identity_change(item, identity_since)))]
        events.extend({"name": resource["name"], "address": item["address"], "detected_at": now, "mac": ""}
                      for item in records if item["state"] == "conflict")
        last_conflict = prior.get("last_conflict")
        conflict_resolved = bool(prior.get("conflict_resolved"))
        for event in events:
            if not last_conflict or event["detected_at"] > last_conflict["detected_at"]:
                last_conflict = event
                conflict_resolved = False
        state = "unknown"
        detail = "Unable to check: native evidence is unavailable."
        if link and observation.get("complete"):
            if not link.get("up") or not link.get("carrier"):
                detail = "Unable to check: link is down or has no carrier."
            elif any(item["state"] == "conflict" for item in records):
                state, detail = "conflict", "IP conflict on a currently configured address."
            elif link.get("configuring") or any(item["state"] == "checking" for item in records):
                state, detail = "checking", "Native address detection is in progress."
            elif assigned and link.get("configured"):
                state, detail = "assigned", "Active addresses observed; this is not proof of global uniqueness."
            else:
                detail = "Unable to check: no usable address has been observed."
        if last_conflict:
            address = last_conflict["address"]
            declined_offer = resource.get("dhcp4") and ip_address(address).version == 4
            # A lease already present when the decline is first observed cannot
            # prove recovery. Require a newly appearing lease after that evidence.
            prior_leases = prior.get("dhcp4_addresses")
            replacement_lease = bool(
                lease_evidence and link.get("configured") and isinstance(prior_leases, list)
                and _event_after_identity_change({"detected_at": prior.get("observed_at")},
                                                 last_conflict["detected_at"])
                and any(address not in prior_leases for address in dhcp4_addresses))
            if replacement_lease and declined_offer:
                conflict_resolved = True
            elif (not declined_offer and address in assigned and resource["checking"]
                  and link.get("configured") and observation.get("complete")):
                conflict_resolved = True
            if not conflict_resolved and ((address in resource["desired"] and address not in assigned) or declined_offer):
                state = "conflict"
                detail = f"IP conflict: {address}. The failed attempted address is not active."
                if assigned:
                    detail += " Other active addresses are shown separately; the working path may have been restored."
            elif address in assigned and resource["checking"] and observation.get("complete"):
                detail += f" Previous conflict for {address}; the address is now assigned."
            else:
                detail += f" Last failed attempt: {address}."
        if not resource["checking"]:
            detail += " IPv4 checking is disabled in desired state; Apply is required to activate edits. IPv6 DAD is retained."
        result["rows"][key] = {
            "dhcp4_addresses": dhcp4_addresses if lease_evidence else None,
            "identity": identity, "identity_since": identity_since,
            "name": resource["name"], "state": state, "detail": detail,
            "active_addresses": assigned, "last_conflict": last_conflict, "conflict_resolved": conflict_resolved, "observed_at": now,
        }
    return result


def refresh_status(db: Session) -> None:
    """Collect native outcomes for boot, DHCP and Apply events without issuing probes.

    Args:
        db: Worker-owned session; only the operational evidence setting is committed.
    """
    adapter = SystemAdapter()
    if adapter.dry_run:
        return
    response = adapter.read_network_address_status()
    try:
        observation = json.loads(response.stdout) if not response.returncode else {}
    except ValueError:
        observation = {}
    if not isinstance(observation, dict):
        observation = {}
    observation.setdefault("observed_at", datetime.now(timezone.utc).isoformat())
    resources = []
    physical = list(db.scalars(select(PhysicalInterface)))
    parents = {row.name: row for row in physical}
    for kind, rows in (("physical", physical), ("vlan", list(db.scalars(select(VlanInterface))))):
        for row in rows:
            if isinstance(row, PhysicalInterface):
                identity = row.mac_address.lower()
            else:
                parent = parents.get(row.parent_interface)
                identity = f"{parent.mac_address.lower() if parent else ''}:{row.vlan_id}"
            desired = []
            for cidr in (row.ip_cidr, row.ipv6_cidr):
                if not cidr:
                    continue
                try:
                    desired.append(str(ip_interface(cidr).ip))
                except (ValueError, TypeError):
                    continue
            resources.append({"key": f"{kind}:{row.id}", "name": row.name, "identity": identity,
                              "desired": desired, "physical": kind == "physical",
                              "dhcp4": isinstance(row, PhysicalInterface) and row.ipv4_method == "dhcp",
                              "parent": row.parent_interface if isinstance(row, VlanInterface) else "",
                              "checking": row.check_duplicate_ip_addresses is not False})
    projection = project_status(observation, read_status(db), resources)
    saved = db.scalar(select(Setting).where(Setting.key == STATUS_KEY))
    if saved is None:
        saved = Setting(key=STATUS_KEY, value="{}")
        db.add(saved)
    saved.value = json.dumps(projection, sort_keys=True)
    db.commit()


def row_status(saved: dict[str, Any], kind: str, record_id: int) -> dict[str, Any]:
    """Expose a cached row with explicit stale/unavailable state.

    Args:
        saved: Read-only evidence snapshot.
        kind: Physical or VLAN resource kind.
        record_id: Stable database row identity.
    """
    row = dict(saved.get("rows", {}).get(f"{kind}:{record_id}", {}))
    try:
        stale = (datetime.now(timezone.utc) - datetime.fromisoformat(row["observed_at"])).total_seconds() > 30
    except (KeyError, TypeError, ValueError):
        stale = True
    if stale:
        row["state"] = "unknown"
        row["detail"] = "Live address evidence is unavailable or stale. " + row.get("detail", "")
    return row
