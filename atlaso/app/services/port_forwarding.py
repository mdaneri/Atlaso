"""Own complete destination-translation validation and atomic desired-state writes."""

import hashlib
import json
import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_interface, ip_network
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app import models
from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.port_forward_schemas import PortForwardCreate, PortForwardStatus
from atlaso.app.services.esxi_pxe import esxi_pxe_boot_settings
from atlaso.app.services.firewall import (
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    firewall_interface_networks,
    firewall_source_group_state,
)
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.traffic_publishing import nat_targets, resolved_nat_source

MAX_PORT_FORWARDS = 256
MAX_MAPPED_PORTS = 65535
type ServiceListenerSettings = (models.KmsSettings | models.LdapSettings | models.OidcProviderSettings
                               | models.NtpSettings | models.VcfBackupSettings | models.VcfOfflineDepotSettings
                               | models.VcfPrivateRegistrySettings)


@dataclass(frozen=True)
class ListenerClaim:
    """Reserve one appliance-owned transport endpoint before destination NAT."""

    interface: str
    address: str
    protocol: str
    start: int
    end: int


def unicast_address(value: str, family: int) -> IPv4Address | IPv6Address:
    """Parse a literal same-family unicast address without scope or mapped aliases.

    Args:
        value: Operator-supplied literal address.
        family: Required IP version.
    """
    address = ip_address(value)
    if (address.version != family or "%" in value or address.is_loopback
            or address.is_link_local or address.is_multicast or address.is_unspecified
            or address.is_reserved or isinstance(address, IPv6Address) and address.ipv4_mapped):
        raise ValueError("Use a same-family ordinary unicast address; special-purpose listener or target addresses are excluded.")
    return address


def source_networks(source: str, family: int, groups: list[dict[str, Any]]) -> list[str]:
    """Expand a reviewed source boundary without silently dropping another family.

    Args:
        source: Any, explicit CIDRs, or one stable Source Group reference.
        family: Rule IP family.
        groups: Current shared Source Group definitions.
    """
    resolved = resolved_nat_source(source, groups)
    if resolved.lower() == "any":
        return []
    values = [item.strip() for item in re.split(r"[\n,]+", resolved) if item.strip()]
    if not values or len(values) > 128:
        raise ValueError("Choose Any or at most 128 same-family source networks.")
    networks = [ip_network(value, strict=False) for value in values]
    if any(network.version != family for network in networks):
        raise ValueError("Every Source Group member or source CIDR must match the rule's IP family.")
    return sorted({str(network) for network in networks})


def listener_claims(db: Session) -> list[ListenerClaim]:
    """Reserve stable protocol front doors and configured service listener ports.

    The browser/API, CA and public protocol routes share HTTP front doors. Keep
    their standard ports reserved even when optional publication is disabled so
    enabling a service cannot silently redirect its authentication to a target.

    Args:
        db: Desired-state transaction containing service listener configurations.
    """
    claims = [ListenerClaim("*", "*", "tcp", port, port) for port in (22, 80, 443)]
    specs = (
        (models.KmsSettings, "port", "tcp"),
        (models.LdapSettings, "port", "tcp"),
        (models.LdapSettings, "ldap_port", "tcp"),
        (models.OidcProviderSettings, "port", "tcp"),
        (models.NtpSettings, "port", "udp"),
        (models.NtpSettings, "nts_ke_port", "tcp"),
        (models.VcfBackupSettings, "port", "tcp"),
        (models.VcfOfflineDepotSettings, "port", "tcp"),
        (models.VcfPrivateRegistrySettings, "port", "tcp"),
    )
    for model, field, protocol in specs:
        row = cast(ServiceListenerSettings | None, db.scalar(select(model)))
        if row is None or not row.enabled:
            continue
        if isinstance(row, models.LdapSettings) and not (row.ldaps_enabled if field == "port" else row.ldap_enabled):
            continue
        if isinstance(row, models.NtpSettings) and field == "nts_ke_port" and not row.nts_server_enabled:
            continue
        port = int(getattr(row, field))
        for name in re.split(r"[,\s]+", row.listen_interface or ""):
            if name:
                claims.append(ListenerClaim(name, "*", protocol, port, port))
    # DNS/DHCP and Network Boot include socket-activated protocol endpoints;
    # their ports must never become a destination-translation editing shortcut.
    for protocol, ports in (("udp", (53, 67, 68, 69, 111, 547)), ("tcp", (53, 111, 2049, 20048))):
        claims.extend(ListenerClaim("*", "*", protocol, port, port) for port in ports)
    pxe = esxi_pxe_boot_settings(db)
    if pxe["enabled"]:
        for name in re.split(r"[,\s]+", pxe["listen_interface"]):
            if name:
                claims.append(ListenerClaim(name, "*", "tcp", pxe["http_port"], pxe["http_port"]))
    return claims


def validation_context(db: Session) -> dict[str, Any]:
    """Capture all listener and source prerequisites in the owning transaction.

    Args:
        db: Active desired-state transaction.
    """
    interfaces = list(db.scalars(select(models.PhysicalInterface)))
    vlans = list(db.scalars(select(models.VlanInterface)))
    row = db.scalar(select(models.Setting).where(models.Setting.key == FIREWALL_SOURCE_GROUPS_SETTING_KEY))
    groups = firewall_source_group_state(row.value if row else "", firewall_interface_networks(interfaces, vlans))["groups"]
    return {"targets": nat_targets(interfaces, vlans), "interfaces": [*interfaces, *vlans],
            "groups": groups, "claims": listener_claims(db)}


def validate_port_forward(rule: models.PortForward, peers: list[models.PortForward], context: dict[str, Any], *, require_binding: bool = True) -> list[str]:
    """Validate a complete candidate including overlap before any database commit.

    Args:
        rule: Complete candidate destination translation.
        peers: Saved rules inspected under the same write lock.
        context: Captured interfaces, Source Groups and owned listener claims.
        require_binding: False only for retained disabled archive relationships.
    """
    errors: list[str] = []
    try:
        PortForwardCreate(**{field: getattr(rule, field) for field in PortForwardCreate.model_fields
                             if field != "acknowledge_source_loss"}, acknowledge_source_loss=True)
        listener = unicast_address(rule.listener_address, rule.ip_family)
        target = unicast_address(rule.target_address, rule.ip_family)
        if require_binding or rule.enabled:
            source_networks(rule.source, rule.ip_family, context["groups"])
    except ValueError:
        return ["Review the name, family, source boundary, unicast addresses, protocol and equal-length port mapping."]
    if not require_binding and not rule.enabled:
        return []
    eligible = {item["name"]: item for item in context["targets"]}
    ingress = eligible.get(rule.ingress_interface)
    if require_binding:
        cidr = (ingress or {}).get("ip_cidr" if rule.ip_family == 4 else "ipv6_cidr", "")
        if not cidr or ip_interface(cidr).ip != listener:
            errors.append("Select an exact assigned listener on an enabled same-family access or route interface or VLAN.")
    for interface in context["interfaces"]:
        for cidr in (interface.ip_cidr, interface.ipv6_cidr):
            try:
                assigned = ip_interface(cidr or "")
            except ValueError:
                continue
            if target == assigned.ip:
                errors.append("A port-forward target cannot be an Atlaso appliance address.")
            if assigned.version != rule.ip_family:
                continue
            if interface.role == "management" and target in assigned.network:
                errors.append("Dedicated management networks cannot be port-forward targets.")
            if assigned.version == 4 and assigned.network.prefixlen < 31:
                if listener in (assigned.network.network_address, assigned.network.broadcast_address) or target in (assigned.network.network_address, assigned.network.broadcast_address):
                    errors.append("Listener and target addresses cannot be subnet network or broadcast addresses.")
    for claim in context["claims"]:
        if (claim.interface in ("*", rule.ingress_interface)
                and claim.address in ("*", str(listener)) and claim.protocol == rule.protocol
                and rule.external_port_start <= claim.end and claim.start <= rule.external_port_end):
            errors.append("The external mapping collides with an Atlaso-owned service or protocol listener.")
            break
    for peer in peers:
        if peer.id == rule.id and rule.id is not None or not peer.enabled or not rule.enabled:
            continue
        if (peer.ip_family == rule.ip_family and peer.listener_address == str(listener)
                and peer.protocol == rule.protocol and peer.external_port_start <= rule.external_port_end
                and rule.external_port_start <= peer.external_port_end):
            errors.append("Enabled port forwards cannot overlap on the same family, listener, protocol and external ports.")
            break
    if rule.enabled:
        mapped_ports = rule.external_port_end - rule.external_port_start + 1
        mapped_ports += sum(peer.external_port_end - peer.external_port_start + 1
                            for peer in peers if peer.enabled and (rule.id is None or peer.id != rule.id))
        if mapped_ports > MAX_MAPPED_PORTS:
            errors.append("Enabled port forwards may map at most 65535 external ports in total.")
    return list(dict.fromkeys(errors))


def save_port_forward(db: Session, payload: PortForwardCreate, *, actor: str, rule_id: int | None = None) -> models.PortForward:
    """Serialize validation, complete replacement and audit as one transaction.

    Args:
        db: Caller transaction, rolled back on every failure.
        payload: Complete reviewed request with explicit masquerade acknowledgement.
        actor: Authorized operator account name, never credential material.
        rule_id: Existing row to replace; None creates a default-off resource.
    """
    acquire_network_objects_write_lock(db)
    try:
        peers = list(db.scalars(select(models.PortForward)))
        current = db.get(models.PortForward, rule_id) if rule_id is not None else None
        if rule_id is not None and current is None:
            raise LookupError("Port forward does not exist.")
        if current is None and len(peers) >= MAX_PORT_FORWARDS:
            raise ValueError("At most 256 port forwards may be saved.")
        values = payload.model_dump(exclude={"acknowledge_source_loss"})
        values["listener_address"] = str(ip_address(payload.listener_address))
        values["target_address"] = str(ip_address(payload.target_address))
        candidate = models.PortForward(id=rule_id, **values)
        # Complete replacements must revalidate every binding even when disabled;
        # only archive restoration may retain unavailable disabled relationships.
        errors = validate_port_forward(candidate, peers, validation_context(db))
        if errors:
            raise ValueError(" ".join(errors))
        if current is None:
            current = candidate
            db.add(current)
        else:
            for key, value in values.items():
                setattr(current, key, value)
        current.restore_review_required = False
        db.flush()
        if not 1 <= current.id <= 0xFFFFFF:
            raise ValueError("Port-forward identity capacity is exhausted; contact the appliance maintainer.")
        db.add(models.AuditEvent(actor=actor, action="create_port_forward" if rule_id is None else "update_port_forward",
                                resource_type="port_forward", resource_id=str(current.id), success=True,
                                detail="Desired state only; global Appliance Apply required."))
        db.commit()
        return current
    except IntegrityError as exc:
        db.rollback()
        raise ValueError("A port forward with that name already exists.") from exc
    except Exception:
        db.rollback()
        raise


def snapshot_has_port_forwards(preview: str) -> bool:
    """Keep paired retirement after the last desired rule is removed.

    Args:
        preview: Previously applied, application-owned NAT snapshot.

    Malformed recorded sections retain the paired validation boundary instead of
    silently falling back to a source-NAT-only publication.
    """
    active = False
    for line in preview.splitlines():
        line = line.strip()
        if line.startswith("["):
            if active:
                return True
            active = line == "[port_forwards]"
        elif active and line.startswith("json="):
            try:
                records = json.loads(line[5:])
            except ValueError:
                return True
            return not isinstance(records, list) or bool(records)
    return active


def port_forward_firewall_projection(
    firewall: str, rules: list[models.PortForward], groups: list[dict[str, Any]], *, routing_enabled: bool,
) -> tuple[str, list[dict[str, Any]]]:
    """Project exact admission and read-only attribution from owning resources.

    Args:
        firewall: Reviewed base Firewall configuration before DNAT admission.
        rules: Desired port forwards, never independently editable Firewall rows.
        groups: Shared source boundaries captured for this preview.
        routing_enabled: Global forwarding gate.

    The privileged helper independently regenerates these lines from captured
    typed NAT input. It never trusts the preview as authorization for a mapping.
    """
    active = [rule for rule in rules if rule.enabled and routing_enabled]
    rows: list[dict[str, Any]] = []
    lines = [firewall.rstrip(), "# BEGIN ATLASO PORT FORWARD ADMISSION"]
    for rule in sorted(active, key=lambda item: (item.priority, item.id)):
        sources = source_networks(rule.source, rule.ip_family, groups)
        family = "ip" if rule.ip_family == 4 else "ip6"
        source = f'ct original {family} saddr {{ {", ".join(sources)} }} ' if sources else ""
        ports = str(rule.external_port_start) if rule.external_port_start == rule.external_port_end else f"{rule.external_port_start}-{rule.external_port_end}"
        for reply in (False, True):
            direction, interface = ("reply", "oifname") if reply else ("original", "iifname")
            match = (f"ct mark {hex(0xa7000000 | rule.id)} ct status dnat ct direction {direction} "
                     f"{interface} {json.dumps(rule.ingress_interface)} "
                     f"ct original {family} daddr {rule.listener_address} {source}"
                     f"meta l4proto {rule.protocol} ct original proto-dst {ports}")
            lines.append(f'add rule inet atlaso forward {match} accept comment "Atlaso port forward {rule.id}"')
        rows.append({
            "id": f"port-forward:{rule.id}", "name": f"Port forward: {rule.name}",
            "managed_state": "generated", "managed_status": "generated", "source_group_id": "",
            "source_group_name": rule.source, "source_group_sources": ", ".join(sources),
            "direction": "forward", "action": "accept", "protocol": rule.protocol,
            "destination_port": ports, "interface_name": rule.ingress_interface,
            "priority": rule.priority, "enabled": True,
            "description": (f"Port forward #{rule.id}: IPv{rule.ip_family} {rule.listener_address}:{ports} to "
                            f"{rule.target_address}:{rule.target_port_start}-{rule.target_port_end}; "
                            f"reply mode {rule.reply_mode}. Edit this resource in Traffic Publishing."),
        })
    if not active or not re.search(r"^table inet atlaso\s*\{", firewall, re.MULTILINE):
        return firewall, rows
    return "\n".join([*lines, "# END ATLASO PORT FORWARD ADMISSION"]) + "\n", rows


def render_port_forward_records(rules: list[models.PortForward], groups: list[dict[str, Any]]) -> str:
    """Serialize bounded typed helper input without accepting nftables expressions.

    Args:
        rules: Saved destination translation intent.
        groups: Source Groups captured with the reviewed snapshot.
    """
    records = []
    for rule in sorted(rules, key=lambda item: (item.priority, item.id or 0)):
        record = {field: getattr(rule, field) for field in PortForwardCreate.model_fields if field != "acknowledge_source_loss"}
        record["id"] = rule.id
        try:
            record["source_networks"] = source_networks(rule.source, rule.ip_family, groups)
        except ValueError:
            if rule.enabled:
                raise
            # Retain an unavailable archive reference verbatim. An empty expansion
            # cannot widen access because the independently checked row is disabled.
            record["source_networks"] = []
        records.append(record)
    return "\n[port_forwards]\njson=" + json.dumps(records, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"


def delete_port_forward(db: Session, rule_id: int, *, actor: str) -> None:
    """Remove desired intent and its audit in one shared-consumer transaction.

    Args:
        db: Caller transaction; rollback preserves the row on every failure.
        rule_id: Exact saved rule to remove.
        actor: Authorized Firewall writer.
    """
    acquire_network_objects_write_lock(db)
    try:
        row = db.get(models.PortForward, rule_id)
        if row is None:
            raise LookupError("Port forward does not exist.")
        db.delete(row)
        db.add(models.AuditEvent(actor=actor, action="delete_port_forward", resource_type="port_forward",
                                resource_id=str(rule_id), success=True,
                                detail="Desired state only; global Appliance Apply required."))
        db.commit()
    except Exception:
        db.rollback()
        raise


def set_port_forward_enabled(db: Session, rule_id: int, *, enabled: bool, actor: str) -> models.PortForward:
    """Toggle only Enabled after locking and rereading the complete saved intent.

    Args:
        db: Shared-consumer transaction.
        rule_id: Exact saved destination translation.
        enabled: Explicit desired state of the ordinary grid switch.
        actor: Authorized Firewall writer.
    """
    acquire_network_objects_write_lock(db)
    row = db.get(models.PortForward, rule_id)
    if row is None:
        db.rollback()
        raise LookupError("Port forward does not exist.")
    try:
        values = {field: getattr(row, field) for field in PortForwardCreate.model_fields if field != "acknowledge_source_loss"}
        values.update(enabled=enabled, acknowledge_source_loss=True)
        return save_port_forward(db, PortForwardCreate(**values), actor=actor, rule_id=rule_id)
    except Exception:
        # Schema construction can fail before the save helper owns rollback.
        db.rollback()
        raise


def observe_port_forwards(db: Session) -> list[PortForwardStatus]:
    """Read one bounded helper snapshot and compare it to saved desired intent.

    Args:
        db: Read-only desired-state session; no migration or host mutation is run.
    """
    result = SystemAdapter().port_forward_status()
    observation: dict[str, Any] = {"available": False, "rules": []}
    if result.returncode == 0 and len(result.stdout) <= 2_000_000:
        try:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, dict):
                observation = parsed
        except ValueError:
            pass
    rules = list(db.scalars(select(models.PortForward).order_by(models.PortForward.priority, models.PortForward.name).limit(MAX_PORT_FORWARDS)))
    routing = db.scalar(select(models.Setting.value).where(models.Setting.key == "routes_wan.routing_enabled"))
    return port_forward_status(rules, validation_context(db)["groups"],
                               routing_enabled=str(routing).lower() in {"true", "1", "on", "yes"}, observation=observation)


def port_forward_status(
    rules: list[models.PortForward], groups: list[dict[str, Any]],
    *, routing_enabled: bool, observation: dict[str, Any],
) -> list[PortForwardStatus]:
    """Compare current intent to bounded applied observations without host writes.

    Args:
        rules: Saved destination translations, including disabled intent.
        groups: Current source definitions used to detect pending boundary edits.
        routing_enabled: Desired global Routing gate.
        observation: Read-only helper result, never raw rules or handles.
    """
    observed_rows = observation.get("rules", [])
    if not isinstance(observed_rows, list) or len(observed_rows) > MAX_PORT_FORWARDS:
        observed_rows = []
        observation = {"available": False}
    applied = {row["id"]: row for row in observed_rows
               if isinstance(row, dict) and type(row.get("id")) is int}
    statuses: list[PortForwardStatus] = []
    for rule in rules[:MAX_PORT_FORWARDS]:
        runtime = applied.get(rule.id)
        status = PortForwardStatus(id=rule.id, state="pending", detail="Desired intent differs from the applied snapshot; submit appliance changes.")
        if observation.get("available") is not True:
            status.state = "degraded"
            status.detail = "Applied translation observations are unavailable; review runtime readiness."
        elif not rule.enabled and runtime is None:
            status.state = "disabled"
            status.detail = "This rule is disabled and has no applied translation."
        elif not routing_enabled and runtime is None:
            status.state = "suspended"
            status.detail = "Routing is disabled; this rule remains saved without active translation."
        elif rule.enabled and routing_enabled and runtime is not None:
            try:
                serialized = render_port_forward_records([rule], groups).split("json=", 1)[1]
                record = json.loads(serialized)[0]
                fingerprint = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            except ValueError:
                fingerprint = ""
            if fingerprint and runtime.get("snapshot_hash") == fingerprint:
                valid_counters = all(type(runtime.get(key)) is int and runtime[key] >= 0 for key in ("packets", "bytes"))
                status.state = "applied" if valid_counters and runtime.get("state") == "applied" else "degraded"
                status.detail = "Applied translation matches current intent." if status.state == "applied" else "Applied translation needs runtime or target-readiness review."
                if status.state == "degraded":
                    status.detail = {
                        "target_route_missing": "The target has no usable lab route. Review Routing & WAN and the target network; translation remains applied.",
                        "target_neighbor_failed": "The target or its next-hop neighbor failed resolution. Check its address, power, and network connection; translation remains applied.",
                        "target_observation_unavailable": "Target path observations are unavailable. Review appliance runtime readiness and test from a selected client.",
                    }.get(str(runtime.get("warning") or ""), status.detail)
                if valid_counters:
                    status.packets = runtime["packets"]
                    status.bytes = runtime["bytes"]
        statuses.append(status)
    return statuses
