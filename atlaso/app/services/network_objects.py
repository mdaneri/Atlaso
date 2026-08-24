"""Implement Network Objects source-group behavior."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from atlaso.app.models import FirewallRule, NatRule
from atlaso.app.services.firewall import (
    FIREWALL_ANY_SOURCE_GROUP_ID,
    FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX,
    validate_firewall_source_groups,
)


def normalize_source_group(group: dict[str, Any]) -> dict[str, Any]:
    """Return one source group in the stable persisted and browser shape.

    Args:
        group: Candidate source-group state.

    Returns:
        Normalized source-group state.
    """
    raw_entries = group.get("entries") or group.get("sources") or []
    if isinstance(raw_entries, str):
        raw_entries = re.split(r"[\n,]+", raw_entries)
    entries = [str(item).strip() for item in raw_entries if str(item).strip()] or ["any"]
    normalized_entries: list[str] = []
    for entry in entries:
        if entry.lower() == "any":
            normalized_entries.append("any")
        elif entry.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
            target = entry[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX) :]
            normalized_entries.append(f"{FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX}{target}")
        else:
            normalized_entries.append(entry)
    group_id = str(group.get("id", ""))
    return {
        "id": group_id,
        "name": str(group.get("name", "")).strip() or group_id,
        "entries": normalized_entries,
        "sources": normalized_entries,
        "description": str(group.get("description") or "Custom source group."),
        "builtin": bool(group.get("builtin")),
    }


def source_group_id(name: str, groups: Iterable[dict[str, Any]]) -> str:
    """Create a stable unused custom source-group identifier.

    Args:
        name: Operator-facing source-group name.
        groups: Existing source groups.

    Returns:
        Stable custom identifier.
    """
    base = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-") or "group"
    existing = {str(group.get("id", "")) for group in groups}
    candidate = f"custom:{base}"
    index = 2
    while candidate in existing:
        candidate = f"custom:{base}-{index}"
        index += 1
    return candidate


def source_group_reference_target(value: str, groups: Iterable[dict[str, Any]]) -> str:
    """Resolve a persisted source-group reference to a stable identifier.

    Args:
        value: Candidate rule value or nested group entry.
        groups: Existing source groups.

    Returns:
        Referenced group identifier, or an empty string.
    """
    groups_by_id = {str(group.get("id", "")): group for group in groups}
    item = value.strip()
    if item in groups_by_id:
        return item
    if item.lower().startswith(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX):
        group_id = item[len(FIREWALL_SOURCE_GROUP_REFERENCE_PREFIX) :]
        return group_id if group_id in groups_by_id else ""
    if item.startswith("@"):
        target_name = item[1:].strip().lower()
        for group_id, group in groups_by_id.items():
            if str(group.get("name", "")).strip().lower() == target_name:
                return group_id
    return ""


def source_group_consumers(
    group_id: str,
    groups: list[dict[str, Any]],
    assignments: dict[str, str],
    firewall_rules: Iterable[FirewallRule],
    nat_rules: Iterable[NatRule],
) -> list[dict[str, str]]:
    """Return every saved consumer that prevents source-group deletion.

    Args:
        group_id: Stable identifier of the source group under review.
        groups: Existing source groups.
        assignments: Managed-rule source-group assignments.
        firewall_rules: Operator-defined Firewall rules.
        nat_rules: Saved NAT rules.

    Returns:
        Deterministically ordered consumer descriptions.
    """
    consumers: list[dict[str, str]] = []
    for group in groups:
        if str(group.get("id", "")) == group_id:
            continue
        for entry in group.get("entries") or group.get("sources") or []:
            if source_group_reference_target(str(entry), groups) == group_id:
                consumers.append(
                    {
                        "kind": "nested_group",
                        "label": f"Source Group: {group.get('name') or group.get('id')}",
                        "detail": "Nested entry",
                    }
                )
                break
    for rule in firewall_rules:
        for field, label in (("source", "Source"), ("destination", "Destination")):
            if source_group_reference_target(str(getattr(rule, field, "")), groups) == group_id:
                consumers.append(
                    {
                        "kind": "firewall_rule",
                        "label": f"Firewall rule: {rule.name}",
                        "detail": label,
                    }
                )
    for rule_name, assigned_group_id in assignments.items():
        if assigned_group_id == group_id:
            consumers.append(
                {
                    "kind": "managed_rule",
                    "label": f"Managed Firewall rule: {rule_name}",
                    "detail": "Source Group assignment",
                }
            )
    for rule in nat_rules:
        if source_group_reference_target(str(rule.source), groups) == group_id:
            consumers.append(
                {
                    "kind": "nat_rule",
                    "label": f"NAT rule: {rule.name}",
                    "detail": "Source restriction",
                }
            )
    return sorted(consumers, key=lambda item: (item["kind"], item["label"].lower(), item["detail"]))


def source_group_rows(
    groups: list[dict[str, Any]],
    assignments: dict[str, str],
    firewall_rules: Iterable[FirewallRule],
    nat_rules: Iterable[NatRule],
) -> list[dict[str, Any]]:
    """Build escaped-at-the-sink browser rows with validation and usage state.

    Args:
        groups: Existing source groups.
        assignments: Managed-rule source-group assignments.
        firewall_rules: Operator-defined Firewall rules.
        nat_rules: Saved NAT rules.

    Returns:
        Source-group browser rows.
    """
    firewall_rules = list(firewall_rules)
    nat_rules = list(nat_rules)
    all_errors = validate_firewall_source_groups(groups)
    rows: list[dict[str, Any]] = []
    for group in groups:
        group_id = str(group.get("id", ""))
        name = str(group.get("name") or group_id)
        entries = [str(entry) for entry in group.get("entries") or group.get("sources") or []]
        consumers = source_group_consumers(group_id, groups, assignments, firewall_rules, nat_rules)
        validation_errors = [error for error in all_errors if name.lower() in error.lower()]
        if group_id == FIREWALL_ANY_SOURCE_GROUP_ID:
            validation_errors.extend(error for error in all_errors if error.startswith("Any "))
        rows.append(
            {
                **normalize_source_group(group),
                "entry_count": len(entries),
                "entries_summary": ", ".join(entries),
                "consumer_count": len(consumers),
                "consumers": consumers,
                "usage_summary": ", ".join(item["label"] for item in consumers) or "Not in use",
                "validation_errors": list(dict.fromkeys(validation_errors)),
                "validation_state": "needs attention" if validation_errors else "valid",
            }
        )
    return rows
