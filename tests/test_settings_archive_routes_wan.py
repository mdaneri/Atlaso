"""Verify Routes and WAN archive restore validation honors feature switches."""

from copy import deepcopy

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import NatRule, Route
from atlaso.app.services.routes_wan import (
    NAT_ENABLED_SETTING_KEY,
    ROUTING_ENABLED_SETTING_KEY,
    WAN_SIMULATION_ENABLED_SETTING_KEY,
)
from atlaso.app.services.settings_archive import (
    ROUTES_WAN_SETTING_KEYS,
    _archive_routes_wan_feature_state,
    export_settings_archive,
    restore_settings_archive,
)


def _set_routes_wan_setting(archive: dict, *, key: str, value: bool) -> None:
    """Set one routes-and-WAN setting row in an archive payload.

    Args:
        archive: Mutable settings archive payload.
        key: Safe Routes and WAN setting key to update.
        value: Boolean value to persist in the archive.
    """
    rows = archive["data"].setdefault("settings", [])
    for row in rows:
        if row.get("key") == key:
            row["value"] = "true" if value else "false"
            return
    rows.append({"key": key, "value": "true" if value else "false"})


def _disable_routes_and_nat_rows(archive: dict) -> None:
    """Disable routes and NAT rows and introduce unresolved references.

    Args:
        archive: Mutable settings archive payload.
    """
    for route in archive["data"].get("routes", []):
        route["enabled"] = False
        route["interface_name"] = "missing-route-target"

    for rule in archive["data"].get("nat_rules", []):
        rule["enabled"] = False
        rule["outbound_interface"] = "missing-nat-target"

    for rule in archive["data"].get("routing_rules", []):
        rule["enabled"] = False
        rule["source_interface"] = "missing-source"
        rule["destination_interface"] = "missing-destination"


def _invalidate_routes_and_nat_rows(archive: dict) -> None:
    """Enable routes and NAT rows and introduce unresolved references.

    Args:
        archive: Mutable settings archive payload.
    """
    for route in archive["data"].get("routes", []):
        route["enabled"] = True
        route["destination_cidr"] = "not-a-cidr"

    for rule in archive["data"].get("nat_rules", []):
        rule["enabled"] = True
        rule["source"] = "not-a-source-cidr"


def _make_enabled_rows_dormant_invalid(archive: dict) -> None:
    """Keep saved rows enabled while making globally gated values invalid.

    Args:
        archive: Mutable settings archive payload.
    """
    for route in archive["data"].get("routes", []):
        route["enabled"] = True
        route["gateway"] = "203.0.113.1"

    for rule in archive["data"].get("nat_rules", []):
        rule["enabled"] = True
        rule["outbound_interface"] = "missing-nat-target"

    for rule in archive["data"].get("routing_rules", []):
        rule["enabled"] = True
        rule["source_interface"] = "missing-source"
        rule["destination_interface"] = "missing-destination"


def test_restore_routes_wan_archive_preserves_inactive_rows_when_features_off(client):
    """Globally dormant enabled rows remain restorable with their intent intact.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    _make_enabled_rows_dormant_invalid(archive)
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)
    _set_routes_wan_setting(archive, key=NAT_ENABLED_SETTING_KEY, value=False)

    with SessionLocal() as db_session:
        counts = restore_settings_archive(db_session, archive)
        assert counts["routes"] == len(archive["data"].get("routes", []))
        assert counts["nat_rules"] == len(archive["data"].get("nat_rules", []))
        assert counts["routing_rules"] == len(archive["data"].get("routing_rules", []))

    with SessionLocal() as db_session:
        assert db_session.execute(
            select(Route).where(Route.gateway == "203.0.113.1")
        ).scalar_one_or_none()
        assert db_session.execute(
            select(NatRule).where(NatRule.outbound_interface == "missing-nat-target")
        ).scalar_one_or_none()


def test_restore_routes_wan_archive_rejects_invalid_route_destination_when_routing_off(client):
    """Malformed routes fail archive preflight even when Routing is disabled.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)
    _set_routes_wan_setting(archive, key=NAT_ENABLED_SETTING_KEY, value=False)
    archive["data"]["routes"][0]["destination_cidr"] = "bad-cidr"

    with pytest.raises(ValueError, match="Routes and WAN state is invalid: Route bad-cidr is not a valid destination CIDR"):
        with SessionLocal() as db_session:
            restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_rejects_missing_dormant_wan_policy(client):
    """Dormant WAN assignments retain referential integrity during restore.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)
    archive["data"]["settings"] = [
        row
        for row in archive["data"]["settings"]
        if row.get("key") != WAN_SIMULATION_ENABLED_SETTING_KEY
    ]
    archive["data"]["settings"].append(
        {"key": WAN_SIMULATION_ENABLED_SETTING_KEY, "value": "false"}
    )
    archive["data"]["routes"][0]["wan_policy_name"] = "Missing dormant policy"

    with pytest.raises(ValueError, match="references an unknown WAN policy"):
        with SessionLocal() as db_session:
            restore_settings_archive(db_session, archive)


def test_restore_wan_only_archive_ignores_unassigned_route_target(client):
    """WAN-only restore does not activate a route without a policy assignment.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    route = archive["data"]["routes"][0]
    route["enabled"] = True
    route["interface_name"] = "missing-unassigned-target"
    route["wan_policy_name"] = None
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)
    _set_routes_wan_setting(
        archive,
        key=WAN_SIMULATION_ENABLED_SETTING_KEY,
        value=True,
    )

    with SessionLocal() as db_session:
        restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_rejects_inactive_rows_when_features_on(client):
    """Dormant rows become invalid when routing and NAT are explicitly enabled.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    _invalidate_routes_and_nat_rows(archive)
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=True)
    _set_routes_wan_setting(archive, key=NAT_ENABLED_SETTING_KEY, value=True)

    with pytest.raises(ValueError, match="invalid"):
        with SessionLocal() as db_session:
            restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_still_validates_management_default(client):
    """Routing off does not suppress validation of a protected management default.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    flagged_access = next(
        row
        for row in archive["data"]["physical_interfaces"]
        if row.get("role") == "access" and row.get("ip_cidr")
    )
    flagged_access["access_management_ui_enabled"] = True
    archive["data"]["routes"].append(
        {
            "destination_cidr": "0.0.0.0/0",
            "gateway": "203.0.113.1",
            "interface_name": flagged_access["name"],
            "metric": 100,
            "enabled": True,
            "wan_mode": "interface",
            "wan_policy_name": None,
        }
    )
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)
    _set_routes_wan_setting(archive, key=NAT_ENABLED_SETTING_KEY, value=False)

    with pytest.raises(ValueError, match="not on-link"):
        with SessionLocal() as db_session:
            restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_ignores_inactive_physical_management_default(client):
    """Routing-off preflight leaves an inactive flagged physical default dormant.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    flagged_access = next(
        row
        for row in archive["data"]["physical_interfaces"]
        if row.get("role") == "access" and row.get("ip_cidr")
    )
    flagged_access["access_management_ui_enabled"] = True
    flagged_access["admin_state"] = "down"
    archive["data"]["routes"].append(
        {
            "destination_cidr": "0.0.0.0/0",
            "gateway": "203.0.113.1",
            "interface_name": flagged_access["name"],
            "metric": 100,
            "enabled": True,
            "wan_mode": "interface",
            "wan_policy_name": None,
        }
    )
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)

    with SessionLocal() as db_session:
        restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_ignores_parent_down_vlan_management_default(client):
    """Routing-off preflight leaves a flagged VLAN default dormant with its parent down.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    flagged_vlan = next(
        row
        for row in archive["data"]["vlan_interfaces"]
        if row.get("enabled") and row.get("ip_cidr")
    )
    parent = next(
        row
        for row in archive["data"]["physical_interfaces"]
        if row["name"] == flagged_vlan["parent_interface"]
    )
    flagged_vlan["role"] = "access"
    flagged_vlan["access_management_ui_enabled"] = True
    parent["admin_state"] = "down"
    archive["data"]["routes"].append(
        {
            "destination_cidr": "0.0.0.0/0",
            "gateway": "203.0.113.1",
            "interface_name": flagged_vlan["name"],
            "metric": 100,
            "enabled": True,
            "wan_mode": "interface",
            "wan_policy_name": None,
        }
    )
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)

    with SessionLocal() as db_session:
        restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_rejects_dedicated_management_route(client):
    """Dedicated management interfaces are not ordinary lab-route targets.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    management_interface = next(
        row["name"]
        for row in archive["data"]["physical_interfaces"]
        if row.get("role") == "management"
    )
    archive["data"]["routes"].append(
        {
            "destination_cidr": "10.123.0.0/24",
            "gateway": None,
            "interface_name": management_interface,
            "metric": 100,
            "enabled": True,
            "wan_mode": "interface",
            "wan_policy_name": None,
        }
    )
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=True)

    with pytest.raises(ValueError, match="ineligible target interface"):
        with SessionLocal() as db_session:
            restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_legacy_inference_turns_features_off_for_dormant_rows(
    client,
):
    """Legacy archives without rows infer off for disabled routes and NAT.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    archive["data"]["settings"] = [
        row
        for row in archive["data"].get("settings", [])
        if row.get("key") not in ROUTES_WAN_SETTING_KEYS
    ]

    _disable_routes_and_nat_rows(archive)
    feature_state = _archive_routes_wan_feature_state(archive["data"])

    assert feature_state.routing_enabled is False
    assert feature_state.nat_enabled is False
    with SessionLocal() as db_session:
        restore_settings_archive(db_session, archive)


def test_routes_wan_archive_legacy_inference_preserves_admin_down_topology(
    client,
):
    """Infer Routing for an addressed route topology with an admin-down target.

    Args:
        client: HTTP test client that initializes the archive fixture state.
    """
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    archive["data"]["settings"] = [
        row
        for row in archive["data"].get("settings", [])
        if row.get("key") not in ROUTES_WAN_SETTING_KEYS
    ]
    _disable_routes_and_nat_rows(archive)
    route_targets = archive["data"]["physical_interfaces"][:2]
    assert len(route_targets) == 2
    for index, interface in enumerate(route_targets, start=1):
        interface.update(
            {
                "role": "route",
                "mode": "access",
                "admin_state": "down" if index == 1 else "up",
                "oper_state": "up",
                "ip_cidr": f"192.0.{index}.10/24",
                "ipv6_cidr": None,
            }
        )

    feature_state = _archive_routes_wan_feature_state(archive["data"])

    assert feature_state.routing_enabled is True
