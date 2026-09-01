"""Verify Routes and WAN archive restore validation honors feature switches."""

from copy import deepcopy

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import NatRule, Route
from atlaso.app.services.routes_wan import (
    NAT_ENABLED_SETTING_KEY,
    ROUTING_ENABLED_SETTING_KEY,
)
from atlaso.app.services.settings_archive import (
    ROUTES_WAN_SETTING_KEYS,
    _archive_routes_wan_feature_state,
    export_settings_archive,
    restore_settings_archive,
)


def _set_routes_wan_setting(archive: dict, *, key: str, value: bool) -> None:
    """Set one routes-and-WAN setting row in an archive payload."""
    rows = archive["data"].setdefault("settings", [])
    for row in rows:
        if row.get("key") == key:
            row["value"] = "true" if value else "false"
            return
    rows.append({"key": key, "value": "true" if value else "false"})


def _disable_routes_and_nat_rows(archive: dict) -> None:
    """Disable routes and NAT rows and introduce unresolved references."""
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
    """Enable routes and NAT rows and introduce unresolved references."""
    for route in archive["data"].get("routes", []):
        route["enabled"] = True
        route["destination_cidr"] = "not-a-cidr"

    for rule in archive["data"].get("nat_rules", []):
        rule["enabled"] = True
        rule["source"] = "not-a-source-cidr"


def _make_enabled_rows_dormant_invalid(archive: dict) -> None:
    """Keep saved rows enabled while making globally gated values invalid."""
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
    """Globally dormant enabled rows remain restorable with their intent intact."""
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
    """Malformed routes fail archive preflight even when Routing is disabled."""
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=False)
    _set_routes_wan_setting(archive, key=NAT_ENABLED_SETTING_KEY, value=False)
    archive["data"]["routes"][0]["destination_cidr"] = "bad-cidr"

    with pytest.raises(ValueError, match="Routes and WAN state is invalid: Route bad-cidr is not a valid destination CIDR"):
        with SessionLocal() as db_session:
            restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_rejects_inactive_rows_when_features_on(client):
    """Dormant rows become invalid when routing and NAT are explicitly enabled."""
    with SessionLocal() as db_session:
        archive = deepcopy(export_settings_archive(db_session, actor="test"))
    _invalidate_routes_and_nat_rows(archive)
    _set_routes_wan_setting(archive, key=ROUTING_ENABLED_SETTING_KEY, value=True)
    _set_routes_wan_setting(archive, key=NAT_ENABLED_SETTING_KEY, value=True)

    with pytest.raises(ValueError, match="invalid"):
        with SessionLocal() as db_session:
            restore_settings_archive(db_session, archive)


def test_restore_routes_wan_archive_still_validates_management_default(client):
    """Routing off does not suppress validation of a protected management default."""
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


def test_restore_routes_wan_archive_rejects_dedicated_management_route(client):
    """Dedicated management interfaces are not ordinary lab-route targets."""
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
    """Legacy archives without rows infer off for disabled routes and NAT."""
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
