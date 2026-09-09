"""Verify first-boot management source policy survives normal firewall rendering."""

import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.database import Base
from atlaso.app.models import PhysicalInterface, Setting, VlanInterface
from atlaso.app.seed import seed_initial_data
from atlaso.app.services.firewall import FIREWALL_SOURCE_GROUPS_SETTING_KEY


@pytest.mark.parametrize("raw", ["", "invalid", "[]", '{"groups":null}', '{"groups":[null]}'])
def test_console_preserves_unrecognized_source_policy(raw):
    """Leave malformed saved state to normal validation without blocking recovery.

    Args:
        raw: Unrecognized persisted policy.
    """
    from atlaso.app.services.firewall import update_bootstrap_management_ipv6

    assert update_bootstrap_management_ipv6(raw, "auto", "") == raw


@pytest.mark.parametrize(
    ("source", "ipv6", "ipv6_cidr", "expected"),
    [
        ("", False, "", ["0.0.0.0/0"]),
        ("10.42.0.0/16", False, "", ["10.42.0.0/16"]),
        ("", True, "", ["0.0.0.0/0", "::/0"]),
        ("172.25.80.0/20", True, "fd00:49::10/64", ["172.25.80.0/20", "fd00:49::/64"]),
    ],
)
def test_bootstrap_management_policy_survives_managed_render_and_reseed(
    monkeypatch, source, ipv6, ipv6_cidr, expected,
):
    """Preserve initial restrictions through both production renderers and restart.

    Args:
        monkeypatch: Isolated deployment environment configuration.
        source: Initial IPv4 management source restriction.
        ipv6: Whether deployment explicitly enables IPv6 management.
        ipv6_cidr: Static IPv6 management address, or empty for automatic addressing.
        expected: Source Group entries expected after initialization.
    """
    from atlaso.app.api.v1 import firewall_validation_payload
    from atlaso.app.ui import firewall_context

    monkeypatch.setenv("ATLASO_MANAGEMENT_SOURCE_CIDR", source)
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_IPV6_ENABLED", str(ipv6).lower())
    monkeypatch.setenv("ATLASO_APPLIANCE_MANAGEMENT_IPV6_CIDR", ipv6_cidr)
    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            seed_initial_data(db, include_examples=False, appliance_mode=True)
            row = db.execute(select(Setting).where(Setting.key == FIREWALL_SOURCE_GROUPS_SETTING_KEY)).scalar_one()
            state = json.loads(row.value)
            assert state["groups"][0]["entries"] == expected
            for preview in (firewall_validation_payload(db)[2], firewall_context(db, reconcile=False)["firewall_config_preview"]):
                management = [line for line in preview.splitlines() if 'comment "mgmt-console"' in line]
                assert len(management) == len(expected)
                assert all('iifname "eth0"' in line for line in management)
                for entry in expected:
                    assert any(f"saddr {entry}" in line for line in management)
            interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
            interface.role = "access"
            interface.access_management_ui_enabled = True
            db.commit()
            rows = firewall_context(db, reconcile=False)["firewall_managed_rule_rows"]
            assert next(row for row in rows if row["name"] == "management-ui-eth0")["source_group_id"] == "custom:bootstrap-management"
            for preview in (firewall_validation_payload(db)[2], firewall_context(db, reconcile=False)["firewall_config_preview"]):
                management = [line for line in preview.splitlines() if 'comment "management-ui-eth0"' in line]
                assert len(management) == len(expected)
                for entry in expected:
                    assert any(f"saddr {entry}" in line for line in management)
            interface.access_management_ui_enabled = False
            interface.mode = "trunk"
            db.add(VlanInterface(name="eth0.10", parent_interface="eth0", vlan_id=10,
                                 ip_cidr="172.25.81.1/20", enabled=True, role="access",
                                 access_management_ui_enabled=True))
            db.commit()
            rows = firewall_context(db, reconcile=False)["firewall_managed_rule_rows"]
            assert next(row for row in rows if row["name"] == "management-ui-eth0.10")["source_group_id"] == "custom:bootstrap-management"
            for preview in (firewall_validation_payload(db)[2], firewall_context(db, reconcile=False)["firewall_config_preview"]):
                management = [line for line in preview.splitlines() if 'comment "management-ui-eth0.10"' in line]
                assert len(management) == len(expected)
                for entry in expected:
                    assert any(f"saddr {entry}" in line for line in management)
            # A saved operator edit is authoritative on subsequent initialization.
            state["groups"][0]["entries"] = ["10.99.0.0/16"]
            row.value = json.dumps(state)
            db.commit()
            seed_initial_data(db, include_examples=False, appliance_mode=True)
            assert json.loads(row.value)["groups"][0]["entries"] == ["10.99.0.0/16"]
    finally:
        engine.dispose()
        get_settings.cache_clear()


@pytest.mark.parametrize("mode", ["existing", "saved", "factory"])
def test_bootstrap_management_seed_preserves_existing_state(monkeypatch, mode):
    """Do not migrate existing appliances, overwrite groups, or override reset policy.

    Args:
        monkeypatch: Isolated bootstrap settings.
        mode: Existing-install, retained-group, or factory-reset scenario.
    """
    monkeypatch.setenv("ATLASO_MANAGEMENT_SOURCE_CIDR", "10.42.0.0/16")
    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as db:
            if mode == "existing":
                seed_initial_data(db, include_examples=False)
            if mode == "saved":
                db.add(Setting(key=FIREWALL_SOURCE_GROUPS_SETTING_KEY, value='{"groups":[],"assignments":{}}'))
                db.commit()
            seed_initial_data(db, include_examples=False, appliance_mode=True, factory_defaults=mode == "factory")
            row = db.execute(select(Setting).where(Setting.key == FIREWALL_SOURCE_GROUPS_SETTING_KEY)).scalar_one_or_none()
            if mode == "saved":
                assert row is not None
                assert row.value == '{"groups":[],"assignments":{}}'
            else:
                assert row is None
    finally:
        engine.dispose()
        get_settings.cache_clear()


@pytest.mark.parametrize(
    ("mode", "cidr", "edited", "expected"),
    [
        ("auto", "", False, ["10.42.0.0/16", "::/0"]),
        ("static", "fd00:42::10/64", False, ["10.42.0.0/16", "fd00:42::/64"]),
        ("disabled", "", False, ["10.42.0.0/16"]),
        ("auto", "", True, ["10.99.0.0/16"]),
    ],
)
def test_console_updates_untouched_bootstrap_family_before_apply(client, monkeypatch, mode, cidr, edited, expected):
    """Console recovery stages the selected family while preserving operator changes.

    Args:
        client: Initialized application database fixture.
        monkeypatch: Replace privileged apply/recovery with observations.
        mode: Requested IPv6 mode.
        cidr: Requested static IPv6 address.
        edited: Whether an operator has replaced the seeded group entries.
        expected: Effective entries before Apply admission.
    """
    from atlaso.app import appliance_console
    from atlaso.app.database import SessionLocal

    initial = ["10.42.0.0/16", "fd00:123::/64"] if mode == "disabled" else ["10.42.0.0/16"]
    with SessionLocal() as db:
        db.add(Setting(key=FIREWALL_SOURCE_GROUPS_SETTING_KEY, value=json.dumps({
            "groups": [{"id": "custom:bootstrap-management", "entries": ["10.99.0.0/16"] if edited else initial,
                        "bootstrap_entries": initial}],
            "assignments": {"mgmt-console": "custom:bootstrap-management"},
        })))
        db.commit()

    def submit(_units, **_kwargs):
        with SessionLocal() as db:
            row = db.scalar(select(Setting).where(Setting.key == FIREWALL_SOURCE_GROUPS_SETTING_KEY))
            assert json.loads(row.value)["groups"][0]["entries"] == expected
        return "test-job"

    monkeypatch.setattr(appliance_console, "_submit_console_apply", submit)
    monkeypatch.setattr(appliance_console, "_recover_management_plane", lambda _stage: None)
    appliance_console.configure_management("dhcp", "", "", mode, cidr, "", "192.0.2.53")
