"""Verify first-boot management source policy survives normal firewall rendering."""

import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.config import get_settings
from atlaso.app.database import Base
from atlaso.app.models import Setting
from atlaso.app.seed import seed_initial_data
from atlaso.app.services.firewall import FIREWALL_SOURCE_GROUPS_SETTING_KEY


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
