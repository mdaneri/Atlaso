"""Verify defaults, durable opt-out, legacy reconciliation and effective config."""

import copy

from sqlalchemy import create_engine, select, text

from atlaso.app.database import SessionLocal, _create_database_schema
from atlaso.app.models import DhcpSettings, DnsSettings
from atlaso.app.services.dnsmasq import render_dnsmasq_config


def test_legacy_database_reconciliation_defaults_enabled_and_preserves_opt_out():
    """Repeated startup adds the default without overwriting a persisted choice."""
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE dhcp_settings (id INTEGER PRIMARY KEY)"))
        connection.execute(text("INSERT INTO dhcp_settings (id) VALUES (1)"))
    _create_database_schema(engine)
    with engine.begin() as connection:
        assert connection.scalar(text("SELECT check_ip_availability FROM dhcp_settings")) == 1
        connection.execute(text("UPDATE dhcp_settings SET check_ip_availability = 0"))
    _create_database_schema(engine)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT check_ip_availability FROM dhcp_settings")) == 0
    engine.dispose()


def test_opt_out_changes_native_ping_option_without_changing_lease_uniqueness():
    """Emit one daemon-wide option only when DHCP checks are explicitly disabled."""
    values = dict(dns_settings=DnsSettings(enabled=False), dns_records=[], dhcp_scopes=[],
                  dhcp_reservations=[], dhcp_options=[], conditional_forwarders="")
    default = render_dnsmasq_config(dhcp_settings=DhcpSettings(enabled=True), **values)
    disabled = render_dnsmasq_config(dhcp_settings=DhcpSettings(enabled=True, check_ip_availability=False), **values)
    assert "no-ping" not in default
    assert disabled.splitlines().count("no-ping") == 1
    assert disabled.replace("no-ping\n", "") == default
    off = render_dnsmasq_config(dhcp_settings=DhcpSettings(enabled=False, check_ip_availability=False), **values)
    assert "no-ping" not in off


def test_archive_opt_out_round_trip_and_legacy_default(client):
    """Restore explicit false and preserve native checking for old archives."""
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        settings = db.scalar(select(DhcpSettings))
        assert settings.check_ip_availability is True
        settings.check_ip_availability = False
        db.commit()
        archive = export_settings_archive(db, actor="test")
        assert archive["data"]["dhcp_settings"][0]["check_ip_availability"] is False
        restore_settings_archive(db, archive)
        assert db.scalar(select(DhcpSettings)).check_ip_availability is False
        legacy = copy.deepcopy(archive)
        legacy["data"]["dhcp_settings"][0].pop("check_ip_availability")
        restore_settings_archive(db, legacy)
        assert db.scalar(select(DhcpSettings)).check_ip_availability is True
