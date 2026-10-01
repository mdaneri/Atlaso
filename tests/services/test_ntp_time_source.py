"""Persisted time-source selection and NTP rendering contracts."""

from __future__ import annotations

import copy

import pytest
from sqlalchemy import create_engine, text

from atlaso.app.models import NtpSettings
from atlaso.app.services.ntp import (
    NTP_DEFAULT_UPSTREAM_SERVERS,
    NTP_DEFAULT_UPSTREAM_SOURCES_JSON,
    NTP_STAGED_CONFIG_PATH,
    ntp_settings_to_dict,
    ntp_time_mode,
    render_ntp_config,
    validate_ntp_state,
)


def _settings(**overrides: object) -> NtpSettings:
    values: dict[str, object] = {
        "id": 1,
        "enabled": False,
        "time_source": "ntp_client",
        "hostname": "ntp.atlaso.internal",
        "listen_interface": "",
        "listen_address": "",
        "port": 123,
        "upstream_servers": NTP_DEFAULT_UPSTREAM_SERVERS,
        "upstream_sources_json": NTP_DEFAULT_UPSTREAM_SOURCES_JSON,
        "allow_clients": "any",
        "nts_server_enabled": True,
        "nts_server_cert_path": "/etc/ssl/ntp.crt",
        "nts_server_key_path": "/etc/ssl/ntp.key",
        "nts_ke_port": 4460,
        "minsources": None,
        "config_path": NTP_STAGED_CONFIG_PATH,
    }
    values.update(overrides)
    return NtpSettings(**values)


def test_ntp_time_source_migration_defaults_existing_rows() -> None:
    """Legacy database rows gain a portable default without losing their state."""
    from atlaso.app.database import _reconcile_ntp_time_source_column

    engine = create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE ntp_settings (id INTEGER PRIMARY KEY, enabled BOOLEAN NOT NULL DEFAULT 0)")
            )
            connection.execute(text("INSERT INTO ntp_settings (id, enabled) VALUES (1, 0)"))

            _reconcile_ntp_time_source_column(connection)
            _reconcile_ntp_time_source_column(connection)

            row = connection.execute(
                text("SELECT enabled, time_source FROM ntp_settings WHERE id = 1")
            ).one()
            assert row == (0, "ntp_client")
    finally:
        engine.dispose()


def test_ntp_client_mode_uses_upstreams_without_server_listen_requirements() -> None:
    """NTP client mode validates and renders upstreams while blocking inbound service."""
    settings = _settings()

    assert ntp_time_mode(settings) == "ntp_client"
    assert validate_ntp_state(settings, set()) == []
    rendered = render_ntp_config(settings)
    assert "# Atlaso time mode: ntp_client" in rendered
    assert "restrict default ignore" in rendered
    assert "restrict source nomodify noquery" in rendered
    assert "interface ignore wildcard" not in rendered
    assert "interface listen" not in rendered
    assert "nts enable" not in rendered
    assert "server time.cloudflare.com iburst nts" in rendered


def test_ntp_client_mode_requires_at_least_one_valid_upstream() -> None:
    """Client mode rejects an empty source list even without server listeners."""
    settings = _settings(upstream_servers="", upstream_sources_json="[]")

    errors = validate_ntp_state(settings, set())

    assert "At least one NTP upstream server is required." in errors


def test_ntp_server_precedes_and_preserves_selected_time_source() -> None:
    """Enabled server mode wins while the selected source remains persisted."""
    settings = _settings(
        enabled=True,
        time_source="vmware_tools",
        listen_interface="eth0",
        listen_address="192.0.2.15",
    )

    assert ntp_time_mode(settings) == "ntp_server"
    state = ntp_settings_to_dict(settings)
    assert state["time_source"] == "vmware_tools"
    assert state["time_mode"] == "ntp_server"
    rendered = render_ntp_config(settings)
    assert "# Atlaso time mode: ntp_server" in rendered
    directives = rendered.splitlines()
    assert directives.index("interface listen all") < directives.index(
        "interface ignore wildcard"
    ) < directives.index("interface listen 192.0.2.15")
    assert "nts enable" in rendered
    assert "restrict default ignore" not in rendered


def test_vmware_tools_mode_omits_ntp_sources_and_service_listeners() -> None:
    """VMware Tools selection keeps NTPsec out of the time-source path."""
    settings = _settings(time_source="vmware_tools")

    assert ntp_time_mode(settings) == "vmware_tools"
    assert validate_ntp_state(settings, set()) == []
    rendered = render_ntp_config(settings)
    assert "# Atlaso time mode: vmware_tools" in rendered
    assert "restrict default ignore" in rendered
    assert "interface listen" not in rendered
    assert "server " not in rendered
    assert "nts enable" not in rendered


def test_settings_archive_round_trips_time_source_and_defaults_legacy_archives(client) -> None:
    """Archives preserve an explicit choice and supply the legacy client default."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        settings.time_source = "vmware_tools"
        db.commit()

        archive = export_settings_archive(db, actor="test")
        assert archive["data"]["ntp_settings"][0]["time_source"] == "vmware_tools"
        restore_settings_archive(db, archive)
        assert db.execute(select(NtpSettings)).scalar_one().time_source == "vmware_tools"

        legacy_archive = copy.deepcopy(archive)
        legacy_archive["data"]["ntp_settings"][0].pop("time_source")
        restore_settings_archive(db, legacy_archive)
        restored = db.execute(select(NtpSettings)).scalar_one()
        assert restored.time_source == "ntp_client"
        assert ntp_settings_to_dict(restored)["time_mode"] == "ntp_client"


def test_settings_archive_rejects_unknown_time_source(client) -> None:
    """Portable restore rejects a source mode outside the supported choices."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
        archive["data"]["ntp_settings"][0]["time_source"] = "host_clock"

        with pytest.raises(ValueError, match="Time source must be ntp_client or vmware_tools"):
            restore_settings_archive(db, archive)

        assert db.execute(select(NtpSettings)).scalar_one().time_source == "ntp_client"


def test_factory_seed_defaults_time_source_to_ntp_client(client) -> None:
    """Fresh factory desired state selects NTP client mode by default."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        settings = db.execute(select(NtpSettings)).scalar_one()
        assert settings.time_source == "ntp_client"
        assert ntp_settings_to_dict(settings)["time_mode"] == "ntp_client"


def test_archive_restores_inactive_nts_server_preference_without_ca(client) -> None:
    """Remembered server options cannot make a VMware client archive require CA."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        archive = export_settings_archive(db, actor="test")
        row = archive["data"]["ntp_settings"][0]
        row.update(enabled=False, time_source="vmware_tools", nts_server_enabled=True)
        archive["data"]["ca_settings"][0]["enabled"] = False
        restore_settings_archive(db, archive)
        restored = db.execute(select(NtpSettings)).scalar_one()
        assert restored.time_source == "vmware_tools"
        assert restored.nts_server_enabled is True
        assert ntp_time_mode(restored) == "vmware_tools"


@pytest.mark.parametrize("mode", ["ntp_client", "vmware_tools", "ntp_server"])
def test_rendered_mode_passes_privileged_helper_validation(mode, tmp_path, monkeypatch) -> None:
    """Exercise the renderer and host validator together for each supported mode."""
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper, "_ntpd_supports_nts", lambda: True)
    settings = _settings(
        enabled=mode == "ntp_server",
        time_source=mode if mode != "ntp_server" else "vmware_tools",
        listen_interface="eth0",
        listen_address="192.0.2.15",
        nts_server_enabled=False,
    )
    config = tmp_path / "ntp.conf"
    config.write_text(render_ntp_config(settings), encoding="utf-8")
    assert helper._ntpd_time_mode(config) == mode
    assert helper._ntpd_config_errors(config) == []
