"""Explicit single-host SSH penalty exemptions for native VCF backup probes."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

from atlaso.app.database import _reconcile_vcf_backup_probe_column
from atlaso.app.models import VcfBackupSettings
from atlaso.app.services.vcf_backups import (
    normalize_trusted_backup_sources,
    render_vcf_backup_probe_config,
)


@pytest.mark.parametrize("value", ["192.168.1.0/24", "0.0.0.0/0", "*", "::/0", "::", "224.0.0.1", "fe80::1%eth0", "192.0.2.1\nPerSourcePenalties no"])
def test_trusted_backup_sources_refuse_networks_wildcards_and_directives(value):
    """Never broaden an explicit host exception into a network or SSH directive.

    Args:
        value: Unsafe operator-entered exemption.
    """
    with pytest.raises(ValueError):
        normalize_trusted_backup_sources(value)


def test_trusted_backup_sources_are_canonical_unique_hosts_and_disabled_by_default():
    """Do not silently exempt clients during upgrade or receiver enablement."""
    assert normalize_trusted_backup_sources("192.0.2.41, 2001:db8::1/128, 192.0.2.41/32") == "192.0.2.41/32,2001:db8::1/128"
    settings = VcfBackupSettings(enabled=True, trusted_backup_sources="")
    assert render_vcf_backup_probe_config(settings) == ""
    settings.trusted_backup_sources = "192.0.2.41/32"
    assert render_vcf_backup_probe_config(settings) == "# Managed by Atlaso VCF Backups.\nPerSourcePenaltyExemptList 192.0.2.41/32\n"
    settings.enabled = False
    assert render_vcf_backup_probe_config(settings) == ""


def test_legacy_backup_database_upgrade_preserves_rows_without_exemptions():
    """The additive migration never adopts a native source as trusted automatically."""
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE vcf_backup_settings (id INTEGER PRIMARY KEY, enabled BOOLEAN)"))
        connection.execute(text("INSERT INTO vcf_backup_settings VALUES (1, 1)"))
        _reconcile_vcf_backup_probe_column(connection)
        _reconcile_vcf_backup_probe_column(connection)
        assert connection.execute(text("SELECT id, enabled, trusted_backup_sources FROM vcf_backup_settings")).one() == (1, 1, "")
    engine.dispose()


def test_backup_source_exemptions_round_trip_in_archives_and_legacy_archives_default_empty(client):
    """Preserve reviewed intent while legacy archives introduce no exemptions.

    Args:
        client: Fixture initializing an isolated appliance database.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    with SessionLocal() as db:
        settings = db.scalar(select(VcfBackupSettings))
        settings.trusted_backup_sources = "192.0.2.41/32"
        db.commit()
        archive = export_settings_archive(db, actor="admin")
        restore_settings_archive(db, archive)
        db.expire_all()
        assert db.scalar(select(VcfBackupSettings)).trusted_backup_sources == "192.0.2.41/32"
        archive["data"]["vcf_backup_settings"][0].pop("trusted_backup_sources")
        restore_settings_archive(db, archive)
        db.expire_all()
        assert db.scalar(select(VcfBackupSettings)).trusted_backup_sources == ""
