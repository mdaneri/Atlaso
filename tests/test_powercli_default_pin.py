"""Verify PowerCLI defaults advance without rewriting operator pins."""

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

LEGACY_PIN = "9.1.0.25380678"
CURRENT_PIN = "9.1.1.25718932"
FUTURE_PIN = "9.2.0.123"


@pytest.mark.parametrize(
    ("pin", "policy", "repo", "enabled", "audit_action", "tracks_default"),
    [
        (LEGACY_PIN, "pinned", "PSGallery", True, "", True),
        (CURRENT_PIN, "pinned", "PSGallery", True, "", True),
        ("8.0.0", "pinned", "PSGallery", True, "", False),
        ("", "latest", "PSGallery", True, "", False),
        (LEGACY_PIN, "pinned", "Mirror", True, "", False),
        (LEGACY_PIN, "pinned", "PSGallery", False, "", False),
        (LEGACY_PIN, "pinned", "PSGallery", True, "create_managed_package", False),
        (LEGACY_PIN, "pinned", "PSGallery", True, "update_managed_package", False),
    ],
)
def test_legacy_powercli_pin_upgrade(monkeypatch, pin, policy, repo, enabled, audit_action, tracks_default):
    """Adopt untouched historical defaults once, then follow future release pins.

    Args:
        monkeypatch: Fixture simulating the next packaged PowerCLI baseline.
        pin: Saved target version before the schema upgrade.
        policy: Saved package policy.
        repo: Name of the bound repository.
        enabled: Saved package enablement.
        audit_action: Recorded operator action for the module, if any.
        tracks_default: Whether this row is eligible to follow the release pin.
    """
    from atlaso.app import seed
    from atlaso.app.database import _create_database_schema
    from atlaso.app.models import AuditEvent, ManagedPackage, UpdateSource

    engine = create_engine("sqlite:///:memory:")
    try:
        with Session(engine) as db:
            _create_database_schema(engine)
            source = UpdateSource(kind="powershell", name=repo, url="https://www.powershellgallery.com/api/v2")
            package = ManagedPackage(
                ecosystem="powershell", name="VCF.PowerCLI", source=source, policy=policy,
                target_version=pin, enabled=enabled,
            )
            db.add(package)
            db.flush()
            source_id = source.id
            if audit_action:
                db.add(AuditEvent(
                    actor="admin", action=audit_action, resource_type="managed_package",
                    resource_id=str(package.id),
                ))
            db.commit()
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE managed_packages DROP COLUMN atlaso_default_version"))

        _create_database_schema(engine)
        with Session(engine) as db:
            saved = db.scalars(select(ManagedPackage)).one()
            assert saved.target_version == (seed.DEFAULT_POWERCLI_VERSION if tracks_default else pin)
            assert saved.atlaso_default_version == (seed.DEFAULT_POWERCLI_VERSION if tracks_default else "")
            assert (saved.policy, saved.source_id, saved.enabled) == (policy, source_id, enabled)

        monkeypatch.setattr(seed, "DEFAULT_POWERCLI_VERSION", FUTURE_PIN)
        _create_database_schema(engine)
        monkeypatch.setattr(seed, "DEFAULT_POWERCLI_VERSION", CURRENT_PIN)
        _create_database_schema(engine)
        with Session(engine) as db:
            saved = db.scalars(select(ManagedPackage)).one()
            assert saved.target_version == (FUTURE_PIN if tracks_default else pin)
    finally:
        engine.dispose()


def test_operator_powercli_pin_survives_restart_and_archive(monkeypatch):
    """Preserve an explicitly changed pin across startup and settings archive restore.

    Args:
        monkeypatch: Fixture simulating the next packaged PowerCLI baseline.
    """
    from atlaso.app import seed
    from atlaso.app.database import _create_database_schema
    from atlaso.app.models import ManagedPackage, UpdateSource
    from atlaso.app.services.appliance_update import (
        update_stream_configuration_fingerprint,
    )
    from atlaso.app.services.settings_archive import (
        _managed_packages_to_archive,
        _restore_managed_packages,
    )
    from atlaso.app.services.update_sources import effective_update_settings
    from atlaso.app.ui import _managed_package_from_form

    engine = create_engine("sqlite:///:memory:")
    try:
        _create_database_schema(engine)
        with Session(engine) as db:
            seed.seed_update_sources(db)
            db.commit()
            package = db.scalars(select(ManagedPackage)).one()
            assert package.atlaso_default_version == package.target_version == seed.DEFAULT_POWERCLI_VERSION
            default_archive = _managed_packages_to_archive(db)
            previous_fingerprint = update_stream_configuration_fingerprint(
                "powershell_modules", effective_update_settings(db)
            )
            source_id = db.scalars(select(UpdateSource.id).where(UpdateSource.name == "PSGallery")).one()
            assert not _managed_package_from_form(
                package, name=package.name, source_id=source_id, policy="pinned",
                target_version=LEGACY_PIN, enabled=True, db=db,
            )
            assert package.atlaso_default_version == ""
            custom_archive = _managed_packages_to_archive(db)
            db.delete(package)
            db.flush()
            _restore_managed_packages(db, custom_archive)
            db.commit()

        monkeypatch.setattr(seed, "DEFAULT_POWERCLI_VERSION", FUTURE_PIN)
        _create_database_schema(engine)
        with Session(engine) as db:
            package = db.scalars(select(ManagedPackage)).one()
            assert package.target_version == LEGACY_PIN
            assert package.atlaso_default_version == ""
            db.delete(package)
            db.flush()
            _restore_managed_packages(db, default_archive)
            db.commit()

        _create_database_schema(engine)
        with Session(engine) as db:
            package = db.scalars(select(ManagedPackage)).one()
            assert package.atlaso_default_version == package.target_version == FUTURE_PIN
            assert update_stream_configuration_fingerprint(
                "powershell_modules", effective_update_settings(db)
            ) != previous_fingerprint
    finally:
        engine.dispose()
