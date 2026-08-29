"""Configure database sessions and perform bounded startup reconciliation."""

import json
from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from atlaso.app.config import get_settings


class Base(DeclarativeBase):
    """Represent base."""
    pass


def _engine_url() -> str:
    """Return engine url."""
    settings = get_settings()
    url = settings.database_url
    if url.startswith("sqlite:///"):
        db_path = Path(url.removeprefix("sqlite:///"))
        if str(db_path) != ":memory:":
            db_path.parent.mkdir(parents=True, exist_ok=True)
    return url


engine = create_engine(
    _engine_url(),
    connect_args={"check_same_thread": False} if _engine_url().startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    """Handle enable sqlite foreign keys.

    Args:
        dbapi_connection: Dbapi connection consumed by enable sqlite foreign keys.
        _connection_record: Connection record consumed by enable sqlite foreign keys.
    """
    if dbapi_connection.__class__.__module__.split(".", 1)[0] != "sqlite3":
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


DNS_AUTHORITY_SERIAL_FIELDS = {
    "domain",
    "disabled_domains",
    "authoritative",
    "authoritative_server",
    "authoritative_contact",
    "authoritative_ttl",
    "authoritative_refresh",
    "authoritative_retry",
    "authoritative_expire",
    "listen_interface",
    "listen_address",
}
ATLASO_SCHEMA_LOCK_ID = 0x41544C41534F


def _create_database_schema(bind: Engine) -> None:
    """Create registered tables while serializing concurrent service startup.

    Args:
        bind: Database engine whose registered schema should be created.
    """
    if bind.dialect.name == "sqlite":
        with bind.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                Base.metadata.create_all(bind=connection)
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        return
    if bind.dialect.name == "postgresql":
        with bind.begin() as connection:
            connection.execute(
                text("SELECT pg_advisory_xact_lock(:lock_id)"),
                {"lock_id": ATLASO_SCHEMA_LOCK_ID},
            )
            Base.metadata.create_all(bind=connection)
        return
    Base.metadata.create_all(bind=bind)


def _reconcile_vcf_depot_job_queue(connection: Connection) -> None:
    """Create and upgrade the cross-database VCFDT queue constraints.

    Args:
        connection: Transactional database connection used during startup.
    """
    job_columns = {column["name"] for column in inspect(connection).get_columns("jobs")}
    idempotent_column_clause = "IF NOT EXISTS " if connection.dialect.name == "postgresql" else ""
    if "vcf_depot_operation" not in job_columns:
        connection.execute(
            text(
                "ALTER TABLE jobs "
                f"ADD COLUMN {idempotent_column_clause}"
                "vcf_depot_operation BOOLEAN NOT NULL DEFAULT FALSE"
            )
        )
    if "vcf_depot_profile_id" not in job_columns:
        connection.execute(
            text(
                "ALTER TABLE jobs "
                f"ADD COLUMN {idempotent_column_clause}vcf_depot_profile_id INTEGER"
            )
        )

    connection.execute(
        text(
            "UPDATE jobs SET vcf_depot_operation = TRUE "
            "WHERE type IN ('vcf-depot-download', 'vcf-depot-software-id')"
        )
    )
    legacy_appliance_applies = connection.execute(
        text("SELECT id, result FROM jobs WHERE type = 'appliance-apply'")
    ).all()
    for job_id, raw_result in legacy_appliance_applies:
        try:
            result = json.loads(raw_result or "{}")
        except (TypeError, json.JSONDecodeError):
            result = {}
        selected_units = result.get("selected_units") if isinstance(result, dict) else None
        is_vcf_depot_operation = (
            isinstance(selected_units, list) and "vcf_offline_depot" in selected_units
        )
        connection.execute(
            text(
                "UPDATE jobs SET vcf_depot_operation = :is_vcf_depot_operation "
                "WHERE id = :job_id"
            ),
            {
                "job_id": job_id,
                "is_vcf_depot_operation": is_vcf_depot_operation,
            },
        )
    legacy_downloads = connection.execute(
        text(
            "SELECT id, task_config_json FROM jobs "
            "WHERE type = 'vcf-depot-download' AND vcf_depot_profile_id IS NULL"
        )
    ).all()
    for job_id, raw_config in legacy_downloads:
        try:
            profile_id = int(json.loads(raw_config or "{}").get("profile_id") or 0)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if profile_id:
            connection.execute(
                text("UPDATE jobs SET vcf_depot_profile_id = :profile_id WHERE id = :job_id"),
                {"job_id": job_id, "profile_id": profile_id},
            )

    active_downloads = connection.execute(
        text(
            "SELECT id, vcf_depot_profile_id, status FROM jobs "
            "WHERE type = 'vcf-depot-download' "
            "AND status IN ('pending', 'running') "
            "ORDER BY vcf_depot_profile_id, "
            "CASE WHEN status = 'running' THEN 0 ELSE 1 END, created_at, id"
        )
    ).all()
    downloads_by_profile: dict[int, list[tuple[str, str]]] = {}
    for job_id, raw_profile_id, job_status in active_downloads:
        profile_id = int(raw_profile_id or 0)
        if profile_id:
            downloads_by_profile.setdefault(profile_id, []).append((job_id, job_status))
    duplicate_running_profile = False
    for profile_jobs in downloads_by_profile.values():
        running_jobs = [job_id for job_id, job_status in profile_jobs if job_status == "running"]
        pending_jobs = [job_id for job_id, job_status in profile_jobs if job_status == "pending"]
        duplicate_running_profile = duplicate_running_profile or len(running_jobs) > 1
        retained_pending = pending_jobs[:1] if not running_jobs else []
        for duplicate_job_id in pending_jobs[len(retained_pending):]:
            connection.execute(
                text(
                    "UPDATE jobs SET status = 'skipped', progress_percent = 100, "
                    "finished_at = CURRENT_TIMESTAMP, "
                    "error = 'Skipped during database upgrade because this VCFDT profile already had an active task.' "
                    "WHERE id = :job_id"
                ),
                {"job_id": duplicate_job_id},
            )

    running_operations = connection.execute(
        text(
            "SELECT id, type FROM jobs WHERE vcf_depot_operation = TRUE "
            "AND status = 'running' ORDER BY started_at, created_at, id"
        )
    ).all()
    remaining_running_operations = len(running_operations)

    connection.execute(text("DROP INDEX IF EXISTS uq_jobs_active_vcf_depot_download"))
    connection.execute(text("DROP INDEX IF EXISTS uq_jobs_active_vcf_depot_operation"))
    connection.execute(text("DROP INDEX IF EXISTS uq_jobs_running_vcf_depot_operation"))
    if not duplicate_running_profile:
        _create_vcf_depot_active_profile_index(connection)
    if remaining_running_operations <= 1:
        _create_vcf_depot_running_operation_index(connection)


def _reconcile_vcf_depot_job_queue_schema(bind: Engine) -> None:
    """Run VCFDT queue reconciliation with a serialized SQLite schema lock.

    Args:
        bind: Database engine whose VCFDT queue schema should be reconciled.
    """
    if bind.dialect.name != "sqlite":
        with bind.begin() as connection:
            _reconcile_vcf_depot_job_queue(connection)
        return

    with bind.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            _reconcile_vcf_depot_job_queue(connection)
        except Exception:
            connection.rollback()
            raise
        connection.commit()


def _create_vcf_depot_running_operation_index(connection: Connection) -> None:
    """Create the single-running-VCFDT-operation database guard.

    Args:
        connection: Transactional database connection used to create the index.
    """
    connection.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_jobs_running_vcf_depot_operation "
            "ON jobs (vcf_depot_operation) "
            "WHERE vcf_depot_operation = TRUE AND status = 'running'"
        )
    )


def _create_vcf_depot_active_profile_index(connection: Connection) -> None:
    """Create the one-active-download-per-profile database guard.

    Args:
        connection: Transactional database connection used to create the index.
    """
    connection.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_jobs_active_vcf_depot_profile "
            "ON jobs (vcf_depot_profile_id) "
            "WHERE type = 'vcf-depot-download' "
            "AND vcf_depot_profile_id IS NOT NULL "
            "AND status IN ('pending', 'running')"
        )
    )


def ensure_vcf_depot_running_operation_index(bind: Engine | None = None) -> bool:
    """Create the runtime guard after type-specific startup recovery finishes.

    Args:
        bind: Optional database engine whose VCFDT operation guard should be ensured.

    Returns:
        True when the guard exists, or False while multiple recovery tasks remain running.
    """
    target_engine = bind or engine
    with target_engine.begin() as connection:
        duplicate_profile_count = int(
            connection.execute(
                text(
                    "SELECT COUNT(*) FROM ("
                    "SELECT vcf_depot_profile_id FROM jobs "
                    "WHERE type = 'vcf-depot-download' "
                    "AND vcf_depot_profile_id IS NOT NULL "
                    "AND status IN ('pending', 'running') "
                    "GROUP BY vcf_depot_profile_id HAVING COUNT(*) > 1"
                    ") AS duplicate_profiles"
                )
            ).scalar_one()
            or 0
        )
        running_count = int(
            connection.execute(
                text(
                    "SELECT COUNT(*) FROM jobs WHERE vcf_depot_operation = TRUE "
                    "AND status = 'running'"
                )
            ).scalar_one()
            or 0
        )
        if duplicate_profile_count or running_count > 1:
            return False
        _create_vcf_depot_active_profile_index(connection)
        _create_vcf_depot_running_operation_index(connection)
    return True


@event.listens_for(Session, "before_flush")
def _advance_dns_authoritative_serial(session: Session, _flush_context, _instances) -> None:
    """Handle advance dns authoritative serial.

    Args:
        session: Active database or protocol session.
        _flush_context:  flush context supplied by the caller.
        _instances:  instances supplied by the caller.
    """
    from atlaso.app.models import DnsRecord, DnsSettings

    record_changed = any(isinstance(item, DnsRecord) for item in session.new | session.deleted)
    if not record_changed:
        record_changed = any(
            isinstance(item, DnsRecord) and session.is_modified(item, include_collections=False)
            for item in session.dirty
        )

    settings_changed = False
    for item in session.dirty:
        if not isinstance(item, DnsSettings):
            continue
        state = inspect(item)
        if any(state.attrs[field].history.has_changes() for field in DNS_AUTHORITY_SERIAL_FIELDS):
            settings_changed = True
            break

    if not record_changed and not settings_changed:
        return

    settings = next((item for item in session.new if isinstance(item, DnsSettings)), None)
    if settings is None:
        settings = session.execute(select(DnsSettings)).scalar_one_or_none()
    if settings is None:
        return

    current = int(settings.authoritative_serial or 0)
    now = int(datetime.now(timezone.utc).timestamp())
    settings.authoritative_serial = max(current + 1, now)


def _reconcile_authentication_lifetime_columns(connection: Connection) -> None:
    """Add authentication-lifetime columns to an existing appliance settings table.

    Args:
        connection: Transactional database connection used for schema reconciliation.
    """
    existing_columns = {
        column["name"] for column in inspect(connection).get_columns("appliance_settings")
    }
    additions = {
        "browser_session_idle_timeout_minutes": "INTEGER NOT NULL DEFAULT 30",
        "api_token_max_lifetime_days": "INTEGER NOT NULL DEFAULT 90",
    }
    idempotent_column_clause = (
        "IF NOT EXISTS " if connection.dialect.name == "postgresql" else ""
    )
    for name, definition in additions.items():
        if name not in existing_columns:
            connection.execute(
                text(
                    "ALTER TABLE appliance_settings ADD COLUMN "
                    f"{idempotent_column_clause}{name} {definition}"
                )
            )
            if name == "api_token_max_lifetime_days":
                legacy_token_days = get_settings().api_token_ttl_days
                if legacy_token_days is not None:
                    # Preserve a stricter legacy environment policy only while the
                    # persisted column is first introduced. Later startups must
                    # never overwrite an operator-managed database value.
                    connection.execute(
                        text(
                            "UPDATE appliance_settings "
                            "SET api_token_max_lifetime_days = :legacy_token_days"
                        ),
                        {"legacy_token_days": legacy_token_days},
                    )


def init_db() -> None:
    """Handle init db."""
    from atlaso.app import (  # noqa: F401 - importing models registers SQLAlchemy metadata.
        models,
    )

    _create_database_schema(engine)
    with engine.begin() as connection:
        _reconcile_authentication_lifetime_columns(connection)
        if engine.dialect.name == "sqlite":
            connection.execute(
                text(
                    "INSERT OR IGNORE INTO vcf_depot_admission_gate (id, generation) "
                    "VALUES (1, 0)"
                )
            )
        else:
            connection.execute(
                text(
                    "INSERT INTO vcf_depot_admission_gate (id, generation) VALUES (1, 0) "
                    "ON CONFLICT (id) DO NOTHING"
                )
            )
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            for table_name in ("physical_interfaces", "vlan_interfaces"):
                interface_columns = {
                    row[1]
                    for row in connection.execute(text(f"PRAGMA table_info({table_name})")).all()
                }
                if "access_management_ui_enabled" not in interface_columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE {table_name} ADD COLUMN "
                            "access_management_ui_enabled BOOLEAN NOT NULL DEFAULT 0"
                        )
                    )
            columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(oidc_provider_settings)")
                ).all()
            }
            additions = {
                "hostname": "VARCHAR(180) NOT NULL DEFAULT 'oidc.atlaso.internal'",
                "listen_interface": "VARCHAR(240) NOT NULL DEFAULT ''",
                "listen_address": "VARCHAR(240) NOT NULL DEFAULT ''",
                "port": "INTEGER NOT NULL DEFAULT 443",
            }
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(
                        text(
                            f"ALTER TABLE oidc_provider_settings "
                            f"ADD COLUMN {name} {definition}"
                        )
                    )
            dns_columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(dns_settings)")
                ).all()
            }
            if "disabled_domains" not in dns_columns:
                connection.execute(
                    text(
                        "ALTER TABLE dns_settings "
                        "ADD COLUMN disabled_domains VARCHAR(500) NOT NULL DEFAULT ''"
                    )
                )
            if "domain_descriptions_json" not in dns_columns:
                connection.execute(
                    text(
                        "ALTER TABLE dns_settings "
                        "ADD COLUMN domain_descriptions_json TEXT NOT NULL DEFAULT '{}'"
                    )
                )
            user_columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(users)")
                ).all()
            }
            if "description" not in user_columns:
                connection.execute(
                    text(
                        "ALTER TABLE users "
                        "ADD COLUMN description TEXT NOT NULL DEFAULT ''"
                    )
                )
            oidc_client_columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(oidc_clients)")
                ).all()
            }
            if "description" not in oidc_client_columns:
                connection.execute(
                    text(
                        "ALTER TABLE oidc_clients "
                        "ADD COLUMN description TEXT NOT NULL DEFAULT ''"
                    )
                )
            ldap_organization_columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(ldap_organizations)")
                ).all()
            }
            if "description" not in ldap_organization_columns:
                connection.execute(
                    text(
                        "ALTER TABLE ldap_organizations "
                        "ADD COLUMN description TEXT NOT NULL DEFAULT ''"
                    )
                )
            job_columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(jobs)")
                ).all()
            }
            if "network_boot_environment_key" not in job_columns:
                connection.execute(
                    text(
                        "ALTER TABLE jobs "
                        "ADD COLUMN network_boot_environment_key VARCHAR(80)"
                    )
                )
            if "network_boot_source" not in job_columns:
                connection.execute(
                    text(
                        "ALTER TABLE jobs "
                        "ADD COLUMN network_boot_source VARCHAR(20)"
                    )
                )
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "uq_jobs_active_network_boot_download "
                    "ON jobs (network_boot_environment_key) "
                    "WHERE type = 'pxe-media-sync' "
                    "AND network_boot_source = 'download' "
                    "AND status IN ('pending', 'running')"
                )
            )
    _reconcile_vcf_depot_job_queue_schema(engine)


def get_db() -> Generator[Session, None, None]:
    """Return db."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
