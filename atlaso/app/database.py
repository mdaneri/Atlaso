from collections.abc import Generator
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from atlaso.app.config import get_settings


class Base(DeclarativeBase):
    pass


def _engine_url() -> str:
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


@event.listens_for(Session, "before_flush")
def _advance_dns_authoritative_serial(session: Session, _flush_context, _instances) -> None:
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


def init_db() -> None:
    from atlaso.app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
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
            kms_settings_columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(kms_settings)")
                ).all()
            }
            if "provider_id" not in kms_settings_columns:
                connection.execute(
                    text(
                        "ALTER TABLE kms_settings "
                        "ADD COLUMN provider_id VARCHAR(36) NOT NULL DEFAULT ''"
                    )
                )
            kms_client_columns = {
                row[1]
                for row in connection.execute(
                    text("PRAGMA table_info(kms_clients)")
                ).all()
            }
            if "certificate_fingerprint" not in kms_client_columns:
                connection.execute(
                    text(
                        "ALTER TABLE kms_clients "
                        "ADD COLUMN certificate_fingerprint VARCHAR(64) NOT NULL DEFAULT ''"
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
            if "vcf_depot_operation" not in job_columns:
                connection.execute(
                    text(
                        "ALTER TABLE jobs "
                        "ADD COLUMN vcf_depot_operation BOOLEAN NOT NULL DEFAULT 0"
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
            connection.execute(
                text(
                    "UPDATE jobs SET vcf_depot_operation = 1 "
                    "WHERE type IN ('vcf-depot-download', 'vcf-depot-software-id') "
                    "OR (type = 'appliance-apply' AND instr(COALESCE(result, ''), '\"vcf_offline_depot\"') > 0)"
                )
            )
            active_vcf_operations = connection.execute(
                text(
                    "SELECT id FROM jobs "
                    "WHERE vcf_depot_operation = 1 "
                    "AND status IN ('pending', 'running') "
                    "ORDER BY created_at, id"
                )
            ).scalars().all()
            for duplicate_job_id in active_vcf_operations[1:]:
                connection.execute(
                    text(
                        "UPDATE jobs SET status = 'skipped', progress_percent = 100, "
                        "finished_at = CURRENT_TIMESTAMP, "
                        "error = 'Skipped during database upgrade because another VCFDT operation was active.' "
                        "WHERE id = :job_id"
                    ),
                    {"job_id": duplicate_job_id},
                )
            connection.execute(text("DROP INDEX IF EXISTS uq_jobs_active_vcf_depot_download"))
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS "
                    "uq_jobs_active_vcf_depot_operation "
                    "ON jobs (vcf_depot_operation) "
                    "WHERE vcf_depot_operation = 1 "
                    "AND status IN ('pending', 'running')"
                )
            )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
