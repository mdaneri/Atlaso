from collections.abc import Generator
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from labfoundry.app.config import get_settings


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
    from labfoundry.app.models import DnsRecord, DnsSettings

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
    from labfoundry.app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_network_columns()
    _ensure_sqlite_dhcp_columns()
    _ensure_sqlite_user_sync_columns()
    _ensure_sqlite_appliance_settings_columns()
    _ensure_sqlite_ntp_settings_columns()
    _ensure_sqlite_dns_security_columns()
    _ensure_sqlite_ca_columns()
    _ensure_sqlite_vcf_depot_columns()
    _ensure_sqlite_vcf_trust_columns()
    _ensure_sqlite_esxi_pxe_columns()
    _ensure_sqlite_ldap_columns()
    _ensure_sqlite_job_schedule_columns()
    _migrate_appliance_update_release_state()


def _migrate_appliance_update_release_state() -> None:
    """Retire live pip updates and normalize persisted release stream identifiers."""
    from labfoundry.app.models import AuditEvent, Job, JobStatus, ManagedPackage, Schedule, UpdateSource

    changed: list[str] = []

    def normalized_streams(raw_value: object) -> list[str]:
        if not isinstance(raw_value, list):
            return []
        normalized: list[str] = []
        for value in raw_value:
            stream = "labfoundry_release" if value == "labfoundry_wheel" else str(value)
            if stream == "python_libraries" or stream not in {"photon_os", "powershell_modules", "labfoundry_release"}:
                continue
            if stream not in normalized:
                normalized.append(stream)
        return normalized

    with SessionLocal() as session:
        python_sources = session.execute(select(UpdateSource).where(UpdateSource.kind == "python")).scalars().all()
        for source in python_sources:
            for package in session.execute(select(ManagedPackage).where(ManagedPackage.source_id == source.id)).scalars().all():
                session.delete(package)
            session.delete(source)
        if python_sources:
            changed.append(f"removed_python_sources={len(python_sources)}")

        retired_packages = session.execute(
            select(ManagedPackage).where(ManagedPackage.ecosystem.in_(["python", "labfoundry"]))
        ).scalars().all()
        for package in retired_packages:
            session.delete(package)
        if retired_packages:
            changed.append(f"removed_retired_managed_packages={len(retired_packages)}")

        labfoundry_sources = session.execute(select(UpdateSource).where(UpdateSource.kind == "labfoundry")).scalars().all()
        normalized_release_sources = 0
        disabled_release_sources = 0
        for source in labfoundry_sources:
            parsed = urlsplit(source.url.strip())
            if (
                not source.url.strip()
                or parsed.scheme != "https"
                or not parsed.netloc
                or parsed.username
                or parsed.password
            ):
                if source.enabled:
                    source.enabled = False
                    source.validation_status = "invalid"
                    source.validation_message = "Disabled during signed-release migration because the source was not an HTTPS v2 base URL."
                    source.validated_at = None
                    session.add(source)
                    disabled_release_sources += 1
                continue
            path = parsed.path.rstrip("/")
            if path.endswith("/manifest.json"):
                path = path[: -len("/manifest.json")]
            normalized_url = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
            try:
                settings = json.loads(source.settings_json or "{}")
            except json.JSONDecodeError:
                settings = {}
            settings = settings if isinstance(settings, dict) else {}
            settings = {"channel": str(settings.get("channel") or "stable").lower()}
            if settings["channel"] not in {"stable", "preview", "development"}:
                settings["channel"] = "stable"
            normalized_settings = json.dumps(settings, sort_keys=True)
            if source.url != normalized_url or source.settings_json != normalized_settings:
                source.url = normalized_url
                source.settings_json = normalized_settings
                source.validation_status = "not_checked"
                source.validation_message = ""
                source.validated_at = None
                session.add(source)
                normalized_release_sources += 1
        if normalized_release_sources:
            changed.append(f"normalized_release_sources={normalized_release_sources}")
        if disabled_release_sources:
            changed.append(f"disabled_invalid_release_sources={disabled_release_sources}")

        if labfoundry_sources and not any(source.enabled for source in labfoundry_sources):
            public_source = next((source for source in labfoundry_sources if source.name == "GitHub Releases"), None)
            if public_source is not None:
                public_source.url = "https://mdaneri.github.io/LabFoundry/updates"
                public_source.enabled = True
                public_source.priority = 10
                public_source.settings_json = '{"channel": "stable"}'
                public_source.validation_status = "not_checked"
                public_source.validation_message = ""
                public_source.validated_at = None
                session.add(public_source)
            else:
                session.add(
                    UpdateSource(
                        kind="labfoundry",
                        name="GitHub Releases",
                        url="https://mdaneri.github.io/LabFoundry/updates",
                        enabled=True,
                        priority=10,
                        settings_json='{"channel": "stable"}',
                    )
                )
            changed.append("seeded_signed_github_source=1")

        schedules_changed = 0
        schedules_disabled = 0
        schedules = session.execute(
            select(Schedule).where(Schedule.task_type.in_(["appliance_update_check", "appliance_update_install"]))
        ).scalars().all()
        for schedule in schedules:
            try:
                config = json.loads(schedule.task_config_json or "{}")
            except json.JSONDecodeError:
                config = {}
            config = config if isinstance(config, dict) else {}
            old_streams = config.get("selected_streams")
            streams = normalized_streams(old_streams)
            if old_streams != streams:
                config["selected_streams"] = streams
                schedules_changed += 1
            if not streams and schedule.enabled:
                schedule.enabled = False
                schedule.next_run_at = None
                config["_migration_notice"] = "Disabled because Python Libraries was the schedule's only update stream."
                schedules_disabled += 1
            schedule.task_config_json = json.dumps(config, sort_keys=True)
            session.add(schedule)
        if schedules_changed:
            changed.append(f"migrated_schedules={schedules_changed}")
        if schedules_disabled:
            changed.append(f"disabled_python_only_schedules={schedules_disabled}")

        pending_jobs_changed = 0
        job_columns = (
            {column["name"] for column in inspect(engine).get_columns("jobs")}
            if "jobs" in inspect(engine).get_table_names()
            else set()
        )
        pending_jobs = (
            session.execute(
                select(Job).where(
                    Job.type == "appliance-update",
                    Job.status == JobStatus.PENDING.value,
                )
            ).scalars().all()
            if "type" in job_columns
            else []
        )
        for job in pending_jobs:
            try:
                config = json.loads(job.task_config_json or "{}")
            except json.JSONDecodeError:
                config = {}
            if not isinstance(config, dict):
                continue
            old_streams = config.get("selected_streams")
            streams = normalized_streams(old_streams)
            if old_streams == streams:
                continue
            config["selected_streams"] = streams
            job.task_config_json = json.dumps(config, sort_keys=True)
            session.add(job)
            pending_jobs_changed += 1
        if pending_jobs_changed:
            changed.append(f"migrated_pending_jobs={pending_jobs_changed}")

        if changed:
            session.add(
                AuditEvent(
                    actor="system:migration",
                    action="migrate_signed_release_updates",
                    resource_type="appliance_update",
                    resource_id="v2",
                    detail="; ".join(changed),
                )
            )
        session.commit()


def _ensure_sqlite_job_schedule_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "jobs" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("jobs")}
    columns = {
        "schedule_id": "INTEGER",
        "trigger": "VARCHAR(20) DEFAULT 'manual'",
        "planned_for": "DATETIME",
        "task_config_json": "TEXT DEFAULT '{}'",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE jobs ADD COLUMN {name} {definition}"))


def _ensure_sqlite_network_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    tables = {
        "physical_interfaces": {
            "host_ipv6_cidr": "VARCHAR(64)",
            "ipv6_cidr": "VARCHAR(64)",
            "gateway": "VARCHAR(64)",
            "ipv4_method": "VARCHAR(20) DEFAULT 'static'",
            "ipv6_enabled": "BOOLEAN DEFAULT 0",
            "ipv6_gateway": "VARCHAR(64)",
        },
        "vlan_interfaces": {
            "ipv6_cidr": "VARCHAR(64)",
        },
    }
    with engine.begin() as connection:
        for table_name, columns in tables.items():
            if table_name not in table_names:
                continue
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {name} {definition}"))
            if table_name == "physical_interfaces" and "ipv6_enabled" not in existing:
                connection.execute(text("UPDATE physical_interfaces SET ipv6_enabled = 1 WHERE ipv6_cidr IS NOT NULL AND TRIM(ipv6_cidr) <> ''"))


def _ensure_sqlite_dhcp_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "dhcp_scopes" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("dhcp_scopes")}
    columns = {
        "address_family": "VARCHAR(10) DEFAULT 'ipv4'",
        "range_expression": "VARCHAR(500) DEFAULT ''",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE dhcp_scopes ADD COLUMN {name} {definition}"))


def _ensure_sqlite_user_sync_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("users")}
    columns = {
        "roles_json": "TEXT DEFAULT ''",
        "auth_provider": "VARCHAR(40) DEFAULT 'local'",
        "external_subject": "VARCHAR(240) DEFAULT ''",
        "external_display_name": "VARCHAR(180) DEFAULT ''",
        "external_email": "VARCHAR(240) DEFAULT ''",
        "role_override_json": "TEXT DEFAULT ''",
        "shell": "VARCHAR(80) DEFAULT '/sbin/nologin'",
        "web_terminal_access": "BOOLEAN DEFAULT 0",
        "os_password_applied_at": "DATETIME",
        "os_sync_applied_at": "DATETIME",
        "os_sync_status": "VARCHAR(80) DEFAULT 'password_not_staged'",
        "os_sync_error": "TEXT",
        "os_unlock_requested_at": "DATETIME",
    }
    added_web_terminal_access = "web_terminal_access" not in existing
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE users ADD COLUMN {name} {definition}"))
        connection.execute(text("""UPDATE users SET roles_json = '["' || role || '"]' WHERE COALESCE(roles_json, '') = ''"""))
        if added_web_terminal_access:
            connection.execute(
                text(
                    "UPDATE users SET web_terminal_access = 1 "
                    "WHERE role = 'admin' OR roles_json LIKE '%\"admin\"%'"
                )
            )


def _ensure_sqlite_appliance_settings_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "appliance_settings" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("appliance_settings")}
    columns = {
        "management_https_enabled": "BOOLEAN DEFAULT 0",
        "web_terminal_enabled": "BOOLEAN DEFAULT 0",
        "web_terminal_interfaces_json": "TEXT DEFAULT '[]'",
        "root_ssh_enabled": "BOOLEAN DEFAULT 0",
        "vmware_ceip_enabled": "BOOLEAN DEFAULT 0",
        "service_dns_target_naming": "VARCHAR(20) DEFAULT 'ip'",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE appliance_settings ADD COLUMN {name} {definition}"))


def _ensure_sqlite_ntp_settings_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "ntp_settings" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("ntp_settings")}
    columns = {
        "hostname": "VARCHAR(180) DEFAULT 'ntp.labfoundry.internal'",
        "listen_interface": "VARCHAR(240) DEFAULT ''",
        "listen_address": "VARCHAR(240) DEFAULT ''",
        "port": "INTEGER DEFAULT 123",
        "upstream_servers": "TEXT DEFAULT 'time.cloudflare.com\nnts.netnod.se'",
        "upstream_sources_json": """TEXT DEFAULT '[{"description":"Cloudflare public NTS","enabled":true,"id":"cloudflare-nts","source":"time.cloudflare.com","use_nts":true},{"description":"Netnod public NTS","enabled":true,"id":"netnod-nts","source":"nts.netnod.se","use_nts":true}]'""",
        "allow_clients": "TEXT DEFAULT 'any'",
        "nts_server_enabled": "BOOLEAN DEFAULT 0",
        "nts_server_cert_path": "VARCHAR(300) DEFAULT ''",
        "nts_server_key_path": "VARCHAR(300) DEFAULT ''",
        "nts_ke_port": "INTEGER DEFAULT 4460",
        "minsources": "INTEGER",
        "config_path": "VARCHAR(240) DEFAULT '/var/lib/labfoundry/apply/ntpd/labfoundry-ntp.conf'",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE ntp_settings ADD COLUMN {name} {definition}"))


def _ensure_sqlite_dns_security_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    with engine.begin() as connection:
        if "dns_settings" in table_names:
            existing = {column["name"] for column in inspector.get_columns("dns_settings")}
            columns = {
                "authoritative_server": "VARCHAR(253) DEFAULT ''",
                "authoritative_contact": "VARCHAR(253) DEFAULT ''",
                "authoritative_ttl": "INTEGER DEFAULT 3600",
                "authoritative_serial": "INTEGER DEFAULT 0",
                "authoritative_refresh": "INTEGER DEFAULT 1200",
                "authoritative_retry": "INTEGER DEFAULT 180",
                "authoritative_expire": "INTEGER DEFAULT 1209600",
                "dnssec_enabled": "BOOLEAN DEFAULT 0",
                "rebind_protection_enabled": "BOOLEAN DEFAULT 0",
                "rebind_domain_exemptions": "TEXT DEFAULT ''",
                "query_logging_mode": "VARCHAR(20) DEFAULT 'off'",
            }
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE dns_settings ADD COLUMN {name} {definition}"))
            connection.execute(
                text(
                    "UPDATE dns_settings SET authoritative_serial = CAST(strftime('%s', 'now') AS INTEGER) "
                    "WHERE COALESCE(authoritative_serial, 0) <= 0"
                )
            )
        if "dns_records" in table_names:
            existing = {column["name"] for column in inspector.get_columns("dns_records")}
            if "record_data_json" not in existing:
                connection.execute(text("ALTER TABLE dns_records ADD COLUMN record_data_json TEXT DEFAULT ''"))
            indexes = connection.execute(text("PRAGMA index_list('dns_records')")).fetchall()
            has_old_unique = False
            has_new_unique = False
            for index in indexes:
                index_name = index[1]
                is_unique = bool(index[2])
                if not is_unique:
                    continue
                columns = [row[2] for row in connection.execute(text(f"PRAGMA index_info('{index_name}')")).fetchall()]
                if columns == ["hostname", "record_type"]:
                    has_old_unique = True
                if columns == ["hostname", "record_type", "address"]:
                    has_new_unique = True
            if has_old_unique and not has_new_unique:
                connection.execute(text("ALTER TABLE dns_records RENAME TO dns_records_old_unique"))
                connection.execute(
                    text(
                        """
                        CREATE TABLE dns_records (
                            id INTEGER NOT NULL,
                            hostname VARCHAR(120) NOT NULL,
                            record_type VARCHAR(20) NOT NULL,
                            address VARCHAR(120) NOT NULL,
                            record_data_json TEXT NOT NULL DEFAULT '',
                            description TEXT,
                            enabled BOOLEAN NOT NULL,
                            created_at DATETIME NOT NULL,
                            PRIMARY KEY (id),
                            CONSTRAINT uq_dns_record_hostname_type_address UNIQUE (hostname, record_type, address)
                        )
                        """
                    )
                )
                connection.execute(text("CREATE INDEX ix_dns_records_hostname ON dns_records (hostname)"))
                connection.execute(
                    text(
                        """
                        INSERT INTO dns_records (id, hostname, record_type, address, record_data_json, description, enabled, created_at)
                        SELECT id, hostname, record_type, address, COALESCE(record_data_json, ''), description, enabled, created_at
                        FROM dns_records_old_unique
                        """
                    )
                )
                connection.execute(text("DROP TABLE dns_records_old_unique"))


def _ensure_sqlite_ca_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    with engine.begin() as connection:
        if "ca_settings" in table_names:
            existing = {column["name"] for column in inspector.get_columns("ca_settings")}
            columns = {
                "portal_hostname": "VARCHAR(180) DEFAULT 'ca.labfoundry.internal'",
                "root_certificate_pem": "TEXT DEFAULT ''",
                "root_private_key_encrypted": "TEXT DEFAULT ''",
                "root_serial_number": "VARCHAR(120) DEFAULT ''",
                "root_fingerprint": "VARCHAR(128) DEFAULT ''",
                "root_issued_at": "DATETIME",
                "root_expires_at": "DATETIME",
                "listen_interface": "VARCHAR(80) DEFAULT ''",
                "listen_address": "VARCHAR(240) DEFAULT ''",
            }
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE ca_settings ADD COLUMN {name} {definition}"))
        if "ca_certificates" in table_names:
            existing = {column["name"] for column in inspector.get_columns("ca_certificates")}
            columns = {
                "certificate_pem": "TEXT DEFAULT ''",
                "private_key_encrypted": "TEXT DEFAULT ''",
                "chain_pem": "TEXT DEFAULT ''",
                "issuer_common_name": "VARCHAR(180) DEFAULT ''",
                "fingerprint": "VARCHAR(128) DEFAULT ''",
                "managed_owner": "VARCHAR(120) DEFAULT ''",
                "cert_path": "VARCHAR(300) DEFAULT ''",
                "key_path": "VARCHAR(300) DEFAULT ''",
                "chain_path": "VARCHAR(300) DEFAULT ''",
                "revoked_at": "DATETIME",
                "revoked_by": "VARCHAR(100)",
                "revocation_reason": "VARCHAR(120) DEFAULT ''",
            }
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE ca_certificates ADD COLUMN {name} {definition}"))
            connection.execute(
                text(
                    """
                    DELETE FROM ca_certificates
                    WHERE id IN (
                        SELECT id
                        FROM (
                            SELECT
                                id,
                                ROW_NUMBER() OVER (
                                    PARTITION BY managed_owner
                                    ORDER BY
                                        CASE
                                            WHEN status = 'issued'
                                                AND COALESCE(certificate_pem, '') <> ''
                                                AND COALESCE(private_key_encrypted, '') <> '' THEN 0
                                            WHEN status = 'issued' THEN 1
                                            ELSE 2
                                        END,
                                        id
                                ) AS duplicate_position
                            FROM ca_certificates
                            WHERE COALESCE(managed_owner, '') <> ''
                        ) ranked_managed_certificates
                        WHERE duplicate_position > 1
                    )
                    """
                )
            )
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_ca_certificates_managed_owner "
                    "ON ca_certificates (managed_owner) WHERE managed_owner <> ''"
                )
            )


def _ensure_sqlite_vcf_depot_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    with engine.begin() as connection:
        if "vcf_depot_download_profiles" in table_names:
            existing = {column["name"] for column in inspector.get_columns("vcf_depot_download_profiles")}
            columns = {
                "patches_only": "BOOLEAN DEFAULT 0",
            }
            for name, definition in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE vcf_depot_download_profiles ADD COLUMN {name} {definition}"))
        if "vcf_offline_depot_settings" in table_names:
            depot_existing = {column["name"] for column in inspector.get_columns("vcf_offline_depot_settings")}
            depot_columns = {
                "http_user_id": "INTEGER",
                "allow_unauthenticated_access": "BOOLEAN DEFAULT 0",
            }
            for name, definition in depot_columns.items():
                if name not in depot_existing:
                    connection.execute(text(f"ALTER TABLE vcf_offline_depot_settings ADD COLUMN {name} {definition}"))


def _ensure_sqlite_vcf_trust_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "vcf_trust_targets" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("vcf_trust_targets")}
    columns = {
        "api_port": "INTEGER DEFAULT 443",
        "tls_fingerprint": "VARCHAR(160) DEFAULT ''",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE vcf_trust_targets ADD COLUMN {name} {definition}"))
        indexes = connection.execute(text("PRAGMA index_list('vcf_trust_targets')")).fetchall()
        has_legacy_unique = False
        has_api_unique = False
        for index in indexes:
            index_name = index[1]
            is_unique = bool(index[2])
            if not is_unique:
                continue
            index_columns = [row[2] for row in connection.execute(text(f"PRAGMA index_info('{index_name}')")).fetchall()]
            if index_columns == ["address", "ssh_port"]:
                has_legacy_unique = True
            if index_columns == ["address", "api_port"]:
                has_api_unique = True
        if has_legacy_unique and not has_api_unique:
            connection.execute(text("ALTER TABLE vcf_trust_targets RENAME TO vcf_trust_targets_legacy_unique"))
            connection.execute(
                text(
                    """
                    CREATE TABLE vcf_trust_targets (
                        id INTEGER NOT NULL,
                        address VARCHAR(240) NOT NULL,
                        ssh_port INTEGER NOT NULL,
                        api_port INTEGER NOT NULL,
                        appliance_role VARCHAR(40) NOT NULL,
                        appliance_version VARCHAR(80) NOT NULL,
                        ssh_host_key_fingerprint VARCHAR(160) NOT NULL,
                        tls_fingerprint VARCHAR(160) NOT NULL,
                        last_ca_fingerprint VARCHAR(128) NOT NULL,
                        last_result VARCHAR(80) NOT NULL,
                        last_job_id VARCHAR(40) NOT NULL,
                        last_attempted_at DATETIME,
                        last_succeeded_at DATETIME,
                        created_at DATETIME NOT NULL,
                        updated_at DATETIME NOT NULL,
                        PRIMARY KEY (id),
                        CONSTRAINT uq_vcf_trust_target_address_api_port UNIQUE (address, api_port)
                    )
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO vcf_trust_targets (
                        id,
                        address,
                        ssh_port,
                        api_port,
                        appliance_role,
                        appliance_version,
                        ssh_host_key_fingerprint,
                        tls_fingerprint,
                        last_ca_fingerprint,
                        last_result,
                        last_job_id,
                        last_attempted_at,
                        last_succeeded_at,
                        created_at,
                        updated_at
                    )
                    SELECT
                        id,
                        address,
                        COALESCE(ssh_port, 22),
                        COALESCE(api_port, 443),
                        COALESCE(appliance_role, ''),
                        COALESCE(appliance_version, ''),
                        COALESCE(ssh_host_key_fingerprint, ''),
                        COALESCE(tls_fingerprint, ''),
                        COALESCE(last_ca_fingerprint, ''),
                        COALESCE(last_result, ''),
                        COALESCE(last_job_id, ''),
                        last_attempted_at,
                        last_succeeded_at,
                        COALESCE(created_at, CURRENT_TIMESTAMP),
                        COALESCE(updated_at, CURRENT_TIMESTAMP)
                    FROM vcf_trust_targets_legacy_unique
                    WHERE id IN (
                        SELECT MIN(id)
                        FROM vcf_trust_targets_legacy_unique
                        GROUP BY address, COALESCE(api_port, 443)
                    )
                    """
                )
            )
            connection.execute(text("DROP TABLE vcf_trust_targets_legacy_unique"))
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_vcf_trust_targets_address ON vcf_trust_targets (address)"))


def _ensure_sqlite_esxi_pxe_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    if "esxi_pxe_hosts" not in inspector.get_table_names():
        return
    existing = {column["name"] for column in inspector.get_columns("esxi_pxe_hosts")}
    columns = {
        "installer_iso_path": "VARCHAR(500) DEFAULT ''",
        "ip_address": "VARCHAR(64) DEFAULT ''",
        "variables_json": "TEXT DEFAULT '{}'",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE esxi_pxe_hosts ADD COLUMN {name} {definition}"))


def _ensure_sqlite_ldap_columns() -> None:
    if not str(engine.url).startswith("sqlite"):
        return
    inspector = inspect(engine)
    table_names = inspector.get_table_names()
    if "ldap_settings" not in table_names:
        return
    existing = {column["name"] for column in inspector.get_columns("ldap_settings")}
    columns = {
        "hostname": "VARCHAR(180) DEFAULT 'ldap.labfoundry.internal'",
        "listen_interface": "VARCHAR(240) DEFAULT ''",
        "listen_address": "VARCHAR(240) DEFAULT ''",
        "ldaps_enabled": "BOOLEAN DEFAULT 1",
        "port": "INTEGER DEFAULT 636",
        "ldap_enabled": "BOOLEAN DEFAULT 0",
        "ldap_port": "INTEGER DEFAULT 389",
        "min_password_length": "INTEGER DEFAULT 14",
        "require_uppercase": "BOOLEAN DEFAULT 1",
        "require_lowercase": "BOOLEAN DEFAULT 1",
        "require_number": "BOOLEAN DEFAULT 1",
        "require_special": "BOOLEAN DEFAULT 1",
        "disallow_username": "BOOLEAN DEFAULT 1",
        "max_failures": "INTEGER DEFAULT 5",
        "lockout_minutes": "INTEGER DEFAULT 15",
        "failure_window_minutes": "INTEGER DEFAULT 15",
        "password_history": "INTEGER DEFAULT 5",
        "password_max_age_days": "INTEGER DEFAULT 0",
        "config_path": "VARCHAR(240) DEFAULT '/var/lib/labfoundry/apply/ldap/labfoundry-ldap.json'",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE ldap_settings ADD COLUMN {name} {definition}"))


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
