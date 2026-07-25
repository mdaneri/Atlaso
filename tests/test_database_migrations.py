import sqlite3

import pytest


def test_existing_database_startup_adds_job_steps_table(tmp_path):
    from labfoundry.app import database
    db_path = tmp_path / "existing.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        CREATE TABLE jobs (
            id VARCHAR(64) PRIMARY KEY,
            job_type VARCHAR(64) NOT NULL,
            status VARCHAR(32) NOT NULL,
            progress_percent INTEGER NOT NULL,
            created_by VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            started_at DATETIME,
            finished_at DATETIME,
            result JSON,
            error TEXT
        )
        """
    )
    connection.commit()
    connection.close()

    previous_engine = database.engine
    migrated_engine = database.create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    try:
        database.engine = migrated_engine
        database.SessionLocal.configure(bind=migrated_engine)
        database.init_db()
        table_names = set(database.inspect(migrated_engine).get_table_names())
        step_columns = {column["name"] for column in database.inspect(migrated_engine).get_columns("job_steps")}
        job_columns = {column["name"] for column in database.inspect(migrated_engine).get_columns("jobs")}
    finally:
        migrated_engine.dispose()
        database.engine = previous_engine
        database.SessionLocal.configure(bind=previous_engine)

    assert "job_steps" in table_names
    assert {"update_sources", "managed_packages", "automation_scripts", "automation_script_revisions", "schedules"} <= table_names
    assert {"job_id", "component_key", "position", "status", "result", "error"} <= step_columns
    assert {"schedule_id", "trigger", "planned_for", "task_config_json"} <= job_columns


def test_physical_interface_ipv6_enabled_migration_backfills_only_static_ipv6(tmp_path):
    from labfoundry.app import database

    db_path = tmp_path / "legacy-network.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE physical_interfaces (id INTEGER PRIMARY KEY, ipv6_cidr VARCHAR(64))")
    connection.execute("INSERT INTO physical_interfaces (id, ipv6_cidr) VALUES (1, 'fd00:10::1/64'), (2, NULL), (3, '')")
    connection.commit()
    connection.close()

    previous_engine = database.engine
    migrated_engine = database.create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    try:
        database.engine = migrated_engine
        database._ensure_sqlite_network_columns()
        connection = sqlite3.connect(db_path)
        rows = connection.execute("SELECT id, ipv6_enabled, ipv6_gateway FROM physical_interfaces ORDER BY id").fetchall()
        columns = {row[1] for row in connection.execute("PRAGMA table_info(physical_interfaces)").fetchall()}
        connection.close()
    finally:
        migrated_engine.dispose()
        database.engine = previous_engine

    assert rows == [(1, 1, None), (2, 0, None), (3, 0, None)]
    assert "gateway" in columns
    assert "ipv6_gateway" in columns


def test_appliance_settings_migration_adds_disabled_vmware_ceip_without_copying_vcfdt_choice(tmp_path):
    from labfoundry.app import database

    db_path = tmp_path / "legacy-ceip.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE appliance_settings (id INTEGER PRIMARY KEY)")
    connection.execute("INSERT INTO appliance_settings (id) VALUES (1)")
    connection.execute(
        "CREATE TABLE vcf_offline_depot_settings "
        "(id INTEGER PRIMARY KEY, telemetry_choice VARCHAR(20) DEFAULT 'DISABLE')"
    )
    connection.execute(
        "INSERT INTO vcf_offline_depot_settings (id, telemetry_choice) VALUES (1, 'ENABLE')"
    )
    connection.commit()
    connection.close()

    previous_engine = database.engine
    migrated_engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    try:
        database.engine = migrated_engine
        database._ensure_sqlite_appliance_settings_columns()
        connection = sqlite3.connect(db_path)
        vmware_ceip_enabled = connection.execute(
            "SELECT vmware_ceip_enabled FROM appliance_settings WHERE id = 1"
        ).fetchone()[0]
        legacy_choice = connection.execute(
            "SELECT telemetry_choice FROM vcf_offline_depot_settings WHERE id = 1"
        ).fetchone()[0]
        connection.close()
    finally:
        migrated_engine.dispose()
        database.engine = previous_engine

    assert vmware_ceip_enabled == 0
    assert legacy_choice == "ENABLE"


def test_ldap_listener_migration_adds_protocol_controls_and_ports(tmp_path):
    from labfoundry.app import database

    db_path = tmp_path / "legacy-ldap.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE ldap_settings (id INTEGER PRIMARY KEY, port INTEGER DEFAULT 636)")
    connection.execute("INSERT INTO ldap_settings (id, port) VALUES (1, 1636)")
    connection.commit()
    connection.close()

    previous_engine = database.engine
    migrated_engine = database.create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    try:
        database.engine = migrated_engine
        database._ensure_sqlite_ldap_columns()
        connection = sqlite3.connect(db_path)
        row = connection.execute(
            "SELECT ldaps_enabled, port, ldap_enabled, ldap_port FROM ldap_settings WHERE id = 1"
        ).fetchone()
        columns = {column[1] for column in connection.execute("PRAGMA table_info(ldap_settings)").fetchall()}
        connection.close()
    finally:
        migrated_engine.dispose()
        database.engine = previous_engine

    assert row == (1, 1636, 0, 389)
    assert {"ldaps_enabled", "ldap_enabled", "ldap_port"} <= columns


def test_ca_migration_deduplicates_managed_owners_and_enforces_uniqueness(tmp_path):
    from labfoundry.app import database

    db_path = tmp_path / "legacy-ca.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        CREATE TABLE ca_certificates (
            id INTEGER PRIMARY KEY,
            common_name VARCHAR(180) NOT NULL,
            status VARCHAR(40) NOT NULL,
            certificate_pem TEXT DEFAULT '',
            private_key_encrypted TEXT DEFAULT '',
            managed_owner VARCHAR(120) DEFAULT ''
        )
        """
    )
    connection.execute(
        """
        INSERT INTO ca_certificates (
            id, common_name, status, certificate_pem, private_key_encrypted, managed_owner
        ) VALUES
            (1, 'ldap-old.example.test', 'planned', '', '', 'ldap:ldaps'),
            (2, 'ldap.example.test', 'issued', 'certificate', 'encrypted-key', 'ldap:ldaps'),
            (3, 'manual-one.example.test', 'planned', '', '', ''),
            (4, 'manual-two.example.test', 'planned', '', '', '')
        """
    )
    connection.commit()
    connection.close()

    previous_engine = database.engine
    migrated_engine = database.create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    try:
        database.engine = migrated_engine
        database._ensure_sqlite_ca_columns()
        connection = sqlite3.connect(db_path)
        managed_rows = connection.execute(
            "SELECT id, status FROM ca_certificates WHERE managed_owner = 'ldap:ldaps'"
        ).fetchall()
        manual_count = connection.execute(
            "SELECT COUNT(*) FROM ca_certificates WHERE managed_owner = ''"
        ).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO ca_certificates (
                    common_name, status, certificate_pem, private_key_encrypted, managed_owner
                ) VALUES ('duplicate.example.test', 'planned', '', '', 'ldap:ldaps')
                """
            )
        connection.close()
    finally:
        migrated_engine.dispose()
        database.engine = previous_engine

    assert managed_rows == [(2, "issued")]
    assert manual_count == 2


def test_vcf_trust_target_migration_uses_api_port_uniqueness(tmp_path):
    from labfoundry.app import database

    db_path = tmp_path / "legacy-trust.db"
    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        CREATE TABLE vcf_trust_targets (
            id INTEGER NOT NULL,
            address VARCHAR(240) NOT NULL,
            ssh_port INTEGER NOT NULL,
            appliance_role VARCHAR(40) NOT NULL,
            appliance_version VARCHAR(80) NOT NULL,
            ssh_host_key_fingerprint VARCHAR(160) NOT NULL,
            last_ca_fingerprint VARCHAR(128) NOT NULL,
            last_result VARCHAR(80) NOT NULL,
            last_job_id VARCHAR(40) NOT NULL,
            last_attempted_at DATETIME,
            last_succeeded_at DATETIME,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            CONSTRAINT uq_vcf_trust_target_address_port UNIQUE (address, ssh_port)
        )
        """
    )
    connection.execute("CREATE INDEX ix_vcf_trust_targets_address ON vcf_trust_targets (address)")
    connection.execute(
        """
        INSERT INTO vcf_trust_targets (
            id,
            address,
            ssh_port,
            appliance_role,
            appliance_version,
            ssh_host_key_fingerprint,
            last_ca_fingerprint,
            last_result,
            last_job_id,
            created_at,
            updated_at
        ) VALUES (1, 'vcf.example.test', 22, '', '', '', '', '', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """
    )
    connection.commit()
    connection.close()

    previous_engine = database.engine
    migrated_engine = database.create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    try:
        database.engine = migrated_engine
        database.SessionLocal.configure(bind=migrated_engine)
        database._ensure_sqlite_vcf_trust_columns()

        connection = sqlite3.connect(db_path)
        unique_columns = []
        for index in connection.execute("PRAGMA index_list('vcf_trust_targets')").fetchall():
            if index[2]:
                unique_columns.append(
                    [column[2] for column in connection.execute(f"PRAGMA index_info('{index[1]}')").fetchall()]
                )
        connection.execute(
            """
            INSERT INTO vcf_trust_targets (
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
                created_at,
                updated_at
            ) VALUES ('vcf.example.test', 22, 8443, '', '', '', '', '', '', '', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """
        )
        connection.commit()
        rows_for_host = connection.execute("SELECT COUNT(*) FROM vcf_trust_targets WHERE address='vcf.example.test'").fetchone()[0]
        connection.close()
    finally:
        migrated_engine.dispose()
        database.engine = previous_engine
        database.SessionLocal.configure(bind=previous_engine)

    assert ["address", "api_port"] in unique_columns
    assert rows_for_host == 2
