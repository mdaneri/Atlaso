"""Verify an existing vault schema gains service labels without rewriting stored credentials."""

from sqlalchemy import create_engine, inspect, text


def test_legacy_vault_service_upgrade_preserves_all_existing_columns(client):
    """Backfill known imports once while preserving ciphertext, keys, URI order, and timestamps.

    Args:
        client: Fixture initializing the application and its registered models.
    """
    from atlaso.app.database import _reconcile_vault_service_type_column

    engine = create_engine("sqlite:///:memory:")
    try:
        with engine.begin() as connection:
            connection.execute(text("""CREATE TABLE vault_entries (
                id INTEGER PRIMARY KEY, key TEXT NOT NULL, source_type TEXT NOT NULL,
                secret_type TEXT NOT NULL, description TEXT NOT NULL, encrypted_value TEXT NOT NULL,
                uris_json TEXT NOT NULL, updated_at TEXT NOT NULL
            )"""))
            descriptions = [
                ("sddc_manager", "Imported SDDC Manager VCENTER credential for arbitrary.example.test."),
                ("vcf_installer", "Deployment-time password from vcfOperationsSpec.adminUserPassword; may be stale after rotation."),
                ("vcf_installer", "Deployment-time password from vcfAutomationSpec.adminUserPassword; may be stale after rotation."),
                ("vcf_installer", "Imported VCF Installer password from vcfOperationsCollectorSpec.rootUserPassword."),
                ("vcf_installer", "Imported VCF Installer password from vspClusterSpec.systemUserPassword.vmware-system-user."),
                ("sddc_manager", "An edited description without known component metadata"),
                ("manual", "Imported SDDC Manager VCENTER credential for spoofed.example.test."),
            ]
            for index, (source, description) in enumerate(descriptions, 1):
                connection.execute(text("INSERT INTO vault_entries VALUES (:id,:key,:source,'vcf_password',:description,:ciphertext,:uris,:updated)"),
                                   {"id": index, "key": f"vcf.imported.entry_{index}", "source": source,
                                    "description": description, "ciphertext": f"fixture-encrypted-value-{index}",
                                    "uris": '["ssh://operator.example.test","https://operator.example.test"]',
                                    "updated": "2026-11-01T00:00:00"})
            before = [dict(row) for row in connection.execute(text("SELECT * FROM vault_entries ORDER BY id")).mappings()]
            _reconcile_vault_service_type_column(connection)
            after = [dict(row) for row in connection.execute(text("SELECT * FROM vault_entries ORDER BY id")).mappings()]
            assert [row.pop("service_type") for row in after] == [
                "vcenter", "operations", "automation", "operations_collector", "services_runtime", "unknown", "unknown",
            ]
            assert after == before
            column = next(column for column in inspect(connection).get_columns("vault_entries") if column["name"] == "service_type")
            assert not column["nullable"]
            # Later starts must not reinterpret a deliberate operator correction.
            connection.execute(text("UPDATE vault_entries SET service_type = 'nsx' WHERE id = 1"))
            _reconcile_vault_service_type_column(connection)
            assert connection.scalar(text("SELECT service_type FROM vault_entries WHERE id = 1")) == "nsx"
    finally:
        engine.dispose()
