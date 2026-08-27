"""Verify factory-owned service identities follow the appliance domain."""

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def _session_factory():
    from atlaso.app.database import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


def test_fresh_seed_and_lazy_service_defaults_use_appliance_domain(monkeypatch):
    """Fresh and OVF-derived first boot state uses one canonical domain source."""

    monkeypatch.setenv("ATLASO_APPLIANCE_FQDN", "atlaso.lab.internal")

    from atlaso.app.config import get_settings
    from atlaso.app.models import (
        ApplianceSettings,
        CaSettings,
        KmsSettings,
        LdapSettings,
        NtpSettings,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.seed import seed_initial_data
    from atlaso.app.services.esxi_pxe import esxi_pxe_boot_settings
    from atlaso.app.services.oidc import ensure_provider_settings
    from atlaso.app.ui import get_esx_storage_settings_row

    get_settings.cache_clear()
    try:
        with _session_factory()() as db:
            seed_initial_data(db, include_examples=False, commit=False)

            appliance = db.execute(select(ApplianceSettings)).scalar_one()
            assert appliance.fqdn == "atlaso.lab.internal"
            assert db.execute(select(NtpSettings)).scalar_one().hostname == "ntp.lab.internal"
            assert db.execute(select(CaSettings)).scalar_one().portal_hostname == "ca.lab.internal"
            kms = db.execute(select(KmsSettings)).scalar_one()
            assert (kms.hostname, kms.server_certificate) == (
                "kms.lab.internal",
                "kms.lab.internal",
            )
            assert db.execute(select(LdapSettings)).scalar_one().hostname == "ldap.lab.internal"
            registry = db.execute(select(VcfPrivateRegistrySettings)).scalar_one()
            assert (registry.hostname, registry.server_certificate) == (
                "registry.lab.internal",
                "registry.lab.internal",
            )
            depot = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
            assert (depot.hostname, depot.server_certificate) == (
                "depot.lab.internal",
                "depot.lab.internal",
            )

            oidc = ensure_provider_settings(db)
            assert oidc.hostname == "oidc.lab.internal"
            assert oidc.issuer_url == "https://oidc.lab.internal/identity"
            assert get_esx_storage_settings_row(db).hostname == "nfs.lab.internal"
            assert esxi_pxe_boot_settings(db)["hostname"] == "esxi-pxe.lab.internal"
    finally:
        get_settings.cache_clear()


def test_reconcile_factory_identities_preserves_operator_state_and_dns_conflicts():
    """Domain reconciliation touches only proven factory-owned state."""

    from atlaso.app.models import (
        ApplianceSettings,
        CaCertificate,
        DnsRecord,
        EsxStorageSettings,
        LdapSettings,
        OidcProviderSettings,
        Setting,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.seed import seed_initial_data
    from atlaso.app.services.service_dns_defaults import (
        ESX_STORAGE_DNS_DESCRIPTION,
        ESXI_PXE_DNS_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION,
        reconcile_factory_service_identities,
    )

    with _session_factory()() as db:
        seed_initial_data(db, include_examples=False, commit=False)
        appliance = db.execute(select(ApplianceSettings)).scalar_one()
        appliance.fqdn = "atlaso.lab.internal"
        ldap = db.execute(select(LdapSettings)).scalar_one()
        ldap.hostname = "directory.operator.example"
        depot = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        depot.enabled = True
        db.add(
            OidcProviderSettings(
                hostname="oidc.atlaso.internal",
                issuer_url="https://oidc.atlaso.internal/identity",
            )
        )
        db.add(EsxStorageSettings(hostname="nfs.atlaso.internal"))
        db.add(Setting(key="esxi_pxe.boot.hostname", value="esxi-pxe.atlaso.internal"))
        db.add(
            CaCertificate(
                common_name="depot.atlaso.internal",
                subject_alt_names="depot.atlaso.internal\nunchanged.operator.example",
                status="issued",
                managed_owner="vcf_offline_depot:https",
                cert_path="/etc/atlaso/depot.atlaso.internal.crt",
                key_path="/etc/atlaso/depot.atlaso.internal.key",
                chain_path="/etc/atlaso/depot.atlaso.internal-chain.pem",
            )
        )
        db.add_all(
            [
                DnsRecord(
                    hostname="depot.atlaso.internal",
                    record_type="A",
                    address="192.0.2.20",
                    description=VCF_DEPOT_DNS_DESCRIPTION,
                ),
                DnsRecord(
                    hostname="depot.atlaso.internal",
                    record_type="AAAA",
                    address="2001:db8::20",
                    description=VCF_DEPOT_DNS_DESCRIPTION,
                ),
                DnsRecord(
                    hostname="depot-eth2.atlaso.internal",
                    record_type="CNAME",
                    address="depot.atlaso.internal",
                    description=VCF_DEPOT_DNS_DESCRIPTION,
                ),
                DnsRecord(
                    hostname="depot.lab.internal",
                    record_type="A",
                    address="192.0.2.99",
                    description="Operator-owned record",
                ),
                DnsRecord(
                    hostname="manual.atlaso.internal",
                    record_type="A",
                    address="192.0.2.30",
                    description="Operator-owned record",
                ),
                DnsRecord(
                    hostname="nfs.atlaso.internal",
                    record_type="AAAA",
                    address="2001:db8::40",
                    description=ESX_STORAGE_DNS_DESCRIPTION,
                ),
                DnsRecord(
                    hostname="esxi-pxe.atlaso.internal",
                    record_type="A",
                    address="192.0.2.50",
                    description=ESXI_PXE_DNS_DESCRIPTION,
                ),
                DnsRecord(
                    hostname="esxi-pxe.lab.internal",
                    record_type="CNAME",
                    address="operator-target.example",
                    description="Operator-owned record",
                ),
            ]
        )
        db.flush()

        changes = reconcile_factory_service_identities(db)
        db.commit()

        assert changes["vcf_offline_depot"]["dns_conflicts"] == 1
        assert depot.hostname == "depot.lab.internal"
        assert depot.server_certificate == "depot.lab.internal"
        oidc = db.execute(select(OidcProviderSettings)).scalar_one()
        assert oidc.hostname == "oidc.lab.internal"
        assert oidc.issuer_url == "https://oidc.lab.internal/identity"
        assert ldap.hostname == "directory.operator.example"
        certificate = db.execute(
            select(CaCertificate).where(
                CaCertificate.managed_owner == "vcf_offline_depot:https"
            )
        ).scalar_one()
        assert certificate.common_name == "depot.lab.internal"
        assert certificate.subject_alt_names.splitlines() == [
            "depot.lab.internal",
            "unchanged.operator.example",
        ]
        assert certificate.status == "planned"
        assert "depot.lab.internal" in certificate.cert_path

        records = db.execute(select(DnsRecord)).scalars().all()
        keyed = {(row.hostname, row.record_type, row.address, row.description) for row in records}
        assert (
            "depot.lab.internal",
            "A",
            "192.0.2.99",
            "Operator-owned record",
        ) in keyed
        assert not any(
            row.hostname == "depot.atlaso.internal"
            and row.description == VCF_DEPOT_DNS_DESCRIPTION
            for row in records
        )
        assert any(
            row.hostname == "depot.lab.internal"
            and row.record_type == "AAAA"
            and row.address == "2001:db8::20"
            for row in records
        )
        assert any(
            row.hostname == "depot-eth2.lab.internal"
            and row.record_type == "CNAME"
            and row.address == "depot.lab.internal"
            for row in records
        )
        assert any(row.hostname == "manual.atlaso.internal" for row in records)
        assert any(row.hostname == "nfs.lab.internal" for row in records)
        assert any(
            row.hostname == "esxi-pxe.lab.internal"
            and row.record_type == "CNAME"
            and row.description == "Operator-owned record"
            for row in records
        )
        assert not any(
            row.hostname == "esxi-pxe.atlaso.internal"
            and row.description == ESXI_PXE_DNS_DESCRIPTION
            for row in records
        )


def test_factory_reset_seed_restores_coherent_factory_service_domain(monkeypatch):
    """Factory replacement ignores deployment overrides and restores one factory domain."""

    monkeypatch.setenv("ATLASO_APPLIANCE_FQDN", "atlaso.lab.internal")

    from atlaso.app.config import get_settings
    from atlaso.app.models import (
        ApplianceSettings,
        CaSettings,
        KmsSettings,
        LdapSettings,
        NtpSettings,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.seed import seed_initial_data

    get_settings.cache_clear()
    try:
        with _session_factory()() as db:
            seed_initial_data(
                db,
                include_examples=False,
                factory_defaults=True,
                commit=False,
            )

            assert db.execute(select(ApplianceSettings)).scalar_one().fqdn == (
                "core.atlaso.internal"
            )
            assert db.execute(select(NtpSettings)).scalar_one().hostname == (
                "ntp.atlaso.internal"
            )
            assert db.execute(select(CaSettings)).scalar_one().portal_hostname == (
                "ca.atlaso.internal"
            )
            assert db.execute(select(KmsSettings)).scalar_one().hostname == (
                "kms.atlaso.internal"
            )
            assert db.execute(select(LdapSettings)).scalar_one().hostname == (
                "ldap.atlaso.internal"
            )
            assert (
                db.execute(select(VcfPrivateRegistrySettings)).scalar_one().hostname
                == "registry.atlaso.internal"
            )
            assert (
                db.execute(select(VcfOfflineDepotSettings)).scalar_one().hostname
                == "depot.atlaso.internal"
            )
    finally:
        get_settings.cache_clear()


def test_appliance_domain_change_reconciles_only_previous_factory_domain():
    """A later appliance rename recognizes only its immediate factory-derived names."""

    from atlaso.app.models import (
        ApplianceSettings,
        LdapSettings,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.seed import seed_initial_data
    from atlaso.app.services.service_dns_defaults import (
        reconcile_factory_service_identities,
    )

    with _session_factory()() as db:
        seed_initial_data(db, include_examples=False, commit=False)
        appliance = db.execute(select(ApplianceSettings)).scalar_one()
        appliance.fqdn = "atlaso.corp.internal"
        depot = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        depot.hostname = "depot.lab.internal"
        depot.server_certificate = "depot.lab.internal"
        ldap = db.execute(select(LdapSettings)).scalar_one()
        ldap.hostname = "ldap.legacy.example"
        db.flush()

        changes = reconcile_factory_service_identities(
            db,
            previous_appliance_fqdn="atlaso.lab.internal",
        )

        assert changes["vcf_offline_depot"]["new_hostname"] == "depot.corp.internal"
        assert depot.hostname == "depot.corp.internal"
        assert depot.server_certificate == "depot.corp.internal"
        assert ldap.hostname == "ldap.legacy.example"


def test_appliance_settings_autosave_reconciles_factory_service_desired_state(client):
    """A valid appliance-domain change leaves every factory service truthfully pending."""

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        EsxStorageSettings,
        KmsSettings,
        LdapSettings,
        NtpSettings,
        OidcProviderSettings,
        Setting,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.ui import appliance_apply_units
    from tests.routers.ui.helpers import login

    with SessionLocal() as db:
        db.add(
            OidcProviderSettings(
                hostname="oidc.atlaso.internal",
                issuer_url="https://oidc.atlaso.internal/identity",
            )
        )
        db.add(EsxStorageSettings(hostname="nfs.atlaso.internal"))
        db.add(Setting(key="esxi_pxe.boot.hostname", value="esxi-pxe.atlaso.internal"))
        db.commit()

    login(client)
    page = client.get("/settings")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/settings",
        data={
            "fqdn": "atlaso.lab.internal",
            "external_dns_servers": "1.1.1.1\n9.9.9.9",
            "csrf": csrf,
        },
        headers={"X-Atlaso-Autosave": "1"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["fqdn"] == "atlaso.lab.internal"
    with SessionLocal() as db:
        assert db.execute(select(NtpSettings)).scalar_one().hostname == "ntp.lab.internal"
        assert db.execute(select(CaSettings)).scalar_one().portal_hostname == "ca.lab.internal"
        assert db.execute(select(KmsSettings)).scalar_one().hostname == "kms.lab.internal"
        assert db.execute(select(LdapSettings)).scalar_one().hostname == "ldap.lab.internal"
        assert db.execute(select(OidcProviderSettings)).scalar_one().hostname == "oidc.lab.internal"
        assert db.execute(select(EsxStorageSettings)).scalar_one().hostname == "nfs.lab.internal"
        assert (
            db.execute(
                select(Setting).where(Setting.key == "esxi_pxe.boot.hostname")
            ).scalar_one().value
            == "esxi-pxe.lab.internal"
        )
        assert (
            db.execute(select(VcfPrivateRegistrySettings)).scalar_one().hostname
            == "registry.lab.internal"
        )
        assert (
            db.execute(select(VcfOfflineDepotSettings)).scalar_one().hostname
            == "depot.lab.internal"
        )
        units = {unit["id"]: unit for unit in appliance_apply_units(db)}
        for unit_id in {
            "appliance_settings",
            "ca",
            "kms",
            "ldap",
            "ntpd",
            "esxi_pxe",
            "esx_storage",
            "vcf_offline_depot",
            "vcf_private_registry",
        }:
            assert units[unit_id]["changed"] is True


def test_settings_restore_reconciles_legacy_factory_service_domain(client):
    """Archive restore upgrades legacy factory identities without rewriting custom names."""

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        ApplianceSettings,
        DnsRecord,
        LdapSettings,
        OidcProviderSettings,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.services.service_dns_defaults import VCF_DEPOT_DNS_DESCRIPTION
    from tests.routers.ui.helpers import login

    login(client)
    with SessionLocal() as db:
        appliance = db.execute(select(ApplianceSettings)).scalar_one()
        appliance.fqdn = "atlaso.lab.internal"
        ldap = db.execute(select(LdapSettings)).scalar_one()
        ldap.hostname = "directory.operator.example"
        db.add(
            OidcProviderSettings(
                hostname="oidc.atlaso.internal",
                issuer_url="https://oidc.atlaso.internal/identity",
            )
        )
        db.add(
            DnsRecord(
                hostname="depot.atlaso.internal",
                record_type="AAAA",
                address="2001:db8::20",
                description=VCF_DEPOT_DNS_DESCRIPTION,
            )
        )
        db.commit()

    page = client.get("/backup-restore")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    exported = client.post("/backup-restore/export", data={"csrf": csrf})
    assert exported.status_code == 200, exported.text

    restored = client.post(
        "/backup-restore/restore",
        data={"csrf": csrf},
        files={
            "archive_file": (
                "atlaso-settings.json",
                exported.content,
                "application/json",
            )
        },
    )

    assert restored.status_code == 200, restored.text
    with SessionLocal() as db:
        depot = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
        assert depot.hostname == "depot.lab.internal"
        assert depot.server_certificate == "depot.lab.internal"
        oidc = db.execute(select(OidcProviderSettings)).scalar_one()
        assert oidc.hostname == "oidc.lab.internal"
        assert oidc.issuer_url == "https://oidc.lab.internal/identity"
        assert db.execute(select(LdapSettings)).scalar_one().hostname == (
            "directory.operator.example"
        )
        restored_records = db.execute(
            select(DnsRecord).where(
                DnsRecord.description == VCF_DEPOT_DNS_DESCRIPTION
            )
        ).scalars().all()
        assert any(
            row.hostname == "depot.lab.internal"
            and row.record_type == "AAAA"
            and row.address == "2001:db8::20"
            for row in restored_records
        )
