"""Preserve proxy intent and route relationships through desired-state recovery."""

from copy import deepcopy

import pytest
from sqlalchemy import event, select

from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    AuditEvent,
    EsxStorageSettings,
    LdapRecoveryArchive,
    PhysicalInterface,
    ReverseProxy,
    ReverseProxyRoute,
    Setting,
)
from atlaso.app.services.esxi_pxe import ESXI_PXE_HOSTNAME_KEY
from atlaso.app.services.reverse_proxies import (
    desired_rows,
    save_proxy,
    validate_proxy,
    validation_context,
)
from atlaso.app.services.service_dns_defaults import factory_service_hostname
from atlaso.app.services.settings_archive import (
    export_settings_archive,
    restore_settings_archive,
)
from tests.services.test_reverse_proxies import payload


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("within_budget", [False, True])
def test_restore_checks_publication_with_assigned_ids_atomically(client, monkeypatch, enabled, within_budget):
    """Model advanced database sequences at the actual publication-size boundary.

    Args:
        client: Initialized appliance fixture.
        monkeypatch: Scoped dependency replacements supplied by pytest.
        enabled: Whether the restored proxy publishes a listener.
        within_budget: Whether the budget admits the database-assigned IDs.
    """
    from atlaso.app.services import reverse_proxy_publication as publication
    from atlaso.app.services.ldap import LDAP_PENDING_RECOVERY_PAYLOADS
    from atlaso.app.services.reverse_proxies import publication_snapshot
    from atlaso.app.services.reverse_proxy_archive import candidates

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(scheme="http", port=8084, redirect_http=False,
                               listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        recovery = LdapRecoveryArchive(filename="retained.ldif", path="retained-recovery-fixture",
                                       sha256="a" * 64, created_by="test")
        db.add(recovery)
        db.commit()
        recovery_id = recovery.id
        before = deepcopy(export_settings_archive(db, actor="test")["data"])
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["reverse_proxies"][0].update(enabled=enabled, description="Restored candidate")
        addresses = publication.appliance_addresses(db)
        synthetic = publication_snapshot(candidates(archive["data"]))

        def rendered_size(snapshot):
            """Measure the real publication at the configured test budget.

            Args:
                snapshot: Canonical candidate proxy collection to render.
            """
            return len(publication.render_proxy_servers(
                snapshot, publication.transport_manifest(snapshot, addresses)).encode("utf-8"))

        preflight_size = rendered_size(synthetic)
        assigned = deepcopy(synthetic)
        assigned[0]["id"] = assigned[0]["routes"][0]["id"] = 1000
        assigned_size = rendered_size(assigned)
        assert assigned_size > preflight_size
        monkeypatch.setattr(publication, "MAX_PUBLICATION_BYTES", assigned_size if within_budget else preflight_size)
        recovery_bytes = b"synthetic retained recovery payload"
        monkeypatch.setitem(LDAP_PENDING_RECOVERY_PAYLOADS, recovery_id, recovery_bytes)
        audit_ids = list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id)))

        def assign_advanced_id(_mapper, _connection, row):
            """Simulate a retained database sequence during row insertion.

            Args:
                _mapper: SQLAlchemy mapper invoking the insert event.
                _connection: Transaction connection supplied by SQLAlchemy.
                row: Candidate proxy or route receiving its assigned identity.
            """
            # Exercise the flushed insert path with the IDs a retained sequence
            # could allocate; no PostgreSQL server is required by this fixture.
            row.id = 1000

        for model in (ReverseProxy, ReverseProxyRoute):
            event.listen(model, "before_insert", assign_advanced_id)
        try:
            if within_budget:
                counts = restore_settings_archive(db, archive)
                assert counts["reverse_proxies"] == counts["reverse_proxy_routes"] == 1
                db.expire_all()
                restored = db.scalar(select(ReverseProxy))
                assert restored.id == restored.routes[0].id == 1000
                assert restored.description == "Restored candidate" and restored.enabled is enabled
                assert recovery_id not in LDAP_PENDING_RECOVERY_PAYLOADS
            else:
                with pytest.raises(ValueError, match="generated configuration size bound"):
                    restore_settings_archive(db, archive)
                db.expire_all()
                assert export_settings_archive(db, actor="test")["data"] == before
                assert list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id))) == audit_ids
                assert db.get(LdapRecoveryArchive, recovery_id).filename == "retained.ldif"
                assert LDAP_PENDING_RECOVERY_PAYLOADS[recovery_id] == recovery_bytes
        finally:
            for model in (ReverseProxy, ReverseProxyRoute):
                event.remove(model, "before_insert", assign_advanced_id)


def test_archive_rejects_different_ingress_scopes_on_shared_proxy_socket(client):
    """Reject shared-socket scope differences before replacing any saved section.

    Args:
        client: Initialized appliance test fixture.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        address = interface.ip_cidr.split("/")[0]
        db.add(PhysicalInterface(
            name="eth3", mac_address="02:00:00:00:00:04", admin_state="up", oper_state="up",
            role="access", mode="access", ip_cidr=interface.ip_cidr,
        ))
        db.commit()
        for name, target, port in (("First", "eth2", 8084), ("Second", "eth3", 8085)):
            save_proxy(db, payload(name=name, hostname=name.lower() + ".example.test", enabled=True,
                                   scheme="http", port=port, redirect_http=False,
                                   listeners=[{"interface": target, "address": address}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        before = deepcopy(archive["data"])
        second = next(row for row in archive["data"]["reverse_proxies"] if row["name"] == "Second")
        second["port"] = 8084
        before_audits = list(db.scalars(select(AuditEvent.id)))
        with pytest.raises(ValueError, match="identical interface scopes"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert list(db.scalars(select(AuditEvent.id))) == before_audits
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("target", ["served", "upstream"])
@pytest.mark.parametrize("host", ["127.1", "0177.0.0.1", "0x7f.0.0.1"])
def test_archive_rejects_legacy_numeric_names_before_replacement(client, target, host):
    """Reject ambiguous restored names without replacing any saved section.

    Args:
        client: Initialized appliance test fixture.
        target: Served hostname or upstream field in the archive.
        host: Noncanonical numeric address spelling.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        if target == "served":
            archive["data"]["reverse_proxies"][0]["hostname"] = host
        else:
            archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = host
        with pytest.raises(ValueError, match="legacy numeric"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("target", ["served", "upstream"])
@pytest.mark.parametrize("configured", ["Ns1.Example.Test.", ""])
@pytest.mark.parametrize("authoritative", [False, True])
def test_archive_reserves_authoritative_primary_before_replacement(client, target, configured, authoritative):
    """Reject archived nameserver collisions without replacing saved sections.

    Args:
        client: Initialized appliance test fixture.
        target: Served hostname or upstream route that claims the nameserver.
        configured: Explicit primary name or empty value selecting the canonical default.
        authoritative: Active or dormant authoritative settings in the archive.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["dns_settings"][0].update(authoritative=authoritative, domain="example.test", disabled_domains="",
                                                  authoritative_server=configured, authoritative_admin="hostmaster.example.test")
        if target == "served":
            archive["data"]["reverse_proxies"][0]["hostname"] = "ns1.example.test"
        else:
            archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = "ns1.example.test"
        with pytest.raises(ValueError, match="Atlaso.*service"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("hostname", ["APPLICATION.EXAMPLE.TEST", "Application.Example.Test."])
def test_archive_dns_collision_rejects_before_replacement(client, hostname):
    """Preserve all saved sections when archived operator DNS conflicts with a proxy.

    Args:
        client: Initialized appliance test fixture.
        hostname: DNS-equivalent archived operator hostname.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["dns_settings"][0].update(enabled=True, authoritative=True, domain="example.test", disabled_domains="",
                                                  authoritative_server="ns.example.test", authoritative_admin="hostmaster.example.test")
        archive["data"]["reverse_proxies"][0].update(enabled=True, managed_dns=True, scheme="http", port=8080, redirect_http=False)
        archive["data"]["dns_records"].append({"hostname": hostname, "record_type": "A", "address": "192.0.2.50",
                                                "description": "operator", "enabled": True})
        with pytest.raises(ValueError, match="conflicts with an operator"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before


def test_archive_rejects_enabled_https_without_ca_before_replacement(client):
    """Keep every saved section intact when HTTPS cannot recreate its managed leaf.

    Args:
        client: Initialized appliance test fixture.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(port=8443, redirect_http=False, listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["ca_settings"][0]["enabled"] = False
        archive["data"]["reverse_proxies"][0]["enabled"] = True
        with pytest.raises(ValueError, match="requires an enabled CA for HTTPS"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert not db.get(ReverseProxy, saved.id).enabled
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize(("scheme", "enabled"), [("https", False), ("http", True)])
def test_archive_without_ca_preserves_disabled_https_and_enabled_http(client, scheme, enabled):
    """Retain intent that does not need an immediately issuable HTTPS leaf.

    Args:
        client: Initialized appliance test fixture.
        scheme: Archived listener protocol.
        enabled: Archived publication enablement.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        archive["data"]["ca_settings"][0]["enabled"] = False
        archive["data"]["reverse_proxies"][0].update(scheme=scheme, enabled=enabled, port=8080, redirect_http=False)
        restore_settings_archive(db, archive)
        restored = db.scalar(select(ReverseProxy))
        assert restored.enabled is enabled and restored.scheme == scheme


def test_archive_round_trip_uses_names_and_legacy_v2_remains_supported(client):
    """Restore nested routes by stable proxy name and accept pre-proxy archives.

    Args:
        client: Initialized authenticated appliance test client.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        assert archive["data"]["reverse_proxy_routes"][0]["proxy_name"] == saved.name
        assert "proxy_id" not in archive["data"]["reverse_proxy_routes"][0]
        assert "id" not in archive["data"]["reverse_proxies"][0]
        result = restore_settings_archive(db, archive)
        assert result["reverse_proxies"] == result["reverse_proxy_routes"] == 1
        db.expire_all()
        restored = db.scalar(select(ReverseProxy))
        assert restored.routes[0].upstream_host == "10.10.20.30"
        restored_rows = desired_rows(db)
        assert not validate_proxy(
            restored_rows[0],
            validation_context(db),
            restored_rows,
            exclude_id=restored_rows[0].id,
        )
        legacy = deepcopy(archive)
        legacy["data"].pop("reverse_proxies")
        legacy["data"].pop("reverse_proxy_routes")
        result = restore_settings_archive(db, legacy)
        assert result["reverse_proxies"] == result["reverse_proxy_routes"] == 0


def test_archive_round_trip_preserves_network_boot_hostname(client):
    """Retain the public Network Boot hostname as a portable safe setting.

    Args:
        client: Initialized authenticated appliance test client.
    """
    with SessionLocal() as db:
        db.add(Setting(key=ESXI_PXE_HOSTNAME_KEY, value="boot.example.test"))
        db.commit()
        archive = export_settings_archive(db, actor="test")
        assert {row["key"]: row["value"] for row in archive["data"]["settings"]}[ESXI_PXE_HOSTNAME_KEY] == "boot.example.test"

        restore_settings_archive(db, archive)

        restored = db.scalar(select(Setting).where(Setting.key == ESXI_PXE_HOSTNAME_KEY))
        assert restored is not None
        assert restored.value == "boot.example.test"


@pytest.mark.parametrize("target", ["served", "upstream"])
def test_archive_reserves_configured_network_boot_hostname_before_replacement(client, target):
    """Reject archived served and upstream names colliding with Network Boot.

    Args:
        client: Initialized authenticated appliance test client.
        target: Served or upstream hostname relationship under test.
    """
    with SessionLocal() as db:
        db.add(Setting(key=ESXI_PXE_HOSTNAME_KEY, value="boot.example.test"))
        db.commit()
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        if target == "served":
            archive["data"]["reverse_proxies"][0]["hostname"] = "boot.example.test"
        else:
            archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = "boot.example.test"

        with pytest.raises(ValueError, match="Atlaso"):
            restore_settings_archive(db, archive)

        assert db.get(ReverseProxy, saved.id).hostname == "application.example.test"


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("reverse_proxies", "hostname", "APP.EXAMPLE.TEST."),
        ("reverse_proxy_routes", "upstream_host", "UPSTREAM.EXAMPLE.TEST."),
        ("reverse_proxy_routes", "path_prefix", " / "),
    ],
)
def test_archive_rejects_proxy_values_that_schema_would_normalize(
    client, section, field, value
):
    """Fail preflight instead of restoring values that future Apply rejects.

    Args:
        client: Initialized authenticated appliance test client.
        section: Archive section containing the candidate value.
        field: Archived field whose value is under test.
        value: Candidate value to normalize or validate.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        archive_row = archive["data"][section][0]
        archive_row[field] = value

        with pytest.raises(ValueError, match="non-canonical"):
            restore_settings_archive(db, archive)

        db.expire_all()
        assert db.get(ReverseProxy, saved.id).hostname == "application.example.test"


def test_legacy_archive_without_network_boot_hostname_reserves_canonical_default(client):
    """Derive the appliance-domain Network Boot default for older archives.

    Args:
        client: Initialized authenticated appliance test client.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        archive["data"]["settings"] = [
            row for row in archive["data"]["settings"] if row["key"] != ESXI_PXE_HOSTNAME_KEY
        ]
        appliance_fqdn = archive["data"]["appliance_settings"][0]["fqdn"]
        archive["data"]["reverse_proxies"][0]["hostname"] = factory_service_hostname(
            "esxi-pxe", appliance_fqdn
        )

        with pytest.raises(ValueError, match="Atlaso"):
            restore_settings_archive(db, archive)

        assert db.get(ReverseProxy, saved.id).hostname == "application.example.test"


@pytest.mark.parametrize("target", ["served", "upstream"])
def test_archive_reserves_esx_storage_hostname_before_replacement(client, target):
    """Reject archived storage collisions while retaining the saved proxy.

    Args:
        client: Initialized authenticated appliance test client.
        target: Served or upstream hostname relationship under test.
    """
    with SessionLocal() as db:
        storage = db.scalar(select(EsxStorageSettings))
        if storage is None:
            storage = EsxStorageSettings(hostname="nfs.atlaso.internal")
            db.add(storage)
            db.commit()
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        if target == "served":
            archive["data"]["reverse_proxies"][0]["hostname"] = storage.hostname
        else:
            archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = storage.hostname
        with pytest.raises(ValueError, match="Atlaso"):
            restore_settings_archive(db, archive)
        assert db.get(ReverseProxy, saved.id).hostname == "application.example.test"


@pytest.mark.parametrize("corruption", ["missing_owner", "credentials", "reserved_path", "mixed_protocol", "position"])
def test_invalid_proxy_archive_preserves_saved_state(client, corruption):
    """Reject invalid route ownership and traffic intent before deleting current rows.

    Args:
        client: Initialized authenticated appliance test client.
        corruption: Parameterized invalid archive relationship.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        route = archive["data"]["reverse_proxy_routes"][0]
        if corruption == "missing_owner":
            route["proxy_name"] = "absent"
        elif corruption == "credentials":
            route["upstream_host"] = "https://user:password@app.example.test"
        elif corruption == "reserved_path":
            route["path_prefix"] = "/api/"
        elif corruption == "position":
            route["position"] = 8
        else:
            archive["data"]["reverse_proxies"][0].update(scheme="http", redirect_http=True)
        with pytest.raises(ValueError):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert db.get(ReverseProxy, saved.id).routes[0].path_prefix == "/"


@pytest.mark.parametrize(
    ("field", "cidr", "upstream"),
    [("host_ip_cidr", "192.0.2.99/24", "192.0.2.99"),
     ("host_ipv6_cidr", "2001:db8::99/64", "2001:db8::99")],
)
def test_archive_rejects_observed_appliance_upstream_before_replacement(client, field, cidr, upstream):
    """Preserve all saved state when an upstream loops to an observed address.

    Args:
        client: Initialized appliance test fixture.
        field: Archived physical observed-address field.
        cidr: Observed interface address including prefix.
        upstream: Route destination equal to that observed appliance address.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        original = export_settings_archive(db, actor="test")
        archive = deepcopy(original)
        row = next(row for row in archive["data"]["physical_interfaces"] if row["name"] == "eth2")
        row[field] = cidr
        archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = upstream
        with pytest.raises(ValueError, match="appliance"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert db.get(ReverseProxy, saved.id).routes[0].upstream_host == "10.10.20.30"
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("target", ["served", "upstream"])
def test_archive_reserves_migrated_factory_names_atomically(client, target):
    """Reject every factory migration collision before replacing archived rows.

    Args:
        client: Initialized appliance fixture.
        target: Served hostname or upstream position claiming the migrated identity.
    """
    from atlaso.app.services.service_dns_defaults import FACTORY_SERVICE_IDENTITIES

    with SessionLocal() as db:
        for identity in FACTORY_SERVICE_IDENTITIES:
            if db.scalar(select(identity.model)) is None:
                db.add(identity.model())
        db.commit()
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        for identity in [*FACTORY_SERVICE_IDENTITIES, None]:
            archive = deepcopy(export_settings_archive(db, actor="test"))
            data = archive["data"]
            data["appliance_settings"][0]["fqdn"] = "core.example.test"
            label = identity.label if identity else "esxi-pxe"
            if identity:
                data[identity.model.__tablename__][0][identity.hostname_attribute] = f"{label.upper()}.ATLASO.INTERNAL."
            else:
                data["settings"] = [row for row in data["settings"] if row["key"] != ESXI_PXE_HOSTNAME_KEY]
                data["settings"].append({"key": ESXI_PXE_HOSTNAME_KEY, "value": "ESXI-PXE.ATLASO.INTERNAL."})
            if target == "served":
                data["reverse_proxies"][0]["hostname"] = f"{label}.example.test"
            else:
                data["reverse_proxy_routes"][0]["upstream_host"] = f"{label}.example.test"
            with pytest.raises(ValueError, match="Atlaso.*service"):
                restore_settings_archive(db, archive)
            db.expire_all()
            assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("label", ["ntp", "ca", "kms", "ldap", "oidc", "nfs", "registry", "depot", "esxi-pxe"])
def test_factory_projection_preserves_operator_names(label):
    """Keep custom service names while projecting canonical factory migration.

    Args:
        label: Canonical factory-owned service label.
    """
    from atlaso.app.services.service_dns_defaults import (
        projected_factory_service_hostname,
    )

    assert projected_factory_service_hostname(label, f"{label.upper()}.ATLASO.INTERNAL.", "core.example.test") == f"{label}.example.test"
    assert projected_factory_service_hostname(label, "custom.operator.test", "core.example.test") == "custom.operator.test"
    assert projected_factory_service_hostname(label, f"{label}.atlaso.internal", "") == f"{label}.atlaso.internal"


def test_archive_allows_unclaimed_factory_target_for_operator_identity(client):
    """Restore a proxy at a factory target when the service retains a custom name.

    Args:
        client: Initialized appliance fixture.
    """
    from atlaso.app.models import NtpSettings

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        archive["data"]["appliance_settings"][0]["fqdn"] = "core.example.test"
        archive["data"]["ntp_settings"][0]["hostname"] = "custom.operator.test"
        archive["data"]["reverse_proxies"][0]["hostname"] = "ntp.example.test"
        restore_settings_archive(db, archive)
        db.expire_all()
        assert db.scalar(select(NtpSettings)).hostname == "custom.operator.test"
        assert db.scalar(select(ReverseProxy)).hostname == "ntp.example.test"


@pytest.mark.parametrize("count", [64, 256])
def test_archive_preflights_combined_unicode_publication_before_replacement(client, count):
    """Accept bounded intent and reject oversized metadata before any restore write.

    Args:
        client: Initialized appliance fixture.
        count: Number of individually valid disabled proxies in the archive.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        proxy_template = archive["data"]["reverse_proxies"][0]
        route_template = archive["data"]["reverse_proxy_routes"][0]
        archive["data"]["reverse_proxies"] = []
        archive["data"]["reverse_proxy_routes"] = []
        for index in range(count):
            name = f"Archived {index}"
            archive["data"]["reverse_proxies"].append({
                **proxy_template, "name": name, "hostname": f"archive-{index}.example.test",
                "enabled": False, "description": "界" * 1000,
            })
            archive["data"]["reverse_proxy_routes"].append({
                **route_template, "proxy_name": name, "path_prefix": "/" + "界" * 1023,
            })
        audits = list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id)))
        if count == 256:
            with pytest.raises(ValueError, match="generated configuration size bound"):
                restore_settings_archive(db, archive)
            db.expire_all()
            assert list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id))) == audits
            assert export_settings_archive(db, actor="test")["data"] == before
        else:
            result = restore_settings_archive(db, archive)
            assert result["reverse_proxies"] == result["reverse_proxy_routes"] == count
            assert all(not row.enabled for row in desired_rows(db))


@pytest.mark.parametrize("naming", ["ip", "interface"])
@pytest.mark.parametrize("service_section", ["ntp_settings", "kms_settings"])
def test_archive_reserves_projected_service_alias_before_replacement(client, naming, service_section):
    """Reject generated aliases from archived desired state before replacing any section.

    Args:
        client: Initialized appliance test fixture.
        naming: Archived service target naming strategy.
        service_section: Archived service whose binding supplies the generated alias.
    """
    from atlaso.app.services.service_dns_names import (
        service_dns_target_token,
        service_target_hostname,
    )

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        address = interface.ip_cidr.split("/")[0]
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": address}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["appliance_settings"][0]["service_dns_target_naming"] = naming
        service = archive["data"][service_section][0]
        service.update(hostname="owned.example.test", listen_interface="eth2", listen_address=address)
        token = "service" if service_section == "ntp_settings" else service_dns_target_token(naming, "eth2", address)
        archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = service_target_hostname(service["hostname"], token)
        audit_ids = list(db.scalars(select(AuditEvent.id)))
        with pytest.raises(ValueError, match="Atlaso.*service"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert list(db.scalars(select(AuditEvent.id))) == audit_ids
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("target", ["served", "upstream"])
def test_archive_reserves_retained_service_dns_alias(client, target):
    """Reserve archived generated records without replacing current state.

    Args:
        client: Initialized appliance test fixture.
        target: Served hostname or upstream route claiming the retained alias.
    """
    from atlaso.app.services.service_dns_defaults import NTP_DNS_DESCRIPTION

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        record = archive["data"]["dns_records"][0]
        record.update(hostname="ntp-192-168-1-10.example.test", description=NTP_DNS_DESCRIPTION)
        if target == "served":
            archive["data"]["reverse_proxies"][0]["hostname"] = record["hostname"]
        else:
            archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = record["hostname"]
        with pytest.raises(ValueError, match="Atlaso.*service"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("address", ["192.168.49.10", "2001:db8:49::10"])
@pytest.mark.parametrize(("scheme", "port", "redirect"), [("http", 80, False), ("https", 443, False), ("https", 9443, True)])
def test_archive_rejects_management_socket_scope_mismatch(client, address, scheme, port, redirect):
    """Project archived management ingress before replacing desired state.

    Args:
        client: Initialized appliance fixture.
        address: Shared IPv4 or IPv6 destination in the candidate archive.
        scheme: Candidate proxy protocol.
        port: Candidate primary port.
        redirect: Whether conflict uses its HTTP redirect socket.
    """
    with SessionLocal() as db:
        access = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8:49::10/64"
        access.ip_cidr = "192.168.49.10/24"
        from atlaso.app.models import CaSettings

        db.scalar(select(CaSettings)).enabled = True
        db.commit()
        save_proxy(db, payload(enabled=True, scheme=scheme, port=9444, redirect_http=False,
                               listeners=[{"interface": "eth2", "address": address}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        before = deepcopy(archive["data"])
        management = next(row for row in archive["data"]["physical_interfaces"] if row["role"] == "management")
        management["ip_cidr"] = "192.168.49.10/24"
        management["ipv6_enabled"] = True
        management["ipv6_cidr"] = "2001:db8:49::10/64"
        # This archive deliberately permits duplicate addresses; proxy socket
        # ownership still must not inherit another interface's management scope.
        for interface in archive["data"]["physical_interfaces"]:
            interface["check_duplicate_ip_addresses"] = False
        proxy = archive["data"]["reverse_proxies"][0]
        proxy.update(port=port, redirect_http=redirect)
        audits = list(db.scalars(select(AuditEvent.id)))
        with pytest.raises(ValueError, match="exclusive Atlaso service socket"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert list(db.scalars(select(AuditEvent.id))) == audits
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("upstream", ["2001:db8:55::10", "2001:db8:55::20"])
def test_restore_checks_complete_target_ipv6_inventory_before_replacement(client, enabled, upstream):
    """Reject foreign archive upstreams matching any current automatic target address.

    Args:
        client: Initialized appliance fixture.
        enabled: Enabled publication or retained disabled proxy intent.
        upstream: First or secondary observed IPv6 address omitted from the archive.
    """
    with SessionLocal() as db:
        observed = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        observed.ipv6_enabled = True
        observed.ipv6_cidr = None
        observed.host_ipv6_cidr = None
        observed.host_ipv6_cidrs = ["2001:db8:55::10/64", "2001:db8:55::20/64"]
        db.commit()
        listener = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(enabled=enabled, scheme="http", port=8084, redirect_http=False,
                                       listeners=[{"interface": "eth2", "address": listener.ip_cidr.split("/")[0]}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        before = deepcopy(archive["data"])
        audits = list(db.scalars(select(AuditEvent.id)))
        for interface in archive["data"]["physical_interfaces"]:
            assert "host_ipv6_cidrs" not in interface
            interface["host_ipv6_cidr"] = None
        archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = upstream
        with pytest.raises(ValueError, match="observed target appliance address"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before
        assert list(db.scalars(select(AuditEvent.id))) == audits
        assert db.get(ReverseProxy, saved.id).routes[0].upstream_host == "10.10.20.30"
        assert db.get(PhysicalInterface, observed.id).host_ipv6_cidrs == ["2001:db8:55::10/64", "2001:db8:55::20/64"]


def test_restore_allows_external_ipv6_upstream_with_target_observations(client):
    """Keep an external upstream admissible while target automatic addresses exist.

    Args:
        client: Initialized appliance fixture.
    """
    with SessionLocal() as db:
        observed = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        observed.host_ipv6_cidrs = ["2001:db8:55::10/64", "2001:db8:55::20/64"]
        db.commit()
        listener = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(enabled=True, scheme="http", port=8084, redirect_http=False,
                               listeners=[{"interface": "eth2", "address": listener.ip_cidr.split("/")[0]}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = "2001:db8:99::55"
        restore_settings_archive(db, archive)
        restored = db.scalar(select(ReverseProxy))
        assert restored.enabled and restored.routes[0].upstream_host == "2001:db8:99::55"


@pytest.mark.parametrize("address", ["192.168.49.10", "2001:db8:49::10"])
def test_restore_rejects_independent_terminal_scope(client, address):
    """Reject cross-scope terminal HTTPS before replacing any archived state.

    Args:
        client: Initialized appliance fixture.
        address: Duplicate IPv4 or IPv6 destination.
    """
    import json

    from atlaso.app import ui
    from atlaso.app.models import ApplianceSettings, CaSettings

    with SessionLocal() as db:
        listener = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        listener.ip_cidr = "192.168.49.10/24"
        listener.ipv6_enabled = True
        listener.ipv6_cidr = "2001:db8:49::10/64"
        db.scalar(select(CaSettings)).enabled = True
        db.scalar(select(ApplianceSettings)).management_https_enabled = True
        db.commit()
        assert ui.ensure_ca_state(db) == []
        save_proxy(db, payload(enabled=True, port=9444, redirect_http=False,
                               listeners=[{"interface": "eth2", "address": address}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        before = deepcopy(archive["data"])
        other = archive["data"]["vlan_interfaces"][0]
        other.update(role="access", enabled=True, ip_cidr="192.168.49.10/24", ipv6_cidr="2001:db8:49::10/64")
        other["check_duplicate_ip_addresses"] = False
        for interface in archive["data"]["physical_interfaces"]:
            interface["check_duplicate_ip_addresses"] = False
        settings = archive["data"]["appliance_settings"][0]
        settings.update(management_https_enabled=True, web_terminal_enabled=True, web_terminal_interfaces_json=json.dumps([other["name"]]))
        archive["data"]["reverse_proxies"][0]["port"] = 443
        audits = list(db.scalars(select(AuditEvent.id)))
        with pytest.raises(ValueError, match="exclusive Atlaso service socket"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert list(db.scalars(select(AuditEvent.id))) == audits
        assert export_settings_archive(db, actor="test")["data"] == before


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("assigned_id", [0xFFFFFF, 0x1000000])
def test_restore_checks_assigned_proxy_identity_capacity_atomically(client, monkeypatch, enabled, assigned_id):
    """Enforce the helper identity limit after database assignment before committing.

    Args:
        client: Initialized appliance fixture.
        monkeypatch: Scoped dependency replacements supplied by pytest.
        enabled: Whether the restored proxy publishes a listener.
        assigned_id: Last supported identity or first unsupported identity.
    """
    from atlaso.app.services import reverse_proxy_publication as publication
    from atlaso.app.services.ldap import LDAP_PENDING_RECOVERY_PAYLOADS
    from atlaso.app.services.reverse_proxies import publication_snapshot
    from atlaso.app.services.reverse_proxy_archive import candidates

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(scheme="http", port=8084, redirect_http=False,
                               listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        recovery = LdapRecoveryArchive(filename="retained.ldif", path="retained-recovery-fixture",
                                       sha256="a" * 64, created_by="test")
        db.add(recovery)
        db.commit()
        recovery_id = recovery.id
        before = deepcopy(export_settings_archive(db, actor="test")["data"])
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["reverse_proxies"][0].update(enabled=enabled, description="Restored candidate")
        addresses = publication.appliance_addresses(db)
        synthetic = publication_snapshot(candidates(archive["data"]))

        def rendered_size(snapshot):
            """Measure the real publication at the configured test budget.

            Args:
                snapshot: Canonical candidate proxy collection to render.
            """
            return len(publication.render_proxy_servers(
                snapshot, publication.transport_manifest(snapshot, addresses)).encode("utf-8"))

        preflight_size = rendered_size(synthetic)
        assigned = deepcopy(synthetic)
        assigned[0]["id"] = assigned[0]["routes"][0]["id"] = assigned_id
        assigned_size = rendered_size(assigned)
        assert assigned_size > preflight_size
        monkeypatch.setattr(publication, "MAX_PUBLICATION_BYTES", max(assigned_size, preflight_size) + 10000)
        recovery_bytes = b"synthetic retained recovery payload"
        monkeypatch.setitem(LDAP_PENDING_RECOVERY_PAYLOADS, recovery_id, recovery_bytes)
        audit_ids = list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id)))

        def assign_advanced_id(_mapper, _connection, row):
            """Simulate a retained database sequence during row insertion.

            Args:
                _mapper: SQLAlchemy mapper invoking the insert event.
                _connection: Transaction connection supplied by SQLAlchemy.
                row: Candidate proxy or route receiving its assigned identity.
            """
            # Exercise the flushed insert path with the IDs a retained sequence
            # could allocate; no PostgreSQL server is required by this fixture.
            row.id = assigned_id

        for model in (ReverseProxy, ReverseProxyRoute):
            event.listen(model, "before_insert", assign_advanced_id)
        try:
            if assigned_id <= 0xFFFFFF:
                counts = restore_settings_archive(db, archive)
                assert counts["reverse_proxies"] == counts["reverse_proxy_routes"] == 1
                db.expire_all()
                restored = db.scalar(select(ReverseProxy))
                assert restored.id == restored.routes[0].id == assigned_id
                assert restored.description == "Restored candidate" and restored.enabled is enabled
                assert recovery_id not in LDAP_PENDING_RECOVERY_PAYLOADS
            else:
                with pytest.raises(ValueError, match="identity capacity is exhausted"):
                    restore_settings_archive(db, archive)
                db.expire_all()
                assert export_settings_archive(db, actor="test")["data"] == before
                assert list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id))) == audit_ids
                assert db.get(LdapRecoveryArchive, recovery_id).filename == "retained.ldif"
                assert LDAP_PENDING_RECOVERY_PAYLOADS[recovery_id] == recovery_bytes
        finally:
            for model in (ReverseProxy, ReverseProxyRoute):
                event.remove(model, "before_insert", assign_advanced_id)


@pytest.mark.parametrize("availability", ["down", "missing", "unaddressed"])
@pytest.mark.parametrize("target", ["served", "upstream"])
def test_archive_reserves_dormant_interface_named_storage_alias(client, availability, target):
    """Reserve deterministic share names in portable candidates before replacement.

    Args:
        client: Initialized appliance fixture.
        availability: Candidate interface unavailable state.
        target: Proxy hostname or upstream using the reserved alias.
    """
    from atlaso.app.models import (
        ApplianceSettings,
        EsxNfsShare,
        EsxStorageSettings,
        EsxStorageVolume,
    )
    from atlaso.app.services.esx_storage import target_hostname, target_token

    with SessionLocal() as db:
        db.scalar(select(ApplianceSettings)).service_dns_target_naming = "interface"
        storage = db.scalar(select(EsxStorageSettings))
        if storage is None:
            storage = EsxStorageSettings()
            db.add(storage)
        storage.hostname, storage.enabled = "nfs.example.test", False
        volume = EsxStorageVolume(name="dormant", stable_device_id="dormant")
        db.add(volume)
        db.flush()
        db.add(EsxNfsShare(datastore_name="dormant", volume_id=volume.id, interface_name="eth2", enabled=False))
        db.commit()
        listener = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(enabled=False, listeners=[{"interface": "eth2", "address": listener.ip_cidr.split("/")[0]}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        before = deepcopy(archive["data"])
        audits = list(db.scalars(select(AuditEvent.id)))
        interface = next(row for row in archive["data"]["physical_interfaces"] if row["name"] == "eth2")
        if availability == "unaddressed":
            interface.update(ip_cidr=None, ipv6_cidr=None, host_ip_cidr=None, host_ipv6_cidr=None)
        elif availability == "down":
            interface["admin_state"] = "down"
        else:
            interface["oper_state"] = "missing"
        alias = target_hostname(storage.hostname, target_token("", "interface", "eth2"))
        if target == "served":
            archive["data"]["reverse_proxies"][0]["hostname"] = alias
        else:
            archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = alias
        with pytest.raises(ValueError, match="Atlaso.*service"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before
        assert list(db.scalars(select(AuditEvent.id))) == audits


@pytest.mark.parametrize("enabled", [False, True])
def test_restore_rejects_secondary_observed_ipv4_upstream(client, enabled):
    """Exclude plural IPv4 observations from archives while protecting the live target.

    Args:
        client: Initialized appliance fixture.
        enabled: Enabled publication or disabled saved intent.
    """
    with SessionLocal() as db:
        observed = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        observed.host_ip_cidrs = ["192.168.55.10/24", "192.168.55.20/24"]
        db.commit()
        listener = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(enabled=enabled, scheme="http", port=8084, redirect_http=False,
                                       listeners=[{"interface": "eth2", "address": listener.ip_cidr.split("/")[0]}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        before = deepcopy(archive["data"])
        audits = list(db.scalars(select(AuditEvent.id)))
        assert all("host_ip_cidrs" not in row for row in archive["data"]["physical_interfaces"])
        archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = "192.168.55.20"
        with pytest.raises(ValueError, match="observed target appliance address"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before
        assert list(db.scalars(select(AuditEvent.id))) == audits
        assert db.get(ReverseProxy, saved.id).routes[0].upstream_host == "10.10.20.30"
        assert observed.host_ip_cidrs == ["192.168.55.10/24", "192.168.55.20/24"]


@pytest.mark.parametrize(("kind", "redirect"), [("management", False), ("management", True),
                                                   ("flagged", False), ("flagged", True),
                                                   ("terminal", False), ("enable_terminal", False), ("rename_terminal", False),
                                                   ("matching_terminal", False), ("disabled_proxy", False),
                                                   ("applied_management", False), ("applied_management", True)])
@pytest.mark.parametrize("family", [4, 6])
def test_restore_checks_target_observed_browser_socket_scopes(client, kind, family, redirect):
    """Reject nonportable target scope conflicts before any desired-state replacement.

    Args:
        client: Initialized appliance fixture.
        kind: Current management/terminal exposure or terminal enabled only by the archive.
        family: Secondary observed IPv4 or automatic IPv6 address.
        redirect: HTTP redirect conflict for management, or HTTPS primary for terminal.
    """
    import json

    from atlaso.app import ui
    from atlaso.app.models import ApplianceSettings, CaSettings
    from atlaso.app.services.networking import render_network_config

    address = "192.168.55.20" if family == 4 else "2001:db8:55::20"
    with SessionLocal() as db:
        source = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        if kind != "management":
            source = PhysicalInterface(name="eth9", mac_address="02:00:00:00:00:99", role="access", mode="access",
                                       admin_state="up", oper_state="up", ip_cidr="192.168.55.10/24",
                                       access_management_ui_enabled=kind == "flagged")
            db.add(source)
        source.check_duplicate_ip_addresses = False
        source.host_ip_cidrs = ["192.168.55.10/24", "192.168.55.20/24"]
        source.ipv6_enabled, source.ipv6_cidr = True, None
        source.host_ipv6_cidrs = ["2001:db8:55::10/64", "2001:db8:55::20/64"]
        listener = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        listener.ip_cidr, listener.ipv6_cidr = "192.168.55.20/24", "2001:db8:55::20/64"
        listener.ipv6_enabled, listener.check_duplicate_ip_addresses = True, False
        settings = db.scalar(select(ApplianceSettings))
        settings.management_https_enabled = True
        settings.web_terminal_enabled = kind in {"terminal", "disabled_proxy"}
        settings.web_terminal_interfaces_json = json.dumps([source.name])
        db.scalar(select(CaSettings)).enabled = True
        if kind == "applied_management":
            source.role = "management"
            preview = render_network_config(interfaces=[source], vlans=[])
            source.role = "access"
            baseline = db.scalar(select(Setting).where(Setting.key == "appliance_apply.baselines.v1"))
            if baseline is None:
                baseline = Setting(key="appliance_apply.baselines.v1")
                db.add(baseline)
            baseline.value = json.dumps({"network": {"config_preview": preview}})
        db.commit()
        assert ui.ensure_ca_state(db) == []
        saved = save_proxy(db, payload(enabled=True, port=9444, redirect_http=False,
                                       listeners=[{"interface": "eth2", "address": address}]), actor="test")
        archive = deepcopy(export_settings_archive(db, actor="test"))
        before = deepcopy(archive["data"])
        audits = list(db.scalars(select(AuditEvent.id)))
        for row in archive["data"]["physical_interfaces"]:
            assert "host_ip_cidrs" not in row and "host_ipv6_cidrs" not in row
        if kind in {"enable_terminal", "matching_terminal", "rename_terminal"}:
            archive["data"]["appliance_settings"][0]["web_terminal_enabled"] = True
            if kind == "matching_terminal":
                archive["data"]["appliance_settings"][0]["web_terminal_interfaces_json"] = json.dumps([listener.name])
            if family == 6:
                next(row for row in archive["data"]["physical_interfaces"] if row["name"] == source.name)["ipv6_cidr"] = "2001:db8:66::1/64"
        if kind == "rename_terminal":
            next(row for row in archive["data"]["physical_interfaces"] if row["name"] == source.name)["name"] = "eth8"
            archive["data"]["appliance_settings"][0]["web_terminal_interfaces_json"] = json.dumps(["eth8"])
        proxy = archive["data"]["reverse_proxies"][0]
        if kind in {"management", "flagged", "applied_management"} and redirect:
            proxy.update(port=9443, redirect_http=True, redirect_port=80)
        else:
            proxy.update(port=443, redirect_http=False)
        if kind == "disabled_proxy":
            proxy["enabled"] = False
        if kind in {"matching_terminal", "disabled_proxy"}:
            restore_settings_archive(db, archive)
            restored = db.scalar(select(ReverseProxy))
            assert restored.enabled == (kind == "matching_terminal") and restored.port == 443
            assert db.scalar(select(ApplianceSettings)).web_terminal_enabled
            assert all(not row.host_ip_cidrs and not row.host_ipv6_cidrs for row in db.scalars(select(PhysicalInterface)))
            return
        with pytest.raises(ValueError, match="target browser scopes.*exclusive Atlaso service socket"):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert export_settings_archive(db, actor="test")["data"] == before
        assert list(db.scalars(select(AuditEvent.id))) == audits
        assert db.get(ReverseProxy, saved.id).port == 9444
        assert source.host_ip_cidrs == ["192.168.55.10/24", "192.168.55.20/24"]
        assert source.host_ipv6_cidrs == ["2001:db8:55::10/64", "2001:db8:55::20/64"]
