"""Preserve proxy intent and route relationships through desired-state recovery."""

from copy import deepcopy

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    EsxStorageSettings,
    PhysicalInterface,
    ReverseProxy,
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


@pytest.mark.parametrize("target", ["served", "upstream"])
@pytest.mark.parametrize("configured", ["Ns1.Example.Test.", ""])
def test_archive_reserves_authoritative_primary_before_replacement(client, target, configured):
    """Reject archived nameserver collisions without replacing saved sections.

    Args:
        client: Initialized appliance test fixture.
        target: Served hostname or upstream route that claims the nameserver.
        configured: Explicit primary name or empty value selecting the canonical default.
    """
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        before = export_settings_archive(db, actor="test")["data"]
        archive = deepcopy(export_settings_archive(db, actor="test"))
        archive["data"]["dns_settings"][0].update(authoritative=True, domain="example.test", disabled_domains="",
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
