"""Exercise generated DNS capture during Network Apply."""

import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from tests.routers.ui.helpers import login


def test_partial_dns_baseline_compares_served_records_and_keeps_manual_edits_pending(client):
    """A readback baseline converges despite projection order and display summary.

    Args:
        client: Seeded application client.
    """
    from atlaso.app import ui

    prior = "listen-address=127.0.0.1\nhost-record=b.example.internal,192.0.2.2\nhost-record=a.example.internal,192.0.2.1\n"
    baseline = {"config_preview": prior, "config_path": "/etc/dnsmasq.conf", "snapshot_hash": "legacy"}
    kwargs = dict(unit_id="dnsmasq", label="DNS", page_url="/dns", context={},
                  summary=["Generated address reconciliation"], validation_errors=[],
                  config_path="/etc/dnsmasq.conf", baseline=baseline)
    ordered = "listen-address=127.0.0.1\nhost-record=a.example.internal,192.0.2.1\nhost-record=b.example.internal,192.0.2.2\n"
    assert ui.make_appliance_apply_unit(config_preview=ordered, **kwargs)["changed"] is False
    assert ui.make_appliance_apply_unit(config_preview=ordered + "txt-record=manual.example.internal,pending\n", **kwargs)["changed"] is True


@pytest.mark.parametrize("service", ["ntpd", "ldap", "kms"])
def test_listener_baseline_projection_preserves_pending_non_listener_fields(client, service):
    """Successful narrow rewrites advance applied addresses without applying edits.

    Args:
        client: Seeded application client.
        service: Applied native listener service.
    """
    from atlaso.app import ui

    old, new = "192.0.2.10", "192.0.2.11"
    if service == "ntpd":
        prior = f"# Atlaso NTP listen addresses: {old}\ninterface listen {old}\nserver applied.example.internal"
        desired = prior.replace(old, new)
        pending = desired.replace("applied.example.internal", "pending.example.internal")
    elif service == "kms":
        prior = json.dumps({"listen": {"addresses": [old], "port": 5696}, "policy": "applied"}, indent=2, sort_keys=True)
        desired = prior.replace(old, new)
        pending = desired.replace('"applied"', '"pending"')
    else:
        prior = json.dumps({"service": {"listen_address": old, "hostname": "applied"}, "organizations": []}, indent=2, sort_keys=True)
        desired = prior.replace(old, new)
        pending = desired.replace('"applied"', '"pending"')
    kwargs = dict(unit_id=service, label=service, page_url="/service", context={}, summary=["applied"],
                  validation_errors=[], config_path="/service/config", snapshot_marker={"credential": "applied"})
    original = ui.make_appliance_apply_unit(config_preview=prior, baseline=None, **kwargs)
    baseline = {key: original[key] for key in ("snapshot_hash", "snapshot_marker", "config_preview", "config_path", "summary")}
    projected = ui.projected_handoff_listener_baselines({service: baseline}, {service: original},
                                                       [{"service": service, "old_address": old, "new_address": new}])[service]
    assert projected["config_preview"] == desired
    assert ui.make_appliance_apply_unit(config_preview=desired, baseline=projected, **kwargs)["changed"] is False
    assert ui.make_appliance_apply_unit(config_preview=pending, baseline=projected, **kwargs)["changed"] is True
    legacy = {key: value for key, value in baseline.items() if key != "snapshot_marker"}
    changed_marker_unit = {**original, "snapshot_marker": {"credential": "pending"}}
    legacy_projected = ui.projected_handoff_listener_baselines({service: legacy}, {service: changed_marker_unit},
                                                              [{"service": service, "old_address": old, "new_address": new}])[service]
    assert legacy_projected["snapshot_marker"] != changed_marker_unit["snapshot_marker"]


def test_dynamic_binding_refresh_requires_complete_assigned_native_address(client, monkeypatch):
    """DHCP/SLAAC publication uses verified host readback rather than saved intent.

    Args:
        client: Seeded application client.
        monkeypatch: Native inventory adapter substitutions.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        from atlaso.app.models import PhysicalInterface

        db.add(PhysicalInterface(name="inactive-dhcp", role="unused", mode="access", admin_state="down",
                                 ipv4_method="dhcp", ipv6_enabled=True, mac_address="02:00:00:00:00:99"))
        db.add(PhysicalInterface(name="unrelated-dhcp", role="unused", mode="access", admin_state="up",
                                 ipv4_method="dhcp", ipv6_enabled=True, mac_address="02:00:00:00:00:98"))
        access.ipv4_method = "dhcp"
        access.ip_cidr = None
        access.ipv6_cidr = None
        db.flush()
        network = next(unit for unit in ui.appliance_apply_units(db) if unit["id"] == "network")
        host = SimpleNamespace(name="eth9", mac_address=access.mac_address,
                               host_ip_cidr="192.0.2.21/24", host_ipv6_cidr="2001:db8::21/64")
        monkeypatch.setattr(ui, "discover_host_physical_interfaces", lambda: [host])
        link = {"name": "eth9", "configured": True, "address_inventory_complete": True,
                "addresses": [{"address": "192.0.2.21", "state": "assigned"},
                              {"address": "2001:db8::21", "state": "assigned"}]}
        evidence = {"service_address_observation": {"complete": True, "links": [link]}}
        ui.refresh_service_dns_effective_observations(db, network["raw_config_preview"], evidence, source_interfaces={"eth9"})
        assert access.host_ip_cidr == "192.0.2.21/24"
        assert access.host_ipv6_cidr == "2001:db8::21/64"
        host.host_ip_cidr = "192.0.2.99/24"
        with pytest.raises(ValueError, match="confirm IPv4"):
            ui.refresh_service_dns_effective_observations(db, network["raw_config_preview"], evidence, source_interfaces={"eth9"})


def _prepare_service_address_baseline(db, ui):
    """Record applied Network and generated DNS state for an access interface.

    Args:
        db: Active seeded test database session.
        ui: Appliance UI module that owns Apply unit and baseline helpers.
    """
    from atlaso.app.models import (
        CaSettings,
        DnsRecord,
        DnsSettings,
        NtpSettings,
        PhysicalInterface,
        User,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.services.service_dns_defaults import (
        CA_PORTAL_DNS_DESCRIPTION,
        NTP_DNS_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION,
    )

    management = db.execute(
        select(PhysicalInterface).where(PhysicalInterface.role == "management").order_by(PhysicalInterface.name)
    ).scalars().first()
    if management is None:
        management = PhysicalInterface(
            name="mgmt0", mac_address="02:00:00:00:00:01", role="management", mode="access",
            admin_state="up", oper_state="up", ipv4_method="static", ip_cidr="198.51.100.10/24",
        )
        db.add(management)
    else:
        management.mode = "access"
        management.admin_state = "up"
        management.ipv4_method = "static"
        management.ip_cidr = "198.51.100.10/24"
    access = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth9")).scalar_one_or_none()
    if access is None:
        access = PhysicalInterface(
            name="eth9", mac_address="02:00:00:00:00:19", role="access", mode="access",
            admin_state="up", oper_state="up", ipv4_method="static", ip_cidr="192.0.2.10/24",
            ipv6_enabled=True, ipv6_cidr="2001:db8::10/64",
        )
        db.add(access)
    else:
        access.role = "access"
        access.mode = "access"
        access.admin_state = "up"
        access.ipv4_method = "static"
        access.ip_cidr = "192.0.2.10/24"
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8::10/64"

    dns = db.execute(select(DnsSettings)).scalar_one()
    dns.enabled = True
    ca = db.execute(select(CaSettings)).scalar_one()
    ca.enabled = True
    ca.portal_hostname = "ca.custom.example.internal"
    ca.listen_interface = "eth9"
    ca.listen_address = "192.0.2.10\n2001:db8::10"
    ntp = db.execute(select(NtpSettings)).scalar_one()
    ntp.enabled = True
    ntp.hostname = "time.custom.example.internal"
    ntp.listen_interface = "eth9"
    ntp.listen_address = "192.0.2.10\n2001:db8::10"
    depot = db.execute(select(VcfOfflineDepotSettings)).scalar_one()
    depot.enabled = True
    depot.hostname = "depot.custom.example.internal"
    depot.listen_interface = "eth9"
    depot.listen_address = "192.0.2.10\n2001:db8::10"
    depot_user = db.execute(select(User).where(User.username == "vcf-depot")).scalar_one()
    depot_user.enabled = True
    db.add_all([
        DnsRecord(hostname="operator-shared.example.internal", record_type="A", address="192.0.2.10",
                  description="Operator", enabled=True),
        DnsRecord(hostname="operator-shared.example.internal", record_type="AAAA", address="2001:db8::10",
                  description="Operator", enabled=True),
    ])
    db.flush()
    units = ui.appliance_apply_units(db)
    ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
    baselines = ui.load_appliance_apply_baselines(db)
    # DNS was already active with the local stub resolver at this baseline;
    # avoid turning this Network-only test into a resolver activation request.
    baselines["appliance_settings"]["config_preview"] = json.dumps(
        {"resolver_mode": "local_dns", "resolver_servers": ["127.0.0.1"]}
    )
    ui.save_appliance_apply_baselines(db, baselines)
    # Make the ownership assertion explicit: the applied baseline captures only
    # Atlaso's records, even though an operator record uses the same addresses.
    baseline = ui.load_appliance_apply_baselines(db)["dnsmasq"]
    owned_descriptions = {
        CA_PORTAL_DNS_DESCRIPTION,
        NTP_DNS_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION,
    }
    assert {row["description"] for row in baseline["service_dns_records"]} & owned_descriptions == owned_descriptions
    assert all(row["description"] != "Operator" for row in baseline["service_dns_records"])
    # Add a manual row that resembles a generated old target only after the
    # applied service target has been captured, so it cannot block initial alias creation.
    db.add(DnsRecord(
        hostname="ca-192-0-2-10.custom.example.internal", record_type="A", address="192.0.2.99",
        description="Operator", enabled=True,
    ))
    db.flush()
    return management, access


@pytest.mark.parametrize("pending_dns_disable", [False, True])
def test_network_apply_captures_refreshed_service_dns_after_direct_ip_change(client, monkeypatch, pending_dns_disable):
    """Capture CA, Depot, and NTP dual-stack aliases after direct interface edits.

    The same Network POST must project only applied generated DNS ownership through
    management handoff, preserving prior manual records while excluding an
    unrelated operator record added after the last DNS Apply.

    Args:
        client: Isolated authenticated application client.
        pending_dns_disable: Keep an unrelated DNS shutdown pending during Network Apply.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        DnsRecord,
        DnsSettings,
        Job,
        NtpSettings,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.services.service_dns_defaults import (
        CA_PORTAL_DNS_DESCRIPTION,
        NTP_DNS_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION,
    )

    login(client)
    with SessionLocal() as db:
        management, access = _prepare_service_address_baseline(db, ui)
        if pending_dns_disable:
            db.scalar(select(DnsSettings)).enabled = False
        management.ip_cidr = "198.51.100.11/24"
        access.ip_cidr = "192.0.2.11/24"
        access.ipv6_cidr = "2001:db8::11/64"
        db.add(DnsRecord(
            hostname="operator-pending.example.internal", record_type="TXT", address="pending-note",
            description="Operator", enabled=True,
        ))
        db.commit()

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 202, response.text

    with SessionLocal() as db:
        payload = json.loads(db.get(Job, response.json()["job_id"]).result)
        assert payload["generated_dns_only"] is True
        assert payload["management_handoff"] is True
        assert {"network", "dnsmasq", *ui.MANAGEMENT_HANDOFF_UNIT_IDS} <= set(payload["selected_units"])
        dns_capture = next(row for row in payload["captured_units"] if row["unit_id"] == "dnsmasq")
        preview = dns_capture["config_preview"]
        assert "192.0.2.11" in preview
        assert "2001:db8::11" in preview
        assert "host-record=operator-shared.example.internal,192.0.2.10" in preview
        assert "host-record=operator-shared.example.internal,2001:db8::10" in preview
        assert "txt-record=operator-pending.example.internal,pending-note" not in preview
        assert "pending-note" not in preview
        assert payload["skipped_changed_units"]
        assert all(row["unit_id"] != "dnsmasq" for row in payload["skipped_changed_units"])

        baseline = ui.load_appliance_apply_baselines(db)["dnsmasq"]
        previous_owned = [
            row for row in baseline["service_dns_records"]
            if row["description"] in {
                CA_PORTAL_DNS_DESCRIPTION, VCF_DEPOT_DNS_DESCRIPTION, NTP_DNS_DESCRIPTION,
            }
        ]
        prior_descriptions = {row["description"] for row in previous_owned}
        assert {CA_PORTAL_DNS_DESCRIPTION, VCF_DEPOT_DNS_DESCRIPTION, NTP_DNS_DESCRIPTION} <= prior_descriptions
        previous_directives = {
            f"{'cname' if row['record_type'] == 'CNAME' else 'host-record'}={row['hostname']},{row['address']}"
            for row in previous_owned
        }
        desired_units = ui.appliance_apply_units(db)
        desired_dns = next(unit for unit in desired_units if unit["id"] == "dnsmasq")
        assert "pending-note" in desired_dns["raw_config_preview"]
        assert "pending-note" not in preview
        for model in (CaSettings, VcfOfflineDepotSettings, NtpSettings):
            settings = db.execute(select(model)).scalar_one()
            assert settings.listen_address == "192.0.2.11\n2001:db8::11"
        current_owned = ui.owned_service_dns_records(db, desired_dns["raw_config_preview"])
        desired_directives = {
            f"{'cname' if row['record_type'] == 'CNAME' else 'host-record'}={row['hostname']},{row['address']}"
            for row in current_owned if row["description"] in prior_descriptions
        }
        assert desired_directives
        captured_directives = {
            line.removeprefix("# atlaso-authoritative-config: ")
            for line in preview.splitlines()
        }
        assert desired_directives <= captured_directives
        assert not (previous_directives - desired_directives) & captured_directives


def test_dhcp_to_static_management_move_projects_appliance_dns_with_legacy_inventory(client):
    """Applied DHCP addresses remain identifiable without a desired Network CIDR.

    Args:
        client: Seeded application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        management, _access = _prepare_service_address_baseline(db, ui)
        management.ipv4_method = "dhcp"
        management.host_ip_cidr = management.ip_cidr
        management.ip_cidr = None
        db.flush()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = ui.load_appliance_apply_baselines(db)
        applied_record = next(row for row in baselines["dnsmasq"]["service_dns_records"]
                              if row["description"] == ui.APPLIANCE_DNS_RECORD_DESCRIPTION and row["address"] == "198.51.100.10")
        assert applied_record["source_interface"] == management.name
        for row in baselines["dnsmasq"]["service_dns_records"]:
            if row["description"] == ui.APPLIANCE_DNS_RECORD_DESCRIPTION:
                row["source_interface"] = ""
        ui.save_appliance_apply_baselines(db, baselines)
        management.ipv4_method = "static"
        management.ip_cidr = "198.51.100.11/24"
        db.flush()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        projected = ui.network_generated_dns_unit(db, units)
        assert projected is not None
        assert projected["validation_errors"] == []
        assert "198.51.100.11" in projected["raw_config_preview"]
        fqdn = ui.get_appliance_settings_row(db).fqdn
        assert f"host-record={fqdn},198.51.100.10" not in projected["raw_config_preview"]
        assert f"host-record={fqdn},198.51.100.11" in projected["raw_config_preview"]


def test_startup_preserves_legacy_dhcp_dns_provenance_after_offline_address_change(client, monkeypatch):
    """A legacy applied DHCP record remains part of Network-only publication.

    Args:
        client: Seeded application client.
        monkeypatch: Replace host discovery with a changed assigned address.
    """
    from atlaso.app import main, ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    login(client)
    with SessionLocal() as db:
        management, _access = _prepare_service_address_baseline(db, ui)
        management.ipv4_method = "dhcp"
        management.host_ip_cidr = management.ip_cidr
        management.ip_cidr = None
        db.flush()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = ui.load_appliance_apply_baselines(db)
        baselines["dnsmasq"].pop("service_dns_records")
        prior_config = baselines["dnsmasq"]["config_preview"]
        ui.save_appliance_apply_baselines(db, baselines)
        management_name = management.name
        db.commit()

    def changed_inventory(db):
        """Emulate host discovery replacing the persisted DHCP observation."""
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == management_name))
        management.host_ip_cidr = "198.51.100.11/24"
        db.flush()

    monkeypatch.setattr(main, "sync_host_physical_interfaces", changed_inventory)
    with SessionLocal() as db:
        main.refresh_startup_host_inventory(db, environment="appliance")

    with SessionLocal() as db:
        baseline = ui.load_appliance_apply_baselines(db)["dnsmasq"]
        assert baseline["config_preview"] == prior_config
        applied_record = next(row for row in baseline["service_dns_records"]
                              if row["description"] == ui.APPLIANCE_DNS_RECORD_DESCRIPTION
                              and row["address"] == "198.51.100.10")
        assert applied_record["source_interface"] == management_name
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        projected = ui.network_generated_dns_unit(db, units)
        assert projected is not None
        assert projected["generated_dns_only"] is True
        assert projected["validation_errors"] == []
        fqdn = ui.get_appliance_settings_row(db).fqdn
        assert f"host-record={fqdn},198.51.100.10" not in projected["raw_config_preview"]
        assert f"host-record={fqdn},198.51.100.11" in projected["raw_config_preview"]


def test_alias_refresh_is_idempotent_across_sessions_for_service_inventory(client):
    """Refresh generated names after one address move, then survive a fresh session.

    Cover the service families reconciled by the shared refresh path, retain an
    operator row that resembles a generated target hostname, and verify a second
    process-like Session does not recreate stale addresses.

    Args:
        client: Isolated application client used to initialize seeded state.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        DnsRecord,
        EsxNfsShare,
        EsxStorageVolume,
        KmsSettings,
        LdapSettings,
        OidcProviderSettings,
        Setting,
        VcfPrivateRegistrySettings,
    )
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_BOOT_ENABLED_KEY,
        ESXI_PXE_HOSTNAME_KEY,
        ESXI_PXE_LISTEN_ADDRESS_KEY,
        ESXI_PXE_LISTEN_INTERFACE_KEY,
    )
    from atlaso.app.services.service_dns_defaults import (
        CA_PORTAL_DNS_DESCRIPTION,
        ESX_STORAGE_DNS_DESCRIPTION,
        NTP_DNS_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION,
        VCF_REGISTRY_DNS_DESCRIPTION,
    )
    ESXI_PXE_DNS_RECORD_DESCRIPTION = ui.ESXI_PXE_DNS_RECORD_DESCRIPTION
    KMS_DNS_RECORD_DESCRIPTION = ui.KMS_DNS_RECORD_DESCRIPTION
    LDAP_DNS_RECORD_DESCRIPTION = ui.LDAP_DNS_RECORD_DESCRIPTION
    OIDC_DNS_RECORD_DESCRIPTION = ui.OIDC_DNS_RECORD_DESCRIPTION

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        for model, hostname in (
            (KmsSettings, "kms.custom.example.internal"),
            (LdapSettings, "ldap.custom.example.internal"),
            (OidcProviderSettings, "oidc.custom.example.internal"),
            (VcfPrivateRegistrySettings, "registry.custom.example.internal"),
        ):
            settings = db.execute(select(model)).scalar_one()
            settings.enabled = True
            settings.hostname = hostname
            settings.listen_interface = "eth9"
            settings.listen_address = "192.0.2.10\n2001:db8::10"
            if isinstance(settings, KmsSettings):
                settings.server_certificate = hostname
            if isinstance(settings, VcfPrivateRegistrySettings):
                settings.server_certificate = hostname

        storage = ui.get_esx_storage_settings_row(db)
        storage.enabled = True
        storage.hostname = "nfs.custom.example.internal"
        volume = EsxStorageVolume(
            name="dns-refresh-volume", source_type="blank_disk",
            stable_device_id="/dev/disk/by-id/atlaso-dns-refresh-test",
            state="mounted",
        )
        db.add(volume)
        db.flush()
        db.add(EsxNfsShare(
            datastore_name="dns-refresh", volume_id=volume.id, relative_path="/",
            interface_name="eth9", address_families="ipv4\nipv6",
            ipv4_clients="192.0.2.0/24", ipv6_clients="2001:db8::/64", enabled=True,
        ))
        for key, value in (
            (ESXI_PXE_BOOT_ENABLED_KEY, "true"),
            (ESXI_PXE_HOSTNAME_KEY, "pxe.custom.example.internal"),
            (ESXI_PXE_LISTEN_INTERFACE_KEY, "eth9"),
            (ESXI_PXE_LISTEN_ADDRESS_KEY, "192.0.2.10\n2001:db8::10"),
        ):
            setting = db.execute(select(Setting).where(Setting.key == key)).scalar_one_or_none()
            if setting is None:
                setting = Setting(key=key, value=value)
            else:
                setting.value = value
            db.add(setting)
        db.flush()
        access.ip_cidr = "192.0.2.11/24"
        access.ipv6_cidr = "2001:db8::11/64"
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        db.commit()

    expected_descriptions = {
        CA_PORTAL_DNS_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION,
        NTP_DNS_DESCRIPTION,
        KMS_DNS_RECORD_DESCRIPTION,
        LDAP_DNS_RECORD_DESCRIPTION,
        OIDC_DNS_RECORD_DESCRIPTION,
        VCF_REGISTRY_DNS_DESCRIPTION,
        ESXI_PXE_DNS_RECORD_DESCRIPTION,
        ESX_STORAGE_DNS_DESCRIPTION,
    }
    with SessionLocal() as db:
        first_rows = db.execute(select(DnsRecord)).scalars().all()
        first_owned = [row for row in first_rows if row.description in expected_descriptions]
        assert {row.description for row in first_owned} == expected_descriptions
        assert all(row.address not in {"192.0.2.10", "2001:db8::10"} for row in first_owned if row.record_type in {"A", "AAAA"})
        assert {row.address for row in first_owned if row.record_type in {"A", "AAAA"}} >= {
            "192.0.2.11", "2001:db8::11",
        }
        assert db.execute(select(DnsRecord).where(
            DnsRecord.hostname == "ca-192-0-2-10.custom.example.internal",
            DnsRecord.description == "Operator",
        )).scalar_one().address == "192.0.2.99"
        first_signature = sorted(
            (row.hostname, row.record_type, row.address, row.description)
            for row in first_owned
        )
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        db.commit()

    with SessionLocal() as db:
        second_rows = db.execute(select(DnsRecord)).scalars().all()
        second_owned = [row for row in second_rows if row.description in expected_descriptions]
        second_signature = sorted(
            (row.hostname, row.record_type, row.address, row.description)
            for row in second_owned
        )
        assert second_signature == first_signature
        assert db.execute(select(DnsRecord).where(
            DnsRecord.hostname == "ca-192-0-2-10.custom.example.internal",
            DnsRecord.description == "Operator",
        )).scalar_one().address == "192.0.2.99"


@pytest.mark.parametrize("dynamic_failure", [None, "publication", "reload", "readback", "identity", "identity-storage", "identity-pxe"])
def test_management_handoff_dns_readback_failure_triggers_proven_recovery(client, monkeypatch, tmp_path, dynamic_failure):
    """Treat failed generated-DNS readback as handoff failure and recover.

    Args:
        client: Isolated application client used to initialize the database.
        monkeypatch: Replace helper, staging, and DNS readback boundaries.
        tmp_path: Owned temporary location for mocked staged configuration paths.
        dynamic_failure: Dynamic publication phase to fail, or static readback.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        DnsRecord,
        DnsSettings,
        EsxNfsShare,
        EsxStorageVolume,
        Job,
        PhysicalInterface,
    )
    from atlaso.app.services import service_dns_readback
    from atlaso.app.services.service_dns_defaults import CA_PORTAL_DNS_DESCRIPTION

    class SuccessfulApplyAdapter:
        """Apply the candidate, then report a bounded rollback on recovery."""

        dry_run = False

        def validate_management_handoff(self, manifest_path):
            """Return successful helper validation.

            Args:
                manifest_path: Staged manifest passed to the helper.
            """
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "validate", manifest_path],
                dry_run=False, returncode=0,
            )

        def apply_management_handoff(self, manifest_path):
            """Return successful candidate activation.

            Args:
                manifest_path: Staged manifest passed to the helper.
            """
            if (dynamic_failure or "").startswith("identity"):
                with SessionLocal() as other:
                    if dynamic_failure == "identity-storage":
                        storage = ui.get_esx_storage_settings_row(other)
                        storage.enabled = True
                        storage.hostname = "concurrent-nfs.example.internal"
                        volume = EsxStorageVolume(name="concurrent-volume", source_type="blank_disk", state="mounted",
                                                  stable_device_id="/dev/disk/by-id/concurrent-test")
                        other.add(volume)
                        other.flush()
                        other.add(EsxNfsShare(datastore_name="concurrent-share", volume_id=volume.id,
                                              interface_name="dynamic0", address_families="ipv4", enabled=True))
                    elif dynamic_failure == "identity-pxe":
                        for key, value in (("esxi_pxe.boot.enabled", "true"), ("esxi_pxe.boot.hostname", "concurrent-pxe.example.internal"),
                                           ("esxi_pxe.boot.listen_interface", "dynamic0"), ("esxi_pxe.boot.listen_address", "192.0.2.11")):
                            ui.set_setting_value(other, key, value)
                    else:
                        ui.get_appliance_settings_row(other).fqdn = "concurrent.example.internal"
                    other.flush()
                    ui.refresh_interface_service_dns_aliases(other, actor=None)
                    settings = ui.get_appliance_settings_row(other)
                    ui.ensure_dns_for_appliance_settings(other, settings, previous_fqdn="atlaso.internal", actor=None)
                    other.commit()
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "apply", manifest_path],
                dry_run=False, returncode=0,
            )

        def validate_dnsmasq_config(self, _path):
            assert not (dynamic_failure or "").startswith("identity"), "unreviewed identity must never reach DNS publication"
            return AdapterResult(command=["dnsmasq", "validate"], dry_run=False, returncode=0)

        def apply_dnsmasq_config(self, _path):
            return AdapterResult(command=["dnsmasq", "apply"], dry_run=False,
                                 returncode=1 if dynamic_failure == "publication" else 0)

        def reload_dnsmasq(self):
            return AdapterResult(command=["dnsmasq", "reload"], dry_run=False,
                                 returncode=1 if dynamic_failure == "reload" else 0)

        def recover_management_handoff(self):
            """Prove the candidate was rolled back after readback failure."""
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "recover"],
                dry_run=False,
                returncode=0,
                stdout=json.dumps({
                    "management_handoff": "rolled back after interruption",
                    "rolled_back": True,
                }),
            )

    monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(tmp_path / "ca.json"))
    monkeypatch.setattr(ui, "MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH", str(tmp_path / "handoff.json"))
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db: {
        "appliance_settings": {},
        "dnsmasq": {"config_preview": "host-record=ca.custom.example.internal,192.0.2.10\n"},
    })
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda target, _content: str(target))
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
    monkeypatch.setattr(
        service_dns_readback,
        "verify_service_dns_records",
        lambda _records: (_ for _ in ()).throw(ValueError("controlled DNS readback failure")),
    )
    unit_defaults = {
        "label": "Management handoff component",
        "page_url": "/appliance-apply",
        "summary": ["Apply the management handoff component."],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "",
        "config_preview": "",
        "config_diff": "",
        "raw_config_preview": "",
    }
    units = {
        unit_id: {**unit_defaults, "id": unit_id}
        for unit_id in (*ui.MANAGEMENT_HANDOFF_UNIT_IDS, "dnsmasq")
    }
    units["network"]["previous_management_paths"] = []
    units["network"]["removed_vlan_interfaces"] = []
    units["network"]["raw_config_preview"] = "[physical_interfaces]\ninterface=inactive\nadmin_state=down\nipv4_method=dhcp\nipv6_enabled=true\n"
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": []}
    units["dnsmasq"]["raw_config_preview"] = "host-record=ca.custom.example.internal,192.0.2.11\n"
    units["dnsmasq"]["context"] = {"dns_settings": SimpleNamespace(enabled=False)}
    units["dnsmasq"]["applied_dns_enabled"] = True

    login(client)
    with SessionLocal() as db:
        if dynamic_failure:
            interface = PhysicalInterface(name="dynamic0", mac_address="02:00:00:00:00:88", role="access", mode="access",
                                          admin_state="up", ipv4_method="dhcp", host_ip_cidr="192.0.2.11/24")
            db.add(interface)
            ca = db.scalar(select(CaSettings))
            db.scalar(select(DnsSettings)).enabled = True
            ca.enabled = True
            ca.portal_hostname = "ca.custom.example.internal"
            ca.listen_interface = "dynamic0"
            ca.listen_address = "192.0.2.11"
            units["network"]["raw_config_preview"] = "[physical_interfaces]\ninterface=dynamic0\nadmin_state=up\nipv4_method=dhcp\n"
            monkeypatch.setattr(ui, "discover_host_physical_interfaces", lambda: [SimpleNamespace(
                name="dynamic0", mac_address="02:00:00:00:00:88", host_ip_cidr="192.0.2.21/24", host_ipv6_cidr=None,
            )])
            monkeypatch.setattr(ui, "management_handoff_result_evidence", lambda _result: {
                "service_address_observation": {"complete": True, "links": [{
                    "name": "dynamic0", "configured": True, "address_inventory_complete": True,
                    "addresses": [{"address": "192.0.2.21", "state": "assigned"}],
                }]},
                "rolled_back": _result.command[-1] == "recover",
            })
        db.add(DnsRecord(
            hostname="ca.custom.example.internal", record_type="A", address="192.0.2.11",
            description=CA_PORTAL_DNS_DESCRIPTION, enabled=True,
        ))
        db.commit()
        group, results = ui.execute_management_handoff(
            units,
            job_id="job_generated_dns_readback",
            adapter=SuccessfulApplyAdapter(),
            db=db,
            include_dnsmasq=True,
        )
        db.add(Job(id="job_dynamic_dns_failure", type="appliance-apply", status="failed", created_by="admin", result=json.dumps(group)))
        db.commit()
    if dynamic_failure:
        with SessionLocal() as db:
            assert db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "dynamic0")).host_ip_cidr == "192.0.2.11/24"
            assert db.scalar(select(CaSettings)).listen_address == "192.0.2.11"
            owned = db.scalars(select(DnsRecord).where(DnsRecord.description == CA_PORTAL_DNS_DESCRIPTION,
                                                      DnsRecord.record_type == "A")).all()
            assert owned and {row.address for row in owned} == {"192.0.2.11"}
            assert db.get(Job, "job_dynamic_dns_failure").status == "failed"

    assert group["success"] is False
    assert group["rollback_proven"] is True
    assert group["management_handoff"]["failing_layer"] == "generated service DNS readback"
    expected_error = {
        "publication": "Effective dynamic service DNS publication failed.",
        "reload": "Effective dynamic service DNS reload failed.",
        "identity": "Service DNS identity changed during network readiness; resubmit the changes.",
        "identity-storage": "Service DNS identity changed during network readiness; resubmit the changes.",
        "identity-pxe": "Service DNS identity changed during network readiness; resubmit the changes.",
    }.get(dynamic_failure, "controlled DNS readback failure")
    assert group["management_handoff"]["error"] == expected_error
    assert group["management_handoff"]["rolled_back"] is True
    assert any(
        command["command"] == ["service-dns", "readback"] and command["returncode"] == 1
        for command in group["commands"]
    )
    assert all(row["success"] is False and row["rolled_back"] is True for row in results)
