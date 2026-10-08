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


def test_verified_public_dynamic_sockets_advance_only_submitted_baseline(client):
    """A native address move updates sockets while preserving other submitted text.

    Args:
        client: Seeded application client.
    """
    from atlaso.app import ui

    submitted = "server {\n    listen 192.0.2.20:443 ssl;\n    listen [2001:db8::20]:8080;\n    server_name applied.example.internal;\n}\n"
    moves = [{"interface": "eth9", "old_address": "192.0.2.20", "new_address": "192.0.2.21"},
             {"interface": "eth9", "old_address": "2001:db8::20", "new_address": "2001:db8::21"}]
    projected = ui.projected_public_service_config(submitted, moves)
    expected = submitted.replace("192.0.2.20", "192.0.2.21").replace("2001:db8::20", "2001:db8::21")
    assert projected == expected
    kwargs = dict(unit_id="public_services", label="Public Services", page_url="/public-services", context={},
                  summary=[], validation_errors=[], config_path="/public/config")
    applied = ui.make_appliance_apply_unit(config_preview=projected, baseline=None, **kwargs)
    assert ui.make_appliance_apply_unit(config_preview=expected, baseline=applied, **kwargs)["changed"] is False
    assert ui.make_appliance_apply_unit(config_preview=expected.replace("applied.example.internal", "pending.example.internal"),
                                        baseline=applied, **kwargs)["changed"] is True


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


@pytest.mark.parametrize("include_cidr_metadata", [True, False], ids=["helper-cidr", "host-fallback"])
def test_dynamic_ipv6_readback_selects_helper_cidr_before_generated_dns_refresh(
    client, monkeypatch, include_cidr_metadata
):
    """Keep SLAAC DNS aliases aligned with the helper-selected address ordering.

    Args:
        client: Seeded application client.
        monkeypatch: Replace host discovery with a different SLAAC observation order.
        include_cidr_metadata: Whether helper address rows carry their assigned CIDRs.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        DnsRecord,
        NtpSettings,
        VcfOfflineDepotSettings,
    )
    from atlaso.app.services.service_dns_defaults import (
        CA_PORTAL_DNS_DESCRIPTION,
        NTP_DNS_DESCRIPTION,
        VCF_DEPOT_DNS_DESCRIPTION,
    )

    selected_address = "2001:db8::21"
    later_address = "2001:db8::22"
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        access.ipv6_cidr = None
        access.host_ipv6_cidr = f"{later_address}/64" if include_cidr_metadata else f"{selected_address}/64"
        access.ipv6_enabled = True
        db.flush()
        network = next(unit for unit in ui.appliance_apply_units(db) if unit["id"] == "network")
        host = SimpleNamespace(
            name="eth9",
            mac_address=access.mac_address,
            host_ip_cidr=None,
            host_ipv6_cidr=f"{later_address}/64" if include_cidr_metadata else f"{selected_address}/64",
        )
        monkeypatch.setattr(ui, "discover_host_physical_interfaces", lambda: [host])
        addresses = [
            {"address": selected_address, "state": "assigned", "scope": "global"},
            {"address": later_address, "state": "assigned", "scope": "global"},
        ]
        if include_cidr_metadata:
            addresses[0]["cidr"] = f"{selected_address}/64"
            addresses[1]["cidr"] = f"{later_address}/64"
        evidence = {"service_address_observation": {"complete": True, "links": [{
            "name": "eth9",
            "configured": True,
            "address_inventory_complete": True,
            "addresses": addresses,
        }]}}

        ui.refresh_service_dns_effective_observations(
            db, network["raw_config_preview"], evidence, source_interfaces={"eth9"},
        )
        assert access.host_ipv6_cidr == f"{selected_address}/64"
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        owned_aaaa = db.scalars(select(DnsRecord).where(
            DnsRecord.description.in_({
                CA_PORTAL_DNS_DESCRIPTION,
                NTP_DNS_DESCRIPTION,
                VCF_DEPOT_DNS_DESCRIPTION,
            }),
            DnsRecord.record_type == "AAAA",
            DnsRecord.enabled.is_(True),
        )).all()
        assert {record.address for record in owned_aaaa} == {selected_address}
        for model in (CaSettings, NtpSettings, VcfOfflineDepotSettings):
            settings = db.scalar(select(model))
            assert selected_address in settings.listen_address.splitlines()
            assert later_address not in settings.listen_address.splitlines()


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
        client: HTTP test client for the UI request.
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        pending_dns_disable: Whether generated DNS is pending disablement in the same network apply.
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
        data={"csrf": csrf, "selected_units": list(ui.MANAGEMENT_HANDOFF_UNIT_IDS)},
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


def test_network_only_apply_cannot_omit_dns_when_static_service_interface_goes_down(client, monkeypatch):
    """Require safe generated-DNS removal or explicit review when its static source goes down.

    Args:
        client: Isolated authenticated application client.
        monkeypatch: Prevent background appliance apply execution.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job
    from atlaso.app.services.service_dns_defaults import CA_PORTAL_DNS_DESCRIPTION

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        access.admin_state = "down"
        db.add(DnsRecord(
            hostname="operator-pending.example.internal",
            record_type="TXT",
            address="pending-note",
            description="Operator",
            enabled=True,
        ))
        db.commit()

        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        projected = ui.network_generated_dns_unit(db, units)
        assert projected is not None
        assert access.ip_cidr == "192.0.2.10/24"
        if projected["validation_errors"]:
            assert any(
                ("DNS" in error or "service" in error.lower())
                and ("review" in error.lower() or "include" in error.lower())
                for error in projected["validation_errors"]
            )
        else:
            preview = projected["raw_config_preview"]
            previous_ca_records = [
                row for row in ui.load_appliance_apply_baselines(db)["dnsmasq"]["service_dns_records"]
                if row["description"] == CA_PORTAL_DNS_DESCRIPTION
            ]
            assert previous_ca_records
            for row in previous_ca_records:
                directive = f"{'cname' if row['record_type'] == 'CNAME' else 'host-record'}={row['hostname']},{row['address']}"
                assert directive not in preview
            assert "host-record=operator-shared.example.internal,192.0.2.10" in preview
            assert "host-record=operator-shared.example.internal,2001:db8::10" in preview
            assert "txt-record=operator-pending.example.internal,pending-note" not in preview

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code in {202, 422}, response.text

    with SessionLocal() as db:
        assert db.scalar(select(DnsRecord).where(
            DnsRecord.hostname == "operator-pending.example.internal",
            DnsRecord.record_type == "TXT",
            DnsRecord.address == "pending-note",
        )) is not None
        baseline_dns = ui.load_appliance_apply_baselines(db)["dnsmasq"]
        assert "txt-record=operator-pending.example.internal,pending-note" not in baseline_dns["config_preview"]
        if response.status_code == 202:
            payload = json.loads(db.get(Job, response.json()["job_id"]).result)
            assert payload["generated_dns_only"] is True
            assert "dnsmasq" in payload["selected_units"]
            captured_dns = next(row for row in payload["captured_units"] if row["unit_id"] == "dnsmasq")
            assert "txt-record=operator-pending.example.internal,pending-note" not in captured_dns["config_preview"]
        else:
            assert any(message in response.json()["detail"] for message in (
                "Resolve validation errors", "Unchecked changes cannot be applied",
            ))
            assert db.scalar(select(Job).where(Job.type == "appliance-apply")) is None


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
        """Emulate host discovery replacing the persisted DHCP observation.

        Args:
            db: Database session whose discovered interface state is updated.
        """
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


@pytest.mark.parametrize("ipv6_enabled", [False, True], ids=["stale-disabled-ipv6", "enabled-slaac"])
def test_oidc_alias_refresh_uses_only_effective_ipv6_listener(client, ipv6_enabled):
    """Keep OIDC DNS and nginx listeners aligned with effective IPv6 state.

    Args:
        client: Isolated authenticated application client.
        ipv6_enabled: Whether the access interface may publish its observed SLAAC address.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaSettings,
        DnsRecord,
        OidcProviderSettings,
        VcfOfflineDepotSettings,
        VcfPrivateRegistrySettings,
    )

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        access.ipv6_cidr = None
        access.host_ipv6_cidr = "2001:db8::10/64"
        access.ipv6_enabled = True
        oidc = db.scalar(select(OidcProviderSettings))
        oidc.enabled = True
        oidc.hostname = "oidc.custom.example.internal"
        oidc.listen_interface = access.name
        oidc.listen_address = "192.0.2.10\n2001:db8::10"
        ca = db.scalar(select(CaSettings))
        depot = db.scalar(select(VcfOfflineDepotSettings))
        registry = db.scalar(select(VcfPrivateRegistrySettings))
        ca.enabled = False
        depot.enabled = False
        registry.enabled = False
        db.flush()

        # Establish an applied-looking dual-stack alias first, then leave its
        # observed IPv6 address stale while turning the family off.
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        db.flush()
        assert db.scalar(select(DnsRecord).where(
            DnsRecord.record_type == "AAAA",
            DnsRecord.description == ui.OIDC_DNS_RECORD_DESCRIPTION,
        )) is not None
        access.ipv6_enabled = ipv6_enabled
        db.flush()

        ui.refresh_interface_service_dns_aliases(db, actor=None)
        db.flush()

        expected_addresses = ["192.0.2.10", *(["2001:db8::10"] if ipv6_enabled else [])]
        assert oidc.listen_address.splitlines() == expected_addresses
        option = next(row for row in ui.ldap_service_bind_options(db) if row["name"] == access.name)
        assert option["addresses"] == expected_addresses
        oidc_aaaa = db.scalars(select(DnsRecord).where(
            DnsRecord.record_type == "AAAA",
            DnsRecord.description == ui.OIDC_DNS_RECORD_DESCRIPTION,
        )).all()
        assert {row.address for row in oidc_aaaa} == ({"2001:db8::10"} if ipv6_enabled else set())
        oidc_a = db.scalars(select(DnsRecord).where(
            DnsRecord.record_type == "A",
            DnsRecord.description == ui.OIDC_DNS_RECORD_DESCRIPTION,
        )).all()
        assert {row.address for row in oidc_a} == {"192.0.2.10"}

        public_context = ui.public_services_context(db, reconcile=False)
        public_config = public_context["public_service_config_preview"]
        if ipv6_enabled:
            assert "listen [2001:db8::10]:443 ssl;" in public_config
        else:
            assert "listen [2001:db8::10]:443 ssl;" not in public_config


@pytest.mark.parametrize("dynamic_failure", [
    None, "publication", "reload", "readback", "identity", "identity-storage", "identity-pxe",
    "identity-dns-edit", "identity-dns-create",
    "identity-dns-zone-toggle", "identity-dns-render-setting",
])
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
    dns_publication_attempts = []

    class SuccessfulApplyAdapter:
        """Apply the candidate, then report a bounded rollback on recovery."""

        dry_run = False

        def validate_management_handoff(self, manifest_path):
            """Return successful helper validation.

            Args:
                manifest_path: Path to the staged management-handoff manifest.
            """
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "validate", manifest_path],
                dry_run=False, returncode=0,
            )

        def apply_management_handoff(self, manifest_path):
            """Return successful candidate activation.

            Args:
                manifest_path: Path to the staged management-handoff manifest.
            """
            if (dynamic_failure or "").startswith("identity"):
                # Inject a same-writer callback fault; external writers now wait for publication.
                from contextlib import nullcontext

                with nullcontext(db) as other:
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
                    elif dynamic_failure == "identity-dns-edit":
                        generated = other.scalar(select(DnsRecord).where(
                            DnsRecord.hostname == "ca.custom.example.internal",
                            DnsRecord.record_type == "A",
                            DnsRecord.address == "192.0.2.11",
                            DnsRecord.description == CA_PORTAL_DNS_DESCRIPTION,
                        ))
                        assert generated is not None
                        generated.enabled = False
                    elif dynamic_failure == "identity-dns-create":
                        other.add(DnsRecord(
                            hostname="ca.custom.example.internal", record_type="A",
                            address="192.0.2.99", description="Operator conflict", enabled=True,
                        ))
                    elif dynamic_failure == "identity-dns-zone-toggle":
                        dns_settings = other.scalar(select(DnsSettings))
                        assert dns_settings.domain.splitlines() == [
                            "atlaso.internal", "custom.example.internal",
                        ]
                        assert not dns_settings.disabled_domains
                        dns_settings.domain = "atlaso.internal"
                        dns_settings.disabled_domains = "custom.example.internal"
                    elif dynamic_failure == "identity-dns-render-setting":
                        other.scalar(select(DnsSettings)).cache_size = 4321
                    else:
                        ui.get_appliance_settings_row(other).fqdn = "concurrent.example.internal"
                    other.flush()
                    if dynamic_failure not in {
                        "identity-dns-edit", "identity-dns-create", "identity-dns-zone-toggle",
                        "identity-dns-render-setting",
                    }:
                        ui.refresh_interface_service_dns_aliases(other, actor=None)
                        settings = ui.get_appliance_settings_row(other)
                        ui.ensure_dns_for_appliance_settings(other, settings, previous_fqdn="atlaso.internal", actor=None)
                    other.flush()
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "apply", manifest_path],
                dry_run=False, returncode=0,
            )

        def validate_dnsmasq_config(self, _path):
            """Validate the candidate dnsmasq configuration path.

            Args:
                _path: Candidate configuration path supplied to the validation or apply callback.
            """
            dns_publication_attempts.append(_path)
            assert not (dynamic_failure or "").startswith("identity"), "unreviewed identity must never reach DNS publication"
            return AdapterResult(command=["dnsmasq", "validate"], dry_run=False, returncode=0)

        def apply_dnsmasq_config(self, _path):
            """Apply the candidate dnsmasq configuration path.

            Args:
                _path: Candidate configuration path supplied to the validation or apply callback.
            """
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
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db, *, refresh=False: {
        "appliance_settings": {},
        "dnsmasq": {"config_preview": "host-record=ca.custom.example.internal,192.0.2.10\n"},
    })
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda target, _content: str(target))
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
    monkeypatch.setattr(
        service_dns_readback,
        "verify_service_dns_records",
        lambda _records, **_kwargs: (_ for _ in ()).throw(ValueError("controlled DNS readback failure")),
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
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": [], "ca_profiles": []}
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
            dns_settings = db.scalar(select(DnsSettings))
            dns_settings.enabled = True
            if dynamic_failure in {"identity-dns-zone-toggle", "identity-dns-render-setting"}:
                dns_settings.domain = "atlaso.internal\ncustom.example.internal"
                dns_settings.disabled_domains = ""
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
        dns_rows_before = sorted(
            (row.id, row.hostname, row.record_type, row.address, row.record_data_json,
             row.description, row.enabled)
            for row in db.scalars(select(DnsRecord)).all()
        )
        dns_updated_at_before = db.scalar(select(DnsSettings)).updated_at
        dns_cache_size_before = db.scalar(select(DnsSettings)).cache_size
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
        # Recovery discards the injected, uncommitted same-writer fault.
        with SessionLocal() as db:
            assert db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "dynamic0")).host_ip_cidr == "192.0.2.11/24"
            assert db.scalar(select(CaSettings)).listen_address == "192.0.2.11"
            dns_settings = db.scalar(select(DnsSettings))
            if dynamic_failure == "identity-dns-zone-toggle":
                assert dns_settings.domain == "atlaso.internal\ncustom.example.internal"
                assert dns_settings.disabled_domains == ""
            elif dynamic_failure == "identity-dns-render-setting":
                assert dns_settings.domain == "atlaso.internal\ncustom.example.internal"
                assert dns_settings.disabled_domains == ""
                assert dns_settings.cache_size == dns_cache_size_before
                assert dns_settings.updated_at == dns_updated_at_before
            if dynamic_failure in {"identity-dns-zone-toggle", "identity-dns-render-setting"}:
                dns_rows_after = sorted(
                    (row.id, row.hostname, row.record_type, row.address, row.record_data_json,
                     row.description, row.enabled)
                    for row in db.scalars(select(DnsRecord)).all()
                )
                assert dns_rows_after == dns_rows_before
            owned = db.scalars(select(DnsRecord).where(DnsRecord.description == CA_PORTAL_DNS_DESCRIPTION,
                                                      DnsRecord.record_type == "A")).all()
            assert owned and {row.address for row in owned} == {"192.0.2.11"}
            if dynamic_failure == "identity-dns-edit":
                generated = db.scalar(select(DnsRecord).where(
                    DnsRecord.hostname == "ca.custom.example.internal",
                    DnsRecord.record_type == "A",
                    DnsRecord.address == "192.0.2.11",
                    DnsRecord.description == CA_PORTAL_DNS_DESCRIPTION,
                ))
                assert generated is not None and generated.enabled is True
            elif dynamic_failure == "identity-dns-create":
                concurrent_conflict = db.scalar(select(DnsRecord).where(
                    DnsRecord.hostname == "ca.custom.example.internal",
                    DnsRecord.record_type == "A",
                    DnsRecord.address == "192.0.2.99",
                    DnsRecord.description == "Operator conflict",
                ))
                assert concurrent_conflict is None
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
        "identity-dns-edit": "Service DNS identity changed during network readiness; resubmit the changes.",
        "identity-dns-create": "Service DNS identity changed during network readiness; resubmit the changes.",
        "identity-dns-zone-toggle": "Service DNS identity changed during network readiness; resubmit the changes.",
        "identity-dns-render-setting": "Service DNS identity changed during network readiness; resubmit the changes.",
    }.get(dynamic_failure, "controlled DNS readback failure")
    assert group["management_handoff"]["error"] == expected_error
    assert group["management_handoff"]["rolled_back"] is True
    assert any(
        command["command"] == ["service-dns", "readback"] and command["returncode"] == 1
        for command in group["commands"]
    )
    assert all(row["success"] is False and row["rolled_back"] is True for row in results)
    if (dynamic_failure or "").startswith("identity"):
        assert dns_publication_attempts == []
        assert "verified_service_dns_records" not in units["dnsmasq"]


def _run_static_identity_race_handoff(client, monkeypatch, tmp_path, *, concurrent_identity_edit, missing_replacement, nss_failure=False):
    """Run a static DNS handoff while another session may change service identity.

    Args:
        client: Isolated application client used to initialize the database.
        monkeypatch: Replace helper staging and DNS readback boundaries.
        tmp_path: Owned location for mocked staged configuration paths.
        concurrent_identity_edit: Inject a service hostname edit in the admitted helper callback.
        missing_replacement: Simulate a DNS answer that lacks the submitted owner.
        nss_failure: Fail appliance-local resolution after direct DNS succeeds.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaSettings
    from atlaso.app.services.service_dns_defaults import CA_PORTAL_DNS_DESCRIPTION

    class StaticHandoffAdapter:
        """Apply the captured static handoff and report rollback when readback fails."""

        dry_run = False

        def validate_management_handoff(self, manifest_path):
            """Validate the staged management-handoff manifest.

            Args:
                manifest_path: Path to the staged management-handoff manifest.
            """
            return AdapterResult(command=["atlaso-helper", "validate", manifest_path], dry_run=False, returncode=0)

        def apply_management_handoff(self, manifest_path):
            """Apply the staged management-handoff manifest.

            Args:
                manifest_path: Path to the staged management-handoff manifest.
            """
            if concurrent_identity_edit:
                # Inject a same-writer callback fault; external writers now wait for publication.
                from contextlib import nullcontext

                with nullcontext(db) as other:
                    settings = other.scalar(select(CaSettings))
                    settings.portal_hostname = "ca.concurrent.example.internal"
                    ui.refresh_interface_service_dns_aliases(other, actor=None)
                    other.flush()
            return AdapterResult(command=["atlaso-helper", "apply", manifest_path], dry_run=False, returncode=0)

        def recover_management_handoff(self):
            return AdapterResult(
                command=["atlaso-helper", "recover"], dry_run=False, returncode=0,
                stdout=json.dumps({"management_handoff": "rolled back", "rolled_back": True}),
            )

    monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(tmp_path / "ca.json"))
    monkeypatch.setattr(ui, "MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH", str(tmp_path / "handoff.json"))
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda target, _content: str(target))
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
    observed = []

    def verify(records, prior_records, config, *, authoritative):
        """Verify the DNS records returned by the controlled readback.

        Args:
            records: Desired DNS records used for the readback check.
            prior_records: Previously owned DNS records whose removal must be verified.
            config: Candidate DNS or management configuration used for validation.
            authoritative: Whether the mocked DNS answer is authoritative.
        """
        observed.append([dict(record) for record in records])
        assert prior_records
        assert config
        assert authoritative is True
        if missing_replacement and any(
            record["hostname"] == "ca.custom.example.internal"
            and record["description"] == CA_PORTAL_DNS_DESCRIPTION
            for record in records
        ):
            raise ValueError("DNS replacement answer is missing the submitted service owner.")

    if nss_failure:
        from atlaso.app.services import service_dns_readback

        monkeypatch.setattr(service_dns_readback, "verify_service_dns_records",
                            lambda records, **_kwargs: observed.append([dict(record) for record in records]))

        def fail_nss(_records, **_kwargs):
            """Raise the configured local name-service lookup failure.

            Args:
                _records: DNS records supplied to the mocked resolver.
                **_kwargs: Captured prior ownership passed to the resolver.
            """
            raise ValueError("Controlled stale NSS service DNS answer.")

        monkeypatch.setattr(service_dns_readback, "verify_service_dns_nss", fail_nss)
    else:
        monkeypatch.setattr(ui, "verify_handoff_service_dns", verify)
    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        access.ip_cidr = "192.0.2.21/24"
        ca = db.scalar(select(CaSettings))
        ca.listen_address = "192.0.2.21\n2001:db8::10"
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        db.commit()
        units_by_id = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        submitted = ui.owned_service_dns_records(db, units_by_id["dnsmasq"]["raw_config_preview"])
        assert any(
            record["description"] == CA_PORTAL_DNS_DESCRIPTION and record["address"] == "192.0.2.21"
            for record in submitted
        ), [
            (record["hostname"], record["record_type"], record["address"])
            for record in submitted if record["description"] == CA_PORTAL_DNS_DESCRIPTION
        ]

        group, results = ui.execute_management_handoff(
            units_by_id,
            job_id="job_static_dns_identity_race",
            adapter=StaticHandoffAdapter(),
            db=db,
            include_dnsmasq=True,
        )
        if not missing_replacement:
            db.expire_all()
            ui.update_appliance_apply_baselines(db, list(units_by_id.values()), {"dnsmasq"})
            baseline = ui.load_appliance_apply_baselines(db)["dnsmasq"]
            live_config = ui.dnsmasq_context(db, reconcile=False, include_leases=False)["config_preview"]
            live_records = ui.owned_service_dns_records(db, live_config)
            return submitted, observed, group, results, units_by_id["dnsmasq"], baseline, live_records
        return submitted, observed, group, results, units_by_id["dnsmasq"], {}, []


def test_static_handoff_keeps_submitted_dns_ownership_across_concurrent_identity_edit(client, monkeypatch, tmp_path):
    """Verify and baseline the exact submitted DNS records despite a later DB edit.

    Args:
        client: HTTP test client for the UI request.
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
    """
    submitted, observed, group, _results, dnsmasq, baseline, live_records = _run_static_identity_race_handoff(
        client, monkeypatch, tmp_path, concurrent_identity_edit=True, missing_replacement=False,
    )

    assert group["success"] is True
    assert observed == [submitted]
    assert dnsmasq["verified_service_dns_records"] == submitted
    assert baseline["service_dns_records"] == submitted
    assert any(record["hostname"] == "ca.concurrent.example.internal" for record in live_records)


def test_static_handoff_missing_submitted_dns_replacement_recovers(client, monkeypatch, tmp_path):
    """Reject missing static DNS readback and recover the prior handoff state.

    Args:
        client: HTTP test client for the UI request.
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
    """
    submitted, observed, group, results, dnsmasq, _baseline, _live_records = _run_static_identity_race_handoff(
        client, monkeypatch, tmp_path, concurrent_identity_edit=True, missing_replacement=True,
    )

    assert observed == [submitted]
    assert group["success"] is False
    assert group["rollback_proven"] is True
    assert group["management_handoff"]["failing_layer"] == "generated service DNS readback"
    assert group["management_handoff"]["error"] == "DNS replacement answer is missing the submitted service owner."
    assert group["management_handoff"]["rolled_back"] is True
    assert "verified_service_dns_records" not in dnsmasq
    assert all(row["success"] is False and row["rolled_back"] is True for row in results)


def test_static_handoff_nss_failure_recovers_after_direct_dns_succeeds(client, monkeypatch, tmp_path):
    """Recover when appliance-local resolution disagrees with successful direct DNS.

    Args:
        client: HTTP test client for the UI request.
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
    """
    submitted, observed, group, results, dnsmasq, _baseline, _live_records = _run_static_identity_race_handoff(
        client, monkeypatch, tmp_path, concurrent_identity_edit=True, missing_replacement=True, nss_failure=True,
    )

    assert observed == [submitted]
    assert group["success"] is False
    assert group["rollback_proven"] is True
    assert group["management_handoff"]["failing_layer"] == "generated service DNS readback"
    assert group["management_handoff"]["error"] == "Controlled stale NSS service DNS answer."
    assert "verified_service_dns_records" not in dnsmasq
    assert all(row["success"] is False and row["rolled_back"] is True for row in results)


@pytest.mark.parametrize("pending_dependency", [None, "ca", "firewall", "appliance_settings", "public_services"])
def test_slaac_address_drift_offers_network_review_and_captures_dns_after_reboot(client, monkeypatch, pending_dependency):
    """Expose unchanged Network intent when SLAAC DNS needs a readiness handoff.

    Args:
        client: Authenticated application test client.
        monkeypatch: Host discovery and asynchronous job execution substitutions.
        pending_dependency: Unrelated protected unit deliberately omitted from the first submission.
    """
    from atlaso.app import main, ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job, JobStatus, PhysicalInterface
    from atlaso.app.services.networking import HostPhysicalInterface

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        address_pattern_record = db.scalar(select(DnsRecord).where(
            DnsRecord.hostname == "ca-192-0-2-10.custom.example.internal",
            DnsRecord.description == "Operator",
        ))
        if address_pattern_record is not None:
            db.delete(address_pattern_record)
        access.host_ip_cidr = "192.0.2.10/24"
        access.ipv6_cidr = None
        access.host_ipv6_cidr = "2001:db8::10/64"
        access.ipv6_enabled = True
        interfaces = db.scalars(select(PhysicalInterface).order_by(PhysicalInterface.name)).all()
        for interface in interfaces:
            # Model previously reviewed intent so startup discovery updates only observations.
            interface.desired_state_source = "user"
        db.flush()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = ui.load_appliance_apply_baselines(db)
        baselines["appliance_settings"]["config_preview"] = json.dumps(
            {"resolver_mode": "local_dns", "resolver_servers": ["127.0.0.1"]}
        )
        ui.save_appliance_apply_baselines(db, baselines)
        db.add(Job(
            id="prior-successful-appliance-apply",
            type="appliance-apply",
            status=JobStatus.SUCCEEDED.value,
            created_by="admin",
            result="{}",
        ))
        # This operator edit remains pending until DNS is explicitly selected.
        db.add(DnsRecord(
            hostname="operator-pending.example.internal", record_type="TXT", address="pending-note",
            description="Operator", enabled=True,
        ))
        db.commit()

    discovery = []
    for interface in interfaces:
        is_access = interface.name == "eth9"
        discovery.append(HostPhysicalInterface(
            name=interface.name,
            mac_address=interface.mac_address or "",
            driver=None,
            speed=None,
            host_ip_cidr=interface.ip_cidr or interface.host_ip_cidr,
            host_mtu=interface.mtu,
            host_admin_state=interface.admin_state,
            oper_state="up" if interface.admin_state == "up" else "down",
            host_ipv6_cidr=(
                "2001:db8::21/64" if is_access else interface.ipv6_cidr or interface.host_ipv6_cidr
            ),
            host_dynamic_ipv6_cidr="2001:db8::21/64" if is_access else None,
            host_dynamic_ipv6_cidrs=("2001:db8::21/64",) if is_access else (),
        ))
    monkeypatch.setattr("atlaso.app.services.networking.discover_host_physical_interfaces", lambda **kwargs: discovery)
    with SessionLocal() as db:
        main.refresh_startup_host_inventory(db, environment="appliance")
        context = ui.appliance_apply_context(db)
        network = next(unit for unit in context["apply_units"] if unit["id"] == "network")
        assert network["changed"] is False, network["config_diff"]
        desired_dns = next(unit for unit in context["apply_units"] if unit["id"] == "dnsmasq")
        assert "2001:db8::21" in desired_dns["raw_config_preview"]
        assert "network" not in {unit["id"] for unit in context["changed_apply_units"]}
        assert context["changed_apply_unit_count"] == len(context["changed_apply_units"])
        offered_network = next(unit for unit in context["review_apply_units"] if unit["id"] == "network")
        assert offered_network["valid"] is True, offered_network["validation_errors"]
        assert any(
            "dns" in summary.lower() and "listener" in summary.lower()
            for summary in offered_network["summary"]
        )

    if pending_dependency:
        render_units = ui.appliance_apply_units

        def pending_units(*args, **kwargs):
            # Model an independently saved edit without changing the DNS identity.
            """Return the pending units selected for appliance apply.

            Args:
                *args: Positional arguments forwarded to the wrapped operation.
                **kwargs: Keyword arguments forwarded to the wrapped operation.
            """
            rendered = render_units(*args, **kwargs)
            for unit in rendered:
                if unit["id"] != pending_dependency:
                    continue
                unit["changed"] = True
                unit["snapshot_hash"] = "pending-independent-edit"
                for key in ("config_preview", "raw_config_preview"):
                    if unit[key].lstrip().startswith("{"):
                        unit[key] = json.dumps({**json.loads(unit[key]), "pending_review_note": "independent edit"})
                    else:
                        unit[key] += "\n# pending independent edit"
            return rendered

        monkeypatch.setattr(ui, "appliance_apply_units", pending_units)

    review_response = client.get("/appliance-apply/review")
    assert review_response.status_code == 200, review_response.text
    review = review_response.json()
    network_review = next(unit for unit in review["units"] if unit["id"] == "network")
    dns_review = next(unit for unit in review["units"] if unit["id"] == "dnsmasq")
    assert network_review["valid"] is True
    assert network_review["selected"] is True
    assert any(
        "dns" in summary.lower() and "listener" in summary.lower()
        for summary in network_review["summary"]
    )
    assert dns_review["valid"] is True

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    required_dependencies = [unit["id"] for unit in review["units"] if unit.get("requires_network_selection")]
    if pending_dependency:
        assert pending_dependency in required_dependencies
        pending_review = next(unit for unit in review["units"] if unit["id"] == pending_dependency)
        assert any("Required with Network" in summary for summary in pending_review["summary"])
    if required_dependencies:
        with SessionLocal() as db:
            previous_baselines = ui.load_appliance_apply_baselines(db)
        rejected = client.post(
            "/appliance-apply",
            data={"csrf": csrf, "selected_units": ["network", "dnsmasq"]},
            headers={"Accept": "application/json"},
        )
        assert rejected.status_code == 422, rejected.text
        assert "Unchecked changes cannot be applied" in rejected.json()["detail"]
        with SessionLocal() as db:
            assert ui.load_appliance_apply_baselines(db) == previous_baselines
            assert db.scalar(select(Job).where(Job.status == JobStatus.PENDING.value)) is None
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network", "dnsmasq", *required_dependencies]},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 202, response.text

    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
        assert payload["management_handoff"] is True
        assert payload["generated_dns_only"] is False
        assert payload["dns_resolver_activation"] is False
        assert {"network", "dnsmasq", *ui.MANAGEMENT_HANDOFF_UNIT_IDS} <= set(payload["selected_units"])
        dns_capture = next(unit for unit in payload["captured_units"] if unit["unit_id"] == "dnsmasq")
        preview = dns_capture["config_preview"]
        assert "cname=ca.custom.example.internal," in preview
        assert "host-record=ca-192-0-2-10.custom.example.internal,192.0.2.10" in preview
        assert "host-record=ca-2001-db8-0-0-0-0-0-21.custom.example.internal,2001:db8::21" in preview
        assert "host-record=ca-2001-db8-0-0-0-0-0-10.custom.example.internal,2001:db8::10" not in preview
        assert 'txt-record=operator-pending.example.internal,"pending-note"' in preview


@pytest.mark.parametrize("dynamic", [False, True], ids=["static", "slaac"])
def test_depot_generated_dns_captures_custom_port_listener_move_without_pending_edits(client, dynamic):
    """Protect the separate applied Depot nginx site while leaving other edits pending.

    Args:
        client: Isolated appliance client.
        dynamic: Use native-observed SLAAC rather than a saved static IPv6 address.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfOfflineDepotSettings

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        depot = db.scalar(select(VcfOfflineDepotSettings))
        depot.port = 9443
        if dynamic:
            access.ipv6_cidr = None
            access.host_ipv6_cidr = "2001:db8::10/64"
        db.flush()
        prior_units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, prior_units, {unit["id"] for unit in prior_units})
        prior = ui.load_appliance_apply_baselines(db)
        # The operator's independently saved port edit is never an address-only move.
        depot.port = 10443
        if dynamic:
            access.host_ipv6_cidr = "2001:db8::21/64"
        else:
            access.ipv6_cidr = "2001:db8::21/64"
        db.flush()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        generated = ui.network_generated_dns_unit(db, units)
        moves = [move for move in generated["listener_address_moves"] if move["service"] == "vcf_offline_depot"]
        ipv6_move = next(move for move in moves if move["old_address"] == "2001:db8::10")
        assert ipv6_move["new_address"] == "2001:db8::21"
        assert (ipv6_move.get("interface") == access.name) is dynamic
        projected = ui.projected_handoff_listener_baselines(prior, units, moves)["vcf_offline_depot"]
        assert "listen [2001:db8::21]:9443 ssl;" in projected["config_preview"]
        assert "listen [2001:db8::10]:9443 ssl;" not in projected["config_preview"]
        assert "10443" not in projected["config_preview"]
        assert "# Listen addresses: 192.0.2.10, 2001:db8::21" in projected["config_preview"]
        assert projected["snapshot_marker"] == prior["vcf_offline_depot"]["snapshot_marker"]
        assert "listen [2001:db8::21]:10443 ssl;" in units["vcf_offline_depot"]["config_preview"]
        unchanged_prefix = prior["vcf_offline_depot"]["config_preview"].split("# VCFDT", 1)[1]
        assert projected["config_preview"].split("# VCFDT", 1)[1] == unchanged_prefix


def test_verified_depot_moves_update_separately_selected_captured_config(client, monkeypatch, tmp_path):
    """Keep approved Depot edits while preventing a later step from restoring an old bind.

    Args:
        client: Isolated appliance client.
        monkeypatch: Substitute native execution, staging and DNS query boundaries.
        tmp_path: Private pytest path for staged CA configuration.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfOfflineDepotSettings
    from atlaso.app.services import service_dns_readback

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        depot = db.scalar(select(VcfOfflineDepotSettings))
        depot.port = 9443
        access.ipv6_cidr = None
        access.host_ipv6_cidr = "2001:db8::10/64"
        db.flush()
        prior = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, prior, {unit["id"] for unit in prior})
        access.ip_cidr = "192.0.2.11/24"
        access.host_ipv6_cidr = "2001:db8::11/64"
        depot.port = 10443
        db.flush()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        units["dnsmasq"] = ui.network_generated_dns_unit(db, units)
        moves = units["dnsmasq"]["listener_address_moves"]
        # Native proof can choose a later address than the captured candidate.
        native_moves = [{**move, "new_address": move["new_address"].replace("::11", "::21")}
                        for move in moves]

        class Adapter:
            dry_run = False

            def validate_management_handoff(self, _path):
                """Validate the staged management-handoff manifest.

                Args:
                    _path: Candidate configuration path supplied to the validation or apply callback.
                """
                return AdapterResult(command=["validate"], dry_run=False, returncode=0)

            def apply_management_handoff(self, _path):
                """Apply the staged management-handoff manifest.

                Args:
                    _path: Candidate configuration path supplied to the validation or apply callback.
                """
                return AdapterResult(command=["apply"], dry_run=False, returncode=0,
                                     stdout=json.dumps({"management_handoff": "applied",
                                                        "listener_address_moves": native_moves,
                                                        "public_service_address_moves": [{
                                                            "interface": access.name,
                                                            "old_address": "2001:db8::11",
                                                            "new_address": "2001:db8::21",
                                                        }]}))

            def validate_dnsmasq_config(self, _path):
                """Validate the candidate dnsmasq configuration path.

                Args:
                    _path: Candidate configuration path supplied to the validation or apply callback.
                """
                return AdapterResult(command=["dnsmasq", "validate"], dry_run=False, returncode=0)

            def apply_dnsmasq_config(self, _path):
                """Apply the candidate dnsmasq configuration path.

                Args:
                    _path: Candidate configuration path supplied to the validation or apply callback.
                """
                return AdapterResult(command=["dnsmasq", "apply"], dry_run=False, returncode=0)

            def reload_dnsmasq(self):
                return AdapterResult(command=["dnsmasq", "reload"], dry_run=False, returncode=0)

            def recover_management_handoff(self):
                raise AssertionError("successful captured projection must not require recovery")

        def effective_observation(_db, _config, _evidence, **_kwargs):
            """Return the controlled effective-address observation.

            Args:
                _db: Database session passed to the address-observation function.
                _config: Configuration passed to the address-observation function.
                _evidence: Captured evidence passed to the address-observation function.
                **_kwargs: Keyword arguments accepted by the wrapped operation.
            """
            access.host_ipv6_cidr = "2001:db8::21/64"
            db.flush()

        monkeypatch.setattr(ui, "refresh_service_dns_effective_observations", effective_observation)
        monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(tmp_path / "ca.json"))
        monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda target, _content: str(target))
        monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
        readback_calls = []
        monkeypatch.setattr(service_dns_readback, "verify_service_dns_records",
                            lambda records, **kwargs: readback_calls.append((records, kwargs)))
        monkeypatch.setattr(service_dns_readback, "verify_service_dns_nss", lambda _records, **_kwargs: None)
        group, _results = ui.execute_management_handoff(
            units, job_id="job_depot853abc", adapter=Adapter(), db=db, include_dnsmasq=True,
        )
        assert group["success"] is True
        assert any(record["address"] == "2001:db8::10"
                   for record in readback_calls[0][1]["prior_records"])
        assert any(record["address"] == "2001:db8::21" for record in readback_calls[0][0])
        captured = units["vcf_offline_depot"]
        assert "listen [2001:db8::21]:10443 ssl;" in captured["config_preview"]
        assert "listen [2001:db8::11]:10443 ssl;" not in captured["config_preview"]
        assert "listen [2001:db8::21]:10443 ssl;" in captured["context"]["vcf_depot_https_config_preview"]
        prior_projection = group["listener_baselines"]["vcf_offline_depot"]["config_preview"]
        assert "listen [2001:db8::21]:9443 ssl;" in prior_projection
        assert "10443" not in prior_projection


@pytest.mark.parametrize("failed_listener", [None, "192.0.2.21", "authoritative"],
                         ids=["all-paths", "client-unavailable", "backend-unavailable"])
def test_handoff_readback_requires_captured_authoritative_and_recursive_paths(monkeypatch, failed_listener):
    """Query applied endpoints, retaining retired expectations on every DNS path.

    Args:
        monkeypatch: Replace direct UDP queries with endpoint evidence.
        failed_listener: Inject failure on one protected endpoint.
    """
    from atlaso.app import ui
    from atlaso.app.services import service_dns_readback

    prior = [{"hostname": "retired.example.internal", "record_type": "AAAA", "address": "2001:db8::10"}]
    desired = [{"hostname": "ca.example.internal", "record_type": "A", "address": "192.0.2.21"}]
    config = ("listen-address=192.0.2.21\nlisten-address=127.0.0.1\n"
              "# atlaso-authoritative-config: port=5353\n"
              "# atlaso-authoritative-config: listen-address=127.0.0.1\n"
              "# atlaso-authoritative-config: auth-zone=example.internal,192.0.2.0/24\n")
    calls = []

    def verify(records, **kwargs):
        """Verify the DNS records returned by the controlled readback.

        Args:
            records: Desired DNS records used for the readback check.
            **kwargs: Keyword arguments forwarded to the wrapped operation.
        """
        calls.append((records, kwargs))
        if (failed_listener and (kwargs.get("nameserver") == failed_listener
                or (failed_listener == "authoritative" and kwargs.get("port") == 5353))):
            raise ValueError("controlled listener failure")

    monkeypatch.setattr(service_dns_readback, "verify_service_dns_records", verify)
    nss_calls = []
    monkeypatch.setattr(service_dns_readback, "verify_service_dns_nss", lambda records, **kwargs: nss_calls.append((records, kwargs)))
    if failed_listener:
        with pytest.raises(ValueError, match="controlled listener failure"):
            ui.verify_handoff_service_dns(desired, prior, config, authoritative=True)
    else:
        ui.verify_handoff_service_dns(desired, prior, config, authoritative=True)
        assert len(calls) == 3
        assert nss_calls == [(desired, {"prior_records": prior})]
        assert calls[0] == (desired, {"prior_records": prior})
        assert calls[1] == (desired, {"nameserver": "192.0.2.21", "prior_records": prior,
                                     "require_authoritative": True})
        assert calls[2] == (desired, {"nameserver": "127.0.0.1", "port": 5353,
                                     "prior_records": prior, "require_authoritative": True})


def test_handoff_readback_rejects_missing_authoritative_evidence(monkeypatch):
    """Never substitute pending DNS settings for absent captured authoritative bindings.

    Args:
        monkeypatch: Replace UDP query execution.
    """
    from atlaso.app import ui
    from atlaso.app.services import service_dns_readback

    monkeypatch.setattr(service_dns_readback, "verify_service_dns_records", lambda *_args, **_kwargs: None)
    with pytest.raises(ValueError, match="listener evidence is incomplete"):
        ui.verify_handoff_service_dns([], [], "listen-address=127.0.0.1\n", authoritative=True)


@pytest.mark.parametrize("failed_listener", [None, "recursive", "client", "authoritative"])
def test_handoff_synthetic_own_hostname_preserves_all_wire_checks(monkeypatch, failed_listener):
    """Synthetic native NSS permits the own name without weakening wire publication.

    Args:
        monkeypatch: Replace native commands and wire queries with captured evidence.
        failed_listener: Wire endpoint whose exact publication proof fails.
    """
    from atlaso.app import ui
    from atlaso.app.services import service_dns_readback

    records = [{"hostname": "atlaso.lab.internal", "record_type": "A", "address": "192.0.2.10"}]
    config = ("listen-address=192.0.2.20\nlisten-address=127.0.0.1\n"
              "# atlaso-authoritative-config: port=5353\n"
              "# atlaso-authoritative-config: listen-address=127.0.0.1\n"
              "# atlaso-authoritative-config: auth-zone=lab.internal,192.0.2.0/24\n")
    calls = []

    def verify(captured, **kwargs):
        """Reject the selected wire endpoint while recording all attempted checks.

        Args:
            captured: Captured generated ownership sent to the wire verifier.
            **kwargs: Endpoint and retirement verification options.
        """
        calls.append((captured, kwargs))
        endpoint = ("authoritative" if kwargs.get("port") == 5353 else
                    "client" if kwargs.get("nameserver") else "recursive")
        if endpoint == failed_listener:
            raise ValueError("wire publication failure")

    def run(args, **_kwargs):
        """Return fresh multi-interface synthesis and local-address evidence.

        Args:
            args: Native readback argument vector.
            **_kwargs: Bounded native invocation options.
        """
        if args[0] == "getent":
            return SimpleNamespace(returncode=0, stdout="::1 atlaso.lab.internal\n", stderr="")
        if args[0] == "resolvectl":
            return SimpleNamespace(returncode=0, stderr="", stdout=(
                "atlaso.lab.internal: 192.0.2.10 -- link: eth0\n"
                "                     192.0.2.20 -- link: eth1\n"
                "                     ::1\n\n-- Data from: synthetic\n"))
        assert args == ["ip", "-j", "address", "show"]
        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps([
            {"addr_info": [{"local": "192.0.2.10"}]},
            {"addr_info": [{"local": "192.0.2.20"}]},
        ]))

    monkeypatch.setattr(service_dns_readback, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(service_dns_readback.socket, "gethostname", lambda: "atlaso.lab.internal")
    monkeypatch.setattr(service_dns_readback.subprocess, "run", run)
    monkeypatch.setattr(service_dns_readback, "verify_service_dns_records", verify)
    if failed_listener:
        with pytest.raises(ValueError, match="wire publication failure"):
            ui.verify_handoff_service_dns(records, [], config, authoritative=True)
    else:
        ui.verify_handoff_service_dns(records, [], config, authoritative=True)
        assert calls == [
            (records, {"prior_records": []}),
            (records, {"nameserver": "192.0.2.20", "prior_records": [], "require_authoritative": True}),
            (records, {"nameserver": "127.0.0.1", "port": 5353, "prior_records": [],
                       "require_authoritative": True}),
        ]
