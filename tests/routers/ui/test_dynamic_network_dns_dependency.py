"""Cover protected DNS readiness for dynamic Network-only changes."""

import json

from sqlalchemy import select

from tests.routers.ui.helpers import login
from tests.routers.ui.test_generated_dns_apply import _prepare_service_address_baseline


def test_network_mtu_only_slaac_change_projects_dynamic_dns_and_uses_handoff(client, monkeypatch):
    """Dynamic listeners enter protected readiness when Network changes without address edits.

    Args:
        client: Isolated authenticated application client.
        monkeypatch: Prevent background apply execution.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsRecord, Job, PhysicalInterface

    expected_address = "2001:db8::10"

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        access.mtu = 1500
        access.ipv6_enabled = True
        access.ipv6_cidr = None
        access.host_ipv6_cidr = f"{expected_address}/64"
        db.flush()
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        baseline_units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, baseline_units, {unit["id"] for unit in baseline_units})

        # A pending operator record must remain outside the generated ownership projection.
        db.add(DnsRecord(
            hostname="operator-pending.example.internal", record_type="TXT", address="pending-note",
            description="Operator", enabled=True,
        ))
        access.mtu = 1400
        db.flush()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert units["network"]["changed"] is True
        assert access.mtu == 1400
        assert units["network"]["validation_errors"] == []

        projected = ui.network_generated_dns_unit(db, units)
        assert projected is not None
        assert projected["generated_dns_only"] is True
        assert projected["validation_errors"] == []
        assert {
            "service": "ntpd",
            "interface": "eth9",
            "old_address": expected_address,
            "new_address": expected_address,
        } in projected["listener_address_moves"]
        assert "txt-record=operator-pending.example.internal,pending-note" not in projected["raw_config_preview"]
        assert ui.network_listener_handoff_required(db, units) is True
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
        capture = next(row for row in payload["captured_units"] if row["unit_id"] == "dnsmasq")
        assert expected_address in capture["config_preview"]
        assert "operator-pending.example.internal" not in capture["config_preview"]
        assert db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth9")).mtu == 1400


def test_static_only_mtu_change_does_not_create_dynamic_dns_dependency(client):
    """A static source with stable addresses does not gain the dynamic readiness dependency.

    Args:
        client: Isolated authenticated application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        access.mtu = 1500
        db.flush()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        access.mtu = 1400
        db.flush()
        units_by_id = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}

        assert units_by_id["network"]["changed"] is True
        assert ui.network_generated_dns_unit(db, units_by_id) is None
        assert ui.network_listener_handoff_required(db, units_by_id) is False


def test_network_mtu_only_management_dhcp_projects_appliance_dns(client):
    """A valid management DHCP source admits its applied appliance FQDN to projection.

    Args:
        client: Isolated authenticated application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        management, _access = _prepare_service_address_baseline(db, ui)
        management.ipv4_method = "dhcp"
        management.host_ip_cidr = "198.51.100.10/24"
        management.ip_cidr = None
        management.mtu = 1500
        db.flush()
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        baseline_units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, baseline_units, {unit["id"] for unit in baseline_units})
        baseline = ui.load_appliance_apply_baselines(db)["dnsmasq"]
        assert any(
            row["description"] == ui.APPLIANCE_DNS_RECORD_DESCRIPTION and row["address"] == "198.51.100.10"
            for row in baseline["service_dns_records"]
        )

        management.mtu = 1400
        db.flush()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        projected = ui.network_generated_dns_unit(db, units)

        assert units["network"]["changed"] is True
        assert units["network"]["validation_errors"] == []
        assert projected is not None
        assert projected["generated_dns_only"] is True
        assert ui.get_appliance_settings_row(db).fqdn in projected["raw_config_preview"]
        assert "198.51.100.10" in projected["raw_config_preview"]
        assert projected["listener_address_moves"] == []


def test_admin_down_dynamic_source_is_not_admitted_as_active_listener_move(client):
    """A disabled dynamic source is not promoted to active listener readiness.

    Args:
        client: Isolated authenticated application client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    login(client)
    with SessionLocal() as db:
        _management, access = _prepare_service_address_baseline(db, ui)
        access.ipv6_enabled = True
        access.ipv6_cidr = None
        access.host_ipv6_cidr = "2001:db8::10/64"
        access.mtu = 1500
        db.flush()
        ui.refresh_interface_service_dns_aliases(db, actor=None)
        baseline_units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, baseline_units, {unit["id"] for unit in baseline_units})
        access.admin_state = "down"
        access.mtu = 1400
        db.flush()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}

        # Retirement of records after disablement is allowed; it must not claim an
        # unchanged address as a listener move for the disabled source.
        projected = ui.network_generated_dns_unit(db, units)
        if projected is not None:
            assert not any(
                move.get("interface") == "eth9" and move["service"] == "ntpd"
                for move in projected["listener_address_moves"]
            )
