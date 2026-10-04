"""Protect dynamic Public Services listeners during Network Apply admission."""

import json

import pytest
from sqlalchemy import select

from tests.routers.ui.helpers import login


def _prepare_dynamic_public_baseline(db, ui, *, dns_enabled: bool, access_dynamic: bool = True):
    """Capture a known applied dynamic Public Services listener state.

    Args:
        db: Test database session.
        ui: Appliance Apply module used to capture baselines.
        dns_enabled: Whether the applied DNS baseline reports DNS enabled.
        access_dynamic: Whether the public interface uses SLAAC.

    Returns:
        The public access interface.
    """
    from atlaso.app.models import (
        CaSettings,
        DnsSettings,
        Job,
        JobStatus,
        NtpSettings,
        VcfOfflineDepotSettings,
    )
    from tests.routers.ui.test_generated_dns_apply import (
        _prepare_service_address_baseline,
    )

    _management, access = _prepare_service_address_baseline(db, ui)
    dns = db.scalar(select(DnsSettings))
    dns.enabled = dns_enabled
    access.ipv4_method = "static"
    access.ip_cidr = "192.0.2.10/24"
    access.host_ip_cidr = "192.0.2.10/24"
    access.ipv6_enabled = True
    access.ipv6_cidr = None if access_dynamic else "2001:db8::10/64"
    access.host_ipv6_cidr = "2001:db8::10/64"
    ca = db.scalar(select(CaSettings))
    ca.enabled = True
    ca.listen_interface = access.name
    ca.listen_address = "192.0.2.10\n2001:db8::10"
    db.scalar(select(NtpSettings)).enabled = False
    db.scalar(select(VcfOfflineDepotSettings)).enabled = False

    units = ui.appliance_apply_units(db)
    ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
    baselines = ui.load_appliance_apply_baselines(db)
    if dns_enabled:
        # Model an applied enabled DNS service with no captured Atlaso-owned
        # records. Listener admission must not depend on that inventory.
        baselines["dnsmasq"]["service_dns_records"] = []
    ui.save_appliance_apply_baselines(db, baselines)
    db.add(Job(
        id=f"prior-public-handoff-{access.id}",
        type="appliance-apply",
        status=JobStatus.SUCCEEDED.value,
        created_by="admin",
        result="{}",
    ))
    db.flush()
    return access


def _mark_pending_protected_units(monkeypatch, ui):
    """Make the protected handoff units independently pending for review.

    Args:
        monkeypatch: Pytest fixture for replacing Apply unit rendering.
        ui: Appliance Apply module whose renderer is wrapped.
    """
    original = ui.appliance_apply_units
    pending = {"ca", "firewall", "appliance_settings", "public_services"}

    def render_with_pending(*args, **kwargs):
        """Return captured units with controlled independent pending changes.

        Args:
            *args: Arguments forwarded to the real unit renderer.
            **kwargs: Keyword arguments forwarded to the real unit renderer.
        """
        units = original(*args, **kwargs)
        for unit in units:
            if unit["id"] in pending:
                unit["changed"] = True
                unit["snapshot_hash"] = f"pending-{unit['id']}"
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", render_with_pending)


@pytest.mark.parametrize("applied_dns", ["disabled", "enabled-without-owned-records"])
def test_dynamic_public_listener_requires_network_handoff_without_dns_projection(
    client, monkeypatch, applied_dns
):
    """A SLAAC public listener protects Network even without generated DNS ownership.

    Args:
        client: Authenticated application test client.
        monkeypatch: Host job runner and Apply unit rendering substitutions.
        applied_dns: DNS baseline condition unrelated to listener safety.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    with SessionLocal() as db:
        access = _prepare_dynamic_public_baseline(
            db, ui, dns_enabled=applied_dns != "disabled"
        )
        access.mtu = 1400
        db.commit()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert units["network"]["changed"] is True
        assert units["public_services"]["context"]["public_service_entries"]
        assert ui.network_dynamic_public_bindings(units) == [
            {"interface": "eth9", "old_address": "2001:db8::10"}
        ]
        assert ui.network_generated_dns_unit(db, units) is None
        assert ui.network_listener_handoff_required(db, units) is True

    _mark_pending_protected_units(monkeypatch, ui)
    review_response = client.get("/appliance-apply/review")
    assert review_response.status_code == 200, review_response.text
    review = review_response.json()
    reviewed_network = next(unit for unit in review["units"] if unit["id"] == "network")
    assert reviewed_network["valid"] is True, reviewed_network["validation_errors"]
    required = {
        unit["id"] for unit in review["units"]
        if unit.get("requires_network_selection")
    }
    assert required == {"ca", "firewall", "appliance_settings", "public_services"}

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    rejected = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network"]},
        headers={"Accept": "application/json"},
    )
    assert rejected.status_code == 422, rejected.text
    assert "Unchecked changes cannot be applied" in rejected.json()["detail"]
    with SessionLocal() as db:
        assert db.scalar(select(Job).where(Job.status == JobStatus.PENDING.value)) is None

    submitted = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network", *sorted(required)]},
        headers={"Accept": "application/json"},
    )
    assert submitted.status_code == 202, submitted.text
    with SessionLocal() as db:
        job = db.get(Job, submitted.json()["job_id"])
        payload = json.loads(job.result or "{}")
        assert payload["management_handoff"] is True
        assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) <= set(payload["selected_units"])
        assert "dnsmasq" not in payload["selected_units"]
        captured = {unit["unit_id"] for unit in payload["captured_units"]}
        assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) <= captured
        assert "dnsmasq" not in captured


def test_static_public_listener_network_edit_does_not_force_protected_handoff(client, monkeypatch):
    """A static public listener does not turn an unrelated MTU edit into a handoff.

    Args:
        client: Authenticated application test client.
        monkeypatch: Host job runner substitution.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    with SessionLocal() as db:
        access = _prepare_dynamic_public_baseline(db, ui, dns_enabled=False, access_dynamic=False)
        access.mtu = 1400
        db.commit()
        units = {unit["id"]: unit for unit in ui.appliance_apply_units(db)}
        assert units["network"]["changed"] is True
        assert ui.network_dynamic_public_bindings(units) == []
        assert ui.network_listener_handoff_required(db, units) is False

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network"]},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        payload = json.loads(db.get(Job, response.json()["job_id"]).result or "{}")
        assert payload["management_handoff"] is False
        assert "dnsmasq" not in payload["selected_units"]


def test_console_dynamic_public_listener_captures_handoff_without_dns(client, monkeypatch):
    """Console Network Apply captures dynamic sockets without a DNS unit.

    Args:
        client: Seeded application test client.
        monkeypatch: Replace the constrained real job runner with a payload capture.
    """
    from atlaso.app import appliance_console, ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    with SessionLocal() as db:
        access = _prepare_dynamic_public_baseline(db, ui, dns_enabled=False)
        access.mtu = 1400
        db.commit()

    captured = []

    def complete_apply(job_id, *, force_real):
        """Capture the committed console task and mark the stub run successful.

        Args:
            job_id: Persisted Appliance Apply job identifier.
            force_real: Whether the console requested the constrained apply path.
        """
        assert force_real is True
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            captured.append(json.loads(job.result or "{}"))
            job.status = JobStatus.SUCCEEDED.value
            db.commit()

    monkeypatch.setattr(ui, "run_appliance_apply_job", complete_apply)
    appliance_console._submit_console_apply({"network"})

    assert len(captured) == 1
    payload = captured[0]
    assert payload["management_handoff"] is True
    assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) <= set(payload["selected_units"])
    assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) <= set(payload["management_handoff_units"])
    assert "dnsmasq" not in payload["selected_units"]
    assert "dnsmasq" not in payload["management_handoff_units"]
    assert "dnsmasq" not in {unit["unit_id"] for unit in payload["captured_units"]}
