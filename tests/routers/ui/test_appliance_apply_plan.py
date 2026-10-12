"""Cover server-owned Appliance Apply review plans and consent binding."""

import json

from tests.routers.ui.helpers import login


def _prepare_network_handoff_review(client, monkeypatch, *, invalid_firewall=False, changed_local_users=False):
    """Build current unit snapshots with a protected Network/WAN handoff.

    Args:
        client: Isolated authenticated HTTP client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        invalid_firewall: Whether the unchanged Firewall dependency is invalid.
        changed_local_users: Whether an independent Local Users change is pending.

    Returns:
        Current real Apply units, the logged-in request CSRF value, and UI module.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.add(Job(
            id="completed-before-review",
            type="appliance-apply",
            status="succeeded",
            created_by="admin",
        ))
        db.commit()

    for unit in units:
        unit["changed"] = False
        unit["has_baseline"] = True
        if unit["id"] in {"network", "wan"}:
            unit["changed"] = True
        if unit["id"] == "network":
            unit["management_handoff_required"] = True
        if unit["id"] == "firewall" and invalid_firewall:
            unit["valid"] = False
            unit["validation_errors"] = ["Firewall dependency is invalid."]
        if unit["id"] == "local_users" and changed_local_users:
            unit["changed"] = True

    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: units)
    monkeypatch.setattr(ui, "network_listener_handoff_required", lambda _db, _units: False)
    return units, csrf, ui


def test_network_wan_review_expands_to_five_unchanged_handoff_dependencies(client, monkeypatch):
    """Show the full seven-unit execution plan and dependency explanations."""
    _units, _csrf, _ui = _prepare_network_handoff_review(client, monkeypatch)

    response = client.get("/appliance-apply/review?selected_units=network&selected_units=wan")

    assert response.status_code == 200
    payload = response.json()
    selected = [unit for unit in payload["units"] if unit["selected"]]
    required = [unit for unit in selected if unit["required_dependency"]]
    assert payload["requested_units"] == ["network", "wan"]
    assert payload["pending_count"] == 2
    assert payload["execution_count"] == 7
    assert len(selected) == 7
    assert {unit["id"] for unit in required} == {
        "ca", "firewall", "appliance_settings", "public_services", "nat",
    }
    assert all(not unit["changed"] and unit["dependency_reason"] for unit in required)
    assert all(unit["valid"] for unit in required)
    assert payload["plan_token"]
    assert not payload["plan_error"]


def test_reviewed_network_wan_plan_submits_same_ordered_effective_selection(client, monkeypatch):
    """Submit exactly the effective units represented by a reviewed token."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    _units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    effective = [unit["id"] for unit in preview["units"] if unit["selected"]]

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": preview["plan_token"],
            "requested_units": preview["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        submitted = json.loads(job.result or "{}")
    assert submitted["selected_units"] == effective
    assert submitted["management_handoff"] is True
    assert len(submitted["captured_units"]) == 7


def test_deselected_network_plan_can_shrink_to_local_users_or_empty(client, monkeypatch):
    """Recompute dependencies when Network is deselected, including empty choice."""
    _units, _csrf, _ui = _prepare_network_handoff_review(
        client, monkeypatch, changed_local_users=True,
    )
    initial = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    assert initial["execution_count"] == 7

    independent = client.get("/appliance-apply/review?selected_units=local_users").json()
    independent_selected = [unit["id"] for unit in independent["units"] if unit["selected"]]
    assert independent["requested_units"] == ["local_users"]
    assert independent["pending_count"] == 3
    assert independent["execution_count"] == 1
    assert independent_selected == ["local_users"]

    empty = client.get("/appliance-apply/review?selected_units=").json()
    assert empty["requested_units"] == []
    assert empty["pending_count"] == 3
    assert empty["execution_count"] == 0
    assert not any(unit["selected"] for unit in empty["units"])


def test_invalid_required_handoff_dependency_is_visible_and_submit_is_rejected(client, monkeypatch):
    """Keep an invalid required dependency in the plan and fail submission closed."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    _units, csrf, ui = _prepare_network_handoff_review(
        client, monkeypatch, invalid_firewall=True,
    )
    before = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    firewall = next(unit for unit in before["units"] if unit["id"] == "firewall")
    assert firewall["selected"] is True
    assert firewall["required_dependency"] is True
    assert firewall["valid"] is False
    assert "Firewall dependency is invalid." in firewall["validation_errors"]
    assert "Firewall" in before["plan_error"]
    effective = [unit["id"] for unit in before["units"] if unit["selected"]]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": before["plan_token"],
            "requested_units": before["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 422
    assert "Resolve validation errors" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


def test_reviewed_plan_rejects_snapshot_change_before_submission(client, monkeypatch):
    """Reject a plan token after one captured component snapshot changes."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    effective = [unit["id"] for unit in preview["units"] if unit["selected"]]
    network = next(unit for unit in units if unit["id"] == "network")
    network["snapshot_hash"] = "changed-after-review"
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": preview["plan_token"],
            "requested_units": preview["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 422
    assert "changed since review" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


def test_generated_dns_only_plan_captures_the_reviewed_generated_snapshot(client, monkeypatch):
    """Preserve the generated DNS snapshot through review and token-bound submit."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    dns = next(unit for unit in units if unit["id"] == "dnsmasq")
    generated_dns = {
        **dns,
        "changed": True,
        "snapshot_hash": "generated-dns-snapshot",
        "config_preview": "generated listener DNS records",
        "config_diff": "generated diff",
    }
    monkeypatch.setattr(ui, "network_generated_dns_unit", lambda _db, _unit_map: generated_dns)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    dns_review = next(unit for unit in preview["units"] if unit["id"] == "dnsmasq")
    assert preview["plan_error"] == ""
    assert dns_review["selected"] is True
    assert dns_review["required_dependency"] is True
    assert dns_review["config_preview"] == "generated listener DNS records"
    effective = [unit["id"] for unit in preview["units"] if unit["selected"]]

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": preview["plan_token"],
            "requested_units": preview["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        submitted = json.loads(job.result or "{}")
    assert submitted["generated_dns_only"] is True
    captured_dns = next(unit for unit in submitted["captured_units"] if unit["unit_id"] == "dnsmasq")
    assert captured_dns["snapshot_hash"] == "generated-dns-snapshot"
    assert captured_dns["config_preview"] == "generated listener DNS records"
