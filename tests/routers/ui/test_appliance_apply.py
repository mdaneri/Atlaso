"""Test Appliance Apply management UI transport behavior."""

import json
from datetime import datetime, timedelta, timezone

from tests.routers.ui.helpers import login


def test_appliance_apply_router_owns_exact_transport_set():
    """Keep the extracted route identities and response classes exact."""
    from atlaso.app import ui

    assert [
        (
            route.path,
            tuple(sorted((route.methods or set()) - {"HEAD"})),
            route.name,
            route.response_class.__name__,
        )
        for route in ui.appliance_apply_router.routes
    ] == [
        (
            "/ui/management/appliance-apply",
            ("GET",),
            "appliance_apply_page",
            "RedirectResponse",
        ),
        (
            "/ui/management/appliance-apply/review",
            ("GET",),
            "appliance_apply_review",
            "JSONResponse",
        ),
        (
            "/ui/management/appliance-apply/status",
            ("GET",),
            "appliance_apply_status_api",
            "JSONResponse",
        ),
        (
            "/ui/management/appliance-apply",
            ("POST",),
            "submit_appliance_apply",
            "HTMLResponse",
        ),
    ]


def test_appliance_apply_status_tolerates_duplicate_managed_certificate_owners(client):
    """Verify that status tolerates duplicate managed certificate owners.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate

    login(client)
    with SessionLocal() as db:
        db.add_all(
            [
                CaCertificate(
                    common_name="older-kms.atlaso.internal",
                    managed_owner="kms:server",
                    status="planned",
                ),
                CaCertificate(
                    common_name="newer-kms.atlaso.internal",
                    managed_owner="kms:server",
                    status="issued",
                    certificate_pem="test-certificate",
                    private_key_encrypted="test-encrypted-key",
                ),
            ]
        )
        db.commit()

    response = client.get("/appliance-apply/status")

    assert response.status_code == 200
    assert response.json()["units"]


def test_appliance_apply_status_uses_lightweight_projection(client, monkeypatch):
    """Verify ordinary status polling never runs apply-time reconciliation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui

    login(client)
    original = ui.appliance_apply_units
    monkeypatch.setattr(ui, "_appliance_apply_status_cache", None)
    reconcile_values = []

    def tracked_units(db, *, reconcile=True):
        """Track reconciliation selection.

        Args:
            db: Active database session.
            reconcile: Whether dependent desired state should be reconciled.
        """
        reconcile_values.append(reconcile)
        return original(db, reconcile=reconcile)

    monkeypatch.setattr(ui, "appliance_apply_units", tracked_units)
    first = client.get("/appliance-apply/status")
    second = client.get("/appliance-apply/status")
    users_page = client.get("/users")
    refreshed = client.get("/appliance-apply/status?refresh=true")

    assert first.status_code == 200
    assert second.status_code == 200
    assert users_page.status_code == 200
    assert refreshed.status_code == 200
    assert first.json().keys() == second.json().keys()
    assert reconcile_values == [False, False]


def test_appliance_apply_status_preserves_planned_management_restart_context(client):
    """Keep durable reconnect context available before the management front door restarts.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    login(client)
    with SessionLocal() as db:
        job = Job(
            id="job_planned_management_restart",
            type="appliance-apply",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            progress_percent=50,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": {
                        "kind": "planned_service_restart",
                        "restart_delay_seconds": 3,
                        "grace_seconds": 15,
                    },
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=datetime(2026, 8, 20, 19, 30, 0),
                result="{}",
            )
        )
        db.add(
            JobStep(
                id=f"{job.id}:firewall",
                job=job,
                component_key="firewall",
                label="Firewall",
                position=2,
                status=JobStatus.RUNNING.value,
                progress_percent=50,
                result="{}",
            )
        )
        db.commit()

    response = client.get("/appliance-apply/status")

    assert response.status_code == 200
    task = response.json()["active_task"]
    assert task["id"] == "job_planned_management_restart"
    assert task["result"]["management_status_transition"] == {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    assert [(step["component_key"], step["status"]) for step in task["_children"]] == [
        ("appliance_settings", "succeeded"),
        ("firewall", "running"),
    ]
    assert task["_children"][0]["finished_at"] == "2026-08-20T19:30:00+00:00"


def test_appliance_apply_status_retains_terminal_planned_restart_lock(client, monkeypatch):
    """Keep a settings-only task and the mutation lock through its restart window.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    observed_at = datetime(2026, 8, 20, 20, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(ui, "utcnow", lambda: observed_at)
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    transition = {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    with SessionLocal() as db:
        job = Job(
            id="job_terminal_management_restart",
            type="appliance-apply",
            status=JobStatus.SUCCEEDED.value,
            created_by="admin",
            progress_percent=100,
            finished_at=observed_at,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": transition,
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=observed_at,
                result="{}",
            )
        )
        db.commit()

    retained = client.get("/appliance-apply/status?refresh=true")
    assert retained.status_code == 200
    assert retained.json()["locked"] is True
    assert retained.json()["active_task"]["id"] == "job_terminal_management_restart"
    assert retained.json()["active_task"]["status"] == JobStatus.SUCCEEDED.value
    assert retained.json()["active_task"]["mutation_locked"] is True

    blocked = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
    )
    assert blocked.status_code == 423
    assert blocked.json()["job_id"] == "job_terminal_management_restart"

    monkeypatch.setattr(ui, "utcnow", lambda: observed_at + timedelta(seconds=19))
    released = client.get("/appliance-apply/status?refresh=true")
    assert released.status_code == 200
    assert released.json()["locked"] is False
    assert released.json()["active_task"] is None


def test_appliance_apply_transition_context_requires_helper_confirmation():
    """Mark only a real helper-confirmed Appliance Settings restart as planned."""
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.ui import appliance_settings_management_status_transition

    confirmed = AdapterResult(
        command=["atlaso-helper", "appliance-settings", "apply"],
        dry_run=False,
        stdout=json.dumps(
            {
                "appliance_settings": "apply complete",
                "management_status_transition": {
                    "kind": "planned_service_restart",
                    "restart_delay_seconds": 3,
                },
            }
        ),
    )
    assert appliance_settings_management_status_transition([confirmed]) == {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=False, stdout='{"appliance_settings":"apply complete"}')]
    ) is None
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=True, stdout=confirmed.stdout)]
    ) is None
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=False, stdout=confirmed.stdout, returncode=1)]
    ) is None


def test_appliance_apply_job_persists_helper_confirmed_transition(client, monkeypatch):
    """Persist confirmed restart context before the helper's delayed restart fires.

    Args:
        client: HTTP test client used to initialize an isolated database.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    transition = {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    unit = {
        "id": "appliance_settings",
        "label": "Appliance Settings",
        "snapshot_hash": "captured-settings",
        "summary": ["Apply settings"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "/etc/atlaso/atlaso-settings.json",
        "config_preview": "{}\n",
        "config_diff": "",
    }
    with SessionLocal() as db:
        job = Job(
            id="job_confirmed_management_restart",
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "captured_units": [
                        {
                            "unit_id": "appliance_settings",
                            "snapshot_hash": "captured-settings",
                        }
                    ],
                    "units": [],
                    "dry_run": False,
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.PENDING.value,
                result="{}",
            )
        )
        db.commit()

    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, reconcile=True: [unit])
    monkeypatch.setattr(
        ui,
        "execute_appliance_apply_unit",
        lambda _unit, **_kwargs: {
            **unit,
            "unit_id": "appliance_settings",
            "success": True,
            "status": JobStatus.SUCCEEDED.value,
            "dry_run": False,
            "commands": [],
            "management_status_transition": transition,
        },
    )

    ui.run_appliance_apply_job("job_confirmed_management_restart")

    with SessionLocal() as db:
        completed = db.get(Job, "job_confirmed_management_restart")
        assert completed is not None
        assert completed.status == JobStatus.SUCCEEDED.value
        assert json.loads(completed.result or "{}")["management_status_transition"] == transition


def test_appliance_apply_review_returns_management_address_connection_warning(client):
    """Verify review returns the management-address connection warning.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.20/24"
        db.commit()

    review = client.get("/appliance-apply/review")

    assert review.status_code == 200
    network = next(unit for unit in review.json()["units"] if unit["id"] == "network")
    assert len(network["connection_warnings"]) == 1
    assert "from 192.168.49.1/24 to 192.168.49.20/24" in network["connection_warnings"][0]


def test_appliance_apply_json_submission_returns_master_with_live_child_status(client):
    """Verify JSON submission returns the master and live child status.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["job_id"].startswith("job_")
    assert payload["status_url"] == f"/tasks/{payload['job_id']}/status"
    assert payload["task"]["type"] == "appliance-apply"
    assert [(step["component_key"], step["status"]) for step in payload["task"]["_children"]] == [
        ("firewall", "pending")
    ]

    status_response = client.get(payload["status_url"])
    assert status_response.status_code == 200
    task = status_response.json()["task"]
    assert task["status"] == "succeeded"
    assert [(step["component_key"], step["status"]) for step in task["_children"]] == [
        ("firewall", "succeeded")
    ]


def test_appliance_apply_rejects_submission_while_another_task_is_active(client):
    """Verify submission rejects another active Appliance Apply task.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_active_apply",
                type="appliance-apply",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=25,
                result="{}",
            )
        )
        db.commit()

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
    )

    assert response.status_code == 423
    assert response.json()["job_id"] == "job_active_apply"
    assert "Changes are locked" in response.json()["detail"]
    with SessionLocal() as db:
        jobs = db.scalars(select(Job).where(Job.type == "appliance-apply")).all()
        assert [job.id for job in jobs] == ["job_active_apply"]
