"""Test operational management UI transports."""

import json

from atlaso.app.database import SessionLocal
from atlaso.app.models import Job, JobStatus
from tests.routers.ui.helpers import login


def test_operations_router_owns_exact_transport_set():
    """Keep operational route identities in their established order."""
    from atlaso.app import ui

    assert [
        (route.path, tuple(sorted((route.methods or set()) - {"HEAD"})), route.name)
        for route in ui.operations_router.routes
    ] == [
        (
            "/ui/management/services/{service}/{action}",
            ("POST",),
            "service_action_from_ui",
        ),
        ("/ui/management/services/{service}/logs", ("GET",), "service_logs_from_ui"),
        ("/ui/management/services", ("GET",), "services"),
        ("/ui/management/logs", ("GET",), "logs_page"),
        ("/ui/management/logs/data", ("GET",), "logs_data"),
        ("/ui/management/tasks", ("GET",), "tasks_page"),
        ("/ui/management/tasks/status", ("GET",), "tasks_status"),
        ("/ui/management/tasks/{job_id}/status", ("GET",), "task_status"),
        ("/ui/management/tasks/{job_id}/log", ("GET",), "task_log"),
        ("/ui/management/tasks/{job_id}/cancel", ("POST",), "cancel_task_from_ui"),
        ("/ui/management/audit-log", ("GET",), "audit_log"),
    ]


def test_operational_pages_keep_stable_management_transports(client):
    """Verify the extracted pages retain their stable paths and content."""
    login(client)

    assert client.get("/services").status_code == 200
    assert client.get("/logs").status_code == 200
    assert client.get("/tasks").status_code == 200
    audit = client.get("/audit-log")
    assert audit.status_code == 200
    assert "Audit Events" in audit.text


def test_task_status_transport_retains_secret_redaction(client):
    """Verify task JSON remains redacted after transport extraction."""
    login(client)
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_operations_router",
                type="manual-placeholder",
                status=JobStatus.FAILED.value,
                created_by="admin",
                result=json.dumps({"token": "secret-value", "state": "failed"}),
                error="password=secret-value",
            )
        )
        db.commit()

    response = client.get("/tasks/job_operations_router/status")

    assert response.status_code == 200
    payload = response.json()["task"]
    assert payload["result"]["token"] == "[redacted]"
    assert "secret-value" not in response.text
