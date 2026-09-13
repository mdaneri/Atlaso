"""Test operational API v1 transports."""

from tests.routers.api_v1.helpers import create_token


def test_operations_api_router_owns_exact_transport_set():
    """Keep service, log, audit, and job route identities exact."""
    from atlaso.app.api import v1

    assert [
        (route.path, tuple(sorted((route.methods or set()) - {"HEAD"})), route.name)
        for route in v1.operations_router.routes
    ] == [
        ("/api/v1/services", ("GET",), "list_services"),
        ("/api/v1/services/{service}", ("GET",), "get_service"),
        ("/api/v1/services/{service}/start", ("POST",), "start_service"),
        ("/api/v1/services/{service}/stop", ("POST",), "stop_service"),
        ("/api/v1/services/{service}/restart", ("POST",), "restart_service"),
        ("/api/v1/services/{service}/enable", ("POST",), "enable_service"),
        ("/api/v1/services/{service}/disable", ("POST",), "disable_service"),
        ("/api/v1/services/{service}/logs", ("GET",), "get_service_logs"),
        ("/api/v1/logs", ("GET",), "list_logs"),
        ("/api/v1/logs/{source}", ("GET",), "get_log_source"),
        ("/api/v1/audit", ("GET",), "list_audit_events"),
        ("/api/v1/jobs", ("GET",), "list_jobs"),
        ("/api/v1/jobs", ("POST",), "create_job"),
        ("/api/v1/jobs/{job_id}", ("GET",), "get_job"),
        ("/api/v1/jobs/{job_id}/cancel", ("POST",), "cancel_job"),
    ]


def test_operational_api_transports_keep_scopes_and_schemas(client):
    """Verify representative operational API reads retain scope and schema.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    raw_token, _token = create_token(
        client, ["read:services", "read:logs", "read:audit", "read:dashboard"]
    )
    headers = {"Authorization": f"Bearer {raw_token}"}

    service = client.get("/api/v1/services/not-approved", headers=headers)
    logs = client.get("/api/v1/logs", headers=headers)
    audit = client.get("/api/v1/audit", headers=headers)
    jobs = client.get("/api/v1/jobs", headers=headers)

    assert service.status_code == 404
    assert service.json()["detail"] == "Service not found"
    assert logs.status_code == 200
    assert "atlaso" in logs.json()
    assert audit.status_code == 200
    assert jobs.status_code == 200


def test_operational_api_transports_reject_wrong_scope(client):
    """Verify representative operational reads reject an unrelated scope.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    raw_token, _token = create_token(client, ["read:wan"])
    headers = {"Authorization": f"Bearer {raw_token}"}

    assert client.get("/api/v1/services", headers=headers).status_code == 403
    assert client.get("/api/v1/logs", headers=headers).status_code == 403
    assert client.get("/api/v1/audit", headers=headers).status_code == 403
    assert client.get("/api/v1/jobs", headers=headers).status_code == 403


def test_cancellation_api_matches_backend_capability_and_preserves_running(client):
    """API callers receive the same reasons and durable request semantics as Tasks.

    Args:
        client: Initialized authenticated test application.
    """
    import json

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    raw_token, _ = create_token(client, ["admin:all", "read:dashboard"])
    headers = {"Authorization": f"Bearer {raw_token}"}
    with SessionLocal() as db:
        db.add_all([
            Job(id="api-cancel-unsafe", type="managed-script", status="running", created_by="admin"),
            Job(id="api-cancel-check", type="appliance-update", status="running", created_by="admin",
                task_config_json=json.dumps({"mode": "check", "selected_streams": ["atlaso_release"]})),
        ])
        db.commit()
    unsafe = client.get("/api/v1/jobs/api-cancel-unsafe", headers=headers).json()
    assert not unsafe["can_cancel"]
    rejected = client.post("/api/v1/jobs/api-cancel-unsafe/cancel", headers=headers)
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == unsafe["cancel_reason"]
    accepted = client.post("/api/v1/jobs/api-cancel-check/cancel", headers=headers)
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "running"
    assert accepted.json()["cancel_requested_at"]
    assert accepted.json()["cancel_requested_by"] == "admin"
    assert accepted.json()["cancel_completed_at"] is None
    assert not accepted.json()["can_cancel"]
    repeated = client.post("/api/v1/jobs/api-cancel-check/cancel", headers=headers)
    assert repeated.json()["cancel_requested_at"] == accepted.json()["cancel_requested_at"]
