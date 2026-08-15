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
