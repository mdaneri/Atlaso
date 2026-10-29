"""Browser route contracts for reviewed VCF Backup operations."""

import pytest

from tests.routers.ui.helpers import login

PREFIX = "/ui/management/vcf-helper/backups"


def csrf_token(client) -> str:
    """Read the session CSRF token from the VCF Helper page."""
    page = client.get("/ui/management/vcf-helper")
    assert page.status_code == 200
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_backup_workflow_routes_are_excluded_from_openapi(client):
    """Keep the appliance-specific browser transport out of the public API schema."""
    schema = client.get("/openapi.json").json()
    assert not any("vcf-helper/backups" in path for path in schema["paths"])


def test_backup_operation_requires_administrator(client):
    """Reject non-admin sessions before workflow dispatch."""
    login(client)
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    with SessionLocal() as db:
        user = db.query(User).filter_by(username="admin").one()
        user.role = "viewer"
        user.roles_json = '["viewer"]'
        db.commit()
    response = client.post(
        f"{PREFIX}/probe", json={}, headers={"X-CSRF-Token": csrf_token(client)}
    )
    assert response.status_code == 403


@pytest.mark.parametrize("content", [b"[]", b"null", b"not-json"])
def test_backup_operation_requires_csrf_and_json_object(client, content):
    """Validate CSRF and object-shaped JSON before dispatch."""
    login(client)
    assert client.post(f"{PREFIX}/probe", content=b"{}").status_code == 403
    response = client.post(
        f"{PREFIX}/probe", content=content, headers={"X-CSRF-Token": csrf_token(client)}
    )
    assert response.status_code == 422


def test_backup_operation_rejects_oversized_body(client):
    """Bound credential-bearing JSON before parsing or dispatch."""
    login(client)
    response = client.post(
        f"{PREFIX}/probe", content=b" " * 65537,
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    assert response.status_code == 413


def test_backup_operation_rejects_unknown_action(client):
    """Allow only the five explicit workflow actions."""
    login(client)
    response = client.post(
        f"{PREFIX}/unknown", json={}, headers={"X-CSRF-Token": csrf_token(client)}
    )
    assert response.status_code == 404


def test_backup_dispatch_and_status_return_service_results(client, monkeypatch):
    """Forward the request-local action and return its public result unchanged."""
    login(client)
    from atlaso.app.services import vcf_backup_workflow as workflow

    calls = []
    public_service = {
        "address": "lcm.example.test", "port": 443, "base_path": "/v1",
        "key": "fleet-lcm", "fingerprint": "AA:BB", "version": "9.1.0",
    }

    def dispatch(db, actor, action, values, background_tasks):
        calls.append((actor, action, values, background_tasks))
        return {
            "operation_id": "a" * 32, "state": "draft", "revision": "rev",
            "sources": [{"source_id": "source-1", "kind": "fleet", "service": public_service}],
        }

    monkeypatch.setattr(workflow, "dispatch", dispatch)
    token = csrf_token(client)
    response = client.post(
        f"{PREFIX}/inspect", json={"source_kind": "sddc"},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 200
    assert response.json() == {
        "operation_id": "a" * 32, "state": "draft", "revision": "rev",
        "sources": [{"source_id": "source-1", "kind": "fleet", "service": public_service}],
    }
    assert calls[0][:3] == ("admin", "inspect", {"source_kind": "sddc"})

    monkeypatch.setattr(
        workflow, "operation_status",
        lambda db, actor, operation_id: {
            "operation_id": operation_id, "state": "running",
            "sources": [{"source_id": "source-1", "kind": "fleet", "service": public_service}],
        },
    )
    status = client.get(f"{PREFIX}/operations/{'a' * 32}")
    assert status.status_code == 200
    assert status.json() == {
        "operation_id": "a" * 32, "state": "running",
        "sources": [{"source_id": "source-1", "kind": "fleet", "service": public_service}],
    }


@pytest.mark.parametrize(("action", "expected"), [("review", 422), ("execute", 409)])
def test_backup_service_errors_are_returned_without_traceback(client, monkeypatch, action, expected):
    """Map service refusals to bounded browser errors without leaking tracebacks."""
    login(client)
    from atlaso.app.services import vcf_backup_workflow as workflow

    def fail(*args):
        raise workflow.BackupOperationError("The discovery revision changed.")

    monkeypatch.setattr(workflow, "dispatch", fail)
    response = client.post(
        f"{PREFIX}/{action}", json={}, headers={"X-CSRF-Token": csrf_token(client)}
    )
    assert response.status_code == expected
    assert response.json()["detail"] == "The discovery revision changed."
    assert "Traceback" not in response.text


def test_backup_status_error_is_sanitized(client, monkeypatch):
    """Keep owner-bound status refusals inside the JSON error contract."""
    login(client)
    from atlaso.app.services import vcf_backup_workflow as workflow

    def fail(*args):
        raise workflow.BackupOperationError("This operation belongs to another administrator.")

    monkeypatch.setattr(workflow, "operation_status", fail)
    response = client.get(f"{PREFIX}/operations/{'b' * 32}")
    assert response.status_code == 422
    assert response.json()["detail"] == "This operation belongs to another administrator."
    assert "Traceback" not in response.text
