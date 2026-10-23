"""Browser route contract tests for appliance certificate operations."""

import pytest

from tests.routers.ui.helpers import login

PREFIX = "/ui/management/vcf-helper/appliance-certificates"


def csrf_token(client) -> str:
    """Provide csrf token.

    Args:
        client: Authenticated test client initializing isolated appliance state.
    """
    page = client.get("/ui/management/vcf-helper")
    assert page.status_code == 200
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_certificate_operations_are_excluded_from_openapi(client):
    """Verify certificate operations are excluded from openapi.

    Args:
        client: Authenticated test client initializing isolated appliance state.
    """
    schema = client.get("/openapi.json").json()
    assert not any("appliance-certificates" in path for path in schema["paths"])


def test_certificate_operation_requires_admin(client):
    """Verify certificate operation requires admin.

    Args:
        client: Authenticated test client initializing isolated appliance state.
    """
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
def test_certificate_operation_requires_csrf_and_json_object(client, content):
    """Verify certificate operation requires csrf and json object.

    Args:
        client: Authenticated test client initializing isolated appliance state.
        content: Bounded native response content.
    """
    login(client)
    no_csrf = client.post(f"{PREFIX}/probe", content=b"{}")
    assert no_csrf.status_code == 403
    malformed = client.post(
        f"{PREFIX}/probe", content=content, headers={"X-CSRF-Token": csrf_token(client)}
    )
    assert malformed.status_code == 422


def test_certificate_operation_rejects_oversized_body(client):
    """Verify certificate operation rejects oversized body.

    Args:
        client: Authenticated test client initializing isolated appliance state.
    """
    login(client)
    response = client.post(
        f"{PREFIX}/probe",
        content=b" " * 16385,
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    assert response.status_code == 413


def test_certificate_operation_rejects_unknown_operation(client):
    """Verify certificate operation rejects unknown operation.

    Args:
        client: Authenticated test client initializing isolated appliance state.
    """
    login(client)
    response = client.post(
        f"{PREFIX}/unknown", json={}, headers={"X-CSRF-Token": csrf_token(client)}
    )
    assert response.status_code == 404


def test_certificate_dispatch_and_status_return_service_results(client, monkeypatch):
    """Verify certificate dispatch and status return service results.

    Args:
        client: Authenticated test client initializing isolated appliance state.
        monkeypatch: Pytest patch fixture isolating native and background behavior.
    """
    login(client)
    from atlaso.app.services import vcf_certificates as cert

    calls = []

    def dispatch(db, actor, operation, values, background_tasks):
        """Provide dispatch.

        Args:
            db: Database session holding operation records and target reservations.
            actor: Submitting administrator username.
            operation: Requested certificate workflow action.
            values: Validated browser workflow input values.
            background_tasks: Request-owned scheduler for admitted certificate jobs.
        """
        calls.append((actor, operation, values))
        return {"operation_id": "op-123", "state": "prepared"}

    monkeypatch.setattr(cert, "dispatch", dispatch)
    token = csrf_token(client)
    response = client.post(
        f"{PREFIX}/prepare", json={"product": "srm"}, headers={"X-CSRF-Token": token}
    )
    assert response.status_code == 200
    assert response.json() == {"operation_id": "op-123", "state": "prepared"}
    assert calls == [("admin", "prepare", {"product": "srm"})]

    monkeypatch.setattr(
        cert,
        "operation_status",
        lambda db, actor, op: {"operation_id": op, "state": "ready"},
    )
    status = client.get(f"{PREFIX}/operations/op-123")
    assert status.status_code == 200
    assert status.json() == {"operation_id": "op-123", "state": "ready"}


@pytest.mark.parametrize(("operation", "expected"), [("review", 422), ("execute", 409)])
def test_certificate_service_errors_are_returned_without_traceback(
    client, monkeypatch, operation, expected
):
    """Verify certificate service errors are returned without traceback.

    Args:
        client: Authenticated test client initializing isolated appliance state.
        monkeypatch: Pytest patch fixture isolating native and background behavior.
        operation: Requested certificate workflow action.
        expected: Expected accepted value or response used by the assertion.
    """
    login(client)
    from atlaso.app.services import vcf_certificates as cert

    def fail(*args):
        """Provide fail.

        Args:
            *args: Positional callback arguments supplied by the caller.
        """
        raise cert.CertificateOperationError("Review is stale.")

    monkeypatch.setattr(cert, "dispatch", fail)
    response = client.post(
        f"{PREFIX}/{operation}", json={}, headers={"X-CSRF-Token": csrf_token(client)}
    )
    assert response.status_code == expected
    assert response.json()["detail"] == "Review is stale."
    assert "Traceback" not in response.text


def test_certificate_status_error_is_sanitized(client, monkeypatch):
    """Verify certificate status error is sanitized.

    Args:
        client: Authenticated test client initializing isolated appliance state.
        monkeypatch: Pytest patch fixture isolating native and background behavior.
    """
    login(client)
    from atlaso.app.services import vcf_certificates as cert

    monkeypatch.setattr(
        cert,
        "operation_status",
        lambda *args: (_ for _ in ()).throw(
            cert.CertificateOperationError("Operation not found.")
        ),
    )
    response = client.get(f"{PREFIX}/operations/missing")
    assert response.status_code == 422
    assert response.json()["detail"] == "Operation not found."
