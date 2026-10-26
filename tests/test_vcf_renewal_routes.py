"""Browser route contract tests for VCF Helper certificate renewal."""

import pytest

from tests.routers.ui.helpers import login

PREFIX = "/ui/management/vcf-helper/certificate-renewals"


def test_web_restart_leaves_active_worker_checkpoint_and_request_identity_intact(client):
    """A web restart cannot invalidate a separate worker's in-flight CSR response.

    Args:
        client: Application fixture with an initialized isolated database.
    """
    from starlette.testclient import TestClient

    from atlaso.app.database import SessionLocal
    from atlaso.app.main import create_app
    from atlaso.app.models import Job
    from atlaso.app.services import vcf_certificate_renewal as renewal

    operation_id = "e" * 32
    job_id = "job_renewal_live_worker"
    operation = {"id": operation_id, "state": "preparing", "checkpoint": "csr_dispatch_pending", "write_revision": 4}
    with SessionLocal() as db:
        renewal._put(db, "operation", operation_id, operation)
        db.add(Job(id=job_id, type=renewal.JOB_TYPE, status="running", created_by="admin", task_config_json='{"operation_id":"' + operation_id + '"}'))
        db.commit()
    with TestClient(create_app()) as restarted:
        assert restarted.get("/ui/management/login").status_code == 200
    with SessionLocal() as db:
        assert db.get(Job, job_id).status == "running"
        assert renewal._row(db, "operation", operation_id)[1] == operation
        # Simulate the original worker returning from the dispatched request.
        renewal._checkpoint(db, operation, checkpoint="csr_submitted", csr_request_id="native-returned-request")
        assert renewal._row(db, "operation", operation_id)[1]["csr_request_id"] == "native-returned-request"


@pytest.mark.parametrize("action", ["edit", "toggle", "delete"])
def test_renewal_schedule_edits_stay_with_enrollment_policy(client, action):
    """Generic schedule actions cannot detach timing from its renewal policy.

    Args:
        client: Administrator browser using an isolated database.
        action: Generic schedule mutation to reject.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Schedule

    login(client)
    token = csrf_token(client)
    with SessionLocal() as db:
        schedule = Schedule(name="VCF renewal", task_type="vcf_certificate_renewal_check", created_by="admin", task_config_json='{"policy_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}')
        db.add(schedule)
        db.commit()
        identifier = schedule.id
    response = client.post(f"/ui/management/automation/schedules/{identifier}/{action}", data={"csrf": token, "name": "Changed", "task_type": "appliance_update_check"})
    assert response.status_code == 409
    assert "VCF Helper" in response.text
    with SessionLocal() as db:
        assert db.get(Schedule, identifier) is not None


def csrf_token(client) -> str:
    """Return the CSRF token rendered by the authenticated VCF Helper page.

    Args:
        client: Authenticated test client with isolated appliance state.
    """
    page = client.get("/ui/management/vcf-helper")
    assert page.status_code == 200
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_renewal_browser_routes_are_excluded_from_openapi(client):
    """Keep browser-only renewal transports outside the public API schema.

    Args:
        client: Test client using the application OpenAPI surface.
    """
    schema = client.get("/openapi.json").json()
    assert not any("certificate-renewals" in path for path in schema["paths"])


def test_renewal_workspace_is_rendered_inside_vcf_helper_certificates_tab(client):
    """Keep the experimental workspace inside the existing Certificates tab.

    Args:
        client: Authenticated administrator test client.
    """
    login(client)
    response = client.get("/ui/management/vcf-helper")
    assert response.status_code == 200
    assert 'id="vcf-helper-certificates"' in response.text
    assert response.text.index('id="vcf-helper-certificates"') < response.text.index('data-vcf-renewal-root')
    assert "Experimental — live validation pending" in response.text
    assert "Administrator access is required to view VCF certificate renewal state" not in response.text
    connection_start = response.text.index('data-vcf-renewal-connection-form')
    connection_steps = [response.text.index(f'data-atlaso-wizard-step="{step}"', connection_start) for step in ("credential", "server", "fingerprint")]
    assert connection_steps == sorted(connection_steps)
    assert 'data-address-field="address"' in response.text[connection_start : connection_steps[-1]]
    policy_start = response.text.index('data-vcf-renewal-policy-form')
    policy_steps = [response.text.index(f'data-atlaso-wizard-step="{step}"', policy_start) for step in ("target", "target-health", "policy")]
    assert policy_steps == sorted(policy_steps)
    assert 'name="health_credential_vault_id"' in response.text
    assert 'name="health_credential_entry_id"' in response.text
    health_start = response.text.index('data-vcf-renewal-health-form')
    health_steps = [response.text.index(f'data-atlaso-wizard-step="{step}"', health_start) for step in ("credential", "fingerprint")]
    assert health_steps == sorted(health_steps)
    assert 'data-vcf-renewal-health-host' in response.text[health_start:health_steps[-1]]
    assert 'name="confirm_health_fingerprint"' in response.text[health_start:]


def test_renewal_state_requires_admin(client):
    """Enforce administrator access before exposing saved renewal state.

    Args:
        client: Test client with an authenticated session.
    """
    login(client)
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    with SessionLocal() as db:
        user = db.query(User).filter_by(username="admin").one()
        user.role = "viewer"
        user.roles_json = '["viewer"]'
        db.commit()
    assert client.get(f"{PREFIX}/state").status_code == 403


@pytest.mark.parametrize("content", [b"[]", b"null", b"not-json"])
def test_renewal_actions_require_csrf_and_json_object(client, content):
    """Reject missing CSRF or non-object request bodies before dispatch.

    Args:
        client: Authenticated test client initializing isolated appliance state.
        content: Request content that must not be accepted as an action object.
    """
    login(client)
    assert client.post(f"{PREFIX}/check", content=b"{}").status_code == 403
    response = client.post(
        f"{PREFIX}/check",
        content=content,
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    assert response.status_code == 422


def test_renewal_action_rejects_oversized_request_body(client):
    """Keep request parsing bounded before the renewal service is called.

    Args:
        client: Authenticated test client initializing isolated appliance state.
    """
    login(client)
    response = client.post(
        f"{PREFIX}/check",
        content=b" " * 16385,
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    assert response.status_code == 413


def test_renewal_dispatch_preserves_actor_action_and_safe_payload(client, monkeypatch):
    """Route only the operator payload to the service and return its result.

    Args:
        client: Authenticated test client initializing isolated appliance state.
        monkeypatch: Fixture isolating renewal-service behavior.
    """
    login(client)
    from atlaso.app.services import vcf_certificate_renewal as renewal

    calls = []
    monkeypatch.setattr(
        renewal,
        "state",
        lambda db, actor: {"connections": [], "profiles": [], "inventory": [], "policies": []},
    )

    def dispatch(db, actor, action, values):
        """Dispatch.

        Args:
            db: Isolated database session containing enrollment and task state.
            actor: Authenticated administrator initiating the browser action.
            action: Allowlisted browser renewal action.
            values: Parsed public browser action parameters.
        """
        calls.append((actor, action, values))
        return {"job_id": "task-123", "state": "queued"}

    monkeypatch.setattr(renewal, "dispatch", dispatch)
    assert client.get(f"{PREFIX}/state").json()["connections"] == []
    token = csrf_token(client)
    response = client.post(
        f"{PREFIX}/check",
        json={"policy_id": "policy-1"},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 200
    assert response.json() == {"job_id": "task-123", "state": "queued"}
    assert calls == [("admin", "check", {"policy_id": "policy-1"})]


def test_renewal_action_rejects_unknown_action(client):
    """Do not forward unrecognized URL actions to the renewal service.

    Args:
        client: Authenticated test client initializing isolated appliance state.
    """
    login(client)
    response = client.post(
        f"{PREFIX}/unsupported",
        json={},
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    assert response.status_code == 404


def test_renewal_service_conflicts_are_sanitized(client, monkeypatch):
    """Return stale-review conflicts without exposing a traceback.

    Args:
        client: Authenticated test client initializing isolated appliance state.
        monkeypatch: Fixture isolating renewal-service behavior.
    """
    login(client)
    from atlaso.app.services import vcf_certificate_renewal as renewal

    def fail(*args):
        """Fail.

        Args:
            *args: Unused arguments supplied to the synthetic failure callback.
        """
        raise renewal.RenewalError("The replacement review is stale.")

    monkeypatch.setattr(renewal, "dispatch", fail)
    response = client.post(
        f"{PREFIX}/execute",
        json={"operation_id": "operation-1", "review_token": "stale-token"},
        headers={"X-CSRF-Token": csrf_token(client)},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "The replacement review is stale."
    assert "Traceback" not in response.text
