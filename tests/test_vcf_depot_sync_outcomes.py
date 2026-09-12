"""Exercise asynchronous sync attribution and independent configuration evidence."""

import httpx
import pytest

from atlaso.app.services import vcf_depot_target as service

LOCAL = service.LocalDepotEndpoint("depot.example.test", 443, "https://depot.example.test", "depot")
OLD = "2026-09-11T20:30:00+00:00"
NEW = "2026-09-11T20:42:00+00:00"
API_CLIENT = service.VcfDepotApiClient


def snapshot(status="COMPLETED", timestamp=OLD, error=""):
    """Build one vendor response with independently controlled lifecycle fields.

    Args:
        status: Vendor sync status.
        timestamp: Last completion marker.
        error: Retained or current vendor error.
    """
    return {"syncStatus": status, "lastSyncCompletionTimestamp": timestamp, "errorMessage": error}


@pytest.fixture
def target(monkeypatch):
    """Provide a bounded clock and a fake target which records remote mutations.

    Args:
        monkeypatch: Dependency replacement fixture.
    """
    class Target:
        """Model a configured target and independently failing readback."""

        responses = []
        sync_requests = 0
        updates = 0
        reads = 0
        readback_fails = False
        mismatch = False

        def __enter__(self):
            """Return the fake authenticated client."""
            return self

        def __exit__(self, *_args):
            """Close the fake client.

            Args:
                *_args: Context manager exception information.
            """

        def appliance_info(self):
            """Identify the supported target."""
            return {"role": "VcfInstaller", "version": "9.1.0"}

        def depot_settings(self):
            """Read settings independently of synchronization status."""
            self.reads += 1
            if self.readback_fails and self.reads > 1:
                raise service.VcfDepotTargetError("secret-bearing upstream failure")
            return {
                "depotConfiguration": {"isOfflineDepot": True, "hostname": "other.example.test" if self.mismatch else LOCAL.hostname, "port": LOCAL.port},
                "offlineAccount": {"username": LOCAL.username, "status": "DEPOT_CONNECTION_SUCCESSFUL", "message": "private message"},
            }

        def update_depot(self, *_args):
            """Record a write and make the endpoint match.

            Args:
                *_args: Endpoint and transient password.
            """
            self.updates += 1
            self.mismatch = False
            return self.depot_settings()

        def sync_info(self):
            """Return queued status, retaining the last response indefinitely."""
            if len(self.responses) > 1:
                return self.responses.pop(0)
            return self.responses[0]

        def start_sync(self):
            """Accept one asynchronous request without completing it."""
            self.sync_requests += 1
            return snapshot("IN_PROGRESS")

    api = Target()
    clock = [0.0]

    def tick():
        """Advance synthetic time so every failure test terminates."""
        clock[0] += 0.1
        return clock[0]

    monkeypatch.setattr(service, "VcfDepotApiClient", lambda *_args, **_kwargs: api)
    monkeypatch.setattr(service.time, "monotonic", tick)
    monkeypatch.setattr(service.time, "sleep", lambda _seconds: None)
    return api


def configure():
    """Run the service against the fixture without network activity."""
    return service.configure_target_depot("target.example.test", "admin", "api", LOCAL, "depot", replace_existing=True, timeout=3, poll_interval=0)


def test_retained_error_is_reported_as_possible_historical_evidence(target):
    """Record the ambiguous lifecycle without changing the existing failure policy.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot("FAILED", error="Vmware compatibility data download failed."),
                        snapshot("IN_PROGRESS", error="Vmware compatibility data download failed.")]
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    result = caught.value.outcome
    assert result["sync"]["historical_error_possible"] is True
    assert result["sync"]["before_request"]["status"] == "FAILED"
    assert result["sync"]["latest_observation"]["status"] == "IN_PROGRESS"
    assert result["configuration_verified"] is True
    assert result["manual_recovery_required"] is False
    assert target.sync_requests == 1
    assert target.updates == 0


def test_fresh_error_retains_configuration_readback(target):
    """Expose a new metadata failure separately from a working depot connection.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot(), snapshot("FAILED", NEW, "Compatibility metadata failed.")]
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    result = caught.value.outcome
    assert result["sync"]["historical_error_possible"] is False
    assert result["sync"]["latest_observation"]["last_completed_at"] == NEW
    assert result["configuration_verified"] is True
    assert "message" not in result["depot"]


def test_timeout_retains_working_configuration_evidence(target):
    """A wait timeout does not imply that the depot configuration needs repair.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot(), snapshot("IN_PROGRESS")]
    with pytest.raises(service.VcfDepotTargetPartialError, match="timeout") as caught:
        configure()
    assert caught.value.outcome["configuration_verified"] is True
    assert caught.value.outcome["sync"]["request_accepted"] is True
    assert caught.value.outcome["manual_recovery_required"] is False


def test_readback_failure_is_unknown_not_configuration_failure(target):
    """Unavailable independent evidence must not invent an intervention requirement.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot(), snapshot("FAILED", NEW, "Metadata failed.")]
    target.readback_fails = True
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    assert caught.value.outcome["configuration_readback"] == "unavailable"
    assert caught.value.outcome["manual_recovery_required"] is False
    assert "secret-bearing" not in str(caught.value)


def test_request_error_keeps_configuration_readback(target, monkeypatch):
    """A rejected sync request must not lose a verified existing configuration.

    Args:
        target: Fake target fixture.
        monkeypatch: Dependency replacement fixture.
    """
    target.responses = [snapshot()]

    def rejected():
        """Simulate a vendor rejection containing unsafe detail."""
        raise service.VcfDepotTargetError("private request detail")

    monkeypatch.setattr(target, "start_sync", rejected)
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    assert caught.value.outcome["configuration_verified"] is True
    assert caught.value.outcome["sync"]["request_accepted"] is False
    assert "private request detail" not in str(caught.value)


@pytest.mark.parametrize("payload", [None, 42, [1]])
def test_non_object_sync_json_preserves_readback(target, monkeypatch, payload):
    """Retain configuration evidence when decoding a vendor JSON object fails.

    Args:
        target: Fake target fixture.
        monkeypatch: Dependency replacement fixture.
        payload: Valid JSON value which cannot become a response dictionary.
    """
    target.responses = [snapshot()]

    def malformed():
        """Model the API client's response dictionary conversion."""
        return dict(payload)

    monkeypatch.setattr(target, "sync_info", malformed)
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    assert caught.value.outcome["configuration_verified"] is True
    assert caught.value.outcome["manual_recovery_required"] is False
    assert caught.value.outcome["sync"]["request_accepted"] is False


@pytest.mark.parametrize("response_body", [b"null", b"42", b"[1]", b"not-json"])
@pytest.mark.parametrize("status", [200, 202, 503, None])
def test_sync_acceptance_survives_unusable_response(target, monkeypatch, response_body, status):
    """Separate HTTP acceptance from body decoding and uncertain transport failure.

    Args:
        target: Fake target fixture.
        monkeypatch: Dependency replacement fixture.
        response_body: Vendor response bytes.
        status: HTTP response status, or None for a transport timeout.
    """
    from types import MethodType

    def respond(request):
        """Serve a response without external network access.

        Args:
            request: Captured outgoing HTTP request.
        """
        assert request.method == "PATCH"
        if status is None:
            raise httpx.ReadTimeout("response unavailable", request=request)
        return httpx.Response(status, content=response_body)

    target.responses = [snapshot()]
    with httpx.Client(base_url="https://target.example.test", transport=httpx.MockTransport(respond)) as client:
        monkeypatch.setattr(target, "client", client, raising=False)
        monkeypatch.setattr(target, "_raise", API_CLIENT._raise, raising=False)
        monkeypatch.setattr(target, "start_sync", MethodType(API_CLIENT.start_sync, target))
        with pytest.raises(service.VcfDepotTargetPartialError) as caught:
            configure()
    assert caught.value.outcome["configuration_verified"] is True
    assert caught.value.outcome["sync"]["request_accepted"] is (None if status is None else status < 300)


def test_failed_sync_evidence_is_bounded_and_does_not_echo_errors(target):
    """Record usable timestamps without publishing arbitrary target diagnostics.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot(), snapshot("FAILED", NEW, "private error detail")]
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    sync = caught.value.outcome["sync"]
    assert sync["before_request"]["last_completed_at"] == OLD
    assert sync["latest_observation"] == {"status": "FAILED", "last_completed_at": NEW, "error_present": True}
    assert "private error detail" not in str(caught.value.outcome)


@pytest.mark.parametrize("deployment", [False, True])
def test_partial_job_preserves_component_evidence(client, monkeypatch, deployment):
    """Keep a working depot distinct from metadata failure in task and audit state.

    Args:
        client: Isolated application and database fixture.
        monkeypatch: Dependency replacement fixture.
        deployment: Whether configuration follows an appliance deployment.
    """
    import json

    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job

    outcome = {"configuration": "unchanged", "configuration_verified": True,
               "configuration_readback": "verified", "sync": {"outcome": "failed", "request_accepted": True},
               "manual_recovery_required": False}

    def fail(*_args, **_kwargs):
        """Return structured metadata failure without invoking a target.

        Args:
            *_args: Unused connection arguments.
            **_kwargs: Unused task arguments.
        """
        raise service.VcfDepotTargetPartialError("Compatibility metadata download failed.", outcome=outcome)

    monkeypatch.setattr(ui, "configure_target_depot", fail)
    monkeypatch.setattr(ui, "_local_depot_endpoint", lambda _db: LOCAL)
    monkeypatch.setattr(ui, "configure_operational_logging", lambda _db: None)
    with SessionLocal() as db:
        db.add(Job(id="job_sync_outcome", type="vcf-offline-depot-target-config", status="pending", created_by="admin"))
        db.commit()
    if deployment:
        monkeypatch.setattr(ui, "inspect_ova", lambda _path: object())
        monkeypatch.setattr(ui, "deploy_ova", lambda *_args, **_kwargs: {"guest_ip": "target.example.test"})
        monkeypatch.setattr(ui, "_wait_for_vcf_api", lambda *_args, **_kwargs: {"role": "VcfInstaller"})
        monkeypatch.setattr(ui, "_configure_deployed_target_depot", fail)
        ui.run_vcf_sddc_deployment_job(
            "job_sync_outcome", ova_path="fake.ova", endpoint="vcenter.example.test",
            endpoint_username="admin", endpoint_password="test", endpoint_fingerprint="",
            destination={}, vm_name="test", disk_provisioning="thin", power_on=True,
            property_values={}, add_dns=False, apply_trust=False, configure_offline_depot=True,
            depot_password="test-depot",
        )
    else:
        ui.run_vcf_target_depot_job("job_sync_outcome", address="target.example.test", port=443,
                                  api_username="admin", api_password="test-api", depot_password="test-depot",
                                  replace_existing=False, expected_fingerprint="")
    with SessionLocal() as db:
        job = db.get(Job, "job_sync_outcome")
        assert job.status == "partial-failure"
        result = json.loads(job.result)
        assert result["configuration_verified"] is True
        assert result["sync"]["outcome"] == "failed"
        assert result["manual_recovery_required"] is False
        if deployment:
            assert result["vm_preserved"] is True
            assert result["target"] == "target.example.test"
        audit = db.scalars(select(AuditEvent).where(AuditEvent.resource_id == job.id)).one()
        assert audit.success is False
