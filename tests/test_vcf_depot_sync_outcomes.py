"""Exercise asynchronous sync attribution and independent configuration evidence."""

import pytest

from atlaso.app.services import vcf_depot_target as service

LOCAL = service.LocalDepotEndpoint("depot.example.test", 443, "https://depot.example.test", "depot")
OLD = "2026-09-11T20:30:00+00:00"
NEW = "2026-09-11T20:42:00+00:00"


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


def test_retained_error_does_not_end_new_sync(target):
    """Wait through retained errors and stale completion before accepting success.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot("FAILED", error="Vmware compatibility data download failed."),
                        snapshot("IN_PROGRESS", error="Vmware compatibility data download failed."),
                        snapshot("FAILED", error="Vmware compatibility data download failed."),
                        snapshot(timestamp=NEW)]
    result = configure()
    assert result["sync"]["outcome"] == "succeeded"
    assert result["configuration_verified"] is True
    assert result["configuration"] == "unchanged"
    assert target.sync_requests == 1
    assert target.updates == 0


@pytest.mark.parametrize("status,error", [("FAILED", ""), ("COMPLETED", "Vmware compatibility data download failed.")])
def test_current_failure_retains_independent_readback(target, status, error):
    """A genuine new failure remains partial even with a working configured depot.

    Args:
        target: Fake target fixture.
        status: Terminal status.
        error: Current attempt's error.
    """
    target.responses = [snapshot(), snapshot(status, NEW, error)]
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    result = caught.value.outcome
    assert result["sync"]["outcome"] == "failed"
    assert result["configuration_verified"] is True
    assert result["manual_recovery_required"] is False
    assert "message" not in result["depot"]
    assert target.reads == 2


@pytest.mark.parametrize("latest", [snapshot(), snapshot(timestamp=""), snapshot("UNRECOGNIZED", NEW), snapshot(timestamp="2026-09-10T00:00:00+00:00")])
def test_ambiguous_completion_times_out_without_success(target, latest):
    """Unknown, missing, old and regressed evidence cannot prove completion.

    Args:
        target: Fake target fixture.
        latest: Ambiguous completion response.
    """
    target.responses = [snapshot(), latest]
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    assert caught.value.outcome["sync"]["outcome"] == "unconfirmed"
    assert caught.value.outcome["configuration_verified"] is True


def test_existing_sync_is_not_duplicated(target):
    """An active target sync requires readback instead of another request.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot("IN_PROGRESS")]
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    assert caught.value.outcome["sync"]["outcome"] == "already-running"
    assert caught.value.outcome["sync"]["request_accepted"] is False
    assert target.sync_requests == 0
    assert target.updates == 0


def test_readback_failure_is_unknown_not_configuration_failure(target):
    """Unavailable independent evidence must not invent an intervention requirement.

    Args:
        target: Fake target fixture.
    """
    target.responses = [snapshot(), snapshot("FAILED", NEW)]
    target.readback_fails = True
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    assert caught.value.outcome["configuration_readback"] == "unavailable"
    assert caught.value.outcome["manual_recovery_required"] is False
    assert "secret-bearing" not in str(caught.value)


def test_new_configuration_is_read_back_after_sync_failure(target):
    """Preserve a successful settings write when the subsequent sync fails.

    Args:
        target: Fake target fixture.
    """
    target.mismatch = True
    target.responses = [snapshot(), snapshot(), snapshot("FAILED", NEW)]
    with pytest.raises(service.VcfDepotTargetPartialError) as caught:
        configure()
    assert caught.value.outcome["configuration"] == "updated"
    assert caught.value.outcome["configuration_verified"] is True
    assert target.updates == 1


def test_active_sync_blocks_depot_replacement(target):
    """Do not change the source underneath an already-active remote sync.

    Args:
        target: Fake target fixture.
    """
    target.mismatch = True
    target.responses = [snapshot("IN_PROGRESS")]
    with pytest.raises(service.VcfDepotTargetError, match="no configuration was changed"):
        configure()
    assert target.updates == 0
    assert target.sync_requests == 0


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


def test_partial_job_preserves_component_evidence(client, monkeypatch):
    """Keep a working depot distinct from metadata failure in task and audit state.

    Args:
        client: Isolated application and database fixture.
        monkeypatch: Dependency replacement fixture.
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
        audit = db.scalars(select(AuditEvent).where(AuditEvent.resource_id == job.id)).one()
        assert audit.success is False
