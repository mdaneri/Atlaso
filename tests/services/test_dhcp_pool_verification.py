"""Exercise evidence classification, identity admission and report retention."""

import hashlib
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from atlaso.app.database import Base
from atlaso.app.models import DhcpScope, Job, Setting
from atlaso.app.services import dhcp_pool_verification as verifier
from atlaso.app.services.dnsmasq import DHCP_POOL_METADATA_PREFIX, dhcp_pool_metadata

NOW = "2030-01-01T00:00:00+00:00"
MAC = "02:00:00:00:00:01"
OTHER = "02:00:00:00:00:02"
IP = "192.168.50.100"
POOL = {"reservations": []}


def observation(macs, status="response"):
    """Build a fresh helper observation with no payload content."""
    return {"ip_address": IP, "mac_addresses": macs, "status": status}


def lease(mac=MAC, expires=0):
    """Build an attributable current DHCP lease."""
    return {"ip_address": IP, "mac_address": mac, "client_id": "01:client", "expires_epoch": expires}


@pytest.mark.parametrize("macs,leases,expected", [
    ([MAC], [lease()], "legitimate_use"),
    ([OTHER], [lease()], "occupant_lease_mismatch"),
    ([MAC, OTHER], [lease()], "confirmed_conflict"),
    ([MAC], [], "unexpected_occupancy"),
    ([MAC], [lease(expires=1)], "unexpected_occupancy"),
])
def test_fresh_occupancy_identity_classification(macs, leases, expected):
    """Distinguish valid clients, expired leases and unexpected responders."""
    result = verifier.classify(observation(macs), POOL, leases, leases, NOW)
    assert result["status"] == expected


def test_reservation_outside_dynamic_range_is_legitimate():
    """Declared static use is not a foreign occupant."""
    pool = {"reservations": [{"ip_address": IP, "mac_address": MAC}]}
    assert verifier.classify(observation([MAC]), pool, [], [], NOW)["status"] == "legitimate_use"
    assert verifier.classify(observation([OTHER]), pool, [], [], NOW)["status"] == "occupant_lease_mismatch"


def test_lease_changes_and_unscoped_overlap_remain_unknown():
    """Do not label a concurrent renewal or another link's lease a mismatch."""
    assert verifier.classify(observation([OTHER]), POOL, [lease()], [lease(OTHER)], NOW)["status"] == "unknown"
    assert verifier.classify(observation([OTHER]), POOL, [lease()], [lease()], NOW,
                             lease_attribution_unknown=True)["status"] == "unknown"


def test_no_response_retains_finding_until_positive_matching_use():
    """A silent or ICMP-blocking host must not appear resolved by silence."""
    conflict = verifier.classify(observation([OTHER]), POOL, [lease()], [lease()], NOW)
    absent = verifier.classify(observation([], "no_response"), POOL, [lease()], [lease()], NOW)
    retained = verifier.retain_history(absent, conflict)
    assert retained["status"] == "no_response" and retained["unresolved"]
    assert retained["resolved_at"] is None
    matching = verifier.classify(observation([MAC]), POOL, [lease()], [lease()], NOW)
    resolved = verifier.retain_history(matching, conflict)
    assert not resolved["unresolved"] and resolved["resolved_at"] == NOW
    later = verifier.retain_history(verifier.classify(observation([], "no_response"), POOL, [], [], NOW), resolved)
    assert later["resolved_at"] == NOW and not later["unresolved"]


def setup_pool(db):
    """Persist a known applied identity using an in-memory database."""
    pool = DhcpScope(name="Site", address_family="ipv4", enabled=True, interface_name="eth1",
                     site_address="192.168.50.1", prefix_length=24, range_expression="192.168.50.100-110")
    db.add(pool)
    db.flush()
    metadata = dhcp_pool_metadata(pool, [])
    config = DHCP_POOL_METADATA_PREFIX + json.dumps(metadata) + "\n"
    db.add(Setting(key=verifier.BASELINES_KEY, value=json.dumps({"dnsmasq": {"config_preview": config}})))
    db.commit()
    return pool, config


def test_enqueue_deduplicates_and_invalidates_changed_or_deleted_pool():
    """Only applied identities may queue and only one verifier runs globally."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        pool, config = setup_pool(db)
        job = verifier.enqueue(db, scope_id=pool.id, actor="operator")
        db.commit()
        assert verifier.object_json(job.task_config_json)["config_hash"] == hashlib.sha256(config.encode()).hexdigest()
        assert db.scalar(select(Job.id)) == job.id
        with pytest.raises(ValueError, match="already active"):
            verifier.enqueue(db, scope_id=pool.id, actor="operator")
        db.rollback()
        pool.range_expression = "192.168.50.100-120"
        db.commit()
        with pytest.raises(ValueError, match="changed"):
            verifier.applied_pool(db, pool.id)
        assert verifier.status(db, pool.id)["state"] == "unknown"
        pool_id = pool.id
        db.delete(pool)
        db.commit()
        with pytest.raises(ValueError, match="no longer exists"):
            verifier.status(db, pool_id)
    engine.dispose()


def test_worker_publishes_progress_report_and_keeps_service_untouched(client, monkeypatch):
    """One fresh probe updates live status without a service reload or lease mutation."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import JobStatus

    with SessionLocal() as db:
        for existing in db.scalars(select(DhcpScope)):
            existing.enabled = False
        db.commit()
        pool, _config = setup_pool(db)
        scope_id = pool.id
        job = verifier.enqueue(db, scope_id=scope_id, actor="operator")
        job.status = JobStatus.RUNNING.value
        job_id = job.id
        db.commit()
        metadata, digest = verifier.applied_pool(db, scope_id)
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter

    def probe(_self, received_scope, offset, received_digest):
        assert (received_scope, offset, received_digest) == (scope_id, 0, digest)
        return AdapterResult(command=[], dry_run=False, stdout=json.dumps({
            "status": "complete", "config_hash": digest, "scope": metadata, "total": 1,
            "offset": 0, "next_offset": None, "observed_at": NOW, "dnsmasq_version": "test-version",
            "link_identity_hash": "a" * 64,
            "observations": [observation([MAC])], "leases_before": [], "leases_after": [],
        }))

    monkeypatch.setattr(SystemAdapter, "verify_dhcp_pool", probe)
    verifier.run(job_id)
    with SessionLocal() as db:
        report = verifier.status(db, scope_id)
        assert report["state"] == "complete"
        assert report["unresolved_count"] == 1
        assert db.get(Job, job_id).status == JobStatus.SUCCEEDED.value


@pytest.mark.parametrize("transport", ["api", "ui"])
def test_deleted_scope_id_reuse_does_not_inherit_report(client, transport):
    """Both deletion paths clear evidence before SQLite reuses an identical pool ID."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Schedule, utcnow
    from atlaso.app.services.automation import (
        enqueue_due_schedules,
        enqueue_schedule_now,
    )
    from tests.routers.api_v1.test_dns_dhcp import create_token
    from tests.routers.ui.helpers import login

    with SessionLocal() as db:
        pool, config = setup_pool(db)
        scope_id = pool.id
        values = {key: getattr(pool, key) for key in ("name", "address_family", "enabled", "interface_name",
                  "site_address", "prefix_length", "range_expression")}
        db.add(Setting(key=verifier.REPORT_PREFIX + str(scope_id), value=json.dumps({
            "state": "complete", "job_id": "old_job", "config_hash": hashlib.sha256(config.encode()).hexdigest(),
            "observations": [verifier.classify(observation([OTHER]), POOL, [], [], NOW)],
        })))
        db.commit()
        assert verifier.status(db, scope_id)["observations"]
        schedule = Schedule(name="deleted-pool", task_type="dhcp_pool_verify",
                            task_config_json=json.dumps({"scope_id": scope_id}), enabled=True,
                            cron_expression="0 * * * *", next_run_at=utcnow(), created_by="admin")
        db.add(schedule)
        db.commit()
        schedule_id = schedule.id
    if transport == "api":
        token = create_token(client, ["read:dhcp", "write:dhcp"])
        response = client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers={"Authorization": f"Bearer {token}"})
    else:
        login(client)
        page = client.get("/dhcp")
        csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
        response = client.post(f"/dhcp/scopes/{scope_id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert response.status_code in {204, 303}, response.text
    with SessionLocal() as db:
        assert db.scalar(select(Setting).where(Setting.key == verifier.REPORT_PREFIX + str(scope_id))) is None
        replacement = DhcpScope(**values)
        db.add(replacement)
        db.commit()
        assert replacement.id == scope_id
        schedule = db.get(Schedule, schedule_id)
        assert schedule.enabled is False and schedule.next_run_at is None
        assert "scope_id" not in json.loads(schedule.task_config_json)
        assert enqueue_due_schedules(db, now=utcnow()) == []
        with pytest.raises(ValueError, match="scope is invalid"):
            enqueue_schedule_now(db, schedule=schedule, actor="admin")
        report = verifier.status(db, replacement.id)
        assert report["state"] == "not_recorded" and report["job_id"] is None and report["observations"] == []
        job = verifier.enqueue(db, scope_id=scope_id, actor="admin")
        db.commit()
        assert verifier.status(db, scope_id)["job_id"] == job.id
        assert verifier.status(db, scope_id)["observations"] == []


@pytest.mark.parametrize("delete_during_probe", [False, True])
def test_deleted_report_cannot_be_republished_by_old_worker(client, monkeypatch, delete_during_probe):
    """Reject old jobs before observation or after a completed in-flight helper chunk."""
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import JobStatus

    with SessionLocal() as db:
        pool, _config = setup_pool(db)
        scope_id = pool.id
        job = verifier.enqueue(db, scope_id=scope_id, actor="admin")
        job.status = JobStatus.RUNNING.value
        job_id = job.id
        db.commit()
        metadata, digest = verifier.applied_pool(db, scope_id)
        if not delete_during_probe:
            verifier.forget_scope(db, scope_id)
            db.commit()
    calls = []

    def probe(_adapter, _scope_id, offset, _digest):
        calls.append(offset)
        with SessionLocal() as db:
            verifier.forget_scope(db, scope_id)
            db.commit()
        return AdapterResult(command=[], dry_run=False, stdout=json.dumps({
            "status": "complete", "config_hash": digest, "scope": metadata, "total": 1,
            "offset": 0, "next_offset": None, "observed_at": NOW, "dnsmasq_version": "test-version",
            "link_identity_hash": "a" * 64,
            "observations": [observation([MAC])], "leases_before": [], "leases_after": [],
        }))

    monkeypatch.setattr(SystemAdapter, "verify_dhcp_pool", probe)
    with pytest.raises(ValueError, match="ownership changed"):
        verifier.run(job_id)
    assert calls == ([0] if delete_during_probe else [])
    with SessionLocal() as db:
        assert db.scalar(select(Setting).where(Setting.key == verifier.REPORT_PREFIX + str(scope_id))) is None
        assert verifier.status(db, scope_id)["observations"] == []


def test_native_lease_expiry_is_not_renewal_mismatch():
    """A refreshed lease expiry with the same MAC/client identity stays valid."""
    epoch = int(datetime.fromisoformat(NOW).replace(tzinfo=timezone.utc).timestamp())
    assert verifier.classify(observation([MAC]), POOL, [lease(expires=epoch + 60)],
                             [lease(expires=epoch + 600)], NOW)["status"] == "legitimate_use"


def test_due_and_manual_schedules_share_global_admission_and_current_pool_identity(client):
    """Scheduled and manual runs cannot create overlapping network probes."""
    from datetime import timedelta

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import JobStatus, Schedule, utcnow
    from atlaso.app.services.automation import (
        enqueue_due_schedules,
        enqueue_schedule_now,
    )

    now = utcnow()
    with SessionLocal() as db:
        pool, _config = setup_pool(db)
        schedule = Schedule(name="verify-site", task_type="dhcp_pool_verify",
                            task_config_json=json.dumps({"scope_id": pool.id}),
                            cron_expression="0 * * * *", enabled=True,
                            next_run_at=now - timedelta(minutes=1), created_by="admin")
        db.add(schedule)
        db.commit()
        jobs = enqueue_due_schedules(db, now=now)
        assert len(jobs) == 1 and jobs[0].status == JobStatus.PENDING.value
        assert verifier.object_json(jobs[0].task_config_json)["config_hash"]
        with pytest.raises(ValueError, match="already active"):
            enqueue_schedule_now(db, schedule=schedule, actor="admin", now=now)
        db.rollback()
        schedule.next_run_at = now - timedelta(seconds=1)
        db.commit()
        skipped = enqueue_due_schedules(db, now=now)
        assert len(skipped) == 1 and skipped[0].status == JobStatus.SKIPPED.value
        assert verifier.status(db, pool.id)["job_id"] == jobs[0].id


def test_running_cancellation_acknowledges_only_after_helper_chunk_returns(client, monkeypatch):
    """Keep a returned partial observation and stop without another helper call."""
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import JobStatus, utcnow

    with SessionLocal() as db:
        for scope in db.scalars(select(DhcpScope)):
            scope.enabled = False
        db.commit()
        pool, _config = setup_pool(db)
        job = verifier.enqueue(db, scope_id=pool.id, actor="admin")
        job.status = JobStatus.RUNNING.value
        db.commit()
        job_id, scope_id = job.id, pool.id
        metadata, digest = verifier.applied_pool(db, scope_id)
    calls = []

    def probe(_adapter, _scope_id, offset, _digest):
        calls.append(offset)
        with SessionLocal() as db:
            job = db.get(Job, job_id)
            job.cancel_requested_at = utcnow()
            job.cancel_requested_by = "admin"
            db.commit()
        return AdapterResult(command=[], dry_run=False, stdout=json.dumps({
            "status": "complete", "config_hash": digest, "scope": metadata, "total": 2,
            "offset": 0, "next_offset": 1, "observed_at": NOW, "dnsmasq_version": "test-version",
            "link_identity_hash": "a" * 64,
            "observations": [observation([MAC])], "leases_before": [], "leases_after": [],
        }))

    monkeypatch.setattr(SystemAdapter, "verify_dhcp_pool", probe)
    verifier.run(job_id)
    assert calls == [0]
    with SessionLocal() as db:
        assert db.get(Job, job_id).status == JobStatus.CANCELLED.value
        report = verifier.status(db, scope_id)
        assert report["state"] == "cancelled" and report["unresolved_count"] == 1
        assert len(report["observations"]) == 1
