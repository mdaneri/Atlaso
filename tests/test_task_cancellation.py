"""Exercise authoritative cancellation against claims, completion, and cleanup."""

import json
import uuid

import pytest
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from atlaso.app.models import AuditEvent, Base, Job, JobStep
from atlaso.app.security import Identity
from atlaso.app.services import task_cancellation as cancellation

ADMIN = Identity("operator", "admin", {"admin:all"})


@pytest.fixture()
def db(tmp_path):
    """Create a task-owned isolated lifecycle database.

    Args:
        tmp_path: Test-owned database directory.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'tasks.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def make_job(db, kind="managed-script", status="pending", **config):
    """Persist a real task with server-owned execution metadata.

    Args:
        db: Isolated lifecycle database.
        kind: Registered execution owner.
        status: Current lifecycle stage.
        **config: Execution configuration.
    """
    job = Job(id="job_" + uuid.uuid4().hex, type=kind, status=status, created_by="operator", task_config_json=json.dumps(config))
    db.add(job)
    db.commit()
    return job


@pytest.mark.parametrize("kind,config,allowed", [
    ("managed-script", {}, False), ("vcf-depot-download", {}, False),
    ("vcf-depot-software-id", {}, False), ("vcf-sddc-manager-deploy", {}, False),
    ("vcf-offline-depot-target-config", {}, False), ("vcf-ca-trust", {}, False),
    ("diagnostic-bundle", {}, False), ("unregistered", {}, False),
    ("appliance-update", {"mode": "install"}, False),
    ("appliance-update", {"mode": "check"}, False),
    ("appliance-update", {"mode": "check", "selected_streams": ["atlaso_release"]}, True),
    ("appliance-apply", {}, True),
    ("pxe-media-sync", {"source": "delete"}, False),
    ("pxe-media-sync", {"source": "download"}, True),
    ("pxe-media-sync", {"source": "upload"}, True),
])
def test_running_capability_matrix(db, kind, config, allowed):
    """Only audited running owners can accept a stop request.

    Args:
        db: Isolated lifecycle database.
        kind: Execution owner.
        config: Persisted execution contract.
        allowed: Expected audited capability.
    """
    job = make_job(db, kind, "running", **config)
    contract = cancellation.capability(job, ADMIN)
    assert contract.can_cancel is allowed
    assert contract.reason
    if allowed:
        cancellation.request(db, job, ADMIN)
        assert job.status == "running"
        assert job.cancel_requested_at is not None
        assert job.cancel_completed_at is None
    else:
        with pytest.raises(cancellation.CancellationError):
            cancellation.request(db, job, ADMIN)
        assert job.status == "running"
        assert job.cancel_requested_at is None


def test_request_reservation_prevents_claim_and_retries_cleanup(db, monkeypatch):
    """Failed staging cleanup cannot release or start a reserved queued task.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Inject an owned staging cleanup failure.
    """
    from atlaso.app import worker
    from atlaso.app.services import network_boot

    job = make_job(db, "pxe-media-sync", source="upload")
    def fail(_job_id):
        raise OSError("synthetic cleanup denial")
    monkeypatch.setattr(network_boot, "cleanup_network_boot_upload", fail)
    with pytest.raises(cancellation.CancellationError):
        cancellation.request(db, job, ADMIN)
    assert job.status == "pending"
    assert job.cancel_outcome == "cleanup-required"
    assert worker.claim_next_job(db) is None
    monkeypatch.setattr(network_boot, "cleanup_network_boot_upload", lambda _job_id: None)
    cancellation.reconcile_requests(db)
    assert job.status == "cancelled"
    assert job.cancel_outcome == "confirmed"
    assert job.cancel_completed_at is not None
    assert worker.claim_next_job(db) is None


def test_completion_wins_without_overwriting_result(db):
    """A late request preserves success and records its actual disposition.

    Args:
        db: Isolated lifecycle database.
    """
    job = make_job(db, "appliance-apply", "running")
    cancellation.request(db, job, ADMIN)
    job.status = "succeeded"
    job.result = '{"proof":"completed"}'
    db.commit()
    cancellation.reconcile_requests(db)
    assert job.cancel_outcome == "completion-won"
    assert job.result == '{"proof":"completed"}'
    cancellation.request(db, job, ADMIN)
    assert job.status == "succeeded"
    assert job.result == '{"proof":"completed"}'


def test_verified_parent_stop_preserves_finished_children(db):
    """Parent confirmation changes only unfinished children.

    Args:
        db: Isolated lifecycle database.
    """
    job = make_job(db, "appliance-update", "running", mode="check", selected_streams=["atlaso_release"])
    for index, status in enumerate(["succeeded", "failed", "pending"]):
        db.add(JobStep(id=f"{job.id}-{index}", position=index, job_id=job.id, component_key=f"component-{index}", label="Check", status=status,
                       result='{"proof":"retained"}'))
    db.commit()
    cancellation.request(db, job, ADMIN)
    job.result = json.dumps({"ownership_unresolved": True})
    db.commit()
    cancellation.finish_stop(db, job, detail="Synthetic owner proved stop and cleanup.")
    db.commit()
    children = db.scalars(select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.component_key)).all()
    assert [step.status for step in children] == ["succeeded", "failed", "skipped"]
    assert children[0].result == children[1].result == '{"proof":"retained"}'
    assert job.cancel_requested_by == "operator"
    assert "ownership_unresolved" not in json.loads(job.result)
    assert len(db.scalars(select(AuditEvent)).all()) == 2


def test_additive_schema_upgrade_preserves_existing_jobs(tmp_path):
    """An existing installation gains nullable request columns without data loss.

    Args:
        tmp_path: Test-owned old schema database.
    """
    from atlaso.app.database import _reconcile_task_cancellation_columns

    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE jobs (id TEXT PRIMARY KEY, status TEXT)")
        connection.exec_driver_sql("INSERT INTO jobs VALUES ('prior', 'succeeded')")
        _reconcile_task_cancellation_columns(connection)
        _reconcile_task_cancellation_columns(connection)
        assert connection.exec_driver_sql("SELECT status, cancel_requested_at FROM jobs").one() == ("succeeded", None)
        assert {"cancel_requested_at", "cancel_requested_by", "cancel_completed_at", "cancel_outcome"} <= {column["name"] for column in inspect(connection).get_columns("jobs")}
    engine.dispose()


def test_claim_winning_at_request_update_rejects_stale_capability(db, monkeypatch):
    """The guarded request cannot apply pending eligibility after a worker claim.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Inject a claim at the cancellation compare-and-set boundary.
    """
    from sqlalchemy import update

    job = make_job(db)
    original = db.execute
    claimed = False
    def execute(statement, *args, **kwargs):
        nonlocal claimed
        if not claimed and "cancel_requested_at=" in str(statement):
            claimed = True
            original(update(Job).where(Job.id == job.id).values(status="running")
                     .execution_options(synchronize_session=False))
            db.commit()
        return original(statement, *args, **kwargs)
    monkeypatch.setattr(db, "execute", execute)
    with pytest.raises(cancellation.CancellationError, match="changed"):
        cancellation.request(db, job, ADMIN)
    db.refresh(job)
    assert job.status == "running"
    assert job.cancel_requested_at is None


def test_check_checkpoint_and_restart_require_cleanup(db, monkeypatch):
    """A failed ownership probe retains the running parent until a safe retry.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Inject bounded helper cleanup evidence.
    """
    from atlaso.app import worker

    job = make_job(db, "appliance-update", "running", mode="check", selected_streams=["atlaso_release"])
    db.add(JobStep(id="check-child", job_id=job.id, position=0, component_key="atlaso_release", label="Check", status="running"))
    db.commit()
    cancellation.request(db, job, ADMIN)
    monkeypatch.setattr(worker, "recover_interrupted_network_boot_media_swaps", lambda _db: 0)
    monkeypatch.setattr(worker, "_release_finalizer", lambda: {})
    monkeypatch.setattr(worker, "_quiesce_appliance_update_action", lambda *_args: False)
    worker.recover_interrupted_worker_jobs(db)
    db.refresh(job)
    assert job.status == "running"
    assert job.cancel_outcome == "cleanup-required"
    monkeypatch.setattr(worker, "_quiesce_appliance_update_action", lambda *_args: True)
    worker.recover_interrupted_worker_jobs(db)
    db.refresh(job)
    assert job.status == "cancelled"
    assert job.cancel_outcome == "confirmed"
    assert db.get(JobStep, "check-child").status == "cancelled"


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_staged_download_cancellation_rolls_back_before_confirmation(db, monkeypatch, tmp_path, cleanup_fails):
    """Real cache rollback completes before the task receives a cancelled state.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Inject a download finishing at the stop boundary.
        tmp_path: Owned replacement and backup cache directories.
        cleanup_fails: Whether rollback ownership remains unresolved.
    """
    from atlaso.app import worker
    from atlaso.app.services import network_boot

    job = make_job(db, "pxe-media-sync", "running", source="download", environment="shredos")
    final_dir, backup_dir = tmp_path / "current", tmp_path / "backup"
    final_dir.mkdir()
    backup_dir.mkdir()
    (final_dir / "image").write_bytes(b"replacement")
    (backup_dir / "image").write_bytes(b"original")
    staged = network_boot.DeferredNetworkBootMediaSync(media=None, final_dir=final_dir, backup_dir=backup_dir)
    def download(*_args, cancelled, **_kwargs):
        cancellation.request(db, job, ADMIN)
        assert job.status == "running"
        assert cancelled()
        return staged
    monkeypatch.setattr(network_boot, "sync_network_boot_media", download)
    monkeypatch.setattr(worker, "cleanup_network_boot_upload", lambda _job_id: None)
    if cleanup_fails:
        def fail_rollback(_self):
            raise OSError("synthetic rollback failure")
        monkeypatch.setattr(network_boot.DeferredNetworkBootMediaSync, "rollback_filesystem", fail_rollback)
        with pytest.raises(OSError):
            worker._run_pxe_media_sync(db, job)
        db.refresh(job)
        assert job.status == "running"
        assert job.cancel_outcome == "cleanup-required"
        assert job.cancel_completed_at is None
        assert (final_dir / "image").read_bytes() == b"replacement"
        return
    worker._run_pxe_media_sync(db, job)
    db.refresh(job)
    assert (final_dir / "image").read_bytes() == b"original"
    assert not backup_dir.exists()
    assert job.status == "cancelled"
    assert job.cancel_outcome == "confirmed"


def test_download_request_is_rechecked_before_connection_retry(monkeypatch, tmp_path):
    """A failed connection does not delay cancellation through additional attempts.

    Args:
        monkeypatch: Replace only the network opener and retry sleep.
        tmp_path: Owned destination for the unstarted download.
    """
    import urllib.error

    from atlaso.app.services import network_boot

    requested, attempts = [], []
    class Opener:
        def open(self, *_args, **_kwargs):
            attempts.append(True)
            requested.append(True)
            raise urllib.error.URLError("synthetic connection failure")
    monkeypatch.setattr(network_boot.urllib.request, "build_opener", lambda *_args: Opener())
    monkeypatch.setattr(network_boot.time, "sleep", lambda *_args: None)
    with pytest.raises(network_boot.NetworkBootMediaSyncCancelled):
        network_boot.BoundedHttpsDownloader().download("https://example.test/media", tmp_path / "media", cancelled=lambda: bool(requested))
    assert len(attempts) == 1
    assert not (tmp_path / "media").exists()
