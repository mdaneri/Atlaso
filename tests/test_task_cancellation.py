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


@pytest.mark.parametrize("after_staging", [False, True])
def test_media_error_racing_cancellation_releases_clean_ownership(db, monkeypatch, tmp_path, after_staging):
    """Ordinary media failures do not retain a queue hold after verified cleanup.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Fail media execution while accepting a cancellation request.
        tmp_path: Owned original and replacement cache paths.
        after_staging: Exercise errors before and after a rollback object exists.
    """
    from atlaso.app import worker
    from atlaso.app.services import network_boot

    job = make_job(db, "pxe-media-sync", "running", source="download", environment="shredos")
    following = make_job(db)
    final_dir, backup_dir = tmp_path / "current", tmp_path / "backup"
    final_dir.mkdir()
    backup_dir.mkdir()
    (final_dir / "image").write_bytes(b"replacement")
    (backup_dir / "image").write_bytes(b"original")
    staged = network_boot.DeferredNetworkBootMediaSync(media=None, final_dir=final_dir, backup_dir=backup_dir)
    cleaned = []
    def fail(*_args, **_kwargs):
        cancellation.request(db, job, ADMIN)
        raise ValueError("synthetic media validation failure")
    monkeypatch.setattr(network_boot, "sync_network_boot_media", (lambda *_args, **_kwargs: staged) if after_staging else fail)
    monkeypatch.setattr(network_boot, "media_to_dict", fail)
    monkeypatch.setattr(worker, "cleanup_network_boot_upload", cleaned.append)
    worker._run_pxe_media_sync(db, job)
    db.refresh(job)
    assert cleaned == [job.id]
    assert job.status == "cancelled"
    assert job.cancel_outcome == "confirmed"
    assert job.cancel_completed_at is not None
    if after_staging:
        assert (final_dir / "image").read_bytes() == b"original"
        assert not backup_dir.exists()
    assert not db.scalars(select(Job).where(Job.status.in_(cancellation.ACTIVE), Job.cancel_outcome == "cleanup-required")).all()
    assert worker.claim_next_job(db).id == following.id


def test_media_startup_requires_complete_recovery_before_confirmation(db, monkeypatch, tmp_path):
    """Malformed recovery evidence retains ownership until real rollback succeeds.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Bind recovery to the owned test media root.
        tmp_path: Owned recovery journal and cache directories.
    """
    from functools import partial

    from atlaso.app import worker
    from atlaso.app.services import network_boot

    job = make_job(db, "pxe-media-sync", "running", source="download", environment="shredos")
    following = make_job(db)
    cancellation.request(db, job, ADMIN)
    media_root = tmp_path / "media"
    environment = media_root / "shredos"
    final_dir = environment / "1.0"
    backup_dir = environment / (".1.0.replacement-" + "a" * 32)
    final_dir.mkdir(parents=True)
    backup_dir.mkdir()
    (final_dir / "image").write_bytes(b"replacement")
    (backup_dir / "image").write_bytes(b"original")
    journal = environment / (".atlaso-media-sync-" + "a" * 32 + ".json")
    journal.write_text("invalid journal", encoding="utf-8")
    monkeypatch.setattr(worker, "recover_interrupted_network_boot_media_swaps", partial(network_boot.recover_interrupted_network_boot_media_swaps, media_root=media_root))
    monkeypatch.setattr(worker, "_release_finalizer", lambda: {})
    uploads = []
    monkeypatch.setattr(worker, "cleanup_network_boot_upload", uploads.append)
    worker.recover_interrupted_worker_jobs(db)
    db.refresh(job)
    assert job.status == "running"
    assert job.cancel_outcome == "cleanup-required"
    assert job.cancel_completed_at is None
    assert journal.exists() and backup_dir.exists()
    assert uploads == []
    journal.write_text(json.dumps({"environment": "shredos", "version": "1.0"}), encoding="utf-8")
    worker.recover_interrupted_worker_jobs(db)
    db.refresh(job)
    assert job.status == "cancelled"
    assert job.cancel_outcome == "confirmed"
    assert job.cancel_completed_at is not None
    assert not journal.exists() and not backup_dir.exists()
    assert (final_dir / "image").read_bytes() == b"original"
    assert uploads == [job.id]
    assert worker.claim_next_job(db).id == following.id


@pytest.mark.parametrize("role,allowed", [("admin", True), ("viewer", False), ("service-admin", False)])
def test_embedded_update_capability_uses_caller_identity(db, role, allowed):
    """Embedded task rows advertise only cancellation actions the caller can submit.

    Args:
        db: Isolated lifecycle database.
        role: Current browser caller role.
        allowed: Whether that role can cancel an update check.
    """
    from atlaso.app import ui

    job = make_job(db, "appliance-update", "running", mode="check", selected_streams=["atlaso_release"])
    context = ui.appliance_update_context(db, identity=Identity("caller", role, set()))
    row = next(row for row in context["recent_update_tasks"] if row["id"] == job.id)
    assert row["can_cancel"] is allowed
    if not allowed:
        assert "permission" in row["cancel_reason"]


@pytest.mark.parametrize("boundary", ["before_start", "claim_race", "reconciliation"])
def test_pending_apply_cancellation_releases_lock_without_execution(db, monkeypatch, boundary):
    """Queued apply cancellation wins atomically and releases the global apply owner.

    Args:
        db: Isolated task database.
        monkeypatch: Bind the actual execution entry point to this database.
        boundary: Exercise direct cancellation, the start race, and an old pending request.
    """
    from contextlib import contextmanager

    from atlaso.app import ui
    from atlaso.app.models import utcnow

    job = make_job(db, "appliance-apply", "pending")
    db.add(JobStep(id=job.id + ":unit", job_id=job.id, component_key="test", label="Test", position=0, status="pending"))
    db.commit()
    def unexpected_units(_db):
        pytest.fail("A cancelled queued apply reached execution preparation")
    monkeypatch.setattr(ui, "appliance_apply_units", unexpected_units)
    @contextmanager
    def execution_session():
        with Session(db.get_bind()) as execution_db:
            original = execution_db.execute
            raced = False
            def execute(statement, *args, **kwargs):
                nonlocal raced
                if boundary == "claim_race" and not raced and str(statement).startswith("UPDATE jobs SET"):
                    raced = True
                    cancellation.request(db, job, ADMIN)
                return original(statement, *args, **kwargs)
            monkeypatch.setattr(execution_db, "execute", execute)
            yield execution_db
    monkeypatch.setattr(ui, "SessionLocal", execution_session)
    if boundary == "before_start":
        cancellation.request(db, job, ADMIN)
    elif boundary == "reconciliation":
        job.cancel_requested_at = utcnow()
        job.cancel_requested_by = ADMIN.username
        job.cancel_outcome = "requested"
        db.commit()
        cancellation.reconcile_requests(db)
    ui.run_appliance_apply_job(job.id)
    db.refresh(job)
    assert job.status == "cancelled"
    assert job.cancel_outcome == "confirmed"
    assert job.cancel_completed_at is not None
    assert job.started_at is None
    assert db.get(JobStep, job.id + ":unit").status == "skipped"
    assert ui.active_appliance_apply_job(db) is None
    replacement = make_job(db, "appliance-apply", "pending")
    assert ui.active_appliance_apply_job(db).id == replacement.id


def test_web_startup_confirms_reserved_apply_before_interruption_recovery(db, monkeypatch):
    """Lifespan honors pre-claim cancellation even behind a full worker request batch.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Isolate unrelated startup services while retaining real Apply recovery.
    """
    import asyncio
    from types import SimpleNamespace

    from atlaso.app import main, ui
    from atlaso.app.models import utcnow

    # Unrelated reservations must not crowd this owner out of a bounded worker pass.
    for index in range(101):
        db.add(Job(id=f"earlier-{index}", type="managed-script", status="pending", created_by="operator",
                   cancel_requested_at=utcnow(), cancel_requested_by="operator", cancel_outcome="requested"))
    reserved = make_job(db, "appliance-apply", "pending")
    interrupted = make_job(db, "appliance-apply", "pending")
    reserved.cancel_requested_at = utcnow()
    reserved.cancel_requested_by = "operator"
    reserved.cancel_outcome = "requested"
    db.add(JobStep(id=reserved.id + ":firewall", job_id=reserved.id, component_key="firewall", label="Firewall", position=0, status="pending"))
    db.commit()
    monkeypatch.setattr(main, "SessionLocal", lambda: Session(db.get_bind()))
    monkeypatch.setattr(main, "get_settings", lambda: SimpleNamespace(environment="development"))
    for name in ("cleanup_transient_secret_staging_files", "configure_logging", "init_db", "seed_initial_data",
                 "ensure_environment_rows", "recover_interrupted_network_boot_media_swaps", "register_bundled_inventory_media",
                 "recover_interrupted_vcf_depot_software_id_jobs", "ensure_vcf_depot_running_operation_index",
                 "recover_interrupted_vcf_helper_jobs", "refresh_startup_host_inventory", "initialize_factory_appliance_apply_baseline",
                 "validate_enabled_provider_at_startup", "start_monitor_sampler"):
        monkeypatch.setattr(main, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(main.upload_store, "close", lambda: None)
    async def startup():
        async with main.lifespan(main.app):
            pass
    asyncio.run(startup())
    db.expire_all()
    assert reserved.status == "cancelled"
    assert reserved.cancel_outcome == "confirmed"
    assert reserved.cancel_completed_at is not None
    assert reserved.started_at is None
    assert db.get(JobStep, reserved.id + ":firewall").status == "skipped"
    assert interrupted.status == "failed"
    assert ui.active_appliance_apply_job(db) is None
    assert db.get(Job, "earlier-0").status == "pending"


@pytest.mark.parametrize("startup", [False, True])
@pytest.mark.parametrize("newer_confirmation", [False, True])
def test_cancelled_check_retains_completed_availability(db, monkeypatch, startup, newer_confirmation):
    """Completed check state survives cancellation while skipped and newer evidence stays intact.

    Args:
        db: Isolated lifecycle database.
        monkeypatch: Bind checkpoint sessions and prove startup helper shutdown.
        startup: Exercise restart recovery instead of the between-child checkpoint.
        newer_confirmation: Preserve a confirmation newer than this completed child.
    """
    from datetime import timedelta

    from atlaso.app import ui, worker
    from atlaso.app.models import utcnow
    from atlaso.app.services.appliance_update import (
        empty_update_availability,
        record_update_availability_attempt,
        update_availability_summary,
        update_availability_to_json,
        update_stream_configuration_fingerprint,
    )

    finished = utcnow()
    settings = {}
    state = empty_update_availability()
    for stream in ("atlaso_release", "photon_os"):
        state = record_update_availability_attempt(
            state, stream=stream, job_id="prior", checked_at=finished + timedelta(minutes=1 if newer_confirmation else -1),
            fingerprint=update_stream_configuration_fingerprint(stream, settings),
            result={"state": "available", "update_available": True, "change_count": 1},
        )
    untouched = state["streams"]["photon_os"]
    ui.set_setting_value(db, ui.APPLIANCE_UPDATE_AVAILABILITY_KEY, update_availability_to_json(state))
    job = make_job(db, "appliance-update", "running", mode="check", selected_streams=["atlaso_release", "photon_os"], settings=settings)
    db.add(JobStep(id=job.id + ":release", job_id=job.id, component_key="atlaso_release", label="Release", position=0,
                   status="succeeded", finished_at=finished, result=json.dumps({"unit_id": "atlaso_release", "success": True,
                   "availability": {"state": "up_to_date", "update_available": False, "change_count": 0}})))
    db.add(JobStep(id=job.id + ":photon", job_id=job.id, component_key="photon_os", label="Photon", position=1, status="pending"))
    db.commit()
    cancellation.request(db, job, ADMIN)
    if startup:
        monkeypatch.setattr(worker, "recover_interrupted_network_boot_media_swaps", lambda _db: 0)
        monkeypatch.setattr(worker, "_release_finalizer", lambda: {})
        monkeypatch.setattr(worker, "_quiesce_appliance_update_action", lambda *_args: True)
        worker.recover_interrupted_worker_jobs(db)
    else:
        monkeypatch.setattr(worker, "SessionLocal", lambda: Session(db.get_bind()))
        assert worker._cancel_update_check_if_requested(job.id)
    db.expire_all()
    assert job.status == "cancelled"
    assert job.cancel_outcome == "confirmed"
    assert db.get(JobStep, job.id + ":release").status == "succeeded"
    assert db.get(JobStep, job.id + ":photon").status == "skipped"
    actual = ui.appliance_update_availability_state(db)
    assert actual["streams"]["photon_os"] == untouched
    assert actual["streams"]["atlaso_release"]["confirmed"]["update_available"] is newer_confirmation
    summary = update_availability_summary(actual, settings, result_streams=["atlaso_release"])
    release = next(row for row in summary["streams"] if row["id"] == "atlaso_release")
    assert release["confirmed"]["change_count"] == (1 if newer_confirmation else 0)
