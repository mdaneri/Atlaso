"""Exercise current-admin authorization, lifecycle, expiry and maintenance integration."""

import json
from datetime import timedelta

import pytest

from tests.routers.ui.helpers import login

ROOT = "/ui/management/backup-restore/diagnostics"


@pytest.mark.parametrize("cancelled", [False, True])
def test_running_collection_failure_finishes_task_progress(client, monkeypatch, tmp_path, cancelled):
    """Terminal collection errors finish progress without reporting success.

    Args:
        client: Authenticated application client.
        monkeypatch: Fixture restoring collector behavior.
        tmp_path: Isolated diagnostic spool fixture.
        cancelled: Whether cancellation was requested before the collector stopped.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import Collector, EvidenceError

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "running"
        job.progress_percent = 37
        job.result = json.dumps({"cancel_requested": cancelled})
        db.commit()

    def stop_capture(*_args):
        """Simulate a global collector failure after partial progress.

        Args:
            *_args: Capture arguments unused by the failure fixture.
        """
        raise EvidenceError("cancelled" if cancelled else "insufficient_space")

    monkeypatch.setattr(Collector, "capture", stop_capture)
    diagnostics.run(bundle_id)
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        assert job.status == ("cancelled" if cancelled else "failed")
        assert job.progress_percent == 100
        assert job.finished_at is not None
    assert not diagnostics.artifact_path(bundle_id).exists()


def test_expiry_continues_after_one_artifact_failure(client, monkeypatch, tmp_path):
    """Preserve an unsafe artifact while still deleting an older ordinary bundle.

    Args:
        client: Test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, utcnow
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import EvidenceError, write_new

    prepare(client, monkeypatch, tmp_path)
    ids = ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"]
    for bundle_id in ids:
        write_new(diagnostics.artifact_path(bundle_id), b"safe")
    original = diagnostics.remove

    def fail_newest(db, job, *, actor, expired=False):
        """Simulate an item-specific filesystem rejection.

        Args:
            db: Worker database session.
            job: Candidate expired job.
            actor: Cleanup audit identity.
            expired: Whether this is retention cleanup.
        """
        if job.id == ids[0]:
            raise EvidenceError("permission_denied")
        original(db, job, actor=actor, expired=expired)

    monkeypatch.setattr(diagnostics, "remove", fail_newest)
    with SessionLocal() as db:
        for index, bundle_id in enumerate(ids):
            db.add(Job(id=bundle_id, type=diagnostics.JOB_TYPE, status="succeeded", created_by="admin",
                       created_at=utcnow() - timedelta(days=2 + index), result='{"bundle_status":"ready"}'))
        db.commit()
        diagnostics.expire(db)
        assert diagnostics.result(diagnostics.find_job(db, ids[1]))["bundle_status"] == "expired"
        assert diagnostics.result(diagnostics.find_job(db, ids[0]))["bundle_status"] == "ready"
    assert diagnostics.artifact_path(ids[0]).exists()
    assert not diagnostics.artifact_path(ids[1]).exists()


def test_current_job_status_overrides_stale_bundle_metadata():
    """Keep claimed and interrupted jobs actionable despite stale result metadata."""
    from atlaso.app.models import Job, utcnow
    from atlaso.app.services import diagnostics

    job = Job(id="0" * 36, type=diagnostics.JOB_TYPE, created_at=utcnow(),
              result='{"bundle_status":"pending"}', task_config_json="{}", progress_percent=50)
    for state in ("running", "failed", "cancelled"):
        job.status = state
        assert diagnostics.row(job)["status"] == state
    job.status = "succeeded"
    job.result = '{"bundle_status":"ready_with_omissions"}'
    assert diagnostics.row(job)["status"] == "ready_with_omissions"
    job.created_at = utcnow() - timedelta(days=2)
    for state in ("pending", "running"):
        job.status = state
        assert diagnostics.row(job)["status"] == state
    job.status = "succeeded"
    assert diagnostics.row(job)["status"] == "expired"


def prepare(client, monkeypatch, tmp_path):
    """Prepare.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from atlaso.app.config import get_settings

    monkeypatch.setattr(get_settings(), "diagnostics_spool_path", tmp_path / "diagnostics")
    login(client)
    page = client.get("/ui/management/backup-restore")
    assert page.status_code == 200
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_maintenance_tabs_keep_recovery_actions(client, monkeypatch, tmp_path):
    """Test maintenance tabs keep recovery actions.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    prepare(client, monkeypatch, tmp_path)
    html = client.get("/ui/management/backup-restore").text
    assert html.index('>LDAP</button>') < html.index('>Backup</button>') < html.index('>Reset</button>') < html.index('>Diagnostics</button>')
    for text in ("Maintenance", "Download settings backup", "Restore settings backup", "Factory reset appliance", "Download encrypted LDAP recovery", "Anonymize hostnames and usernames"):
        assert text in html
    import re

    from atlaso.diagnostics import TASK_ID_PATTERN

    correlation = re.search(r'<input name="correlation_id"[^>]+>', html).group()
    assert f'pattern="{TASK_ID_PATTERN}"' in correlation
    assert int(re.search(r'maxlength="([0-9]+)"', correlation).group(1)) >= 54
    assert 'name="anonymize" checked' not in html
    assert 'name="detailed_logs" checked' not in html


def test_create_requires_csrf_and_runs_shared_collector(client, monkeypatch, tmp_path):
    """Test create requires csrf and runs shared collector.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import Collector, EvidenceError

    csrf = prepare(client, monkeypatch, tmp_path)
    assert client.post(ROOT + "/create", data={"csrf": "bad"}).status_code == 403
    response = client.post(ROOT + "/create", data={"csrf": csrf, "anonymize": "on"})
    assert response.status_code == 202
    bundle_id = response.json()["id"]
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "running"
        db.commit()
    def unavailable(*args):
        """Unavailable.

        Args:
            *args: Fixed command arguments or synthetic helper invocation.
        """
        raise EvidenceError("unavailable")
    monkeypatch.setattr(Collector, "command", unavailable)
    diagnostics.run(bundle_id)
    detail = client.get(ROOT + "/" + bundle_id)
    assert detail.status_code == 200
    assert detail.json()["status"] == "ready_with_omissions"
    download = client.get(ROOT + "/" + bundle_id + "/download")
    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store, private"
    assert download.content.startswith(b"PK")
    assert client.post(ROOT + "/" + bundle_id + "/delete", data={"csrf": csrf}).status_code == 200
    assert not diagnostics.artifact_path(bundle_id).exists()
    assert client.get(ROOT + "/" + bundle_id + "/download").status_code == 404


def test_expiry_and_task_domain_isolation(client, monkeypatch, tmp_path):
    """Test expiry and task domain isolation.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, utcnow
    from atlaso.app.services import diagnostics

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "succeeded"
        job.created_at = utcnow() - timedelta(days=2)
        job.result = json.dumps({"bundle_status": "ready"})
        db.add(Job(id="0" * 36, type="appliance-update", created_by="admin"))
        db.commit()
    assert client.get(ROOT + "/" + bundle_id + "/download").status_code == 404
    assert client.get(ROOT + "/" + "0" * 36).status_code == 404
    assert client.get(ROOT + "/data").json()["bundles"][0]["status"] == "expired"


def test_active_delete_blocked_cancel_supported(client, monkeypatch, tmp_path):
    """Test active delete blocked cancel supported.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    assert client.post(ROOT + "/" + bundle_id + "/delete", data={"csrf": csrf}).status_code == 409
    assert client.post(ROOT + "/" + bundle_id + "/cancel", data={"csrf": csrf}).json()["status"] == "cancelled"
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics

    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        assert job.finished_at is not None
        assert job.progress_percent == 100
        finished_at = job.finished_at
    client.post(ROOT + "/" + bundle_id + "/cancel", data={"csrf": csrf})
    with SessionLocal() as db:
        assert diagnostics.find_job(db, bundle_id).finished_at == finished_at
    assert client.post(ROOT + "/" + bundle_id + "/delete", data={"csrf": csrf}).status_code == 200


def test_revocation_blocks_every_bundle_surface(client, monkeypatch, tmp_path):
    """Test revocation blocks every bundle surface.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import User

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.role = "viewer"
        user.roles_json = '["viewer"]'
        db.commit()
    for path in ("/data", "/" + bundle_id, "/" + bundle_id + "/download"):
        assert client.get(ROOT + path).status_code == 403
    for path in ("/create", "/" + bundle_id + "/delete", "/" + bundle_id + "/cancel"):
        assert client.post(ROOT + path, data={"csrf": csrf}).status_code == 403


def test_disk_admission_does_not_queue_a_job(client, monkeypatch, tmp_path):
    """Test disk admission does not queue a job.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from collections import namedtuple

    from atlaso.app.services import diagnostics

    csrf = prepare(client, monkeypatch, tmp_path)
    usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(diagnostics.shutil, "disk_usage", lambda path: usage(100, 99, 1))
    assert client.post(ROOT + "/create", data={"csrf": csrf}).status_code == 400
    assert client.get(ROOT + "/data").json()["bundles"] == []


def test_running_collection_rejects_cancel_and_preserves_publication(client, monkeypatch, tmp_path):
    """An unsupported running cancellation leaves collection and its publication owned.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import Collector

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "running"
        db.commit()
    monkeypatch.setattr(Collector, "capture", lambda *args: (b"safe", {"status": "ready", "omissions": []}))
    original = diagnostics.write_new

    def write_and_cancel(path, content):
        """Write and cancel.

        Args:
            path: Fixed source or task-owned output path.
            content: Already sanitized archive bytes.
        """
        original(path, content)
        assert client.post(ROOT + "/" + bundle_id + "/cancel", data={"csrf": csrf}).status_code == 409

    monkeypatch.setattr(diagnostics, "write_new", write_and_cancel)
    diagnostics.run(bundle_id)
    with SessionLocal() as db:
        assert diagnostics.find_job(db, bundle_id).status == "succeeded"
    assert diagnostics.artifact_path(bundle_id).exists()
    with SessionLocal() as db:
        assert diagnostics.find_job(db, bundle_id).progress_percent == 100


def test_expiry_cleans_interrupted_job_without_result(client, monkeypatch, tmp_path):
    """An interrupted terminal job must not strand an artifact behind a SQL NULL.

    Args:
        client: Authenticated test application client fixture.
        monkeypatch: Fixture restoring patched dependencies after the test.
        tmp_path: Task-local isolated filesystem fixture.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import utcnow
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import write_new

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    write_new(diagnostics.artifact_path(bundle_id), b"safe")
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "failed"
        job.result = None
        job.created_at = utcnow() - timedelta(days=2)
        db.commit()
        diagnostics.expire(db)
    assert not diagnostics.artifact_path(bundle_id).exists()


@pytest.mark.parametrize("missing_manifest", [False, True])
def test_corrupt_archive_detail_is_unavailable(client, monkeypatch, tmp_path, missing_manifest):
    """Report damaged archive structure through the bounded detail response.

    Args:
        client: Application client fixture.
        monkeypatch: Dependency override fixture.
        tmp_path: Private test filesystem root.
        missing_manifest: Select a valid ZIP lacking the required manifest.
    """
    import io
    import zipfile

    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import write_new

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    data = b"truncated zip"
    if missing_manifest:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("summary.txt", "partial")
        data = buffer.getvalue()
    write_new(diagnostics.artifact_path(bundle_id), data)
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "succeeded"
        job.result = '{"bundle_status":"ready"}'
        db.commit()
    response = client.get(ROOT + "/" + bundle_id)
    assert response.status_code == 503
    assert response.json()["detail"] == "Bundle evidence is unavailable."


@pytest.mark.parametrize("expired", [False, True])
def test_deletion_flush_failure_keeps_lifecycle_retryable(client, monkeypatch, tmp_path, expired):
    """Keep retention metadata until directory durability succeeds, including retries.

    Args:
        client: Application client fixture.
        monkeypatch: Dependency override fixture.
        tmp_path: Private test filesystem root.
        expired: Exercise automatic expiry as well as explicit deletion.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import write_new

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    target = diagnostics.artifact_path(bundle_id)
    write_new(target, b"private evidence")
    attempts = []

    def flush(directory):
        """Fail once after unlink to exercise the absent-file retry.

        Args:
            directory: Spool whose deletion is being persisted.
        """
        assert directory == target.parent
        assert not target.exists()
        attempts.append(directory)
        if len(attempts) == 1:
            raise OSError("simulated flush failure")

    monkeypatch.setattr(diagnostics, "sync_spool", flush)
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "succeeded"
        job.result = '{"bundle_status":"ready"}'
        db.commit()
        with pytest.raises(OSError):
            diagnostics.remove(db, job, actor="admin", expired=expired)
        db.rollback()
        assert diagnostics.result(diagnostics.find_job(db, bundle_id))["bundle_status"] == "ready"
        diagnostics.remove(db, job, actor="admin", expired=expired)
        assert diagnostics.result(job)["bundle_status"] == ("expired" if expired else "deleted")
    assert len(attempts) == 2


@pytest.mark.parametrize("flush_fails", [False, True])
def test_publication_flush_precedes_ready_state(client, monkeypatch, tmp_path, flush_fails):
    """A bundle becomes ready only after its directory entry is durable.

    Args:
        client: Application client fixture.
        monkeypatch: Dependency override fixture.
        tmp_path: Private test filesystem root.
        flush_fails: Simulate a failed appliance directory flush.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics
    from atlaso.diagnostics import Collector

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = "running"
        db.commit()
    monkeypatch.setattr(Collector, "capture", lambda *args: (b"safe", {"status": "ready", "omissions": []}))
    flushed = []

    def flush(directory):
        """Verify publication ordering before optionally rejecting durability.

        Args:
            directory: Private spool holding the new archive.
        """
        assert diagnostics.artifact_path(bundle_id).read_bytes() == b"safe"
        with SessionLocal() as db:
            assert diagnostics.find_job(db, bundle_id).status == "running"
        flushed.append(directory)
        if flush_fails:
            raise OSError("simulated flush failure")

    monkeypatch.setattr(diagnostics, "sync_spool", flush)
    diagnostics.run(bundle_id)
    assert len(flushed) == 1
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        assert job.status == ("failed" if flush_fails else "succeeded")
        assert diagnostics.result(job)["bundle_status"] == ("failed" if flush_fails else "ready")
        assert job.finished_at is not None
        assert job.progress_percent == 100


@pytest.mark.parametrize("terminal_status", ["succeeded", "failed", "cancelled"])
def test_terminal_cancellation_is_idempotent_without_audit(client, monkeypatch, tmp_path, terminal_status):
    """A stale cancel action must not claim or audit a cancellation that did not occur.

    Args:
        client: Application client fixture.
        monkeypatch: Dependency override fixture.
        tmp_path: Private test filesystem root.
        terminal_status: Completed job state reached before the cancellation request.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services import diagnostics
    from atlaso.app.services import task_cancellation as cancellation

    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        job.status = terminal_status
        original_result = job.result
        db.commit()
    audits = []
    monkeypatch.setattr(cancellation, "_audit", lambda *args, **kwargs: audits.append(kwargs))
    response = client.post(ROOT + "/" + bundle_id + "/cancel", data={"csrf": csrf})
    assert response.status_code == 200
    assert audits == []
    with SessionLocal() as db:
        job = diagnostics.find_job(db, bundle_id)
        assert job.status == terminal_status
        assert job.result == original_result
