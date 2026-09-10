"""Exercise current-admin authorization, lifecycle, expiry and maintenance integration."""

import json
from datetime import timedelta

from tests.routers.ui.helpers import login

ROOT = "/ui/management/backup-restore/diagnostics"


def prepare(client, monkeypatch, tmp_path):
    from atlaso.app.config import get_settings

    monkeypatch.setattr(get_settings(), "diagnostics_spool_path", tmp_path / "diagnostics")
    login(client)
    page = client.get("/ui/management/backup-restore")
    assert page.status_code == 200
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_maintenance_tabs_keep_recovery_actions(client, monkeypatch, tmp_path):
    prepare(client, monkeypatch, tmp_path)
    html = client.get("/ui/management/backup-restore").text
    assert html.index('>LDAP</button>') < html.index('>Backup</button>') < html.index('>Reset</button>') < html.index('>Diagnostics</button>')
    for text in ("Maintenance", "Download settings backup", "Restore settings backup", "Factory reset appliance", "Download encrypted LDAP recovery", "Anonymize hostnames and usernames"):
        assert text in html
    assert 'name="anonymize" checked' not in html
    assert 'name="detailed_logs" checked' not in html


def test_create_requires_csrf_and_runs_shared_collector(client, monkeypatch, tmp_path):
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
    csrf = prepare(client, monkeypatch, tmp_path)
    bundle_id = client.post(ROOT + "/create", data={"csrf": csrf}).json()["id"]
    assert client.post(ROOT + "/" + bundle_id + "/delete", data={"csrf": csrf}).status_code == 409
    assert client.post(ROOT + "/" + bundle_id + "/cancel", data={"csrf": csrf}).json()["status"] == "cancelled"
    assert client.post(ROOT + "/" + bundle_id + "/delete", data={"csrf": csrf}).status_code == 200


def test_revocation_blocks_every_bundle_surface(client, monkeypatch, tmp_path):
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
    from collections import namedtuple

    from atlaso.app.services import diagnostics

    csrf = prepare(client, monkeypatch, tmp_path)
    usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(diagnostics.shutil, "disk_usage", lambda path: usage(100, 99, 1))
    assert client.post(ROOT + "/create", data={"csrf": csrf}).status_code == 400
    assert client.get(ROOT + "/data").json()["bundles"] == []


def test_cancel_during_publication_removes_only_new_bundle(client, monkeypatch, tmp_path):
    """A cancellation arriving after the write still prevents artifact publication."""
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
        original(path, content)
        assert client.post(ROOT + "/" + bundle_id + "/cancel", data={"csrf": csrf}).status_code == 200

    monkeypatch.setattr(diagnostics, "write_new", write_and_cancel)
    diagnostics.run(bundle_id)
    assert client.get(ROOT + "/" + bundle_id).json()["status"] == "cancelled"
    assert not diagnostics.artifact_path(bundle_id).exists()


def test_expiry_cleans_interrupted_job_without_result(client, monkeypatch, tmp_path):
    """An interrupted terminal job must not strand an artifact behind a SQL NULL."""
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
