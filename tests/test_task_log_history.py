"""Verify transactional, append-stable task history and bounded navigation."""

import json

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from atlaso.app.database import Base
from atlaso.app.models import AuditEvent, Job, TaskLogCheckpoint, TaskLogChunk
from atlaso.app.services.task_log_history import (
    capture_task_history,
    initialize_task_history,
    task_history_page,
)


@pytest.fixture
def history_db():
    """Provide isolated in-memory task storage with production capture hooks."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()


def _job(db, result):
    """Commit a running fixture task through the production flush hooks.

    Args:
        db: Isolated producer session.
        result: Initial task result mapping.
    """
    job = Job(id="task", type="vmware-deploy", created_by="test", status="running", result=json.dumps(result, sort_keys=True))
    db.add(job)
    db.commit()
    return job


def _all(db):
    """Walk every bounded forward page of the fixture history.

    Args:
        db: Isolated read session.
    """
    cursor, parts = "", []
    for _ in range(100):
        page = task_history_page(db, "task", cursor=cursor)
        assert not page["reset"]
        assert len(json.dumps(page, ensure_ascii=False).encode()) <= 1024 * 1024
        parts.append(page["text"])
        if not page["has_more"]:
            return "".join(parts)
        assert page["next_cursor"] != cursor
        cursor = page["next_cursor"]
    raise AssertionError("History did not finish")


def test_result_and_audit_growth_preserve_existing_cursor(history_db):
    """Neither earlier result keys nor interleaved audit output move old positions.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    job = _job(db, {"vm": "first", "log_lines": [f"line {i}" for i in range(1100)]})
    db.add_all([AuditEvent(actor="test", action="progress", resource_type="job", resource_id=job.id,
                           detail=f"event {i}") for i in range(600)])
    db.commit()
    cursor = task_history_page(db, job.id)["next_cursor"]
    before = task_history_page(db, job.id, cursor=cursor)
    result = json.loads(job.result)
    result["appliance"] = "new field"
    result["log_lines"].append("new output")
    job.result = json.dumps(result, sort_keys=True)
    db.commit()
    after = task_history_page(db, job.id, cursor=cursor)
    assert not after["reset"]
    assert after["text"] == before["text"]
    text = _all(db)
    assert text.count("new output") == 1
    assert text.count("line 0\n") == 1
    assert text.index("event 599") < text.index("appliance: new field") < text.index("new output")


def test_capture_rolls_back_and_core_updates_append_once(history_db):
    """An aborted producer transaction leaves neither content nor checkpoint progress.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    job = _job(db, {"vm": "first"})
    before = _all(db)
    job.result = json.dumps({"vm": "aborted"})
    db.flush()
    db.rollback()
    assert _all(db) == before
    changed = db.execute(update(Job).where(Job.id == job.id, Job.status == "running").values(result='{"vm":"core"}'))
    assert changed.rowcount == 1
    capture_task_history(db.connection(), job.id)
    db.commit()
    assert _all(db) == before + "vm: core\n"
    capture_task_history(db.connection(), job.id)
    db.commit()
    assert _all(db).count("vm: core") == 1


def test_capture_never_persists_private_key_body_or_secret_value(history_db):
    """Cross-commit log bodies and nested result credentials are sanitized before copies.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    job = _job(db, {"password": "password-secret", "nested": ["-----BEGIN PRIVATE KEY-----", "nested-secret"],
                    "log_lines": ["-----BEGIN PRIVATE KEY-----"]})
    job.result = json.dumps({"password": "password-secret", "log_lines": ["-----BEGIN PRIVATE KEY-----", "body-secret"]})
    db.commit()
    job.result = json.dumps({"log_lines": ["-----BEGIN PRIVATE KEY-----", "body-secret", "-----END PRIVATE KEY-----", "visible"]})
    db.commit()
    stored = "".join(db.execute(select(TaskLogChunk.content)).scalars())
    stored += "".join(db.execute(select(TaskLogCheckpoint.state_json)).scalars())
    for secret in ["password-secret", "nested-secret", "body-secret"]:
        assert secret not in stored
    assert "visible" in _all(db)


@pytest.mark.parametrize("ending", ["-----END CERTIFICATE-----", "-----END", "-----END PUBLIC KEY-----"])
def test_unrelated_task_pem_end_preserves_redaction_across_commits(history_db, ending):
    """Only a complete private-key closing marker releases persisted concealment.

    Args:
        history_db: Transactional history fixture.
        ending: Unrelated or incomplete marker interleaved into task output.
    """
    db = history_db
    lines = ["-----BEGIN RSA PRIVATE KEY-----"]
    job = _job(db, {"log_lines": lines})
    for line in [ending, "synthetic-private-body", "-----END RSA PRIVATE KEY-----", "visible-after-close"]:
        lines.append(line)
        job.result = json.dumps({"log_lines": lines})
        db.commit()
    stored = "".join(db.execute(select(TaskLogChunk.content)).scalars())
    stored += "".join(db.execute(select(TaskLogCheckpoint.state_json)).scalars())
    assert "synthetic-private-body" not in stored
    assert "visible-after-close" in _all(db)


@pytest.mark.parametrize("stream", ["log", "structured-log", "result", "audit"])
@pytest.mark.parametrize("split", [3, 8, 20000])
def test_task_marker_fragments_survive_commits(history_db, stream, split):
    """Persist finite parser state without copying a split key body into history.

    Args:
        history_db: Transactional task fixture.
        stream: Independently persisted producer stream.
        split: Header boundary, including within an oversized arbitrary label.
    """
    db = history_db
    job = _job(db, {})
    header = "-----BEGIN " + "LONG-LABEL-" * 3000 + "PRIVATE KEY-----"
    fragments = [header[:split], header[split:], "synthetic-split-body", "-----END CERTIFICATE-----",
                 "another-private-body", "-----END PRI", "VATE KEY-----", "visible-after-split-close"]
    logs = []
    for fragment in fragments:
        if stream == "audit":
            db.add(AuditEvent(actor="test", action="output", resource_type="job", resource_id=job.id, detail=fragment))
        elif stream == "result":
            job.result = json.dumps({"output": {"value": fragment}})
        else:
            logs.append({"output": fragment} if stream == "structured-log" else fragment)
            job.result = json.dumps({"log_lines": logs})
        db.commit()
        checkpoint = db.execute(select(TaskLogCheckpoint.state_json)).scalar_one()
        state = json.loads(checkpoint)
        assert all(len(state[key]) <= 16 for key in ("log_pem_state", "result_pem_state", "audit_pem_state"))
        stored = "".join(db.execute(select(TaskLogChunk.content)).scalars()) + checkpoint
        assert "synthetic-split-body" not in stored and "another-private-body" not in stored
    assert "visible-after-split-close" in _all(db)


def test_legacy_initialization_restart_and_deletion(history_db):
    """Legacy capture is idempotent and task deletion removes all owned history.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    db.connection().execute(Job.__table__.insert().values(id="task", type="test", created_by="test", result='{"vm":"legacy"}'))
    db.connection().execute(AuditEvent.__table__.insert().values(actor="test", action="old", resource_type="job", resource_id="task"))
    db.commit()
    initialize_task_history(db.get_bind())
    before = _all(db)
    assert "vm: legacy" in before and " old success" in before
    db.rollback()
    initialize_task_history(db.get_bind())
    assert _all(db) == before
    db.delete(db.get(Job, "task"))
    db.commit()
    assert db.execute(select(TaskLogChunk)).first() is None
    assert db.execute(select(TaskLogCheckpoint)).first() is None


def test_forward_and_backward_pages_reconstruct_unicode_history(history_db):
    """Bounded windows preserve every character through tail and Previous navigation.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    _job(db, {"log_lines": [f"row-{i} 漢字🙂" for i in range(1800)]})
    expected = _all(db)
    page = task_history_page(db, "task", tail=True)
    parts = []
    for _ in range(100):
        parts.append(page["text"])
        if not page["previous_cursor"]:
            break
        page = task_history_page(db, "task", cursor=page["previous_cursor"])
    assert "".join(reversed(parts)) == expected


def test_http_task_log_retains_cursor_after_result_growth(client):
    """The management route preserves the same historical window after a commit.

    Args:
        client: Authenticated application test transport.
    """
    from atlaso.app.database import SessionLocal
    from tests.routers.ui.helpers import login

    login(client)
    with SessionLocal() as db:
        job = _job(db, {"vm": "first", "log_lines": [f"line {i}" for i in range(1100)]})
        job_id = job.id
    first = client.get(f"/tasks/{job_id}/log").json()
    assert "next_cursor" in first
    query = {"cursor": first["next_cursor"]}
    before = client.get(f"/tasks/{job_id}/log", params=query).json()
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        result = json.loads(job.result)
        result["appliance"] = "new"
        job.result = json.dumps(result, sort_keys=True)
        db.commit()
    response = client.get(f"/tasks/{job_id}/log", params=query)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert not response.json()["reset"]
    assert response.json()["text"] == before["text"]


def test_concurrent_result_and_audit_commits_have_stable_order(tmp_path):
    """A task row lock serializes result and audit history across producer sessions.

    Args:
        tmp_path: Owned SQLite concurrency database directory.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    engine = create_engine(f"sqlite:///{tmp_path / 'history.db'}", connect_args={"timeout": 10})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _job(db, {"vm": "initial"})
    flushed, release, second_started = Event(), Event(), Event()

    def first_writer():
        """Hold the result transaction until the audit writer starts."""
        with Session(engine) as db:
            job = db.get(Job, "task")
            job.result = '{"vm":"committed first"}'
            db.flush()
            flushed.set()
            assert release.wait(10)
            db.commit()

    def second_writer():
        """Commit audit output through a distinct concurrent connection."""
        assert flushed.wait(10)
        with Session(engine) as db:
            db.add(AuditEvent(actor="test", action="after", resource_type="job", resource_id="task", detail="committed second"))
            second_started.set()
            db.commit()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(first_writer)
        second = pool.submit(second_writer)
        try:
            assert second_started.wait(10)
        finally:
            release.set()
        first.result(timeout=15)
        second.result(timeout=15)
    with Session(engine) as db:
        text = _all(db)
        assert text.index("committed first") < text.index("committed second")
    engine.dispose()


def test_changed_fields_and_log_replacement_append_without_erasing(history_db):
    """Updated, removed, and replaced result output remains in commit order.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    job = _job(db, {"vm": "first", "log_lines": ["old line"]})
    job.result = json.dumps({"vm": "second", "log_lines": ["replacement"]})
    db.commit()
    job.result = json.dumps({"log_lines": ["replacement", "next"]})
    db.commit()
    assert _all(db) == "vm: first\nold line\nvm: second\nreplacement\nvm: [removed]\nnext\n"


@pytest.mark.parametrize("kind", ["appliance-update", "vcf-depot-download"])
def test_pending_bulk_cancellation_captures_result_and_error(history_db, kind):
    """Both conditional cancellation owners append their successful bulk result.

    Args:
        history_db: Transactional history fixture.
        kind: Pending cancellation owner using a bulk result update.
    """
    from atlaso.app.models import utcnow
    from atlaso.app.services.appliance_update import cancel_pending_appliance_update
    from atlaso.app.services.vcf_depot_downloads import (
        cancel_pending_vcf_depot_download,
    )

    db = history_db
    job = Job(id="task", type=kind, created_by="test", status="pending", result="{}")
    db.add(job)
    db.commit()
    options = {"finished_at": utcnow(), "error": "cancelled safely", "result": '{"outcome":"cancelled"}'}
    if kind == "appliance-update":
        assert cancel_pending_appliance_update(db, job.id, **options)
    else:
        assert cancel_pending_vcf_depot_download(db, job.id, profile_id=1, profile_status_before_enqueue="planned", **options)
    db.commit()
    text = _all(db)
    assert "outcome: cancelled" in text
    assert "Error: cancelled safely" in text


def test_nonstandard_log_values_preserve_output_without_nested_secrets(history_db):
    """Non-list result fields remain visible and structured log items hide secret keys.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    job = _job(db, {"log_lines": "legacy scalar"})
    job.result = json.dumps({"log_lines": [{"password": "hidden-value", "message": "visible item"}]})
    db.commit()
    text = _all(db)
    assert "log_lines: legacy scalar" in text
    assert "visible item" in text
    assert "hidden-value" not in text
    assert "hidden-value" not in "".join(db.execute(select(TaskLogCheckpoint.state_json)).scalars())
