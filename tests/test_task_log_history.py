"""Verify transactional, append-stable task history and bounded navigation."""

import json

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from atlaso.app.database import Base
from atlaso.app.models import AuditEvent, Job, TaskLogCheckpoint, TaskLogChunk
from atlaso.app.services.task_log_history import (
    append_task_log_lines,
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
    job = _job(db, {"password": "password-secret", "nested": ["-----BEGIN PRIVATE KEY-----", "nested-secret", "-----END PRIVATE KEY-----"],
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


@pytest.mark.parametrize("ending", ["-----END EC PRIVATE KEY-----", "-----END CERTIFICATE-----", "-----END", "-----END PUBLIC KEY-----"])
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
                 "another-private-body", "-----END " + "LONG-LABEL-" * 3000 + "PRI", "VATE KEY-----", "visible-after-split-close"]
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
        assert all(len(state[key]) <= 512 for key in ("log_pem_state", "result_pem_state", "audit_pem_state"))
        stored = "".join(db.execute(select(TaskLogChunk.content)).scalars()) + checkpoint
        assert "synthetic-split-body" not in stored and "another-private-body" not in stored
    assert "visible-after-split-close" in _all(db)


@pytest.mark.parametrize("structured", [False, True])
def test_numeric_log_value_inside_private_block_is_concealed(history_db, structured):
    """Non-string output retains concealment without replaying rendered structures.

    Args:
        history_db: Transactional task fixture.
        structured: Place the numeric value inside a structured producer record.
    """
    db = history_db
    body = {"output": 9876543210123456789} if structured else 9876543210123456789
    _job(db, {"log_lines": ["-----BEGIN PRIVATE KEY-----", body, "-----END PRIVATE KEY-----", "visible"]})
    assert "9876543210123456789" not in _all(db)
    assert "visible" in _all(db)


def test_non_result_updates_do_not_rehash_task_log(history_db, monkeypatch):
    """Progress and audit commits preserve parser state without replaying old logs.

    Args:
        history_db: Transactional task fixture.
        monkeypatch: Reject any unexpected cumulative log hashing.
    """
    from atlaso.app.services import task_log_history

    db = history_db
    job = _job(db, {"log_lines": ["-----BEG"]})
    before = db.execute(select(TaskLogCheckpoint.state_json)).scalar_one()
    original = task_log_history._log_digest

    def reject(_lines):
        """Fail if an unchanged producer result enters cumulative hashing.

        Args:
            _lines: Unexpected raw log prefix.
        """
        raise AssertionError("unchanged result rehashed")

    monkeypatch.setattr(task_log_history, "_log_digest", reject)
    job.progress_percent = 30
    db.commit()
    assert db.execute(select(TaskLogCheckpoint.state_json)).scalar_one() == before
    db.add(AuditEvent(actor="test", action="progress", resource_type="job", resource_id=job.id, detail="audit-only"))
    db.commit()
    monkeypatch.setattr(task_log_history, "_log_digest", original)
    job.result = json.dumps({"log_lines": ["-----BEG", "IN PRIVATE KEY-----", "synthetic-unchanged-body"]})
    db.commit()
    assert "progress success" in _all(db)
    assert "audit-only" not in _all(db)
    assert "synthetic-unchanged-body" not in _all(db)


def test_legacy_initialization_restart_and_deletion(history_db, monkeypatch):
    """Restarts skip initialized payloads, including a competing initializer.

    Args:
        history_db: Transactional history fixture.
        monkeypatch: Reject any repeated result decoding during initialization.
    """
    db = history_db
    db.connection().execute(Job.__table__.insert().values(id="task", type="test", created_by="test", result='{"vm":"legacy"}'))
    db.connection().execute(AuditEvent.__table__.insert().values(actor="test", action="old", resource_type="job", resource_id="task"))
    db.commit()
    initialize_task_history(db.get_bind())
    before = _all(db)
    assert "vm: legacy" in before and " old success" in before
    db.rollback()
    from atlaso.app.services import task_log_history

    def reject_payload(_value):
        """Reject parsing an already initialized task result or checkpoint.

        Args:
            _value: Existing payload that startup must leave untouched.
        """
        raise AssertionError("Startup reparsed existing history")

    with monkeypatch.context() as patch:
        patch.setattr(task_log_history, "_payload", reject_payload)
        initialize_task_history(db.get_bind())
        with db.get_bind().begin() as connection:
            capture_task_history(connection, "task", only_if_missing=True)
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


@pytest.mark.parametrize("structured_log", [False, True])
def test_secret_named_field_preserves_following_key_context(history_db, structured_log):
    """Discarded secret fields still govern the following structured values.

    Args:
        history_db: Transactional task database.
        structured_log: Capture a nested log item instead of a result field.
    """
    db = history_db
    job = _job(db, {})
    value = {"private_key_header": "-----BEGIN RSA PRIVATE KEY-----", "body": "synthetic-secret-key-body",
             "end": "-----END RSA PRIVATE KEY-----", "visible": "after-matching-close"}
    job.result = json.dumps({"log_lines": [value]} if structured_log else {"output": value})
    db.commit()
    stored = "".join(db.execute(select(TaskLogChunk.content)).scalars())
    stored += "".join(db.execute(select(TaskLogCheckpoint.state_json)).scalars())
    assert "synthetic-secret-key-body" not in stored
    assert "after-matching-close" in _all(db)


@pytest.mark.parametrize("destination", ["log", "audit", "error"])
@pytest.mark.parametrize("same_commit", [False, True])
def test_result_marker_continues_through_following_task_stream(history_db, destination, same_commit):
    """One state protects result-to-output boundaries without replaying old fields.

    Args:
        history_db: Transactional fixture with the production flush hooks.
        destination: Subsequent displayed stream containing the key body.
        same_commit: Open the result marker in the same transaction as the following stream.
    """
    db = history_db
    result = {"header": "-----BEGIN RSA PRIVATE KEY-----"}
    job = _job(db, {} if same_commit else result)
    job.result = json.dumps(result)
    if destination == "log":
        result["log_lines"] = ["synthetic-cross-stream-body", "-----END RSA PRIVATE KEY-----", "visible-after-close"]
        job.result = json.dumps(result)
    elif destination == "audit":
        db.add(AuditEvent(actor="test", action="output", resource_type="job", resource_id=job.id,
                          detail="synthetic-cross-stream-body\n-----END RSA PRIVATE KEY-----\nvisible-after-close"))
    else:
        job.status = "failed"
        job.error = "synthetic-cross-stream-body\n-----END RSA PRIVATE KEY-----\nvisible-after-close"
    db.commit()
    stored = "".join(db.execute(select(TaskLogChunk.content)).scalars())
    stored += "".join(db.execute(select(TaskLogCheckpoint.state_json)).scalars())
    assert "synthetic-cross-stream-body" not in stored
    assert "visible-after-close" in _all(db)
    if destination == "log":
        result["log_lines"].append("visible-on-next-commit")
        job.result = json.dumps(result)
        db.commit()
        assert "visible-on-next-commit" in _all(db)


@pytest.mark.parametrize("boundary_change", ["changed", "removed", "reordered"])
@pytest.mark.parametrize("structured", [False, True])
def test_unchanged_opener_replays_when_result_boundaries_change(history_db, boundary_change, structured):
    """A changed snapshot cannot reuse its formerly closed final parser state.

    Args:
        history_db: Transactional fixture with production capture hooks.
        boundary_change: Alter the previously matching result footer or field order.
        structured: Continue the key in nested list and numeric values.
    """
    db = history_db
    job = _job(db, {})
    result = {"header": "-----BEGIN RSA PRIVATE KEY-----", "footer": "-----END RSA PRIVATE KEY-----"}
    job.result = json.dumps(result)
    db.commit()
    if boundary_change == "changed":
        result["footer"] = "-----END EC PRIVATE KEY-----"
    elif boundary_change == "removed":
        del result["footer"]
    else:
        result = {"footer": result["footer"], "header": result["header"]}
    result["body"] = {"parts": ["synthetic-replayed-body", 9423109]} if structured else "synthetic-replayed-body"
    job.result = json.dumps(result)
    db.commit()
    stored = "".join(db.execute(select(TaskLogChunk.content)).scalars())
    stored += "".join(db.execute(select(TaskLogCheckpoint.state_json)).scalars())
    assert "synthetic-replayed-body" not in stored
    if structured:
        assert "9423109" not in stored
    result["log_lines"] = ["-----END RSA PRIVATE KEY-----", "visible-after-snapshot-close"]
    job.result = json.dumps(result)
    db.commit()
    assert "visible-after-snapshot-close" in _all(db)


def test_nested_result_order_changes_recompute_concealment(history_db):
    """Field fingerprints preserve nested ordering because it determines PEM context.

    Args:
        history_db: Transactional task fixture.
    """
    db = history_db
    job = _job(db, {})
    value = {"body": "synthetic-reordered-value", "header": "-----BEGIN RSA PRIVATE KEY-----",
             "footer": "-----END RSA PRIVATE KEY-----"}
    job.result = json.dumps({"output": value})
    db.commit()
    boundary = db.execute(select(TaskLogCheckpoint.end_offset)).scalar_one()
    job.result = json.dumps({"output": {"header": value["header"], "body": value["body"], "footer": value["footer"]}})
    db.commit()
    new_text = "".join(db.execute(select(TaskLogChunk.content).where(TaskLogChunk.start_offset >= boundary)).scalars())
    checkpoint = db.execute(select(TaskLogCheckpoint.state_json)).scalar_one()
    assert "synthetic-reordered-value" not in new_text + checkpoint
    assert "[redacted private key]" in new_text


def test_incremental_appends_do_not_rehash_or_select_cumulative_result(history_db, monkeypatch):
    """Repeated bounded appends do no work proportional to retained producer output.

    Args:
        history_db: Transactional history fixture.
        monkeypatch: Guards old-result transfer and authentication work.
    """
    from sqlalchemy import event

    from atlaso.app.services import task_log_history

    db = history_db
    job = _job(db, {"log_lines": ["legacy " + str(i) for i in range(1000)]})
    job_id = job.id
    def reject_digest(_values):
        """Reject any old-result authentication during delta-only commits.

        Args:
            _values: Unexpected cumulative result submitted for authentication.
        """
        raise AssertionError("incremental append hashed a cumulative result")
    monkeypatch.setattr(task_log_history, "_log_digest", reject_digest)
    queries = []
    def record_query(_connection, _cursor, statement, _parameters, _context, _many):
        """Record SQL so retained raw output transfer is detected.

        Args:
            _connection: SQLAlchemy connection emitting the statement.
            _cursor: Driver cursor executing the statement.
            statement: SQL text inspected for cumulative result reads.
            _parameters: Bound SQL values, unused by this assertion.
            _context: SQLAlchemy execution context.
            _many: Whether the driver executes multiple parameter sets.
        """
        queries.append(statement)
    event.listen(db.get_bind(), "before_cursor_execute", record_query)
    try:
        for i in range(200):
            append_task_log_lines(db, job_id, (f"delta {i}",))
            db.commit()
    finally:
        event.remove(db.get_bind(), "before_cursor_execute", record_query)
    assert not any("jobs.result" in query for query in queries)
    text = _all(db)
    assert text.count("legacy 0\n") == 1
    assert text.count("delta 0\n") == 1
    assert text.endswith("delta 199\n")


def test_incremental_append_shares_redaction_and_rolls_back(history_db):
    """Result headers conceal delta bodies, and aborted writes retain no state.

    Args:
        history_db: Transactional history fixture.
    """
    db = history_db
    job = _job(db, {})
    job.result = json.dumps({"header": "-----BEGIN RSA PRIVATE KEY-----"})
    append_task_log_lines(db, job.id, ("synthetic-delta-secret",))
    db.commit()
    before = _all(db)
    append_task_log_lines(db, job.id, ("-----END RSA PRIVATE KEY-----", "aborted"))
    db.rollback()
    assert _all(db) == before
    append_task_log_lines(db, job.id, ("still-secret", "-----END RSA PRIVATE KEY-----", "visible-delta"))
    db.commit()
    text = _all(db)
    assert "synthetic-delta-secret" not in text and "still-secret" not in text and "aborted" not in text
    assert text.endswith("visible-delta\n")
    checkpoint = db.get(TaskLogCheckpoint, job.id).state_json
    assert "synthetic-delta-secret" not in checkpoint and "still-secret" not in checkpoint


@pytest.mark.parametrize("lines", [("x" * 65537,), tuple("x" for _ in range(501)), (1,)])
def test_incremental_append_rejects_invalid_batch_before_flush(history_db, lines):
    """Invalid producer batches do not flush unrelated pending task updates.

    Args:
        history_db: Transactional history fixture.
        lines: Oversized or non-string batch.
    """
    db = history_db
    job = _job(db, {})
    job_id = job.id
    job.result = json.dumps({"output": "not flushed"})
    with pytest.raises(ValueError):
        append_task_log_lines(db, job_id, lines)
    assert job in db.dirty
    db.rollback()
    assert "not flushed" not in _all(db)
