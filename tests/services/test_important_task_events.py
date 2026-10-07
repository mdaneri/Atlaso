"""Exercise important-event capture at real ORM/Core transaction boundaries."""

import json
import logging
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import Session

from atlaso.app.database import Base
from atlaso.app.models import (
    AuditEvent,
    Job,
    JobStep,
    TaskLogCheckpoint,
    TaskLogChunk,
    utcnow,
)
from atlaso.app.services.task_log_history import (
    capture_task_history_for_session,
    initialize_task_history,
    task_history_page,
)
from atlaso.important_events import COMPONENTS, validate_event


@pytest.fixture
def db(tmp_path):
    """Create persistent isolated storage with the production flush/commit hooks.

    Args:
        tmp_path: Owned test directory under the recorded validation root.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'events.db'}")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def _new_task(db, task_id="job_123456789abc"):
    """Submit a task and component using the same transaction as admission.

    Args:
        db: Isolated producer session.
        task_id: Unique identifier for the fixture task.
    """
    task = Job(id=task_id, type="appliance-apply", created_by="console:root", status="pending", result="{}")
    step = JobStep(id=f"{task.id}:network", job=task, component_key="network", label="Network", position=1, status="pending")
    db.add_all([task, step])
    db.commit()
    return task, step


def _state(db, task):
    """Read the committed producer checkpoint directly.

    Args:
        db: Isolated reader.
        task: Task owning evidence.
    """
    db.expire_all()
    return json.loads(db.get(TaskLogCheckpoint, task.id).state_json)


def test_failure_and_failed_recovery_survive_restart_without_raw_data(db, caplog):
    """Keep original failure, prior success, and rollback error as separate evidence.

    Args:
        db: Persistent isolated producer.
        caplog: Capture shared operational messages.
    """
    caplog.set_level(logging.INFO, logger="atlaso.tasks")
    task, step = _new_task(db)
    task.status = step.status = "running"
    task.started_at = step.started_at = utcnow()
    db.commit()
    step.status = "failed"
    step.result = json.dumps({"commands": [
        {"stage": "validation", "returncode": 0},
        {"stage": "execution", "returncode": 124, "stderr": "password=synthetic-password https://user:synthetic-token@example.invalid"},
        {"stage": "rollback", "returncode": 1, "stderr": "-----BEGIN PRIVATE KEY-----\nsynthetic-private-key-fragment"},
    ]})
    task.status = "failed"
    task.finished_at = step.finished_at = utcnow()
    task.error = "Task failed."
    db.commit()
    state = _state(db, task)
    events = state["important_events"]
    assert any(e["stage"] == "validation" and e["outcome"] == "succeeded" for e in events)
    assert any(e["stage"] == "execution" and e["reason"] == "timed_out" for e in events)
    assert any(e["stage"] == "rollback" and e["reason"] == "rollback_failed" for e in events)
    assert all(validate_event(e) == e for e in events)
    assert "component=network stage=execution" in caplog.text
    persisted = json.dumps(state) + "".join(db.scalars(select(TaskLogChunk.content)).all()) + caplog.text
    assert "synthetic-password" not in persisted
    assert "synthetic-token" not in persisted
    assert "synthetic-private-key-fragment" not in persisted
    with Session(db.get_bind()) as restarted:
        assert json.loads(restarted.get(TaskLogCheckpoint, task.id).state_json)["important_events"] == events


def test_vcf_noop_and_partial_failure_keep_truthful_outcome_reason_and_severity(db):
    """Preserve VCF terminal statuses and classify partial failure as an error.

    Args:
        db: Isolated producer session.
    """
    noop, noop_step = _new_task(db, "job_vcf_noop_1234")
    noop.type = "vcf-target-trust"
    noop.status = noop_step.status = "no-op"
    noop.result = '{"status":"no-op"}'
    db.commit()

    partial, partial_step = _new_task(db, "job_vcf_partial_1234")
    partial.type = "vcf-sddc-deployment"
    partial.status = partial_step.status = "partial-failure"
    partial.error = partial_step.error = "Connection refused by the target service."
    partial.result = '{"status":"partial-failure","reason_code":"connection_refused"}'
    db.commit()

    noop_events = _state(db, noop)["important_events"]
    assert all(validate_event(event) == event for event in noop_events)
    assert any(event["outcome"] == "no-op" and event["severity"] == "INFO" and event["reason"] == "none"
               for event in noop_events)
    partial_events = _state(db, partial)["important_events"]
    assert all(validate_event(event) == event for event in partial_events)
    assert any(event["component"] == "task" and event["outcome"] == "partial-failure"
               and event["severity"] == "ERROR" and event["reason"] == "connection_refused"
               for event in partial_events)
    assert any(event["component"] == "network" and event["outcome"] == "partial-failure"
               and event["severity"] == "ERROR" and event["reason"] == "connection_refused"
               for event in partial_events)


def test_committed_audits_and_core_claims_mirror_once_aborted_writes_do_not(db, caplog):
    """Direct audit producers and Core updates share committed-only event capture.

    Args:
        db: Isolated producer.
        caplog: Capture operational output.
    """
    caplog.set_level(logging.INFO)
    task, _ = _new_task(db)
    db.execute(update(Job).where(Job.id == task.id).values(status="running", started_at=utcnow()))
    capture_task_history_for_session(db, task.id, result_changed=False)
    db.add(AuditEvent(actor="scheduler", action="queue_scheduled_task", resource_type="job", resource_id=task.id, success=True))
    db.commit()
    assert caplog.text.count("component=task stage=started") == 1
    assert caplog.text.count("action=queue_scheduled_task") == 1
    caplog.clear()
    task.status = "succeeded"
    db.add(AuditEvent(actor="api", action="aborted_change", resource_type="interface", resource_id="eth0", success=True))
    db.flush()
    db.rollback()
    assert "stage=completed" not in caplog.text
    assert "action=aborted_change" not in caplog.text
    assert not any(e["outcome"] == "succeeded" for e in _state(db, task)["important_events"])


def test_savepoint_commit_mirrors_only_after_outer_commit(db, caplog):
    """A successful savepoint does not publish before its owning transaction.

    Args:
        db: Isolated producer session.
        caplog: Capture shared operational messages.
    """
    caplog.set_level(logging.INFO, logger="atlaso.tasks")
    task, step = _new_task(db)
    caplog.clear()
    task.status = "running"
    db.flush()

    with db.begin_nested():
        step.status = "running"
        db.flush()

    assert caplog.text == ""
    db.commit()

    assert caplog.text.count("component=task stage=started") == 1
    assert caplog.text.count("component=network stage=started") == 1


def test_savepoint_success_followed_by_outer_rollback_emits_nothing(db, caplog):
    """A savepoint cannot claim durable success when its outer transaction rolls back.

    Args:
        db: Isolated producer session.
        caplog: Capture shared operational messages.
    """
    caplog.set_level(logging.INFO, logger="atlaso.tasks")
    task, step = _new_task(db)
    caplog.clear()
    task.status = "running"
    db.flush()

    with db.begin_nested():
        step.status = "running"
        db.flush()

    assert caplog.text == ""
    db.rollback()

    assert caplog.text == ""
    assert _state(db, task)["important_events"][-1]["outcome"] == "pending"


def test_savepoint_rollback_discards_local_mirrors_and_preserves_outer_queue(db, caplog):
    """Rollback removes savepoint events without dropping earlier outer events.

    Args:
        db: Isolated producer session.
        caplog: Capture shared operational messages.
    """
    caplog.set_level(logging.INFO, logger="atlaso.tasks")
    task, step = _new_task(db)
    caplog.clear()
    task.status = "running"
    db.flush()

    with pytest.raises(RuntimeError, match="abort savepoint"):
        with db.begin_nested():
            step.status = "failed"
            db.flush()
            raise RuntimeError("abort savepoint")

    assert caplog.text == ""
    db.commit()

    assert caplog.text.count("component=task stage=started") == 1
    assert "component=network stage=completed outcome=failed" not in caplog.text
    assert step.status == "pending"


def test_no_progress_noise_cancellation_cleanup_and_bounded_events(db):
    """Progress polls stay quiet while meaningful dispositions survive bounded retention.

    Args:
        db: Isolated producer.
    """
    task, step = _new_task(db)
    task.status = step.status = "running"
    db.commit()
    before = _state(db, task)["important_events"]
    for percent in range(15):
        task.progress_percent = percent
        db.commit()
    assert _state(db, task)["important_events"] == before
    task.cancel_requested_at = utcnow()
    task.cancel_outcome = "requested"
    db.commit()
    requested_events = _state(db, task)["important_events"]
    assert any(e["stage"] == "cancellation" and e["outcome"] == "running"
               and e["reason"] == "cancelled" and e["severity"] == "WARNING"
               for e in requested_events)
    task.cancel_outcome = "cleanup-required"
    task.result = '{"state":"cleanup-required"}'
    db.commit()
    pending_events = _state(db, task)["important_events"]
    assert any(e["stage"] == "cancellation" and e["outcome"] == "running"
               and e["reason"] == "cleanup_required" and e["severity"] == "WARNING"
               for e in pending_events)
    assert any(e["stage"] == "cleanup" and e["outcome"] == "partial"
               and e["severity"] == "WARNING" for e in pending_events)
    for i in range(90):
        step.status = "running" if i % 2 else "succeeded"
        db.commit()
    state = _state(db, task)
    assert len(state["important_events"]) == 64
    assert state["important_events_omitted"] > 0
    assert any(e["reason"] == "cleanup_required" for e in state["important_events"])
    task.status = "cancelled"
    step.status = "cancelled"
    task.cancel_completed_at = utcnow()
    task.cancel_outcome = "confirmed"
    db.commit()
    confirmed_events = _state(db, task)["important_events"]
    assert any(e["component"] == "task" and e["stage"] == "completed"
               and e["outcome"] == "cancelled" and e["severity"] == "INFO"
               for e in confirmed_events)
    assert any(e["component"] == "network" and e["stage"] == "completed"
               and e["outcome"] == "cancelled" and e["severity"] == "INFO"
               for e in confirmed_events)
    assert any(e["stage"] == "cancellation" and e["outcome"] == "cancelled"
               and e["severity"] == "INFO" for e in confirmed_events)


@pytest.mark.parametrize(("status", "expected_severity"), [("succeeded", "INFO"), ("failed", "ERROR")])
def test_completion_won_keeps_actual_terminal_outcome_severity(db, status, expected_severity):
    """Cancellation completion-won records the task's actual terminal result.

    Args:
        db: Isolated producer session.
        status: Terminal outcome that won the race.
        expected_severity: Severity matching the actual terminal outcome.
    """
    task, step = _new_task(db)
    task.status = step.status = status
    if status == "failed":
        task.error = step.error = "Synthetic operation failure."
    task.cancel_requested_at = utcnow()
    task.cancel_completed_at = utcnow()
    task.cancel_outcome = "completion-won"
    db.commit()

    events = _state(db, task)["important_events"]
    assert all(validate_event(event) == event for event in events)
    assert any(event["stage"] == "completed" and event["outcome"] == status
               and event["severity"] == expected_severity for event in events)
    assert any(event["stage"] == "cancellation" and event["outcome"] == status
               and event["reason"] == "completion_won" and event["severity"] == expected_severity
               for event in events)


def test_history_retention_reopens_old_cursor_with_explicit_notice(db, monkeypatch):
    """Rotation does not silently skip content behind an old signed cursor.

    Args:
        db: Isolated producer.
        monkeypatch: Bound the retention window for this regression.
    """
    from atlaso.app.services import task_log_history

    monkeypatch.setattr(task_log_history, "RETAINED_CHARS", 512)
    task, _ = _new_task(db)
    cursor = task_history_page(db, task.id)["next_cursor"]
    for i in range(10):
        task_log_history.append_task_log_lines(db, task.id, (f"batch {i} " + "x" * 200,))
        db.commit()
    page = task_history_page(db, task.id, cursor=cursor)
    assert page["reset"]
    assert "retention" in page["notice"]
    assert "batch 9" in page["text"]
    assert "batch 0" not in page["text"]


def test_event_projection_rejects_malformed_and_secret_fields():
    """Diagnostic schemas accept a fixed vocabulary and discard unknown payloads."""
    assert validate_event({"schema": True}) is None
    assert validate_event({"schema": 1, "at": "password=synthetic", "severity": "ERROR"}) is None
    assert {"network", "task", "ntpd"} <= COMPONENTS


def test_legacy_backfill_orders_persisted_times_before_bounded_retention(db, monkeypatch):
    """Initialization dates lifecycle/cancellation evidence from durable columns only.

    Args:
        db: Persistent isolated producer.
        monkeypatch: Bound retained events to exercise chronological eviction.
    """
    from atlaso.app.services import important_task_events

    monkeypatch.setattr(important_task_events, "EVENT_LIMIT", 4)
    engine = db.get_bind()
    times = {
        "queued": datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
        "running_created": datetime(2024, 2, 2, 3, 4, 5, tzinfo=timezone.utc),
        "running_started": datetime(2024, 2, 2, 3, 5, 5, tzinfo=timezone.utc),
        "completed_created": datetime(2024, 3, 2, 3, 4, 5, tzinfo=timezone.utc),
        "completed_started": datetime(2024, 3, 2, 3, 5, 5, tzinfo=timezone.utc),
        "completed_step_one_finished": datetime(2024, 3, 2, 3, 5, 45, tzinfo=timezone.utc),
        "completed_finished": datetime(2024, 3, 2, 3, 7, 5, tzinfo=timezone.utc),
        "cancel_requested": datetime(2024, 3, 2, 3, 5, 30, tzinfo=timezone.utc),
        "cancel_completed": datetime(2024, 3, 2, 3, 6, 30, tzinfo=timezone.utc),
    }
    with engine.begin() as connection:
        for values in [
            {"id": "job_backfill_queued", "type": "test", "created_by": "test", "status": "pending",
             "created_at": times["queued"], "result": "{}"},
            {"id": "job_backfill_running", "type": "test", "created_by": "test", "status": "running",
             "created_at": times["running_created"], "started_at": times["running_started"], "result": "{}"},
            {"id": "job_backfill_complete", "type": "test", "created_by": "test", "status": "succeeded",
             "created_at": times["completed_created"], "started_at": times["completed_started"],
             "finished_at": times["completed_finished"], "cancel_requested_at": times["cancel_requested"],
             "cancel_completed_at": times["cancel_completed"], "cancel_outcome": "completion-won",
             "result": json.dumps({"commands": [{"stage": "execution", "returncode": 0}],
                                   "state": "cleanup-required"})},
        ]:
            connection.execute(Job.__table__.insert().values(**values))
        for values in [
            {"id": "step_backfill_queued", "job_id": "job_backfill_queued", "component_key": "network",
             "label": "Network", "position": 1, "status": "pending", "created_at": times["queued"], "result": "{}"},
            {"id": "step_backfill_running", "job_id": "job_backfill_running", "component_key": "network",
             "label": "Network", "position": 1, "status": "running", "created_at": times["running_created"],
             "started_at": times["running_started"], "result": "{}"},
            {"id": "step_backfill_complete", "job_id": "job_backfill_complete", "component_key": "network",
             "label": "Network", "position": 1, "status": "succeeded", "created_at": times["completed_created"],
             "started_at": times["completed_started"], "finished_at": times["completed_step_one_finished"], "result": "{}"},
            {"id": "step_backfill_ntpd", "job_id": "job_backfill_complete", "component_key": "ntpd",
             "label": "Time service", "position": 2, "status": "succeeded", "created_at": times["completed_created"],
             "started_at": times["completed_started"], "finished_at": times["cancel_completed"], "result": "{}"},
            {"id": "step_backfill_firewall", "job_id": "job_backfill_complete", "component_key": "firewall",
             "label": "Firewall", "position": 3, "status": "succeeded", "created_at": times["completed_created"],
             "started_at": times["completed_started"], "finished_at": datetime(2024, 3, 2, 3, 6, 45, tzinfo=timezone.utc),
             "result": "{}"},
        ]:
            connection.execute(JobStep.__table__.insert().values(**values))

    initialize_task_history(engine)
    db.expire_all()
    expected = {
        "job_backfill_queued": {"task": ("queued", times["queued"]), "network": ("queued", times["queued"])},
        "job_backfill_running": {"task": ("started", times["running_started"]),
                                 "network": ("started", times["running_started"])},
        "job_backfill_complete": {"task": ("completed", times["completed_finished"])},
    }
    for job_id, stages in expected.items():
        events = json.loads(db.get(TaskLogCheckpoint, job_id).state_json)["important_events"]
        for component, (stage, timestamp) in stages.items():
            event = next((event for event in events if event["component"] == component and event["stage"] == stage), None)
            assert event is not None, (job_id, component, events)
            assert datetime.fromisoformat(event["at"]) == timestamp
            assert datetime.fromisoformat(event["at"]).utcoffset().total_seconds() == 0

    completed_state = json.loads(db.get(TaskLogCheckpoint, "job_backfill_complete").state_json)
    ordered = completed_state["important_events"]
    expected_order = [
        ("task", "cancellation", times["cancel_completed"]),
        ("ntpd", "completed", times["cancel_completed"]),
        ("firewall", "completed", datetime(2024, 3, 2, 3, 6, 45, tzinfo=timezone.utc)),
        ("task", "completed", times["completed_finished"]),
    ]
    assert [(event["component"], event["stage"], datetime.fromisoformat(event["at"]))
            for event in ordered] == expected_order
    assert completed_state["important_events_omitted"] == 3  # Two undated projections and oldest retained event.
    history_text = task_history_page(db, "job_backfill_complete")["text"]
    expected_text_order = [
        "component=network stage=completed",
        "component=task stage=cancellation",
        "component=ntpd stage=completed",
        "component=firewall stage=completed",
        "component=task stage=completed",
    ]
    positions = [history_text.index(marker) for marker in expected_text_order]
    assert positions == sorted(positions)
    before = {
        job_id: db.get(TaskLogCheckpoint, job_id).state_json
        for job_id in expected
    }
    initialize_task_history(engine)
    db.expire_all()
    assert {job_id: db.get(TaskLogCheckpoint, job_id).state_json for job_id in expected} == before

    running = db.get(Job, "job_backfill_running")
    running.status = "succeeded"
    live_transition = datetime.now(timezone.utc)
    running.finished_at = times["completed_finished"]
    db.commit()
    latest = json.loads(db.get(TaskLogCheckpoint, running.id).state_json)["important_events"][-1]
    assert datetime.fromisoformat(latest["at"]) >= live_transition
