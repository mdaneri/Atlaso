"""Typed task diagnostics for management-route handoff failures."""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from atlaso.app import ui
from atlaso.app.adapters.system import AdapterResult
from atlaso.app.database import Base
from atlaso.app.models import Job, JobStep, TaskLogCheckpoint, utcnow
from atlaso.app.services.important_task_events import execution_projection
from atlaso.app.services.task_log_history import initialize_task_history
from atlaso.app.ui import adapter_result_to_payload, management_handoff_result_evidence
from atlaso.important_events import (
    failure_reason,
    format_event,
    validate_event,
    validate_route_conflict,
)

ROUTE_CONFLICT = {
    "condition": "same_destination_without_successor",
    "interface": "eth0",
    "family": 4,
    "table": 100,
    "expected": {
        "destination": "0.0.0.0/0",
        "gateway": "192.0.2.1",
        "protocol": "unknown",
        "metric": 2,
    },
    "observed": {
        "destination": "0.0.0.0/0",
        "gateway": "192.0.2.1",
        "protocol": "boot",
        "metric": 100,
    },
}


@pytest.fixture
def db(tmp_path):
    """Create a task-history database with the production capture hooks.

    Args:
        tmp_path: Isolated pytest temporary directory.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'events.db'}")
    Base.metadata.create_all(engine)
    initialize_task_history(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def _state(db, task_id):
    """Read the persisted task checkpoint.

    Args:
        db: Task-history database session.
        task_id: Task checkpoint identifier.
    """
    db.expire_all()
    return json.loads(db.get(TaskLogCheckpoint, task_id).state_json)


def test_route_conflict_is_canonical_and_bounded():
    """Normalize route identity and reject arbitrary helper fields."""
    normalized = validate_route_conflict(ROUTE_CONFLICT)
    assert normalized == ROUTE_CONFLICT
    assert validate_route_conflict({**ROUTE_CONFLICT, "raw_stderr": "untrusted"}) is None
    assert validate_route_conflict({**ROUTE_CONFLICT, "interface": "eth0\nsecret"}) is None
    assert validate_route_conflict({
        **ROUTE_CONFLICT,
        "observed": {**ROUTE_CONFLICT["observed"], "metric": True},
    }) is None


def test_important_event_formats_only_typed_route_context():
    """A route-conflict event carries exact safe fields and no helper prose."""
    event = {
        "schema": 1,
        "at": "2026-10-08T20:00:00+00:00",
        "severity": "ERROR",
        "component": "management_handoff",
        "stage": "execution",
        "outcome": "failed",
        "reason": "management_route_conflict",
        "returncode": 1,
        "route_conflict": ROUTE_CONFLICT,
    }
    safe = validate_event(event)
    assert safe is not None
    rendered = format_event(event)
    assert "condition=same_destination_without_successor" in rendered
    assert "protocol=boot metric=100" in rendered
    assert "secret" not in rendered
    assert validate_event({**event, "reason": "unknown_failure"}) is None


def test_typed_helper_reason_is_used_without_copying_raw_error():
    """The fixed reason code wins over arbitrary raw helper diagnostic text."""
    output = json.dumps({
        "management_handoff": "rolled back",
        "reason_code": "management_route_conflict",
        "route_conflict": ROUTE_CONFLICT,
        "error": "raw failure text with secret=synthetic",
    })
    assert failure_reason(output, 1) == "management_route_conflict"


def test_helper_adapter_propagates_only_valid_route_conflict_fields():
    """The task adapter retains typed cause and drops unsupported route fields."""
    output = json.dumps({
        "management_handoff": "rolled back",
        "reason_code": "management_route_conflict",
        "route_conflict": {**ROUTE_CONFLICT, "private_text": "do not retain"},
        "error": "previous management route conflicts with live domain",
    })
    result = AdapterResult(command=["atlaso-helper", "management-handoff", "apply"],
                           dry_run=False, stderr=output, returncode=1)
    payload = adapter_result_to_payload(result)
    evidence = management_handoff_result_evidence(result)
    assert payload["reason_code"] == "management_route_conflict"
    assert evidence["reason_code"] == "management_route_conflict"
    assert evidence.get("route_conflict") is None


@pytest.mark.parametrize("returncode,verb,conflict,expected", [
    (2, "apply", ROUTE_CONFLICT, True),
    (2, "apply", {**ROUTE_CONFLICT, "private_text": "synthetic"}, False),
    (0, "apply", ROUTE_CONFLICT, False),
    (2, "validate", ROUTE_CONFLICT, False),
])
def test_ordinary_network_adapter_retains_only_failed_execution_route_pairs(returncode, verb, conflict, expected):
    """Only strictly validated failed execution evidence reaches event projections.

    Args:
        returncode: Helper exit code.
        verb: Helper operation stage.
        conflict: Candidate typed route-conflict record.
        expected: Whether route context may be retained.
    """
    stderr = json.dumps({"network": "apply failed", "reason_code": "management_route_conflict",
                         "error": "previous management route conflicts with live domain",
                         "route_conflict": conflict, "private_text": "synthetic"})
    result = AdapterResult(command=["atlaso-helper", "network", verb], dry_run=False,
                           returncode=returncode, stderr=stderr)
    payload = adapter_result_to_payload(result)
    assert ("route_conflict" in payload) is expected
    projected = execution_projection({"commands": [payload]}, "network")
    assert "synthetic" not in json.dumps(projected)


@pytest.mark.parametrize("rollback_evidence", [{"rolled_back": True}, {"management_handoff": "rolled back"}])
def test_execution_projection_separates_route_failure_from_rollback(rollback_evidence):
    """Original failure, proven rollback, and dependent skip get distinct reasons.

    Args:
        rollback_evidence: Recognized helper rollback evidence shape.
    """
    payload = {
        "reason_code": "management_route_conflict",
        "rollback_proven": True,
        "management_handoff": {
            "reason_code": "management_route_conflict",
            **rollback_evidence,
        },
        "commands": [{
            "stage": "execution",
            "returncode": 1,
            "reason_code": "management_route_conflict",
            "route_conflict": ROUTE_CONFLICT,
            "stderr": "raw failure text with secret=synthetic",
        }],
    }
    events = execution_projection(payload, "network")
    assert events[0]["reason"] == "management_route_conflict"
    assert events[0]["route_conflict"]["observed"]["protocol"] == "boot"
    rollback_events = execution_projection(payload, "task")
    assert rollback_events[1] == {
        "component": "task",
        "stage": "rollback",
        "outcome": "succeeded",
        "reason": "dependent_work_rolled_back",
        "returncode": 0,
    }
    assert len(events) == 1
    payload["rollback_proven"] = False
    assert not any(event["stage"] == "rollback" and event["outcome"] == "succeeded"
                   for event in execution_projection(payload, "task"))


def test_task_events_propagate_route_failure_rollback_and_dependent_skip(db):
    """Task and component events retain typed cause and distinct dispositions.

    Args:
        db: Task-history database session with capture hooks.
    """
    task = Job(id="job_934events1234", type="appliance-apply", created_by="console:root",
               status="running", started_at=utcnow(), result="{}")
    network = JobStep(id=f"{task.id}:network", job=task, component_key="network", label="Network",
                      position=1, status="running")
    firewall = JobStep(id=f"{task.id}:firewall", job=task, component_key="firewall", label="Firewall",
                       position=2, status="running")
    db.add_all([task, network, firewall])
    db.commit()

    command = {
        "stage": "execution",
        "returncode": 1,
        "reason_code": "management_route_conflict",
        "route_conflict": ROUTE_CONFLICT,
        "stderr": "raw failure text with secret=synthetic",
    }
    handoff = {"reason_code": "management_route_conflict", "rolled_back": True}
    network.status = "failed"
    network.error = "Management route conflict."
    network.result = json.dumps({"reason_code": "management_route_conflict", "management_handoff": handoff,
                                 "commands": [command]})
    firewall.status = "skipped"
    firewall.error = "Skipped because the management handoff failed and rolled back."
    firewall.result = json.dumps({"reason_code": "dependent_work_skipped"})
    task.status = "failed"
    task.error = "Management handoff failed; previous path rolled back."
    task.result = json.dumps({"reason_code": "management_route_conflict", "management_handoff": True,
                              "management_handoff_failure": handoff,
                              "rollback_proven": True, "commands": [command]})
    task.finished_at = network.finished_at = firewall.finished_at = utcnow()
    db.commit()

    events = _state(db, task.id)["important_events"]
    assert any(event["component"] == "task" and event["reason"] == "management_route_conflict"
               and event["outcome"] == "failed" for event in events)
    route_event = next(event for event in events if event["component"] == "network"
                       and event["stage"] == "execution")
    assert route_event["reason"] == "management_route_conflict"
    assert route_event["route_conflict"]["observed"]["protocol"] == "boot"
    assert any(event["component"] == "task" and event["stage"] == "rollback"
               and event["reason"] == "dependent_work_rolled_back" for event in events)
    assert any(event["component"] == "firewall" and event["outcome"] == "skipped"
               and event["reason"] == "dependent_work_skipped" for event in events)
    assert "synthetic" not in json.dumps(events)

    # A later status/error-only flush intentionally does not reread result JSON.
    # It must retain typed causes rather than emitting unknown/none replacements.
    task.error = "Updated recovery summary."
    db.commit()
    snapshots = _state(db, task.id)["important_event_state"]
    assert snapshots["task"]["reason"] == "management_route_conflict"
    assert snapshots["step:1"]["reason"] == "management_route_conflict"
    assert snapshots["step:2"]["reason"] == "dependent_work_skipped"


@pytest.mark.parametrize("bad", [None, "bad", {"condition": "raw text"}])
def test_route_conflict_validator_rejects_incomplete_records(bad):
    """Reject incomplete route-conflict evidence.

    Args:
        bad: Invalid route-conflict record.
    """
    assert validate_route_conflict(bad) is None


@pytest.mark.parametrize("typed", [True, False])
def test_execute_management_handoff_keeps_root_failure_and_bundled_disposition(monkeypatch, tmp_path, typed):
    """The real handoff coordinator preserves the helper cause across recovery.

    Args:
        monkeypatch: Scoped dependency replacement fixture.
        tmp_path: Isolated staging directory.
        typed: Whether the helper supplies typed diagnostics.
    """
    monkeypatch.setattr(ui, "acquire_network_objects_write_lock", lambda _db: None)
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db: {"appliance_settings": {}})
    monkeypatch.setattr(ui, "network_config_with_removed_vlans", lambda preview, _removed: preview)
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda target, _content: str(target))
    monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(tmp_path / "ca.json"))
    monkeypatch.setattr(ui, "MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH", str(tmp_path / "manifest.json"))

    class RouteConflictAdapter:
        """Return the helper's typed route conflict and a no-op recovery proof."""

        dry_run = False

        def validate_management_handoff(self, manifest_path):
            """Return successful manifest validation.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            return AdapterResult(command=["atlaso-helper", "management-handoff", "validate", manifest_path],
                                 dry_run=False, returncode=0)

        def apply_management_handoff(self, manifest_path):
            """Return the route-conflict response.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            evidence = {
                "management_handoff": "rolled back",
                "reason_code": "management_route_conflict",
                "route_conflict": ROUTE_CONFLICT,
                "failing_layer": "network",
                "error": "previous management route conflicts with live domain",
            }
            if not typed:
                evidence.pop("reason_code")
                evidence.pop("route_conflict")
            return AdapterResult(command=["atlaso-helper", "management-handoff", "apply", manifest_path],
                                 dry_run=False, stderr=json.dumps(evidence), returncode=1)

        def recover_management_handoff(self):
            return AdapterResult(command=["atlaso-helper", "management-handoff", "recover"], dry_run=False,
                                 stdout=json.dumps({"management_handoff": "no interrupted transaction"}),
                                 returncode=0)

    defaults = {
        "label": "Handoff component", "summary": "Apply component.", "validation_errors": [],
        "validation_warnings": [], "config_path": "", "config_preview": "", "config_diff": "",
        "raw_config_preview": "", "context": {},
    }
    units = {unit_id: {**defaults, "id": unit_id} for unit_id in ui.MANAGEMENT_HANDOFF_UNIT_IDS}
    units["network"].update(previous_management_paths=[], removed_vlan_interfaces=[])
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": [], "ca_profiles": []}

    group, results = ui.execute_management_handoff(
        units, job_id="job_934route1234", adapter=RouteConflictAdapter(), db=object(),
    )

    by_id = {result["unit_id"]: result for result in results}
    assert group["success"] is False
    assert group["rollback_proven"] is True
    assert group["reason_code"] == "management_route_conflict"
    if typed:
        assert group["management_handoff"]["reason_code"] == "management_route_conflict"
        assert "rolled_back" not in group["management_handoff"]
        assert execution_projection(group, "task")[-1] == {
            "component": "task", "stage": "rollback", "outcome": "succeeded",
            "reason": "dependent_work_rolled_back", "returncode": 0,
        }
    assert group["management_handoff"]["recovery"]["management_handoff"] == "no interrupted transaction"
    assert by_id["network"]["reason_code"] == "management_route_conflict"
    assert by_id["firewall"]["reason_code"] == "dependent_work_rolled_back"
    assert by_id["network"]["commands"][1]["reason_code"] == "management_route_conflict"
    if typed:
        assert by_id["network"]["commands"][1]["route_conflict"] == ROUTE_CONFLICT
    else:
        assert "route_conflict" not in by_id["network"]["commands"][1]
    assert by_id["firewall"]["commands"] == []
