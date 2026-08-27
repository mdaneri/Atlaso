"""Test appliance update behavior."""

import importlib.machinery
import importlib.util
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from atlaso.app.adapters.system import AdapterResult


def login(client):
    """Return login.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return csrf


def csrf_from_page(page_text: str) -> str:
    """Return csrf from page.

    Args:
        page_text: Page text supplied to the test scenario.
    """
    return page_text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def load_helper_module():
    """Return helper module."""
    helper_path = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"
    loader = importlib.machinery.SourceFileLoader("atlaso_helper_update", str(helper_path))
    spec = importlib.util.spec_from_loader("atlaso_helper_update", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_reserved_psgallery_source_requires_the_canonical_endpoint():
    """Reject case-variant reserved names paired with custom endpoints."""
    from atlaso.app.models import UpdateSource
    from atlaso.app.services.update_sources import validate_update_source

    invalid = UpdateSource(
        kind="powershell",
        name="psgallery",
        url="https://packages.example.test/api/v2",
        priority=50,
        settings_json="{}",
    )
    valid = UpdateSource(
        kind="powershell",
        name="pSgAlLeRy",
        url="https://www.powershellgallery.com/api/v2/",
        priority=50,
        settings_json="{}",
    )

    errors = validate_update_source(invalid)

    assert errors == [
        "PSGallery is reserved for the built-in PowerShell Gallery. "
        "Use https://www.powershellgallery.com/api/v2, or choose a different repository name for a custom endpoint."
    ]
    assert validate_update_source(valid) == []


def test_update_evidence_state_distinguishes_normal_absence_and_read_only_checks(tmp_path):
    """Keep source, fresh packaged, and read-only states neutral without fabricating evidence.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """
    from atlaso.app.services.appliance_update import appliance_update_evidence_state

    missing_info = tmp_path / "update-info"
    missing_finalizer = tmp_path / "finalizer.json"
    source_state = appliance_update_evidence_state(
        update_info_path=str(missing_info), finalizer_path=str(missing_finalizer)
    )
    packaged_state = appliance_update_evidence_state(
        update_info_path=str(missing_info), finalizer_path=str(missing_finalizer)
    )
    check_state = appliance_update_evidence_state(
        update_info_path=str(missing_info), finalizer_path=str(missing_finalizer)
    )

    assert source_state["state"] == "not_recorded"
    assert packaged_state["label"] == "Not recorded"
    assert check_state["state"] == "not_recorded"
    assert "No such file" not in check_state["message"]


def test_update_evidence_state_validates_available_and_actionable_records(tmp_path):
    """Expose valid evidence and flag missing, unreadable, malformed, or inconsistent records.

    Args:
        tmp_path: Temporary directory provided by pytest.
    """
    from atlaso.app.services.appliance_update import appliance_update_evidence_state

    info_path = tmp_path / "update-info"
    finalizer_path = tmp_path / "finalizer.json"
    aggregate = {
        "status": "succeeded",
        "job_id": "job-3",
        "applied": {"photon_os": {}},
        "attempted": {"photon_os": {}},
        "commands": [],
        "reboot_recommended": False,
        "restart_required": False,
        "selected_streams": ["photon_os"],
        "finished_at": "2026-08-22T20:00:01+00:00",
        "finalizer_status_path": "",
    }
    finalizer = {
        "status": "succeeded",
        "job_id": "job-3",
        "release": "0.9.186",
        "candidate_version": "0.9.186",
        "compatibility": {},
        "rolled_back": False,
        "commands": [],
        "finished_at": "2026-08-22T20:00:00+00:00",
    }
    expected_missing = appliance_update_evidence_state(
        qualifying_install_expected=True,
        update_info_path=str(info_path),
        finalizer_path=str(finalizer_path),
    )
    assert expected_missing["state"] == "needs_attention"
    assert "No such file" not in expected_missing["message"]

    info_path.write_text(json.dumps(aggregate), encoding="utf-8")
    available = appliance_update_evidence_state(
        qualifying_install_expected=True,
        update_info_path=str(info_path),
        finalizer_path=str(finalizer_path),
    )
    assert available["state"] == "available"
    assert available["label"] == "Available"
    assert available["content"].startswith("{")

    matching_task = appliance_update_evidence_state(
        qualifying_install_job_id="job-3",
        qualifying_install_stream="photon_os",
        qualifying_install_started_at=datetime(2026, 8, 22, 19, 59, tzinfo=timezone.utc),
        update_info_path=str(info_path),
        finalizer_path=str(finalizer_path),
    )
    assert matching_task["state"] == "available"

    later_stream = appliance_update_evidence_state(
        qualifying_install_job_id="job-3",
        qualifying_install_stream="powershell_modules",
        qualifying_install_started_at=datetime(2026, 8, 22, 20, 0, 2, tzinfo=timezone.utc),
        update_info_path=str(info_path),
        finalizer_path=str(finalizer_path),
    )
    assert later_stream["state"] == "needs_attention"

    stale_task = appliance_update_evidence_state(
        qualifying_install_job_id="job-4",
        qualifying_install_started_at=datetime(2026, 8, 22, 20, 0, 2, tzinfo=timezone.utc),
        update_info_path=str(info_path),
        finalizer_path=str(finalizer_path),
    )
    assert stale_task["state"] == "needs_attention"

    legacy_aggregate = dict(aggregate)
    legacy_aggregate.pop("job_id")
    legacy_aggregate.pop("selected_streams")
    info_path.write_text(json.dumps(legacy_aggregate), encoding="utf-8")
    stale_legacy_task = appliance_update_evidence_state(
        qualifying_install_job_id="job-legacy-latest",
        qualifying_install_started_at=datetime(2026, 8, 22, 20, 0, 2, tzinfo=timezone.utc),
        update_info_path=str(info_path),
        finalizer_path=str(finalizer_path),
    )
    assert stale_legacy_task["state"] == "needs_attention"

    current_legacy_task = appliance_update_evidence_state(
        qualifying_install_job_id="job-legacy-current",
        qualifying_install_started_at=datetime(2026, 8, 22, 19, 59, tzinfo=timezone.utc),
        update_info_path=str(info_path),
        finalizer_path=str(finalizer_path),
    )
    assert current_legacy_task["state"] == "available"

    legacy_finalizer = {
        "status": "succeeded",
        "job_id": "job-legacy",
        "release": "0.9.185",
        "git_commit": "a" * 40,
        "bundle_sha256": "b" * 64,
        "release_manifest_sha256": "c" * 64,
        "rolled_back": False,
        "service_health": True,
    }
    info_path.write_text(json.dumps(legacy_finalizer), encoding="utf-8")
    finalizer_path.write_text(json.dumps(legacy_finalizer), encoding="utf-8")
    legacy_available = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert legacy_available["state"] == "available"

    unmarked_legacy = dict(legacy_finalizer)
    unmarked_legacy.pop("service_health")
    info_path.write_text(json.dumps(unmarked_legacy), encoding="utf-8")
    finalizer_path.write_text(json.dumps(unmarked_legacy), encoding="utf-8")
    invalid_legacy = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert invalid_legacy["state"] == "needs_attention"

    rollback_finalizer = {**finalizer, "status": "failed", "rolled_back": True}
    rollback = {
        "status": "failed",
        "success": False,
        "release": "0.9.186",
        "rolled_back": True,
        "host_facing_ready": True,
        "failure_layer": "candidate_health",
        "rollback_health": {"openapi": {"success": True}},
        "rollback_failures": [],
        "error": "Candidate readiness failed and the previous release was restored.",
        "finished_at": "2026-08-22T20:00:01+00:00",
    }
    info_path.write_text(json.dumps(rollback), encoding="utf-8")
    finalizer_path.write_text(json.dumps(rollback_finalizer), encoding="utf-8")
    rollback_available = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert rollback_available["state"] == "available"

    info_path.write_text(json.dumps({**rollback, "release": "0.9.184"}), encoding="utf-8")
    rollback_mismatch = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert rollback_mismatch["state"] == "needs_attention"
    finalizer_path.unlink()

    for incompatible in (
        {"status": "arbitrary"},
        {"status": 123},
        {"status": "succeeded", "commands": []},
        {**aggregate, "reboot_recommended": "false"},
        {**aggregate, "selected_streams": ["unknown"]},
        {**aggregate, "selected_streams": ["atlaso_release"]},
        {**aggregate, "finalizer_status_path": str(finalizer_path)},
    ):
        info_path.write_text(json.dumps(incompatible), encoding="utf-8")
        incompatible_state = appliance_update_evidence_state(
            update_info_path=str(info_path), finalizer_path=str(finalizer_path)
        )
        assert incompatible_state["state"] == "needs_attention"

    info_path.write_text("not-json", encoding="utf-8")
    malformed = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert malformed["state"] == "needs_attention"

    unreadable_path = tmp_path / "update-info-directory"
    unreadable_path.mkdir()
    unreadable = appliance_update_evidence_state(
        update_info_path=str(unreadable_path), finalizer_path=str(finalizer_path)
    )
    assert unreadable["state"] == "needs_attention"

    invalid_utf8_path = tmp_path / "update-info-invalid-utf8"
    invalid_utf8_path.write_bytes(b'\xff{"status":"succeeded"}')
    invalid_utf8 = appliance_update_evidence_state(
        update_info_path=str(invalid_utf8_path), finalizer_path=str(finalizer_path)
    )
    assert invalid_utf8["state"] == "needs_attention"

    info_path.write_text(json.dumps({**finalizer, "job_id": "job-1"}), encoding="utf-8")
    missing_paired_finalizer = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert missing_paired_finalizer["state"] == "needs_attention"

    finalizer_path.write_text(json.dumps({**finalizer, "job_id": "job-2"}), encoding="utf-8")
    inconsistent = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert inconsistent["state"] == "needs_attention"
    assert "inconsistent" in inconsistent["message"]

    info_path.write_text(
        json.dumps({**finalizer, "commands": [{"success": True, "layer": "old"}]}),
        encoding="utf-8",
    )
    finalizer_path.write_text(
        json.dumps({**finalizer, "commands": [{"success": True, "layer": "recovered"}]}),
        encoding="utf-8",
    )
    stale_direct_finalizer = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert stale_direct_finalizer["state"] == "needs_attention"

    info_path.write_text(
        json.dumps({**finalizer, "status": "failed", "job_id": "job-2"}),
        encoding="utf-8",
    )
    inconsistent_status = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert inconsistent_status["state"] == "needs_attention"

    finalizer_path.write_text(json.dumps(finalizer), encoding="utf-8")
    info_path.write_text(
        json.dumps(
            {
                **aggregate,
                "selected_streams": ["atlaso_release"],
                "finalizer_status_path": str(finalizer_path),
            }
        ),
        encoding="utf-8",
    )
    bound = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert bound["state"] == "available"

    info_path.write_text(
        json.dumps(
            {
                **aggregate,
                "selected_streams": ["atlaso_release"],
                "finished_at": "2026-08-22T19:59:59+00:00",
                "finalizer_status_path": str(finalizer_path),
            }
        ),
        encoding="utf-8",
    )
    stale = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert stale["state"] == "needs_attention"

    info_path.write_text(
        json.dumps(
            {
                **aggregate,
                "selected_streams": ["atlaso_release"],
                "finished_at": "2026-08-22T20:00:01",
                "finalizer_status_path": str(finalizer_path),
            }
        ),
        encoding="utf-8",
    )
    mixed_timezone = appliance_update_evidence_state(
        update_info_path=str(info_path), finalizer_path=str(finalizer_path)
    )
    assert mixed_timezone["state"] == "needs_attention"


def test_update_evidence_panel_accessibility_states(client, monkeypatch):
    """Render neutral evidence without an alert and actionable evidence with one.

    Args:
        client: HTTP test client used to render the management page.
        monkeypatch: Pytest fixture used to replace the evidence projection.
    """
    from atlaso.app import ui

    login(client)
    states = {
        "state": "not_recorded",
        "label": "Not recorded",
        "available": False,
        "content": "",
        "message": "No qualifying update transaction has recorded durable evidence yet.",
    }
    monkeypatch.setattr(ui, "appliance_update_evidence_state", lambda **_kwargs: states)
    neutral = client.get("/ui/management/appliance-update")
    panel = neutral.text.split("<h2>Update transaction evidence</h2>", 1)[1].split("</div>\n    </div>", 1)[0]
    assert "Not recorded" in panel
    assert 'role="alert"' not in panel
    assert "No such file" not in neutral.text

    states.update(
        state="needs_attention",
        label="Needs attention",
        message="Durable update transaction evidence cannot be read. Review the Appliance Update task.",
    )
    actionable = client.get("/ui/management/appliance-update")
    panel = actionable.text.split("<h2>Update transaction evidence</h2>", 1)[1].split("</aside>", 1)[0]
    assert "Needs attention" in panel
    assert 'role="alert"' in panel

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep

    with SessionLocal() as db:
        db.add(
            Job(
                id="job_real_evidence_expected",
                type="appliance-update",
                status="succeeded",
                created_by="admin",
                task_config_json=json.dumps({"mode": "run", "selected_streams": ["atlaso_release"]}),
                result=json.dumps({"dry_run": False, "apply_started": False}),
            )
        )
        db.add(
            JobStep(
                id="job_real_evidence_expected:atlaso_release",
                job_id="job_real_evidence_expected",
                component_key="atlaso_release",
                label="Atlaso release",
                position=0,
                status="succeeded",
                started_at=datetime(2026, 8, 22, 20, 0, tzinfo=timezone.utc),
                result=json.dumps({"apply_started": False}),
            )
        )
        db.commit()
    captured: dict[str, object] = {}

    def capture_expected_state(**kwargs):
        """Capture the bounded durable-task existence projection.

        Args:
            **kwargs: Evidence projection keyword arguments.
        """
        captured.update(kwargs)
        return states

    monkeypatch.setattr(ui, "appliance_update_evidence_state", capture_expected_state)
    client.get("/ui/management/appliance-update")
    assert captured["qualifying_install_job_id"] == ""

    with SessionLocal() as db:
        job = db.get(Job, "job_real_evidence_expected")
        assert job is not None
        job.result = json.dumps({"dry_run": False, "apply_started": True})
        step = db.get(JobStep, "job_real_evidence_expected:atlaso_release")
        assert step is not None
        step.result = json.dumps({"dry_run": False, "apply_started": True})
        db.add(job)
        db.add(step)
        db.commit()
    client.get("/ui/management/appliance-update")
    assert captured["qualifying_install_job_id"] == "job_real_evidence_expected"
    assert captured["qualifying_install_stream"] == "atlaso_release"
    assert isinstance(captured["qualifying_install_started_at"], datetime)

    with SessionLocal() as db:
        job = db.get(Job, "job_real_evidence_expected")
        assert job is not None
        job.result = json.dumps(
            {
                "dry_run": False,
                "commands": [
                    {
                        "command_line": (
                            "/opt/atlaso/bin/atlaso-helper appliance-update apply --real "
                            "/var/lib/atlaso/apply/appliance-update/atlaso-update.json"
                        )
                    }
                ],
            }
        )
        step = db.get(JobStep, "job_real_evidence_expected:atlaso_release")
        assert step is not None
        step.result = job.result
        db.add(job)
        db.add(step)
        db.commit()
    client.get("/ui/management/appliance-update")
    assert captured["qualifying_install_job_id"] == "job_real_evidence_expected"

    with SessionLocal() as db:
        job = db.get(Job, "job_real_evidence_expected")
        assert job is not None
        job.result = json.dumps(
            {
                "dry_run": False,
                "commands": [
                    {
                        "command_line": (
                            "sudo -n /opt/atlaso/bin/atlaso-helper appliance-update apply --real "
                            "/var/lib/atlaso/apply/appliance-update/atlaso-update.json"
                        )
                    }
                ],
            }
        )
        step = db.get(JobStep, "job_real_evidence_expected:atlaso_release")
        assert step is not None
        step.result = job.result
        db.add(job)
        db.add(step)
        db.commit()
    client.get("/ui/management/appliance-update")
    assert captured["qualifying_install_job_id"] == "job_real_evidence_expected"


def test_real_install_marks_evidence_expected_only_after_apply_starts(monkeypatch):
    """Distinguish a failed preflight from an invoked evidence-writing apply helper.

    Args:
        monkeypatch: Pytest fixture used to replace the system adapter and staging path.
    """
    from atlaso.app import ui

    events: list[str] = []

    class PreflightFailingAdapter:
        """Reject the read-only check before apply can start."""

        dry_run = False

        def check_appliance_update_config(self, config_path: str) -> AdapterResult:
            """Reject the read-only preflight.

            Args:
                config_path: Staged Appliance Update manifest path.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-update", "check", config_path],
                dry_run=False,
                stdout="",
                stderr="preflight failed",
                returncode=1,
            )

    class ApplyFailingAdapter:
        """Return a successful check followed by a failed real apply."""

        dry_run = False

        def check_appliance_update_config(self, config_path: str) -> AdapterResult:
            """Accept the read-only preflight.

            Args:
                config_path: Staged Appliance Update manifest path.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-update", "check", config_path],
                dry_run=False,
                stdout='{"checks":{}}',
                stderr="",
                returncode=0,
            )

        def apply_appliance_update_config(self, config_path: str) -> AdapterResult:
            """Fail after the evidence-writing helper is invoked.

            Args:
                config_path: Staged Appliance Update manifest path.
            """
            events.append("apply")
            return AdapterResult(
                command=["atlaso-helper", "appliance-update", "apply", config_path],
                dry_run=False,
                stdout='{"status":"failed"}',
                stderr="apply failed",
                returncode=1,
            )

    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda _path, _preview: "atlaso-update.json")

    monkeypatch.setattr(ui, "SystemAdapter", lambda: PreflightFailingAdapter())
    preflight = ui.execute_appliance_update_job(
        selected_stream_ids=["photon_os"],
        settings={},
        actor="admin",
        mode="run",
    )
    assert preflight["apply_started"] is False

    monkeypatch.setattr(ui, "SystemAdapter", lambda: ApplyFailingAdapter())
    result = ui.execute_appliance_update_job(
        selected_stream_ids=["photon_os"],
        settings={},
        actor="admin",
        mode="run",
        before_apply=lambda: events.append("persist"),
    )
    aggregate = ui.aggregate_appliance_update_results(
        selected_stream_ids=["photon_os"],
        settings={},
        actor="admin",
        mode="run",
        stream_results=[result],
    )

    assert result["apply_started"] is True
    assert aggregate["apply_started"] is True
    assert events == ["persist", "apply"]


def test_worker_persists_apply_started_for_interruption_recovery():
    """Keep durable apply-started evidence when the worker is interrupted."""
    from atlaso.app import ui, worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    job_id = "job_apply_started_interruption"
    with SessionLocal() as db:
        job = Job(
            id=job_id,
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            task_config_json=json.dumps({"mode": "run", "selected_streams": ["photon_os"]}),
            result=json.dumps({"apply_started": False}),
        )
        db.add(job)
        db.flush()
        ui.ensure_appliance_update_job_steps(db, job=job, selected_streams=["photon_os"])
        db.commit()

    worker._mark_appliance_update_apply_started(job_id, "photon_os")

    with SessionLocal() as db:
        job = db.get(Job, job_id)
        step = db.get(JobStep, f"{job_id}:photon_os")
        assert job is not None
        assert step is not None
        assert json.loads(job.result or "{}")["apply_started"] is True
        assert json.loads(step.result or "{}")["apply_started"] is True
        recovered = worker._recovered_appliance_update_step_result(
            job,
            step,
            status=JobStatus.FAILED.value,
            error="The Atlaso worker restarted while this update stream was running.",
        )
        assert recovered["apply_started"] is True


def test_unexpected_parent_failure_terminalizes_incomplete_update_children(client):
    """Preserve terminal children and fail or skip every incomplete selected child.

    Args:
        client: Test client whose fixture initializes the isolated database.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    job_id = "job_terminal_children"
    with SessionLocal() as db:
        job = Job(
            id=job_id,
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            progress_percent=30,
            result="{}",
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=["photon_os", "powershell_modules", "atlaso_release"],
        )
        steps[0].status = JobStatus.SUCCEEDED.value
        steps[0].progress_percent = 100
        steps[0].result = json.dumps({"status": "succeeded", "success": True})
        steps[1].status = JobStatus.RUNNING.value
        steps[1].result = json.dumps({"apply_started": True})
        db.commit()

        worker._fail_job(db, job, RuntimeError("durable completion write failed"))

        persisted = db.execute(
            select(JobStep).where(JobStep.job_id == job_id).order_by(JobStep.position)
        ).scalars().all()
        assert job.status == JobStatus.FAILED.value
        assert [step.status for step in persisted] == [
            JobStatus.SUCCEEDED.value,
            JobStatus.FAILED.value,
            JobStatus.SKIPPED.value,
        ]
        assert json.loads(persisted[0].result)["success"] is True
        assert json.loads(persisted[1].result)["apply_started"] is True
        assert all(step.finished_at is not None for step in persisted[1:])


def seed_available_confirmations(streams: list[str]) -> None:
    """Persist fresh available confirmations for manual-install tests.

    Args:
        streams: Stream identifiers to confirm as available.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.appliance_update import (
        APPLIANCE_UPDATE_AVAILABILITY_KEY,
        empty_update_availability,
        record_update_availability_attempt,
        update_availability_to_json,
        update_stream_configuration_fingerprints,
    )

    with SessionLocal() as db:
        settings = ui.appliance_update_settings(db)
        fingerprints = update_stream_configuration_fingerprints(settings)
        state = empty_update_availability()
        for stream in streams:
            state = record_update_availability_attempt(
                state,
                stream=stream,
                job_id="job-confirmed-check",
                checked_at=datetime.now(timezone.utc),
                fingerprint=fingerprints[stream],
                result={
                    "state": "available",
                    "current": "installed",
                    "target": "available",
                    "change_count": 1,
                    "changes": [{"name": stream, "action": "upgrade"}],
                },
            )
        ui.set_setting_value(
            db,
            APPLIANCE_UPDATE_AVAILABILITY_KEY,
            update_availability_to_json(state),
        )
        db.commit()


def test_availability_preserves_confirmed_update_across_failed_recheck_and_stales_on_change():
    """Preserve prior confirmation while making the failed latest attempt install-blocking."""
    from atlaso.app.services.appliance_update import (
        clear_installed_update_availability,
        empty_update_availability,
        manual_install_gate,
        record_update_availability_attempt,
        update_availability_summary,
        update_stream_configuration_fingerprint,
    )

    settings = {
        "source_definitions": [
            {
                "id": 10,
                "kind": "photon",
                "name": "Photon",
                "url": "https://packages.example.test/photon",
                "enabled": True,
                "validation_status": "valid",
                "settings": {"managed": True},
            }
        ]
    }
    fingerprint = update_stream_configuration_fingerprint("photon_os", settings)
    changes = [
        {"name": f"package-{index}", "current": "1", "target": "2", "action": "upgrade"}
        for index in range(105)
    ]
    state = record_update_availability_attempt(
        empty_update_availability(),
        stream="photon_os",
        job_id="job-success",
        checked_at=datetime(2026, 8, 21, 10, tzinfo=timezone.utc),
        fingerprint=fingerprint,
        result={
            "state": "available",
            "current": "Installed packages",
            "target": "105 updates",
            "change_count": 105,
            "changes": changes,
            "summary": "Photon updates are available.",
        },
    )
    state = record_update_availability_attempt(
        state,
        stream="photon_os",
        job_id="job-failed",
        checked_at=datetime(2026, 8, 21, 11, tzinfo=timezone.utc),
        fingerprint=fingerprint,
        result={
            "state": "failed",
            "remediation": "Synchronize repositories and check Photon OS again.",
        },
    )

    summary = update_availability_summary(state, settings)
    photon = next(row for row in summary["streams"] if row["id"] == "photon_os")
    assert summary["available"] is True
    assert summary["affected_stream_count"] == 1
    assert photon["last_attempt"] == {
        "checked_at": "2026-08-21T11:00:00+00:00",
        "success": False,
        "state": "failed",
        "current": "Installed packages",
        "target": "105 updates",
        "remediation": "Synchronize repositories and check Photon OS again.",
    }
    assert photon["confirmed"]["change_count"] == 105
    assert len(photon["confirmed"]["changes"]) == 20
    assert photon["confirmed"]["details_incomplete"] is True
    assert manual_install_gate(summary, ["photon_os"]) == (
        False,
        "Synchronize repositories and check Photon OS again.",
    )

    changed_settings = json.loads(json.dumps(settings))
    changed_settings["source_definitions"][0]["url"] += "/changed"
    stale = update_availability_summary(state, changed_settings)
    stale_photon = next(row for row in stale["streams"] if row["id"] == "photon_os")
    assert stale["available"] is False
    assert stale_photon["stale"] is True
    assert stale_photon["confirmed"] is None

    retained = clear_installed_update_availability(
        state, successful_streams=["powershell_modules"]
    )
    assert retained["streams"]["photon_os"]["confirmed"]
    cleared = clear_installed_update_availability(
        state, successful_streams=["photon_os"]
    )
    assert "confirmed" not in cleared["streams"]["photon_os"]


def test_availability_summary_marks_visible_change_truncation():
    """Tell operators when the browser projection omits recorded changes."""
    from atlaso.app.services.appliance_update import (
        empty_update_availability,
        record_update_availability_attempt,
        update_availability_summary,
        update_stream_configuration_fingerprint,
    )

    settings = {"photon_source": "configured Photon repositories"}
    fingerprint = update_stream_configuration_fingerprint("photon_os", settings)
    state = record_update_availability_attempt(
        empty_update_availability(),
        stream="photon_os",
        job_id="job-visible-truncation",
        checked_at=datetime(2026, 8, 21, 10, tzinfo=timezone.utc),
        fingerprint=fingerprint,
        result={
            "state": "available",
            "change_count": 21,
            "changes": [
                {"name": f"package-{index}", "action": "upgrade"}
                for index in range(21)
            ],
        },
    )

    assert state["streams"]["photon_os"]["confirmed"]["details_incomplete"] is False
    summary = update_availability_summary(state, settings)
    photon = next(row for row in summary["streams"] if row["id"] == "photon_os")
    assert len(photon["confirmed"]["changes"]) == 20
    assert photon["confirmed"]["details_incomplete"] is True


def test_availability_release_notes_url_is_bounded():
    """Keep the browser projection within the signed release-notes URL limit."""
    from atlaso.app.services.appliance_update import normalized_availability_result
    from atlaso.app.services.release_updates import RELEASE_NOTES_URL_MAX_LENGTH

    prefix = "https://example.test/"
    accepted_url = prefix + "a" * (RELEASE_NOTES_URL_MAX_LENGTH - len(prefix))
    rejected_url = accepted_url + "a"

    assert normalized_availability_result(
        {"state": "available", "release_notes_url": accepted_url}
    )["release_notes_url"] == accepted_url
    assert normalized_availability_result(
        {"state": "available", "release_notes_url": rejected_url}
    )["release_notes_url"] == ""


def test_availability_fingerprint_stales_after_source_credential_revision():
    """Require a fresh check after a source edit such as credential rotation."""
    from atlaso.app.services.appliance_update import (
        empty_update_availability,
        record_update_availability_attempt,
        update_availability_summary,
        update_stream_configuration_fingerprint,
    )

    settings = {
        "source_definitions": [
            {
                "id": 7,
                "kind": "powershell",
                "name": "PrivateGallery",
                "url": "https://packages.example.test/powershell",
                "enabled": True,
                "priority": 20,
                "settings": {"trusted": True},
                "credential_present": True,
                "validation_status": "valid",
                "updated_at": "2026-08-21T12:00:00+00:00",
            },
            {
                "id": 8,
                "kind": "powershell",
                "name": "UnusedGallery",
                "url": "https://unused.example.test/powershell",
                "enabled": True,
                "priority": 30,
                "settings": {"trusted": True},
                "credential_present": True,
                "validation_status": "valid",
                "updated_at": "2026-08-21T12:00:00+00:00",
            },
        ],
        "powershell_modules": [
            {
                "name": "Private.Tools",
                "policy": "latest",
                "target_version": "",
                "repository_name": "PrivateGallery",
            }
        ],
    }
    fingerprint = update_stream_configuration_fingerprint(
        "powershell_modules", settings
    )
    state = record_update_availability_attempt(
        empty_update_availability(),
        stream="powershell_modules",
        job_id="job-before-credential-rotation",
        checked_at=datetime(2026, 8, 21, 12, 5, tzinfo=timezone.utc),
        fingerprint=fingerprint,
        result={"state": "available", "change_count": 1},
    )

    settings["source_definitions"][1]["updated_at"] = (
        "2026-08-21T12:30:00+00:00"
    )
    unchanged = update_availability_summary(state, settings)
    unchanged_powershell = next(
        row for row in unchanged["streams"] if row["id"] == "powershell_modules"
    )
    assert unchanged_powershell["stale"] is False
    assert unchanged_powershell["confirmed"]["update_available"] is True

    settings["source_definitions"][0]["updated_at"] = (
        "2026-08-21T13:00:00+00:00"
    )
    summary = update_availability_summary(state, settings)
    powershell = next(
        row for row in summary["streams"] if row["id"] == "powershell_modules"
    )
    assert powershell["stale"] is True
    assert powershell["confirmed"] is None
    assert summary["available"] is False


def test_update_source_payload_exposes_only_non_secret_revision():
    """Project the source edit revision without exposing encrypted credentials."""
    from atlaso.app.models import UpdateSource
    from atlaso.app.services.update_sources import update_source_payload

    source = UpdateSource(
        id=7,
        kind="powershell",
        name="PrivateGallery",
        url="https://packages.example.test/powershell",
        credential_encrypted="encrypted-credential-material",
        validated_at=datetime(2026, 8, 21, 12, 30, tzinfo=timezone.utc),
        updated_at=datetime(2026, 8, 21, 13, tzinfo=timezone.utc),
    )
    payload = update_source_payload(source)

    assert payload["credential_present"] is True
    assert payload["validated_at"] == "2026-08-21T12:30:00+00:00"
    assert payload["updated_at"] == "2026-08-21T13:00:00+00:00"
    assert "credential_encrypted" not in payload


def test_availability_fingerprint_stales_after_repository_synchronization():
    """Require a fresh check after a repository synchronization succeeds."""
    from atlaso.app.services.appliance_update import (
        empty_update_availability,
        record_update_availability_attempt,
        update_availability_summary,
        update_stream_configuration_fingerprint,
    )

    settings = {
        "source_definitions": [
            {
                "id": 9,
                "kind": "photon",
                "name": "Photon",
                "url": "https://packages.example.test/photon",
                "enabled": True,
                "priority": 10,
                "settings": {"managed": True},
                "credential_present": False,
                "validation_status": "valid",
                "validated_at": "2026-08-21T12:00:00+00:00",
                "updated_at": "2026-08-21T11:00:00+00:00",
            }
        ]
    }
    fingerprint = update_stream_configuration_fingerprint("photon_os", settings)
    state = record_update_availability_attempt(
        empty_update_availability(),
        stream="photon_os",
        job_id="job-before-resynchronization",
        checked_at=datetime(2026, 8, 21, 12, 5, tzinfo=timezone.utc),
        fingerprint=fingerprint,
        result={"state": "available", "change_count": 1},
    )

    settings["source_definitions"][0]["validated_at"] = (
        "2026-08-21T13:00:00+00:00"
    )
    summary = update_availability_summary(state, settings)
    photon = next(row for row in summary["streams"] if row["id"] == "photon_os")

    assert photon["stale"] is True
    assert photon["confirmed"] is None
    assert summary["available"] is False


def test_availability_mixed_stream_results_and_manual_install_gate():
    """Expose mixed results independently and gate all selected streams."""
    from atlaso.app.services.appliance_update import (
        empty_update_availability,
        manual_install_gate,
        record_update_availability_attempt,
        update_availability_summary,
        update_stream_configuration_fingerprints,
    )

    settings = {}
    fingerprints = update_stream_configuration_fingerprints(settings)
    state = empty_update_availability()
    for stream, result in (
        ("photon_os", {"state": "available", "change_count": 2}),
        ("powershell_modules", {"state": "up_to_date"}),
        ("atlaso_release", {"state": "failed", "remediation": "Verify the signed source."}),
    ):
        state = record_update_availability_attempt(
            state,
            stream=stream,
            job_id=f"job-{stream}",
            checked_at=datetime(2026, 8, 21, 12, tzinfo=timezone.utc),
            fingerprint=fingerprints[stream],
            result=result,
        )

    summary = update_availability_summary(state, settings)
    states = {
        row["id"]: row["last_attempt"]["state"] for row in summary["streams"]
    }
    assert states == {
        "photon_os": "available",
        "powershell_modules": "up_to_date",
        "atlaso_release": "failed",
    }
    assert summary["result_summary"] == {
        "pill": "Check failed",
        "pill_class": "error",
        "title": "1 selected update stream needs attention",
        "description": "Successful and failed stream results remain independently visible below.",
    }
    selected_summary = update_availability_summary(
        state, settings, result_streams=["powershell_modules"]
    )
    assert selected_summary["available"] is True
    assert selected_summary["affected_stream_count"] == 1
    assert selected_summary["result_summary"] == {
        "pill": "Up to date",
        "pill_class": "good",
        "title": "The selected streams are current",
        "description": "No installation is needed for the latest confirmed checks.",
    }
    assert manual_install_gate(summary, ["photon_os", "powershell_modules"]) == (
        True,
        "",
    )
    assert manual_install_gate(summary, ["powershell_modules"]) == (
        False,
        "The selected streams are up to date.",
    )
    assert manual_install_gate(summary, ["photon_os", "atlaso_release"]) == (
        False,
        "Verify the signed source.",
    )


def test_scheduled_check_persists_the_configuration_it_actually_used(client):
    """Keep scheduled confirmations current without a browser snapshot.

    Args:
        client: Test application HTTP client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    client.get("/ui/management/login")
    with SessionLocal() as db:
        settings = ui.appliance_update_settings(db)
        job = Job(
            id="job-scheduled-check",
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="automation",
            trigger="schedule",
            task_config_json=json.dumps(
                {"mode": "check", "selected_streams": ["photon_os"]}
            ),
        )
        db.add(job)
        db.commit()
        result = ui.aggregate_appliance_update_results(
            selected_stream_ids=["photon_os"],
            settings=settings,
            actor="automation",
            mode="check",
            stream_results=[
                {
                    "unit_id": "photon_os",
                    "status": JobStatus.SUCCEEDED.value,
                    "success": True,
                    "dry_run": False,
                    "commands": [],
                    "availability": {
                        "state": "available",
                        "current": "1",
                        "target": "2",
                        "change_count": 1,
                    },
                }
            ],
            job_id=job.id,
        )
        ui.complete_appliance_update_task(db, job=job, update_result=result)
        summary = ui.appliance_update_availability_summary(db)

    photon = next(row for row in summary["streams"] if row["id"] == "photon_os")
    assert photon["stale"] is False
    assert photon["confirmed"]["update_available"] is True


def test_dry_run_install_retains_confirmed_availability(client):
    """Keep the update indicator when a dry run records install intent only.

    Args:
        client: Test application HTTP client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    client.get("/ui/management/login")
    seed_available_confirmations(["photon_os"])
    with SessionLocal() as db:
        settings = ui.appliance_update_settings(db)
        job = Job(
            id="job-dry-run-install",
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            trigger="manual",
            task_config_json=json.dumps(
                {
                    "mode": "run",
                    "selected_streams": ["photon_os"],
                    "settings": settings,
                }
            ),
        )
        db.add(job)
        db.commit()
        result = ui.aggregate_appliance_update_results(
            selected_stream_ids=["photon_os"],
            settings=settings,
            actor="admin",
            mode="run",
            stream_results=[
                {
                    "unit_id": "photon_os",
                    "status": JobStatus.SUCCEEDED.value,
                    "success": True,
                    "dry_run": True,
                    "commands": [],
                }
            ],
            job_id=job.id,
        )
        ui.complete_appliance_update_task(db, job=job, update_result=result)
        summary = ui.appliance_update_availability_summary(db)

    photon = next(row for row in summary["streams"] if row["id"] == "photon_os")
    assert photon["confirmed"]["update_available"] is True


def test_no_change_release_does_not_schedule_an_unverified_restart():
    """Verify an already-active release completes without a delayed service restart."""
    from atlaso.app.ui import aggregate_appliance_update_results

    result = aggregate_appliance_update_results(
        selected_stream_ids=["atlaso_release"],
        settings={},
        actor="admin",
        mode="run",
        stream_results=[
            {
                "unit_id": "atlaso_release",
                "status": "succeeded",
                "success": True,
                "dry_run": False,
                "commands": [],
                "release_transaction": {
                    "status": "succeeded",
                    "no_change": True,
                    "active_release_verification": {"success": True},
                },
            }
        ],
        job_id="job-no-change-release",
    )

    assert result["success"] is True
    assert result["release_no_change"] is True
    assert result["release_worker_restarted"] is False
    assert result["restart_after_commit"] is False


def test_release_last_worker_handoff_suppresses_the_photon_delayed_restart():
    """Do not kill the candidate worker after release-last terminal bookkeeping."""
    from atlaso.app.ui import aggregate_appliance_update_results

    result = aggregate_appliance_update_results(
        selected_stream_ids=["photon_os", "atlaso_release"],
        settings={},
        actor="admin",
        mode="run",
        stream_results=[
            {
                "unit_id": "photon_os",
                "status": "succeeded",
                "success": True,
                "dry_run": False,
                "commands": [],
            },
            {
                "unit_id": "atlaso_release",
                "status": "succeeded",
                "success": True,
                "dry_run": False,
                "commands": [],
                "release_transaction": {
                    "status": "succeeded",
                    "worker_restart": {"success": True},
                    "active_release_verification": {"success": True},
                },
            },
        ],
        job_id="job-release-last",
    )

    assert result["success"] is True
    assert result["release_worker_restarted"] is True
    assert result["restart_after_commit"] is False


def test_successful_photon_still_restarts_worker_when_a_later_stream_fails():
    """Restart after Photon changes even when a later selected stream fails."""
    from atlaso.app.ui import aggregate_appliance_update_results

    result = aggregate_appliance_update_results(
        selected_stream_ids=["photon_os", "powershell_modules"],
        settings={},
        actor="admin",
        mode="run",
        stream_results=[
            {"unit_id": "photon_os", "status": "succeeded", "success": True},
            {"unit_id": "powershell_modules", "status": "failed", "success": False},
        ],
        job_id="job-photon-success-module-failure",
    )

    assert result["success"] is False
    assert result["restart_after_commit"] is True


def test_status_recovery_accepts_receipt_before_schedule_flag_commit(
    client,
    monkeypatch,
    tmp_path,
):
    """Finish from an exact receipt after the schedule-flag commit is interrupted.

    Args:
        client: Test application HTTP client.
        monkeypatch: Pytest fixture used to replace recovery paths and effects.
        tmp_path: Temporary directory provided for isolated startup evidence.
    """
    import os

    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    job_id = "job_012345abcdef"
    marker = tmp_path / "appliance-update-status"
    marker.write_text(job_id, encoding="utf-8")
    startup = tmp_path / "worker-startup.json"
    startup.write_text(
        json.dumps(
            {
                "boot_id": "boot-a",
                "pid": os.getpid(),
                "start_ticks": "100",
                "started_at": "2026-08-27T02:00:01+00:00",
            }
        ),
        encoding="utf-8",
    )
    with SessionLocal() as db:
        db.add(
            Job(
                id=job_id,
                type="appliance-update",
                status="succeeded",
                created_by="admin",
                finished_at=datetime(2026, 8, 27, 2, 0, 0),
                result='{"restart_after_commit":true}',
            )
        )
        db.commit()
    published = []
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_STATUS_MARKER_PATH", marker)
    monkeypatch.setattr(worker, "WORKER_STARTUP_STATUS_PATH", startup)
    monkeypatch.setattr(
        worker,
        "_inspect_appliance_update_restart",
        lambda observed_job_id: {
            "job_id": observed_job_id,
            "state": "completed",
            "worker_pid": os.getpid(),
            "worker_boot_id": "boot-a",
            "worker_start_ticks": "100",
            "worker_started_at": "2026-08-27T02:00:01+00:00",
        },
    )
    monkeypatch.setattr(
        worker,
        "_publish_appliance_update_status",
        lambda observed_job_id, *, finish=False: published.append(
            (observed_job_id, finish)
        )
        or True,
    )

    assert worker._reconcile_appliance_update_status_surface() is True
    assert published == [(job_id, True)]


def test_status_recovery_requires_durable_restart_scheduling_proof(
    client,
    monkeypatch,
    tmp_path,
):
    """Reject an unrelated worker restart after the pre-scheduling commit.

    Args:
        client: Test application HTTP client.
        monkeypatch: Pytest fixture used to replace recovery paths and effects.
        tmp_path: Temporary directory provided for isolated startup evidence.
    """
    import os

    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    job_id = "job_012345abcdea"
    marker = tmp_path / "appliance-update-status"
    marker.write_text(job_id, encoding="utf-8")
    startup = tmp_path / "worker-startup.json"
    startup.write_text(
        json.dumps({"pid": os.getpid(), "started_at": "2026-08-27T02:00:01+00:00"}),
        encoding="utf-8",
    )
    with SessionLocal() as db:
        db.add(
            Job(
                id=job_id,
                type="appliance-update",
                status="succeeded",
                created_by="admin",
                finished_at=datetime(2026, 8, 27, 2, 0, 0),
                result='{"restart_after_commit":true}',
            )
        )
        db.commit()
    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_STATUS_MARKER_PATH", marker)
    monkeypatch.setattr(worker, "WORKER_STARTUP_STATUS_PATH", startup)
    monkeypatch.setattr(
        worker,
        "_publish_appliance_update_status",
        lambda *_args, **_kwargs: pytest.fail("status hold must remain active"),
    )

    assert worker._reconcile_appliance_update_status_surface() is False


def test_status_recovery_retries_a_missing_restart_receipt(
    client,
    monkeypatch,
    tmp_path,
):
    """Retry a dispatched all-service restart whose completion proof is absent.

    Args:
        client: Test application HTTP client.
        monkeypatch: Pytest fixture used to replace restart recovery effects.
        tmp_path: Temporary directory provided for worker startup evidence.
    """
    import os

    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    job_id = "job_012345abcdec"
    marker = tmp_path / "appliance-update-status"
    marker.write_text(job_id, encoding="utf-8")
    startup = tmp_path / "worker-startup.json"
    startup.write_text(
        json.dumps(
            {
                "boot_id": "boot-a",
                "pid": os.getpid(),
                "start_ticks": "100",
                "started_at": "2000-01-01T00:00:01+00:00",
            }
        ),
        encoding="utf-8",
    )
    with SessionLocal() as db:
        db.add(
            Job(
                id=job_id,
                type="appliance-update",
                status="failed",
                created_by="admin",
                finished_at=datetime(2000, 1, 1, 0, 0, 0),
                result=json.dumps(
                    {
                        "restart_after_commit": True,
                        "restart_scheduled": True,
                        "config_path": "/var/lib/atlaso/apply/appliance-update/update.json",
                    }
                ),
            )
        )
        db.commit()
    calls = []

    class RetryAdapter:
        """Record a bounded delayed-restart retry."""

        def restart_appliance_after_update(self, config_path: str) -> AdapterResult:
            """Return a successful retry dispatch.

            Args:
                config_path: Staged Appliance Update manifest path.
            """
            calls.append(config_path)
            return AdapterResult(command=["restart-service", config_path], dry_run=False)

    monkeypatch.setattr(worker, "APPLIANCE_UPDATE_STATUS_MARKER_PATH", marker)
    monkeypatch.setattr(worker, "WORKER_STARTUP_STATUS_PATH", startup)
    monkeypatch.setattr(worker, "_inspect_appliance_update_restart", lambda _job_id: None)
    monkeypatch.setattr(worker, "SystemAdapter", RetryAdapter)
    monkeypatch.setattr(
        worker,
        "_publish_appliance_update_status",
        lambda *_args, **_kwargs: pytest.fail("status hold must remain active"),
    )

    assert worker._reconcile_appliance_update_status_surface() is False
    assert worker._reconcile_appliance_update_status_surface() is False
    assert calls == ["/var/lib/atlaso/apply/appliance-update/update.json"]
    with SessionLocal() as db:
        result = json.loads(db.get(Job, job_id).result)
    assert result["restart_recovery_attempts"] == 1


def test_status_recovery_retries_pending_restoration_without_runtime_marker(
    client,
    monkeypatch,
):
    """Retry terminal restoration from durable state when the marker vanished.

    Args:
        client: Test application HTTP client.
        monkeypatch: Pytest fixture used to replace recovery paths and effects.
    """
    from atlaso.app import worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    job_id = "job_012345abcdeb"
    with SessionLocal() as db:
        db.add(
            Job(
                id=job_id,
                type="appliance-update",
                status="failed",
                created_by="admin",
                finished_at=datetime(2026, 8, 27, 2, 0, 0),
                result='{"restart_after_commit":false}',
            )
        )
        db.commit()
    monkeypatch.setattr(
        worker,
        "_inspect_appliance_update_status",
        lambda: {"state": "pending", "task_id": job_id, "terminal": True},
    )
    published = []
    monkeypatch.setattr(
        worker,
        "_publish_appliance_update_status",
        lambda observed_job_id, *, finish=False: published.append(
            (observed_job_id, finish)
        )
        or True,
    )

    assert worker._reconcile_appliance_update_status_surface() is True
    assert published == [(job_id, True)]


def test_restart_scheduling_failure_logs_terminal_update_result(
    client,
    monkeypatch,
):
    """Log an actionable terminal failure when delayed restart scheduling fails.

    Args:
        client: Test application HTTP client.
        monkeypatch: Pytest fixture used to replace restart and logging effects.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    class FailingRestartAdapter:
        """Return a deterministic delayed-restart scheduling failure."""

        def restart_appliance_after_update(self, config_path: str) -> AdapterResult:
            """Return the failed scheduling command result.

            Args:
                config_path: Filesystem path containing the update configuration.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-update", "restart", config_path],
                dry_run=False,
                stdout="",
                stderr="restart scheduling failed",
                returncode=1,
            )

    failures = []
    submissions = []
    monkeypatch.setattr(ui, "SystemAdapter", lambda: FailingRestartAdapter())
    monkeypatch.setattr(
        ui,
        "log_appliance_update_failures",
        lambda job_id, result: failures.append((job_id, result["status"])),
    )
    monkeypatch.setattr(
        ui,
        "log_appliance_update_submission",
        lambda job_id, result: submissions.append((job_id, result["status"])),
    )
    with SessionLocal() as db:
        job = Job(
            id="job_restart_schedule_failure",
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
        )
        db.add(job)
        db.commit()
        result = ui.aggregate_appliance_update_results(
            selected_stream_ids=["photon_os"],
            settings={},
            actor="admin",
            mode="run",
            stream_results=[
                {
                    "unit_id": "photon_os",
                    "status": "succeeded",
                    "success": True,
                    "dry_run": False,
                    "commands": [],
                }
            ],
            job_id=job.id,
        )
        ui.complete_appliance_update_task(db, job=job, update_result=result)
        persisted_result = json.loads(job.result or "{}")

    assert failures == [(job.id, "failed")]
    assert submissions == [(job.id, "failed")]
    assert persisted_result["restart_after_commit"] is True
    assert persisted_result["restart_scheduled"] is False


def test_appliance_update_page_and_dry_run_job(client):
    """Verify that appliance update page and dry run job.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import UpdateSource

    with SessionLocal() as db:
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "atlaso")).scalar_one()
        source.url = "https://updates.example.test/releases"
        db.add(source)
        db.commit()
    seed_available_confirmations(["photon_os", "atlaso_release"])
    page = client.get("/appliance-update")
    assert page.status_code == 200
    assert "Appliance Update" in page.text
    assert "Photon OS" in page.text
    assert "Python Libraries" not in page.text
    assert "PowerShell Modules" in page.text
    assert "Atlaso Release" in page.text
    assert "Check for updates" in page.text
    assert "Install updates" in page.text
    assert (
        "Checking is read-only. Installation runs Photon OS first, PowerShell Modules second, "
        "and Atlaso Release last among the selected streams."
    ) in page.text
    assert 'href="/ui/management/automation"' in page.text
    assert "schedule update checks or installations in Automation" in page.text
    assert 'formaction="/ui/management/appliance-update/check" title="Check the selected streams without installing changes"' in page.text
    assert 'formaction="/ui/management/appliance-update/run" title="Install updates from the selected streams"' in page.text
    assert "https://updates.example.test/releases" in page.text
    assert "channels/&lt;channel&gt;/manifest.json" in page.text
    assert "Recent update tasks" in page.text
    assert "No Appliance Update tasks have been recorded yet." in page.text
    assert "Appliance Update only" in page.text
    assert 'data-task-type="appliance-update"' in page.text
    assert 'data-task-lock-component-filter="true"' in page.text
    assert 'data-task-initial-component-filter=""' in page.text
    assert 'data-task-grid-height="100%"' in page.text
    assert 'id="tasks-table" class="tabulator-shell"' in page.text
    assert 'class="tab-panel active appliance-update-stream-panel"' in page.text
    assert page.text.count("data-appliance-update-shared-history") == 1
    assert page.text.index("data-appliance-update-shared-history") > page.text.index('id="appliance-update-streams"')
    assert "The same task grid used by Tasks" in page.text
    assert "Last Update" not in page.text
    assert 'data-tab-target="appliance-update-streams" aria-controls="appliance-update-streams" aria-selected="true"' in page.text
    assert 'data-tab-target="appliance-update-sources" aria-controls="appliance-update-sources" aria-selected="false"' in page.text
    assert "streams_tab_active" not in page.text
    assert "atlaso-helper appliance-update check" not in page.text
    assert '<span class="status-pill warn" data-appliance-update-result-pill>Updates available</span>' in page.text
    assert "2 selected update streams have changes" in page.text

    csrf = csrf_from_page(page.text)
    response = client.post(
        "/appliance-update/run",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf,
            "selected_streams": ["photon_os", "atlaso_release"],
        },
    )
    assert response.status_code == 202
    submitted = response.json()
    assert submitted["status"] == "pending"
    assert submitted["mode"] == "run"
    assert submitted["selected_streams"] == ["photon_os", "atlaso_release"]
    duplicate = client.post(
        "/appliance-update/check",
        headers={"Accept": "application/json"},
        data={"csrf": csrf, "selected_streams": ["photon_os"]},
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["job_id"] == submitted["job_id"]

    from atlaso.app.models import Job, JobStep
    from atlaso.app.worker import run_worker_once

    assert run_worker_once()

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-update")).scalar_one()
        payload = json.loads(job.result or "{}")
        steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
    assert submitted["job_id"] == job.id
    assert payload["mode"] == "run"
    refreshed_page = client.get("/appliance-update")
    assert refreshed_page.status_code == 200
    assert job.id in refreshed_page.text
    assert 'class="appliance-update-history task-grid-section"' in refreshed_page.text
    assert "Install updates" in refreshed_page.text
    assert "Open full task history" in refreshed_page.text
    assert "appliance-update-task-card" not in refreshed_page.text
    assert payload["dry_run"] is True
    assert [(step.component_key, step.status) for step in steps] == [
        ("photon_os", "succeeded"),
        ("atlaso_release", "succeeded"),
    ]
    assert set(payload["stream_results"]) == {"atlaso_release", "photon_os"}
    task_payload = client.get(f"/tasks/{job.id}/status").json()["task"]
    assert task_payload["type_label"] == "Appliance Update install"
    assert task_payload["result"]["label"] == "Appliance Update install"
    assert all(step["type"] == "appliance-update-step" for step in task_payload["_children"])
    assert all(step["type_label"] == "Update stream" for step in task_payload["_children"])
    command_lines = [" ".join(command["command"]) for command in payload["commands"]]
    assert "atlaso-helper appliance-update check /var/lib/atlaso/apply/appliance-update/atlaso-update.json" in command_lines
    assert "atlaso-helper appliance-update apply /var/lib/atlaso/apply/appliance-update/atlaso-update.json" in command_lines
    assert "atlaso-helper appliance-update restart-service /var/lib/atlaso/apply/appliance-update/atlaso-update.json" in command_lines


def test_install_action_has_server_rendered_fresh_check_reason(client):
    """Show the blocker while retaining server-validated fallback submission.

    Args:
        client: Test application HTTP client.
    """
    login(client)
    page = client.get("/ui/management/appliance-update")
    assert page.status_code == 200
    assert "Check Photon OS successfully before installing it." in page.text
    assert "data-appliance-update-install-action disabled" not in page.text


def test_no_javascript_install_can_submit_valid_subset_from_mixed_results(client):
    """Let the server validate a selected subset when another stream failed.

    Args:
        client: Test application HTTP client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.appliance_update import (
        APPLIANCE_UPDATE_AVAILABILITY_KEY,
        record_update_availability_attempt,
        update_availability_to_json,
        update_stream_configuration_fingerprints,
    )

    login(client)
    seed_available_confirmations(["photon_os"])
    with SessionLocal() as db:
        settings = ui.appliance_update_settings(db)
        fingerprints = update_stream_configuration_fingerprints(settings)
        state = ui.appliance_update_availability_state(db)
        state = record_update_availability_attempt(
            state,
            stream="powershell_modules",
            job_id="job-failed-powershell-check",
            checked_at=datetime.now(timezone.utc),
            fingerprint=fingerprints["powershell_modules"],
            result={
                "state": "failed",
                "remediation": "Synchronize the managed PowerShell repository.",
            },
        )
        ui.set_setting_value(
            db,
            APPLIANCE_UPDATE_AVAILABILITY_KEY,
            update_availability_to_json(state),
        )
        db.commit()

    page = client.get("/ui/management/appliance-update")
    assert page.status_code == 200
    assert "Synchronize the managed PowerShell repository." in page.text
    assert "data-appliance-update-install-action disabled" not in page.text

    response = client.post(
        "/ui/management/appliance-update/run",
        headers={"Accept": "application/json"},
        data={
            "csrf": csrf_from_page(page.text),
            "selected_streams": ["photon_os"],
        },
    )
    assert response.status_code == 202
    assert response.json()["selected_streams"] == ["photon_os"]


def test_unsynchronized_stream_is_accessibly_blocked_with_direct_remediation(client):
    """Render repository readiness as a non-selectable prerequisite state.

    Args:
        client: Test application HTTP client.
    """
    login(client)
    page = client.get("/ui/management/appliance-update")
    assert page.status_code == 200
    powershell_input = page.text.split('value="powershell_modules"', 1)[1].split(">", 1)[0]
    assert "disabled" in powershell_input
    assert 'aria-describedby="appliance-update-source-reason-powershell_modules"' in powershell_input
    assert 'data-appliance-update-source-sync-ready="false"' in powershell_input
    assert 'data-appliance-update-source-kind="powershell"' in powershell_input
    assert "Repository setup required" in page.text
    assert "Synchronize repositories for PSGallery" in page.text
    assert 'data-appliance-update-source-remediation' in page.text
    assert ">Open Update Sources</button>" in page.text
    stylesheet = (
        Path(__file__).resolve().parents[1] / "atlaso" / "app" / "static" / "app.css"
    ).read_text(encoding="utf-8")
    blocked_card_rule = stylesheet.split(
        ".update-stream-card.repository-setup-required {", 1
    )[1].split("}", 1)[0]
    blocked_text_rule = stylesheet.split(
        ".update-stream-card.repository-setup-required > .apply-unit-select,", 1
    )[1].split("}", 1)[0]
    assert "background: #fff9ed;" in blocked_card_rule
    assert "color: var(--text);" in blocked_text_rule
    assert "opacity:" not in blocked_card_rule + blocked_text_rule


def test_source_readiness_bounds_repository_details(client, monkeypatch):
    """Bound repository readiness details while preserving an omitted count.

    Args:
        client: Test application HTTP client.
        monkeypatch: Pytest fixture used to replace repository discovery.
    """
    from atlaso.app import ui

    repository_names = [f"Gallery{index:02d}" for index in range(10)]
    monkeypatch.setattr(
        ui,
        "unsynchronized_powershell_repositories",
        lambda _settings: repository_names,
    )
    login(client)

    payload = client.get("/ui/management/appliance-update/availability").json()
    stream = next(
        row for row in payload["streams"] if row["id"] == "powershell_modules"
    )
    readiness = stream["source_sync"]
    assert readiness["repositories"] == repository_names[:6]
    assert readiness["repository_count"] == 10
    assert readiness["repositories_omitted"] == 4
    assert "Gallery05, and 4 more repositories" in readiness["reason"]
    assert "Gallery06" not in readiness["reason"]

    page = client.get("/ui/management/appliance-update")
    assert "Gallery05, and 4 more repositories" in page.text
    assert "Gallery06" not in page.text


def test_blocked_streams_do_not_contribute_to_global_availability(client):
    """Count confirmed updates only when their source prerequisite is ready.

    Args:
        client: Test application HTTP client.
    """
    login(client)
    seed_available_confirmations(["powershell_modules"])

    blocked_only = client.get(
        "/ui/management/appliance-update/availability"
    ).json()
    assert blocked_only["available"] is False
    assert blocked_only["affected_stream_count"] == 0

    seed_available_confirmations(["powershell_modules", "atlaso_release"])
    mixed = client.get("/ui/management/appliance-update/availability").json()
    streams = {stream["id"]: stream for stream in mixed["streams"]}
    assert streams["powershell_modules"]["confirmed"]["update_available"] is True
    assert streams["powershell_modules"]["source_sync"]["ready"] is False
    assert streams["atlaso_release"]["source_sync"]["ready"] is True
    assert mixed["available"] is True
    assert mixed["affected_stream_count"] == 1


def test_forged_unsynchronized_stream_is_rejected_for_check_and_install(client):
    """Reject blocked stream identifiers at the server admission boundary.

    Args:
        client: Test application HTTP client.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/ui/management/appliance-update")
    csrf = csrf_from_page(page.text)
    for route in ("check", "run"):
        response = client.post(
            f"/ui/management/appliance-update/{route}",
            headers={"Accept": "application/json"},
            data={"csrf": csrf, "selected_streams": ["powershell_modules"]},
        )
        assert response.status_code == 422
        assert "Synchronize PowerShell repository PSGallery" in response.json()["detail"]
    fallback = client.post(
        "/ui/management/appliance-update/check",
        data={"csrf": csrf, "selected_streams": ["powershell_modules"]},
    )
    assert fallback.status_code == 422
    assert "data-appliance-update-check-action disabled" in fallback.text
    assert "data-appliance-update-install-action disabled" in fallback.text
    assert "Select a ready update stream. Repository setup is required for PowerShell Modules." in fallback.text
    with SessionLocal() as db:
        assert db.execute(select(Job).where(Job.type == "appliance-update")).scalars().all() == []


def test_source_readiness_projects_synchronizing_and_failed_states(client):
    """Expose active and failed synchronization guidance without secret output.

    Args:
        client: Test application HTTP client.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, UpdateSource

    login(client)
    with SessionLocal() as db:
        job = Job(
            id="job_source_sync_active",
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            task_config_json=json.dumps({"mode": "source_sync", "selected_streams": []}),
            result=json.dumps({"mode": "source_sync", "status": "running"}),
        )
        db.add(job)
        db.commit()
    payload = client.get("/ui/management/appliance-update/availability").json()
    streams = {stream["id"]: stream for stream in payload["streams"]}
    assert streams["powershell_modules"]["source_sync"]["state"] == "synchronizing"
    assert "in progress for PSGallery" in streams["powershell_modules"]["source_sync"]["reason"]

    with SessionLocal() as db:
        job = db.get(Job, "job_source_sync_active")
        job.status = JobStatus.FAILED.value
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "powershell")).scalar_one()
        source.validation_status = "invalid"
        source.validation_message = "Source synchronization failed. Review the task output."
        db.add_all([job, source])
        db.commit()
    payload = client.get("/ui/management/appliance-update/availability").json()
    streams = {stream["id"]: stream for stream in payload["streams"]}
    failed = streams["powershell_modules"]["source_sync"]
    assert failed["state"] == "failed"
    assert "correct the reported repository problem" in failed["reason"]
    assert "secret" not in failed["reason"].lower()


def test_successful_sync_clears_prerequisite_failure_to_check_required(client):
    """Replace the obsolete prerequisite failure when synchronization becomes ready.

    Args:
        client: Test application HTTP client.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import UpdateSource
    from atlaso.app.services.appliance_update import (
        APPLIANCE_UPDATE_AVAILABILITY_KEY,
        record_update_availability_attempt,
        update_availability_to_json,
        update_stream_configuration_fingerprints,
    )

    login(client)
    with SessionLocal() as db:
        settings = ui.appliance_update_settings(db)
        state = record_update_availability_attempt(
            ui.appliance_update_availability_state(db),
            stream="powershell_modules",
            job_id="job_old_prerequisite_failure",
            checked_at=datetime.now(timezone.utc),
            fingerprint=update_stream_configuration_fingerprints(settings)["powershell_modules"],
            result={
                "state": "failed",
                "remediation": "Synchronize repositories for PSGallery and check PowerShell Modules again.",
            },
        )
        ui.set_setting_value(db, APPLIANCE_UPDATE_AVAILABILITY_KEY, update_availability_to_json(state))
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "powershell")).scalar_one()
        source.validation_status = "valid"
        source.validation_message = "Repository synchronized with its appliance package client."
        source.validated_at = datetime.now(timezone.utc)
        db.add(source)
        db.commit()

    payload = client.get("/ui/management/appliance-update/availability").json()
    powershell = next(stream for stream in payload["streams"] if stream["id"] == "powershell_modules")
    assert powershell["source_sync"]["ready"] is True
    assert powershell["check_required"] is True
    assert powershell["last_attempt"]["state"] == ""
    page = client.get("/ui/management/appliance-update")
    assert "Repository setup completed" in page.text
    assert "Check required" in page.text
    assert "job_old_prerequisite_failure" not in page.text


def test_global_update_indicator_is_omitted_for_initial_zero_state(client):
    """Omit every live indicator artifact when no stream has an update.

    Args:
        client: Test application HTTP client.
    """
    login(client)

    page = client.get("/ui/management/dashboard")

    assert page.status_code == 200
    assert "data-update-availability-template" in page.text
    assert "data-update-availability-prototype" in page.text
    assert "data-update-availability-indicator" not in page.text
    assert "Update available for 0 update streams" not in page.text
    assert "data-update-availability-count>0</span>" not in page.text


def test_global_update_indicator_renders_positive_state_and_visibility_aware_refresh(client):
    """Render the count and retain the polling accessibility contract.

    Args:
        client: Test application HTTP client.
    """
    login(client)
    seed_available_confirmations(["photon_os", "atlaso_release"])

    page = client.get("/ui/management/dashboard")
    assert page.status_code == 200
    assert 'data-update-availability-indicator' in page.text
    assert 'href="/ui/management/appliance-update#appliance-update-streams"' in page.text
    assert 'aria-label="Update available for 2 update streams"' in page.text
    assert 'data-update-availability-count>2</span>' in page.text

    app_js = (Path(__file__).resolve().parents[1] / "atlaso" / "app" / "static" / "app.js").read_text(
        encoding="utf-8"
    )
    assert 'fetch("/ui/management/appliance-update/availability"' in app_js
    assert 'cache: "no-store"' in app_js
    assert 'document.addEventListener("visibilitychange"' in app_js
    assert "if (document.hidden) return;" in app_js
    assert "}, 60000);" in app_js
    assert "refreshApplianceUpdateAvailability().catch(() => {});" in app_js
    assert "checkButton.disabled = active || selectedIds.length === 0" in app_js
    assert "stream.last_attempt?.success !== true || !stream.confirmed" in app_js


def test_global_update_indicator_is_hidden_without_appliance_update_permission(client):
    """Hide update availability from identities that cannot open Appliance Update.

    Args:
        client: Test application HTTP client.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    seed_available_confirmations(["photon_os"])
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()

    login(client)
    page = client.get("/ui/management/dashboard")

    assert page.status_code == 200
    assert "data-update-availability-indicator" not in page.text
    assert 'href="/ui/management/appliance-update"' not in page.text


def test_appliance_update_real_helper_failure_is_logged(client, monkeypatch, caplog):
    """Verify that appliance update real helper failure is logged.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        caplog: Pytest fixture used to capture emitted log records.
    """
    import atlaso.app.ui as ui

    class FailingUpdateAdapter:
        """Represent failing update adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

        def check_appliance_update_config(self, config_path: str) -> AdapterResult:
            """Check appliance update config.

            Args:
                config_path: Filesystem path containing the operation configuration.


            Returns:
                The check appliance update config result.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-update", "check", config_path],
                dry_run=False,
                stdout="",
                stderr="manifest refused connection",
                returncode=1,
            )

    monkeypatch.setattr(ui, "SystemAdapter", lambda: FailingUpdateAdapter())
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda _path, _preview: "/var/lib/atlaso/apply/appliance-update/atlaso-update.json")

    login(client)
    page = client.get("/appliance-update")
    csrf = csrf_from_page(page.text)
    with caplog.at_level(logging.INFO, logger="atlaso.appliance_update"):
        response = client.post(
            "/appliance-update/check",
            data={"csrf": csrf, "selected_streams": ["photon_os"]},
        )
        from atlaso.app.worker import run_worker_once

        assert run_worker_once()

    assert response.status_code == 200
    assert "Recent update tasks" in response.text
    assert "appliance-update-task-card" not in response.text
    assert "manifest refused connection" in caplog.text
    assert "completed status=failed mode=check streams=photon_os" in caplog.text
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-update")).scalar_one()
        task_payload = client.get(f"/tasks/{job.id}/status").json()["task"]
    assert task_payload["type_label"] == "Appliance Update check"
    assert task_payload["result"]["label"] == "Appliance Update check"


def test_appliance_update_staging_exception_records_failed_job_and_logs(client, monkeypatch, caplog):
    """Verify that appliance update staging exception records failed job and logs.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        caplog: Pytest fixture used to capture emitted log records.
    """
    import atlaso.app.ui as ui

    class RealUpdateAdapter:
        """Represent real update adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

    monkeypatch.setattr(ui, "SystemAdapter", lambda: RealUpdateAdapter())

    def fail_stage(_path: str, _preview: str) -> str:
        """Return fail stage.

        Args:
            _path: Filesystem path read, validated, or updated by the operation.
            _preview: Preview supplied to the test scenario.


        Raises:
            PermissionError: If the operation lacks the required permission.
        """
        raise PermissionError("staging ownership repair failed")

    monkeypatch.setattr(ui, "stage_appliance_apply_config", fail_stage)

    login(client)
    seed_available_confirmations(["photon_os"])
    page = client.get("/appliance-update")
    csrf = csrf_from_page(page.text)
    with caplog.at_level(logging.INFO, logger="atlaso.appliance_update"):
        response = client.post(
            "/appliance-update/run",
            data={"csrf": csrf, "selected_streams": ["photon_os"]},
        )
        from atlaso.app.worker import run_worker_once

        assert run_worker_once()

    assert response.status_code == 200
    assert "Recent update tasks" in response.text
    assert "appliance-update-task-card" not in response.text
    assert "failed before helper completion" in caplog.text
    assert "staging ownership repair failed" in caplog.text

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-update")).scalar_one()
        payload = json.loads(job.result or "{}")
    assert job.status == "failed"
    assert payload["commands"][0]["command_line"] == "stage-appliance-update /var/lib/atlaso/apply/appliance-update/atlaso-update.json"
    assert "staging ownership repair failed" in payload["commands"][0]["stderr"]


def test_appliance_update_check_runs_every_child_after_failure(client, monkeypatch):
    """Verify that appliance update check runs every child after failure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps
    from atlaso.app.worker import run_worker_once

    client.get("/login")
    selected = ["photon_os", "powershell_modules", "atlaso_release"]
    calls = []

    def fake_execute(**kwargs):
        """Return fake execute.

        Args:
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        stream = kwargs["selected_stream_ids"][0]
        calls.append(stream)
        succeeded = stream != "atlaso_release"
        return {
            "unit_id": stream,
            "label": stream,
            "mode": "check",
            "selected_streams": [stream],
            "selected_labels": [stream],
            "status": "succeeded" if succeeded else "failed",
            "success": succeeded,
            "dry_run": False,
            "restart_after_commit": False,
            "commands": [],
            "config_path": "",
            "config_preview": "",
            "error": "" if succeeded else "release check failed",
        }

    monkeypatch.setattr(ui, "execute_appliance_update_job", fake_execute)
    with SessionLocal() as db:
        job = Job(
            id="job_update_check_children",
            type="appliance-update",
            status=JobStatus.PENDING.value,
            created_by="admin",
            task_config_json=json.dumps(
                {"selected_streams": selected, "settings": {}, "mode": "check"}
            ),
            result="{}",
        )
        db.add(job)
        db.flush()
        ensure_appliance_update_job_steps(db, job=job, selected_streams=selected)
        db.commit()

    assert run_worker_once() == "job_update_check_children"
    assert calls == ["atlaso_release", "powershell_modules", "photon_os"]
    with SessionLocal() as db:
        job = db.get(Job, "job_update_check_children")
        steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert job.status == "failed"
        assert [(step.component_key, step.status) for step in steps] == [
            ("atlaso_release", "failed"),
            ("powershell_modules", "succeeded"),
            ("photon_os", "succeeded"),
        ]


def test_appliance_update_install_skips_later_streams_after_photon_failure(client, monkeypatch):
    """Verify that installation stops after Photon fails.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps
    from atlaso.app.worker import run_worker_once

    client.get("/login")
    selected = ["photon_os", "powershell_modules", "atlaso_release"]
    calls = []

    def fake_execute(**kwargs):
        """Return fake execute.

        Args:
            **kwargs: Additional keyword arguments accepted by the callable.
        """
        stream = kwargs["selected_stream_ids"][0]
        calls.append(stream)
        succeeded = stream != "photon_os"
        return {
            "unit_id": stream,
            "label": stream,
            "mode": "run",
            "selected_streams": [stream],
            "selected_labels": [stream],
            "status": "succeeded" if succeeded else "failed",
            "success": succeeded,
            "dry_run": False,
            "restart_after_commit": False,
            "commands": [],
            "config_path": "",
            "config_preview": "",
            "error": "" if succeeded else "Photon install failed",
        }

    monkeypatch.setattr(ui, "execute_appliance_update_job", fake_execute)
    with SessionLocal() as db:
        job = Job(
            id="job_update_install_children",
            type="appliance-update",
            status=JobStatus.PENDING.value,
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "schema_version": 2,
                    "selected_streams": selected,
                    "execution_order": selected,
                    "settings": {},
                    "mode": "run",
                }
            ),
            result="{}",
        )
        db.add(job)
        db.flush()
        ensure_appliance_update_job_steps(db, job=job, selected_streams=selected)
        db.commit()

    assert run_worker_once() == "job_update_install_children"
    assert calls == ["photon_os"]
    with SessionLocal() as db:
        job = db.get(Job, "job_update_install_children")
        steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert job.status == "failed"
        assert [(step.component_key, step.status) for step in steps] == [
            ("photon_os", "failed"),
            ("powershell_modules", "skipped"),
            ("atlaso_release", "skipped"),
        ]
        assert "earlier selected update stream failed" in (steps[1].error or "")
        assert "earlier selected update stream failed" in (steps[2].error or "")


def test_appliance_update_status_publication_failure_prevents_all_mutation(client, monkeypatch):
    """Fail terminally when listener proof is unavailable.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace worker side effects.
    """
    import atlaso.app.ui as ui
    import atlaso.app.worker as worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    client.get("/login")
    calls = []
    status_calls = []
    monkeypatch.setattr(
        ui,
        "execute_appliance_update_job",
        lambda **kwargs: calls.append(kwargs) or {},
    )
    monkeypatch.setattr(
        worker,
        "_publish_appliance_update_status",
        lambda job_id, *, finish=False: status_calls.append((job_id, finish)) or False,
    )
    selected = ["photon_os", "powershell_modules", "atlaso_release"]
    with SessionLocal() as db:
        job = Job(
            id="job_0123456789ab",
            type="appliance-update",
            status=JobStatus.PENDING.value,
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "schema_version": 2,
                    "mode": "run",
                    "selected_streams": selected,
                    "execution_order": selected,
                    "status_transaction_id": "a" * 32,
                    "settings": {},
                }
            ),
            result="{}",
        )
        db.add(job)
        db.flush()
        ensure_appliance_update_job_steps(db, job=job, selected_streams=selected)
        db.commit()

    assert worker.run_worker_once() == "job_0123456789ab"
    assert calls == []
    assert status_calls[0] == ("job_0123456789ab", False)
    with SessionLocal() as db:
        job = db.get(Job, "job_0123456789ab")
        steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()
        assert job.status == "failed"
        assert all(step.status == "skipped" for step in steps)
        assert "status surface could not be proven continuously" in (job.error or "")


def test_appliance_update_recovery_requeues_only_a_safe_pending_suffix(client):
    """Resume schema-two work interrupted between terminal children.

    Args:
        client: HTTP test client providing isolated application state.
    """
    import atlaso.app.worker as worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    client.get("/login")
    selected = ["photon_os", "powershell_modules", "atlaso_release"]
    with SessionLocal() as db:
        job = Job(
            id="job_fedcba987654",
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "schema_version": 2,
                    "mode": "run",
                    "selected_streams": selected,
                    "execution_order": selected,
                    "status_transaction_id": "b" * 32,
                }
            ),
            result="{}",
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(db, job=job, selected_streams=selected)
        steps[0].status = JobStatus.SUCCEEDED.value
        steps[0].progress_percent = 100
        steps[0].result = json.dumps(
            {"unit_id": "photon_os", "status": "succeeded", "success": True}
        )
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job.id)
        recovered_steps = db.execute(
            select(JobStep).where(JobStep.job_id == job.id).order_by(JobStep.position)
        ).scalars().all()

        assert recovered.status == JobStatus.PENDING.value
        assert json.loads(recovered.result)["worker_recovery"] == "between_streams"
        assert [step.status for step in recovered_steps] == [
            "succeeded",
            "pending",
            "pending",
        ]


def test_recovered_photon_prefix_retains_status_hold_until_restart(client, monkeypatch):
    """Keep the update-only surface active through a recovered restart.

    Args:
        client: HTTP test client providing isolated application state.
        monkeypatch: Pytest fixture used to replace recovery side effects.
    """
    import atlaso.app.ui as ui
    import atlaso.app.worker as worker
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    job_id = "job_abcdef123456"
    finalizer = {
        "job_id": job_id,
        "status": JobStatus.FAILED.value,
        "rolled_back": True,
        "rollback_health": True,
        "error": "candidate readiness failed",
        "commands": [],
    }
    monkeypatch.setattr(worker, "_release_finalizer", lambda: dict(finalizer))
    monkeypatch.setattr(
        worker,
        "reconcile_release_success_finalizer",
        lambda payload: (dict(payload), True),
    )

    class RestartAdapter:
        """Return a successful delayed all-service restart schedule."""

        def restart_appliance_after_update(self, config_path: str) -> AdapterResult:
            """Return a successful scheduling result.

            Args:
                config_path: Staged Appliance Update manifest path.
            """
            return AdapterResult(command=["restart-service", config_path], dry_run=False)

    monkeypatch.setattr(ui, "SystemAdapter", RestartAdapter)
    monkeypatch.setattr(ui, "log_appliance_update_failures", lambda *_args: None)
    monkeypatch.setattr(ui, "log_appliance_update_submission", lambda *_args: None)
    monkeypatch.setattr(ui, "record_audit", lambda *_args, **_kwargs: None)
    status_calls = []
    monkeypatch.setattr(
        worker,
        "_publish_appliance_update_status",
        lambda observed_job_id, *, finish=False: status_calls.append(
            (observed_job_id, finish)
        )
        or True,
    )

    selected = ["photon_os", "atlaso_release"]
    with SessionLocal() as db:
        job = Job(
            id=job_id,
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "schema_version": 2,
                    "mode": "run",
                    "selected_streams": selected,
                    "execution_order": selected,
                    "status_transaction_id": "c" * 32,
                    "settings": {},
                }
            ),
            result="{}",
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=selected,
        )
        steps[0].status = JobStatus.SUCCEEDED.value
        steps[0].progress_percent = 100
        steps[0].result = json.dumps(
            {"unit_id": "photon_os", "status": "succeeded", "success": True}
        )
        steps[1].status = JobStatus.RUNNING.value
        db.commit()

        assert worker.recover_interrupted_worker_jobs(db) == 1
        recovered = db.get(Job, job_id)
        recovered_result = json.loads(recovered.result)

    assert recovered.status == JobStatus.FAILED.value
    assert recovered_result["restart_after_commit"] is True
    assert recovered_result["restart_scheduled"] is True
    assert status_calls == []


@pytest.mark.parametrize(
    ("selected", "expected"),
    [
        (["photon_os"], ["photon_os"]),
        (["powershell_modules"], ["powershell_modules"]),
        (["atlaso_release"], ["atlaso_release"]),
        (["photon_os", "powershell_modules"], ["photon_os", "powershell_modules"]),
        (["photon_os", "atlaso_release"], ["photon_os", "atlaso_release"]),
        (["powershell_modules", "atlaso_release"], ["powershell_modules", "atlaso_release"]),
        (
            ["photon_os", "powershell_modules", "atlaso_release"],
            ["photon_os", "powershell_modules", "atlaso_release"],
        ),
    ],
)
def test_appliance_update_new_tasks_persist_every_subset_in_safe_order(
    client,
    selected,
    expected,
):
    """Persist each installation subset in Photon, PowerShell, Atlaso order.

    Args:
        client: HTTP test client used to initialize an isolated database.
        selected: Selected update streams for the task.
        expected: Expected immutable child order.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_update import ensure_appliance_update_job_steps

    client.get("/login")
    with SessionLocal() as db:
        job = Job(
            id="job_subset_order",
            type="appliance-update",
            status="pending",
            created_by="admin",
            task_config_json=json.dumps(
                {
                    "schema_version": 2,
                    "selected_streams": selected,
                    "execution_order": expected,
                    "status_transaction_id": "a" * 32,
                    "settings": {},
                    "mode": "run",
                }
            ),
            result="{}",
        )
        db.add(job)
        db.flush()
        steps = ensure_appliance_update_job_steps(
            db,
            job=job,
            selected_streams=selected,
        )

        assert [step.component_key for step in steps] == expected
        assert [step.position for step in steps] == list(range(1, len(expected) + 1))


def test_appliance_update_service_version_helpers():
    """Verify that appliance update service version helpers."""
    from atlaso.app.services.appliance_update import (
        redact_url_userinfo,
        version_with_git,
    )

    assert version_with_git("0.1.0", "abcdef1234567890") == "0.1.0+gabcdef123456"
    assert version_with_git("0.1.0+gold", "abcdef") == "0.1.0+gabcdef"
    assert redact_url_userinfo("https://user:token@example.test/simple") == "https://[redacted]@example.test/simple"


def test_current_version_info_has_public_branch_wheel_label(monkeypatch):
    """Verify that current version info has public branch wheel label.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso
    import atlaso.app.services.appliance_update as appliance_update

    monkeypatch.setattr(atlaso, "__build_git_commit__", "dd9fca8d9d2b83d4bd39538cbc3727dfa8a82062")
    monkeypatch.setattr(atlaso, "__build_time_utc__", "2026-07-08T15:45:54Z")
    monkeypatch.setattr(appliance_update, "__version__", "0.1.0+gdd9fca8d9d2b")
    monkeypatch.setattr(appliance_update, "_git_value", lambda _args: "")

    info = appliance_update.current_version_info()

    assert info["base_version"] == "0.1.0"
    assert info["git_short"] == "dd9fca8d9d2b"
    assert info["public_label"] == "dd9fca8 (branch wheel)"


def test_current_version_info_has_installed_checksum_fallback(monkeypatch):
    """Verify that current version info has installed checksum fallback.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso
    import atlaso.app.services.appliance_update as appliance_update

    monkeypatch.setattr(atlaso, "__build_git_commit__", "")
    monkeypatch.setattr(atlaso, "__build_time_utc__", "")
    monkeypatch.setattr(appliance_update, "_git_value", lambda _args: "")
    monkeypatch.setattr(appliance_update, "_installed_record_sha256", lambda: "abc123def4567890")

    info = appliance_update.current_version_info()

    assert info["public_label"] == "installed sha abc123def456"
    assert info["installed_sha256"] == "abc123def4567890"


def test_atlaso_repository_url_derives_channel_manifest(client):
    """Verify that atlaso repository url derives channel manifest.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import UpdateSource
    from atlaso.app.services.update_sources import effective_update_settings

    client.get("/login")
    with SessionLocal() as db:
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "atlaso")).scalar_one()
        source.url = "https://updates.example.test/atlaso/"
        source.settings_json = '{"channel":"preview"}'
        db.add(source)
        db.commit()
        settings = effective_update_settings(db)
    assert settings["atlaso_manifest_url"] == "https://updates.example.test/atlaso/channels/preview/manifest.json"


def test_runtime_photon_source_details(tmp_path):
    """Verify that runtime photon source details.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from atlaso.app.services import appliance_update

    (tmp_path / "photon.repo").write_text(
        "[photon]\nname=Photon 5 release\nbaseurl=https://packages.example.test/photon/$releasever/release\nenabled=1\n"
        "[disabled]\nname=Disabled\nbaseurl=https://packages.example.test/disabled\nenabled=0\n",
        encoding="utf-8",
    )
    details = appliance_update.photon_repository_details(tmp_path)
    assert details == [
        {
            "id": "photon",
            "name": "Photon 5 release",
            "location": "https://packages.example.test/photon/$releasever/release",
            "location_type": "baseurl",
            "file": "photon.repo",
        }
    ]
    assert "photon | Photon 5 release | baseurl=https://packages.example.test" in appliance_update.photon_repository_summary(tmp_path)

def test_source_sync_is_queued_and_records_validation_status(client):
    """Verify that source sync is queued and records validation status.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, UpdateSource
    from atlaso.app.worker import run_worker_once

    login(client)
    page = client.get("/appliance-update")
    csrf = csrf_from_page(page.text)
    response = client.post("/appliance-update/source-sync", data={"csrf": csrf})
    assert response.status_code == 200
    assert "Recent update tasks" in response.text
    assert "appliance-update-task-card" not in response.text
    assert run_worker_once() is not None
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-update")).scalar_one()
        sources = db.execute(select(UpdateSource).where(UpdateSource.enabled.is_(True))).scalars().all()
        assert json.loads(job.result)["mode"] == "source_sync"
        package_sources = [source for source in sources if source.kind in {"photon", "powershell"}]
        signed_sources = [source for source in sources if source.kind == "atlaso"]
        assert all(source.validation_status == "valid" for source in package_sources)
        assert all("dry-run" in source.validation_message for source in package_sources)
        assert all(source.validation_status == "not_checked" for source in signed_sources)

    page = client.get("/appliance-update")
    assert "Synchronized" in page.text
    assert "Checked during update" in page.text
    assert ">invalid<" not in page.text


def test_source_sync_preserves_per_repository_results(client):
    """Verify that source sync preserves per repository results.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, UpdateSource
    from atlaso.app.ui import complete_appliance_update_task

    with SessionLocal() as db:
        sources = db.execute(
            select(UpdateSource).where(UpdateSource.kind == "powershell").order_by(UpdateSource.id)
        ).scalars().all()
        succeeded_source = sources[0]
        failed_source = UpdateSource(
            kind="powershell",
            name="UnavailableGallery",
            url="https://unavailable.example.test/api/v2",
            enabled=True,
            settings_json=json.dumps({"trusted": False}),
            validation_status="not_checked",
        )
        db.add(failed_source)
        db.flush()
        job = Job(
            id="job_partial_source_sync",
            type="appliance-update",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            result="{}",
        )
        db.add(job)
        db.flush()
        complete_appliance_update_task(
            db,
            job=job,
            update_result={
                "mode": "source_sync",
                "status": JobStatus.FAILED.value,
                "success": False,
                "dry_run": False,
                "commands": [],
                "source_results": [
                    {"id": succeeded_source.id, "kind": "powershell", "name": succeeded_source.name, "success": True},
                    {"id": failed_source.id, "kind": "powershell", "name": failed_source.name, "success": False},
                ],
            },
        )
        db.refresh(succeeded_source)
        db.refresh(failed_source)
        assert succeeded_source.validation_status == "valid"
        assert failed_source.validation_status == "invalid"
        assert "synchronized" in succeeded_source.validation_message
        assert "failed" in failed_source.validation_message


def test_source_sync_helper_results_are_promoted_to_task_result(client, monkeypatch):
    """Verify that source sync helper results are promoted to task result.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import UpdateSource
    from atlaso.app.services.update_sources import effective_update_settings

    with SessionLocal() as db:
        settings = effective_update_settings(db)
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "powershell")).scalars().first()
        source_result = {"id": source.id, "kind": "powershell", "name": source.name, "success": True}

    class SourceSyncAdapter:
        """Represent source sync adapter.

        Attributes:
            dry_run: Dry run captured or supplied by this test helper.
        """
        dry_run = False

        def sync_appliance_update_sources(self, config_path: str) -> AdapterResult:
            """Handle sync appliance update sources.

            Args:
                config_path: Filesystem path containing the operation configuration.
            """
            return AdapterResult(
                command=["atlaso-helper", "appliance-update", "sync-sources", config_path],
                dry_run=False,
                stdout=json.dumps({"status": "succeeded", "commands": [], "source_results": [source_result]}),
                stderr="",
                returncode=0,
            )

    monkeypatch.setattr(ui, "SystemAdapter", lambda: SourceSyncAdapter())
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda _path, _preview: "atlaso-update.json")

    result = ui.execute_appliance_update_job(
        selected_stream_ids=[],
        settings=settings,
        actor="admin",
        mode="source_sync",
    )

    assert result["success"] is True
    assert result["source_results"] == [source_result]


def test_software_source_and_managed_module_lifecycle(client):
    """Verify that software source and managed module lifecycle.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ManagedPackage, UpdateSource
    from atlaso.app.services.update_sources import effective_update_settings

    login(client)
    csrf = csrf_from_page(client.get("/appliance-update").text)
    created = client.post(
        "/appliance-update/sources",
        data={"csrf": csrf, "kind": "powershell", "name": "PrivateGallery", "url": "https://packages.example.test/powershell", "priority": "20", "enabled": "on"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with SessionLocal() as db:
        source = db.execute(select(UpdateSource).where(UpdateSource.name == "PrivateGallery")).scalar_one()
        source_id = source.id

    package_created = client.post(
        "/appliance-update/packages",
        data={"csrf": csrf, "name": "Private.PowerCLI.Tools", "source_id": str(source_id), "policy": "pinned", "target_version": "1.2.3", "enabled": "on"},
        follow_redirects=False,
    )
    assert package_created.status_code == 303
    grouped_page = client.get("/appliance-update")
    assert "data-runtime-photon-repositories" in grouped_page.text
    assert "data-runtime-python-index" not in grouped_page.text
    assert "https://pypi.org/simple" not in grouped_page.text
    assert 'aria-label="Appliance update workspace"' in grouped_page.text
    assert 'data-tab-target="appliance-update-sources"' in grouped_page.text
    assert 'data-tab-target="appliance-update-streams"' in grouped_page.text
    assert grouped_page.text.index('data-tab-target="appliance-update-streams"') < grouped_page.text.index('data-tab-target="appliance-update-sources"')
    assert "Synchronize repositories" in grouped_page.text
    assert grouped_page.text.count('class="appliance-update-source-actions"') == 1
    assert 'action="/ui/management/appliance-update/source-sync" data-appliance-update-source-sync-form' in grouped_page.text
    assert 'class="button secondary icon-button" type="submit" aria-label="Synchronize repositories" title="Synchronize repositories" data-appliance-update-source-sync-action' in grouped_page.text
    assert grouped_page.text.count("Synchronize repositories") >= 2
    assert 'class="muted appliance-update-source-intro"' in grouped_page.text
    assert 'data-appliance-update-validation-panel' in grouped_page.text
    assert "Staged update manifest" in grouped_page.text
    assert 'data-config-preview-open' in grouped_page.text
    assert '<div class="config-preview">' not in grouped_page.text
    assert grouped_page.text.index("Update transaction evidence") < grouped_page.text.index(
        'data-appliance-update-validation-panel'
    )
    source_actions = grouped_page.text.index('class="appliance-update-source-actions"')
    source_list = grouped_page.text.index('class="apply-unit-list"', source_actions)
    assert source_actions < source_list
    assert 'aria-label="Managed PowerShell modules"' in grouped_page.text
    assert 'data-tab-target="powershell-module-new"' not in grouped_page.text
    assert 'data-managed-package-wizard-open' in grouped_page.text
    assert 'id="managed-package-dialog"' in grouped_page.text
    assert 'data-managed-package-create-form' in grouped_page.text
    managed_module_tabs = grouped_page.text.split('aria-label="Managed PowerShell modules"', 1)[1].split("</div>", 1)[0]
    assert "data-managed-package-wizard-open" in managed_module_tabs
    assert "VCF.PowerCLI" in grouped_page.text
    assert "Private.PowerCLI.Tools" in grouped_page.text
    assert 'data-update-source-section="managed-modules"' in grouped_page.text
    assert "<strong>POWERSHELL</strong> · managed modules" in grouped_page.text
    assert "Saved, not synchronized" in grouped_page.text
    assert "saved in Atlaso but has not been validated or written" in grouped_page.text
    assert "data-add-powershell-repository" not in grouped_page.text
    assert 'data-update-source-group="powershell"' in grouped_page.text
    assert 'aria-label="powershell repositories"' in grouped_page.text
    assert grouped_page.text.count('data-update-source-mode="create"') == 3
    assert grouped_page.text.count('data-update-source-mode="edit"') >= 4
    assert 'data-update-source-kind="powershell"' in grouped_page.text
    powershell_tabs = grouped_page.text.split('aria-label="powershell repositories"', 1)[1].split("</div>", 1)[0]
    assert "data-update-source-wizard-open" in powershell_tabs
    assert 'id="appliance-update-source-dialog"' in grouped_page.text
    assert "data-appliance-update-source-form" in grouped_page.text
    assert "data-powershell-source-new-tab" not in grouped_page.text
    assert 'data-tab-target="update-source-powershell-new"' not in grouped_page.text
    assert "PSGallery" in grouped_page.text
    assert "PrivateGallery" in grouped_page.text
    app_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    assert "function initializeApplianceUpdateSourceWizard()" in app_js
    assert "function initializeManagedPackageWizard()" in app_js
    assert "window.AtlasoUiPatterns.createWizard({" in app_js
    assert 'form.action = source?.id ? `${createAction}/${source.id}` : createAction;' in app_js
    assert "if (source) populateSource(source);" in app_js
    assert 'form.action = editing ? `${defaultAction}/${managedPackage.id}` : defaultAction;' in app_js
    assert 'wizard.open({ launcher, context: managedPackage });' in app_js
    assert '"X-Atlaso-Wizard": "1"' in app_js
    assert 'throw new Error(payload.detail || "The managed PowerShell module could not be saved.");' in app_js
    assert 'window.history.replaceState(null, "", managementUiPath("/appliance-update#update-sources"));' in app_js
    assert 'window.history.replaceState(null, "", managementUiPath("/appliance-update#managed-packages"));' in app_js
    source_wizard_js = app_js.split("function initializeApplianceUpdateSourceWizard()", 1)[1].split(
        "function initializeManagedPackageWizard()", 1
    )[0]
    package_wizard_js = app_js.split("function initializeManagedPackageWizard()", 1)[1].split(
        "function initializeEsxStorageTables()", 1
    )[0]
    assert 'window.location.assign("/appliance-update#update-sources")' not in source_wizard_js
    assert 'window.location.assign("/appliance-update#managed-packages")' not in package_wizard_js
    assert "window.location.reload();" in source_wizard_js
    assert "window.location.reload();" in package_wizard_js
    app_css = Path("atlaso/app/static/app.css").read_text(encoding="utf-8")
    assert ".detail-rail .detail-panel {\n  position: static;" in app_css
    assert ".detail-rail {\n  position: sticky;\n  top: 22px;" in app_css
    assert 'data-update-source-readonly' in grouped_page.text
    private_source_panel = grouped_page.text.split(f'id="update-source-{source_id}"', 1)[1].split(
        f'id="delete-update-source-{source_id}"', 1
    )[0]
    assert 'data-update-source-mode="edit"' in private_source_panel
    assert 'aria-label="Edit PrivateGallery repository"' in private_source_panel
    assert 'aria-label="Delete PrivateGallery repository"' in private_source_panel
    assert private_source_panel.index('class="source-readonly-heading"') < private_source_panel.index(
        'class="settings-list source-readonly-list"'
    )
    assert private_source_panel.index('aria-label="Edit PrivateGallery repository"') < private_source_panel.index(
        'aria-label="Delete PrivateGallery repository"'
    )
    assert '<input name="name"' not in private_source_panel
    assert 'data-autosave-form' not in private_source_panel
    assert 'data-managed-package-readonly' in grouped_page.text
    assert 'data-managed-package-mode="create"' in grouped_page.text
    assert 'data-managed-package-mode="edit"' in grouped_page.text
    assert 'aria-label="Edit Private.PowerCLI.Tools module"' in grouped_page.text
    assert 'aria-label="Delete Private.PowerCLI.Tools module"' in grouped_page.text
    assert 'class="source-readonly-view" data-managed-package-readonly' in grouped_page.text
    assert 'data-managed-package-form' not in grouped_page.text
    assert 'class="apply-unit-card source-editor-form managed-package-editor"' not in grouped_page.text
    assert "Changes save automatically." not in grouped_page.text
    assert "Repository behavior" in grouped_page.text
    assert "Module behavior" in grouped_page.text
    assert "1.2.3" in grouped_page.text
    assert "appliance-update-task-card" not in app_css
    assert ".appliance-update-history .tabulator-row.task-grid-new-task" in app_css
    assert ".source-editor-grid {\n  display: grid;" in app_css
    assert ".source-readonly-view {\n  display: grid;" in app_css
    assert ".source-readonly-heading {\n  display: flex;" in app_css
    assert ".config-diff .source-readonly-full pre code .token {\n  color: #0f172a;" in app_css
    assert ".source-option-grid {\n  display: grid;" in app_css
    assert ".source-editor-footer {\n  display: flex;" in app_css
    assert "class=\"source-validation-state\"" in grouped_page.text
    wizard_created = client.post(
        "/appliance-update/sources",
        data={
            "csrf": csrf,
            "kind": "photon",
            "name": "WizardPhoton",
            "url": "https://packages.example.test/photon",
            "priority": "15",
            "managed": "on",
            "gpgcheck": "on",
            "gpgkey": "https://packages.example.test/keys/RPM-GPG-KEY",
            "tls_verify": "on",
            "enabled": "on",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )
    assert wizard_created.status_code == 200
    assert wizard_created.json()["status"] == "saved"
    assert wizard_created.json()["source"]["settings"] == {
        "gpgcheck": True,
        "gpgkey": "https://packages.example.test/keys/RPM-GPG-KEY",
        "managed": True,
        "tls_verify": True,
    }
    wizard_updated = client.post(
        f"/appliance-update/sources/{source_id}",
        data={
            "csrf": csrf,
            "name": "PrivateGallery",
            "url": "https://packages.example.test/powershell-v2",
            "priority": "25",
            "enabled_present": "1",
            "enabled": "on",
            "trusted": "on",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )
    assert wizard_updated.status_code == 200
    assert wizard_updated.json()["status"] == "saved"
    assert wizard_updated.json()["source"]["priority"] == 25
    assert wizard_updated.json()["source"]["url"] == "https://packages.example.test/powershell-v2"
    assert wizard_updated.json()["source"]["settings"] == {"trusted": True}
    with SessionLocal() as db:
        package = db.execute(select(ManagedPackage).where(ManagedPackage.name == "Private.PowerCLI.Tools")).scalar_one()
        package_id = package.id
        module = next(item for item in effective_update_settings(db)["powershell_modules"] if item["name"] == package.name)
        assert module["repository_name"] == "PrivateGallery"
        assert module["target_version"] == "1.2.3"

    rejected_wizard_edit = client.post(
        f"/appliance-update/packages/{package_id}",
        data={
            "csrf": csrf,
            "name": "VCF.PowerCLI",
            "source_id": str(source_id),
            "policy": "latest",
            "enabled_present": "1",
            "enabled": "on",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )
    assert rejected_wizard_edit.status_code == 409
    assert rejected_wizard_edit.json() == {
        "status": "error",
        "detail": "This PowerShell module is already managed.",
        "errors": ["This PowerShell module is already managed."],
    }
    with SessionLocal() as db:
        package = db.get(ManagedPackage, package_id)
        assert package.name == "Private.PowerCLI.Tools"
        assert package.policy == "pinned"
        assert package.target_version == "1.2.3"

    changed_to_latest = client.post(
        f"/appliance-update/packages/{package_id}",
        data={
            "csrf": csrf,
            "name": "Private.PowerCLI.Tools",
            "source_id": str(source_id),
            "policy": "latest",
            "target_version": "1.2.3",
            "enabled_present": "1",
            "enabled": "on",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )
    assert changed_to_latest.status_code == 200
    assert changed_to_latest.json() == {"status": "saved", "package": {"id": package_id}}
    with SessionLocal() as db:
        package = db.get(ManagedPackage, package_id)
        assert package.policy == "latest"
        assert package.target_version == ""

    blocked = client.post(f"/appliance-update/sources/{source_id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert blocked.status_code == 409
    assert "Private.PowerCLI.Tools" in blocked.text
    assert client.post(f"/appliance-update/packages/{package_id}/delete", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert client.post(f"/appliance-update/sources/{source_id}/delete", data={"csrf": csrf}, follow_redirects=False).status_code == 303


def test_effective_update_settings_preserves_all_enabled_repository_sources(client):
    """Verify that effective update settings preserves all enabled repository sources.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import UpdateSource
    from atlaso.app.services.update_sources import effective_update_settings

    client.get("/login")
    with SessionLocal() as db:
        db.add_all(
            [
                UpdateSource(
                    kind="atlaso",
                    name="Backup releases",
                    url="https://updates-backup.example.test/atlaso",
                    priority=80,
                    enabled=True,
                    settings_json=json.dumps({"channel": "preview"}),
                ),
            ]
        )
        primary_atlaso = db.execute(select(UpdateSource).where(UpdateSource.kind == "atlaso")).scalars().first()
        primary_atlaso.url = "https://updates-primary.example.test/atlaso"
        db.commit()

        settings = effective_update_settings(db)

    assert "python_index_urls" not in settings
    assert settings["atlaso_manifest_urls"] == [
        "https://updates-primary.example.test/atlaso/channels/stable/manifest.json",
        "https://updates-backup.example.test/atlaso/channels/preview/manifest.json",
    ]
    manifest = json.loads(
        __import__("atlaso.app.services.appliance_update", fromlist=["render_update_manifest"]).render_update_manifest(
            selected_streams=["atlaso_release"], settings=settings, actor="test"
        )
    )
    assert "python_index_urls" not in manifest["sources"]
    assert manifest["sources"]["atlaso_manifest_urls"] == settings["atlaso_manifest_urls"]
    assert manifest["policy"]["vmware_ceip_enabled"] is False


def test_source_credentials_use_protected_runtime_channel_without_manifest_disclosure(client):
    """Verify that source credentials use protected runtime channel without manifest disclosure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import UpdateSource
    from atlaso.app.secrets import encrypt_secret
    from atlaso.app.services.appliance_update import render_update_manifest
    from atlaso.app.services.update_sources import (
        effective_update_settings,
        update_source_credentials,
    )

    client.get("/login")
    with SessionLocal() as db:
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "atlaso")).scalars().first()
        source.url = "https://private.example.test/releases"
        source.credential_encrypted = encrypt_secret(json.dumps({"username": "repo-user", "secret": "repo-token"}))
        db.commit()
        source_id = source.id
        settings = effective_update_settings(db)
        credentials = update_source_credentials(db)

    preview = render_update_manifest(selected_streams=["atlaso_release"], settings=settings, actor="test")
    assert "repo-user" not in preview
    assert "repo-token" not in preview
    assert credentials[str(source_id)] == {"username": "repo-user", "secret": "repo-token"}


def test_helper_rejects_retired_python_library_stream():
    """Verify that helper rejects retired python library stream."""
    helper = load_helper_module()
    errors = helper._appliance_update_config_errors(
        {"selected_streams": ["python_libraries"], "sources": {}},
        require_streams=True,
    )
    assert errors == ["unsupported update stream python_libraries."]


def test_helper_rejects_unsynchronized_powershell_repository():
    """Verify that helper rejects unsynchronized powershell repository."""
    helper = load_helper_module()
    payload = {
        "selected_streams": ["powershell_modules"],
        "sources": {
            "powershell_repository_name": "PSGallery",
            "powershell_repository_url": "https://www.powershellgallery.com/api/v21",
        },
        "powershell_modules": [{"name": "VCF.PowerCLI", "repository_name": "PSGallery"}],
        "source_definitions": [
            {
                "kind": "powershell",
                "name": "PSGallery",
                "enabled": True,
                "validation_status": "not_checked",
            }
        ],
    }

    assert helper._appliance_update_config_errors(payload, require_streams=True) == [
        "PowerShell repository PSGallery is not synchronized; run Synchronize repositories before checking or installing managed modules."
    ]
    assert helper._appliance_update_config_errors(
        payload, require_streams=True, require_synchronized=False
    ) == []
    payload["source_definitions"][0]["validation_status"] = "valid"
    assert helper._appliance_update_config_errors(payload, require_streams=True) == []


def test_helper_rejects_unsynchronized_managed_photon_repository():
    """Verify that helper rejects unsynchronized managed photon repository."""
    helper = load_helper_module()
    payload = {
        "selected_streams": ["photon_os"],
        "sources": {"photon_source": "System Photon repositories"},
        "source_definitions": [
            {
                "kind": "photon",
                "name": "System Photon repositories",
                "enabled": True,
                "settings": {"managed": True},
                "validation_status": "not_checked",
            }
        ],
    }

    assert helper._appliance_update_config_errors(payload, require_streams=True) == [
        "Photon repository System Photon repositories is not synchronized; run Synchronize repositories before checking or installing Photon OS updates."
    ]
    assert helper._appliance_update_config_errors(
        payload, require_streams=True, require_synchronized=False
    ) == []
    payload["source_definitions"][0]["validation_status"] = "valid"
    assert helper._appliance_update_config_errors(payload, require_streams=True) == []


def test_helper_redacts_repository_credentials_from_package_client_output(monkeypatch):
    """Verify that helper redacts repository credentials from package client output.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from types import SimpleNamespace

    helper = load_helper_module()
    monkeypatch.setattr(
        helper,
        "_run",
        lambda _command, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="index https://repo-user:repo-token@private.example.test/simple",
            stderr="authentication failed for repo-user using repo-token",
        ),
    )
    result = helper._command_payload(
        ["python", "-m", "pip", "list"],
        env={
            "PIP_INDEX_URL": "https://repo-user:repo-token@private.example.test/simple",
            "LF_REPO_USER": "repo-user",
            "LF_REPO_SECRET": "repo-token",
        },
    )
    rendered = json.dumps(result)
    assert "repo-user" not in rendered
    assert "repo-token" not in rendered
    assert "[redacted]" in rendered


def test_helper_falls_back_to_next_signed_atlaso_release_source(monkeypatch):
    """Verify that helper falls back to next signed atlaso release source.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    attempted = []
    expected_channel = {"channel": "preview", "release_manifest_url": "https://backup.example.test/release.json"}
    expected_manifest = {"version": "0.9.0", "git_commit": "a" * 40}

    def fake_release(url, credential=None):
        """Return fake release.

        Args:
            url: URL contacted or emitted by the operation.
            credential: Credential supplied to the test scenario.


        Raises:
            OSError: If the operating-system operation fails.
        """
        attempted.append((url, credential))
        if "primary" in url:
            raise OSError("primary unavailable")
        return expected_channel, expected_manifest, credential

    monkeypatch.setattr(helper, "_download_signed_release", fake_release)
    channel, manifest, url, credential = helper._download_signed_release_from_sources(
        {
            "sources": {
                "atlaso_manifest_urls": [
                    "https://primary.example.test/manifest.json",
                    "https://backup.example.test/manifest.json",
                ]
            },
            "source_definitions": [
                {"id": 1, "kind": "atlaso", "url": "https://primary.example.test/manifest.json", "enabled": True},
                {"id": 2, "kind": "atlaso", "url": "https://backup.example.test/manifest.json", "enabled": True},
            ],
        },
        {"2": {"username": "backup", "secret": "token"}},
    )
    assert channel == expected_channel
    assert manifest == expected_manifest
    assert url == "https://backup.example.test/release.json"
    assert credential == {"username": "backup", "secret": "token"}
    assert [item[0] for item in attempted] == [
        "https://primary.example.test/manifest.json",
        "https://backup.example.test/manifest.json",
    ]


def test_helper_syncs_only_owned_photon_and_powershell_sources(monkeypatch, tmp_path):
    """Verify that helper syncs only owned photon and powershell sources.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    photon_path = tmp_path / "atlaso-managed.repo"
    state_path = tmp_path / "update-sources.json"
    monkeypatch.setattr(helper, "MANAGED_PHOTON_REPO_PATH", photon_path)
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "_command_path", lambda _name: None)
    payload = {
        "source_definitions": [
            {
                "kind": "photon",
                "name": "Internal Photon",
                "url": "https://packages.example.test/photon/5/x86_64",
                "enabled": True,
                "settings": {"managed": True, "gpgcheck": True, "tls_verify": True},
            },
        ]
    }
    result = helper._sync_appliance_update_sources(payload)
    assert result["status"] == "succeeded"
    assert "[internal-photon]" in photon_path.read_text(encoding="utf-8")
    assert "gpgcheck=1" in photon_path.read_text(encoding="utf-8")
    assert json.loads(state_path.read_text(encoding="utf-8")) == {"powershell_repositories": []}


def test_helper_reports_unresolvable_powershell_repository_host(monkeypatch, tmp_path):
    """Verify that helper reports unresolvable powershell repository host.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import socket

    helper = load_helper_module()
    state_path = tmp_path / "update-sources.json"
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    monkeypatch.setattr(
        helper.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.gaierror(-2, "Name or service not known")),
    )

    result = helper._sync_appliance_update_sources(
        {
            "source_definitions": [
                {
                    "kind": "powershell",
                    "name": "PSGallery",
                    "url": "https://www.powershellgallery.com/api/v2",
                    "enabled": True,
                    "settings": {"trusted": False},
                }
            ]
        }
    )

    assert result["status"] == "failed"
    assert result["commands"][0]["command"] == ["resolve", "www.powershellgallery.com"]
    assert result["error"].startswith("PowerShell repository PSGallery host www.powershellgallery.com could not be resolved:")


def test_helper_psgallery_sync_uses_default_registration_and_is_idempotent(monkeypatch, tmp_path):
    """Use PowerShellGet's reserved-gallery path and retain canonical state across reruns.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import base64

    helper = load_helper_module()
    state_path = tmp_path / "update-sources.json"
    scripts = []
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    monkeypatch.setattr(helper.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, None)])

    def successful_sync(command, *, success_codes=None, env=None):
        """Capture one successful PowerShell synchronization command.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        scripts.append(base64.b64decode(command[-1]).decode("utf-16-le"))
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": json.dumps(
                {
                    "Name": "PSGallery",
                    "SourceLocation": "https://www.powershellgallery.com/api/v2",
                    "InstallationPolicy": "Trusted",
                    "ProbeSucceeded": True,
                }
            ),
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_command_payload", successful_sync)
    payload = {
        "source_definitions": [
            {
                "id": 1,
                "kind": "powershell",
                "name": "psgallery",
                "url": "https://www.powershellgallery.com/api/v2",
                "enabled": True,
                "settings": {"trusted": True},
            }
        ]
    }

    first = helper._sync_appliance_update_sources(payload)
    second = helper._sync_appliance_update_sources(payload)

    assert first["status"] == second["status"] == "succeeded"
    assert first["source_results"][0]["success"] is True
    assert len(scripts) == 2
    assert all("Register-PSRepository -Default -InstallationPolicy $policy" in script for script in scripts)
    assert all("Register-PSRepository -Name $name" not in script for script in scripts)
    assert all("Unregister-PSRepository -Name $existing.Name -ErrorAction Stop" in script for script in scripts)
    assert all("Set-PSRepository -Name $existing.Name -InstallationPolicy $policy" in script for script in scripts)
    assert all("Set-PSRepository -Name $existing.Name -SourceLocation $url" not in script for script in scripts)
    assert all("Registered repository location does not match Atlaso desired state" in script for script in scripts)
    assert all("Registered repository installation policy does not match Atlaso desired state" in script for script in scripts)
    assert all("Find-Module -Repository $repository.Name" in script for script in scripts)
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "powershell_repositories": ["PSGallery"]
    }


def test_helper_rejects_noncanonical_reserved_gallery_before_host_mutation(monkeypatch, tmp_path):
    """Fail an invalid PSGallery definition before Photon or PowerShell mutation.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    photon_path = tmp_path / "atlaso-managed.repo"
    monkeypatch.setattr(helper, "MANAGED_PHOTON_REPO_PATH", photon_path)
    monkeypatch.setattr(
        helper,
        "_command_payload",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("host command must not run")),
    )
    payload = {
        "source_definitions": [
            {
                "kind": "photon",
                "name": "Internal Photon",
                "url": "https://packages.example.test/photon",
                "enabled": True,
                "settings": {"managed": True},
            },
            {
                "kind": "powershell",
                "name": "PsGaLlErY",
                "url": "https://packages.example.test/api/v2",
                "enabled": True,
                "settings": {"trusted": False},
            },
        ]
    }

    try:
        helper._sync_appliance_update_sources(payload)
    except ValueError as exc:
        message = str(exc)
    else:
        raise AssertionError("invalid reserved PSGallery definition must fail")

    assert "PSGallery is reserved" in message
    assert "choose a different repository name" in message
    assert not photon_path.exists()


def test_helper_custom_repository_keeps_explicit_registration_and_credentials(monkeypatch, tmp_path):
    """Keep custom registration, policy, probe, and protected credential behavior.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import base64

    helper = load_helper_module()
    state_path = tmp_path / "update-sources.json"
    captured = {}
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    monkeypatch.setattr(helper.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, None)])

    def successful_sync(command, *, success_codes=None, env=None):
        """Capture custom repository command and environment.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        captured["script"] = base64.b64decode(command[-1]).decode("utf-16-le")
        captured["env"] = env
        return {"command": command, "returncode": 0, "success": True, "stdout": "{}", "stderr": ""}

    monkeypatch.setattr(helper, "_command_payload", successful_sync)
    result = helper._sync_appliance_update_sources(
        {
            "source_definitions": [
                {
                    "id": 7,
                    "kind": "powershell",
                    "name": "PrivateGallery",
                    "url": "https://packages.example.test/api/v2",
                    "enabled": True,
                    "settings": {"trusted": False},
                }
            ]
        },
        {"7": {"username": "operator", "secret": "test-secret"}},
    )

    assert result["status"] == "succeeded"
    assert "Register-PSRepository -Name $name -SourceLocation $url" in captured["script"]
    assert "Register-PSRepository -Default" not in captured["script"]
    assert "Find-Module -Repository $repository.Name @credentialArgs" in captured["script"]
    assert captured["env"]["LF_REPO_USER"] == "operator"
    assert captured["env"]["LF_REPO_SECRET"] == "test-secret"
    assert "test-secret" not in captured["script"]


def test_helper_readback_mismatch_retains_ownership_without_reporting_success(monkeypatch, tmp_path):
    """Retain cleanup ownership while a failed readback remains unsynchronized.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    state_path = tmp_path / "update-sources.json"
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    monkeypatch.setattr(helper.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, None)])
    monkeypatch.setattr(
        helper,
        "_command_payload",
        lambda command, **_kwargs: {
            "command": command,
            "returncode": 1,
            "success": False,
            "stdout": "",
            "stderr": "Registered repository location does not match Atlaso desired state",
        },
    )

    result = helper._sync_appliance_update_sources(
        {
            "source_definitions": [
                {
                    "id": 1,
                    "kind": "powershell",
                    "name": "PSGallery",
                    "url": "https://www.powershellgallery.com/api/v2",
                    "enabled": True,
                    "settings": {"trusted": False},
                }
            ]
        }
    )

    assert result["status"] == "failed"
    assert result["source_results"][0]["success"] is False
    assert result["error"] == "Registered repository location does not match Atlaso desired state"
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "powershell_repositories": ["PSGallery"]
    }


def test_helper_probe_failure_retains_ownership_without_reporting_success(monkeypatch, tmp_path):
    """Retain cleanup ownership while a failed probe remains unsynchronized.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    state_path = tmp_path / "update-sources.json"
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    monkeypatch.setattr(helper.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, None)])
    monkeypatch.setattr(
        helper,
        "_command_payload",
        lambda command, **_kwargs: {
            "command": command,
            "returncode": 1,
            "success": False,
            "stdout": "",
            "stderr": "No match was found for the specified search criteria and repository name PSGallery.",
        },
    )

    result = helper._sync_appliance_update_sources(
        {
            "source_definitions": [
                {
                    "id": 1,
                    "kind": "powershell",
                    "name": "PSGallery",
                    "url": "https://www.powershellgallery.com/api/v2",
                    "enabled": True,
                    "settings": {"trusted": False},
                }
            ]
        }
    )

    assert result["status"] == "failed"
    assert result["source_results"][0]["success"] is False
    assert result["error"].startswith("No match was found")
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "powershell_repositories": ["PSGallery"]
    }


def test_helper_retries_failed_powershell_repository_removal(monkeypatch, tmp_path):
    """A failed unregister remains recorded until a later synchronization succeeds.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    state_path = tmp_path / "update-sources.json"
    state_path.write_text(
        json.dumps({"powershell_repositories": ["PrivateGallery"]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "MANAGED_PHOTON_REPO_PATH", tmp_path / "atlaso-managed.repo")
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", state_path)
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    attempts = 0

    def unregister_repository(command, *, success_codes=None, env=None):
        """Fail the first unregister attempt and allow its retry.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        nonlocal attempts
        attempts += 1
        success = attempts > 1
        return {
            "command": command,
            "returncode": 0 if success else 1,
            "success": success,
            "stdout": "removed" if success else "",
            "stderr": "transient unregister failure" if not success else "",
        }

    monkeypatch.setattr(helper, "_command_payload", unregister_repository)

    first = helper._sync_appliance_update_sources({"source_definitions": []})
    assert first["status"] == "failed"
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "powershell_repositories": ["PrivateGallery"]
    }

    second = helper._sync_appliance_update_sources({"source_definitions": []})
    assert second["status"] == "succeeded"
    assert attempts == 2
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "powershell_repositories": []
    }


def test_helper_source_sync_probes_powershell_repository_endpoint(monkeypatch, tmp_path):
    """Verify that helper source sync probes powershell repository endpoint.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import base64

    helper = load_helper_module()
    scripts = []
    monkeypatch.setattr(helper, "UPDATE_SOURCE_STATE_PATH", tmp_path / "update-sources.json")
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    monkeypatch.setattr(helper.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, None)])

    def fail_invalid_endpoint(command, *, success_codes=None, env=None):
        """Handle fail invalid endpoint.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        scripts.append(base64.b64decode(command[-1]).decode("utf-16-le"))
        return {
            "command": command,
            "returncode": 1,
            "success": False,
            "stdout": "",
            "stderr": "No match was found for the specified search criteria and repository name PrivateGallery.",
        }

    monkeypatch.setattr(helper, "_command_payload", fail_invalid_endpoint)
    result = helper._sync_appliance_update_sources(
        {
            "source_definitions": [
                {
                    "id": 1,
                    "kind": "powershell",
                    "name": "PrivateGallery",
                    "url": "https://packages.example.test/api/v21",
                    "enabled": True,
                    "settings": {"trusted": False},
                }
            ]
        }
    )

    assert result["status"] == "failed"
    assert result["error"].startswith("No match was found")
    assert result["source_results"] == [
        {"id": 1, "kind": "powershell", "name": "PrivateGallery", "success": False}
    ]
    assert "Set-PSRepository" in scripts[0]
    assert "Find-Module -Repository $repository.Name" in scripts[0]
    assert "https://packages.example.test/api/v21" in scripts[0]


def test_appliance_update_failure_message_uses_actionable_command_stderr():
    """Verify that appliance update failure message uses actionable command stderr."""
    from atlaso.app.ui import appliance_update_failure_message

    message = appliance_update_failure_message(
        {
            "success": False,
            "commands": [
                {
                    "command": ["resolve", "www.powershellgallery.com"],
                    "returncode": 1,
                    "stderr": "PowerShell repository PSGallery host www.powershellgallery.com could not be resolved.",
                }
            ],
        }
    )

    assert message == "PowerShell repository PSGallery host www.powershellgallery.com could not be resolved."


def test_helper_promotes_source_sync_failure_to_stderr(monkeypatch, tmp_path, capsys):
    """Verify that helper promotes source sync failure to stderr.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-update.json"
    config_path.write_text("{}\n", encoding="utf-8")
    message = "PowerShell repository PSGallery host www.powershellgallery.com could not be resolved."
    monkeypatch.setattr(helper, "_validate_appliance_update_config_path", lambda _path: config_path)
    monkeypatch.setattr(helper, "_load_appliance_update_config", lambda _path: {"source_definitions": []})
    monkeypatch.setattr(helper, "_load_appliance_update_credentials", lambda _args: {})
    monkeypatch.setattr(helper, "_appliance_update_config_errors", lambda _payload, require_streams: [])
    monkeypatch.setattr(
        helper,
        "_sync_appliance_update_sources",
        lambda _payload, _credentials: {"status": "failed", "commands": [], "error": message},
    )

    assert helper._handle_appliance_update("sync-sources", [str(config_path)]) == 1
    captured = capsys.readouterr()
    assert message in captured.err


def test_helper_photon_check_parses_and_truncates_candidate_rows(monkeypatch):
    """Use the tdnf return-code contract and retain bounded package details.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    helper = load_helper_module()
    rows = [
        f"package-{index}.x86_64 2.{index}-1 photon-updates"
        for index in range(105)
    ]

    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        helper,
        "_photon_python_compatibility",
        lambda: {
            "command": ["python-compatibility"],
            "returncode": 0,
            "success": True,
            "stdout": "compatible",
            "stderr": "",
        },
    )

    def fake_command(command, *, success_codes=None, env=None, stdout_limit=4000):
        """Return stable tdnf and rpm evidence for the check.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
            stdout_limit: Maximum retained standard output.
        """
        if command[1:] == ["check-update"]:
            return {
                "command": command,
                "returncode": 100,
                "success": True,
                "stdout": "\n".join(rows),
                "stderr": "",
            }
        if command[0].endswith("rpm"):
            names = command[4:]
            return {
                "command": command,
                "returncode": 0,
                "success": True,
                "stdout": "\n".join(f"{name}\t0:1.0-1" for name in names),
                "stderr": "",
            }
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_command_payload", fake_command)
    result = helper._check_appliance_update(
        {"selected_streams": ["photon_os"], "source_definitions": []}
    )

    check = result["checks"]["photon_os"]
    assert check["state"] == "available"
    assert check["change_count"] == 105
    assert len(check["changes"]) == 100
    assert check["changes"][0] == {
        "name": "package-0",
        "current": "0:1.0-1",
        "target": "2.0-1",
        "action": "upgrade",
        "summary": "package-0 from photon-updates",
    }
    assert check["details_incomplete"] is True
    assert result["commands"][1]["returncode"] == 100
    assert len(result["commands"][1]["stdout"]) <= 4000


def test_helper_powershell_check_reports_truthful_version_actions(monkeypatch, tmp_path):
    """Distinguish add, upgrade, side-by-side, and current module states.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Temporary filesystem path fixture.
    """
    import base64

    helper = load_helper_module()
    powershell_home = tmp_path / "powershell"
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", powershell_home)
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")
    evidence = {
        "Add.Tools": ("2.0.0", []),
        "Upgrade.Tools": ("2.0.0", ["1.0.0"]),
        "SideBySide.Tools": ("1.0.0", ["2.0.0"]),
        "Current.Tools": ("2.0.0", ["1.0.0", "2.0.0"]),
    }

    def fake_command(command, *, success_codes=None, env=None, stdout_limit=4000):
        """Return PowerShell module version evidence.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
            stdout_limit: Maximum retained standard output.
        """
        script = base64.b64decode(command[-1]).decode("utf-16-le")
        name = next(candidate for candidate in evidence if candidate in script)
        available, installed = evidence[name]
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": json.dumps(
                {
                    "Name": name,
                    "AvailableVersion": available,
                    "InstalledVersions": installed,
                }
            ),
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_command_payload", fake_command)
    result = helper._check_appliance_update(
        {
            "selected_streams": ["powershell_modules"],
            "sources": {
                "powershell_repository_name": "PSGallery",
                "powershell_repository_url": "https://www.powershellgallery.com/api/v2",
            },
            "powershell_modules": [
                {"name": name, "repository_name": "PSGallery"}
                for name in evidence
            ],
        }
    )

    check = result["checks"]["powershell_modules"]
    assert check["state"] == "available"
    assert {row["name"]: row["action"] for row in check["changes"]} == {
        "Add.Tools": "add",
        "Upgrade.Tools": "upgrade",
        "SideBySide.Tools": "side-by-side",
    }
    assert "Current.Tools" not in {row["name"] for row in check["changes"]}
    assert all("remove" not in row["action"] for row in check["changes"])


def test_helper_powershell_check_ignores_unreferenced_unsynchronized_repository(
    monkeypatch, tmp_path
):
    """Validate only repositories referenced by managed PowerShell modules.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Temporary filesystem path fixture.
    """
    helper = load_helper_module()
    powershell_home = tmp_path / "powershell"
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", powershell_home)
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")

    def fake_command(command, *, success_codes=None, env=None, stdout_limit=4000):
        """Return one current managed-module result.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
            stdout_limit: Maximum retained standard output.
        """
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": json.dumps(
                {
                    "Name": "Current.Tools",
                    "AvailableVersion": "2.0.0",
                    "InstalledVersions": ["2.0.0"],
                }
            ),
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_command_payload", fake_command)
    payload = {
        "selected_streams": ["powershell_modules"],
        "sources": {
            "powershell_repository_name": "PSGallery",
            "powershell_repository_url": "https://www.powershellgallery.com/api/v2",
        },
        "source_definitions": [
            {
                "kind": "powershell",
                "name": "PSGallery",
                "enabled": True,
                "validation_status": "valid",
            },
            {
                "kind": "powershell",
                "name": "UnusedGallery",
                "enabled": True,
                "validation_status": "pending",
            },
        ],
        "powershell_modules": [
            {"name": "Current.Tools", "repository_name": "PSGallery"}
        ],
    }

    current = helper._check_appliance_update(payload)["checks"]["powershell_modules"]
    assert current["state"] == "up_to_date"

    payload["powershell_modules"][0]["repository_name"] = "UnusedGallery"
    blocked = helper._check_appliance_update(payload)["checks"]["powershell_modules"]
    assert blocked["state"] == "failed"
    assert "UnusedGallery" in blocked["remediation"]


def test_helper_atlaso_check_uses_signed_summary_and_legacy_fallback(monkeypatch):
    """Expose optional signed release metadata without fabricating legacy notes.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    helper = load_helper_module()
    release = {
        "version": "0.9.999",
        "git_commit": "a" * 40,
        "supported_python_abis": [helper._current_python_abi()],
        "signing_key_id": "test-key",
        "bundle": {"sha256": "b" * 64},
        "summary": "Improve durable update visibility",
        "release_notes_url": "https://example.test/releases/v0.9.999",
    }
    monkeypatch.setattr(
        helper,
        "_download_signed_release_from_sources",
        lambda _payload, _credentials: (
            {"channel": "stable"},
            release,
            "https://example.test/releases/manifest.json",
            None,
        ),
    )
    payload = {
        "selected_streams": ["atlaso_release"],
        "current": {"base_version": "0.9.1"},
    }
    current = helper._check_appliance_update(payload)["checks"]["atlaso_release"]
    assert current["summary"] == "Improve durable update visibility"
    assert current["release_notes_url"] == "https://example.test/releases/v0.9.999"

    release.pop("summary")
    release.pop("release_notes_url")
    legacy = helper._check_appliance_update(payload)["checks"]["atlaso_release"]
    assert legacy["summary"] == f"Signed Atlaso release 0.9.999 at {'a' * 12}"
    assert legacy["release_notes_url"] == ""


def test_release_manifest_optional_summary_fields_are_backward_compatible_and_safe():
    """Accept legacy v2 manifests and reject unsafe optional publication metadata."""
    helper = load_helper_module()
    manifest = {
        "schema_version": 2,
        "kind": "atlaso-release",
        "updater_protocol": 2,
        "database_schema_version": 1,
        "version": "0.9.999",
        "git_commit": "a" * 40,
        "built_at": "2026-08-21T12:00:00Z",
        "signing_key_id": "test-key",
        "supported_python_abis": [helper._current_python_abi()],
        "bundle": {
            "url": "https://example.test/atlaso.tar.gz",
            "sha256": "b" * 64,
            "size": 123,
        },
        "content_hashes": {"packages/atlaso.whl": "c" * 64},
    }
    assert helper._validate_release_manifest(dict(manifest))["version"] == "0.9.999"

    enriched = {
        **manifest,
        "summary": "Improve update visibility",
        "release_notes_url": "https://example.test/releases/v0.9.999",
    }
    assert helper._validate_release_manifest(enriched)["summary"] == "Improve update visibility"

    for invalid in (
        {**manifest, "summary": "first\nsecond"},
        {**manifest, "release_notes_url": "http://example.test/release"},
        {**manifest, "release_notes_url": "https://user:secret@example.test/release"},
        {**manifest, "release_notes_url": "https://example.test/" + "a" * 2049},
    ):
        try:
            helper._validate_release_manifest(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe optional release metadata was accepted")


def test_helper_uses_each_modules_bound_powershell_repository(monkeypatch, tmp_path):
    """Verify that helper uses each modules bound powershell repository.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import base64

    helper = load_helper_module()
    scripts = []
    environments = []
    powershell_home = tmp_path / "powershell"
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", powershell_home)
    monkeypatch.setattr(helper, "_command_path", lambda _name: "/usr/bin/pwsh")

    def fake_command(command, *, success_codes=None, env=None, stdout_limit=4000):
        """Return fake command.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
            stdout_limit: Maximum retained standard output.
        """
        scripts.append(base64.b64decode(command[-1]).decode("utf-16-le"))
        environments.append(env)
        module_name = "Private.Tools" if "Private.Tools" in scripts[-1] else "VCF.PowerCLI"
        available = "2.0.0" if module_name == "Private.Tools" else "9.1.0"
        installed = ["1.0.0"] if module_name == "Private.Tools" else []
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": json.dumps(
                {
                    "Name": module_name,
                    "AvailableVersion": available,
                    "InstalledVersions": installed,
                }
            ),
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_command_payload", fake_command)
    result = helper._check_appliance_update(
        {
            "selected_streams": ["powershell_modules"],
            "sources": {
                "powershell_repository_name": "PSGallery",
                "powershell_repository_url": "https://www.powershellgallery.com/api/v2",
            },
            "powershell_modules": [
                {"name": "VCF.PowerCLI", "repository_name": "PSGallery", "target_version": "9.1.0"},
                {"name": "Private.Tools", "repository_name": "PrivateGallery", "target_version": ""},
            ],
        }
    )
    changes = result["checks"]["powershell_modules"]["changes"]
    assert [change["name"] for change in changes] == ["VCF.PowerCLI", "Private.Tools"]
    assert changes[0]["action"] == "add"
    assert changes[1]["action"] == "upgrade"
    assert any("-Repository 'PrivateGallery'" in script for script in scripts)
    assert all(environment["HOME"] == str(powershell_home) for environment in environments)


def test_helper_normalizes_system_powershell_module_permissions_after_install(monkeypatch, tmp_path):
    """Verify that helper normalizes system powershell module permissions after install.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    powershell_root = tmp_path / "powershell"
    module_root = powershell_root / "Modules"
    commands = []

    def fake_command(command, *, success_codes=None, env=None):
        """Return fake command.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        commands.append(command)
        return {"command": command, "returncode": 0, "success": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(helper, "POWERSHELL_SYSTEM_ROOT", powershell_root)
    monkeypatch.setattr(helper, "POWERSHELL_MODULE_ROOT", module_root)
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "_command_payload", fake_command)

    result = helper._apply_powershell_modules(
        {
            "sources": {"powershell_repository_name": "PSGallery"},
            "powershell_modules": [
                {
                    "name": "VCF.PowerCLI",
                    "repository_name": "PSGallery",
                    "target_version": "9.1.0.25380678",
                    "policy": "pinned",
                }
            ],
        }
    )

    assert len(result) == 3
    assert commands[-2] == ["/usr/bin/chmod", "0755", str(powershell_root), str(module_root)]
    assert commands[-1] == ["/usr/bin/chmod", "-R", "a+rX,go-w", str(module_root)]


def test_helper_reasserts_global_ceip_after_powercli_install(monkeypatch, tmp_path):
    """Verify that helper reasserts global ceip after powercli install.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    import base64

    helper = load_helper_module()
    scripts = []
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")

    def fake_command(command, *, success_codes=None, env=None):
        """Return fake command.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        if command[0].endswith("pwsh"):
            scripts.append(base64.b64decode(command[-1]).decode("utf-16-le"))
        return {"command": command, "returncode": 0, "success": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "_command_payload", fake_command)

    helper._apply_powershell_modules(
        {
            "sources": {"powershell_repository_name": "PSGallery"},
            "powershell_modules": [
                {
                    "name": "VCF.PowerCLI",
                    "repository_name": "PSGallery",
                    "target_version": "9.1.0.25380678",
                    "policy": "pinned",
                }
            ],
            "policy": {"vmware_ceip_enabled": True},
        }
    )

    assert len(scripts) == 1
    assert "Set-PowerCLIConfiguration -ParticipateInCeip $true -Scope AllUsers -Confirm:$false" in scripts[0]
    assert "Get-PowerCLIConfiguration -Scope AllUsers" in scripts[0]


def test_helper_reports_powershell_permission_normalization_failure(monkeypatch, tmp_path):
    """Verify that helper reports powershell permission normalization failure.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    helper = load_helper_module()
    powershell_root = tmp_path / "powershell"
    module_root = powershell_root / "Modules"

    def fake_command(command, *, success_codes=None, env=None):
        """Return fake command.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
            env: Environment variables supplied to the child process.
        """
        failed = command[:3] == ["/usr/bin/chmod", "-R", "a+rX,go-w"]
        return {
            "command": command,
            "returncode": 1 if failed else 0,
            "success": not failed,
            "stdout": "",
            "stderr": "permission normalization failed" if failed else "",
        }

    monkeypatch.setattr(helper, "POWERSHELL_SYSTEM_ROOT", powershell_root)
    monkeypatch.setattr(helper, "POWERSHELL_MODULE_ROOT", module_root)
    monkeypatch.setattr(helper, "ATLASO_POWERSHELL_HOME", tmp_path / "powershell-home")
    monkeypatch.setattr(
        helper,
        "APPLIANCE_UPDATE_INFO_PATH",
        tmp_path / "atlaso-update-info.json",
    )
    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper, "_command_payload", fake_command)

    result = helper._apply_appliance_update(
        {
            "selected_streams": ["powershell_modules"],
            "sources": {"powershell_repository_name": "PSGallery"},
            "powershell_modules": [
                {
                    "name": "VCF.PowerCLI",
                    "repository_name": "PSGallery",
                    "target_version": "9.1.0.25380678",
                    "policy": "pinned",
                }
            ],
        }
    )

    assert result["status"] == "failed"
    assert result["applied"] == {}
    assert result["commands"][-1]["command"] == [
        "/usr/bin/chmod",
        "-R",
        "a+rX,go-w",
        str(module_root),
    ]
    assert result["commands"][-1]["success"] is False


def test_helper_runs_managed_script_in_unprivileged_systemd_sandbox(monkeypatch, tmp_path):
    """Verify that helper runs managed script in unprivileged systemd sandbox.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    from types import SimpleNamespace

    helper = load_helper_module()
    script_root = tmp_path / "scripts"
    run_root = tmp_path / "runs"
    script_root.mkdir()
    script_path = script_root / "job_1.sh"
    script_path.write_text("date\n", encoding="utf-8")
    monkeypatch.setattr(helper, "AUTOMATION_SCRIPT_DIR", script_root)
    monkeypatch.setattr(helper, "AUTOMATION_RUN_DIR", run_root)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1234, pw_gid=1234))
    monkeypatch.setattr(helper, "_chown_path", lambda *_args: None)
    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "systemd-run" else None)
    captured = {}

    def fake_run(command):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="completed\n", stderr="")

    monkeypatch.setattr(helper, "_run", fake_run)
    assert helper._handle_automation("run", [str(script_path), "bash", "60", "--", "--scope", "lab environment"]) == 0
    command = captured["command"]
    assert "--uid=atlaso-automation" in command
    assert "--property=NoNewPrivileges=yes" in command
    assert "--property=ProtectSystem=strict" in command
    writable_path = Path(next(argument.split("=", 2)[2] for argument in command if argument.startswith("--property=ReadWritePaths=")))
    assert writable_path.parent == run_root
    assert f"--property=WorkingDirectory={writable_path}" in command
    assert f"--setenv=HOME={writable_path}" in command
    assert f"--setenv=XDG_CACHE_HOME={writable_path / '.cache'}" in command
    assert command[-4:] == ["/usr/bin/bash", str(script_path.resolve()), "--scope", "lab environment"]


def test_helper_loads_scoped_vault_credential_and_redacts_output(monkeypatch, tmp_path, capsys):
    """Verify that helper loads scoped vault credential and redacts output.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    from types import SimpleNamespace

    helper = load_helper_module()
    script_root = tmp_path / "scripts"
    run_root = tmp_path / "runs"
    vault_root = tmp_path / "vaults"
    script_root.mkdir()
    vault_root.mkdir()
    script_path = script_root / "job_2.sh"
    script_path.write_text("atlaso-vault get --key esx.root\n", encoding="utf-8")
    vault_path = vault_root / "job_2.json"
    vault_path.write_text(
        json.dumps({"version": 1, "values": {"esx.root": "VMware1!"}}),
        encoding="utf-8",
    )
    vault_path.chmod(0o600)
    monkeypatch.setattr(helper, "AUTOMATION_SCRIPT_DIR", script_root)
    monkeypatch.setattr(helper, "AUTOMATION_RUN_DIR", run_root)
    monkeypatch.setattr(helper, "AUTOMATION_VAULT_DIR", vault_root)
    monkeypatch.setattr(helper.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1234, pw_gid=1234))
    monkeypatch.setattr(helper, "_chown_path", lambda *_args: None)
    monkeypatch.setattr(helper, "_command_path", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(helper.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "systemd-run" else None)
    commands = []

    def fake_run(command):
        """Return fake run.

        Args:
            command: Command and arguments to execute.
        """
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="password=VMware1!\n", stderr="")

    monkeypatch.setattr(helper, "_run", fake_run)
    assert helper._handle_automation(
        "run",
        [str(script_path), "bash", "60", "--vault", str(vault_path), "--"],
    ) == 0
    assert f"--property=LoadCredential=atlaso-vault:{vault_path.resolve()}" in commands[0]
    output = capsys.readouterr()
    assert "password=[redacted]" in output.out
    assert "VMware1!" not in output.out


def test_helper_rejects_appliance_update_config_outside_apply_dir(tmp_path):
    """Verify that helper rejects appliance update config outside apply dir.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.


    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    helper = load_helper_module()
    config_path = tmp_path / "atlaso-update.json"
    config_path.write_text("{}", encoding="utf-8")

    try:
        helper._validate_appliance_update_config_path(str(config_path))
    except ValueError as exc:
        assert "must be staged under" in str(exc)
    else:
        raise AssertionError("expected helper to reject config outside appliance update apply dir")


def test_helper_rejects_unsigned_v1_release_manifest(monkeypatch, tmp_path, capsys):
    """Verify that helper rejects unsigned v1 release manifest.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-update"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-update.json"
    config_path.write_text(
        json.dumps(
            {
                "selected_streams": ["atlaso_release"],
                    "sources": {"atlaso_manifest_urls": ["https://updates.local/manifest.json"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "APPLIANCE_UPDATE_APPLY_DIR", apply_dir)

    def fake_fetch(url: str, _credential=None) -> bytes:
        """Return fake fetch.

        Args:
            url: URL contacted or emitted by the operation.
            _credential: Credential supplied to the test scenario.
        """
        if url.endswith("manifest.json"):
            return json.dumps(
                {
                    "version": "0.1.0+gabc",
                    "git_commit": "abcdef1234567890abcdef1234567890abcdef12",
                    "wheel": "atlaso-0.1.0.whl",
                    "sha256": "0" * 64,
                }
            ).encode("utf-8")
        return b"not-a-detached-signature"

    monkeypatch.setattr(helper, "_fetch_http_bytes", fake_fetch)

    assert helper._handle_appliance_update("apply", [str(config_path)]) == 1
    captured = capsys.readouterr()
    assert "signature" in captured.err


def test_helper_rejects_credentialed_update_urls(tmp_path, capsys):
    """Verify that helper rejects credentialed update urls.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
        capsys: Pytest fixture used to capture standard output and standard error.
    """
    helper = load_helper_module()
    apply_dir = tmp_path / "apply" / "appliance-update"
    apply_dir.mkdir(parents=True)
    config_path = apply_dir / "atlaso-update.json"
    config_path.write_text(
        json.dumps(
            {
                "selected_streams": ["atlaso_release"],
                    "sources": {"atlaso_manifest_urls": ["https://user:token@example.test/manifest.json"]},
            }
        ),
        encoding="utf-8",
    )
    helper.APPLIANCE_UPDATE_APPLY_DIR = apply_dir

    assert helper._handle_appliance_update("check", [str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "must not include embedded credentials" in captured.err


def test_helper_writes_failed_update_info_for_failed_commands(monkeypatch):
    """Verify that helper writes failed update info for failed commands.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    written = {}

    def fake_command_payload(command, *, success_codes=None):
        """Return fake command payload.

        Args:
            command: Command and arguments to execute.
            success_codes: Success codes supplied to the test scenario.
        """
        return {"command": command, "returncode": 1, "success": False, "stdout": "", "stderr": "failed"}

    monkeypatch.setattr(helper, "_command_payload", fake_command_payload)
    monkeypatch.setattr(helper, "_command_path", lambda command: command)
    monkeypatch.setattr(helper, "_write_update_info", lambda payload: written.update(payload))

    result = helper._apply_appliance_update(
        {
            "job_id": "job_photon_evidence_identity",
            "selected_streams": ["photon_os"],
            "sources": {},
        }
    )
    assert result["status"] == "failed"
    assert result["applied"] == {}
    assert result["attempted"]["photon_os"]["automatic_rpm_rollback"] is False
    assert result["reboot_recommended"] is False
    assert "error" in result
    assert written["status"] == "failed"
    assert written["job_id"] == "job_photon_evidence_identity"
    assert written["selected_streams"] == ["photon_os"]


def test_helper_queries_photon_python_without_unsupported_latest_limit(monkeypatch):
    """Verify that helper queries photon python without unsupported latest limit.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    helper = load_helper_module()
    captured = {}

    monkeypatch.setattr(helper, "_command_path", lambda command: f"/usr/bin/{command}")

    def fake_command_payload(command, **_kwargs):
        """Return fake command payload.

        Args:
            command: Command and arguments to execute.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        captured["command"] = command
        return {
            "command": command,
            "returncode": 0,
            "success": True,
            "stdout": "python3-3.12.9-1.ph5.x86_64\npython3-3.14.5-2.ph5.x86_64\n",
            "stderr": "",
        }

    monkeypatch.setattr(helper, "_command_payload", fake_command_payload)

    command, abi = helper._candidate_photon_python_abi()

    assert captured["command"] == ["/usr/bin/tdnf", "repoquery", "python3"]
    assert command["success"] is True
    assert abi == "cp314"
