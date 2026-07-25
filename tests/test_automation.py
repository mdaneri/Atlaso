import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from labfoundry.app.services.automation import next_cron_run, parse_cron_expression, parse_script_arguments


def login(client):
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "labfoundry-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def csrf_from_page(text: str) -> str:
    return text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_cron_parser_supports_steps_ranges_and_sunday_alias():
    minute, hour, day, month, weekday = parse_cron_expression("*/15 1-3 * * 5-7")
    assert minute == {0, 15, 30, 45}
    assert hour == {1, 2, 3}
    assert day == set(range(1, 32))
    assert month == set(range(1, 13))
    assert weekday == {0, 5, 6}


def test_script_parameters_parse_interpreter_continuations_without_shell_evaluation():
    bash_parameters = "--server " + "\\" + "\n'vcf lab.example' " + "\\" + "\n--literal '$HOME'"
    assert parse_script_arguments(bash_parameters, "bash") == ["--server", "vcf lab.example", "--literal", "$HOME"]
    assert parse_script_arguments("-Server `\n'vcf lab.example' `\n-Literal '$HOME'", "powershell") == [
        "-Server",
        "vcf lab.example",
        "-Literal",
        "$HOME",
    ]
    assert parse_script_arguments("''", "powershell") == [""]
    with pytest.raises(ValueError, match="unterminated quote"):
        parse_script_arguments("-Server 'vcf.example", "powershell")


def test_cron_uses_selected_timezone_and_standard_day_or_weekday_behavior():
    after = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
    assert next_cron_run("0 6 * * *", "America/Los_Angeles", after=after) == datetime(
        2026, 7, 20, 13, 0, tzinfo=timezone.utc
    )
    # The 21st is a Tuesday. Standard cron matches when either restricted day field matches.
    assert next_cron_run("0 0 21 * 1", "UTC", after=after) == datetime(
        2026, 7, 21, 0, 0, tzinfo=timezone.utc
    )


def test_managed_script_rejects_content_larger_than_one_mibibyte(client):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import AutomationScript
    from labfoundry.app.services.automation import create_script_revision

    client.get("/login")
    with SessionLocal() as db:
        script = AutomationScript(name="oversized-script", description="size guard", created_by="admin")
        db.add(script)
        db.flush()
        with pytest.raises(ValueError, match="Script content must be 1 MiB or smaller"):
            create_script_revision(
                db,
                script=script,
                interpreter="bash",
                timeout_seconds=60,
                content="x" * (1024 * 1024 + 1),
                actor="admin",
            )


def test_managed_script_revision_is_immutable_enabled_and_run_by_worker(client):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import AutomationScript, AutomationScriptRevision, Job
    from labfoundry.app.worker import run_worker_once

    login(client)
    page = client.get("/automation")
    assert page.status_code == 200
    assert "Managed Scripts" in page.text
    assert "Download profile" in page.text
    assert 'aria-label="Automation workspace"' in page.text
    assert 'data-tab-target="automation-schedules-panel"' in page.text
    assert 'data-tab-target="automation-executions-panel"' in page.text
    assert 'data-tab-target="scripts"' in page.text
    assert 'id="automation-executions-table"' in page.text
    assert 'id="automation-executions-data"' in page.text
    assert 'id="automation-schedule-modal"' in page.text
    assert 'data-automation-wizard-step="identity"' in page.text
    assert 'data-automation-wizard-step="config"' in page.text
    assert 'data-automation-wizard-step="timing"' in page.text
    assert 'data-automation-wizard-step="state"' in page.text
    assert 'data-automation-wizard-step="review"' in page.text
    assert 'data-automation-wizard-nav' in page.text
    assert 'automation-fill-grid' in page.text
    assert 'id="automation-schedule-edit-' not in page.text
    assert 'id="automation-script-modal"' in page.text
    assert 'id="automation-script-run-modal"' in page.text
    assert 'data-automation-script-run-arguments' in page.text
    assert 'id="automation-script-diff-modal"' in page.text
    assert 'data-automation-script-diff-table' in page.text
    assert 'data-automation-script-diff-added' in page.text
    assert 'data-automation-script-diff-removed' in page.text
    assert "data-automation-schedule-kind" in page.text
    assert 'data-automation-schedule-timing="cron"' in page.text
    assert 'data-automation-schedule-timing="once"' in page.text
    assert 'data-automation-cron-frequency' in page.text
    assert 'data-automation-cron-expression' in page.text
    assert 'data-automation-cron-summary' in page.text
    assert 'data-automation-script-revision' in page.text
    assert 'data-automation-script-arguments' in page.text
    assert "automation-option-grid" in page.text
    assert 'id="automation-script-content"' in page.text
    assert "data-codemirror-editor" in page.text
    assert "data-automation-script-file" in page.text
    assert "data-automation-script-source-confirm" in page.text
    assert 'id="automation-script-grid-status"' in page.text
    assert "Import script file" in page.text
    assert "<summary>+ Add schedule here</summary>" not in page.text
    assert "<summary>+ Add managed script here</summary>" not in page.text
    csrf = csrf_from_page(page.text)
    response = client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "inventory-report",
            "description": "Collect a bounded inventory report",
            "interpreter": "powershell",
            "timeout_seconds": "60",
            "content": "Get-Date",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    with SessionLocal() as db:
        script = db.execute(select(AutomationScript).where(AutomationScript.name == "inventory-report")).scalar_one()
        revision = db.execute(
            select(AutomationScriptRevision).where(AutomationScriptRevision.script_id == script.id)
        ).scalar_one()
        assert revision.revision == 1
        assert revision.enabled is False
        script_id = script.id
        revision_id = revision.id

    assert client.post(
        f"/automation/scripts/{script_id}/edit",
        data={"csrf": csrf, "name": "inventory-report-renamed", "description": "Updated from the editable grid"},
        follow_redirects=False,
    ).status_code == 303
    with SessionLocal() as db:
        edited_script = db.get(AutomationScript, script_id)
        assert edited_script.name == "inventory-report-renamed"
        assert edited_script.description == "Updated from the editable grid"

    page = client.get("/automation")
    assert "inventory-report-renamed revisions</summary>" not in page.text
    csrf = csrf_from_page(page.text)
    assert client.post(
        f"/automation/scripts/revisions/{revision_id}/toggle",
        data={"csrf": csrf},
        follow_redirects=False,
    ).status_code == 303
    assert client.post(
        f"/automation/scripts/revisions/{revision_id}/run",
        data={"csrf": csrf},
        follow_redirects=False,
    ).status_code == 303
    assert run_worker_once() is not None

    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "managed-script")).scalar_one()
        payload = json.loads(job.result)
        task_config = json.loads(job.task_config_json)
        assert job.status == "succeeded"
        assert task_config["arguments"] == []
        assert payload["dry_run"] is True
        assert payload["content_sha256"] == revision.content_sha256
        assert payload["command"][1:3] == ["automation", "run"]
        assert not (Path("data") / "automation" / "scripts" / f"{job.id}.ps1").exists()


def test_manual_script_run_collects_parameters_and_exposes_revision_diff(client):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import AutomationScript, AutomationScriptRevision, Job

    login(client)
    page = client.get("/automation")
    csrf = csrf_from_page(page.text)
    assert client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "revision-diff-script",
            "description": "Compare immutable source",
            "interpreter": "powershell",
            "timeout_seconds": "60",
            "content": "Write-Output 'first'",
        },
        follow_redirects=False,
    ).status_code == 303
    with SessionLocal() as db:
        script = db.execute(select(AutomationScript).where(AutomationScript.name == "revision-diff-script")).scalar_one()
        script_id = script.id

    assert client.post(
        f"/automation/scripts/{script_id}/revisions",
        data={
            "csrf": csrf,
            "interpreter": "powershell",
            "timeout_seconds": "90",
            "content": "Write-Output 'second'\nWrite-Output $args.Count",
        },
        follow_redirects=False,
    ).status_code == 303
    with SessionLocal() as db:
        revisions = db.execute(
            select(AutomationScriptRevision)
            .where(AutomationScriptRevision.script_id == script_id)
            .order_by(AutomationScriptRevision.revision)
        ).scalars().all()
        assert [revision.revision for revision in revisions] == [1, 2]
        latest_revision_id = revisions[-1].id

    assert client.post(
        f"/automation/scripts/revisions/{latest_revision_id}/toggle",
        data={"csrf": csrf},
        follow_redirects=False,
    ).status_code == 303

    page = client.get("/automation")
    rows_payload = page.text.split('<script type="application/json" id="automation-scripts-data">', 1)[1].split("</script>", 1)[0]
    rows = json.loads(rows_payload)
    row = next(item for item in rows if item["id"] == script_id)
    assert [revision["revision"] for revision in row["revisions"]] == [1, 2]
    assert row["revisions"][0]["content"] == "Write-Output 'first'"
    assert row["revisions"][1]["content"].endswith("Write-Output $args.Count")
    assert all(revision["created_at"] for revision in row["revisions"])

    app_js = Path("labfoundry/app/static/app.js").read_text()
    assert 'label: "Run latest revision"' in app_js
    assert 'label: "Compare latest revisions"' in app_js
    assert 'class="automation-revision-button"' in app_js
    assert 'class="automation-revision-diff-table"' in page.text
    assert "data-automation-script-diff-previous" in page.text
    assert "data-automation-script-diff-current" in page.text
    assert "sideBySideRevisionDiff" in app_js
    assert "revisionOptionLabel" in app_js
    assert "revisionCreatedLabel" in app_js
    assert "highlightScriptDiffLine" in app_js
    assert 'window.Prism.highlight(String(line || ""), grammar, language)' in app_js
    assert 'collapsed.textContent = `${row.count} unchanged lines`' in app_js
    assert 'code.className = `automation-diff-code ${state}' in app_js
    assert "Queue latest revision" not in app_js

    parameters = "-Server `\n'vcf lab.example' `\n-Count 2"
    response = client.post(
        f"/automation/scripts/revisions/{latest_revision_id}/run",
        data={"csrf": csrf, "script_arguments": parameters},
        follow_redirects=False,
    )
    assert response.status_code == 303
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "managed-script")).scalar_one()
        assert json.loads(job.task_config_json)["arguments"] == ["-Server", "vcf lab.example", "-Count", "2"]


def test_due_schedule_queues_one_job_and_skips_overlap(client):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import Job, JobStep, Schedule
    from labfoundry.app.services.automation import enqueue_due_schedules

    # Initialize and seed the fixture database.
    client.get("/login")
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        schedule = Schedule(
            name="nightly-update-check",
            task_type="appliance_update_check",
            task_config_json=json.dumps({"selected_streams": ["photon_os"]}),
            schedule_kind="cron",
            cron_expression="0 2 * * *",
            timezone_name="UTC",
            enabled=True,
            next_run_at=now - timedelta(minutes=1),
            created_by="admin",
        )
        db.add(schedule)
        db.commit()
        schedule_id = schedule.id

    with SessionLocal() as db:
        jobs = enqueue_due_schedules(db, now=now)
        assert len(jobs) == 1
        assert jobs[0].trigger == "scheduled"
        assert json.loads(jobs[0].task_config_json)["mode"] == "check"
        steps = db.execute(select(JobStep).where(JobStep.job_id == jobs[0].id)).scalars().all()
        assert [(step.component_key, step.status) for step in steps] == [("photon_os", "pending")]

    with SessionLocal() as db:
        schedule = db.get(Schedule, schedule_id)
        schedule.next_run_at = now - timedelta(seconds=1)
        db.add(schedule)
        db.commit()
        assert enqueue_due_schedules(db, now=now) == []
        assert len(db.execute(select(Job).where(Job.schedule_id == schedule_id)).scalars().all()) == 1


def test_worker_rejects_queued_vcf_download_when_profile_was_disabled(client, monkeypatch):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import Job, JobStatus, VcfDepotDownloadProfile
    from labfoundry.app.worker import run_worker_once
    import labfoundry.app.ui as ui

    client.get("/login")
    called = []
    monkeypatch.setattr(ui, "run_vcf_depot_download_job", lambda *_args: called.append(True))
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="disabled-after-queue", enabled=False)
        db.add(profile)
        db.flush()
        job = Job(
            id="job_disabled_vcf_profile",
            type="vcf-depot-download",
            status=JobStatus.PENDING.value,
            created_by="admin",
            progress_percent=0,
            task_config_json=json.dumps({"profile_id": profile.id}),
            result="{}",
        )
        db.add(job)
        db.commit()

    assert run_worker_once() == "job_disabled_vcf_profile"
    assert called == []
    with SessionLocal() as db:
        failed = db.get(Job, "job_disabled_vcf_profile")
        assert failed.status == JobStatus.FAILED.value
        assert "Enable the scheduled VCF Offline Depot profile" in failed.error


def test_schedule_edit_run_now_and_script_dependency_guards(client):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import AutomationScript, AutomationScriptRevision, Job, Schedule
    from labfoundry.app.worker import run_worker_once

    login(client)
    csrf = csrf_from_page(client.get("/automation").text)
    assert client.post(
        "/automation/scripts",
        data={"csrf": csrf, "name": "scheduled-inventory", "description": "dependency guard test", "interpreter": "bash", "timeout_seconds": "30", "content": "date"},
        follow_redirects=False,
    ).status_code == 303
    with SessionLocal() as db:
        script = db.execute(select(AutomationScript).where(AutomationScript.name == "scheduled-inventory")).scalar_one()
        revision = db.execute(select(AutomationScriptRevision).where(AutomationScriptRevision.script_id == script.id)).scalar_one()
        script_id = script.id
        revision_id = revision.id
    assert client.post(f"/automation/scripts/revisions/{revision_id}/toggle", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    nightly_parameters = "--scope " + "\\" + "\n'lab environment'"
    assert client.post(
        "/automation/schedules",
        data={"csrf": csrf, "name": "scheduled-inventory-nightly", "task_type": "managed_script", "revision_id": str(revision_id), "script_arguments": nightly_parameters, "schedule_kind": "cron", "cron_expression": "0 2 * * *", "timezone_name": "UTC", "enabled": "on"},
        follow_redirects=False,
    ).status_code == 303
    with SessionLocal() as db:
        schedule = db.execute(select(Schedule).where(Schedule.name == "scheduled-inventory-nightly")).scalar_one()
        schedule_id = schedule.id
        assert json.loads(schedule.task_config_json)["arguments"] == ["--scope", "lab environment"]

    assert client.post(f"/automation/scripts/revisions/{revision_id}/toggle", data={"csrf": csrf}, follow_redirects=False).status_code == 409
    assert client.post(f"/automation/scripts/{script_id}/delete", data={"csrf": csrf}, follow_redirects=False).status_code == 409
    daily_parameters = "-Mode " + "\\" + "\n'full scan'"
    edited = client.post(
        f"/automation/schedules/{schedule_id}/edit",
        data={"csrf": csrf, "name": "scheduled-inventory-daily", "task_type": "managed_script", "revision_id": str(revision_id), "script_arguments": daily_parameters, "schedule_kind": "cron", "cron_expression": "30 3 * * *", "timezone_name": "America/Los_Angeles", "enabled": "on"},
        follow_redirects=False,
    )
    assert edited.status_code == 303
    assert client.post(f"/automation/schedules/{schedule_id}/run", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        schedule = db.get(Schedule, schedule_id)
        assert schedule.name == "scheduled-inventory-daily"
        assert schedule.cron_expression == "30 3 * * *"
        assert schedule.timezone_name == "America/Los_Angeles"
        job = db.execute(select(Job).where(Job.schedule_id == schedule_id)).scalar_one()
        assert job.trigger == "manual_schedule"
        assert json.loads(job.task_config_json)["arguments"] == ["-Mode", "full scan"]

    assert run_worker_once() is not None
    with SessionLocal() as db:
        completed_job = db.execute(select(Job).where(Job.schedule_id == schedule_id)).scalar_one()
        result = json.loads(completed_job.result)
        assert result["arguments_count"] == 2
        assert result["command"][-3:] == ["--", "-Mode", "full scan"]
        completed_job_id = completed_job.id

    history_page = client.get("/automation")
    assert history_page.status_code == 200
    assert completed_job_id in history_page.text
    assert f"/tasks?job_id={completed_job_id}" in history_page.text
    assert "scheduled-inventory-daily" in history_page.text

    assert client.post(f"/automation/schedules/{schedule_id}/delete", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    deleted_schedule_history = client.get("/automation")
    assert completed_job_id in deleted_schedule_history.text
    assert "scheduled-inventory-daily" in deleted_schedule_history.text
    assert client.post(f"/automation/scripts/{script_id}/delete", data={"csrf": csrf}, follow_redirects=False).status_code == 303


def test_settings_archive_restores_sources_and_automation_disabled(client):
    from labfoundry.app.database import SessionLocal
    from labfoundry.app.models import AutomationScript, AutomationScriptRevision, Schedule, UpdateSource
    from labfoundry.app.services.automation import create_script_revision
    from labfoundry.app.services.settings_archive import export_settings_archive, restore_settings_archive

    client.get("/login")
    with SessionLocal() as db:
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "labfoundry")).scalar_one()
        source.url = "https://updates.example.test/labfoundry"
        source.credential_encrypted = "must-not-leave-appliance"
        db.add(source)
        script = AutomationScript(name="archive-script", description="archive test", created_by="admin")
        db.add(script)
        db.flush()
        revision = create_script_revision(
            db,
            script=script,
            interpreter="bash",
            content="date\n",
            timeout_seconds=30,
            actor="admin",
        )
        db.flush()
        revision.enabled = True
        schedule = Schedule(
            name="archive-schedule",
            task_type="managed_script",
            task_config_json=json.dumps({"revision_id": revision.id}),
            schedule_kind="cron",
            cron_expression="0 3 * * *",
            timezone_name="UTC",
            enabled=True,
            next_run_at=datetime.now(timezone.utc) + timedelta(days=1),
            created_by="admin",
        )
        db.add(schedule)
        db.commit()
        archive = export_settings_archive(db, actor="admin")

        source_payload = next(row for row in archive["data"]["update_sources"] if row["kind"] == "labfoundry")
        assert "credential_encrypted" not in source_payload
        restore_settings_archive(db, archive)

        restored_source = db.execute(select(UpdateSource).where(UpdateSource.kind == "labfoundry")).scalar_one()
        restored_revision = db.execute(
            select(AutomationScriptRevision).join(AutomationScript).where(AutomationScript.name == "archive-script")
        ).scalar_one()
        restored_schedule = db.execute(select(Schedule).where(Schedule.name == "archive-schedule")).scalar_one()
        assert restored_source.url == "https://updates.example.test/labfoundry"
        assert restored_source.credential_encrypted == ""
        assert restored_revision.enabled is False
        assert restored_schedule.enabled is False
        assert restored_schedule.next_run_at is None
        assert json.loads(restored_schedule.task_config_json)["revision_id"] == restored_revision.id
