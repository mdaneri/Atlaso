"""Test automation behavior."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from atlaso.app.services.automation import (
    next_cron_run,
    parse_cron_expression,
    parse_script_arguments,
)


def login(client):
    """Handle login.

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


def csrf_from_page(text: str) -> str:
    """Return csrf from page.

    Args:
        text: Text content consumed by the operation.
    """
    return text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_cron_parser_supports_steps_ranges_and_sunday_alias():
    """Verify that cron parser supports steps ranges and sunday alias."""
    minute, hour, day, month, weekday = parse_cron_expression("*/15 1-3 * * 5-7")
    assert minute == {0, 15, 30, 45}
    assert hour == {1, 2, 3}
    assert day == set(range(1, 32))
    assert month == set(range(1, 13))
    assert weekday == {0, 5, 6}


def test_script_parameters_parse_interpreter_continuations_without_shell_evaluation():
    """Verify that script parameters parse interpreter continuations without shell evaluation."""
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
    """Verify that cron uses selected timezone and standard day or weekday behavior."""
    after = datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc)
    assert next_cron_run("0 6 * * *", "America/Los_Angeles", after=after) == datetime(
        2026, 7, 20, 13, 0, tzinfo=timezone.utc
    )
    # The 21st is a Tuesday. Standard cron matches when either restricted day field matches.
    assert next_cron_run("0 0 21 * 1", "UTC", after=after) == datetime(
        2026, 7, 21, 0, 0, tzinfo=timezone.utc
    )


def test_vcf_schedule_profile_selector_shows_disabled_profiles_and_actionable_guidance(client):
    """Verify that vcf schedule profile selector shows disabled profiles and actionable guidance.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfDepotDownloadProfile

    login(client)
    with SessionLocal() as db:
        for profile in db.execute(select(VcfDepotDownloadProfile)).scalars().all():
            profile.enabled = False
        enabled = VcfDepotDownloadProfile(name="Enabled schedule profile", profile_type="metadata", enabled=True)
        disabled = VcfDepotDownloadProfile(name="Disabled schedule profile", profile_type="metadata", enabled=False)
        db.add_all([enabled, disabled])
        db.commit()
        enabled_id = enabled.id
        disabled_id = disabled.id

    page = client.get("/automation")
    assert page.status_code == 200
    assert '<option value="" disabled selected>Choose a profile</option>' in page.text
    assert f'<option value="{enabled_id}" >Enabled schedule profile</option>' in page.text
    assert f'<option value="{disabled_id}" disabled>Disabled schedule profile · disabled</option>' in page.text
    assert "Only enabled profiles can be scheduled." in page.text
    assert '<a href="/ui/management/vcf-offline-depot">Manage profiles in VCF Offline Depot</a>' in page.text

    with SessionLocal() as db:
        db.get(VcfDepotDownloadProfile, enabled_id).enabled = False
        db.commit()

    page = client.get("/automation")
    assert '<option value="" disabled selected>No enabled profiles</option>' in page.text
    assert "All configured download profiles are disabled." in page.text
    assert '<a href="/ui/management/vcf-offline-depot">Enable a profile in VCF Offline Depot</a>' in page.text


def test_managed_script_rejects_content_larger_than_one_mibibyte(client):
    """Verify that managed script rejects content larger than one mibibyte.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript
    from atlaso.app.services.automation import create_script_revision

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


def test_managed_script_normalizes_line_endings_and_rejects_a_malformed_bash_shebang(client):
    """Verify that managed script normalizes line endings and rejects a malformed bash shebang.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript
    from atlaso.app.services.automation import create_script_revision

    client.get("/login")
    with SessionLocal() as db:
        script = AutomationScript(name="normalized-script", description="line endings", created_by="admin")
        db.add(script)
        db.flush()
        revision = create_script_revision(
            db,
            script=script,
            interpreter="bash",
            timeout_seconds=60,
            content="\ufeff#!/bin/bash\r\necho ok\r\n",
            actor="admin",
        )
        assert revision.content == "#!/bin/bash\necho ok\n"
        assert revision.content_sha256 == hashlib.sha256(revision.content.encode("utf-8")).hexdigest()
        with pytest.raises(ValueError, match=r"shebang must start with #!"):
            create_script_revision(
                db,
                script=script,
                interpreter="bash",
                timeout_seconds=60,
                content="!/bin/bash\r\necho no\r\n",
                actor="admin",
            )


def test_managed_script_wizard_reports_a_malformed_bash_shebang(client):
    """Verify that managed script wizard reports a malformed bash shebang.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript

    login(client)
    csrf = csrf_from_page(client.get("/automation").text)
    response = client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "malformed-shebang",
            "interpreter": "bash",
            "timeout_seconds": "60",
            "content": "!/bin/bash\r\necho no\r\n",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "A Bash shebang must start with #!; add the missing # or remove the shebang line."
    )
    with SessionLocal() as db:
        assert db.execute(
            select(AutomationScript).where(AutomationScript.name == "malformed-shebang")
        ).scalar_one_or_none() is None


@pytest.mark.parametrize("wizard_request", [True, False])
def test_managed_script_source_validation_does_not_expose_backend_error(client, monkeypatch, wizard_request):
    """Verify that managed script source validation does not expose backend error.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        wizard_request: Wizard request supplied to the test scenario.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript

    login(client)
    csrf = csrf_from_page(client.get("/automation").text)

    def fail_source_validation(*_args, **_kwargs):
        """Handle fail source validation.

        Args:
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.
        """
        raise ValueError("private source validation detail")

    monkeypatch.setattr("atlaso.app.ui.normalize_script_content", fail_source_validation)
    headers = {"X-Atlaso-Wizard": "1", "Accept": "application/json"} if wizard_request else {}
    response = client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "source-validation-failure",
            "interpreter": "bash",
            "timeout_seconds": "120",
            "content": "#!/bin/bash\ndate",
        },
        headers=headers,
    )

    assert response.status_code == 422
    assert "Managed script source is invalid. Review the interpreter and source, then try again." in response.text
    assert "private source validation detail" not in response.text
    with SessionLocal() as db:
        assert db.execute(
            select(AutomationScript).where(AutomationScript.name == "source-validation-failure")
        ).scalar_one_or_none() is None


def test_managed_script_wizard_does_not_expose_unexpected_validation_errors(client, monkeypatch):
    """Verify that managed script wizard does not expose unexpected validation errors.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript

    login(client)
    csrf = csrf_from_page(client.get("/automation").text)

    def fail_revision(*_args, **_kwargs):
        """Handle fail revision.

        Args:
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.


        Raises:
            ValueError: If an input value is invalid.
        """
        raise ValueError("private implementation detail")

    monkeypatch.setattr("atlaso.app.ui.create_script_revision", fail_revision)
    response = client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "validation-failure",
            "interpreter": "bash",
            "timeout_seconds": "120",
            "content": "#!/bin/bash\ndate",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Managed script validation failed."
    assert "private implementation detail" not in response.text
    with SessionLocal() as db:
        assert db.execute(
            select(AutomationScript).where(AutomationScript.name == "validation-failure")
        ).scalar_one_or_none() is None


def test_managed_script_revision_is_immutable_enabled_and_run_by_worker(client):
    """Verify that managed script revision is immutable enabled and run by worker.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript, AutomationScriptRevision, Job
    from atlaso.app.worker import run_worker_once

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
    assert 'id="automation-script-create-dialog"' in page.text
    assert "data-automation-script-create-form" in page.text
    assert 'data-atlaso-wizard-step="identity"' in page.text
    assert 'data-atlaso-wizard-step="runtime"' in page.text
    assert 'data-atlaso-wizard-step="source"' in page.text
    assert 'data-atlaso-wizard-step="review"' in page.text
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
    assert "data-monaco-editor" in page.text
    assert "data-automation-script-file" in page.text
    assert "data-automation-script-create-file" in page.text
    assert "data-automation-script-create-fullscreen" not in page.text
    assert 'id="automation-script-create-fullscreen-dialog"' not in page.text
    assert 'id="automation-script-create-fullscreen-content"' not in page.text
    assert "Paste code or import" not in page.text
    assert 'data-monaco-language="shell"' in page.text
    assert '<label class="full"><span class="field-label"><span>Description</span>' in page.text
    assert '<textarea name="description" rows="3" maxlength="500"></textarea>' in page.text
    assert '<div class="form-grid automation-script-identity-grid">' in page.text
    assert ".automation-script-identity-grid > .full" in Path("atlaso/app/static/app.css").read_text()
    assert "align-content: start;" in Path("atlaso/app/static/app.css").read_text()
    assert "data-automation-script-source-confirm" in page.text
    assert 'id="automation-script-grid-status"' in page.text
    assert "Import script file" in page.text
    assert "<summary>+ Add schedule here</summary>" not in page.text
    assert "<summary>+ Add managed script here</summary>" not in page.text
    app_js = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    assert "scriptCreateWizard = window.AtlasoUiPatterns.createWizard({" in app_js
    assert "data-automation-script-wizard-open" in app_js
    assert "AtlasoMonaco.setLanguage" in app_js
    assert 'bash: "shell", powershell: "powershell", python: "python"' in app_js
    assert "const managedScriptInterpreterEditor = (cell, onRendered, success, cancel) =>" in app_js
    assert 'select.setAttribute("aria-label", "Managed script interpreter")' in app_js
    assert "cell.edit();" in app_js
    assert 'window.location.hash = "scripts";' in app_js
    assert "window.location.reload();" in app_js
    monaco_source = Path("scripts/monaco-entry.js").read_text(encoding="utf-8")
    assert "basic-languages/shell/shell.contribution" in monaco_source
    assert "basic-languages/powershell/powershell.contribution" in monaco_source
    assert "basic-languages/python/python.contribution" in monaco_source
    assert '"X-Atlaso-Wizard": "1"' in app_js
    assert 'scheduleQuery.get("new") === "vcf_depot_download"' in app_js
    assert 'scheduleForm.elements.task_type.value = "vcf_depot_download"' in app_js
    assert 'scheduleForm.elements.vcf_profile_id.value = profileOption ? requestedProfileId : ""' in app_js
    assert 'scheduleWizard?.steps.find((item) => item.id === "config")' in app_js
    assert 'window.history.replaceState({}, "", cleanUrl)' in app_js
    csrf = csrf_from_page(page.text)
    wizard_response = client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "wizard-inventory-report",
            "description": "Created through the guided flow",
            "interpreter": "bash",
            "timeout_seconds": "120",
            "content": "#!/bin/bash\ndate",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )
    assert wizard_response.status_code == 200
    assert wizard_response.json()["status"] == "saved"
    duplicate_wizard_response = client.post(
        "/automation/scripts",
        data={
            "csrf": csrf,
            "name": "wizard-inventory-report",
            "interpreter": "bash",
            "timeout_seconds": "120",
            "content": "#!/bin/bash\ndate",
        },
        headers={"X-Atlaso-Wizard": "1", "Accept": "application/json"},
    )
    assert duplicate_wizard_response.status_code == 409
    assert duplicate_wizard_response.json()["detail"] == "A script with this name already exists."
    with SessionLocal() as db:
        wizard_script = db.execute(
            select(AutomationScript).where(AutomationScript.name == "wizard-inventory-report")
        ).scalar_one()
        wizard_revision = db.execute(
            select(AutomationScriptRevision).where(AutomationScriptRevision.script_id == wizard_script.id)
        ).scalar_one()
        assert wizard_revision.interpreter == "bash"
        assert wizard_revision.timeout_seconds == 120
        assert wizard_revision.enabled is False
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


def test_worker_normalizes_line_endings_for_an_existing_managed_script_revision(client, monkeypatch):
    """Verify that worker normalizes line endings for an existing managed script revision.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript, Job
    from atlaso.app.services.automation import create_script_revision
    from atlaso.app.worker import _run_managed_script

    captured = {}

    def fake_run(_self, script_path, _interpreter, _timeout_seconds, _arguments, _vault_path):
        """Return fake run.

        Args:
            _self:  self supplied by the caller.
            script_path: Filesystem path for the script.
            _interpreter:  interpreter supplied by the caller.
            _timeout_seconds:  timeout seconds supplied by the caller.
            _arguments:  arguments supplied by the caller.
            _vault_path: Filesystem path for the vault.
        """
        captured["content"] = Path(script_path).read_bytes()
        return AdapterResult(command=["atlaso-helper", "automation", "run"], dry_run=False, stdout="ok\n", stderr="", returncode=0)

    monkeypatch.setattr(SystemAdapter, "run_automation_script", fake_run)
    with SessionLocal() as db:
        script = AutomationScript(name="legacy-crlf-script", description="", created_by="admin")
        db.add(script)
        db.flush()
        revision = create_script_revision(
            db,
            script=script,
            interpreter="bash",
            content="#!/bin/bash\necho ok\n",
            timeout_seconds=60,
            actor="admin",
        )
        revision.content = "#!/bin/bash\r\necho ok\r\n"
        revision.enabled = True
        db.flush()
        job = Job(
            id="job_legacy_crlf_script",
            type="managed-script",
            status="running",
            created_by="admin",
            task_config_json=json.dumps({"revision_id": revision.id, "arguments": []}),
        )
        db.add(job)
        db.commit()

        _run_managed_script(db, job)

    assert captured["content"] == b"#!/bin/bash\necho ok\n"


def test_manual_script_run_collects_parameters_and_exposes_revision_diff(client):
    """Verify that manual script run collects parameters and exposes revision diff.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AutomationScript, AutomationScriptRevision, Job

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

    app_js = Path("atlaso/app/static/app.js").read_text()
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
    """Verify that due schedule queues one job and skips overlap.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStep, Schedule
    from atlaso.app.services.automation import enqueue_due_schedules

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
    """Verify that worker rejects queued vcf download when profile was disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job, JobStatus, VcfDepotDownloadProfile
    from atlaso.app.worker import run_worker_once

    def reject_appliance_log_path(_path):
        """Handle reject appliance log path.

        Args:
            _path: Filesystem path read, validated, or updated by the operation.


        Raises:
            PermissionError: If the operation lacks the required permission.
        """
        raise PermissionError("appliance log path unavailable")

    monkeypatch.setattr("atlaso.app.ui.filesystem_path", reject_appliance_log_path)
    client.get("/login")
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
    with SessionLocal() as db:
        failed = db.get(Job, "job_disabled_vcf_profile")
        assert failed.status == JobStatus.FAILED.value
        assert "Enable the VCFDT download profile" in failed.error
        audit = db.execute(
            select(AuditEvent).where(AuditEvent.resource_id == failed.id)
        ).scalar_one()
        assert audit.action == "fail_vcf_depot_download"
        assert audit.success is False


def test_due_vcf_schedules_share_global_download_lock_and_record_skipped_run(client):
    """Verify that due vcf schedules share global download lock and record skipped run.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        JobStatus,
        Schedule,
        VcfDepotDownloadProfile,
    )
    from atlaso.app.services.automation import enqueue_due_schedules

    client.get("/login")
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        first_profile = VcfDepotDownloadProfile(name="scheduled-metadata", profile_type="metadata", enabled=True)
        second_profile = VcfDepotDownloadProfile(name="scheduled-esx", profile_type="esx", enabled=True)
        db.add_all([first_profile, second_profile])
        db.flush()
        db.add_all(
            [
                Schedule(
                    name="scheduled-metadata-nightly",
                    task_type="vcf_depot_download",
                    task_config_json=json.dumps({"profile_id": first_profile.id}),
                    schedule_kind="cron",
                    cron_expression="0 2 * * *",
                    timezone_name="UTC",
                    enabled=True,
                    next_run_at=now - timedelta(minutes=2),
                    created_by="admin",
                ),
                Schedule(
                    name="scheduled-esx-nightly",
                    task_type="vcf_depot_download",
                    task_config_json=json.dumps({"profile_id": second_profile.id}),
                    schedule_kind="cron",
                    cron_expression="0 3 * * *",
                    timezone_name="UTC",
                    enabled=True,
                    next_run_at=now - timedelta(minutes=1),
                    created_by="admin",
                ),
            ]
        )
        db.commit()

    with SessionLocal() as db:
        jobs = enqueue_due_schedules(db, now=now)
        assert [job.status for job in jobs] == [JobStatus.PENDING.value, JobStatus.SKIPPED.value]
        skipped = jobs[1]
        result = json.loads(skipped.result)
        assert result["profile_name"] == "scheduled-esx"
        assert result["schedule_name"] == "scheduled-esx-nightly"
        assert result["planned_for"]
        assert result["active_job_id"] == jobs[0].id
        assert db.execute(
            select(AuditEvent).where(
                AuditEvent.resource_id == skipped.id,
                AuditEvent.action == "skip_scheduled_vcf_depot_download",
            )
        ).scalar_one().success is False


def test_vcf_download_database_guard_rejects_second_active_job(client):
    """Verify that vcf download database guard rejects second active job.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfDepotDownloadProfile
    from atlaso.app.services.vcf_depot_downloads import (
        ActiveVcfDepotDownloadError,
        enqueue_vcf_depot_download,
        vcf_depot_task_log_reference,
    )

    client.get("/login")
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="atomic-profile", profile_type="metadata", enabled=True)
        db.add(profile)
        db.flush()
        first = enqueue_vcf_depot_download(db, profile=profile, actor="admin", trigger="manual")
        expected_log = f"/var/lib/atlaso/vcfDownloadTool/task-logs/{first.id}.log"
        assert vcf_depot_task_log_reference(first.id, "before-rename") == expected_log
        assert vcf_depot_task_log_reference(first.id, "after-rename") == expected_log
        with pytest.raises(ActiveVcfDepotDownloadError, match=first.id):
            enqueue_vcf_depot_download(db, profile=profile, actor="admin", trigger="manual")
        db.commit()


def test_vcf_download_database_guard_covers_software_id_and_appliance_apply(client):
    """Verify that vcf download database guard covers software id and appliance apply.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, VcfDepotDownloadProfile
    from atlaso.app.services.vcf_depot_downloads import (
        ActiveVcfDepotDownloadError,
        enqueue_vcf_depot_download,
    )

    client.get("/login")
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="cross-operation-profile", profile_type="metadata", enabled=True)
        db.add(profile)
        db.flush()
        software_id_job = Job(
            id="job_active_software_id",
            type="vcf-depot-software-id",
            status=JobStatus.PENDING.value,
            created_by="admin",
        )
        db.add(software_id_job)
        db.commit()
        assert software_id_job.vcf_depot_operation is True

        with pytest.raises(ActiveVcfDepotDownloadError, match=software_id_job.id):
            enqueue_vcf_depot_download(db, profile=profile, actor="admin", trigger="manual")

        software_id_job.status = JobStatus.SUCCEEDED.value
        db.add(software_id_job)
        db.commit()
        apply_job = Job(
            id="job_active_vcf_apply",
            type="appliance-apply",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            vcf_depot_operation=True,
            result=json.dumps({"selected_units": ["vcf_offline_depot"]}),
        )
        db.add(apply_job)
        db.commit()

        with pytest.raises(ActiveVcfDepotDownloadError, match=apply_job.id):
            enqueue_vcf_depot_download(db, profile=profile, actor="admin", trigger="manual")
        db.commit()


def test_due_vcf_schedule_records_software_id_collision_as_skipped(client):
    """Verify that due vcf schedule records software id collision as skipped.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AuditEvent,
        Job,
        JobStatus,
        Schedule,
        VcfDepotDownloadProfile,
    )
    from atlaso.app.services.automation import enqueue_due_schedules

    client.get("/login")
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="identity-collision-profile", profile_type="metadata", enabled=True)
        db.add(profile)
        db.flush()
        schedule = Schedule(
            name="identity-collision-nightly",
            task_type="vcf_depot_download",
            task_config_json=json.dumps({"profile_id": profile.id}),
            schedule_kind="cron",
            cron_expression="0 2 * * *",
            timezone_name="UTC",
            enabled=True,
            next_run_at=now - timedelta(minutes=1),
            created_by="admin",
        )
        active = Job(
            id="job_active_identity_collision",
            type="vcf-depot-software-id",
            status=JobStatus.RUNNING.value,
            created_by="admin",
        )
        db.add_all([schedule, active])
        db.commit()

    with SessionLocal() as db:
        jobs = enqueue_due_schedules(db, now=now)
        assert len(jobs) == 1
        skipped = jobs[0]
        assert skipped.status == JobStatus.SKIPPED.value
        assert json.loads(skipped.result)["active_job_id"] == active.id
        assert db.execute(
            select(AuditEvent).where(
                AuditEvent.resource_id == skipped.id,
                AuditEvent.action == "skip_scheduled_vcf_depot_download",
            )
        ).scalar_one().success is False


def test_disabling_vcf_profile_disables_schedules_and_delete_requires_detach(client):
    """Verify that disabling vcf profile disables schedules and delete requires detach.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Schedule, VcfDepotDownloadProfile

    login(client)
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="lifecycle-profile", profile_type="metadata", enabled=True)
        db.add(profile)
        db.flush()
        schedule = Schedule(
            name="lifecycle-profile-nightly",
            task_type="vcf_depot_download",
            task_config_json=json.dumps({"profile_id": profile.id}),
            schedule_kind="cron",
            cron_expression="0 2 * * *",
            timezone_name="UTC",
            enabled=True,
            next_run_at=datetime.now(timezone.utc) + timedelta(hours=1),
            created_by="admin",
        )
        db.add(schedule)
        db.commit()
        profile_id = profile.id
        schedule_id = schedule.id

    csrf = csrf_from_page(client.get("/automation").text)
    delete_response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert delete_response.status_code == 409
    assert "lifecycle-profile-nightly" in delete_response.text

    edit_response = client.post(
        f"/vcf-offline-depot/profiles/{profile_id}/edit",
        data={
            "csrf": csrf,
            "name": "renamed-lifecycle-profile",
            "profile_type": "metadata",
            "sku": "VCF",
            "vcf_version": "9.1.0",
            "binary_type": "INSTALL",
            "automated_install": "on",
        },
        follow_redirects=False,
    )
    assert edit_response.status_code == 303
    with SessionLocal() as db:
        schedule = db.get(Schedule, schedule_id)
        assert schedule.enabled is False
        assert schedule.next_run_at is None
        assert json.loads(schedule.task_config_json)["profile_id"] == profile_id


def test_schedule_edit_run_now_and_script_dependency_guards(client):
    """Verify that schedule edit run now and script dependency guards.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AutomationScript,
        AutomationScriptRevision,
        Job,
        Schedule,
    )
    from atlaso.app.worker import run_worker_once

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
    """Verify that settings archive restores sources and automation disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        AutomationScript,
        AutomationScriptRevision,
        Schedule,
        UpdateSource,
    )
    from atlaso.app.services.automation import create_script_revision
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )

    client.get("/login")
    with SessionLocal() as db:
        source = db.execute(select(UpdateSource).where(UpdateSource.kind == "atlaso")).scalar_one()
        source.url = "https://updates.example.test/atlaso"
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

        source_payload = next(row for row in archive["data"]["update_sources"] if row["kind"] == "atlaso")
        assert "credential_encrypted" not in source_payload
        restore_settings_archive(db, archive)

        restored_source = db.execute(select(UpdateSource).where(UpdateSource.kind == "atlaso")).scalar_one()
        restored_revision = db.execute(
            select(AutomationScriptRevision).join(AutomationScript).where(AutomationScript.name == "archive-script")
        ).scalar_one()
        restored_schedule = db.execute(select(Schedule).where(Schedule.name == "archive-schedule")).scalar_one()
        assert restored_source.url == "https://updates.example.test/atlaso"
        assert restored_source.credential_encrypted == ""
        assert restored_revision.enabled is False
        assert restored_schedule.enabled is False
        assert restored_schedule.next_run_at is None
        assert json.loads(restored_schedule.task_config_json)["revision_id"] == restored_revision.id
