"""Keep public depot permission repair on successful and failed task paths."""

import json
import subprocess

import pytest


@pytest.mark.parametrize("failure", ["none", "exit", "launch", "repair", "both", "preflight"])
def test_download_job_repairs_public_content_on_failure(client, monkeypatch, tmp_path, failure):
    """Repair after execution and preserve task failure when repair is unavailable.

    Args:
        client: Isolated application/database fixture.
        monkeypatch: Dependency replacement fixture.
        tmp_path: Isolated test artifact root.
        failure: Execution or repair failure to inject.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, VcfDepotDownloadProfile, VcfOfflineDepotSettings

    store = tmp_path / "depot"
    tool = tmp_path / "tool" / "bin" / "vcf-download-tool"
    settings = VcfOfflineDepotSettings(depot_store_path=str(store))
    events = []

    def preflight(*_args):
        """Return only a validated task-owned store.

        Args:
            *_args: Unused database and profile arguments.
        """
        if failure == "preflight":
            raise ValueError("preflight failed")
        return settings, [[str(tool), "metadata", "download"]], []

    def execute(*_args, **_kwargs):
        """Model command success, nonzero exit or launch failure.

        Args:
            *_args: Command arguments.
            **_kwargs: Subprocess options.
        """
        events.append("execute")
        if failure == "launch":
            raise OSError("launch failed")
        return subprocess.CompletedProcess([], 1 if failure in {"exit", "both"} else 0, "output", "")

    def repair(path):
        """Record permission reconciliation without changing host permissions.

        Args:
            path: Validated public depot store.
        """
        assert path == str(store)
        events.append("repair")
        if failure in {"repair", "both"}:
            raise OSError("repair refused")
        return 2

    monkeypatch.setattr(ui, "vcf_depot_download_preflight", preflight)
    monkeypatch.setattr(ui, "VCF_DEPOT_VDT_LOG_PATH", tmp_path / "vdt.log")
    monkeypatch.setattr(ui, "vcf_depot_secret_context", lambda _db: {
        "download_token_present": False, "activation_code_present": False, "download_credential_type": "",
    })
    monkeypatch.setattr(ui, "render_vcfdt_command_preview", lambda *_args, **_kwargs: "preview")
    monkeypatch.setattr(ui, "prepare_vcf_depot_runtime", lambda *_args: tool)
    monkeypatch.setattr(ui, "append_vcf_depot_task_log", lambda *_args: None)
    monkeypatch.setattr(ui, "archive_vcf_depot_task_log", lambda *_args: tmp_path / "archive.log")
    monkeypatch.setattr(ui.subprocess, "run", execute)
    monkeypatch.setattr(ui, "prepare_downloaded_depot_permissions", repair)
    with SessionLocal() as db:
        profile = VcfDepotDownloadProfile(name="Permission regression")
        db.add(profile)
        db.add(Job(id="job_permissions", type="vcf-depot-download", status="pending", created_by="admin"))
        db.commit()
        profile_id = profile.id
    ui.run_vcf_depot_download_job("job_permissions", profile_id)
    with SessionLocal() as db:
        job = db.get(Job, "job_permissions")
        assert job.status == ("succeeded" if failure == "none" else "failed")
        if failure == "preflight":
            assert events == []
        else:
            assert events[0] == "execute"
            assert "repair" in events[1:]
        if failure == "exit":
            assert "code 1" in job.error
        if failure == "launch":
            assert "launch failed" in job.error
        if failure in {"repair", "both"}:
            assert "permission" in job.error
            assert json.loads(job.result)["commands"][0]["returncode"] == (1 if failure == "both" else 0)
        if failure == "both":
            assert "code 1" in job.error
