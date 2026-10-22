"""Assert that bundled handoff task evidence matches native baseline ownership."""

import json
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize(
    ("environment", "dry_run", "baseline_updated"),
    [
        ("appliance", True, False),
        ("development", True, True),
        ("appliance", False, True),
    ],
)
def test_management_handoff_settings_result_reports_baseline_evidence_through_runner(
    client, monkeypatch, environment, dry_run, baseline_updated,
):
    """Persisted handoff task evidence reflects whether native baselines advanced.

    Args:
        client: Initialized application test client.
        monkeypatch: Fixture for isolating Apply runner dependencies.
        environment: Runtime environment name.
        dry_run: Whether the adapter simulates its commands.
        baseline_updated: Whether native baseline evidence should advance.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    settings_preview = json.dumps({
        "resolver_mode": "dhcp",
        "resolver_servers": ["192.0.2.1"],
        "management_https_enabled": False,
    }, sort_keys=True)
    unit_ids = ui.MANAGEMENT_HANDOFF_UNIT_IDS
    units = [
        {
            "id": unit_id,
            "label": unit_id.replace("_", " ").title(),
            "snapshot_hash": f"submitted-{unit_id}",
            "summary": [f"captured {unit_id}"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": f"/etc/atlaso/{unit_id}.conf",
            "config_preview": settings_preview if unit_id == "appliance_settings" else "{}",
            "config_diff": "",
            "context": {},
        }
        for unit_id in unit_ids
    ]
    baselines = {
        unit["id"]: {
            "snapshot_hash": f"native-{unit['id']}",
            "config_path": unit["config_path"],
            "config_preview": settings_preview if unit["id"] == "appliance_settings" else "native config",
            "summary": [f"native {unit['id']}"],
            "applied_at": "2026-10-22T00:00:00+00:00",
        }
        for unit in units
    }
    task_id = f"job_handoff_baseline_{environment}_{'dry' if dry_run else 'native'}"
    result = {
        "selected_units": list(unit_ids),
        "management_handoff": True,
        "management_handoff_units": list(unit_ids),
        "captured_units": [
            {
                "unit_id": unit["id"],
                "snapshot_hash": unit["snapshot_hash"],
                "summary": unit["summary"],
            }
            for unit in units
        ],
        "skipped_changed_units": [],
        "units": [],
        "dry_run": dry_run,
    }
    with SessionLocal() as db:
        ui.save_appliance_apply_baselines(db, baselines)
        job = Job(
            id=task_id,
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            progress_percent=0,
            result=json.dumps(result),
        )
        db.add(job)
        db.add_all([
            JobStep(
                id=f"{task_id}:{unit['id']}",
                job_id=task_id,
                component_key=unit["id"],
                label=unit["label"],
                position=index,
                status=JobStatus.PENDING.value,
                result=json.dumps({"summary": unit["summary"]}),
            )
            for index, unit in enumerate(units, start=1)
        ])
        db.commit()

    class StubAdapter:
        def __init__(self):
            self.dry_run = dry_run

        def acknowledge_management_handoff(self, _job_id):
            """Acknowledge candidate state with the configured execution mode.

            Args:
                _job_id: Apply task whose management handoff is committed.
            """
            return AdapterResult(
                command=["management-handoff", "acknowledge"],
                dry_run=dry_run,
                stdout=json.dumps({"management_handoff": "committed"}),
            )

    def execute_handoff(_units, *, job_id, adapter, db, include_wan=False, include_nat=False,
                        include_dnsmasq=False):
        """Return successful results for the units in a bundled handoff.

        Args:
            _units: Current Apply units keyed by unit identifier.
            job_id: Apply task executing the handoff.
            adapter: System adapter selected by the runner.
            db: Active database session.
            include_wan: Whether the handoff includes WAN-dependent work.
            include_nat: Whether the handoff includes traffic publishing.
            include_dnsmasq: Whether the handoff includes DNS/DHCP work.
        """
        assert job_id == task_id
        assert adapter.dry_run is dry_run
        assert not include_wan and not include_nat and not include_dnsmasq
        group = {
            "success": True,
            "dry_run": dry_run,
            "management_handoff": {"management_handoff": "candidate_ready"},
            "commands": [],
        }
        component_results = [
            {
                "unit_id": unit["id"],
                "label": unit["label"],
                "status": JobStatus.SUCCEEDED.value,
                "success": True,
                "dry_run": dry_run,
                "commands": [],
                "summary": unit["summary"],
                "validation_errors": [],
                "validation_warnings": [],
                "config_path": unit["config_path"],
                "config_preview": unit["config_preview"],
                "config_diff": "",
            }
            for unit in _units.values()
            if unit["id"] in unit_ids
        ]
        return group, component_results

    monkeypatch.setattr(ui, "get_settings", lambda: SimpleNamespace(environment=environment))
    monkeypatch.setattr(ui, "SystemAdapter", lambda **_kwargs: StubAdapter())
    monkeypatch.setattr(ui, "appliance_apply_units", lambda *_args, **_kwargs: units)
    monkeypatch.setattr(ui, "execute_management_handoff", execute_handoff)
    monkeypatch.setattr(ui, "refresh_management_handoff_dynamic_observations", lambda *_args: None)
    monkeypatch.setattr(ui, "baseline_management_handoff_dhcp_settings", lambda *_args: None)
    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", lambda *_args: None)
    monkeypatch.setattr(ui, "log_appliance_apply_submission", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ui, "invalidate_observed_management_dhcp_dns", lambda: None)
    monkeypatch.setattr(ui, "invalidate_appliance_apply_status_projection", lambda: None)

    ui.run_appliance_apply_job(task_id)

    with SessionLocal() as db:
        job = db.get(Job, task_id)
        assert job is not None and job.status == JobStatus.SUCCEEDED.value
        task_payload = json.loads(job.result or "{}")
        settings_result = next(
            result for result in task_payload["units"] if result["unit_id"] == "appliance_settings"
        )
        assert settings_result["baseline_updated"] is baseline_updated
        if environment == "appliance" and dry_run:
            assert "dry run" in settings_result["remaining_pending_reason"].lower()
        else:
            assert "remaining_pending_reason" not in settings_result

        stored_baselines = ui.load_appliance_apply_baselines(db)
        if baseline_updated:
            assert stored_baselines["appliance_settings"]["snapshot_hash"] == "submitted-appliance_settings"
            assert stored_baselines["network"]["snapshot_hash"] == "submitted-network"
        else:
            assert stored_baselines == baselines
