"""Keep simulated intent out of native management rollback and recovery admission."""

import copy
import json
import subprocess
from datetime import datetime
from types import SimpleNamespace

import pytest

from tests.test_appliance_helper import load_helper_module
from tests.test_management_rollback_addresses import (
    native_observation,
    observed_link,
    rollback_state,
)


@pytest.fixture(scope="module")
def helper():
    """Load the helper without executing privileged operations."""
    return load_helper_module()


@pytest.mark.parametrize("lease", [True, False])
def test_original_dhcp_backup_overrides_simulated_static_rollback(helper, monkeypatch, tmp_path, lease):
    """The exact original configuration authorizes DHCP, never an address alone."""
    state = rollback_state(paths=[{"name": "eth0", "ipv4_method": "static"}])
    original = tmp_path / "original.bin"
    original.write_text("[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n", encoding="utf-8")
    state["snapshots"] = [{"path": str(helper.NETWORKD_MGMT_CONFIG_PATH), "existed": True,
                           "backup": str(original)}]
    before = copy.deepcopy(state)
    sample = observed_link(addresses=[{"address": "192.0.2.10", "cidr": "192.0.2.10/24",
                                      "scope": "global", "source": "DHCPv4", "state": "assigned",
                                      "dhcp4_lease": lease}])
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native_observation(sample))
    monkeypatch.setattr(helper.time, "sleep", lambda _delay: None)
    if lease:
        assert helper._wait_restored_management_addresses(state, attempts=3)["stable_samples"] == 3
    else:
        with pytest.raises(ValueError, match="stable native ownership"):
            helper._wait_restored_management_addresses(state, attempts=3)
    assert state == before


@pytest.mark.parametrize("change", ["static", "other-interface", "missing", "wrong-mac", "conflict"])
def test_original_backup_does_not_relax_native_ownership(helper, monkeypatch, tmp_path, change):
    """A real static config or invalid original DHCP ownership still fails closed."""
    state = rollback_state(paths=[{"name": "eth0", "ipv4_method": "static"}])
    original = tmp_path / "original.bin"
    original.write_text("[Match]\nName=" + ("eth1" if change == "other-interface" else "eth0")
                        + "\n[Network]\nDHCP=" + ("no" if change == "static" else "ipv4") + "\n",
                        encoding="utf-8")
    state["snapshots"] = [{"path": str(helper.NETWORKD_MGMT_CONFIG_PATH), "existed": True,
                           "backup": str(original)}]
    if change == "missing":
        original.unlink()
    sample = observed_link(addresses=[{"address": "192.0.2.10", "cidr": "192.0.2.10/24",
                                      "scope": "global", "source": "DHCPv4", "state": "assigned",
                                      "dhcp4_lease": True}])
    if change == "wrong-mac":
        sample["mac"] = "00:11:22:33:44:66"
    if change == "conflict":
        sample["addresses"][0]["state"] = "conflict"
    monkeypatch.setattr(helper, "_network_address_observation", lambda: native_observation(sample))
    monkeypatch.setattr(helper.time, "sleep", lambda _delay: None)
    with pytest.raises(ValueError):
        helper._wait_restored_management_addresses(state, attempts=3)


@pytest.mark.parametrize("unsafe", [None, "table", "interface", "seed", "dead", "gateway", "source", "host", "type"])
def test_dhcp_gateway_host_seed_retires_only_with_same_domain_replacements(helper, monkeypatch, tmp_path, unsafe):
    """A DHCP /32 need not survive a verified static default plus connected route."""
    common = {"table": 100, "metric": 1024, "holdover_metric": 2049,
              "preferred_source": "192.0.2.10", "scope": "link", "gateway": ""}
    host = {**common, "destination": "192.0.2.1/32", "protocol": "dhcp"}
    if unsafe == "host":
        host["destination"] = "192.0.2.2/32"
    default = {**common, "destination": "0.0.0.0/0", "gateway": "192.0.2.1", "scope": "global", "protocol": "dhcp"}
    connected = {**common, "destination": "192.0.2.0/24", "protocol": "kernel"}
    seed = {"name": "eth0", **host, "seed_metric": 2050}
    observed = [{"dev": "eth0", "table": 100, "dst": "default", "gateway": "192.0.2.1",
                 "prefsrc": "192.0.2.10", "protocol": "static", "metric": 100},
                {"dev": "eth0", "table": 100, "dst": "192.0.2.0/24", "protocol": "kernel",
                 "prefsrc": "192.0.2.10", "scope": "link", "metric": 0}]
    if unsafe == "table":
        # The selector must not report routes from another table.
        observed[0]["table"] = 200
    elif unsafe == "interface":
        observed[0]["dev"] = "eth1"
    elif unsafe == "seed":
        observed[0]["metric"] = 2050
    elif unsafe == "dead":
        observed[0]["flags"] = ["dead"]
    elif unsafe == "gateway":
        observed[0]["gateway"] = "192.0.2.2"
    elif unsafe == "source":
        observed[1]["prefsrc"] = "192.0.2.11"
    elif unsafe == "type":
        observed[0]["type"] = "blackhole"
    observed.append({"dev": "eth0", "table": 100, "dst": host["destination"], "protocol": "kernel",
                     "metric": 2050, "prefsrc": "192.0.2.10", "scope": "link"})
    state = {"previous_management_routing": {"eth0": {"mac": "00:11:22:33:44:55", "cidrs": ["192.0.2.10/24"],
              "table": 100, "routes": [host, default, connected]}}, "transition_seed_routes": [seed]}
    monkeypatch.setattr(helper, "_transition_route_rows", lambda *_args: observed)
    monkeypatch.setattr(helper, "_durable_management_handoff_state_write", lambda *_args: None)
    commands = []
    monkeypatch.setattr(helper, "_run", lambda command: commands.append(command)
                        or subprocess.CompletedProcess(command, 0))
    if unsafe:
        with pytest.raises(ValueError):
            helper._retire_transition_routes(state, tmp_path / "state.json", require_replacement=True)
        assert commands == []
    else:
        helper._retire_transition_routes(state, tmp_path / "state.json", require_replacement=True)
        assert state["transition_seed_routes"] == []
        assert len(commands) == 1 and commands[0][3] == "del"
        assert commands[0][commands[0].index("metric") + 1] == "2050"


@pytest.mark.parametrize("recovered", [True, False])
def test_console_reconciles_exact_terminal_owner_before_correction(client, monkeypatch, recovered):
    """Only verified recovery clears the exact terminal task's admission flag."""
    from atlaso.app import appliance_console, ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    with SessionLocal() as db:
        db.add(Job(id="job_retained", type="appliance-apply", status="failed", created_by="admin",
                   result=json.dumps({
                       "management_handoff": True,
                       "management_handoff_runtime_commit_pending": True,
                   })))
        db.commit()
    calls = []

    def recover(self, *, startup=False):
        """Return bounded rollback evidence through the real recovery coordinator."""
        calls.append(startup)
        return AdapterResult(
            command=["management-handoff", "recover"],
            dry_run=False,
            stdout=json.dumps({"management_handoff": "rolled_back", "rolled_back": recovered}),
            returncode=0 if recovered else 1,
        )

    monkeypatch.setattr(ui.SystemAdapter, "recover_management_handoff", recover)
    if recovered:
        appliance_console._ensure_no_active_apply()
    else:
        with pytest.raises(appliance_console.ConsoleOperationError, match="job_retained.*still owns runtime recovery"):
            appliance_console._ensure_no_active_apply()
    assert calls == [False]
    with SessionLocal() as db:
        payload = json.loads(db.get(Job, "job_retained").result)
        assert payload.get("management_handoff_runtime_commit_pending", False) is (not recovered)
        assert payload["management_handoff_recovery"]["evidence"].get("rolled_back") is recovered
        assert payload.get("interrupted") is not True
        assert "runtime_recovery_retried_at" in payload


def test_console_does_not_recover_running_apply(client, monkeypatch):
    """An active task continues to own admission without starting recovery."""
    from atlaso.app import appliance_console, ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    with SessionLocal() as db:
        db.add(Job(id="job_running", type="appliance-apply", status="running", created_by="admin",
                   result=json.dumps({"management_handoff_runtime_commit_pending": True})))
        db.commit()
    calls = []

    def recover(self, *, startup=False):
        calls.append(startup)
        return AdapterResult(command=[], dry_run=False, returncode=0)

    monkeypatch.setattr(ui.SystemAdapter, "recover_management_handoff", recover)
    with pytest.raises(appliance_console.ConsoleOperationError, match="job_running.*already running"):
        appliance_console._ensure_no_active_apply()
    assert calls == []


def test_console_retained_recovery_respects_busy_writer_admission(client, monkeypatch):
    """A busy writer keeps the failed task untouched and blocks console correction."""
    from atlaso.app import appliance_console, ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_apply_admission import (
        ApplianceApplyAdmissionBusy,
    )

    with SessionLocal() as db:
        db.add(Job(id="job_busy", type="appliance-apply", status="failed", created_by="admin",
                   result=json.dumps({"management_handoff_runtime_commit_pending": True})))
        db.commit()
    recoveries = []

    def busy(_db):
        raise ApplianceApplyAdmissionBusy

    monkeypatch.setattr("atlaso.app.services.appliance_apply_admission.lock_appliance_apply_snapshot_tables", busy)
    monkeypatch.setattr(ui.SystemAdapter, "recover_management_handoff", lambda self, **_kwargs: recoveries.append(True))
    with pytest.raises(appliance_console.ConsoleOperationError, match="state is being updated"):
        appliance_console._ensure_no_active_apply()
    assert recoveries == []
    with SessionLocal() as db:
        payload = json.loads(db.get(Job, "job_busy").result)
        assert payload["management_handoff_runtime_commit_pending"] is True


@pytest.mark.parametrize("environment,dry_run,updated", [("appliance", True, False), ("appliance", False, True), ("development", True, True)])
def test_appliance_dry_run_preserves_native_baseline(client, monkeypatch, environment, dry_run, updated):
    """Simulation cannot replace a native appliance's last applied Network intent."""
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    original = {"network": {"config_preview": "DHCP", "snapshot_hash": "native"}}
    unit = {"id": "network", "config_preview": "static", "snapshot_hash": "simulated", "config_path": "network", "summary": []}
    monkeypatch.setattr(ui, "get_settings", lambda: SimpleNamespace(environment=environment))
    with SessionLocal() as db:
        ui.save_appliance_apply_baselines(db, original)
        db.commit()
        ui.update_appliance_apply_baselines(db, [unit], {"network"}, dry_run=dry_run)
        db.commit()
        assert ui.load_appliance_apply_baselines(db)["network"]["config_preview"] == ("static" if updated else "DHCP")


def test_appliance_network_dry_run_preserves_native_baseline_through_runner(client, monkeypatch):
    """The real Apply runner cannot promote simulated Network intent in appliance mode."""
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    native_preview = "[physical_interfaces]\ninterface=eth0\nrole=management\nDHCP=ipv4\n"
    simulated_preview = "[physical_interfaces]\ninterface=eth0\nrole=management\nDHCP=no\nAddress=192.0.2.10/24\n"
    original = {
        "network": {
            "snapshot_hash": "native-network",
            "config_path": "/etc/systemd/network/20-atlaso.network",
            "config_preview": native_preview,
            "summary": ["eth0 uses DHCP"],
            "applied_at": "2026-10-22T00:00:00+00:00",
        }
    }
    unit = {
        "id": "network",
        "label": "Network",
        "snapshot_hash": "simulated-network",
        "summary": ["eth0 uses static IPv4"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "/etc/systemd/network/20-atlaso.network",
        "config_preview": simulated_preview,
        "config_diff": "",
        "context": {},
    }
    result = {
        "selected_units": ["network"],
        "captured_units": [{"unit_id": "network", "snapshot_hash": unit["snapshot_hash"], "summary": unit["summary"]}],
        "skipped_changed_units": [],
        "units": [],
        "dry_run": True,
    }
    with SessionLocal() as db:
        ui.save_appliance_apply_baselines(db, original)
        db.add(Job(
            id="job_network_dry_run",
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            progress_percent=0,
            result=json.dumps(result),
        ))
        db.add(JobStep(
            id="job_network_dry_run:network",
            job_id="job_network_dry_run",
            component_key="network",
            label="Network",
            position=1,
            status=JobStatus.PENDING.value,
            result=json.dumps({"summary": unit["summary"]}),
        ))
        db.commit()

    class DryRunAdapter:
        dry_run = True

    def execute(current_unit, *, adapter=None, db=None):
        return {
            "unit_id": current_unit["id"],
            "label": current_unit["label"],
            "status": "succeeded",
            "success": True,
            "dry_run": True,
            "commands": [],
            "summary": current_unit["summary"],
            "validation_errors": [],
            "validation_warnings": [],
            "config_path": current_unit["config_path"],
            "config_preview": current_unit["config_preview"],
            "config_diff": "",
        }

    monkeypatch.setattr(ui, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    monkeypatch.setattr(ui, "SystemAdapter", lambda: DryRunAdapter())
    monkeypatch.setattr(ui, "appliance_apply_units", lambda *_args, **_kwargs: [unit])
    monkeypatch.setattr(ui, "execute_appliance_apply_unit", execute)
    monkeypatch.setattr(ui, "persist_vcf_depot_metadata_from_apply", lambda *_args: None)
    monkeypatch.setattr(ui, "log_appliance_apply_submission", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ui, "log_appliance_apply_failures", lambda *_args: None)
    monkeypatch.setattr(ui, "invalidate_observed_management_dhcp_dns", lambda: None)
    monkeypatch.setattr(ui, "invalidate_appliance_apply_status_projection", lambda: None)

    ui.run_appliance_apply_job("job_network_dry_run")

    with SessionLocal() as db:
        job = db.get(Job, "job_network_dry_run")
        assert job.status == JobStatus.SUCCEEDED.value, job.error
        assert json.loads(job.result)["units"][0]["dry_run"] is True
        assert ui.load_appliance_apply_baselines(db) == original


@pytest.mark.parametrize("keys", [("firewall", "nat"), ("network", "wan", "firewall", "nat")])
def test_appliance_paired_dry_run_preserves_all_native_baselines(client, monkeypatch, keys):
    """Paired publication must propagate simulation through baseline admission."""
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    class SimulatedPublication:
        dry_run = True

        def validate_traffic_publishing(self, *args):
            return AdapterResult(command=["validate"], dry_run=True)

        def apply_traffic_publishing(self, *args):
            return AdapterResult(command=["apply"], dry_run=True)

    units = [{"id": key, "label": key, "snapshot_hash": "simulated", "summary": [],
              "config_path": key, "config_preview": "simulated", "config_diff": "",
              "validation_errors": [], "validation_warnings": []} for key in keys]
    original = {key: {"snapshot_hash": "native", "config_preview": "original"} for key in keys}
    monkeypatch.setattr(ui, "get_settings", lambda: SimpleNamespace(environment="appliance"))
    with SessionLocal() as db:
        ui.save_appliance_apply_baselines(db, original)
        job = Job(id="job_paired_dry_run", type="appliance-apply", status="running", created_by="admin", result="{}")
        db.add(job)
        db.commit()
        results = ui.execute_traffic_publishing_pair(db, job, units, adapter=SimulatedPublication())
        assert len(results) == len(keys)
        assert all(result["success"] and result["dry_run"] for result in results)
        assert ui.load_appliance_apply_baselines(db) == original


@pytest.mark.parametrize("status", ["failed", "cancelled"])
def test_console_can_repeat_failed_network_recovery_without_losing_terminal_time(client, monkeypatch, status):
    """An unsuccessful Network retry stays terminal and can be retried again."""
    from atlaso.app import appliance_console, ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    finished = datetime(2026, 10, 22, 16, 55)
    with SessionLocal() as db:
        db.add(Job(id="job_network_retained", type="appliance-apply", status=status, created_by="admin",
                   finished_at=finished, result=json.dumps({"network_runtime_commit_pending": True})))
        db.commit()
    calls = []

    def reconcile(self, job_id, *, committed=False):
        calls.append((job_id, committed))
        return AdapterResult(command=["network", "recover"], dry_run=False, returncode=1)

    monkeypatch.setattr(ui.SystemAdapter, "reconcile_network_transaction", reconcile)
    for _attempt in range(2):
        with pytest.raises(appliance_console.ConsoleOperationError, match="still owns runtime recovery"):
            appliance_console._ensure_no_active_apply()
        with SessionLocal() as db:
            job = db.get(Job, "job_network_retained")
            assert job.status == status
            assert job.finished_at == finished
            assert json.loads(job.result)["network_runtime_commit_pending"] is True
    assert calls == [("job_network_retained", False)] * 2
