"""Verify the database decision for paired Firewall and NAT publication."""

import json

import pytest

from atlaso.app import ui
from atlaso.app.adapters.system import AdapterResult, SystemAdapter
from atlaso.app.database import SessionLocal
from atlaso.app.models import Job


@pytest.mark.parametrize("management_handoff", [False, True])
def test_legacy_restore_retires_runtime_forwards_without_baselines(client, monkeypatch, management_handoff):
    """A full restore must not send durable old forwards through standalone Apply.

    Args:
        client: Isolated application with dry-run publication.
        monkeypatch: Bind runtime observation to the saved pre-restore intent.
        management_handoff: Exercise both ordinary publication and protected management recovery.
    """
    from sqlalchemy import select

    from atlaso.app.models import PhysicalInterface, PortForward
    from atlaso.app.services import port_forwarding
    from atlaso.app.services.settings_archive import (
        export_settings_archive,
        restore_settings_archive,
    )
    from tests.routers.ui.helpers import login
    from tests.services.test_port_forwarding import payload

    with SessionLocal() as db:
        ui.set_setting_value(db, "routes_wan.routing_enabled", "true")
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        db.add(PortForward(**payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
        db.commit()
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        assert port_forwarding.snapshot_has_port_forwards(ui.load_appliance_apply_baselines(db)["nat"]["config_preview"])
        archive = export_settings_archive(db, actor="test")
        archive["data"].pop("port_forwards")
        restore_settings_archive(db, archive)
        assert not ui.load_appliance_apply_baselines(db)
        assert db.scalar(select(PortForward)) is None
    monkeypatch.setattr(SystemAdapter, "port_forward_status", lambda self: AdapterResult(
        command=[], dry_run=False, stdout='{"runtime_has_port_forwards":true}',
    ))
    original_units = ui.appliance_apply_units

    def observed_units(db, **kwargs):
        """Control only whether the restored management front door requires handoff.

        Args:
            db: Current restored desired state with empty Apply baselines.
            **kwargs: Preserve the caller's inventory reconciliation selection.
        """
        units = original_units(db, **kwargs)
        network = next(unit for unit in units if unit["id"] == "network")
        network["management_handoff_required"] = management_handoff
        network["management_default_mirror_change"] = False
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", observed_units)
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": ["firewall", "nat"]},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        result = json.loads(job.result)
        assert job.status == "succeeded", result
        if management_handoff:
            assert result["management_handoff"] is True
            assert "nat" in result["management_handoff_units"]
        else:
            assert result["traffic_publishing_pair"] is True
            assert result["traffic_publishing_runtime_commit_pending"] is False
        assert not port_forwarding.snapshot_has_port_forwards(ui.load_appliance_apply_baselines(db)["nat"]["config_preview"])


@pytest.mark.parametrize("content,expected", [('{"runtime_has_port_forwards":false}', False),
    ('{"runtime_has_port_forwards":true}', True), ('{}', None), ('{"runtime_has_port_forwards":null}', None),
    ('{"runtime_has_port_forwards":1}', None), ('broken', None), ('x' * 2_000_001, None)],
    ids=["absent", "retained", "missing-projection", "unknown", "wrong-type", "malformed", "oversized"])
def test_runtime_forward_presence_uses_bounded_privileged_projection(monkeypatch, content, expected):
    """Unknown runtime intent blocks submission instead of inferring a dependency.

    Args:
        monkeypatch: Substitute the bounded privileged projection.
        content: Helper response without exposing the root-owned snapshot.
        expected: Proven intent or unknown state requiring rejection.
    """
    from atlaso.app.services import port_forwarding

    monkeypatch.setattr(SystemAdapter, "port_forward_status", lambda self: AdapterResult(
        command=[], dry_run=False, stdout=content,
    ))
    if expected is None:
        with pytest.raises(ValueError, match="Cannot verify applied forwarding"):
            port_forwarding.runtime_has_port_forwards()
    else:
        assert port_forwarding.runtime_has_port_forwards() is expected


@pytest.mark.parametrize("presence", [False, None])
@pytest.mark.parametrize("selected_unit", ["kms", "local_users"])
@pytest.mark.parametrize("disabled_rule", [False, True])
def test_listener_only_apply_does_not_infer_forwarding_from_unreadable_snapshot(client, monkeypatch, presence, selected_unit, disabled_rule):
    """A source-only root snapshot cannot select unrelated Firewall/NAT intent.

    Args:
        client: Isolated application and dry-run task runner.
        monkeypatch: Supply the privileged projection without application file access.
        presence: Known source-only intent or failed observation.
        selected_unit: Listener-related or independent requested unit.
        disabled_rule: Retain a disabled desired row and disabled applied baseline.
    """
    from tests.routers.ui.helpers import login

    if disabled_rule:
        from sqlalchemy import select

        from atlaso.app.models import PhysicalInterface, PortForward
        from tests.services.test_port_forwarding import payload

        with SessionLocal() as db:
            ui.set_setting_value(db, "routes_wan.routing_enabled", "true")
            interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
            db.add(PortForward(**payload(enabled=False, ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])))
            db.commit()
            units = ui.appliance_apply_units(db)
            ui.update_appliance_apply_baselines(db, units, {"nat"})

    monkeypatch.setattr(SystemAdapter, "port_forward_status", lambda self: AdapterResult(
        command=[], dry_run=False, stdout=json.dumps({"runtime_has_port_forwards": presence}),
    ))
    if presence is None:
        def unavailable():
            """Model an internal exception that must not reach the public response."""
            raise ValueError("internal runtime diagnostic sentinel")
        monkeypatch.setattr(ui, "runtime_has_port_forwards", unavailable)
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": [selected_unit]},
                           headers={"Accept": "application/json"})
    if presence is None and selected_unit == "kms":
        assert response.status_code == 422
        assert "Cannot verify applied forwarding" in response.json()["detail"]
        assert "internal runtime diagnostic sentinel" not in response.text
    else:
        assert response.status_code == 202, response.text
        with SessionLocal() as db:
            result = json.loads(db.get(Job, response.json()["job_id"]).result)
            assert result["selected_units"] == [selected_unit]
            assert not result["traffic_publishing_pair"]


@pytest.mark.parametrize("management_move,release_listener,enable_nts,cancel_after_pair", [
    (management, listener, nts, False)
    for management in (False, True) for listener in (False, True) for nts in (False, True)
] + [(False, False, False, True)])
def test_global_submission_publishes_captured_port_forward_pair(client, monkeypatch, management_move, release_listener, enable_nts, cancel_after_pair):
    """The real submission and task runner keep Firewall/NAT baselines together.

    Args:
        client: Isolated application with dry-run host adapters.
        monkeypatch: Request cancellation at the completed paired-publication boundary.
        management_move: Include the pair in a protected management handoff.
        cancel_after_pair: Verify completion wins when the pair was the final work.
        release_listener: Disable KMS while assigning its previous endpoint to forwarding.
        enable_nts: Preserve CA deployment before first NTS enablement.
    """
    from sqlalchemy import select

    from atlaso.app.models import (
        KmsSettings,
        NtpSettings,
        PhysicalInterface,
        PortForward,
        VsphereKeyProvider,
        VsphereTrustedVcenter,
        VsphereTrustedVcenterCertificate,
    )
    from atlaso.app.services.vsphere_key_providers import parse_public_certificate
    from tests.routers.ui.helpers import login
    from tests.services.test_port_forwarding import payload
    from tests.test_vsphere_key_providers import _public_client_certificate

    if cancel_after_pair:
        from atlaso.app.security import Identity
        from atlaso.app.services import task_cancellation

        execute_pair = ui.execute_traffic_publishing_pair
        def execute_and_request(db, job, *args, **kwargs):
            results = execute_pair(db, job, *args, **kwargs)
            task_cancellation.request(db, job, Identity("operator", "admin", {"admin:all"}))
            return results
        monkeypatch.setattr(ui, "execute_traffic_publishing_pair", execute_and_request)
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        ui.set_setting_value(db, "routes_wan.routing_enabled", "true")
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        kms = db.scalar(select(KmsSettings))
        if release_listener:
            kms.enabled = True
            kms.port = 5696
            kms.listen_interface = "eth2"
            kms.listen_address = interface.ip_cidr.split("/")[0]
        db.commit()
        before = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, before, {unit["id"] for unit in before})
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        forwarding = payload(ingress_interface="eth2", listener_address=interface.ip_cidr.split("/")[0])
        if release_listener:
            kms.enabled = False
            forwarding.update(external_port_start=5696, external_port_end=5696, target_port_end=13000)
        db.add(PortForward(**forwarding))
        if enable_nts:
            ui.get_ca_settings_row(db).enabled = True
            ntp = db.scalar(select(NtpSettings))
            ntp.enabled = True
            ntp.nts_server_enabled = True
            ntp.hostname = "ntp.atlaso.internal"
            ntp.listen_interface = "eth2"
            ntp.listen_address = interface.ip_cidr.split("/")[0]
            if not release_listener:
                kms.enabled = True
                kms.listen_interface = "eth2"
                kms.listen_address = interface.ip_cidr.split("/")[0]
                public_pem, _private_pem = _public_client_certificate()
                provider = VsphereKeyProvider(name="Apply ordering provider", enabled=True)
                vcenter = VsphereTrustedVcenter(name="Apply ordering vCenter", hostname="vcsa.atlaso.internal", enabled=True)
                vcenter.certificates.append(VsphereTrustedVcenterCertificate(
                    source="uploaded_public", **parse_public_certificate(public_pem),
                ))
                provider.trusted_vcenters.append(vcenter)
                db.add(provider)
        if management_move:
            management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
            management.ip_cidr = "192.168.49.21/24"
        db.commit()
    selected = ["nat"] + (["kms"] if release_listener or enable_nts else []) + (["ntpd"] if enable_nts else [])
    if enable_nts:
        with SessionLocal() as db:
            errors = {unit["id"]: unit["validation_errors"] for unit in ui.appliance_apply_units(db)
                      if unit["id"] in {*selected, "ca"} and unit["validation_errors"]}
            assert not errors, errors
    response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": selected},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        result = json.loads(job.result)
        assert job.status == "succeeded", result
        if cancel_after_pair:
            assert job.cancel_outcome == "completion-won"
            assert job.cancel_completed_at is not None
        if enable_nts:
            assert result["selected_units"].index("ca") < result["selected_units"].index("ntpd")
            if not release_listener:
                assert result["selected_units"].index("ca") < result["selected_units"].index("kms")
            if management_move:
                assert result["selected_units"].index("network") < result["selected_units"].index("ntpd")
        if release_listener:
            assert result["selected_units"].index("kms") < result["selected_units"].index("firewall")
            if management_move:
                assert result["selected_units"].index("kms") < result["selected_units"].index("network")
        if management_move:
            assert result["management_handoff"] is True
            assert "nat" in result["management_handoff_units"]
        else:
            assert result["traffic_publishing_pair"] is True
            assert result["traffic_publishing_runtime_commit_pending"] is False
            if not enable_nts:
                assert [unit["unit_id"] for unit in result["units"]] == (["kms"] if release_listener else []) + ["firewall", "nat"]
        baselines = ui.load_appliance_apply_baselines(db)
        assert "Atlaso port forward" in baselines["firewall"]["config_preview"]
        assert "[port_forwards]" in baselines["nat"]["config_preview"]
        captured_nat = next(unit for unit in result["captured_units"] if unit["unit_id"] == "nat")
        assert baselines["nat"]["snapshot_hash"] == captured_nat["snapshot_hash"]


@pytest.fixture()
def publication(client, monkeypatch):
    """Create a global task without permitting any host staging.

    Args:
        client: Isolated database and application lifecycle.
        monkeypatch: Substitute only the filesystem staging boundary.
    """
    monkeypatch.setattr(ui, "stage_appliance_apply_config", lambda path, content: path)
    with SessionLocal() as db:
        job = Job(id="job_123456789abc", type="appliance-apply", status="running", created_by="admin", result="{}")
        db.add(job)
        db.commit()
        units = [{
            "id": key, "label": key, "snapshot_hash": f"captured-{key}", "summary": f"captured {key}",
            "config_path": f"/var/lib/atlaso/apply/{key}/candidate", "raw_config_preview": f"captured {key}",
            "config_preview": f"captured {key}", "config_diff": "", "validation_errors": [], "validation_warnings": [],
        } for key in ("firewall", "nat")]
        yield db, job, units


def test_acknowledgement_observes_both_durable_captured_baselines(publication, monkeypatch):
    """The helper cannot receive ACK while either baseline is uncommitted.

    Args:
        publication: Global task with two captured units.
        monkeypatch: Inspect the durable database at helper boundaries.
    """
    db, job, units = publication
    actions = []

    def helper(self, group, action, *args, **kwargs):
        """Read through a separate session at the acknowledgement boundary.

        Args:
            group: Constrained helper group.
            action: Publication phase.
            *args: Non-secret task identity and managed paths.
            **kwargs: Bounded execution options.
        """
        actions.append(action)
        if action == "acknowledge-publishing":
            with SessionLocal() as observed:
                baselines = ui.load_appliance_apply_baselines(observed)
                assert baselines["firewall"]["snapshot_hash"] == "captured-firewall"
                assert baselines["nat"]["snapshot_hash"] == "captured-nat"
                assert json.loads(observed.get(Job, job.id).result)["traffic_publishing_application_committed"] is True
        return AdapterResult([group, action], dry_run=False)

    monkeypatch.setattr(SystemAdapter, "_helper_result", helper)
    results = ui.execute_traffic_publishing_pair(db, job, units, adapter=SystemAdapter(dry_run=False))
    assert all(result["success"] for result in results)
    assert actions == ["validate-publishing", "apply-publishing", "acknowledge-publishing"]
    assert json.loads(job.result)["traffic_publishing_runtime_commit_pending"] is False


@pytest.mark.parametrize("failure", ["publication", "baseline", "acknowledgement"])
def test_pair_failure_preserves_the_correct_commit_decision(publication, monkeypatch, failure):
    """Failures before commit roll back; failures after commit retain forward recovery.

    Args:
        publication: Global task with captured units.
        monkeypatch: Inject one failure at a transaction boundary.
        failure: Publication, baseline persistence, or acknowledgement failure.
    """
    db, job, units = publication
    before = ui.load_appliance_apply_baselines(db)
    actions = []

    def helper(self, group, action, *args, **kwargs):
        """Fail only the selected host phase.

        Args:
            group: Constrained helper group.
            action: Current transaction phase.
            *args: Admitted helper arguments.
            **kwargs: Bounded execution options.
        """
        actions.append(action)
        failed = ((failure == "publication" and action == "apply-publishing")
                  or (failure == "acknowledgement" and action == "acknowledge-publishing"))
        return AdapterResult([group, action], dry_run=False, returncode=int(failed))

    monkeypatch.setattr(SystemAdapter, "_helper_result", helper)
    if failure == "baseline":
        def fail_baseline(*args, **kwargs):
            """Simulate unsuccessful baseline persistence.

            Args:
                *args: Captured baseline inputs.
                **kwargs: Persistence options.
            """
            raise RuntimeError("injected baseline failure")

        monkeypatch.setattr(ui, "update_appliance_apply_baselines", fail_baseline)
        with pytest.raises(RuntimeError, match="baseline failure"):
            ui.execute_traffic_publishing_pair(db, job, units, adapter=SystemAdapter(dry_run=False))
    else:
        results = ui.execute_traffic_publishing_pair(db, job, units, adapter=SystemAdapter(dry_run=False))
        assert not any(result["success"] for result in results)
    if failure != "acknowledgement":
        assert ui.load_appliance_apply_baselines(db) == before
        assert actions[-1] == "recover-publishing"
        assert "acknowledge-publishing" not in actions
    else:
        assert ui.load_appliance_apply_baselines(db)["nat"]["snapshot_hash"] == "captured-nat"
        assert "recover-publishing" not in actions
        job.status = "failed"
        db.commit()
        assert ui.active_appliance_apply_job(db).id == job.id
