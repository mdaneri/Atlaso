"""Test Appliance Apply management UI transport behavior."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from tests.routers.ui.helpers import login


def test_management_path_signature_covers_dedicated_and_flagged_access_transitions():
    """Detect every supported management-listener topology change."""
    from atlaso.app.ui import management_handoff_required, network_management_paths

    dedicated = """[physical_interfaces]
interface=eth0
  role=management
  mode=access
  admin_state=up
  ipv4_method=static
  ip_cidr=192.0.2.10/24
  gateway=192.0.2.1
interface=eth1
  role=access
  mode=access
  admin_state=up
  access_management_ui_enabled=false
  ip_cidr=198.51.100.10/24
"""
    flagged = dedicated.replace("role=management", "role=access", 1).replace(
        "access_management_ui_enabled=false",
        "access_management_ui_enabled=true",
    )

    assert network_management_paths(dedicated) == [
        {
            "kind": "physical",
            "name": "eth0",
            "parent": "",
            "parent_admin_state": "",
            "role": "management",
            "mtu": "",
            "ipv4_method": "static",
            "ip_cidr": "192.0.2.10/24",
            "gateway": "192.0.2.1",
            "ipv6_enabled": "",
            "ipv6_cidr": "",
            "ipv6_gateway": "",
        }
    ]
    assert network_management_paths(flagged) == [
        {
            "kind": "physical",
            "name": "eth1",
            "parent": "",
            "parent_admin_state": "",
            "role": "access",
            "mtu": "",
            "ipv4_method": "",
            "ip_cidr": "198.51.100.10/24",
            "gateway": "",
            "ipv6_enabled": "",
            "ipv6_cidr": "",
            "ipv6_gateway": "",
        }
    ]
    assert management_handoff_required(
        {"raw_config_preview": flagged},
        {"config_preview": dedicated},
    )


def test_management_gateway_route_migration_couples_only_unapplied_default():
    """Detect the exact default route created from a removed management gateway."""
    from atlaso.app.ui import (
        management_gateway_route_migrations,
        wan_rollback_config_preview,
    )

    previous_network = """[physical_interfaces]
interface=eth0
role=management
mode=access
admin_state=up
ipv4_method=static
ip_cidr=192.0.2.10/24
gateway=192.0.2.1
ipv6_enabled=false
ipv6_cidr=
ipv6_gateway=
"""
    candidate_network = previous_network.replace(
        "role=management", "role=access"
    ).replace(
        "gateway=192.0.2.1",
        "gateway=\naccess_management_ui_enabled=true",
    )
    previous_wan = """[targets]
target=eth0
role=access
ip_cidr=192.0.2.10/24
management_ui=false
[routes]
[removed_routes]
[routing_rules]
[nat_rules]
[wan_policies]
"""
    candidate_wan = previous_wan.replace(
        "management_ui=false",
        "management_ui=true",
    ).replace(
        "[routes]",
        "[routes]\nroute=0.0.0.0/0\ngateway=192.0.2.1\ninterface=eth0\nmetric=100\nenabled=true",
    )
    migrations = management_gateway_route_migrations(
        {"raw_config_preview": candidate_network},
        {"config_preview": previous_network},
        {"raw_config_preview": candidate_wan},
        {"config_preview": previous_wan},
    )

    assert migrations == [
        {
            "family": "4",
            "destination_cidr": "0.0.0.0/0",
            "gateway": "192.0.2.1",
            "interface": "eth0",
        }
    ]
    assert management_gateway_route_migrations(
        {
            "raw_config_preview": candidate_network.replace(
                "access_management_ui_enabled=true",
                "access_management_ui_enabled=false",
            )
        },
        {"config_preview": previous_network},
        {"raw_config_preview": candidate_wan},
        {"config_preview": previous_wan},
    ) == migrations
    rollback = wan_rollback_config_preview(
        candidate_wan, {"config_preview": previous_wan}
    )
    assert "[removed_routes]" in rollback
    assert "route=0.0.0.0/0" in rollback
    assert "interface=eth0" in rollback
    assert "[removed_main_defaults]" in rollback
    assert "route=0.0.0.0/0" in rollback
    assert (
        management_gateway_route_migrations(
            {"raw_config_preview": candidate_network},
            {"config_preview": previous_network},
            {"raw_config_preview": candidate_wan},
            {"config_preview": candidate_wan},
        )
        == []
    )


def test_wan_rollback_removes_new_mirror_without_removing_retained_lab_route():
    """Encode host-only cleanup when an existing lab default becomes mirrored."""
    from atlaso.app.ui import wan_rollback_config_preview

    baseline = """[targets]
target=eth0
role=access
ip_cidr=192.0.2.10/24
management_ui=false
[routes]
route=0.0.0.0/0
gateway=192.0.2.1
interface=eth0
metric=100
enabled=true
[removed_routes]
[routing_rules]
[nat_rules]
[wan_policies]
"""
    candidate = baseline.replace("management_ui=false", "management_ui=true")

    rollback = wan_rollback_config_preview(
        candidate,
        {"config_preview": baseline},
    )

    assert rollback.count("route=0.0.0.0/0") == 2
    assert "[removed_routes]" in rollback
    assert "[removed_main_defaults]" in rollback


def test_appliance_settings_stages_flagged_access_resolver_interface(client):
    """Bind resolver staging to the effective flagged-access listener.

    Args:
        client: HTTP test client used to initialize an isolated database.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "198.51.100.10/24"
        interface.access_management_ui_enabled = True
        db.commit()

        context = ui.appliance_settings_context(db, reconcile_dns=False)

    preview = json.loads(context["appliance_settings_config_preview"])
    assert context["management_interface"]["name"] == "eth0"
    assert preview["management_interface"] == "eth0"
    assert preview["management_ip"] == "198.51.100.10"


def test_appliance_settings_uses_last_applied_dns_state_for_resolver(client):
    """Keep loopback DNS pending until the DNS/DHCP unit is applied.

    Args:
        client: HTTP test client used to initialize an isolated database.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings

    assert ui.applied_local_dns_enabled({"summary": ["DNS enabled"]}) is True
    assert ui.applied_local_dns_enabled({"summary": ["DNS disabled"]}) is False

    with SessionLocal() as db:
        dns_settings = db.query(DnsSettings).one()
        dns_settings.enabled = True
        db.commit()
        ui.save_appliance_apply_baselines(
            db,
            {"dnsmasq": {"summary": ["DNS disabled"], "dns_enabled": False}},
        )
        db.commit()

        pending_context = ui.appliance_settings_context(db, reconcile_dns=False)
        pending_preview = json.loads(pending_context["appliance_settings_config_preview"])
        assert pending_context["local_dns_enabled"] is False
        assert pending_preview["resolver_mode"] != "local_dns"
        assert pending_preview["resolver_servers"] != ["127.0.0.1"]

        ui.save_appliance_apply_baselines(
            db,
            {"dnsmasq": {"summary": ["DNS enabled"], "dns_enabled": True}},
        )
        db.commit()
        applied_context = ui.appliance_settings_context(db, reconcile_dns=False)
        applied_preview = json.loads(applied_context["appliance_settings_config_preview"])
        assert applied_context["local_dns_enabled"] is True
        assert applied_preview["resolver_mode"] == "local_dns"
        assert applied_preview["resolver_servers"] == ["127.0.0.1"]

        dns_settings.enabled = False
        db.commit()
        disabling_context = ui.appliance_settings_context(db, reconcile_dns=False)
        disabling_preview = json.loads(disabling_context["appliance_settings_config_preview"])

    assert disabling_context["local_dns_enabled"] is False
    assert disabling_preview["resolver_mode"] != "local_dns"
    assert disabling_preview["resolver_servers"] != ["127.0.0.1"]


def test_local_dns_disable_forces_resolver_move_before_dns_stop(client):
    """Move the resolver before an applied local DNS listener is disabled.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DnsSettings, Job
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        dns_settings = db.query(DnsSettings).one()
        dns_settings.enabled = True
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {"appliance_settings"})
        dns_settings.enabled = False
        db.commit()
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "dnsmasq"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["selected_units"] == ["appliance_settings", "dnsmasq"]
    assert [unit["unit_id"] for unit in payload["captured_units"]] == [
        "appliance_settings",
        "dnsmasq",
    ]


def test_management_handoff_fails_closed_without_network_baseline():
    """Require the handoff path when no known-good baseline can identify the old listener."""
    from atlaso.app.ui import management_handoff_required

    network_unit = {
        "raw_config_preview": """[physical_interfaces]
interface=eth1
  role=management
  mode=access
  admin_state=up
  ipv4_method=static
  ip_cidr=198.51.100.10/24
"""
    }

    assert management_handoff_required(network_unit, None)


def test_management_handoff_detects_ipv6_router_advertisement_toggle():
    """Treat SLAAC enablement as a management listener topology change."""
    from atlaso.app.ui import management_handoff_required

    previous = """[physical_interfaces]
interface=eth0
  role=management
  mode=access
  admin_state=up
  ipv4_method=static
  ip_cidr=192.0.2.10/24
  ipv6_enabled=false
"""
    candidate = previous.replace("ipv6_enabled=false", "ipv6_enabled=true")

    assert management_handoff_required(
        {"raw_config_preview": candidate},
        {"config_preview": previous},
    )


def test_management_handoff_detects_flagged_access_vlan_mtu_change():
    """Treat a management-listener VLAN MTU change as a handoff boundary."""
    from atlaso.app.ui import management_handoff_required, network_management_paths

    previous = """[vlan_interfaces]
vlan=eth1.20
  parent=eth1
  role=access
  admin_state=up
  access_management_ui_enabled=true
  mtu=1500
  ipv4_method=static
  ip_cidr=192.0.2.20/24
"""
    candidate = previous.replace("mtu=1500", "mtu=9000")

    assert management_handoff_required(
        {"raw_config_preview": candidate},
        {"config_preview": previous},
    )

    assert network_management_paths(previous.replace("admin_state=up", "enabled=false")) == []


def test_management_handoff_detects_flagged_access_vlan_parent_admin_down():
    """Protect a management VLAN when its trunk parent is disabled."""
    from atlaso.app.ui import management_handoff_required, network_management_paths

    previous = """[physical_interfaces]
interface=eth1
  role=access
  mode=trunk
  admin_state=up
[vlan_interfaces]
vlan=eth1.20
  parent=eth1
  role=access
  admin_state=up
  access_management_ui_enabled=true
  mtu=1500
  ipv4_method=static
  ip_cidr=192.0.2.20/24
"""
    candidate = previous.replace("admin_state=up", "admin_state=down", 1)

    previous_paths = network_management_paths(previous)
    candidate_paths = network_management_paths(candidate)
    assert previous_paths[0]["parent_admin_state"] == "up"
    assert candidate_paths[0]["parent_admin_state"] == "down"
    assert management_handoff_required(
        {"raw_config_preview": candidate},
        {"config_preview": previous},
    )


@pytest.mark.parametrize("failure_target", ["ca", "manifest"])
def test_management_handoff_staging_failure_removes_private_ca_payload(
    monkeypatch,
    tmp_path,
    failure_target,
):
    """Remove the transient private-key payload on every staging failure.

    Args:
        monkeypatch: Pytest fixture used to inject the staging failure.
        tmp_path: Temporary root containing the secret and manifest payloads.
        failure_target: Staging operation that fails after the CA file is written.
    """
    from atlaso.app import ui

    class UnusedAdapter:
        """Reject helper calls because staging must fail first."""

        dry_run = False

        def validate_management_handoff(self, _manifest_path):
            """Fail if staging unexpectedly reaches helper validation.

            Args:
                _manifest_path: Staged manifest that must not reach validation.
            """
            raise AssertionError("helper validation must not run after staging failure")

    unit_defaults = {
        "label": "Management handoff component",
        "summary": "Apply the management handoff component.",
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "",
        "config_preview": "",
        "config_diff": "",
        "raw_config_preview": "",
    }
    units = {
        unit_id: {**unit_defaults, "id": unit_id}
        for unit_id in ui.MANAGEMENT_HANDOFF_UNIT_IDS
    }
    units["network"]["previous_management_paths"] = []
    units["network"]["removed_vlan_interfaces"] = []
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": []}
    ca_path = tmp_path / "atlaso-ca.json"
    manifest_path = tmp_path / "atlaso-management-handoff.json"
    monkeypatch.setattr(ui, "CA_STAGED_CONFIG_PATH", str(ca_path))
    monkeypatch.setattr(ui, "MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db: {"appliance_settings": {}})
    monkeypatch.setattr(ui, "network_config_with_removed_vlans", lambda preview, _removed: preview)
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "private-key-payload")

    def stage_config(target, content):
        """Write the CA payload, then inject the selected staging failure.

        Args:
            target: Canonical staged configuration path.
            content: Rendered staged configuration content.
        """
        if str(target) == str(ca_path):
            ca_path.write_text(content, encoding="utf-8")
            if failure_target == "ca":
                raise OSError("CA staging interrupted")
        if str(target) == str(manifest_path):
            raise OSError("manifest staging interrupted")
        return str(target)

    monkeypatch.setattr(ui, "stage_appliance_apply_config", stage_config)

    with pytest.raises(OSError, match="staging interrupted"):
        ui.execute_management_handoff(
            units,
            job_id="job_secret_cleanup_435",
            adapter=UnusedAdapter(),
            db=object(),
        )

    assert not ca_path.exists()
    assert not manifest_path.exists()


def test_management_handoff_timeout_stops_and_recovers_indeterminate_helper(monkeypatch):
    """Recover the fixed helper unit when the adapter wait times out.

    Args:
        monkeypatch: Pytest fixture used to isolate staging and helper execution.
    """
    from atlaso.app import ui
    from atlaso.app.adapters.system import AdapterResult

    class TimeoutAdapter:
        """Return an indeterminate apply result followed by proven rollback."""

        dry_run = False

        def __init__(self):
            """Initialize the recorded helper actions."""
            self.actions: list[str] = []

        def validate_management_handoff(self, manifest_path):
            """Accept the staged manifest.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            self.actions.append("validate")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "validate", manifest_path],
                dry_run=False,
                returncode=0,
            )

        def apply_management_handoff(self, manifest_path):
            """Return the adapter timeout used for indeterminate execution.

            Args:
                manifest_path: Staged handoff manifest path.
            """
            self.actions.append("apply")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "apply", manifest_path],
                dry_run=False,
                stderr="management handoff helper wait timed out",
                returncode=124,
            )

        def recover_management_handoff(self):
            """Return bounded proof that the surviving helper was rolled back."""
            self.actions.append("recover")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "recover"],
                dry_run=False,
                stdout=json.dumps(
                    {
                        "management_handoff": "rolled back after interruption",
                        "rolled_back": True,
                        "failing_layer": "interruption serialization",
                    }
                ),
                returncode=0,
            )

    unit_defaults = {
        "label": "Management handoff component",
        "summary": "Apply the management handoff component.",
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "",
        "config_preview": "",
        "config_diff": "",
        "raw_config_preview": "",
    }
    units = {
        unit_id: {**unit_defaults, "id": unit_id}
        for unit_id in ui.MANAGEMENT_HANDOFF_UNIT_IDS
    }
    units["network"]["previous_management_paths"] = [
        {
            "name": "eth0.20",
            "parent": "eth0",
            "ip_cidr": "192.0.2.10/24",
            "ipv6_cidr": "",
        }
    ]
    units["network"]["removed_vlan_interfaces"] = []
    units["ca"]["context"] = {"ca_settings": object(), "ca_certificates": []}
    monkeypatch.setattr(ui, "load_appliance_apply_baselines", lambda _db: {"appliance_settings": {}})
    staged: dict[str, str] = {}

    def stage_config(target, content):
        """Capture staged handoff content by target path.

        Args:
            target: Canonical staged configuration path.
            content: Rendered staged configuration content.

        Returns:
            The unchanged target path.
        """
        staged[str(target)] = content
        return target

    monkeypatch.setattr(ui, "stage_appliance_apply_config", stage_config)
    monkeypatch.setattr(ui, "render_ca_apply_payload", lambda *_args, **_kwargs: "{}")
    adapter = TimeoutAdapter()

    group, results = ui.execute_management_handoff(
        units,
        job_id="job_timeout435",
        adapter=adapter,
        db=object(),
    )

    assert adapter.actions == ["validate", "apply", "recover"]
    assert group["success"] is False
    assert group["rollback_proven"] is True
    assert group["management_handoff"]["management_handoff"] == "rolled back"
    assert group["management_handoff"]["failing_layer"] == "handoff helper wait"
    assert all(result["rolled_back"] is True for result in results)
    manifest = json.loads(staged[str(ui.MANAGEMENT_HANDOFF_STAGED_MANIFEST_PATH)])
    assert manifest["previous_management_interfaces"] == ["eth0.20"]
    assert manifest["previous_management_parent_interfaces"] == ["eth0"]
    assert manifest["previous_management_paths"] == [
        {
            "name": "eth0.20",
            "ipv4_method": "",
            "ipv6_enabled": "",
            "ipv6_cidr": "",
        }
    ]


def test_management_handoff_settings_baseline_ignores_only_applied_front_door_fields():
    """Keep unrelated Appliance Settings pending after the management transaction."""
    from atlaso.app.ui import management_handoff_completes_appliance_settings

    previous = {
        "fqdn": "atlaso.example",
        "resolver_mode": "dhcp",
        "resolver_servers": [],
        "local_dns_enabled": False,
        "management_interface": "eth0",
        "management_ip": "192.0.2.10",
        "management_https_enabled": True,
        "root_ssh_enabled": False,
    }
    baseline = {"config_preview": json.dumps(previous)}
    management_only = {
        **previous,
        "resolver_mode": "local_dns",
        "resolver_servers": ["127.0.0.1"],
        "local_dns_enabled": True,
        "management_interface": "eth1",
        "management_ip": "198.51.100.10",
    }

    assert management_handoff_completes_appliance_settings(json.dumps(management_only), baseline)
    assert not management_handoff_completes_appliance_settings(
        json.dumps({**management_only, "root_ssh_enabled": True}),
        baseline,
    )


def test_appliance_apply_router_owns_exact_transport_set():
    """Keep the extracted route identities and response classes exact."""
    from atlaso.app import ui

    assert [
        (
            route.path,
            tuple(sorted((route.methods or set()) - {"HEAD"})),
            route.name,
            route.response_class.__name__,
        )
        for route in ui.appliance_apply_router.routes
    ] == [
        (
            "/ui/management/appliance-apply",
            ("GET",),
            "appliance_apply_page",
            "RedirectResponse",
        ),
        (
            "/ui/management/appliance-apply/review",
            ("GET",),
            "appliance_apply_review",
            "JSONResponse",
        ),
        (
            "/ui/management/appliance-apply/status",
            ("GET",),
            "appliance_apply_status_api",
            "JSONResponse",
        ),
        (
            "/ui/management/appliance-apply",
            ("POST",),
            "submit_appliance_apply",
            "HTMLResponse",
        ),
    ]


def test_appliance_apply_status_tolerates_duplicate_managed_certificate_owners(client):
    """Verify that status tolerates duplicate managed certificate owners.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate

    login(client)
    with SessionLocal() as db:
        db.add_all(
            [
                CaCertificate(
                    common_name="older-kms.atlaso.internal",
                    managed_owner="kms:server",
                    status="planned",
                ),
                CaCertificate(
                    common_name="newer-kms.atlaso.internal",
                    managed_owner="kms:server",
                    status="issued",
                    certificate_pem="test-certificate",
                    private_key_encrypted="test-encrypted-key",
                ),
            ]
        )
        db.commit()

    response = client.get("/appliance-apply/status")

    assert response.status_code == 200
    assert response.json()["units"]


def test_appliance_apply_status_uses_lightweight_projection(client, monkeypatch):
    """Verify ordinary status polling never runs apply-time reconciliation.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui

    login(client)
    original = ui.appliance_apply_units
    monkeypatch.setattr(ui, "_appliance_apply_status_cache", None)
    reconcile_values = []

    def tracked_units(db, *, reconcile=True):
        """Track reconciliation selection.

        Args:
            db: Active database session.
            reconcile: Whether dependent desired state should be reconciled.
        """
        reconcile_values.append(reconcile)
        return original(db, reconcile=reconcile)

    monkeypatch.setattr(ui, "appliance_apply_units", tracked_units)
    first = client.get("/appliance-apply/status")
    second = client.get("/appliance-apply/status")
    users_page = client.get("/users")
    refreshed = client.get("/appliance-apply/status?refresh=true")

    assert first.status_code == 200
    assert second.status_code == 200
    assert users_page.status_code == 200
    assert refreshed.status_code == 200
    assert first.json().keys() == second.json().keys()
    assert reconcile_values == [False, False]


def test_appliance_apply_status_preserves_planned_management_restart_context(client, monkeypatch):
    """Keep durable reconnect context available before the management front door restarts.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    observed_at = datetime(2026, 8, 20, 19, 30, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(ui, "utcnow", lambda: observed_at)
    login(client)
    with SessionLocal() as db:
        job = Job(
            id="job_planned_management_restart",
            type="appliance-apply",
            status=JobStatus.RUNNING.value,
            created_by="admin",
            progress_percent=50,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": {
                        "kind": "planned_service_restart",
                        "restart_delay_seconds": 3,
                        "grace_seconds": 15,
                    },
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=datetime(2026, 8, 20, 19, 30, 0),
                result="{}",
            )
        )
        db.add(
            JobStep(
                id=f"{job.id}:firewall",
                job=job,
                component_key="firewall",
                label="Firewall",
                position=2,
                status=JobStatus.RUNNING.value,
                progress_percent=50,
                result="{}",
            )
        )
        db.commit()

    response = client.get("/appliance-apply/status")

    assert response.status_code == 200
    task = response.json()["active_task"]
    assert task["id"] == "job_planned_management_restart"
    assert task["result"]["management_status_transition"] == {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    assert task["management_restart_window"] == {
        "restart_delay_remaining_ms": 2000,
        "remaining_ms": 17000,
    }
    assert [(step["component_key"], step["status"]) for step in task["_children"]] == [
        ("appliance_settings", "succeeded"),
        ("firewall", "running"),
    ]
    assert task["_children"][0]["finished_at"] == "2026-08-20T19:30:00+00:00"


def test_appliance_apply_status_retains_terminal_planned_restart_lock(client, monkeypatch):
    """Keep a settings-only task and the mutation lock through its restart window.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    observed_at = datetime(2026, 8, 20, 20, 30, tzinfo=timezone.utc)
    monkeypatch.setattr(ui, "utcnow", lambda: observed_at)
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    transition = {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    with SessionLocal() as db:
        job = Job(
            id="job_terminal_management_restart",
            type="appliance-apply",
            status=JobStatus.SUCCEEDED.value,
            created_by="admin",
            progress_percent=100,
            finished_at=observed_at,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": transition,
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=observed_at,
                result="{}",
            )
        )
        db.commit()

    retained = client.get("/appliance-apply/status?refresh=true")
    assert retained.status_code == 200
    assert retained.json()["locked"] is True
    assert retained.json()["active_task"]["id"] == "job_terminal_management_restart"
    assert retained.json()["active_task"]["status"] == JobStatus.SUCCEEDED.value
    assert retained.json()["active_task"]["mutation_locked"] is True
    assert retained.json()["active_task"]["management_restart_window"] == {
        "restart_delay_remaining_ms": 3000,
        "remaining_ms": 18000,
    }

    blocked = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
    )
    assert blocked.status_code == 423
    assert blocked.json()["job_id"] == "job_terminal_management_restart"

    monkeypatch.setattr(ui, "utcnow", lambda: observed_at + timedelta(seconds=19))
    released = client.get("/appliance-apply/status?refresh=true")
    assert released.status_code == 200
    assert released.json()["locked"] is False
    assert released.json()["active_task"] is None


@pytest.mark.parametrize("terminal_status", ["failed", "cancelled"])
def test_appliance_apply_status_retains_non_successful_terminal_restart_lock(
    client,
    monkeypatch,
    terminal_status,
):
    """Retain every terminal master carrying a valid confirmed restart.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        terminal_status: Terminal master status exercised by the regression.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    observed_at = datetime(2026, 8, 20, 20, 45, tzinfo=timezone.utc)
    monkeypatch.setattr(ui, "utcnow", lambda: observed_at)
    login(client)
    with SessionLocal() as db:
        job = Job(
            id=f"job_terminal_management_restart_{terminal_status}",
            type="appliance-apply",
            status=terminal_status,
            created_by="admin",
            progress_percent=100,
            finished_at=observed_at,
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "management_status_transition": {
                        "kind": "planned_service_restart",
                        "restart_delay_seconds": 3,
                        "grace_seconds": 15,
                    },
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.SUCCEEDED.value,
                progress_percent=100,
                finished_at=observed_at,
                result="{}",
            )
        )
        db.commit()

    retained = client.get("/appliance-apply/status?refresh=true")
    assert retained.status_code == 200
    assert retained.json()["locked"] is True
    assert retained.json()["active_task"]["status"] == terminal_status
    assert retained.json()["active_task"]["mutation_locked"] is True


def test_appliance_apply_transition_context_requires_helper_confirmation():
    """Mark only a real helper-confirmed Appliance Settings restart as planned."""
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.ui import appliance_settings_management_status_transition

    confirmed = AdapterResult(
        command=["atlaso-helper", "appliance-settings", "apply"],
        dry_run=False,
        stdout=json.dumps(
            {
                "appliance_settings": "apply complete",
                "management_status_transition": {
                    "kind": "planned_service_restart",
                    "restart_delay_seconds": 3,
                },
            }
        ),
    )
    assert appliance_settings_management_status_transition([confirmed]) == {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=False, stdout='{"appliance_settings":"apply complete"}')]
    ) is None
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=True, stdout=confirmed.stdout)]
    ) is None
    assert appliance_settings_management_status_transition(
        [AdapterResult(command=confirmed.command, dry_run=False, stdout=confirmed.stdout, returncode=1)]
    ) is None


def test_appliance_apply_job_persists_helper_confirmed_transition(client, monkeypatch):
    """Persist confirmed restart context before the helper's delayed restart fires.

    Args:
        client: HTTP test client used to initialize an isolated database.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, JobStep

    transition = {
        "kind": "planned_service_restart",
        "restart_delay_seconds": 3,
        "grace_seconds": 15,
    }
    unit = {
        "id": "appliance_settings",
        "label": "Appliance Settings",
        "snapshot_hash": "captured-settings",
        "summary": ["Apply settings"],
        "validation_errors": [],
        "validation_warnings": [],
        "config_path": "/etc/atlaso/atlaso-settings.json",
        "config_preview": "{}\n",
        "config_diff": "",
    }
    with SessionLocal() as db:
        job = Job(
            id="job_confirmed_management_restart",
            type="appliance-apply",
            status=JobStatus.PENDING.value,
            created_by="admin",
            result=json.dumps(
                {
                    "selected_units": ["appliance_settings"],
                    "captured_units": [
                        {
                            "unit_id": "appliance_settings",
                            "snapshot_hash": "captured-settings",
                        }
                    ],
                    "units": [],
                    "dry_run": False,
                }
            ),
        )
        db.add(job)
        db.add(
            JobStep(
                id=f"{job.id}:appliance_settings",
                job=job,
                component_key="appliance_settings",
                label="Appliance Settings",
                position=1,
                status=JobStatus.PENDING.value,
                result="{}",
            )
        )
        db.commit()

    unit_projection_calls = 0
    durable_before_reconciliation = False

    def appliance_apply_units_with_durable_probe(_db, reconcile=True):
        """Verify confirmed restart state before post-helper reconciliation.

        Args:
            _db: Active job database session.
            reconcile: Whether to reconcile current host observations.
        """
        nonlocal unit_projection_calls, durable_before_reconciliation
        unit_projection_calls += 1
        if unit_projection_calls == 2:
            with SessionLocal() as verification_db:
                persisted = verification_db.get(Job, "job_confirmed_management_restart")
                assert persisted is not None
                persisted_step = verification_db.get(
                    JobStep,
                    "job_confirmed_management_restart:appliance_settings",
                )
                durable_before_reconciliation = (
                    json.loads(persisted.result or "{}").get("management_status_transition") == transition
                    and persisted_step is not None
                    and persisted_step.status == JobStatus.SUCCEEDED.value
                    and persisted_step.finished_at is not None
                )
        return [unit]

    monkeypatch.setattr(ui, "appliance_apply_units", appliance_apply_units_with_durable_probe)
    monkeypatch.setattr(
        ui,
        "execute_appliance_apply_unit",
        lambda _unit, **_kwargs: {
            **unit,
            "unit_id": "appliance_settings",
            "success": True,
            "status": JobStatus.SUCCEEDED.value,
            "dry_run": False,
            "commands": [],
            "management_status_transition": transition,
        },
    )

    ui.run_appliance_apply_job("job_confirmed_management_restart")

    with SessionLocal() as db:
        completed = db.get(Job, "job_confirmed_management_restart")
        assert completed is not None
        assert completed.status == JobStatus.SUCCEEDED.value
        assert json.loads(completed.result or "{}")["management_status_transition"] == transition
    assert durable_before_reconciliation is True


def test_appliance_apply_review_returns_management_address_connection_warning(client):
    """Verify review returns the management-address connection warning.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.20/24"
        db.commit()

    review = client.get("/appliance-apply/review")

    assert review.status_code == 200
    network = next(unit for unit in review.json()["units"] if unit["id"] == "network")
    assert len(network["connection_warnings"]) == 1
    assert "from 192.168.49.1/24 to 192.168.49.20/24" in network["connection_warnings"][0]


def test_management_move_forces_partial_dependency_selection_into_handoff(client):
    """Bundle every runtime layer when Firewall alone is selected for a pending move.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.21/24"
        db.commit()
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
        assert payload["management_handoff"] is True
        assert set(payload["management_handoff_units"]) == {
            "ca",
            "network",
            "firewall",
            "appliance_settings",
            "public_services",
        }
        assert all(
            unit["management_handoff"]["management_handoff"] == "committed"
            for unit in payload["units"]
        )


@pytest.mark.parametrize("listener_change", ["unflag", "admin_down"])
def test_mirror_changing_listener_edit_forces_wan_into_handoff(
    client,
    listener_change,
):
    """Execute host-default cleanup in every protected listener handoff."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.10/24"
        interface.access_management_ui_enabled = True
        db.add(
            Route(
                destination_cidr="0.0.0.0/0",
                gateway="192.168.50.1",
                interface_name="eth2",
                enabled=True,
            )
        )
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        if listener_change == "unflag":
            interface.access_management_ui_enabled = False
        else:
            interface.admin_state = "down"
        db.commit()
        invalid = {
            unit["id"]: unit["validation_errors"]
            for unit in appliance_apply_units(db)
            if unit["validation_errors"]
        }
        assert invalid == {}

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert set(payload["management_handoff_units"]) == {
        "ca",
        "network",
        "firewall",
        "appliance_settings",
        "public_services",
        "wan",
    }
    assert "wan" in payload["selected_units"]
    assert any(unit["unit_id"] == "wan" for unit in payload["units"])


@pytest.mark.parametrize("route_change", ["gateway", "metric", "disable", "remove"])
def test_standalone_mirrored_default_edit_starts_management_handoff(
    client,
    route_change,
):
    """Protect every host-default mutation submitted from Routes & WAN."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        db.query(Route).delete()
        interface = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert interface is not None
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "static"
        interface.ip_cidr = "192.168.50.10/24"
        interface.access_management_ui_enabled = True
        route = Route(
            destination_cidr="0.0.0.0/0",
            gateway="192.168.50.1",
            interface_name="eth2",
            metric=100,
            enabled=True,
        )
        db.add(route)
        db.commit()
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        if route_change == "gateway":
            route.gateway = "192.168.50.2"
        elif route_change == "metric":
            route.metric = 200
        elif route_change == "disable":
            route.enabled = False
        else:
            db.delete(route)
        db.commit()

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "wan"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert set(payload["management_handoff_units"]) == {
        "ca",
        "network",
        "firewall",
        "appliance_settings",
        "public_services",
        "wan",
    }
    assert any(unit["unit_id"] == "wan" for unit in payload["units"])


def test_selected_wan_change_executes_inside_existing_management_handoff(client):
    """Apply a captured non-mirror WAN edit with the protected Network change."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface, Route
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    with SessionLocal() as db:
        units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        )
        access = db.scalar(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth2")
        )
        assert management is not None
        assert access is not None
        management.ip_cidr = "192.168.49.21/24"
        access.role = "access"
        access.mode = "access"
        access.admin_state = "up"
        access.oper_state = "up"
        access.ipv4_method = "static"
        access.ip_cidr = "192.168.50.10/24"
        db.add(
            Route(
                destination_cidr="203.0.113.0/24",
                gateway="192.168.50.1",
                interface_name="eth2",
                enabled=True,
            )
        )
        db.commit()

    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": ["network", "wan"]},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert "wan" in payload["management_handoff_units"]
    assert any(unit["unit_id"] == "wan" for unit in payload["units"])


def test_management_move_rechecks_handoff_after_ldap_dependency_expansion(client, monkeypatch):
    """Protect a Firewall unit added indirectly by the LDAP dependency closure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to isolate background execution.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.22/24"
        db.commit()

    real_units = ui.appliance_apply_units

    def units_with_ldap_firewall_dependency(db, *, reconcile=True):
        """Mark LDAP active and its generated Firewall dependency changed.

        Args:
            db: Active database session.
            reconcile: Whether desired-state dependencies should be reconciled.

        Returns:
            Appliance Apply units with the indirect LDAP dependency active.
        """
        units = real_units(db, reconcile=reconcile)
        unit_map = {unit["id"]: unit for unit in units}
        unit_map["ldap"]["context"]["ldap_organizations"] = [object()]
        unit_map["ldap"]["changed"] = True
        unit_map["firewall"]["changed"] = True
        return units

    monkeypatch.setattr(ui, "appliance_apply_units", units_with_ldap_firewall_dependency)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "ldap"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        payload = json.loads(job.result or "{}")
    assert payload["management_handoff"] is True
    assert set(payload["management_handoff_units"]) == {
        "ca",
        "network",
        "firewall",
        "appliance_settings",
        "public_services",
    }
    assert "ldap" in payload["selected_units"]


def test_management_handoff_baselines_exact_applied_snapshot(client, monkeypatch):
    """Leave a desired-state edit saved during readiness pending.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to inject a concurrent desired-state edit.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.21/24"
        db.commit()

    original_execute = ui.execute_management_handoff

    def execute_with_concurrent_edit(*args, **kwargs):
        """Apply the captured candidate, then save a newer desired address.

        Args:
            *args: Positional arguments forwarded to the production executor.
            **kwargs: Keyword arguments forwarded to the production executor.

        Returns:
            The production management-handoff result.
        """
        result = original_execute(*args, **kwargs)
        with SessionLocal() as edit_db:
            management = edit_db.scalar(
                select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
            )
            assert management is not None
            management.ip_cidr = "192.168.49.22/24"
            edit_db.commit()
        return result

    monkeypatch.setattr(ui, "execute_management_handoff", execute_with_concurrent_edit)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        assert job.status == JobStatus.SUCCEEDED.value
        payload = json.loads(job.result or "{}")
        captured = next(
            unit for unit in payload["captured_units"] if unit["unit_id"] == "network"
        )
        baseline = ui.load_appliance_apply_baselines(db)["network"]
        current = next(
            unit
            for unit in ui.appliance_apply_units(db, reconcile=False)
            if unit["id"] == "network"
        )
        assert baseline["snapshot_hash"] == captured["snapshot_hash"]
        assert baseline["config_preview"] == captured["config_preview"]
        assert current["snapshot_hash"] != baseline["snapshot_hash"]
        assert current["changed"] is True


def test_management_handoff_persists_helper_confirmed_dynamic_address(client, monkeypatch):
    """Publish a DHCP listener binding from the address probed by the handoff helper.

    Args:
        client: HTTP test client providing an isolated database.
        monkeypatch: Pytest fixture used to provide the post-handoff host observation.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services.management_bindings import applied_management_bindings
    from atlaso.app.services.networking import HostPhysicalInterface

    config_preview = """\
[physical_interfaces]
interface=eth0
role=management
mode=access
admin_state=up
ipv4_method=dhcp
ip_cidr=
ipv6_enabled=false
ipv6_cidr=
"""
    observed = HostPhysicalInterface(
        name="eth0",
        mac_address="00:15:5d:01:01:01",
        driver="vmxnet3",
        speed="10000 Mbps",
        host_ip_cidr="192.168.167.134/24",
        host_mtu=1500,
        host_admin_state="up",
        oper_state="up",
    )
    monkeypatch.setattr(ui, "discover_host_physical_interfaces", lambda: [observed])

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert interface is not None
        interface.role = "management"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.ipv4_method = "dhcp"
        interface.ip_cidr = None
        interface.host_ip_cidr = "192.168.49.10/24"
        ui.refresh_management_handoff_dynamic_observations(
            db,
            config_preview,
            {"candidate_addresses": ["192.168.167.134"]},
        )
        ui.save_appliance_apply_baselines(
            db,
            {"network": {"config_preview": config_preview}},
        )
        db.commit()

    with SessionLocal() as db:
        assert applied_management_bindings(db) == [
            {
                "interface": "eth0",
                "role": "management",
                "address": "192.168.167.134",
                "management_ui": "true",
            }
        ]


def test_management_handoff_staging_failure_clears_unstarted_runtime_lock(client, monkeypatch):
    """Do not retain the Apply lock when the helper proves no transaction began.

    Args:
        client: HTTP test client providing an isolated database.
        monkeypatch: Pytest fixture used to fail before privileged helper execution.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface

    login(client)
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        management = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert management is not None
        management.ip_cidr = "192.168.49.21/24"
        db.commit()

    original_run = ui.run_appliance_apply_job
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        ui,
        "execute_management_handoff",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("staging failed")),
    )
    no_transaction = AdapterResult(
        command=["atlaso-helper", "management-handoff", "recover"],
        dry_run=False,
        stdout=json.dumps(
            {
                "management_handoff": "no interrupted transaction",
                "rolled_back": False,
            }
        ),
        returncode=0,
    )
    monkeypatch.setattr(
        ui,
        "reconcile_management_handoff_exception",
        lambda *_args, **_kwargs: (
            no_transaction,
            ui.management_handoff_result_evidence(no_transaction),
        ),
    )
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "network"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        job.created_by = "console:root"
        db.commit()
    original_run(response.json()["job_id"], force_real=True)
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        assert job.status == JobStatus.FAILED.value
        payload = json.loads(job.result or "{}")
        assert "management_handoff_runtime_commit_pending" not in payload
        assert "management_handoff_application_committed" not in payload
        recovery = payload["management_handoff_exception_recovery"]["evidence"]
        assert recovery["management_handoff"] == "no interrupted transaction"
        assert "no runtime rollback was necessary" in (job.error or "")
        assert ui.active_appliance_apply_job(db) is None


def test_interrupted_handoff_reconciles_application_commit_without_false_rollback(client, monkeypatch):
    """Acknowledge a committed baseline and distinguish a missing rollback marker.

    Args:
        client: HTTP test client providing an isolated database.
        monkeypatch: Pytest fixture used to replace privileged helper calls.
    """
    import atlaso.app.ui as ui
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    recovery_calls: list[str] = []

    class RecoveryAdapter:
        """Return deterministic commit and no-marker recovery evidence."""

        def __init__(self, **_kwargs):
            """Accept the production adapter construction contract.

            Args:
                **_kwargs: Adapter options ignored by this test double.
            """

        def acknowledge_management_handoff(self, job_id):
            """Return an idempotent acknowledgement for the committed task.

            Args:
                job_id: Appliance Apply task being acknowledged.
            """
            recovery_calls.append(f"acknowledge:{job_id}")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "acknowledge", job_id],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "already committed", "job_id": job_id}),
                returncode=0,
            )

        def recover_management_handoff(self):
            """Return a successful command that explicitly performed no rollback."""
            recovery_calls.append("recover")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "recover"],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "no interrupted transaction", "rolled_back": False}),
                returncode=0,
            )

    monkeypatch.setattr(ui, "SystemAdapter", RecoveryAdapter)
    with SessionLocal() as db:
        db.add(
            Job(
                id="handoff-committed",
                type="appliance-apply",
                status=JobStatus.FAILED.value,
                created_by="admin",
                progress_percent=80,
                result=json.dumps(
                    {
                        "management_handoff": True,
                        "management_handoff_runtime_commit_pending": True,
                        "management_handoff_application_committed": True,
                    }
                ),
            )
        )
        db.commit()

        active = ui.active_appliance_apply_job(db)
        assert active is not None and active.id == "handoff-committed"
        db.add(
            Job(
                id="handoff-no-marker",
                type="appliance-apply",
                status=JobStatus.PENDING.value,
                created_by="admin",
                progress_percent=20,
                result=json.dumps(
                    {
                        "management_handoff": True,
                        "management_handoff_runtime_commit_pending": True,
                    }
                ),
            )
        )
        db.commit()
        db.add(
            Job(
                id="handoff-unproven",
                type="appliance-apply",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=10,
                result=json.dumps({"management_handoff": True}),
            )
        )
        db.commit()
        assert ui.recover_interrupted_appliance_apply_jobs(db) == 3

        committed = db.get(Job, "handoff-committed")
        missing = db.get(Job, "handoff-no-marker")
        unproven = db.get(Job, "handoff-unproven")
        assert committed is not None and missing is not None and unproven is not None
        committed_payload = json.loads(committed.result or "{}")
        missing_payload = json.loads(missing.result or "{}")
        unproven_payload = json.loads(unproven.result or "{}")
        assert committed_payload["management_handoff_runtime_committed"] is True
        assert committed_payload["management_handoff_runtime_commit_pending"] is False
        assert "management_handoff_application_committed" not in committed_payload
        assert "candidate management path remains active" in (committed.error or "")
        assert "before the privileged management handoff transaction began" in (missing.error or "")
        assert "rolled back" not in (missing.error or "").lower()
        assert "management_handoff_runtime_commit_pending" not in missing_payload
        assert "management_handoff_application_committed" not in missing_payload
        assert unproven_payload["management_handoff_runtime_commit_pending"] is True
        assert "management_handoff_application_committed" not in unproven_payload
        retained_lock = ui.active_appliance_apply_job(db)
        assert retained_lock is not None
        assert retained_lock.id == "handoff-unproven"
        assert recovery_calls == ["acknowledge:handoff-committed", "recover", "recover"]


def test_management_handoff_exception_reconciliation_selects_transaction_boundary():
    """Roll back before the application commit and acknowledge after it."""
    from atlaso.app.adapters.system import AdapterResult
    from atlaso.app.ui import reconcile_management_handoff_exception

    class RecoveryAdapter:
        """Record which retained helper reconciliation path was selected."""

        def __init__(self):
            """Initialize the recorded helper calls."""
            self.calls: list[str] = []

        def recover_management_handoff(self):
            """Return bounded rollback evidence."""
            self.calls.append("recover")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "recover"],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "rolled back", "rolled_back": True}),
                returncode=0,
            )

        def acknowledge_management_handoff(self, job_id):
            """Return bounded committed-candidate evidence.

            Args:
                job_id: Appliance Apply task being acknowledged.
            """
            self.calls.append(f"acknowledge:{job_id}")
            return AdapterResult(
                command=["atlaso-helper", "management-handoff", "acknowledge", job_id],
                dry_run=False,
                stdout=json.dumps({"management_handoff": "committed", "job_id": job_id}),
                returncode=0,
            )

    adapter = RecoveryAdapter()
    rollback, rollback_evidence = reconcile_management_handoff_exception(
        adapter,
        "job-before-commit",
        application_committed=False,
    )
    acknowledgement, acknowledgement_evidence = reconcile_management_handoff_exception(
        adapter,
        "job-after-commit",
        application_committed=True,
    )

    assert rollback.returncode == 0
    assert rollback_evidence["rolled_back"] is True
    assert acknowledgement.returncode == 0
    assert acknowledgement_evidence["management_handoff"] == "committed"
    assert adapter.calls == ["recover", "acknowledge:job-after-commit"]


def test_appliance_apply_json_submission_returns_master_with_live_child_status(client):
    """Verify JSON submission returns the master and live child status.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "wan"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["job_id"].startswith("job_")
    assert payload["status_url"] == f"/tasks/{payload['job_id']}/status"
    assert payload["task"]["type"] == "appliance-apply"
    assert [(step["component_key"], step["status"]) for step in payload["task"]["_children"]] == [
        ("wan", "pending")
    ]

    status_response = client.get(payload["status_url"])
    assert status_response.status_code == 200
    task = status_response.json()["task"]
    assert task["status"] == "succeeded"
    assert [(step["component_key"], step["status"]) for step in task["_children"]] == [
        ("wan", "succeeded")
    ]


def test_appliance_apply_rejects_submission_while_another_task_is_active(client):
    """Verify submission rejects another active Appliance Apply task.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_active_apply",
                type="appliance-apply",
                status=JobStatus.RUNNING.value,
                created_by="admin",
                progress_percent=25,
                result="{}",
            )
        )
        db.commit()

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "firewall"},
    )

    assert response.status_code == 423
    assert response.json()["job_id"] == "job_active_apply"
    assert "Changes are locked" in response.json()["detail"]
    with SessionLocal() as db:
        jobs = db.scalars(select(Job).where(Job.type == "appliance-apply")).all()
        assert [job.id for job in jobs] == ["job_active_apply"]
