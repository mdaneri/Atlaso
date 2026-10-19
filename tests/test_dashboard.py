"""Test dashboard behavior."""

import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select


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


def controlled_units(*, invalid_changed: bool = False, valid_changed: bool = False):
    """Return controlled units.

    Args:
        invalid_changed: Whether invalid changed applies to the operation.
        valid_changed: Whether valid changed applies to the operation.
    """
    return [
        {
            "id": "appliance_settings",
            "label": "Appliance Settings",
            "page_url": "/settings",
            "changed": invalid_changed,
            "valid": not invalid_changed,
            "validation_errors": ["Appliance FQDN is required."] if invalid_changed else [],
        },
        {
            "id": "network",
            "label": "Network",
            "page_url": "/physical-interfaces",
            "changed": valid_changed,
            "valid": True,
            "validation_errors": [],
        },
    ]


def test_dashboard_setup_exit_healthy_and_needs_attention_states(client, monkeypatch):
    """Verify that dashboard setup exit healthy and needs attention states.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow

    monkeypatch.setattr(ui, "dashboard_appliance_apply_units", lambda _db: controlled_units())
    with SessionLocal() as db:
        setup = ui.dashboard_snapshot(db)
        assert setup["overall"]["state"] == "setup-incomplete"
        assert setup["readiness"]["active"] is True
        assert setup["readiness"]["items"][-1]["complete"] is False
        assert setup["overall"]["primary_action"] == {"label": "Continue setup", "url": "/appliance-apply"}

        db.add(
            Job(
                id="job_dashboard_apply",
                type="appliance-apply",
                status=JobStatus.SUCCEEDED.value,
                created_by="admin",
                created_at=utcnow(),
                finished_at=utcnow(),
            )
        )
        db.commit()

        healthy = ui.dashboard_snapshot(db)
        assert healthy["overall"]["state"] == "healthy"
        assert healthy["readiness"]["active"] is False
        assert healthy["overall"]["primary_action"] == {"label": "Open monitor", "url": "/monitor"}

        db.add(
            Job(
                id="job_dashboard_failed",
                type="appliance-update",
                status=JobStatus.FAILED.value,
                created_by="admin",
                created_at=utcnow(),
                finished_at=utcnow(),
                result='{"token":"do-not-render","commands":["root-only"]}',
                error="secret raw failure",
            )
        )
        db.commit()

        attention = ui.dashboard_snapshot(db)
        assert attention["overall"]["state"] == "needs-attention"
        assert attention["overall"]["primary_action"]["url"] == "/tasks?job_id=job_dashboard_failed"


def test_dashboard_successful_appliance_apply_resolves_retried_units(client, monkeypatch):
    """Verify that dashboard successful appliance apply resolves retried units.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow

    monkeypatch.setattr(ui, "dashboard_appliance_apply_units", lambda _db: controlled_units())
    failed_at = utcnow() - timedelta(minutes=2)
    succeeded_at = utcnow()
    with SessionLocal() as db:
        db.add_all(
            [
                Job(
                    id="job_dashboard_apply_failed",
                    type="appliance-apply",
                    status=JobStatus.FAILED.value,
                    created_by="admin",
                    created_at=failed_at,
                    finished_at=failed_at,
                    result=json.dumps(
                        {
                            "selected_units": ["network", "firewall"],
                            "units": [
                                {"unit_id": "network", "success": True},
                                {"unit_id": "firewall", "success": False},
                            ],
                        }
                    ),
                ),
                Job(
                    id="job_dashboard_apply_recovered",
                    type="appliance-apply",
                    status=JobStatus.SUCCEEDED.value,
                    created_by="admin",
                    created_at=succeeded_at,
                    finished_at=succeeded_at,
                    result=json.dumps(
                        {
                            "selected_units": ["firewall"],
                            "units": [{"unit_id": "firewall", "success": True}],
                        }
                    ),
                ),
            ]
        )
        db.commit()

        snapshot = ui.dashboard_snapshot(db)

    assert snapshot["overall"]["state"] == "healthy"
    assert snapshot["attention_items"] == []
    assert snapshot["tasks"]["failed_24h"] == 0
    activity_urls = [item["url"] for item in snapshot["recent_activity"]]
    assert "/tasks?job_id=job_dashboard_apply_failed" in activity_urls
    assert "/tasks?job_id=job_dashboard_apply_recovered" in activity_urls


def test_dashboard_unrelated_success_does_not_resolve_apply_failure(client, monkeypatch):
    """Verify that dashboard unrelated success does not resolve apply failure.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow

    monkeypatch.setattr(ui, "dashboard_appliance_apply_units", lambda _db: controlled_units())
    failed_at = utcnow() - timedelta(minutes=2)
    succeeded_at = utcnow()
    with SessionLocal() as db:
        db.add_all(
            [
                Job(
                    id="job_dashboard_network_failed",
                    type="appliance-apply",
                    status=JobStatus.FAILED.value,
                    created_by="admin",
                    created_at=failed_at,
                    finished_at=failed_at,
                    result=json.dumps(
                        {
                            "selected_units": ["network"],
                            "units": [{"unit_id": "network", "success": False}],
                        }
                    ),
                ),
                Job(
                    id="job_dashboard_firewall_succeeded",
                    type="appliance-apply",
                    status=JobStatus.SUCCEEDED.value,
                    created_by="admin",
                    created_at=succeeded_at,
                    finished_at=succeeded_at,
                    result=json.dumps(
                        {
                            "selected_units": ["firewall"],
                            "units": [{"unit_id": "firewall", "success": True}],
                        }
                    ),
                ),
            ]
        )
        db.commit()

        snapshot = ui.dashboard_snapshot(db)

    assert snapshot["overall"]["state"] == "needs-attention"
    assert [item["url"] for item in snapshot["attention_items"]] == [
        "/tasks?job_id=job_dashboard_network_failed"
    ]
    assert snapshot["tasks"]["failed_24h"] == 1


def test_dashboard_attention_priority_pending_separation_and_false_positive_filters(client, monkeypatch):
    """Verify that dashboard attention priority pending separation and false positive filters.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        Job,
        JobStatus,
        PhysicalInterface,
        ServiceState,
        utcnow,
    )

    monkeypatch.setattr(
        ui,
        "dashboard_appliance_apply_units",
        lambda _db: controlled_units(invalid_changed=True, valid_changed=True),
    )
    with SessionLocal() as db:
        db.add(
            Job(
                id="job_priority_failed",
                type="appliance-update",
                status=JobStatus.FAILED.value,
                created_by="operator",
                created_at=utcnow(),
                finished_at=utcnow(),
                result='{"password":"never render","command":"rm -rf /"}',
                error="access_token=also-never-render",
            )
        )
        dns = db.execute(select(ServiceState).where(ServiceState.service == "dns")).scalar_one()
        dns.enabled = True
        dns.running = False
        dns.health = "unhealthy"
        disabled = db.execute(select(ServiceState).where(ServiceState.service == "dhcp")).scalar_one()
        disabled.enabled = False
        disabled.running = False
        disabled.health = "unhealthy"
        db.add(
            PhysicalInterface(
                name="eth9",
                mac_address="02:00:00:00:00:09",
                role="access",
                mode="access",
                admin_state="up",
                oper_state="missing",
                inventory_source="host",
            )
        )
        db.add(
            PhysicalInterface(
                name="eth10",
                mac_address="02:00:00:00:00:10",
                role="unused",
                mode="unused",
                admin_state="down",
                oper_state="down",
                inventory_source="host",
            )
        )
        db.commit()

        snapshot = ui.dashboard_snapshot(db)

    assert [item["kind"] for item in snapshot["attention_items"]] == [
        "invalid-change",
        "failed-task",
        "service",
        "interface",
    ]
    assert snapshot["pending_changes"]["count"] == 1
    assert snapshot["pending_changes"]["invalid_count"] == 1
    assert [unit["id"] for unit in snapshot["pending_changes"]["units"]] == ["network"]
    assert snapshot["services"]["exceptions"] == [{"name": "DNS", "state": "stopped", "url": "/services"}]
    assert [item["name"] for item in snapshot["network"]["exceptions"]] == ["eth9"]
    serialized = json.dumps(snapshot)
    for forbidden in ["never render", "rm -rf", "access_token", "raw failure", "commands", "password"]:
        assert forbidden not in serialized


def test_dashboard_failed_task_window_and_activity_merge_are_safe(client, monkeypatch):
    """Verify that dashboard failed task window and activity merge are safe.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, Job, JobStatus, utcnow

    monkeypatch.setattr(ui, "dashboard_appliance_apply_units", lambda _db: controlled_units())
    now = utcnow()
    with SessionLocal() as db:
        db.add_all(
            [
                Job(
                    id="job_recent_failure",
                    type="appliance-update",
                    status=JobStatus.FAILED.value,
                    created_by="admin",
                    created_at=now - timedelta(hours=2),
                    result='{"private_key":"hidden"}',
                    error="hidden raw error",
                ),
                Job(
                    id="job_old_failure",
                    type="appliance-update",
                    status=JobStatus.FAILED.value,
                    created_by="admin",
                    created_at=now - timedelta(hours=25),
                ),
                Job(
                    id="job_partial_failure",
                    type="vcf-sddc-manager-deploy",
                    status="partial-failure",
                    created_by="admin",
                    created_at=now - timedelta(hours=1),
                ),
                Job(
                    id="job_running",
                    type="vcf-depot-download",
                    status=JobStatus.RUNNING.value,
                    created_by="service-admin",
                    created_at=now - timedelta(minutes=3),
                ),
                AuditEvent(
                    actor="auditor",
                    action="review_configuration",
                    resource_type="settings",
                    success=True,
                    detail="token=hidden",
                    created_at=now - timedelta(minutes=1),
                ),
            ]
        )
        db.commit()
        snapshot = ui.dashboard_snapshot(db)

    failed_ids = [item["url"] for item in snapshot["attention_items"] if item["kind"] == "failed-task"]
    assert failed_ids == ["/tasks?job_id=job_partial_failure", "/tasks?job_id=job_recent_failure"]
    timestamps = [item["timestamp"] for item in snapshot["recent_activity"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert snapshot["recent_activity"][0]["source"] == "Audit"
    assert snapshot["recent_activity"][0]["actor"] == "auditor"
    assert snapshot["recent_activity"][0]["url"] == "/audit-log"
    assert snapshot["tasks"]["running"] == 1
    assert snapshot["tasks"]["failed_24h"] == 2
    serialized = json.dumps(snapshot)
    assert "private_key" not in serialized
    assert "hidden raw error" not in serialized
    assert "token=hidden" not in serialized


def test_apply_projection_omits_detail_probes_and_preserves_validation(client, monkeypatch):
    """Keep expensive display-only probes out of current apply validation.

    Args:
        client: Initialized application and database fixture.
        monkeypatch: Dependency replacement fixture.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    probes = ("esx_storage_inventory", "read_dhcp_leases", "kms_status")
    calls = []
    for name in probes:
        original = getattr(ui.SystemAdapter, name)

        def observed(adapter, *args, _name=name, _original=original, **kwargs):
            """Record a live detail probe without changing its result.

            Args:
                adapter: Adapter instance receiving the probe.
                *args: Original positional probe arguments.
                _name: Probe name captured for this wrapper.
                _original: Original adapter implementation.
                **kwargs: Original keyword probe arguments.
            """
            calls.append(_name)
            return _original(adapter, *args, **kwargs)

        monkeypatch.setattr(ui.SystemAdapter, name, observed)

    with SessionLocal() as db:
        compact = ui.appliance_apply_units(db, reconcile=False)
        assert calls == []

        # Force the former detail-rich behavior to compare every apply contract field.
        for name, flag in (
            ("esx_storage_context", "include_disk_inventory"),
            ("dnsmasq_context", "include_leases"),
            ("kms_context", "include_runtime_counts"),
        ):
            original_context = getattr(ui, name)

            def detailed(*args, _original=original_context, _flag=flag, **kwargs):
                """Restore detail retrieval for contract comparison.

                Args:
                    *args: Original positional context arguments.
                    _original: Context implementation captured for this wrapper.
                    _flag: Keyword controlling live detail retrieval.
                    **kwargs: Original keyword context arguments.
                """
                kwargs[_flag] = True
                return _original(*args, **kwargs)

            monkeypatch.setattr(ui, name, detailed)
        full = ui.appliance_apply_units(db, reconcile=False)
        assert set(calls) == set(probes)
        assert [{key: value for key, value in unit.items() if key != "context"} for unit in compact] == [
            {key: value for key, value in unit.items() if key != "context"} for unit in full
        ]


def test_detail_contexts_keep_live_probes_by_default(client, monkeypatch):
    """Retain live detail retrieval for existing page callers.

    Args:
        client: Initialized application and database fixture.
        monkeypatch: Dependency replacement fixture.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    calls = []
    for name in ("esx_storage_inventory", "read_dhcp_leases", "kms_status"):
        original = getattr(ui.SystemAdapter, name)

        def observed(adapter, *args, _name=name, _original=original, **kwargs):
            """Record a live detail probe without changing its result.

            Args:
                adapter: Adapter instance receiving the probe.
                *args: Original positional probe arguments.
                _name: Probe name captured for this wrapper.
                _original: Original adapter implementation.
                **kwargs: Original keyword probe arguments.
            """
            calls.append(_name)
            return _original(adapter, *args, **kwargs)

        monkeypatch.setattr(ui.SystemAdapter, name, observed)
    with SessionLocal() as db:
        ui.esx_storage_context(db, reconcile=False)
        ui.dnsmasq_context(db, reconcile=False)
        ui.kms_context(db, reconcile=False)
    assert calls == ["esx_storage_inventory", "read_dhcp_leases", "kms_status"]


def test_dashboard_apply_summary_disables_reconciliation(monkeypatch):
    """Verify that dashboard apply summary disables reconciliation.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui

    calls = []

    def fake_units(_db, *, reconcile=True):
        """Return fake units.

        Args:
            _db: Active database session used by the operation.
            reconcile: Reconcile supplied to the test scenario.
        """
        calls.append(reconcile)
        return controlled_units()

    monkeypatch.setattr(ui, "appliance_apply_units", fake_units)
    assert ui.dashboard_appliance_apply_units(object()) == controlled_units()
    assert calls == [False]


def test_dashboard_snapshot_does_not_call_desired_state_reconcilers(client, monkeypatch):
    """Verify that dashboard snapshot does not call desired state reconcilers.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    def unexpected_reconciliation(*_args, **_kwargs):
        """Handle unexpected reconciliation.

        Args:
            *_args: Additional positional arguments accepted by the callable.
            **_kwargs: Additional keyword arguments accepted by the callable.


        Raises:
            AssertionError: If an expected invariant is not satisfied.
        """
        raise AssertionError("dashboard refresh entered a desired-state reconciliation path")

    for helper_name in (
        "normalize_service_bind_settings",
        "ensure_dns_for_appliance_settings",
        "ensure_dns_for_kms",
        "ensure_ca_state",
        "disable_default_vcf_backup_user_when_service_off",
        "disable_default_vcf_depot_user_when_service_off",
    ):
        monkeypatch.setattr(ui, helper_name, unexpected_reconciliation)

    with SessionLocal() as db:
        snapshot = ui.dashboard_snapshot(db)

    assert snapshot["generated_at"]
    assert set(snapshot["pending_changes"]) == {"count", "invalid_count", "units", "url"}


def test_dashboard_html_removes_old_inventory_and_javascript_refresh_is_resilient(client):
    """Verify that dashboard html removes old inventory and javascript refresh is resilient.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from pathlib import Path

    login(client)
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "dashboard-status-band" in page.text
    assert "Changes &amp; Tasks" in page.text
    assert "Recent activity" in page.text
    assert "Management 127.0.0.1" not in page.text
    assert "/mnt/atlaso-vcf-offline-depot" not in page.text
    assert "/mnt/atlaso-vcf-backups" not in page.text
    assert "<h2>Routes &amp; WAN Simulation</h2>" not in page.text
    assert 'data-refresh-url="/ui/management/dashboard/data"' in page.text
    assert 'href="/ui/management/dashboard#appliance-apply-review" data-appliance-apply-open>Continue setup</a>' in page.text

    javascript = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    assert "function initializeDashboard()" in javascript
    assert 'document.addEventListener("visibilitychange"' in javascript
    assert 'document.visibilityState === "hidden"' in javascript
    assert "window.setTimeout(refresh, 30000)" in javascript
    assert "markStale();" in javascript
    assert "root.innerHTML = dashboardSnapshotMarkup(snapshot);" in javascript
    assert 'const actionOpensApplianceApply = action.url === "/appliance-apply";' in javascript
    assert "focusTarget.focus({ preventScroll: true })" in javascript

    css = Path("atlaso/app/static/app.css").read_text(encoding="utf-8")
    assert ".dashboard-status-band.needs-attention" in css
    assert ".dashboard-status-band.setup-incomplete" in css
    assert ".dashboard-readiness-row:focus-visible" in css
    assert "@media (max-width: 1100px)" in css
    narrow = css.split("@media (max-width: 640px)", 1)[1]
    assert ".dashboard-primary-grid" in narrow
    assert "grid-template-columns: 1fr;" in narrow


def management_nic(**changes):
    """Build an explicitly observed management listener without a database fixture.

    Args:
        **changes: Desired or observed fields varied by the scenario.
    """
    from atlaso.app.models import PhysicalInterface

    fields = dict(name="eth0", role="access", mode="access", admin_state="up", oper_state="up",
                  access_management_ui_enabled=True, ipv4_method="static", ip_cidr="192.0.2.20/24",
                  host_ip_cidr="192.0.2.20/24", ipv6_enabled=False, ipv6_cidr=None,
                  host_ipv6_cidr=None, host_ipv6_cidrs=[], mac_address="02:00:00:00:00:01")
    return PhysicalInterface(**(fields | changes))


@pytest.mark.parametrize(("changes", "name", "address", "link", "healthy", "discovered"), [
    ({}, "eth0", "192.0.2.20/24", "up", True, True),
    ({"ipv4_method": "dhcp", "ip_cidr": "192.0.2.99/24", "host_ip_cidr": "192.0.2.21/24"},
     "eth0", "192.0.2.21/24", "up", True, True),
    ({"ipv4_method": "dhcp", "host_ip_cidr": None}, "eth0", "", "up", False, True),
    ({"oper_state": "down"}, "eth0", "192.0.2.20/24", "down", False, True),
    ({"oper_state": "unknown"}, "eth0", "192.0.2.20/24", "unknown", False, True),
    ({"role": "management", "oper_state": "missing"}, "eth0", "192.0.2.20/24", "missing", False, False),
    ({"role": "management", "admin_state": "down"}, "eth0", "192.0.2.20/24", "up", False, True),
    ({"oper_state": "missing"}, "Not discovered", "", "missing", False, False),
    ({"admin_state": "down"}, "Not discovered", "", "missing", False, False),
    ({"access_management_ui_enabled": False}, "Not discovered", "", "missing", False, False),
    ({"mode": "trunk"}, "Not discovered", "", "missing", False, False),
    ({"role": "unused", "mode": "unused"}, "Not discovered", "", "missing", False, False),
    ({"ip_cidr": None}, "eth0", "", "up", False, True),
    ({"ip_cidr": "169.254.1.2/16"}, "eth0", "", "up", False, True),
    ({"ip_cidr": "invalid"}, "eth0", "", "up", False, True),
    ({"ip_cidr": None, "ipv6_enabled": True, "ipv6_cidr": "2001:db8::20/64"},
     "eth0", "2001:db8::20/64", "up", True, True),
    ({"ip_cidr": None, "ipv6_enabled": True, "host_ipv6_cidrs": ["fe80::1/64", "2001:db8::21/64"]},
     "eth0", "2001:db8::21/64", "up", True, True),
    ({"ip_cidr": None, "ipv6_enabled": True, "ipv6_cidr": "fe80::1/64"},
     "eth0", "", "up", False, True),
    ({"ip_cidr": None, "ipv6_enabled": False, "ipv6_cidr": "2001:db8::20/64"},
     "eth0", "", "up", False, True),
])
def test_dashboard_effective_physical_management(changes, name, address, link, healthy, discovered):
    """Check listener eligibility independently of address and observed link health.

    Args:
        changes: Physical state under test.
        name: Expected selected identity.
        address: Expected usable address.
        link: Expected observed link state.
        healthy: Expected readiness health.
        discovered: Expected discovery status.
    """
    from atlaso.app import ui

    summary, observed = ui._dashboard_management_summary([management_nic(**changes)], [])
    assert summary == dict(name=name, address=address, link=link, healthy=healthy)
    assert observed is discovered


@pytest.mark.parametrize("pending_dhcp", [False, True])
def test_dashboard_dedicated_management_precedence(pending_dhcp):
    """Keep dedicated identity ahead of flagged Access, including DHCP without a lease.

    Args:
        pending_dhcp: Whether the dedicated listener has yet to receive its lease.
    """
    from atlaso.app import ui

    dedicated = management_nic(name="eth1", role="management", ipv4_method="dhcp" if pending_dhcp else "static",
                               host_ip_cidr=None if pending_dhcp else "192.0.2.20/24")
    summary, discovered = ui._dashboard_management_summary([management_nic(), dedicated], [])
    assert summary["name"] == "eth1"
    assert summary["healthy"] is not pending_dhcp
    assert summary["address"] == ("" if pending_dhcp else "192.0.2.20/24")
    assert discovered is True


@pytest.mark.parametrize("fault", [None, "unavailable", "timeout", "missing", "missing-parent", "tag", "parent-mac", "parent-index", "parent-down", "vlan-down", "address", "parent-mode", "parent-disabled", "disabled", "unflagged"])
@pytest.mark.parametrize("ipv6", [False, True])
def test_dashboard_vlan_requires_exact_native_listener(monkeypatch, fault, ipv6):
    """Exercise the real bounded VLAN verifier rather than trusting configured CIDRs.

    Args:
        monkeypatch: Dependency replacement fixture.
        fault: Missing or mismatched native/desired evidence to inject.
        ipv6: Whether the selected VLAN has IPv6-only addressing.
    """
    from atlaso.app import ui
    from atlaso.app.models import VlanInterface
    from atlaso.app.services import networking

    parent = management_nic(mode="trunk", role="unused", access_management_ui_enabled=False)
    vlan = VlanInterface(name="eth0.20", parent_interface="eth0", vlan_id=20, enabled=True,
                         role="access", access_management_ui_enabled=True, ip_cidr="192.0.2.30/24", ipv6_cidr=None)
    rows = [
        dict(ifname="eth0", ifindex=2, link_type="ether", address=parent.mac_address, flags=["UP"], operstate="UP"),
        dict(ifname="eth0.20", ifindex=3, link_index=2, flags=["UP"], operstate="UP",
             linkinfo={"info_kind": "vlan", "info_data": {"id": 20}},
             addr_info=[{"family": "inet", "local": "192.0.2.30", "prefixlen": 24, "scope": "global"}]),
    ]
    if ipv6:
        vlan.ip_cidr = None
        vlan.ipv6_cidr = "2001:db8::30/64"
        rows[1]["addr_info"] = [{"family": "inet6", "local": "2001:db8::30", "prefixlen": 64, "scope": "global"}]
    if fault == "missing":
        rows.pop()
    elif fault == "tag":
        rows[1]["linkinfo"]["info_data"]["id"] = 21
    elif fault == "parent-mac":
        rows[0]["address"] = "02:00:00:00:00:ff"
    elif fault == "parent-index":
        rows[1]["link_index"] = 99
    elif fault == "parent-down":
        rows[0]["operstate"] = "DOWN"
    elif fault == "vlan-down":
        rows[1]["flags"] = []
    elif fault == "address":
        rows[1]["addr_info"][0]["local"] = "2001:db8::31" if ipv6 else "192.0.2.31"
    elif fault == "parent-mode":
        parent.mode = "access"
    elif fault == "parent-disabled":
        parent.admin_state = "down"
    elif fault == "disabled":
        vlan.enabled = False
    elif fault == "unflagged":
        vlan.access_management_ui_enabled = False
    calls = []

    def native_read(args, **kwargs):
        """Return bounded native output or a capability failure.

        Args:
            args: Native command arguments.
            **kwargs: Native subprocess options.
        """
        calls.append((args, kwargs))
        if fault == "unavailable":
            raise FileNotFoundError("native ip unavailable")
        if fault == "timeout":
            raise networking.subprocess.TimeoutExpired(args, 2.0)
        return SimpleNamespace(returncode=0, stdout=json.dumps(rows))

    monkeypatch.setattr(networking.subprocess, "run", native_read)
    summary, discovered = ui._dashboard_management_summary([] if fault == "missing-parent" else [parent], [vlan])
    assert summary["healthy"] is (fault is None)
    assert discovered is (fault is None)
    if fault in {"disabled", "unflagged"}:
        assert summary["name"] == "Not discovered"
    else:
        assert summary["name"] == "eth0.20"
        assert summary["link"] == ("up" if fault is None else "unknown")
    if calls:
        assert calls[0][0] == ["ip", "-d", "-j", "address", "show"]
        assert calls[0][1]["timeout"] == 2.0


def test_dashboard_access_snapshot_html_and_data_preserve_other_failures(client, monkeypatch):
    """Expose the corrected Access listener consistently without clearing independent validation.

    Args:
        client: HTTP test client.
        monkeypatch: Dependency replacement fixture.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, PhysicalInterface

    monkeypatch.setattr(ui, "dashboard_appliance_apply_units", lambda _db: controlled_units(invalid_changed=True))
    with SessionLocal() as db:
        physical = db.execute(select(PhysicalInterface).where(PhysicalInterface.role == "management")).scalar_one()
        physical.role = "access"
        physical.mode = "access"
        physical.access_management_ui_enabled = True
        physical.ipv4_method = "static"
        physical.ip_cidr = "192.0.2.20/24"
        physical.oper_state = "up"
        db.add(Job(id="job_access_dashboard", type="appliance-apply", status="succeeded", created_by="admin"))
        db.commit()
        snapshot = ui.dashboard_snapshot(db)
    assert snapshot["network"]["management"] == dict(name=physical.name, address="192.0.2.20/24", link="up", healthy=True)
    readiness = {item["id"]: item["complete"] for item in snapshot["readiness"]["items"]}
    assert readiness["management-discovery"] and readiness["management-network"]
    assert not readiness["appliance-settings"] and not readiness["desired-state"]
    assert snapshot["overall"]["state"] == "needs-attention"
    login(client)
    data = client.get("/ui/management/dashboard/data")
    assert data.status_code == 200
    assert data.json()["network"]["management"] == snapshot["network"]["management"]
    html = client.get("/ui/management/dashboard")
    assert html.status_code == 200
    assert "192.0.2.20/24" in html.text and "Appliance Settings changes are invalid" in html.text
