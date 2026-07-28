import json
from datetime import timedelta

from sqlalchemy import select


def login(client):
    page = client.get("/login")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/login",
        data={"username": "admin", "password": "atlaso-admin", "csrf": csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303


def controlled_units(*, invalid_changed: bool = False, valid_changed: bool = False):
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


def test_dashboard_data_requires_session_and_preserves_public_api_contract(client):
    private = client.get("/dashboard/data", follow_redirects=False)
    assert private.status_code == 303
    assert private.headers["location"] == "/login?next=/dashboard/data"

    login(client)
    private = client.get("/dashboard/data")
    assert private.status_code == 200
    payload = private.json()
    assert set(payload) == {
        "generated_at",
        "overall",
        "readiness",
        "attention_items",
        "pending_changes",
        "tasks",
        "services",
        "network",
        "recent_activity",
    }
    assert set(payload["overall"]) == {"state", "label", "hostname", "fqdn", "dry_run", "primary_action"}

    token_response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "dashboard contract", "scopes": ["read:dashboard"]},
    )
    token = token_response.json()["raw_token"]
    public = client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert public.status_code == 200
    assert set(public.json()) == {
        "appliance",
        "service_health",
        "interfaces",
        "active_wan_policies",
        "disk_usage",
        "recent_audit_events",
    }


def test_dashboard_setup_exit_healthy_and_needs_attention_states(client, monkeypatch):
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, utcnow

    monkeypatch.setattr(ui, "dashboard_appliance_apply_units", lambda _db: controlled_units())
    with SessionLocal() as db:
        setup = ui.dashboard_snapshot(db)
        assert setup["overall"]["state"] == "setup-incomplete"
        assert setup["readiness"]["active"] is True
        assert setup["readiness"]["items"][-1]["complete"] is False

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
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, JobStatus, PhysicalInterface, ServiceState, utcnow

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


def test_dashboard_apply_summary_disables_reconciliation(monkeypatch):
    from atlaso.app import ui

    calls = []

    def fake_units(_db, *, reconcile=True):
        calls.append(reconcile)
        return controlled_units()

    monkeypatch.setattr(ui, "appliance_apply_units", fake_units)
    assert ui.dashboard_appliance_apply_units(object()) == controlled_units()
    assert calls == [False]


def test_dashboard_snapshot_does_not_call_desired_state_reconcilers(client, monkeypatch):
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal

    def unexpected_reconciliation(*_args, **_kwargs):
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
    assert 'data-refresh-url="/dashboard/data"' in page.text

    javascript = Path("atlaso/app/static/app.js").read_text(encoding="utf-8")
    assert "function initializeDashboard()" in javascript
    assert 'document.addEventListener("visibilitychange"' in javascript
    assert 'document.visibilityState === "hidden"' in javascript
    assert "window.setTimeout(refresh, 30000)" in javascript
    assert "markStale();" in javascript
    assert "root.innerHTML = dashboardSnapshotMarkup(snapshot);" in javascript
    assert "focusTarget.focus({ preventScroll: true })" in javascript

    css = Path("atlaso/app/static/app.css").read_text(encoding="utf-8")
    assert ".dashboard-status-band.needs-attention" in css
    assert ".dashboard-status-band.setup-incomplete" in css
    assert ".dashboard-readiness-row:focus-visible" in css
    assert "@media (max-width: 1100px)" in css
    narrow = css.split("@media (max-width: 640px)", 1)[1]
    assert ".dashboard-primary-grid" in narrow
    assert "grid-template-columns: 1fr;" in narrow
