"""Test Traffic Publishing reverse-proxy UI structure and permissions."""

from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import Role, User
from atlaso.app.security import roles_to_json
from tests.routers.ui.helpers import login


def test_reverse_proxy_page_uses_reviewed_grid_wizard_and_health_contract(client):
    """The management page retains its fallback and explicit review flow.

    Args:
        client: Isolated authenticated management client.
    """
    login(client)
    response = client.get("/ui/management/traffic-publishing")

    assert response.status_code == 200
    page = response.text
    assert 'data-tab-target="reverse-proxy-panel"' in page
    assert 'id="reverse-proxy-panel"' in page
    assert 'id="reverse-proxies-table"' in page
    assert 'id="reverse-proxies-fallback"' in page
    assert 'data-reverse-proxy-wizard' in page
    assert 'data-atlaso-wizard-step="identity"' in page
    assert 'data-atlaso-wizard-step="listener"' in page
    assert 'data-atlaso-wizard-step="routes"' in page
    assert 'data-atlaso-wizard-step="publication"' in page
    assert 'data-atlaso-wizard-step="state"' in page
    assert 'data-atlaso-wizard-step="review"' in page
    assert 'data-reverse-proxy-insecure-warning' in page
    assert 'id="reverse-proxy-health-table"' in page
    assert 'id="reverse-proxy-health-fallback"' in page
    assert 'data-reverse-proxy-health-refresh' in page
    assert "data-reverse-proxy-route-add" in page
    assert 'name="public_listing" checked' in page
    assert 'name="managed_dns"' in page
    assert "raw nginx" in page
    assert 'name="nginx_directive"' not in page
    assert 'name="raw_config"' not in page
    assert "/static/reverse-proxies.js" in page


def test_read_only_firewall_user_keeps_fallback_without_mutation_wizard(client):
    """A reader can inspect rendered proxy rows and health without edit controls.

    Args:
        client: Isolated management client.
    """
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()

    login(client)
    response = client.get("/ui/management/traffic-publishing")

    assert response.status_code == 200
    assert 'id="reverse-proxies-table"' in response.text
    assert 'id="reverse-proxies-fallback"' in response.text
    assert 'id="reverse-proxy-health-table"' in response.text
    assert 'data-reverse-proxy-wizard' not in response.text
    assert 'data-reverse-proxy-add' not in response.text
    assert 'data-reverse-proxy-edit=' not in response.text


def test_reverse_proxy_transport_verifies_csrf_before_json_and_uses_strict_integer_ids(client, monkeypatch):
    """Reject invalid CSRF before body parsing, then save a complete desired record."""
    import json
    from datetime import datetime, timezone

    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.services.reverse_proxies import runtime_snapshot

    login(client)
    page = client.get("/ui/management/traffic-publishing")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    data_url = "/ui/management/traffic-publishing/reverse-proxies/data"
    root = "/ui/management/traffic-publishing/reverse-proxies"
    headers = {"X-CSRF-Token": csrf, "Accept": "application/json", "Content-Type": "application/json"}

    assert client.get(data_url).status_code == 200
    invalid_csrf = client.post(f"{root}/save", content="{", headers={**headers, "X-CSRF-Token": "invalid"})
    assert invalid_csrf.status_code == 403

    options = client.get(data_url).json()["listener_options"]
    assert options
    payload = {
        "name": "Inventory",
        "description": "Internal inventory service",
        "hostname": "inventory.example.test",
        "scheme": "http",
        "port": 18080,
        "redirect_http": False,
        "redirect_port": 80,
        "enabled": False,
        "public_listing": True,
        "managed_dns": False,
        "listeners": [options[0]],
        "connect_timeout": 5,
        "read_timeout": 60,
        "send_timeout": 60,
        "body_limit": 16777216,
        "routes": [{
            "path_prefix": "/",
            "upstream_scheme": "http",
            "upstream_host": "10.10.20.30",
            "upstream_port": 8080,
            "path_behavior": "preserve",
            "trust_mode": "trusted_ca",
        }],
    }
    bad_id = client.post(f"{root}/save", json={**payload, "id": "1"}, headers=headers)
    assert bad_id.status_code == 422
    extra_field = client.post(f"{root}/save", json={**payload, "raw_config": "unsafe"}, headers=headers)
    assert extra_field.status_code == 422

    saved_response = client.post(f"{root}/save", json=payload, headers=headers)
    assert saved_response.status_code == 200, saved_response.text
    saved = saved_response.json()["item"]
    assert type(saved["id"]) is int
    assert saved["enabled"] is False
    assert type(saved["routes"][0]["id"]) is int
    assert saved["apply_required"] is True

    with SessionLocal() as db:
        proxies = runtime_snapshot(db)
    status = {
        "schema": 1,
        "proxies": proxies,
        "generation": "b" * 64,
        "health": {},
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    monkeypatch.setattr(
        SystemAdapter,
        "reverse_proxy_status",
        lambda _self: AdapterResult(command=["atlaso-helper"], dry_run=False, stdout=json.dumps(status)),
    )
    health = client.get(f"{root}/health").json()["items"]
    assert len(health) == 1
    assert health[0]["status"] == "disabled"
    assert health[0]["applied"] is True
    assert health[0]["pending"] is False
    assert health[0]["failure_class"] == ""
    assert health[0]["http_status"] is None

    saved["description"] = "Updated internal inventory service"
    for projection_field in ("created_at", "updated_at", "apply_required"):
        saved.pop(projection_field)
    updated_response = client.post(f"{root}/save", json=saved, headers=headers)
    assert updated_response.status_code == 200, updated_response.text
    updated = updated_response.json()["item"]
    assert updated["id"] == saved["id"]
    assert updated["routes"][0]["id"] == saved["routes"][0]["id"]
    assert updated["description"] == "Updated internal inventory service"

    deleted = client.post(f"{root}/{saved['id']}/delete", headers={"X-CSRF-Token": csrf, "Accept": "application/json"})
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["items"] == []


def test_reverse_proxy_transports_require_firewall_scope(client):
    """Firewall readers can inspect proxies but cannot call mutation transports."""
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()

    login(client)
    root = "/ui/management/traffic-publishing/reverse-proxies"
    assert client.get(f"{root}/data").status_code == 200
    assert client.get(f"{root}/health").status_code == 200
    response = client.post(f"{root}/save", content="not json", headers={"X-CSRF-Token": "invalid"})
    assert response.status_code == 403


def _prepare_proxy_apply_intent(ui, *, applied_intent: str, desired_intent: str, changed_ids: set[str]):
    """Make reverse-proxy intent and independently pending dependencies deterministic.

    Args:
        ui: Appliance Apply module whose unit planner is wrapped.
        applied_intent: Intent marker stored in the Public Services baseline.
        desired_intent: Intent marker exposed by the current Public Services preview.
        changed_ids: Unit identifiers whose pending state is under test.

    Returns:
        The original Appliance Apply unit planner.
    """
    from atlaso.app.database import SessionLocal

    original = ui.appliance_apply_units
    with SessionLocal() as db:
        units = original(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        baselines = ui.load_appliance_apply_baselines(db)
        baselines["public_services"]["config_preview"] = (
            "# Reverse-proxy intent: " + applied_intent + "\n"
            "# Reverse-proxy transport manifest: manifest\n"
        )
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()

    def planned_units(db, **kwargs):
        """Return ordinary units with only the proxy case controlled."""
        units = original(db, **kwargs)
        for unit in units:
            if unit["id"] in changed_ids:
                unit["changed"] = True
                unit["snapshot_hash"] = f"pending-{unit['id']}"
                unit["validation_errors"] = []
            if unit["id"] == "public_services":
                unit["config_preview"] = (
                    "# Reverse-proxy intent: " + desired_intent + "\n"
                    "# Reverse-proxy transport manifest: manifest\n"
                )
        return units

    return planned_units


def test_changed_reverse_proxy_intent_requires_pending_publication_dependencies(client, monkeypatch):
    """A proxy publication change cannot apply while its pending handoff peers are unchecked."""
    import json

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    changed_ids = {*ui.MANAGEMENT_HANDOFF_UNIT_IDS, "dnsmasq"}
    monkeypatch.setattr(
        ui,
        "appliance_apply_units",
        _prepare_proxy_apply_intent(
            ui, applied_intent="old", desired_intent="new", changed_ids=changed_ids,
        ),
    )

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "public_services"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "Select the pending reverse-proxy publication dependencies together" in detail
    assert all(label in detail for label in (
        "Certificate Authority", "Network", "Firewall", "Appliance Settings", "DNS/DHCP (dnsmasq)",
    ))

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    accepted = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": sorted(changed_ids)},
        headers={"Accept": "application/json"},
    )
    assert accepted.status_code == 202, accepted.text
    with SessionLocal() as db:
        job = db.get(Job, accepted.json()["job_id"])
        payload = json.loads(job.result or "{}")
        assert payload["management_handoff"] is True
        assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) <= set(payload["selected_units"])
        assert "dnsmasq" in payload["selected_units"]
        assert set(ui.MANAGEMENT_HANDOFF_UNIT_IDS) | {"dnsmasq"} <= set(payload["management_handoff_units"])


def test_unchanged_reverse_proxy_intent_keeps_public_services_apply_independent(client, monkeypatch):
    """An unrelated Public Services change retains its existing independent Apply behavior."""
    import json

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    csrf = client.get("/dashboard").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    changed_ids = {*ui.MANAGEMENT_HANDOFF_UNIT_IDS, "dnsmasq"}
    monkeypatch.setattr(
        ui,
        "appliance_apply_units",
        _prepare_proxy_apply_intent(
            ui, applied_intent="same", desired_intent="same", changed_ids=changed_ids,
        ),
    )
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)

    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": "public_services"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        payload = json.loads(job.result or "{}")
        assert payload["management_handoff"] is False
        assert payload["selected_units"] == ["public_services"]
        assert payload["management_handoff_units"] == []
