"""Test Traffic Publishing reverse-proxy UI structure and permissions."""

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import Role, User
from atlaso.app.security import roles_to_json
from tests.routers.ui.helpers import login


def test_service_ui_enable_rejects_existing_proxy_socket(client):
    """Reject the reverse-order KMIP collision without persisting service edits.

    Args:
        client: Isolated management client.
    """
    from atlaso.app.models import KmsSettings
    from atlaso.app.services.reverse_proxies import save_proxy
    from tests.routers.api_v1.test_reverse_proxies import (
        _enable_test_listener,
        _payload,
    )

    _enable_test_listener()
    with SessionLocal() as db:
        settings = db.scalar(select(KmsSettings))
        settings.enabled = False
        db.commit()
        before = (settings.enabled, settings.port, settings.hostname)
        save_proxy(db, _payload(enabled=True, scheme="http", port=5696, redirect_http=False), actor="test")
    login(client)
    page = client.get("/ui/management/vsphere-key-providers")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    response = client.post("/ui/management/vsphere-key-providers/settings", data={
        "enabled": "on", "listen_interfaces": "eth1", "listen_addresses": "192.0.2.10",
        "listen_interfaces_present": "1", "listen_addresses_present": "1",
        "hostname": "kms.example.test", "port": "5696", "csrf": csrf,
    })
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        settings = db.scalar(select(KmsSettings))
        assert (settings.enabled, settings.port, settings.hostname) == before


@pytest.mark.parametrize("change", ["hostname", "disable"])
def test_ca_settings_preserve_proxy_dependencies_before_dns_and_commit(client, change):
    """Reject reverse-order CA edits atomically at the actual management writer.

    Args:
        client: Isolated authenticated management client.
        change: Portal-name takeover or disable of the required CA.
    """
    from atlaso.app.models import CaSettings, DnsRecord
    from atlaso.app.services.reverse_proxies import runtime_snapshot, save_proxy
    from tests.routers.api_v1.test_reverse_proxies import (
        _enable_test_listener,
        _payload,
    )

    login(client)
    page = client.get("/ui/management/traffic-publishing")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    _enable_test_listener()
    with SessionLocal() as db:
        proxy = save_proxy(db, _payload(enabled=True), actor="test")
        ca = db.scalar(select(CaSettings))
        before = (ca.enabled, ca.portal_hostname, ca.organization)
        proxy_before = runtime_snapshot(db)
        dns_before = [(r.id, r.hostname, r.address, r.description) for r in db.scalars(select(DnsRecord))]
        form = {"csrf": csrf, "root_common_name": ca.root_common_name,
                "organization": "Attempted change", "portal_hostname": ca.portal_hostname}
        if change == "hostname":
            form.update(enabled="on", portal_hostname=proxy.hostname)
    response = client.post("/ui/management/certificate-authority/settings", data=form, follow_redirects=False)
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        ca = db.scalar(select(CaSettings))
        assert (ca.enabled, ca.portal_hostname, ca.organization) == before
        assert runtime_snapshot(db) == proxy_before
        assert [(r.id, r.hostname, r.address, r.description) for r in db.scalars(select(DnsRecord))] == dns_before


@pytest.mark.parametrize("populated", [False, True])
def test_reverse_proxy_page_uses_reviewed_grid_wizard_and_health_contract(client, populated):
    """The management page retains its fallback and explicit review flow.

    Args:
        client: Isolated authenticated management client.
        populated: Whether the initial server fallback contains a saved proxy.
    """
    if populated:
        from atlaso.app.services.reverse_proxies import save_proxy
        from tests.routers.api_v1.test_reverse_proxies import (
            _enable_test_listener,
            _payload,
        )

        _enable_test_listener()
        with SessionLocal() as db:
            save_proxy(db, _payload(), actor="test")
    login(client)
    response = client.get("/ui/management/traffic-publishing")

    assert response.status_code == 200
    page = response.text
    assert 'data-tab-target="reverse-proxy-panel"' in page
    assert 'id="reverse-proxy-panel"' in page
    assert 'id="reverse-proxies-table"' in page
    assert f'data-reverse-proxy-count>{1 if populated else 0} proxies</span>' in page
    assert 'id="reverse-proxies-fallback"' in page
    fallback = page.split('id="reverse-proxies-fallback"', 1)[1].split('</table>', 1)[0]
    assert ('data-reverse-proxy-delete=' in fallback) is populated
    if populated:
        assert 'aria-label="Delete reverse proxy ' in fallback
        assert 'class="button tiny danger"' in fallback
    assert 'data-reverse-proxy-add' in page.split('id="reverse-proxies-fallback"', 1)[1].split('</table>', 1)[0]
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


@pytest.mark.parametrize("errors,warnings,label,style", [
    ([], [], "valid", "good"),
    ([], ["Insecure upstream TLS requires review"], "review warnings", "warn"),
    (["Listener unavailable"], ["Insecure upstream TLS requires review"], "needs attention", "warn"),
])
def test_reverse_proxy_initial_validation_status_matches_review_state(client, monkeypatch, errors, warnings, label, style):
    """Render warning-only and error states truthfully before browser refresh.

    Args:
        client: Isolated management client.
        monkeypatch: Scoped publication-context replacement.
        errors: Publication validation errors.
        warnings: Publication validation warnings.
        label: Expected initial review state.
        style: Expected shared status-pill style.
    """
    from atlaso.app.services import reverse_proxy_publication

    original = reverse_proxy_publication.context

    def review_context(db):
        """Return publication context with the requested review state.

        Args:
            db: Active database session used by the publication context.
        """
        value = original(db)
        value.update(reverse_proxy_validation_errors=errors, reverse_proxy_validation_warnings=warnings)
        return value

    monkeypatch.setattr(reverse_proxy_publication, "context", review_context)
    login(client)
    response = client.get("/ui/management/traffic-publishing")
    assert response.status_code == 200
    badge = response.text.split('data-reverse-proxy-validation-status>', 1)
    assert badge[0].endswith(f'class="status-pill {style}" ')
    assert badge[1].split('</span>', 1)[0].strip() == label


@pytest.mark.parametrize("populated", [False, True])
def test_read_only_firewall_user_keeps_fallback_without_mutation_wizard(client, populated):
    """A reader can inspect rendered proxy rows and health without edit controls.

    Args:
        client: Isolated management client.
        populated: Whether the initial server fallback contains a saved proxy.
    """
    if populated:
        from atlaso.app.services.reverse_proxies import save_proxy
        from tests.routers.api_v1.test_reverse_proxies import (
            _enable_test_listener,
            _payload,
        )

        _enable_test_listener()
        with SessionLocal() as db:
            save_proxy(db, _payload(), actor="test")
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
    assert 'data-reverse-proxy-delete=' not in response.text


def test_reverse_proxy_transport_verifies_csrf_before_json_and_uses_strict_integer_ids(client, monkeypatch):
    """Reject invalid CSRF before body parsing, then save a complete desired record.

    Args:
        client: Initialized authenticated appliance test client.
        monkeypatch: Scoped dependency replacements supplied by pytest.
    """
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
    """Firewall readers can inspect proxies but cannot call mutation transports.

    Args:
        client: Initialized authenticated appliance test client.
    """
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
        """Return ordinary units with only the proxy case controlled.

        Args:
            db: Caller-owned database session for proxy desired state.
            **kwargs: Input used by planned units.
        """
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
    """A proxy publication change cannot apply while its pending handoff peers are unchecked.

    Args:
        client: Initialized authenticated appliance test client.
        monkeypatch: Scoped dependency replacements supplied by pytest.
    """
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
    """An unrelated Public Services change retains its existing independent Apply behavior.

    Args:
        client: Initialized authenticated appliance test client.
        monkeypatch: Scoped dependency replacements supplied by pytest.
    """
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
