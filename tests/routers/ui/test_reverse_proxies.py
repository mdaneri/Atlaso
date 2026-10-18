"""Test Traffic Publishing reverse-proxy UI structure and permissions."""

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import Role, User
from atlaso.app.security import roles_to_json
from tests.routers.ui.helpers import login, submit_reviewed_appliance_apply


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

    response = submit_reviewed_appliance_apply(
        client, "/appliance-apply",
        data={"csrf": csrf, "selected_units": "public_services"},
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert "Select the pending reverse-proxy publication dependencies together" in detail
    assert all(label in detail for label in (
        "Certificate Authority", "Network", "Firewall", "Appliance Settings", "DNS/DHCP (dnsmasq)",
    ))

    review_response = client.get("/ui/management/appliance-apply/review", params={"selected_units": "public_services"})
    assert review_response.status_code == 200
    review = review_response.json()
    assert not review["plan_error"]
    effective = [unit["id"] for unit in review["units"] if unit["selected"]]
    assert changed_ids <= set(effective)
    assert all(unit["required_dependency"] and unit["dependency_reason"]
               for unit in review["units"] if unit["id"] in changed_ids - {"public_services"})
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    accepted = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": effective, "requested_units": ["public_services"],
              "reviewed_plan": review["plan_token"]},
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

    response = submit_reviewed_appliance_apply(
        client, "/appliance-apply",
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


@pytest.mark.parametrize("change", ["create", "edit", "disable", "delete", "failed", "rollback"])
def test_public_directory_preserves_applied_proxy_links_until_apply(client, monkeypatch, change):
    """Public GET follows applied intent through saved edits and failed or reverted Apply.

    Args:
        client: Isolated HTTP client serving the real public directory.
        monkeypatch: Scoped replacement of the bounded runtime observer.
        change: Pending desired-state mutation or failed/reverted publication state.
    """
    import json
    from datetime import datetime, timezone

    from atlaso.app.adapters.system import AdapterResult, SystemAdapter
    from atlaso.app.models import Job, JobStatus
    from atlaso.app.services.reverse_proxies import (
        delete_proxy,
        runtime_snapshot,
        save_proxy,
        set_enabled,
    )
    from tests.routers.api_v1.test_reverse_proxies import (
        _enable_test_listener,
        _payload,
    )

    _enable_test_listener()
    with SessionLocal() as db:
        proxy = save_proxy(db, _payload(enabled=True), actor="test")
        applied = [] if change == "create" else runtime_snapshot(db)
        if change in {"edit", "failed", "rollback"}:
            save_proxy(db, _payload(enabled=True, hostname="changed.example.test"), actor="test", proxy_id=proxy.id)
        elif change == "disable":
            set_enabled(db, proxy.id, enabled=False, actor="test")
        elif change == "delete":
            delete_proxy(db, proxy.id, actor="test")
        if change in {"failed", "rollback"}:
            db.add(Job(id="public-proxy-" + change, type="appliance-apply", created_by="test",
                       status=JobStatus.FAILED.value, result=json.dumps({
                "management_handoff_runtime_commit_pending": change == "failed",
                "management_handoff_recovery": {"evidence": {"rolled_back": change == "rollback"}},
            })))
            db.commit()
        desired = runtime_snapshot(db)

    status = {"schema": 1, "proxies": applied, "generation": "a" * 64 if applied else None,
              "health": {}, "observed_at": datetime.now(timezone.utc).isoformat()}
    from atlaso.app.services.reverse_proxy_observation import (
        invalidate_public_proxy_snapshot,
    )

    invalidate_public_proxy_snapshot()
    monkeypatch.setattr(SystemAdapter, "reverse_proxy_status", lambda _self: AdapterResult(
        command=["atlaso-helper"], dry_run=False, stdout=json.dumps(status),
    ))
    headers = {"host": "192.0.2.10"}
    pending = client.get("/ui/public", headers=headers)
    assert pending.status_code == 200
    assert ('href="https://application.example.test:8443/"' in pending.text) is (change != "create")
    assert "https://changed.example.test:8443/" not in pending.text

    status["proxies"] = desired
    status["generation"] = "b" * 64 if desired else None
    invalidate_public_proxy_snapshot()
    committed = client.get("/ui/public", headers=headers)
    assert committed.status_code == 200
    expected = "changed.example.test" if change in {"edit", "failed", "rollback"} else "application.example.test"
    assert (f'href="https://{expected}:8443/"' in committed.text) is (change not in {"disable", "delete"})
    if change in {"edit", "failed", "rollback"}:
        assert "https://application.example.test:8443/" not in committed.text


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("name,source", [
    ("eth0proxy", "static"), ("eth2proxy", "static"), ("eth2proxy", "observed"), ("vlan3020", "vlan"),
])
def test_public_directory_hides_proxy_cards_for_ambiguous_ingress(client, monkeypatch, family, name, source):
    """Do not advertise a firewall-scoped proxy through an address shared by NICs.

    Args:
        client: Fixture initializing the real application database.
        monkeypatch: Supply an admitted applied proxy snapshot without helper calls.
        family: IPv4 or IPv6 listener address family.
        name: Competing interface before or after the selected NIC in inventory order.
        source: Desired physical, observed physical, or enabled VLAN address.
    """
    from atlaso.app import ui
    from atlaso.app.models import PhysicalInterface, VlanInterface
    from atlaso.app.services import reverse_proxy_observation
    from atlaso.app.services.reverse_proxies import runtime_snapshot, save_proxy
    from tests.routers.api_v1.test_reverse_proxies import (
        _enable_test_listener,
        _payload,
    )

    _enable_test_listener()
    address = "192.0.2.10" if family == 4 else "2001:db8::10"
    cidr = address + ("/24" if family == 4 else "/64")
    with SessionLocal() as db:
        selected = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        selected.check_duplicate_ip_addresses = False
        if family == 6:
            selected.ipv6_enabled = True
            selected.ipv6_cidr = cidr
            selected.host_ipv6_cidrs = [cidr]
        else:
            selected.host_ip_cidr = cidr
        db.commit()
        save_proxy(db, _payload(enabled=True, listeners=[{"interface": "eth1", "address": address}]), actor="test")
        applied = runtime_snapshot(db)
    monkeypatch.setattr(reverse_proxy_observation, "applied_reverse_proxy_snapshot", lambda: applied)

    with SessionLocal() as db:
        binding = ui.request_host_interface_binding(address, db)
        assert binding["interface_ambiguous"] is False
        assert any(row["id"].startswith("reverse_proxy:") for row in
                   ui.public_service_directory_context(db, binding)["public_services"])
        if source == "vlan":
            duplicate = VlanInterface(name=name, parent_interface="eth1", vlan_id=3020, enabled=True,
                                      role="access", check_duplicate_ip_addresses=False,
                                      **{"ip_cidr" if family == 4 else "ipv6_cidr": cidr})
        else:
            duplicate = PhysicalInterface(name=name, mac_address="02:00:00:00:00:22", role="access",
                mode="access", admin_state="up", oper_state="up", ipv6_enabled=family == 6,
                check_duplicate_ip_addresses=False)
            if source == "static":
                setattr(duplicate, "ip_cidr" if family == 4 else "ipv6_cidr", cidr)
            elif family == 4:
                duplicate.host_ip_cidr = "192.0.2.99/24"
                duplicate.host_ip_cidrs = ["192.0.2.99/24", cidr]
            else:
                duplicate.host_ipv6_cidrs = [cidr]
        db.add(duplicate)
        db.commit()
        binding = ui.request_host_interface_binding(address, db)
        assert binding["interface_ambiguous"] is True
        assert not any(row["id"].startswith("reverse_proxy:") for row in
                       ui.public_service_directory_context(db, binding)["public_services"])


@pytest.mark.parametrize("service_id", ["ca", "vcf_offline_depot"])
def test_unrelated_public_service_admission_never_observes_proxy_runtime(client, monkeypatch, service_id):
    """Evaluate a real public binding without invoking the proxy helper path.

    Args:
        client: Fixture initializing the real application database.
        monkeypatch: Fixture making every proxy observation fail if called.
        service_id: Unrelated native public service being admitted.
    """
    from starlette.requests import Request

    from atlaso.app import ui
    from atlaso.app.services import reverse_proxy_observation
    from tests.routers.api_v1.test_reverse_proxies import _enable_test_listener

    _enable_test_listener()
    monkeypatch.setattr(reverse_proxy_observation, "applied_reverse_proxy_snapshot",
                        lambda: pytest.fail("Native service admission must not observe proxy runtime"))
    request = Request({"type": "http", "headers": [(b"host", b"192.0.2.10")]})
    with SessionLocal() as db:
        binding = ui.request_host_interface_binding("192.0.2.10", db)
        assert binding and binding["role"] != "management"
        assert ui.request_allows_public_service(db, request, service_id) is False
        assert ui.request_public_service_route_allowed(db, request, service_id) is False


@pytest.mark.parametrize("writer", ["generate", "deployment"])
@pytest.mark.parametrize("authoritative", [False, True])
@pytest.mark.parametrize("getter_commits", [False, True])
def test_vcf_dns_writers_preserve_unpublished_proxy_names(client, monkeypatch, writer, authoritative, getter_commits):
    """Both VCF writers honor saved proxy intent under retained writer admission.

    Args:
        client: Fixture initializing the isolated appliance database.
        monkeypatch: Observe locking and simulate a settings getter that commits.
        writer: Complete generated collection or deployed-appliance DNS follow-up.
        authoritative: Disabled authority or an authority serving another zone.
        getter_commits: Exercise reacquisition after default initialization commits.
    """
    from sqlalchemy.exc import OperationalError

    from atlaso.app import ui
    from atlaso.app.models import DnsRecord, DnsSettings
    from atlaso.app.services import reverse_proxy_publication
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock
    from atlaso.app.services.reverse_proxies import runtime_snapshot, save_proxy
    from tests.routers.api_v1.test_reverse_proxies import (
        _enable_test_listener,
        _payload,
    )
    from tests.test_ui import vcf_hostname_form_data

    _enable_test_listener()
    hostname = "reserved-proxy.atlaso.internal"
    with SessionLocal() as db:
        settings = db.scalar(select(DnsSettings))
        settings.enabled = True
        settings.authoritative = authoritative
        settings.domain = "other.test" if authoritative else "atlaso.internal"
        settings.disabled_domains = "atlaso.internal" if authoritative else ""
        db.commit()
        save_proxy(db, _payload(enabled=True, managed_dns=True, hostname=hostname), actor="test")
        assert not db.scalars(select(DnsRecord).where(DnsRecord.hostname == hostname)).all()
        before = [(row.id, row.hostname, row.address) for row in db.scalars(select(DnsRecord))]
        proxy_before = runtime_snapshot(db)

    original_guard = reverse_proxy_publication.proxy_owns_dns_hostname
    observations = []

    def guarded(session, name):
        """Require the ownership check to exclude an actual competing SQLite writer.

        Args:
            session: Admitted VCF writer transaction.
            name: DNS hostname whose ownership is being checked.
        """
        with SessionLocal() as competitor:
            competitor.connection().exec_driver_sql("PRAGMA busy_timeout=0")
            with pytest.raises(OperationalError, match="locked"):
                acquire_network_objects_write_lock(competitor)
        observations.append(name)
        return original_guard(session, name)

    getter = ui.get_dns_settings_row

    def settings_row(session):
        """Model legacy default-row commits before ownership admission is reacquired.

        Args:
            session: Session used by the real VCF writer.
        """
        settings = getter(session)
        if getter_commits:
            session.commit()
        return settings

    monkeypatch.setattr(reverse_proxy_publication, "proxy_owns_dns_hostname", guarded)
    monkeypatch.setattr(ui, "get_dns_settings_row", settings_row)
    with SessionLocal() as db:
        if writer == "generate":
            mapping = vcf_hostname_form_data()
            mapping["hostname"][-1] = "reserved-proxy"
            created, _skipped, errors = ui.create_vcf_generated_dns_records(db,
                target="vcf-9.1", domain="atlaso.internal", prefix="", suffix="", start_ipv4="192.0.2.100/24",
                network_prefix="", component_keys=mapping["component_key"], hostnames=mapping["hostname"], actor="test")
            assert created == [] and any("managed by Reverse Proxies" in error for error in errors)
        else:
            result = ui._add_deployed_vcf_dns(db, hostname.upper() + ".", ["192.0.2.100", "2001:db8::100"], job_id="test")
            assert result["status"] == "warning" and result["created"] == []
            assert any("managed by Reverse Proxies" in conflict for conflict in result["conflicts"])
        assert observations and hostname in observations
        assert [(row.id, row.hostname, row.address) for row in db.scalars(select(DnsRecord))] == before
        assert runtime_snapshot(db) == proxy_before


@pytest.mark.parametrize("transport", ["api", "ui"])
@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("authoritative", [False, True])
@pytest.mark.parametrize("short_name", [False, True])
def test_network_boot_host_writers_preserve_unpublished_proxy_names(client, monkeypatch, transport, operation, authoritative, short_name):
    """Reject specialized host DNS conflicts under writer admission without changing state.

    Args:
        client: Initialized isolated appliance client.
        monkeypatch: Observe writer admission and DNS ownership checks.
        transport: Real API or UI host writer.
        operation: Host creation or update of existing managed records.
        authoritative: Disabled authority or authority serving a different zone.
        short_name: Expand a DHCP-scope-relative host name instead of using its FQDN.
    """
    from ipaddress import ip_network

    from sqlalchemy.exc import OperationalError

    from atlaso.app.models import (
        AuditEvent,
        DhcpReservation,
        DhcpScope,
        DnsRecord,
        DnsSettings,
        EsxiPxeHost,
        Setting,
    )
    from atlaso.app.services import network_objects, reverse_proxy_publication
    from atlaso.app.services.esxi_pxe import (
        ESXI_PXE_DHCP_SCOPE_IDS_KEY,
        esxi_pxe_boot_settings,
        sync_esxi_pxe_host_network_records,
    )
    from atlaso.app.services.reverse_proxies import runtime_snapshot, save_proxy
    from tests.routers.api_v1.helpers import create_token
    from tests.routers.api_v1.test_reverse_proxies import (
        _enable_test_listener,
        _payload,
    )

    _enable_test_listener()
    login(client)
    csrf = client.get("/esxi-pxe").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    token, _metadata = create_token(client, ["write:esxi-pxe"])
    hostname = "reserved-proxy.atlaso.internal"

    def snapshot(db):
        """Capture rows that a rejected host write must preserve.

        Args:
            db: Transaction holding the isolated appliance state.
        """
        return (
            [(r.id, r.hostname, r.mac_address, r.ip_address, r.enabled, r.description)
             for r in db.scalars(select(DhcpReservation).order_by(DhcpReservation.id))],
            [(r.id, r.hostname, r.record_type, r.address, r.enabled, r.description)
             for r in db.scalars(select(DnsRecord).order_by(DnsRecord.id))],
            [(r.id, r.hostname, r.mac_address, r.ip_address, r.enabled)
             for r in db.scalars(select(EsxiPxeHost).order_by(EsxiPxeHost.id))],
            list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id))),
            runtime_snapshot(db),
        )

    with SessionLocal() as db:
        scope = db.scalar(select(DhcpScope).where(DhcpScope.name == "SiteA"))
        scope.domain_name = "atlaso.internal"
        scope.enabled = True
        address = str(ip_network(f"{scope.site_address}/{scope.prefix_length}", strict=False).network_address + 150)
        setting = db.scalar(select(Setting).where(Setting.key == ESXI_PXE_DHCP_SCOPE_IDS_KEY))
        if setting is None:
            setting = Setting(key=ESXI_PXE_DHCP_SCOPE_IDS_KEY)
            db.add(setting)
        setting.value = str(scope.id)
        settings = db.scalar(select(DnsSettings))
        settings.enabled = True
        settings.authoritative = authoritative
        settings.domain = "other.test" if authoritative else "atlaso.internal"
        settings.disabled_domains = "atlaso.internal" if authoritative else ""
        db.commit()
        host_id = None
        if operation == "update":
            host = EsxiPxeHost(hostname="before", mac_address="00:50:56:ab:cd:ef", ip_address=address,
                               variables_json="{}", enabled=True)
            db.add(host)
            sync_esxi_pxe_host_network_records(db, host, esxi_pxe_boot_settings(db))
            db.commit()
            host_id = host.id
        save_proxy(db, _payload(enabled=True, managed_dns=True, hostname=hostname), actor="test")
        assert not db.scalars(select(DnsRecord).where(DnsRecord.hostname == hostname)).all()
        before = snapshot(db)

    real_lock = network_objects.acquire_network_objects_write_lock
    real_guard = reverse_proxy_publication.proxy_owns_dns_hostname
    events = []

    def locked(db):
        """Record explicit Network Objects admission before the specialized guard.

        Args:
            db: Caller-owned host transaction.
        """
        real_lock(db)
        events.append("lock")

    def guarded(db, name):
        """Prove writer exclusion and no reservation/DNS mutation before rejection.

        Args:
            db: Admitted host transaction.
            name: Canonical scope-expanded hostname.
        """
        assert events and events[-1] == "lock"
        assert snapshot(db)[:2] == before[:2]
        with SessionLocal() as competitor:
            competitor.connection().exec_driver_sql("PRAGMA busy_timeout=0")
            with pytest.raises(OperationalError, match="locked"):
                real_lock(competitor)
        events.append(name)
        return real_guard(db, name)

    monkeypatch.setattr(network_objects, "acquire_network_objects_write_lock", locked)
    monkeypatch.setattr(reverse_proxy_publication, "proxy_owns_dns_hostname", guarded)
    host_path = "/esxi-pxe/hosts" + (f"/{host_id}" if host_id else "")
    data = {"hostname": "reserved-proxy" if short_name else hostname.upper() + ".",
            "mac_address": "00:50:56:ab:cd:ef", "ip_address": address, "enabled": True}
    if transport == "api":
        response = client.request("PUT" if host_id else "POST", "/api/v1" + host_path,
                                  headers={"Authorization": f"Bearer {token}"}, json=data)
    else:
        response = client.post(host_path, data={**data, "csrf": csrf, "enabled": "on"}, follow_redirects=False)
    assert response.status_code == 409, response.text
    assert "Reverse Proxies" in response.text
    assert events == ["lock", hostname]
    with SessionLocal() as db:
        assert snapshot(db) == before


@pytest.mark.parametrize("operation", ["api-create", "api-edit", "api-enable", "ui-create"])
@pytest.mark.parametrize("address", ["192.168.87.10", "2001:db8:87::10"])
@pytest.mark.parametrize(("scheme", "port", "redirect"), [("http", 80, False), ("https", 443, False), ("https", 9443, True)])
def test_vlan_writers_reject_new_management_socket_scope(client, operation, address, scheme, port, redirect):
    """Reject actual VLAN writers that introduce a cross-interface management socket.

    Args:
        client: Initialized appliance HTTP client.
        operation: Candidate VLAN writer introducing its management front door.
        address: Duplicate IPv4 or IPv6 destination shared with a proxy.
        scheme: Existing proxy protocol.
        port: Existing primary proxy port.
        redirect: Whether the conflicting socket is the HTTP redirect.
    """
    from atlaso.app.models import (
        AuditEvent,
        CaSettings,
        PhysicalInterface,
        VlanInterface,
    )
    from atlaso.app.services.reverse_proxies import runtime_snapshot, save_proxy
    from tests.routers.api_v1.helpers import create_token
    from tests.routers.api_v1.test_reverse_proxies import _payload

    login(client)
    csrf = client.get("/vlan-interfaces").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    token, _metadata = create_token(client, ["write:vlans"])

    def snapshot(db):
        """Capture VLAN, proxy and audit state around a refused transport operation.

        Args:
            db: Caller-owned appliance database session.
        """
        return (
            [(r.id, r.name, r.enabled, r.access_management_ui_enabled, r.ip_cidr, r.ipv6_cidr)
             for r in db.scalars(select(VlanInterface).order_by(VlanInterface.id))],
            runtime_snapshot(db), list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id))),
        )

    with SessionLocal() as db:
        parent = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        parent.mode = "trunk"
        parent.admin_state = "up"
        parent.oper_state = "up"
        access = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        access.ip_cidr = "192.168.87.10/24"
        access.ipv6_enabled = True
        access.ipv6_cidr = "2001:db8:87::10/64"
        access.check_duplicate_ip_addresses = False
        db.scalar(select(CaSettings)).enabled = True
        db.commit()
        save_proxy(db, _payload(enabled=True, scheme=scheme, port=port, redirect_http=redirect, redirect_port=80,
                                listeners=[{"interface": "eth2", "address": address}]), actor="test")
        vlan_id = None
        if operation in {"api-edit", "api-enable"}:
            vlan = VlanInterface(name="eth1.3025", parent_interface="eth1", vlan_id=3025,
                                 role="access", ip_cidr="192.168.87.10/24", ipv6_cidr="2001:db8:87::10/64",
                                 enabled=operation != "api-enable", access_management_ui_enabled=operation == "api-enable",
                                 check_duplicate_ip_addresses=False)
            db.add(vlan)
            db.commit()
            vlan_id = vlan.id
        before = snapshot(db)
    data = {"parent_interface": "eth1", "vlan_id": 3025, "role": "access", "enabled": True,
            "ip_cidr": "192.168.87.10/24", "ipv6_cidr": "2001:db8:87::10/64",
            "access_management_ui_enabled": True, "check_duplicate_ip_addresses": False}
    headers = {"Authorization": f"Bearer {token}"}
    if operation == "api-create":
        response = client.post("/api/v1/vlans", headers=headers, json=data)
    elif operation == "api-edit":
        response = client.patch(f"/api/v1/vlans/{vlan_id}", headers=headers, json=data)
    elif operation == "api-enable":
        response = client.post(f"/api/v1/vlans/{vlan_id}/enable", headers=headers)
    else:
        response = client.post("/vlan-interfaces", data={**data, "csrf": csrf, "enabled": "on",
                               "access_management_ui_enabled": "on", "check_duplicate_ip_addresses": "false"},
                               follow_redirects=False)
    assert response.status_code == 422, response.text
    assert "Service listener conflicts" in response.text
    with SessionLocal() as db:
        assert snapshot(db) == before


@pytest.mark.parametrize("transport", ["api", "ui"])
@pytest.mark.parametrize("address", ["192.168.87.10", "2001:db8:87::10"])
@pytest.mark.parametrize("selection_change", [False, True])
def test_appliance_settings_reject_cross_scope_terminal_https(client, transport, address, selection_change):
    """Refuse terminal selection changes atomically even when the FQDN is unchanged.

    Args:
        client: Initialized appliance HTTP client.
        transport: API or form writer.
        address: Duplicate IPv4 or IPv6 destination.
        selection_change: Change scopes on an already enabled terminal.
    """
    import json

    from atlaso.app.models import (
        ApplianceSettings,
        AuditEvent,
        CaSettings,
        PhysicalInterface,
    )
    from atlaso.app.services.reverse_proxies import runtime_snapshot, save_proxy
    from tests.routers.api_v1.helpers import create_token
    from tests.routers.api_v1.test_reverse_proxies import _payload

    login(client)
    csrf = client.get("/settings").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    token, _metadata = create_token(client, ["admin:all"])

    def snapshot(db):
        """Capture settings, proxy and audit state.

        Args:
            db: Caller-owned appliance database session.
        """
        settings = db.scalar(select(ApplianceSettings))
        return (settings.fqdn, settings.web_terminal_enabled, settings.web_terminal_interfaces_json,
                runtime_snapshot(db), list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id))))

    with SessionLocal() as db:
        for name in ("eth1", "eth2"):
            interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == name))
            interface.role, interface.mode = "access", "access"
            interface.admin_state, interface.oper_state = "up", "up"
            interface.ip_cidr, interface.ipv6_cidr = "192.168.87.10/24", "2001:db8:87::10/64"
            interface.ipv6_enabled = True
            interface.check_duplicate_ip_addresses = False
        settings = db.scalar(select(ApplianceSettings))
        settings.management_https_enabled = True
        settings.web_terminal_enabled = selection_change
        settings.web_terminal_interfaces_json = json.dumps(["eth2"])
        db.scalar(select(CaSettings)).enabled = True
        db.commit()
        save_proxy(db, _payload(enabled=True, port=443, redirect_http=False,
                                listeners=[{"interface": "eth2", "address": address}]), actor="test")
        before = snapshot(db)
    if transport == "api":
        response = client.patch("/api/v1/settings", headers={"Authorization": f"Bearer {token}"},
                                json={"web_terminal_enabled": True, "web_terminal_interfaces": ["eth1"]})
    else:
        response = client.post("/settings", data={"csrf": csrf, "fqdn": before[0],
                               "management_https_enabled": "on", "web_terminal_enabled": "on",
                               "web_terminal_interfaces_present": "on", "web_terminal_interfaces": "eth1"},
                               follow_redirects=False)
    assert response.status_code == 409, response.text
    assert "Service listener conflicts" in response.text
    with SessionLocal() as db:
        assert snapshot(db) == before


@pytest.mark.parametrize("transport", ["api", "ui"])
@pytest.mark.parametrize("operation", ["create", "update"])
@pytest.mark.parametrize("naming", ["ip", "interface"])
@pytest.mark.parametrize("family", ["ipv4", "ipv6"])
@pytest.mark.parametrize("enabled", [False, True])
def test_storage_share_writers_preserve_proxy_alias_names(client, monkeypatch, transport, operation, naming, family, enabled):
    """Guard generated storage aliases under exclusive writer admission atomically.

    Args:
        client: Initialized appliance HTTP client.
        monkeypatch: Observe candidate validation and competing writer exclusion.
        transport: Actual API or UI share writer.
        operation: Create or retarget an existing share.
        naming: Canonical IP or interface target naming.
        family: IPv4 or IPv6 target address family.
        enabled: Enabled proxy or retained disabled intent.
    """
    import importlib

    from sqlalchemy.exc import OperationalError

    from atlaso.app.models import (
        ApplianceSettings,
        AuditEvent,
        DnsRecord,
        EsxNfsShare,
        EsxStorageSettings,
        EsxStorageVolume,
        PhysicalInterface,
    )
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock
    from atlaso.app.services.reverse_proxies import (
        runtime_snapshot,
        save_proxy,
        validate_service_proxy_dependencies,
    )
    from atlaso.app.services.service_dns_names import storage_alias_names
    from tests.routers.api_v1.helpers import create_token
    from tests.routers.api_v1.test_reverse_proxies import (
        _enable_test_listener,
        _payload,
    )

    _enable_test_listener()
    login(client)
    csrf = client.get("/esx-storage").text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    token, _metadata = create_token(client, ["write:esx-storage"])

    def snapshot(db):
        """Capture share, DNS, proxy and audit rows around the refused write.

        Args:
            db: Caller-owned appliance database transaction.
        """
        return ([(r.id, r.interface_name, r.address_families, r.datastore_name) for r in db.scalars(select(EsxNfsShare).order_by(EsxNfsShare.id))],
                [(r.id, r.hostname, r.record_type, r.address, r.enabled) for r in db.scalars(select(DnsRecord).order_by(DnsRecord.id))],
                runtime_snapshot(db), list(db.scalars(select(AuditEvent.id).order_by(AuditEvent.id))))

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth1"))
        interface.ipv6_enabled, interface.ipv6_cidr = True, "2001:db8:77::10/64"
        db.scalar(select(ApplianceSettings)).service_dns_target_naming = naming
        storage = db.scalar(select(EsxStorageSettings))
        if storage is None:
            storage = EsxStorageSettings()
            db.add(storage)
        storage.hostname, storage.enabled = "nfs.example.test", True
        volume = EsxStorageVolume(name="alias-test", source_type="mounted_ext4", stable_device_id="alias-test", mount_path="/mnt/alias-test")
        db.add(volume)
        db.commit()
        volume_id = volume.id
        share_id = None
        if operation == "update":
            share = EsxNfsShare(datastore_name="alias-test", volume_id=volume_id, interface_name="eth2", address_families=family,
                                relative_path="before", enabled=True)
            db.add(share)
            db.commit()
            share_id = share.id
        hostname = next(iter(storage_alias_names(storage.hostname, "eth1", ["192.0.2.10", "2001:db8:77::10"], family, naming)))
        save_proxy(db, _payload(enabled=enabled, hostname=hostname), actor="test")
        before = snapshot(db)
    events = []

    def guarded(db):
        """Prove the alias check excludes a real competing SQLite writer.

        Args:
            db: Candidate share transaction under test.
        """
        assert snapshot(db)[1:] == before[1:]
        with SessionLocal() as competitor:
            competitor.connection().exec_driver_sql("PRAGMA busy_timeout=0")
            with pytest.raises(OperationalError, match="locked"):
                acquire_network_objects_write_lock(competitor)
        events.append("guard")
        validate_service_proxy_dependencies(db)

    module = importlib.import_module("atlaso.app.routers." + ("api_v1" if transport == "api" else "ui") + ".esx_storage")
    monkeypatch.setattr(module, "validate_service_proxy_dependencies", guarded)
    data = {"datastore_name": "alias-test", "volume_id": volume_id, "relative_path": "after", "interface_name": "eth1",
            "address_families": [family], "enabled": True}
    path = "/esx-storage/shares" + (f"/{share_id}" if share_id else "")
    if transport == "api":
        response = client.request("PATCH" if share_id else "POST", "/api/v1" + path,
                                  headers={"Authorization": f"Bearer {token}"}, json=data)
    else:
        response = client.post(path, data={**data, "csrf": csrf, "enabled": "on"}, follow_redirects=False)
    assert response.status_code == 409, response.text
    assert events == ["guard"]
    with SessionLocal() as db:
        assert snapshot(db) == before


def test_storage_dns_reconciliation_keeps_share_and_audits_uncommitted(client, monkeypatch):
    """Keep generated DNS and audit additions/removals in the share writer transaction.

    Args:
        client: Initialized appliance fixture.
        monkeypatch: Fail on any hidden commit during reconciliation.
    """
    from atlaso.app import ui
    from atlaso.app.models import (
        AuditEvent,
        EsxNfsShare,
        EsxStorageSettings,
        EsxStorageVolume,
    )

    with SessionLocal() as db:
        storage = db.scalar(select(EsxStorageSettings))
        if storage is None:
            storage = EsxStorageSettings()
            db.add(storage)
        storage.enabled = True
        storage.hostname = "nfs.example.test"
        volume = EsxStorageVolume(name="transaction-test", stable_device_id="transaction-test", source_type="mounted_ext4", mount_path="/mnt/test")
        db.add(volume)
        db.commit()
        audits = list(db.scalars(select(AuditEvent.id)))
        share = EsxNfsShare(datastore_name="transaction-test", volume_id=volume.id, interface_name="eth2", relative_path="data", enabled=True)
        db.add(share)
        db.flush()
        transaction = db.get_transaction()

        def refuse_commit():
            """Keep the candidate and generated audit rows under caller ownership."""
            pytest.fail("DNS reconciliation must not commit the share writer")

        monkeypatch.setattr(db, "commit", refuse_commit)
        assert ui.ensure_dns_for_esx_storage(db, "test")
        assert db.get_transaction() is transaction
        assert len(list(db.scalars(select(AuditEvent.id)))) > len(audits)
        share.interface_name = "eth0"
        assert ui.ensure_dns_for_esx_storage(db, "test")
        assert db.get_transaction() is transaction
        db.rollback()
        assert list(db.scalars(select(AuditEvent.id))) == audits
