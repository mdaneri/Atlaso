"""Cover server-owned Appliance Apply review plans and consent binding."""

import json
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from tests.routers.ui.helpers import login


@pytest.mark.parametrize("address", ["192.0.2.10", "2001:db8::10"])
@pytest.mark.parametrize("service,port", [("kms", 5696), ("ldap", 636), ("ntpd", 4460),
                                          ("vcf_backups", 2222), ("vcf_offline_depot", 8444),
                                          ("vcf_private_registry", 8445), ("esxi_pxe", 8088)])
def test_proxy_plan_detects_applied_socket_owner_and_redirect(address, service, port):
    """Resolve release dependencies from applied rather than disabled desired state.

    Args:
        address: Applied service address in either IP family.
        service: Native or shared service listener owner.
        port: Applied owner port taken by the desired proxy redirect.
    """
    from atlaso.app import ui

    previews = {
        "kms": json.dumps({"enabled": True, "listen": {"addresses": [address], "port": port}}),
        "ldap": json.dumps({"service": {"enabled": True, "ldaps_enabled": True, "ldap_enabled": False,
                                           "listen_address": address, "port": port}}),
        "ntpd": f"# Atlaso NTP listen addresses: {address}\nnts enable\n",
        "vcf_backups": f"# Atlaso VCF Backups enabled: true\n# Service listener targets: {address}:{port}\n",
        "vcf_offline_depot": f"server {{ listen {'[' + address + ']' if ':' in address else address}:{port} ssl; }}",
        "vcf_private_registry": f"https:\n  port: {port}\natlaso_listen_address: {address}\n",
        "esxi_pxe": json.dumps({"boot": {"enabled": True, "listen_address": address, "http_port": port}}),
    }
    proxy = {"enabled": True, "port": 8443, "redirect_http": True, "redirect_port": port,
             "listeners": [{"interface": "eth1", "address": address}]}
    units = {"public_services": {"context": {"reverse_proxies": [proxy]}}, service: {"changed": True}}
    baselines = {service: {"config_preview": previews[service]}}
    assert ui.proxy_socket_release_dependencies(units, baselines) == {service}
    proxy["enabled"] = False
    assert ui.proxy_socket_release_dependencies(units, baselines) == set()
    proxy["enabled"] = True
    units[service]["changed"] = False
    assert ui.proxy_socket_release_dependencies(units, baselines) == set()
    units[service]["changed"] = True
    proxy["listeners"][0]["address"] = "192.0.2.99"
    assert ui.proxy_socket_release_dependencies(units, baselines) == set()


@pytest.mark.parametrize("service", ["kms", "esxi_pxe"])
def test_proxy_review_requires_shutdown_and_orders_it_before_protected_group(client, monkeypatch, service):
    """Capture a reviewed shutdown before the first nginx handoff member.

    Args:
        client: Isolated authenticated HTTP client.
        monkeypatch: Fixture pinning real unit snapshots for focused planning.
        service: Applied service whose shutdown releases the proxy socket.
    """
    from atlaso.app.database import SessionLocal

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    unit_map = {unit["id"]: unit for unit in units}
    for unit in units:
        unit["changed"] = False
    unit_map["public_services"].update(changed=True, snapshot_marker={"reverse_proxy_intent_sha256": "new"})
    unit_map["public_services"]["context"]["reverse_proxies"] = [{
        "enabled": True, "port": 5696, "listeners": [{"interface": "eth1", "address": "192.0.2.10"}],
    }]
    state = {"enabled": False} if service == "esxi_pxe" else SimpleNamespace(enabled=False)
    state_key = "esxi_pxe_boot" if service == "esxi_pxe" else "kms_settings"
    unit_map[service].update(changed=True, context={state_key: state})
    with SessionLocal() as db:
        baselines = ui.load_appliance_apply_baselines(db)
        baseline = {
            "enabled": True, "listen": {"addresses": ["192.0.2.10"], "port": 5696},
        } if service == "kms" else {"boot": {"enabled": True, "listen_address": "192.0.2.10", "http_port": 5696}}
        baselines[service]["config_preview"] = json.dumps(baseline)
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()
        with pytest.raises(ui.ApplianceApplyPlanError) as denied:
            ui.appliance_apply_execution_plan(db, units, {"public_services"})
        assert "reverse-proxy publication dependencies" in denied.value.public_detail
        plan = ui.appliance_apply_execution_plan(db, units, {"public_services", service})
        order = [unit["id"] for unit in plan["selected_ordered_units"]]
        assert order.index(service) < min(order.index(unit_id) for unit_id in ui.MANAGEMENT_HANDOFF_UNIT_IDS)
        if service == "kms":
            state.enabled = True
        else:
            state["enabled"] = True
        with pytest.raises(ui.ApplianceApplyPlanError) as moved:
            ui.appliance_apply_execution_plan(db, units, {"public_services", service})
        assert "socket-moving service changes" in moved.value.public_detail
        if service == "kms":
            state.enabled = False
        else:
            state["enabled"] = False

    from atlaso.app.models import Job

    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get(f"/appliance-apply/review?selected_units=public_services&selected_units={service}").json()
    assert not preview["plan_error"]
    effective = [unit["id"] for unit in preview["units"] if unit["selected"]]
    assert effective.index(service) < effective.index("public_services")
    response = client.post("/appliance-apply", data={
        "csrf": csrf, "reviewed_plan": preview["plan_token"],
        "requested_units": preview["requested_units"], "selected_units": effective,
    }, headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        submitted = json.loads(db.get(Job, response.json()["job_id"]).result)
        assert submitted["selected_units"] == effective
        assert submitted["management_handoff"] is True


@pytest.mark.parametrize("address", ["192.0.2.10", "2001:db8::10"])
@pytest.mark.parametrize("redirect", [False, True])
@pytest.mark.parametrize("service", ["kms", "esxi_pxe", "vcf_private_registry"])
def test_service_takeover_requires_reviewed_proxy_retirement_first(client, monkeypatch, address, redirect, service):
    """A service-only Apply cannot bind a still-applied nginx listener.

    Args:
        client: Real management client with an isolated database.
        monkeypatch: Supply captured units without executing host mutation.
        address: Old proxy IPv4 or IPv6 address.
        redirect: Take the redirect socket instead of the main listener.
        service: Selected service taking the old applied proxy socket.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.reverse_proxy_publication import (
        render_proxy_servers,
        transport_manifest,
    )
    from tests.services.test_reverse_proxy_observation import _desired

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    unit_map = {unit["id"]: unit for unit in units}
    for unit in units:
        unit["changed"] = False
    proxy = _desired()[0]
    proxy["listeners"][0]["address"] = address
    proxy.update(redirect_http=redirect, redirect_port=5696, port=8443 if redirect else 5696)
    applied = render_proxy_servers([proxy], transport_manifest([proxy], []))
    unit_map["public_services"].update(changed=True, config_preview="", snapshot_marker={"reverse_proxy_intent_sha256": "removed"})
    unit_map["public_services"]["context"]["reverse_proxies"] = []
    def preview_for(target):
        """Render a service fixture at the selected socket.

        Args:
            target: Candidate listener address in either IP family.
        """
        if service == "vcf_private_registry":
            from atlaso.app.models import VcfPrivateRegistrySettings
            from atlaso.app.services.vcf_private_registry import render_harbor_config

            return render_harbor_config(VcfPrivateRegistrySettings(
                enabled=True, hostname="registry.example.test", port=5696, listen_interface="eth1",
                listen_address="198.51.100.99\n" + target))
        return json.dumps({"enabled": True, "listen": {"addresses": [target], "port": 5696}}
                          if service == "kms" else {"boot": {"enabled": True, "listen_address": target, "http_port": 5696}})

    context = {"kms_settings": SimpleNamespace(enabled=True)} if service == "kms" else {"esxi_pxe_boot": {"enabled": True}}
    if service == "vcf_private_registry":
        context = {"vcf_registry_settings": SimpleNamespace(enabled=True)}
    unit_map[service].update(changed=True, config_preview=preview_for(address), context=context)
    with SessionLocal() as db:
        baselines = ui.load_appliance_apply_baselines(db)
        baselines["public_services"]["config_preview"] = applied
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()
        with pytest.raises(ui.ApplianceApplyPlanError) as denied:
            ui.appliance_apply_execution_plan(db, units, {service})
        assert "Select Public Services" in denied.value.public_detail
        plan = ui.appliance_apply_execution_plan(db, units, {service}, enforce_consent=False)
        assert "public_services" in plan["selected_ids"]
        accepted = ui.appliance_apply_execution_plan(db, units, plan["selected_ids"])
        order = [unit["id"] for unit in accepted["selected_ordered_units"]]
        assert order.index(service) > max(order.index(key) for key in ui.MANAGEMENT_HANDOFF_UNIT_IDS)
        unit_map[service]["config_preview"] = preview_for("192.0.2.99")
        assert ui.proxy_socket_takeover_dependencies(unit_map, baselines, {service}) == set()
    unit_map[service]["config_preview"] = preview_for(address)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get(f"/appliance-apply/review?selected_units={service}").json()
    assert not preview["plan_error"]
    selected = [unit["id"] for unit in preview["units"] if unit["selected"]]
    assert selected.index(service) > selected.index("public_services")
    response = client.post("/appliance-apply", data={
        "csrf": csrf, "reviewed_plan": preview["plan_token"],
        "requested_units": preview["requested_units"], "selected_units": selected,
    }, headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text
    from atlaso.app.models import Job

    with SessionLocal() as db:
        captured = json.loads(db.get(Job, response.json()["job_id"]).result)
        assert captured["management_handoff"] is True
        assert captured["selected_units"].index(service) > captured["selected_units"].index("public_services")


def _prepare_network_handoff_review(client, monkeypatch, *, invalid_firewall=False, changed_local_users=False):
    """Build current unit snapshots with a protected Network/WAN handoff.

    Args:
        client: Isolated authenticated HTTP client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        invalid_firewall: Whether the unchanged Firewall dependency is invalid.
        changed_local_users: Whether an independent Local Users change is pending.

    Returns:
        Current real Apply units, the logged-in request CSRF value, and UI module.
    """
    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    login(client)
    page = client.get("/dashboard")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.add(Job(
            id="completed-before-review",
            type="appliance-apply",
            status="succeeded",
            created_by="admin",
        ))
        db.commit()

    for unit in units:
        unit["changed"] = False
        unit["has_baseline"] = True
        if unit["id"] in {"network", "wan"}:
            unit["changed"] = True
        if unit["id"] == "network":
            unit["management_handoff_required"] = True
        if unit["id"] == "firewall" and invalid_firewall:
            unit["valid"] = False
            unit["validation_errors"] = ["Firewall dependency is invalid."]
        if unit["id"] == "local_users" and changed_local_users:
            unit["changed"] = True

    monkeypatch.setattr(ui, "appliance_apply_units", lambda _db, **_kwargs: units)
    monkeypatch.setattr(ui, "network_listener_handoff_required", lambda _db, _units: False)
    return units, csrf, ui


def test_network_wan_review_expands_to_five_unchanged_handoff_dependencies(client, monkeypatch):
    """Show the full seven-unit execution plan and dependency explanations.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    _units, _csrf, _ui = _prepare_network_handoff_review(client, monkeypatch)

    response = client.get("/appliance-apply/review?selected_units=network&selected_units=wan")

    assert response.status_code == 200
    payload = response.json()
    selected = [unit for unit in payload["units"] if unit["selected"]]
    required = [unit for unit in selected if unit["required_dependency"]]
    assert payload["requested_units"] == ["network", "wan"]
    assert payload["pending_count"] == 2
    assert payload["execution_count"] == 7
    assert len(selected) == 7
    assert {unit["id"] for unit in required} == {
        "ca", "firewall", "appliance_settings", "public_services", "nat",
    }
    assert all(not unit["changed"] and unit["dependency_reason"] for unit in required)
    assert all(unit["valid"] for unit in required)
    assert payload["plan_token"]
    assert not payload["plan_error"]


def test_reviewed_network_wan_plan_submits_same_ordered_effective_selection(client, monkeypatch):
    """Submit exactly the effective units represented by a reviewed token.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    _units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    effective = [unit["id"] for unit in preview["units"] if unit["selected"]]

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": preview["plan_token"],
            "requested_units": preview["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        submitted = json.loads(job.result or "{}")
    assert submitted["selected_units"] == effective
    assert submitted["management_handoff"] is True
    assert len(submitted["captured_units"]) == 7


def test_deselected_network_plan_can_shrink_to_local_users_or_empty(client, monkeypatch):
    """Recompute dependencies when Network is deselected, including empty choice.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    _units, _csrf, _ui = _prepare_network_handoff_review(
        client, monkeypatch, changed_local_users=True,
    )
    initial = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    assert initial["execution_count"] == 7

    independent = client.get("/appliance-apply/review?selected_units=local_users").json()
    independent_selected = [unit["id"] for unit in independent["units"] if unit["selected"]]
    assert independent["requested_units"] == ["local_users"]
    assert independent["pending_count"] == 3
    assert independent["execution_count"] == 1
    assert independent_selected == ["local_users"]

    empty = client.get("/appliance-apply/review?selected_units=").json()
    assert empty["requested_units"] == []
    assert empty["pending_count"] == 3
    assert empty["execution_count"] == 0
    assert not any(unit["selected"] for unit in empty["units"])


def test_invalid_required_handoff_dependency_is_visible_and_submit_is_rejected(client, monkeypatch):
    """Keep an invalid required dependency in the plan and fail submission closed.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    _units, csrf, ui = _prepare_network_handoff_review(
        client, monkeypatch, invalid_firewall=True,
    )
    before = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    firewall = next(unit for unit in before["units"] if unit["id"] == "firewall")
    assert firewall["selected"] is True
    assert firewall["required_dependency"] is True
    assert firewall["valid"] is False
    assert "Firewall dependency is invalid." in firewall["validation_errors"]
    assert "Firewall" in before["plan_error"]
    effective = [unit["id"] for unit in before["units"] if unit["selected"]]
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": before["plan_token"],
            "requested_units": before["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 422
    assert "Resolve validation errors" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


def test_reviewed_plan_rejects_snapshot_change_before_submission(client, monkeypatch):
    """Reject a plan token after one captured component snapshot changes.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    effective = [unit["id"] for unit in preview["units"] if unit["selected"]]
    network = next(unit for unit in units if unit["id"] == "network")
    network["snapshot_hash"] = "changed-after-review"
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": preview["plan_token"],
            "requested_units": preview["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 422
    assert "changed since review" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


def test_generated_dns_only_plan_captures_the_reviewed_generated_snapshot(client, monkeypatch):
    """Preserve the generated DNS snapshot through review and token-bound submit.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    dns = next(unit for unit in units if unit["id"] == "dnsmasq")
    generated_dns = {
        **dns,
        "changed": True,
        "snapshot_hash": "generated-dns-snapshot",
        "config_preview": "generated listener DNS records",
        "config_diff": "generated diff",
    }
    monkeypatch.setattr(ui, "network_generated_dns_unit", lambda _db, _unit_map: generated_dns)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    dns_review = next(unit for unit in preview["units"] if unit["id"] == "dnsmasq")
    assert preview["plan_error"] == ""
    assert dns_review["selected"] is True
    assert dns_review["required_dependency"] is True
    assert dns_review["config_preview"] == "generated listener DNS records"
    effective = [unit["id"] for unit in preview["units"] if unit["selected"]]

    response = client.post(
        "/appliance-apply",
        data={
            "csrf": csrf,
            "reviewed_plan": preview["plan_token"],
            "requested_units": preview["requested_units"],
            "selected_units": effective,
        },
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        assert job is not None
        submitted = json.loads(job.result or "{}")
    assert submitted["generated_dns_only"] is True
    captured_dns = next(unit for unit in submitted["captured_units"] if unit["unit_id"] == "dnsmasq")
    assert captured_dns["snapshot_hash"] == "generated-dns-snapshot"
    assert captured_dns["config_preview"] == "generated listener DNS records"


def test_plan_token_binds_every_boolean_execution_control(client, monkeypatch):
    """Changing an execution control invalidates consent without changing snapshots.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    from atlaso.app.database import SessionLocal

    units, _csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    with SessionLocal() as db:
        plan = ui.appliance_apply_execution_plan(db, units, {"network", "wan"})
    original_token = ui.appliance_apply_plan_token(plan)
    controls = {key: value for key, value in plan.items() if isinstance(value, bool)}
    assert {"publishing_pair_required", "routing_publishing_network"}.issubset(controls)
    for key, value in controls.items():
        assert ui.appliance_apply_plan_token({**plan, key: not value}) != original_token, key


@pytest.mark.parametrize("request_dns", [False, True])
def test_disabled_dns_dependency_preserves_requested_handoff_semantics(client, monkeypatch, request_dns):
    """Consenting to an LDAP dependency must not turn it into a DNS request.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        request_dns: Whether DNS is explicitly requested rather than added as a dependency.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    dns = next(unit for unit in units if unit["id"] == "dnsmasq")
    dns["changed"] = True
    dns["context"]["dns_settings"] = SimpleNamespace(enabled=False)
    ldap = next(unit for unit in units if unit["id"] == "ldap")
    ldap["context"]["ldap_settings"] = SimpleNamespace(enabled=True)
    next(unit for unit in units if unit["id"] == "ca")["changed"] = True
    roots = ["network", "wan", "ca"] + (["dnsmasq"] if request_dns else [])
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review", params=[("selected_units", unit) for unit in roots]).json()
    assert not preview["plan_error"]
    reviewed_dns = next(unit for unit in preview["units"] if unit["id"] == "dnsmasq")
    assert reviewed_dns["selected"]
    assert reviewed_dns["required_dependency"] is (not request_dns)
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "reviewed_plan": preview["plan_token"],
              "requested_units": preview["requested_units"],
              "selected_units": [unit["id"] for unit in preview["units"] if unit["selected"]]},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        job = db.get(Job, response.json()["job_id"])
        submitted = json.loads(job.result or "{}")
    assert ("dnsmasq" in submitted["management_handoff_units"]) is request_dns


@pytest.mark.parametrize("control", ["publishing_pair_required", "routing_publishing_network"])
def test_reviewed_plan_rejects_changed_execution_grouping(client, monkeypatch, control):
    """Reject a grouping change even while every desired snapshot stays identical.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        control: Execution-grouping control changed after review.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    _units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    original = ui.appliance_apply_execution_plan
    changed = False

    def grouped_plan(*args, **kwargs):
        """Recompute the plan with changed grouping after review.

        Args:
            *args: Positional arguments forwarded to the shared planner.
            **kwargs: Keyword arguments forwarded to the shared planner.
        """
        plan = original(*args, **kwargs)
        if changed:
            plan[control] = not plan[control]
        return plan

    monkeypatch.setattr(ui, "appliance_apply_execution_plan", grouped_plan)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    changed = True
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "reviewed_plan": preview["plan_token"],
              "requested_units": preview["requested_units"],
              "selected_units": [unit["id"] for unit in preview["units"] if unit["selected"]]},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 422
    assert "changed since review" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


@pytest.mark.parametrize("submission", [False, True])
def test_unexpected_planning_diagnostics_use_generic_request_failure(client, monkeypatch, submission):
    """Only intentional operator guidance may be returned by Apply planning.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        submission: Whether to exercise submission instead of preview.
    """
    _units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    diagnostic = "unexpected internal planning diagnostic"

    def unexpected_failure(*_args, **_kwargs):
        """Inject an unexpected planning failure.

        Args:
            *_args: Unused positional planner arguments.
            **_kwargs: Unused keyword planner arguments.
        """
        raise ValueError(diagnostic)

    monkeypatch.setattr(ui, "appliance_apply_execution_plan", unexpected_failure)
    guarded_client = TestClient(client.app, raise_server_exceptions=False, cookies=client.cookies)
    try:
        response = (
            guarded_client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "network",
                                                        "reviewed_plan": "reviewed-before-unexpected-failure", "requested_units": "network"},
                                headers={"Accept": "application/json"})
            if submission else guarded_client.get("/appliance-apply/review")
        )
    finally:
        guarded_client.close()
    assert response.status_code == 500
    assert diagnostic not in response.text
    assert "Traceback" not in response.text
def test_storage_review_serializes_changed_manifest_identity(client, monkeypatch):
    """Expose the reviewed snapshot even when the formatted disk identity is unchanged.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
    """
    units, _csrf, _ui = _prepare_network_handoff_review(client, monkeypatch)
    storage = next(unit for unit in units if unit["id"] == "esx_storage")
    storage["changed"] = True
    volume = {
        "id": 17, "name": "datastore", "stable_device_id": "/dev/disk/by-id/original",
        "fingerprint": {"serial": "original", "wwn": "wwn-original", "size_bytes": 1000},
        "requires_format": True,
    }
    storage["context"]["esx_storage_manifest"] = {"volumes": [volume]}
    storage["snapshot_hash"] = "reviewed-storage-manifest"
    before = client.get("/appliance-apply/review?selected_units=esx_storage").json()
    before_storage = next(unit for unit in before["units"] if unit["id"] == "esx_storage")
    assert before_storage["snapshot_hash"] == "reviewed-storage-manifest"
    assert before_storage["format_volumes"][0]["id"] == volume["id"]
    storage["snapshot_hash"] = "changed-storage-manifest"
    after = client.get("/appliance-apply/review?selected_units=esx_storage").json()
    after_storage = next(unit for unit in after["units"] if unit["id"] == "esx_storage")
    assert after_storage["format_volumes"] == before_storage["format_volumes"]
    assert after_storage["snapshot_hash"] != before_storage["snapshot_hash"]
    assert after["plan_token"] != before["plan_token"]
@pytest.mark.parametrize("wants_json", [False, True])
def test_tokenless_apply_refuses_current_state_after_review(client, monkeypatch, wants_json):
    """Old assets and form clients cannot submit unreviewed current snapshots.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        wants_json: Whether the client requests the JSON refusal representation.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, _ui = _prepare_network_handoff_review(client, monkeypatch)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    next(unit for unit in units if unit["id"] == "network")["snapshot_hash"] = "changed-after-review"
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "selected_units": [unit["id"] for unit in preview["units"] if unit["selected"]]},
        headers={"Accept": "application/json" if wants_json else "text/html"},
    )
    assert response.status_code == 422
    assert "Reopen appliance review" in response.text
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0
@pytest.mark.parametrize("reapplied_same_state", [False, True])
def test_reviewed_plan_rejects_intervening_apply_baseline(client, monkeypatch, reapplied_same_state):
    """Another completed Apply invalidates consent even with identical desired hashes.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        reapplied_same_state: Whether only baseline metadata changes on an unchanged unit.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    desired_hashes = [unit["snapshot_hash"] for unit in units]
    target = next(unit for unit in units if unit["id"] == ("ca" if reapplied_same_state else "network"))
    with SessionLocal() as db:
        ui.update_appliance_apply_baselines(db, units, {target["id"]})
        db.commit()
    if not reapplied_same_state:
        target["changed"] = False
        target["has_baseline"] = True
        target["config_diff"] = ""
    assert [unit["snapshot_hash"] for unit in units] == desired_hashes
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "reviewed_plan": preview["plan_token"],
              "requested_units": preview["requested_units"],
              "selected_units": [unit["id"] for unit in preview["units"] if unit["selected"]]},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 422
    assert "changed since review" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


@pytest.mark.parametrize("service_only", [False, True])
def test_reviewed_plan_rechecks_baseline_after_writer_admission(client, monkeypatch, service_only):
    """Reject a completed Apply racing the initial planning check.

    Args:
        client: Isolated authenticated HTTP test client.
        monkeypatch: Test-scoped replacements for Apply planning dependencies.
        service_only: Whether the changed NAT baseline is outside the selected service plan.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    roots = ["network", "wan"]
    if service_only:
        roots = ["ntpd"]
        next(unit for unit in units if unit["id"] == "ntpd")["changed"] = True
    preview = client.get("/appliance-apply/review", params=[("selected_units", unit) for unit in roots]).json()
    if service_only:
        assert {unit["id"] for unit in preview["units"] if unit["selected"]} == {"ntpd"}
    original = ui.appliance_apply_execution_plan

    def plan_with_intervening_apply(*args, **kwargs):
        """Inject a completed baseline change after initial planning.

        Args:
            *args: Positional arguments passed to the original planner.
            **kwargs: Keyword arguments passed to the original planner.
        """
        plan = original(*args, **kwargs)
        db = args[0]
        ui.update_appliance_apply_baselines(db, units, {"nat" if service_only else "ca"})
        db.commit()
        return plan

    monkeypatch.setattr(ui, "appliance_apply_execution_plan", plan_with_intervening_apply)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    response = client.post(
        "/appliance-apply",
        data={"csrf": csrf, "reviewed_plan": preview["plan_token"],
              "requested_units": preview["requested_units"],
              "selected_units": [unit["id"] for unit in preview["units"] if unit["selected"]]},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 422
    assert "changed since review" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


def test_explicit_unchanged_runtime_replay_is_reviewed(client, monkeypatch):
    """An unchanged NTP replay uses the same reviewed submission contract.

    Args:
        client: Isolated authenticated management client.
        monkeypatch: Replace host execution and current snapshots.
    """
    _units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: None)
    preview = client.get("/appliance-apply/review?selected_units=ntpd").json()
    assert preview["requested_units"] == ["ntpd"]
    selected = [unit for unit in preview["units"] if unit["selected"]]
    assert any(unit["id"] == "ntpd" and not unit["changed"] for unit in selected)
    response = client.post("/appliance-apply", data={"csrf": csrf, "reviewed_plan": preview["plan_token"],
                           "requested_units": preview["requested_units"],
                           "selected_units": [unit["id"] for unit in selected]},
                           headers={"Accept": "application/json"})
    assert response.status_code == 202, response.text


@pytest.mark.parametrize("mutation", ["selected", "dependency"])
def test_reviewed_plan_rechecks_desired_state_after_writer_admission(client, monkeypatch, mutation):
    """A desired save at admission cannot become an unreviewed captured job.

    Args:
        client: Isolated authenticated management client.
        monkeypatch: Replace the admission boundary and host execution.
        mutation: Whether the changed snapshot belongs to a root or dependency.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()
    original_lock = ui.lock_appliance_apply_snapshot_tables

    def admit_after_desired_save(db):
        """Inject a desired snapshot change immediately before writer admission.

        Args:
            db: Submission session acquiring the ordinary writer boundary.
        """
        target = next(unit for unit in units if unit["id"] == ("network" if mutation == "selected" else "firewall"))
        target["snapshot_hash"] = "changed-before-writer-admission"
        original_lock(db)

    monkeypatch.setattr(ui, "lock_appliance_apply_snapshot_tables", admit_after_desired_save)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: pytest.fail("stale plan executed"))
    response = client.post("/appliance-apply", data={"csrf": csrf, "reviewed_plan": preview["plan_token"],
                           "requested_units": preview["requested_units"],
                           "selected_units": [unit["id"] for unit in preview["units"] if unit["selected"]]},
                           headers={"Accept": "application/json"})
    assert response.status_code == 422
    assert "changed since review" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


def test_writer_contention_refuses_submission_without_job(client, monkeypatch):
    """Contention returns safe retry guidance without queuing stale captures.

    Args:
        client: Isolated authenticated management client.
        monkeypatch: Inject typed contention at the snapshot admission boundary.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job
    from atlaso.app.services.appliance_apply_admission import (
        ApplianceApplyAdmissionBusy,
    )

    _units, csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    preview = client.get("/appliance-apply/review?selected_units=network&selected_units=wan").json()

    def busy(db):
        """Model release of admission locks on PostgreSQL contention.

        Args:
            db: Submission session holding its initial writer boundary.
        """
        db.rollback()
        raise ApplianceApplyAdmissionBusy("private diagnostic")

    monkeypatch.setattr(ui, "lock_appliance_apply_snapshot_tables", busy)
    monkeypatch.setattr(ui, "run_appliance_apply_job", lambda _job_id: pytest.fail("contended job executed"))
    response = client.post("/appliance-apply", data={"csrf": csrf, "reviewed_plan": preview["plan_token"],
                           "requested_units": preview["requested_units"],
                           "selected_units": [unit["id"] for unit in preview["units"] if unit["selected"]]},
                           headers={"Accept": "application/json"})
    assert response.status_code == 409
    assert "try again" in response.json()["detail"]
    assert "private" not in response.text
    with SessionLocal() as db:
        assert db.query(Job).filter(Job.id != "completed-before-review").count() == 0


@pytest.mark.parametrize("root", ["ca", "wan"])
def test_explicit_coupled_roots_can_be_cleared_without_selection_cycle(client, monkeypatch, root):
    """Explicit handoff/routing roots stay reversible through dependency expansion.

    Args:
        client: Isolated authenticated management client.
        monkeypatch: Supply a pending protected handoff with valid snapshots.
        root: Explicit component coupled to the pending Network handoff.
    """
    units, _csrf, _ui = _prepare_network_handoff_review(client, monkeypatch)
    next(unit for unit in units if unit["id"] == root)["changed"] = True
    initial = client.get("/appliance-apply/review", params=[("selected_units", "network"),
                                                           ("selected_units", root)]).json()
    assert initial["requested_units"] == sorted(["network", root])
    rows = {unit["id"]: unit for unit in initial["units"]}
    assert rows["network"]["selected"] and not rows["network"]["required_dependency"]
    assert rows[root]["selected"] and not rows[root]["required_dependency"]
    assert any(unit["required_dependency"] for unit in initial["units"] if unit["id"] not in {"network", root})

    remaining = client.get("/appliance-apply/review", params={"selected_units": root}).json()
    assert remaining["requested_units"] == [root]
    root_row = next(unit for unit in remaining["units"] if unit["id"] == root)
    assert root_row["selected"] and not root_row["required_dependency"]
    if root == "ca":
        network_row = next(unit for unit in remaining["units"] if unit["id"] == "network")
        assert network_row["selected"] and network_row["required_dependency"]
    cleared = client.get("/appliance-apply/review", params={"selected_units": ""}).json()
    assert cleared["requested_units"] == []
    assert cleared["execution_count"] == 0
    assert not any(unit["selected"] for unit in cleared["units"])


@pytest.mark.parametrize("address", ["192.0.2.20", "2001:db8::20"])
@pytest.mark.parametrize("redirect", [False, True])
def test_registry_plural_socket_release_requires_reviewed_shutdown(client, monkeypatch, address, redirect):
    """Require registry release for a non-first listener from its actual renderer.

    Args:
        client: Isolated appliance HTTP client.
        monkeypatch: Capture reviewed jobs without native mutation.
        address: Non-first IPv4 or IPv6 registry listener being taken over.
        redirect: Proxy redirect socket instead of its primary socket.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import VcfPrivateRegistrySettings
    from atlaso.app.services.vcf_private_registry import render_harbor_config

    units, _csrf, ui = _prepare_network_handoff_review(client, monkeypatch)
    unit_map = {unit["id"]: unit for unit in units}
    for unit in units:
        unit["changed"] = False
    settings = VcfPrivateRegistrySettings(enabled=True, hostname="registry.example.test", port=8445,
                                          listen_interface="eth1", listen_address="192.0.2.10\n" + address)
    preview = render_harbor_config(settings)
    state = SimpleNamespace(enabled=False)
    unit_map["vcf_private_registry"].update(changed=True, context={"vcf_registry_settings": state})
    unit_map["public_services"].update(changed=True, snapshot_marker={"reverse_proxy_intent_sha256": "takeover"})
    unit_map["public_services"]["context"]["reverse_proxies"] = [{
        "enabled": True, "port": 8443 if redirect else 8445, "redirect_http": redirect, "redirect_port": 8445,
        "listeners": [{"interface": "eth1", "address": address}],
    }]
    with SessionLocal() as db:
        baselines = ui.load_appliance_apply_baselines(db)
        baselines["vcf_private_registry"]["config_preview"] = preview
        ui.save_appliance_apply_baselines(db, baselines)
        db.commit()
        assert ui.proxy_socket_release_dependencies(unit_map, baselines) == {"vcf_private_registry"}
        with pytest.raises(ui.ApplianceApplyPlanError) as denied:
            ui.appliance_apply_execution_plan(db, units, {"public_services"})
        assert "reverse-proxy publication dependencies" in denied.value.public_detail
        plan = ui.appliance_apply_execution_plan(db, units, {"public_services", "vcf_private_registry"})
        order = [unit["id"] for unit in plan["selected_ordered_units"]]
        assert order.index("vcf_private_registry") < min(order.index(key) for key in ui.MANAGEMENT_HANDOFF_UNIT_IDS)
        state.enabled = True
        with pytest.raises(ui.ApplianceApplyPlanError, match="planning refused"):
            ui.appliance_apply_execution_plan(db, units, {"public_services", "vcf_private_registry"})


@pytest.mark.parametrize("metadata", ["not-a-list", "[17]", "['invalid-address']", "[]"])
def test_registry_invalid_plural_metadata_cannot_prove_socket_free(metadata):
    """Conservatively retain the dependency when applied plural evidence is invalid.

    Args:
        metadata: Unsupported or malformed plural listener ownership metadata.
    """
    from atlaso.app import ui

    units = {"public_services": {"context": {"reverse_proxies": [{"enabled": True, "port": 8445,
             "listeners": [{"address": "192.0.2.20"}]}]}}, "vcf_private_registry": {"changed": True}}
    baseline = {"vcf_private_registry": {"config_preview": "https:\n  port: 8445\natlaso_listen_addresses: " + metadata + "\n"}}
    assert ui.proxy_socket_release_dependencies(units, baseline) == {"vcf_private_registry"}


@pytest.mark.parametrize("address", ["192.0.2.20", "2001:db8::20"])
def test_registry_legacy_multiline_metadata_retains_nonfirst_socket(address):
    """Keep older multi-line applied previews compatible without plural metadata.

    Args:
        address: Non-first IPv4 or IPv6 listener in retained legacy metadata.
    """
    from atlaso.app import ui
    from atlaso.app.models import VcfPrivateRegistrySettings
    from atlaso.app.services.vcf_private_registry import render_harbor_config

    preview = render_harbor_config(VcfPrivateRegistrySettings(
        enabled=True, hostname="registry.example.test", port=8445, listen_interface="eth1",
        listen_address="192.0.2.10\n" + address))
    preview = "\n".join(line for line in preview.splitlines() if not line.startswith("atlaso_listen_addresses:"))
    units = {"public_services": {"context": {"reverse_proxies": [{"enabled": True, "port": 8445,
             "listeners": [{"address": address}]}]}}, "vcf_private_registry": {"changed": True}}
    assert ui.proxy_socket_release_dependencies(units, {"vcf_private_registry": {"config_preview": preview}}) == {"vcf_private_registry"}
