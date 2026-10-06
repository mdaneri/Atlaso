"""Test Routes/WAN management UI transport behavior."""

import re
from pathlib import Path

import pytest

from tests.routers.ui.helpers import assert_apply_redirect, login


@pytest.mark.parametrize("drift", ["missing", "family"])
def test_ui_can_disable_a_stale_routing_permission(client, drift):
    """The Enabled transport retains a stale rule instead of forcing its deletion.

    Args:
        client: Isolated application client.
        drift: Missing interface or missing selected address family.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface, RoutingRule

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        row = RoutingRule(name="Stale UI denial", enabled=True, source_interface="eth2",
                          destination_interface="eth1.20", policy="deny", ip_family=4)
        db.add(row)
        db.flush()
        rule_id = row.id
        source = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        if drift == "missing":
            source.oper_state = "missing"
        else:
            source.ip_cidr = ""
            source.ipv6_cidr = "2001:db8:50::1/64"
        db.commit()
    data = {"name": "Stale UI denial", "source_interface": "eth2", "destination_interface": "eth1.20",
            "policy": "deny", "ip_family": "4", "priority": "100", "csrf": csrf}
    path = f"/routes-wan/routing-rules/{rule_id}/edit"
    assert client.post(path, data={**data, "enabled": "on"}, follow_redirects=False).status_code == 422
    response = client.post(path, data=data, follow_redirects=False)
    assert response.status_code == 303, response.text
    with SessionLocal() as db:
        row = db.get(RoutingRule, rule_id)
        assert row.enabled is False
        assert (row.policy, row.ip_family, row.source_interface, row.destination_interface) == ("deny", 4, "eth2", "eth1.20")


def test_routes_wan_policy_form_renders(client):
    """Verify that routes wan policy form renders.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    response = client.get("/routes-wan")
    assert response.status_code == 200
    assert "Routing &amp; WAN" in response.text
    nat_page = client.get("/traffic-publishing")
    assert nat_page.status_code == 200
    assert "routes-wan-nat-table" not in response.text
    assert ">Static Routes</button>" in response.text
    assert ">Routing Permissions</button>" in response.text
    assert "Static routes choose a destination path" in response.text
    assert "Routing permissions control forwarding" in response.text
    assert "Routing Permissions" in response.text
    assert 'data-nat-inbound-editor' in nat_page.text
    assert 'data-tag-name="inbound_interfaces"' in nat_page.text
    assert 'name="inbound_interfaces" multiple' not in response.text
    assert "Source NAT" in nat_page.text
    assert "WAN Policies" in response.text
    assert "Routing &amp; WAN has pending appliance changes" in response.text
    assert "Validation" in response.text
    assert "routes-wan-routes-table" in response.text
    assert "routes-wan-routing-table" in response.text
    assert "routes-wan-nat-table" in nat_page.text
    assert "routes-wan-policies-table" in response.text
    assert "auto route-role" in response.text
    assert "explicit policies" in response.text
    assert "management isolated" in response.text
    assert "No automatic route-role paths" in response.text
    assert "data-mode-options" not in response.text
    assert "<th>Mode</th>" not in response.text
    app_js = client.get("/static/app.js").text
    assert "+ Add static route here" in app_js
    assert "+ Add routing permission here" in app_js
    assert "+ Add NAT rule here" in app_js
    assert "+ Add WAN policy here" in app_js
    assert 'name="policy"' in response.text
    assert 'name="ip_family"' in response.text
    assert "Override routing permission" in app_js
    assert "Override routing permission" in Path("atlaso/app/templates/routes_wan.html").read_text(encoding="utf-8")
    assert "effective_action" in app_js
    assert "apply_state" in app_js
    assert 'await postWanAction(managementUiPath(`${path}/${data.id}/edit`), data, csrf, { reload: false })' in app_js
    assert "autoSaveWanRoute" not in app_js
    assert "autoSaveWanRoutingRule" not in app_js
    assert "autoSaveWanNatRule" not in app_js
    assert "autoSaveWanPolicy" not in app_js
    assert app_js.count("window.AtlasoUiPatterns.createWizard({") >= 4
    for dialog_id in (
        "routes-wan-route-dialog",
        "routes-wan-routing-dialog",
        "routes-wan-policy-dialog",
    ):
        assert f'id="{dialog_id}"' in response.text
    assert 'id="routes-wan-nat-dialog"' in nat_page.text
    assert response.text.count("data-routes-wan-wizard=") == 3
    assert len(re.findall(r"<form\b[^>]*\bdata-atlaso-wizard(?:\s|>)", response.text)) == 3
    assert response.text.count('class="vcf-sddc-wizard-rail"') >= 3
    assert response.text.count('class="vcf-sddc-wizard-main"') >= 3
    routes_template = Path("atlaso/app/templates/routes_wan.html").read_text(encoding="utf-8")
    assert routes_template.count("resource_wizard(") == 3
    assert "vcf-sddc-wizard-layout" not in routes_template
    assert "confirm-modal-head" not in routes_template
    assert 'data-routes-wan-nat-source-mode' in nat_page.text
    assert 'data-routes-wan-default-route' in response.text
    assert 'data-routes-wan-default-family' in response.text
    assert '<span>IP family</span>' in response.text
    assert 'type="radio" name="default_route_family" value="4"' in response.text
    assert 'type="radio" name="default_route_family" value="6"' in response.text
    assert "Default route family" not in response.text
    assert 'class="form-grid route-path-choice-grid"' in response.text
    assert ".route-family-field[hidden]" in client.get("/static/app.css").text
    assert 'name="destination_cidr" required' in response.text
    assert 'name="ip_family"' in nat_page.text
    assert 'name="translation_mode"' in nat_page.text
    assert 'name="translated_address"' in nat_page.text
    assert "Europe WAN" in response.text
    assert "SiteA outbound WAN" in nat_page.text
    assert "eth1.20" in response.text
    assert "Routing &amp; WAN Settings" in response.text
    assert 'action="/ui/management/routes-wan/settings"' in response.text
    assert '<noscript><button class="button primary" type="submit">Save Routing &amp; WAN settings</button></noscript>' in response.text
    assert '[feature_settings]' in response.text
    assert "routing_enabled=false" in response.text
    assert "tc qdisc del" in response.text
    assert "[nat_rules]" in nat_page.text
    assert "Review appliance changes" in response.text


def test_routes_wan_generated_routing_permissions_offer_wizard_override(client):
    """Generated route-role paths remain read-only and expose the existing override wizard.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        db.add_all(
            [
                PhysicalInterface(
                    name="route855a",
                    mac_address="00:50:56:aa:85:5a",
                    mode="access",
                    role="route",
                    ip_cidr="192.0.2.1/24",
                    ipv6_cidr="",
                    admin_state="up",
                    oper_state="up",
                ),
                PhysicalInterface(
                    name="route855b",
                    mac_address="00:50:56:aa:85:5b",
                    mode="access",
                    role="route",
                    ip_cidr="198.51.100.1/24",
                    ipv6_cidr="",
                    admin_state="up",
                    oper_state="up",
                ),
            ]
        )
        db.commit()

    login(client)
    response = client.get("/routes-wan")

    assert response.status_code == 200
    assert "route855a to route855b" in response.text
    assert 'data-routes-wan-wizard-open="routing" data-routes-wan-override="true"' in response.text
    assert 'data-routes-wan-source="route855a" data-routes-wan-destination="route855b"' in response.text
    assert "Override routing permission" in response.text


def test_routing_permission_browser_names_match_apply_uniqueness(client):
    """Create and edit reject case-only collisions without changing saved intent.

    Args:
        client: Isolated browser client.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import RoutingRule

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    path = "/routes-wan/routing-rules"
    payload = {
        "name": "Lab path", "source_interface": "eth2", "destination_interface": "eth1.20",
        "policy": "deny", "ip_family": "4", "priority": "100", "enabled": "on", "csrf": csrf,
    }
    created = client.post(path, data=payload, follow_redirects=False)
    assert created.status_code == 303, created.text
    duplicate = client.post(path, data={**payload, "name": "lab PATH"}, follow_redirects=False)
    assert duplicate.status_code == 409, duplicate.text
    line_break = client.post(path, data={**payload, "name": "reviewed\nrouting=Injected"}, follow_redirects=False)
    assert line_break.status_code == 422, line_break.text
    with SessionLocal() as db:
        row = db.scalar(select(RoutingRule).where(RoutingRule.name == "Lab path"))
        assert row is not None
        rule_id = row.id

    self_rename = client.post(f"{path}/{rule_id}/edit", data={**payload, "name": "lAb PaTh"}, follow_redirects=False)
    assert self_rename.status_code == 303, self_rename.text
    other = client.post(path, data={**payload, "name": "Other path"}, follow_redirects=False)
    assert other.status_code == 303, other.text
    collision = client.post(f"{path}/{rule_id}/edit", data={**payload, "name": "other PATH"}, follow_redirects=False)
    assert collision.status_code == 409, collision.text
    with SessionLocal() as db:
        assert [rule.name for rule in db.scalars(select(RoutingRule).order_by(RoutingRule.id))] == ["lAb PaTh", "Other path"]


@pytest.mark.parametrize("operation", ["create", "edit", "delete"])
@pytest.mark.parametrize("failure_point", ["rule_flush", "audit_insert"])
def test_routing_permission_mutations_roll_back_with_persistence_failures(client, monkeypatch, operation, failure_point):
    """Keep each permission mutation atomic when the rule or audit insert fails.

    Args:
        client: Isolated browser client.
        monkeypatch: Fixture replacing the database flush for failure injection.
        operation: Permission mutation exercised by this case.
        failure_point: Whether the rule flush or real database audit insert fails.
    """
    from sqlalchemy import select, text
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import Session

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, RoutingRule

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    rule_id = None
    if operation != "create":
        with SessionLocal() as db:
            rule = RoutingRule(
                name="Atomic permission",
                source_interface="eth2",
                destination_interface="eth1.20",
                policy="deny",
                ip_family=4,
                enabled=True,
                description="before mutation",
            )
            db.add(rule)
            db.commit()
            rule_id = rule.id

    action = {
        "create": "create_routing_rule",
        "edit": "update_routing_rule",
        "delete": "delete_routing_rule",
    }[operation]
    payload = {
        "name": "Atomic permission updated",
        "source_interface": "eth1.20" if operation == "edit" else "eth2",
        "destination_interface": "eth2" if operation == "edit" else "eth1.20",
        "priority": "120",
        "policy": "allow",
        "ip_family": "4",
        "description": "after mutation",
        "enabled": "on",
        "csrf": csrf,
    }
    if operation == "edit":
        payload.pop("enabled")
    paths = {
        "create": "/routes-wan/routing-rules",
        "edit": f"/routes-wan/routing-rules/{rule_id}/edit",
        "delete": f"/routes-wan/routing-rules/{rule_id}/delete",
    }

    trigger_name = "fail_routing_rule_audit_insert"
    if failure_point == "rule_flush":
        original_flush = Session.flush

        def fail_routing_rule_flush(session, *args, **kwargs):
            """Reject permission writes while allowing unrelated session flushes.

            Args:
                session: Database session whose pending objects are inspected.
                *args: Positional arguments forwarded to the original flush.
                **kwargs: Keyword arguments forwarded to the original flush.
            """
            if any(isinstance(row, RoutingRule) for row in session.new | session.dirty | session.deleted):
                raise RuntimeError("injected routing rule flush failure")
            return original_flush(session, *args, **kwargs)

        monkeypatch.setattr(Session, "flush", fail_routing_rule_flush)
    else:
        with SessionLocal() as db:
            db.execute(
                text(
                    f"CREATE TRIGGER {trigger_name} BEFORE INSERT ON audit_events "
                    f"WHEN NEW.action = '{action}' BEGIN "
                    "SELECT RAISE(ABORT, 'injected audit insert failure'); END"
                )
            )
            db.commit()
    try:
        expected_error = RuntimeError if failure_point == "rule_flush" else IntegrityError
        with pytest.raises(expected_error):
            client.post(paths[operation], data=payload, follow_redirects=False)
    finally:
        if failure_point == "audit_insert":
            with SessionLocal() as db:
                db.execute(text(f"DROP TRIGGER IF EXISTS {trigger_name}"))
                db.commit()

    with SessionLocal() as db:
        rule = db.get(RoutingRule, rule_id) if rule_id is not None else None
        if operation == "create":
            assert rule is None
            assert db.scalar(select(RoutingRule).where(RoutingRule.name == payload["name"])) is None
        elif operation == "delete":
            assert rule is not None
            assert (
                rule.name,
                rule.source_interface,
                rule.destination_interface,
                rule.priority,
                rule.policy,
                rule.ip_family,
                rule.enabled,
                rule.description,
            ) == (
                "Atomic permission", "eth2", "eth1.20", 100, "deny", 4, True, "before mutation"
            )
        else:
            assert rule is not None
            assert (
                rule.name,
                rule.source_interface,
                rule.destination_interface,
                rule.priority,
                rule.policy,
                rule.ip_family,
                rule.enabled,
                rule.description,
            ) == (
                "Atomic permission", "eth2", "eth1.20", 100, "deny", 4, True, "before mutation"
            )
        assert db.scalars(
            select(AuditEvent).where(
                AuditEvent.resource_type == "routing_rule",
                AuditEvent.action == action,
            )
        ).all() == []


def test_routing_permission_mutations_commit_with_audit_events(client):
    """Persist each routing permission change with its action and resource ID audit.

    Args:
        client: Isolated browser client.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import AuditEvent, RoutingRule

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    base_payload = {
        "name": "Atomic permission",
        "source_interface": "eth2",
        "destination_interface": "eth1.20",
        "priority": "100",
        "policy": "deny",
        "ip_family": "4",
        "description": "initial policy",
        "enabled": "on",
        "csrf": csrf,
    }

    created = client.post("/routes-wan/routing-rules", data=base_payload, follow_redirects=False)
    assert created.status_code == 303
    assert created.headers["location"] == "/ui/management/routes-wan"
    with SessionLocal() as db:
        rule = db.scalar(select(RoutingRule).where(RoutingRule.name == base_payload["name"]))
        assert rule is not None
        rule_id = rule.id
        create_event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.resource_type == "routing_rule",
                AuditEvent.action == "create_routing_rule",
            )
        )
        assert create_event is not None
        assert create_event.id is not None
        assert create_event.resource_id == str(rule_id)

    edited = client.post(
        f"/routes-wan/routing-rules/{rule_id}/edit",
        data={**base_payload, "policy": "allow", "ip_family": "4", "description": "updated policy"},
        follow_redirects=False,
    )
    assert edited.status_code == 303
    assert edited.headers["location"] == "/ui/management/routes-wan"
    with SessionLocal() as db:
        rule = db.get(RoutingRule, rule_id)
        assert rule is not None
        assert (rule.policy, rule.ip_family, rule.description) == ("allow", 4, "updated policy")
        edit_event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.resource_type == "routing_rule",
                AuditEvent.action == "update_routing_rule",
            )
        )
        assert edit_event is not None
        assert edit_event.id is not None
        assert edit_event.resource_id == str(rule_id)

    deleted = client.post(
        f"/routes-wan/routing-rules/{rule_id}/delete",
        data={"csrf": csrf},
        follow_redirects=False,
    )
    assert deleted.status_code == 303
    assert deleted.headers["location"] == "/ui/management/routes-wan"
    with SessionLocal() as db:
        assert db.get(RoutingRule, rule_id) is None
        delete_event = db.scalar(
            select(AuditEvent).where(
                AuditEvent.resource_type == "routing_rule",
                AuditEvent.action == "delete_routing_rule",
            )
        )
        assert delete_event is not None
        assert delete_event.id is not None
        assert delete_event.resource_id == str(rule_id)


def test_routes_wan_settings_autosave_reports_suspended_nat(client):
    """Autosave global settings and expose NAT's effective suspended state.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    enabled_response = client.post(
        "/routes-wan/settings",
        headers={"X-Atlaso-Autosave": "1"},
        data={"routing_enabled": "on", "nat_enabled": "on", "csrf": csrf},
    )
    assert enabled_response.status_code == 200, enabled_response.text

    response = client.post(
        "/routes-wan/settings",
        headers={"X-Atlaso-Autosave": "1"},
        data={"csrf": csrf},
    )

    assert response.status_code == 200, response.text
    assert response.json()["nat_enabled"] is True
    assert response.json()["effective_nat_enabled"] is False
    assert response.json()["feature_status"]["routing"] == "disabled"
    assert response.json()["feature_status"]["nat"] == "suspended"
    refreshed = client.get("/traffic-publishing")
    assert "NAT is suspended until Routing is enabled." in refreshed.text
    assert 'name="nat_enabled" checked' in refreshed.text

    simulation_response = client.post(
        "/routes-wan/settings",
        headers={"X-Atlaso-Autosave": "1"},
        data={"wan_simulation_enabled": "on", "csrf": csrf},
    )
    assert simulation_response.status_code == 200, simulation_response.text
    assert simulation_response.json()["nat_enabled"] is True
    assert simulation_response.json()["effective_nat_enabled"] is False
    assert simulation_response.json()["wan_simulation_enabled"] is True

    no_javascript_enable = client.post(
        "/routes-wan/settings",
        data={
            "routing_enabled": "on",
            "nat_enabled": "on",
            "wan_simulation_enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert no_javascript_enable.status_code == 303

    from atlaso.app.database import SessionLocal
    from atlaso.app.services.routes_wan import ensure_routes_wan_settings

    with SessionLocal() as db:
        settings = ensure_routes_wan_settings(db)
        assert settings.routing_enabled is True
        assert settings.nat_enabled is True
        assert settings.effective_nat_enabled is True

    simultaneous_disable = client.post(
        "/routes-wan/settings",
        headers={"X-Atlaso-Autosave": "1"},
        data={
            "nat_enabled": "off",
            "wan_simulation_enabled": "on",
            "csrf": csrf,
        },
    )
    assert simultaneous_disable.status_code == 200
    assert simultaneous_disable.json()["routing_enabled"] is False
    assert simultaneous_disable.json()["nat_enabled"] is False
    assert simultaneous_disable.json()["effective_nat_enabled"] is False


def test_routes_wan_settings_autosave_preserves_unconfigured_routing_service(client):
    """Keep restored Routing runtime state unchanged until Appliance Apply.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ServiceState

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "routing")
        ).scalar_one()
        service.enabled = False
        service.running = False
        service.health = "unconfigured"
        db.commit()

    response = client.post(
        "/routes-wan/settings",
        headers={"X-Atlaso-Autosave": "1"},
        data={
            "routing_enabled": "on",
            "nat_enabled": "on",
            "wan_simulation_enabled": "on",
            "csrf": csrf,
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["routing_enabled"] is True
    with SessionLocal() as db:
        service = db.execute(
            select(ServiceState).where(ServiceState.service == "routing")
        ).scalar_one()
        assert service.enabled is False
        assert service.running is False
        assert service.health == "unconfigured"


def test_routes_wan_default_route_add_edit_validation_and_semantic_readback(client):
    """Exercise the explicit default path and its server-owned invariants.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Route

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    base = {
        "destination_cidr": "",
        "interface_name": "eth1.20",
        "metric": "90",
        "wan_policy_id": "",
        "wan_mode": "interface",
        "default_route": "on",
        "default_route_family": "4",
        "enabled": "on",
        "csrf": csrf,
    }

    missing = client.post("/routes-wan/routes", data={**base, "gateway": ""}, follow_redirects=False)
    assert missing.status_code == 422
    assert "requires a gateway" in missing.text

    mismatch = client.post(
        "/routes-wan/routes",
        data={**base, "gateway": "2001:db8::1"},
        follow_redirects=False,
    )
    assert mismatch.status_code == 422
    assert "family must match" in mismatch.text

    conflicting_input = client.post(
        "/routes-wan/routes",
        data={**base, "destination_cidr": "10.0.0.0/8", "gateway": "192.0.2.1"},
        follow_redirects=False,
    )
    assert conflicting_input.status_code == 422
    assert "mutually exclusive" in conflicting_input.text

    manual_default = client.post(
        "/routes-wan/routes",
        data={
            **base,
            "default_route": "",
            "destination_cidr": "0.0.0.0/0",
            "gateway": "192.0.2.1",
        },
        follow_redirects=False,
    )
    assert manual_default.status_code == 422
    assert "Select Default route" in manual_default.text

    invalid_target = client.post(
        "/routes-wan/routes",
        data={**base, "gateway": "192.0.2.1", "interface_name": "eth0"},
        follow_redirects=False,
    )
    assert invalid_target.status_code == 422
    assert "Choose an access physical interface" in invalid_target.text

    off_link = client.post(
        "/routes-wan/routes",
        data={**base, "gateway": "198.51.100.1"},
        follow_redirects=False,
    )
    assert off_link.status_code == 422
    assert "is not on-link" in off_link.text

    created = client.post(
        "/routes-wan/routes",
        data={**base, "gateway": "192.168.20.254"},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with SessionLocal() as db:
        route = db.execute(select(Route).where(Route.destination_cidr == "0.0.0.0/0")).scalar_one()
        route_id = route.id
        assert route.gateway == "192.168.20.254"

    readback = client.get("/routes-wan")
    assert "Default route (IPv4)" in readback.text
    assert "0.0.0.0/0" in readback.text

    inline_disabled = client.post(
        f"/routes-wan/routes/{route_id}/edit",
        data={**base, "default_route": "true", "gateway": "192.168.20.254", "enabled": ""},
        follow_redirects=False,
    )
    assert inline_disabled.status_code == 303
    with SessionLocal() as db:
        route = db.get(Route, route_id)
        assert route is not None
        assert route.destination_cidr == "0.0.0.0/0"
        assert route.enabled is False

    duplicate = client.post(
        "/routes-wan/routes",
        data={**base, "gateway": "192.168.20.253"},
        follow_redirects=False,
    )
    assert duplicate.status_code == 422
    assert "Only one IPv4 default route" in duplicate.text

    target_mismatch = client.post(
        f"/routes-wan/routes/{route_id}/edit",
        data={**base, "default_route_family": "6", "gateway": "2001:db8::1"},
        follow_redirects=False,
    )
    assert target_mismatch.status_code == 422
    assert "does not have a configured IPv6 CIDR" in target_mismatch.text

    from atlaso.app.models import VlanInterface

    with SessionLocal() as db:
        target = db.execute(select(VlanInterface).where(VlanInterface.name == "eth1.20")).scalar_one()
        target.ipv6_cidr = "2001:db8:20::1/64"
        db.commit()

    updated = client.post(
        f"/routes-wan/routes/{route_id}/edit",
        data={**base, "default_route_family": "6", "gateway": "fe80::1"},
        follow_redirects=False,
    )
    assert updated.status_code == 303
    with SessionLocal() as db:
        route = db.get(Route, route_id)
        assert route is not None
        assert route.destination_cidr == "::/0"
        assert route.gateway == "fe80::1"


def test_routes_wan_rejects_route_wan_mode(client):
    """Verify that routes wan rejects route wan mode.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "10.21.0.0/24",
            "gateway": "",
            "interface_name": "eth1.20",
            "metric": "120",
            "wan_policy_id": "",
            "wan_mode": "route",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert response.status_code == 422
    assert "planned but not supported in v1" in response.text


def test_routes_wan_wizards_respect_read_only_permissions(client):
    """Verify that Routes and WAN wizard mutations are hidden from read-only users.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Role, User
    from atlaso.app.security import roles_to_json

    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.role = Role.VIEWER.value
        admin.roles_json = roles_to_json([Role.VIEWER.value])
        db.commit()

    login(client)
    page = client.get("/routes-wan")

    assert page.status_code == 200
    assert page.text.count('data-can-write="false"') == 3
    assert 'data-routes-wan-wizard=' not in page.text
    assert 'id="routes-wan-route-dialog"' not in page.text
    assert 'id="routes-wan-routing-dialog"' not in page.text
    assert 'id="routes-wan-nat-dialog"' not in page.text
    assert 'id="routes-wan-policy-dialog"' not in page.text
    assert 'name="routing_enabled"' in page.text
    assert 'name="routing_enabled" aria-label="Routing enabled"  disabled' in page.text
    assert "Read-only state. Routes and WAN write permissions are required" in page.text
    assert "data-autosave-status-id=\"routes-wan-settings-autosave-status\"" not in page.text


def test_routes_wan_allows_ipv6_only_route_targets_but_not_nat_targets(client):
    """Verify that routes wan allows ipv6 only route targets but not nat targets.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NatRule, PhysicalInterface, Route

    with SessionLocal() as db:
        db.add(
            PhysicalInterface(
                name="eth6",
                mac_address="00:50:56:aa:bb:66",
                mode="access",
                role="access",
                ip_cidr="",
                ipv6_cidr="fd00:66::1/64",
                admin_state="up",
                oper_state="up",
            )
        )
        db.commit()

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    route_response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "2001:db8:66::/64",
            "gateway": "",
            "interface_name": "eth6",
            "metric": "120",
            "wan_policy_id": "",
            "wan_mode": "interface",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    nat_response = client.post(
        "/routes-wan/nat-rules",
        data={
            "name": "IPv6-only outbound",
            "inbound_interfaces": ["eth2"],
            "source": "192.168.50.0/24",
            "outbound_interface": "eth6",
            "masquerade": "on",
            "priority": "110",
            "description": "",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )

    assert route_response.status_code == 303
    assert nat_response.status_code == 422
    assert "IPv4 interface or VLAN" in nat_response.text
    mgmt_route_response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "10.49.0.0/24",
            "gateway": "",
            "interface_name": "eth0",
            "metric": "100",
            "wan_policy_id": "",
            "wan_mode": "interface",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert mgmt_route_response.status_code == 422
    assert "Choose an access physical interface" in mgmt_route_response.text
    with SessionLocal() as db:
        route = db.execute(select(Route).where(Route.interface_name == "eth6")).scalar_one()
        assert route.destination_cidr == "2001:db8:66::/64"
        assert db.execute(select(NatRule).where(NatRule.outbound_interface == "eth6")).scalar_one_or_none() is None


def test_routes_wan_autosave_endpoints_and_apply_task(client):
    """Verify that routes wan autosave endpoints and apply task.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job, NatRule, RoutingRule, WanPolicy
    from atlaso.app.ui import appliance_apply_units, update_appliance_apply_baselines

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    with SessionLocal() as db:
        initial_units = appliance_apply_units(db)
        update_appliance_apply_baselines(db, initial_units, {unit["id"] for unit in initial_units})
        db.commit()
    settings_response = client.post(
        "/routes-wan/settings",
        headers={"X-Atlaso-Autosave": "1"},
        data={
            "routing_enabled": "on",
            "nat_enabled": "on",
            "wan_simulation_enabled": "on",
            "csrf": csrf,
        },
    )
    assert settings_response.status_code == 200
    assert settings_response.json()["effective_nat_enabled"] is True
    policy_response = client.post(
        "/routes-wan/policies",
        data={
            "name": "Metro WAN",
            "description": "short metro impairment",
            "latency_ms": "35",
            "jitter_ms": "5",
            "packet_loss_percent": "0.1",
            "bandwidth_mbit": "250",
            "corrupt_percent": "0",
            "duplicate_percent": "0",
            "reorder_percent": "0",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert policy_response.status_code == 303
    with SessionLocal() as db:
        policy = db.execute(select(WanPolicy).where(WanPolicy.name == "Metro WAN")).scalar_one()
        policy_id = str(policy.id)

    route_response = client.post(
        "/routes-wan/routes",
        data={
            "destination_cidr": "",
            "default_route": "on",
            "default_route_family": "4",
            "gateway": "192.168.20.254",
            "interface_name": "eth1.20",
            "metric": "120",
            "wan_policy_id": policy_id,
            "wan_mode": "interface",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert route_response.status_code == 303
    nat_response = client.post(
        "/routes-wan/nat-rules",
        data={
            "name": "Metro outbound",
            "source": "192.168.50.0/24",
            "outbound_interface": "eth2",
            "masquerade": "on",
            "priority": "110",
            "description": "NAT through test WAN",
            "inbound_interfaces": ["eth1.20"],
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert nat_response.status_code == 303
    routing_response = client.post(
        "/routes-wan/routing-rules",
        data={
            "name": "SiteA to WAN",
            "source_interface": "eth1.20",
            "destination_interface": "eth2",
            "priority": "120",
            "description": "Allow SiteA toward WAN link",
            "policy": "deny",
            "ip_family": "4",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert routing_response.status_code == 303
    with SessionLocal() as db:
        routing = db.execute(select(RoutingRule).where(RoutingRule.name == "SiteA to WAN")).scalar_one()
        routing_id = routing.id
        assert routing.policy == "deny"
        assert routing.ip_family == 4

    routing_edit_response = client.post(
        f"/routes-wan/routing-rules/{routing_id}/edit",
        data={
            "name": "SiteA to WAN",
            "source_interface": "eth1.20",
            "destination_interface": "eth2",
            "priority": "120",
            "description": "Allow SiteA toward WAN link",
            "policy": "automatic",
            "ip_family": "0",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert routing_edit_response.status_code == 303
    with SessionLocal() as db:
        routing = db.execute(select(RoutingRule).where(RoutingRule.id == routing_id)).scalar_one()
        assert routing.policy == "automatic"
        assert routing.ip_family == 0
        assert db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one_or_none() is None
    management_routing_response = client.post(
        "/routes-wan/routing-rules",
        data={
            "name": "Bad management route",
            "source_interface": "eth1.20",
            "destination_interface": "eth0",
            "priority": "120",
            "description": "",
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert management_routing_response.status_code == 422
    assert "non-management destination" in management_routing_response.text
    refreshed = client.get("/routes-wan")
    assert "Metro WAN" in refreshed.text
    nat_page = client.get("/traffic-publishing")
    assert "Metro outbound" in nat_page.text
    assert "SiteA to WAN" in refreshed.text
    assert "Default route" in refreshed.text
    assert "0.0.0.0/0" in refreshed.text
    assert "source_resolved=192.168.50.0/24" in nat_page.text
    assert "ip rule add iif eth1.20 table 200" in refreshed.text
    assert "ip rule add from 192.168.50.0/24 table 200" not in refreshed.text
    assert "tc qdisc replace dev eth1.20" in refreshed.text
    with SessionLocal() as db:
        rule = db.execute(select(NatRule).where(NatRule.name == "Metro outbound")).scalar_one()
        assert rule.outbound_interface == "eth2"
        routing = db.execute(select(RoutingRule).where(RoutingRule.name == "SiteA to WAN")).scalar_one()
        assert routing.source_interface == "eth1.20"
        assert routing.policy == "automatic"
        assert routing.ip_family == 0

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "wan"})
    assert_apply_redirect(apply_response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "wan" in (job.result or "")
        assert "NAT rules" in (job.result or "")
        assert "explicit routing rules" in (job.result or "")
        assert '"unit_id": "nat"' in (job.result or "")
        assert "ip rule add iif eth1.20 table 200" in (job.result or "")
        assert "ip rule add from 192.168.50.0/24 table 200" not in (job.result or "")
        assert "ip route replace 0.0.0.0/0 via 192.168.20.254 dev eth1.20 metric 120 table 200" in (job.result or "")
        assert "tc qdisc replace dev eth1.20" in (job.result or "")


def test_disabled_nat_form_always_validates_interface_syntax(client):
    """The form keeps dormant missing identities but rejects unsafe names.

    Args:
        client: HTTP client for exercising the authenticated NAT form.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NatRule

    login(client)
    page = client.get("/routes-wan")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    payload = dict(name="Form syntax control", source="any", inbound_interfaces=["eth2"],
                   outbound_interface="eth1.20", masquerade="on", priority="100", csrf=csrf)
    created = client.post("/routes-wan/nat-rules", data=payload, follow_redirects=False)
    assert created.status_code == 303, created.text
    with SessionLocal() as db:
        rule_id = db.scalar(select(NatRule.id).where(NatRule.name == payload["name"]))
    url = f"/routes-wan/nat-rules/{rule_id}/edit"
    for bad in ["eth2\nfield=value", "eth2\rfield=value", "eth2,eth3", 'eth2"', "a" * 81]:
        for field, value in [("inbound_interfaces", [bad]), ("outbound_interface", bad)]:
            assert client.post(url, data={**payload, field: value}, follow_redirects=False).status_code == 422
    assert client.post(url, data={**payload, "inbound_interfaces": ["missing_155d011d14.22"], "outbound_interface": "missing_155d011d15.20"}, follow_redirects=False).status_code == 303
    with SessionLocal() as db:
        retained = db.get(NatRule, rule_id)
        assert retained.outbound_interface == "missing_155d011d15.20"
        assert retained.inbound_interfaces == ["missing_155d011d14.22"]
        assert retained.enabled is False
