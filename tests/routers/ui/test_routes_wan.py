"""Test Routes/WAN management UI transport behavior."""

import re
from pathlib import Path

from tests.routers.ui.helpers import assert_apply_redirect, login


def test_routes_wan_policy_form_renders(client):
    """Verify that routes wan policy form renders.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    response = client.get("/routes-wan")
    assert response.status_code == 200
    assert "Routes &amp; WAN Simulation" in response.text
    assert ">Static Routes</button>" in response.text
    assert ">Routing Permissions</button>" in response.text
    assert "Static routes choose a destination path" in response.text
    assert "Routing permissions control forwarding" in response.text
    assert "Routing Permissions" in response.text
    assert "NAT Rules" in response.text
    assert "WAN Policies" in response.text
    assert "Routes &amp; WAN Simulation has pending appliance changes" in response.text
    assert "Validation" in response.text
    assert "routes-wan-routes-table" in response.text
    assert "routes-wan-routing-table" in response.text
    assert "routes-wan-nat-table" in response.text
    assert "routes-wan-policies-table" in response.text
    assert "auto route-role" in response.text
    assert "explicit access" in response.text
    assert "management isolated" in response.text
    assert "No automatic route-role paths" in response.text
    assert "data-mode-options" not in response.text
    assert "<th>Mode</th>" not in response.text
    app_js = client.get("/static/app.js").text
    assert "+ Add static route here" in app_js
    assert "+ Add routing permission here" in app_js
    assert "+ Add NAT rule here" in app_js
    assert "+ Add WAN policy here" in app_js
    assert "autoSaveWanRoute" not in app_js
    assert "autoSaveWanRoutingRule" not in app_js
    assert "autoSaveWanNatRule" not in app_js
    assert "autoSaveWanPolicy" not in app_js
    assert app_js.count("window.AtlasoUiPatterns.createWizard({") >= 4
    for dialog_id in (
        "routes-wan-route-dialog",
        "routes-wan-routing-dialog",
        "routes-wan-nat-dialog",
        "routes-wan-policy-dialog",
    ):
        assert f'id="{dialog_id}"' in response.text
    assert response.text.count("data-routes-wan-wizard=") == 4
    assert len(re.findall(r"<form\b[^>]*\bdata-atlaso-wizard(?:\s|>)", response.text)) == 4
    assert response.text.count('class="vcf-sddc-wizard-rail"') >= 4
    assert response.text.count('class="vcf-sddc-wizard-main"') >= 4
    routes_template = Path("atlaso/app/templates/routes_wan.html").read_text(encoding="utf-8")
    assert routes_template.count("resource_wizard(") == 4
    assert "vcf-sddc-wizard-layout" not in routes_template
    assert "confirm-modal-head" not in routes_template
    assert 'data-routes-wan-nat-source-mode' in response.text
    assert 'data-routes-wan-default-route' in response.text
    assert 'data-routes-wan-default-family' in response.text
    assert '<span>IP family</span>' in response.text
    assert 'type="radio" name="default_route_family" value="4"' in response.text
    assert 'type="radio" name="default_route_family" value="6"' in response.text
    assert "Default route family" not in response.text
    assert 'class="form-grid route-path-choice-grid"' in response.text
    assert ".route-family-field[hidden]" in client.get("/static/app.css").text
    assert 'name="destination_cidr" required' in response.text
    assert 'value="IPv4 masquerade" readonly' in response.text
    assert "Europe WAN" in response.text
    assert "SiteA outbound WAN" in response.text
    assert "eth1.20" in response.text
    assert "Routing &amp; WAN Settings" in response.text
    assert 'action="/ui/management/routes-wan/settings"' in response.text
    assert '[feature_settings]' in response.text
    assert "routing_enabled=false" in response.text
    assert "tc qdisc del" in response.text
    assert "table ip atlaso_nat" in response.text
    assert "Review appliance changes" in response.text


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
    refreshed = client.get("/routes-wan")
    assert "Suspended until Routing is enabled." in refreshed.text
    assert 'name="nat_enabled" aria-label="NAT enabled" checked disabled' in refreshed.text
    assert 'name="nat_enabled" value="on" data-routes-wan-nat-fallback' in refreshed.text

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
    assert page.text.count('data-can-write="false"') == 4
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
    assert "Choose an access physical interface" in nat_response.text
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

    login(client)
    page = client.get("/routes-wan")
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
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
            "enabled": "on",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert routing_response.status_code == 303
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
    assert "Metro outbound" in refreshed.text
    assert "SiteA to WAN" in refreshed.text
    assert "Default route" in refreshed.text
    assert "0.0.0.0/0" in refreshed.text
    assert "ip saddr 192.168.50.0/24 oifname &#34;eth2&#34; masquerade" in refreshed.text
    assert "ip rule add from 192.168.50.0/24 table 200" in refreshed.text
    assert "tc qdisc replace dev eth1.20" in refreshed.text
    with SessionLocal() as db:
        rule = db.execute(select(NatRule).where(NatRule.name == "Metro outbound")).scalar_one()
        assert rule.outbound_interface == "eth2"
        routing = db.execute(select(RoutingRule).where(RoutingRule.name == "SiteA to WAN")).scalar_one()
        assert routing.source_interface == "eth1.20"

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "wan"})
    assert_apply_redirect(apply_response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert job.status == "succeeded"
        assert "atlaso-helper" in (job.result or "")
        assert "wan" in (job.result or "")
        assert "NAT rules" in (job.result or "")
        assert "explicit routing rules" in (job.result or "")
        assert "nft -f /etc/atlaso/nftables.d/atlaso-nat.nft" in (job.result or "")
        assert "ip rule add from 192.168.50.0/24 table 200" in (job.result or "")
        assert "ip route replace 0.0.0.0/0 via 192.168.20.254 dev eth1.20 metric 120 table 200" in (job.result or "")
        assert "tc qdisc replace dev eth1.20" in (job.result or "")
