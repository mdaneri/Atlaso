"""Test Firewall management UI transport behavior."""

from tests.routers.ui.helpers import assert_apply_redirect, login


def test_firewall_preview_derives_dns_dhcp_rule_from_dhcp_scope_vlan(client):
    """Verify that firewall preview derives dns dhcp rule from dhcp scope vlan.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    import html
    import json
    import re

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import DhcpScope, DhcpSettings, FirewallRule, VlanInterface

    with SessionLocal() as db:
        dhcp_settings = db.execute(select(DhcpSettings)).scalar_one()
        dhcp_settings.enabled = True
        scope = db.execute(select(DhcpScope).where(DhcpScope.name == "SiteA")).scalar_one()
        scope.interface_name = "eth2.50"
        scope.site_address = "192.168.50.1"
        scope.prefix_length = 24
        scope.enabled = True
        legacy_rule = db.execute(select(FirewallRule).where(FirewallRule.name == "sitea-dns-dhcp")).scalar_one()
        legacy_rule.interface_name = "eth1"
        if db.execute(select(VlanInterface).where(VlanInterface.name == "eth2.50")).scalar_one_or_none() is None:
            db.add(
                VlanInterface(
                    name="eth2.50",
                    parent_interface="eth2",
                    vlan_id=50,
                    ip_cidr="192.168.50.1/24",
                    role="access",
                    enabled=True,
                )
            )
        db.commit()

    login(client)
    firewall = client.get("/firewall")

    assert firewall.status_code == 200
    assert "Managed Service Rules" in firewall.text
    assert "Network Objects" in firewall.text
    assert "Manage source groups" in firewall.text
    assert "data-firewall-validation-refresh" in firewall.text
    assert "source-group-create-form" not in firewall.text
    assert 'data-source-group-select' not in firewall.text
    assert "eth2.50" in firewall.text
    assert "data-interfaces=" in firewall.text
    assert "&#34;eth2.50&#34;" in firewall.text
    assert "data-source-groups=" in firewall.text
    assert "data-groups=" in firewall.text
    editable_payload = re.search(r'id="firewall-rules-table"[^>]+data-rules=\'([^\']*)\'', firewall.text, re.S)
    managed_payload = re.search(r'id="managed-firewall-rules-table"[^>]+data-rules=\'([^\']*)\'', firewall.text, re.S)
    assert editable_payload is not None
    assert managed_payload is not None
    editable_rows = json.loads(html.unescape(editable_payload.group(1)))
    managed_rows = json.loads(html.unescape(managed_payload.group(1)))
    assert not any(row["name"] == "sitea-dns-dhcp" and row["interface_name"] == "eth1" for row in editable_rows)
    assert any(row["name"] == "sitea-dns-dhcp" and row["interface_name"] == "eth1" and row["managed_state"] == "replaced" for row in managed_rows)
    assert any(row["name"] == "sitea-dns-dhcp" and row["interface_name"] == "eth2.50" and row["managed_state"] == "generated" for row in managed_rows)
    assert any(row["name"] == "mgmt-console" and row["managed_state"] == "generated" and row["source_group_id"] == "any" and row["source_group_name"] == "Any" for row in managed_rows)
    generated_index = next(i for i, row in enumerate(managed_rows) if row["name"] == "sitea-dns-dhcp" and row["managed_state"] == "generated")
    replaced_index = next(i for i, row in enumerate(managed_rows) if row["name"] == "sitea-dns-dhcp" and row["managed_state"] == "replaced")
    assert replaced_index == generated_index + 1
    assert 'iifname &#34;eth2.50&#34; udp dport 67 accept comment &#34;sitea-dns-dhcp&#34;' in firewall.text
    assert 'iifname &#34;eth1&#34; ip saddr 192.168.50.0/24 udp dport { 53, 67 } accept comment &#34;sitea-dns-dhcp&#34;' not in firewall.text

    network_objects = client.get("/network-objects")
    assert network_objects.status_code == 200
    assert "Source Groups" in network_objects.text
    assert "network-object-source-groups-table" in network_objects.text
    assert "Any" in network_objects.text
    csrf = network_objects.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]
    group_response = client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "create",
            "group_name": "Managed clients",
            "group_entries": "any",
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert group_response.status_code == 201

    group_response = client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": "custom:managed-clients",
            "group_name": "Managed clients",
            "group_entries": "10.77.0.0/16",
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert group_response.status_code == 200
    assert group_response.json()["status"] == "saved"
    assert group_response.json()["updated_at"]
    assert group_response.json()["source_group"]["entries"] == ["10.77.0.0/16"]

    rename_response = client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": "custom:managed-clients",
            "group_name": "Managed client sources",
            "group_entries": "10.77.0.0/16",
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert rename_response.status_code == 200

    assignment_response = client.post(
        "/firewall/managed-rules/source-group",
        data={"csrf": csrf, "rule_name": "mgmt-console", "source_group_id": "custom:managed-clients"},
    )
    assert assignment_response.status_code == 200

    rule_response = client.post(
        "/firewall/rules",
        data={
            "csrf": csrf,
            "name": "grouped-custom",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "group:custom:managed-clients",
            "destination": "group:custom:managed-clients",
            "destination_port": "443",
            "interface_name": "eth2.50",
            "priority": "101",
            "enabled": "on",
        },
    )
    assert rule_response.status_code == 200

    updated_firewall = client.get("/firewall")
    assert "Managed client sources" in updated_firewall.text
    updated_network_objects = client.get("/network-objects")
    assert "10.77.0.0/16" in updated_network_objects.text
    assert "Managed client sources" in updated_network_objects.text
    assert 'iifname &#34;eth0&#34; ip saddr 10.77.0.0/16 tcp dport { 22, 80, 443 } accept comment &#34;mgmt-console&#34;' in updated_firewall.text
    assert 'iifname &#34;eth2.50&#34; ip saddr 10.77.0.0/16 ip daddr 10.77.0.0/16 tcp dport 443 accept comment &#34;grouped-custom&#34;' in updated_firewall.text
    assert 'iifname &#34;eth2.50&#34; udp dport 67 accept comment &#34;sitea-dns-dhcp&#34;' in updated_firewall.text

    apply_page = client.get("/appliance-apply")
    assert apply_page.status_code == 200
    review = client.get("/appliance-apply/review")
    units = {unit["id"]: unit for unit in review.json()["units"]}
    assert units["dnsmasq"]["label"] == "DNS/DHCP (dnsmasq)"
    assert units["firewall"]["label"] == "Firewall"
    assert "eth2.50" in units["firewall"]["config_preview"]


def test_firewall_page_create_rule_and_apply_task(client):
    """Verify that firewall page create rule and apply task.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    with SessionLocal() as db:
        units = ui.appliance_apply_units(db)
        ui.update_appliance_apply_baselines(db, units, {unit["id"] for unit in units})
        db.commit()

    login(client)
    page = client.get("/firewall")
    assert page.status_code == 200
    assert "Firewall Rules" in page.text
    assert "firewall-rules-table" in page.text
    assert "Review appliance changes" in page.text
    assert "nftables" in page.text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    rejected = client.post(
        "/firewall/rules",
        data={
            "name": "raw-source-rejected",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "192.168.50.0/24",
            "destination": "any",
            "destination_port": "443",
            "interface_name": "eth2",
            "priority": "29",
            "enabled": "on",
            "description": "raw source should not save",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert rejected.status_code == 422
    assert "Source must use Any or a Source Group." in rejected.text

    group_response = client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "create",
            "group_name": "VCenter clients",
            "group_entries": "192.168.50.0/24",
        },
    )
    assert group_response.status_code == 200

    created = client.post(
        "/firewall/rules",
        data={
            "name": "allow-vcenter",
            "direction": "input",
            "action": "accept",
            "protocol": "tcp",
            "source": "group:custom:vcenter-clients",
            "destination": "any",
            "destination_port": "443",
            "interface_name": "eth2",
            "priority": "30",
            "enabled": "on",
            "description": "VCF management access",
            "csrf": csrf,
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    assert "allow-vcenter" in client.get("/firewall").text

    apply_response = client.post("/appliance-apply", data={"csrf": csrf, "selected_units": "firewall"})
    assert_apply_redirect(apply_response)
    with SessionLocal() as db:
        job = db.execute(select(Job).where(Job.type == "appliance-apply")).scalar_one()
        assert "atlaso-helper firewall apply" in (job.result or "")
        assert "allow-vcenter" in (job.result or "")


def test_firewall_settings_autosave_updates_desired_state_preview(client):
    """Verify that firewall settings autosave updates desired state preview.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    login(client)
    page = client.get("/firewall")
    assert page.status_code == 200
    assert "data-firewall-enabled-status" in page.text
    assert "issue-287-1" in page.text
    monaco = client.get("/static/vendor/monaco/atlaso-monaco.min.js")
    assert monaco.status_code == 200
    assert "AtlasoMonaco" in monaco.text
    assert "initializeSwitchFields" in client.get("/static/app.js").text
    csrf = page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]

    disabled = client.post(
        "/firewall/settings",
        data={
            "csrf": csrf,
            "default_input_policy": "drop",
            "default_forward_policy": "drop",
            "default_output_policy": "accept",
            "allow_established": "on",
            "allow_loopback": "on",
            "allow_icmp": "on",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert disabled.status_code == 200
    disabled_payload = disabled.json()
    assert disabled_payload["enabled"] is False
    assert disabled_payload["valid"] is True
    assert "Atlaso firewall desired state is disabled" in disabled_payload["config_preview"]
    assert "table inet atlaso" not in disabled_payload["config_preview"]

    enabled = client.post(
        "/firewall/settings",
        data={
            "csrf": csrf,
            "enabled": "on",
            "default_input_policy": "drop",
            "default_forward_policy": "drop",
            "default_output_policy": "accept",
            "allow_established": "on",
            "allow_loopback": "on",
            "allow_icmp": "on",
        },
        headers={"X-Atlaso-Autosave": "1"},
    )
    assert enabled.status_code == 200
    enabled_payload = enabled.json()
    assert enabled_payload["enabled"] is True
    assert enabled_payload["settings"]["enabled"] is True
    assert "table inet atlaso" in enabled_payload["config_preview"]
    assert 'comment "mgmt-console"' in enabled_payload["config_preview"]
    assert 'tcp ip saddr' not in enabled_payload["config_preview"]
    assert 'tcp dport { 22, 80, 443 } accept comment "mgmt-console"' in enabled_payload["config_preview"]
