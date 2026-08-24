"""Test Network Objects management UI transport behavior."""

import html
import json
import re

from tests.routers.ui.helpers import login


def _csrf(page) -> str:
    """Return the first CSRF token from one rendered management page."""
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def _create_group(client, csrf: str, name: str, entries: str = "any"):
    """Create one Source Group through the canonical grid transport."""
    return client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "create",
            "group_name": name,
            "group_entries": entries,
            "description": f"{name} description",
        },
        headers={"X-Atlaso-Grid": "1"},
    )


def test_network_objects_page_uses_canonical_grid_wizard_and_safe_return_tokens(client):
    """Render Source Groups as the canonical wizard-backed collection."""
    login(client)

    page = client.get("/network-objects?return_to=firewall-rule")
    assert page.status_code == 200
    assert "Network Objects" in page.text
    assert "Source Groups" in page.text
    assert "network-object-source-groups-table" in page.text
    assert "data-atlaso-wizard" in page.text
    assert "data-network-objects-return=\"firewall-rule\"" in page.text
    assert "restore_source_group_draft=firewall-rule" in page.text
    assert "Any" in page.text
    assert "+ Add Source Group here" in page.text

    rejected_return = client.get("/network-objects?return_to=https://example.invalid")
    assert rejected_return.status_code == 200
    assert "example.invalid" not in rejected_return.text
    assert "data-network-objects-return" not in rejected_return.text


def test_network_objects_create_update_preserves_identifier_and_shared_apply_semantics(client):
    """Keep stable IDs and the existing Firewall/WAN render behavior after edits."""
    login(client)
    page = client.get("/network-objects")
    csrf = _csrf(page)

    created = _create_group(client, csrf, "Application clients", "192.0.2.0/24")
    assert created.status_code == 201
    source_group = created.json()["source_group"]
    assert source_group["id"] == "custom:application-clients"
    assert source_group["entries"] == ["192.0.2.0/24"]

    updated = client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": source_group["id"],
            "group_name": "Application networks",
            "group_entries": "192.0.2.0/24\n2001:db8:1::/64",
            "description": "Application ingress networks",
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert updated.status_code == 200
    assert updated.json()["source_group"]["id"] == source_group["id"]
    assert updated.json()["source_group"]["name"] == "Application networks"

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import FirewallRule, NatRule

    with SessionLocal() as db:
        db.add(
            FirewallRule(
                name="application-ingress",
                source=f"group:{source_group['id']}",
                destination="any",
                interface_name="eth2",
            )
        )
        db.add(
            NatRule(
                name="application-egress",
                source=f"group:{source_group['id']}",
                outbound_interface="eth1",
            )
        )
        db.commit()

    firewall = client.get("/firewall")
    routes_wan = client.get("/routes-wan")
    assert "Application networks" in firewall.text
    assert "Application networks" in routes_wan.text
    assert f'<option value="{source_group["id"]}">Application networks</option>' in firewall.text
    assert "ip saddr 192.0.2.0/24" in html.unescape(firewall.text)
    assert "source_resolved=192.0.2.0/24" in html.unescape(routes_wan.text)


def test_network_objects_delete_conflict_lists_every_consumer_and_rechecks_on_post(client):
    """Block deletion for nested, operator, managed, and NAT consumers."""
    login(client)
    page = client.get("/network-objects")
    csrf = _csrf(page)
    protected = _create_group(client, csrf, "Protected clients", "198.51.100.0/24")
    assert protected.status_code == 201
    group_id = protected.json()["source_group"]["id"]
    nested = _create_group(client, csrf, "Nested clients", f"group:{group_id}")
    assert nested.status_code == 201

    import atlaso.app.ui as ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import FirewallRule, NatRule

    with SessionLocal() as db:
        db.add(FirewallRule(name="protected-firewall", source=group_id, destination=group_id))
        db.add(NatRule(name="protected-nat", source=f"group:{group_id}", outbound_interface="eth1"))
        state = ui.firewall_source_group_state_for_db(db)
        state["assignments"]["mgmt-console"] = group_id
        ui.persist_firewall_source_group_state(db, state)
        db.commit()

    response = client.post(
        "/network-objects/source-groups",
        data={"csrf": csrf, "action": "delete", "group_id": group_id},
        headers={"X-Atlaso-Grid": "1"},
    )
    assert response.status_code == 409
    payload = response.json()
    assert payload["detail"] == "Source Group is in use and cannot be removed."
    kinds = [consumer["kind"] for consumer in payload["consumers"]]
    assert kinds.count("nested_group") == 1
    assert kinds.count("firewall_rule") == 2
    assert kinds.count("managed_rule") == 1
    assert kinds.count("nat_rule") == 1
    labels = " ".join(consumer["label"] for consumer in payload["consumers"])
    assert "Nested clients" in labels
    assert "protected-firewall" in labels
    assert "mgmt-console" in labels
    assert "protected-nat" in labels

    refreshed = client.get("/network-objects")
    match = re.search(
        r'id="network-object-source-groups-table"[^>]+data-source-groups=\'([^\']*)\'',
        refreshed.text,
        re.S,
    )
    assert match is not None
    rows = json.loads(html.unescape(match.group(1)))
    protected_row = next(row for row in rows if row["id"] == group_id)
    assert protected_row["consumer_count"] == 5
    assert len(protected_row["consumers"]) == 5


def test_network_objects_unreferenced_delete_and_legacy_routes_are_non_replaying(client):
    """Delete unused groups and retain safe legacy bookmark/form compatibility."""
    unauthorized = client.get("/ui/management/firewall/source-groups", follow_redirects=False)
    assert unauthorized.status_code == 303
    assert unauthorized.headers["location"].startswith("/ui/management/login?")

    login(client)
    page = client.get("/network-objects")
    csrf = _csrf(page)
    created = _create_group(client, csrf, "Temporary clients", "203.0.113.0/24")
    group_id = created.json()["source_group"]["id"]

    legacy_alias = client.get("/firewall/source-groups", follow_redirects=False)
    assert legacy_alias.status_code == 307
    assert legacy_alias.headers["location"] == "/ui/management/firewall/source-groups"
    legacy_get = client.get("/ui/management/firewall/source-groups", follow_redirects=False)
    assert legacy_get.status_code == 308
    assert legacy_get.headers["location"] == "/ui/management/network-objects"
    legacy_head = client.head("/ui/management/firewall/source-groups", follow_redirects=False)
    assert legacy_head.status_code == 308

    legacy_post = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": group_id,
            "group_name": "Temporary networks",
            "group_entries": "203.0.113.0/24",
        },
        follow_redirects=False,
    )
    assert legacy_post.status_code == 303
    assert legacy_post.headers["location"] == "/ui/management/network-objects"

    deleted = client.post(
        "/network-objects/source-groups",
        data={"csrf": csrf, "action": "delete", "group_id": group_id},
        headers={"X-Atlaso-Grid": "1"},
    )
    assert deleted.status_code == 200
    assert all(row["id"] != group_id for row in deleted.json()["source_groups"])


def test_network_objects_reuses_firewall_authorization_scopes():
    """Preserve the established read/write Firewall access behavior."""
    from atlaso.app.security import UI_PATH_SCOPES

    assert ("/network-objects", "read:firewall", "write:firewall") in UI_PATH_SCOPES
