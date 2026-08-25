"""Test Network Objects management UI transport behavior."""

import html
import json
import re
import threading

import pytest

from tests.routers.ui.helpers import login


def _csrf(page) -> str:
    """Return the first CSRF token from one rendered management page.

    Args:
        page: Rendered management response containing a CSRF field.

    Returns:
        Extracted CSRF token.
    """
    return page.text.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def _create_group(client, csrf: str, name: str, entries: str = "any"):
    """Create one Source Group through the canonical grid transport.

    Args:
        client: HTTP test client used to exercise the application.
        csrf: Valid CSRF token for the authenticated session.
        name: Display name for the new Source Group.
        entries: Serialized Source Group entries.

    Returns:
        HTTP response from the Source Group mutation.
    """
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
    """Render Source Groups as the canonical wizard-backed collection.

    Args:
        client: HTTP test client used to exercise the application.
    """
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
    assert "data-network-object-any-source" in page.text
    assert 'data-network-object-any-source-field hidden' in page.text
    assert "data-network-object-source-group-tag-editor" in page.text
    assert "data-tag-editable" in page.text
    assert "data-network-object-entry-validation-summary" in page.text
    assert 'id="network-object-source-groups-fallback-shell"' in page.text
    app_css = client.get("/static/app.css").text
    assert ".network-objects-panel" in app_css
    assert "height: calc(100vh - 120px)" in app_css
    assert ".network-objects-fallback-shell" in app_css
    assert ".network-objects-panel > .error-list" in app_css
    assert "overflow-y: auto" in app_css

    rejected_return = client.get("/network-objects?return_to=https://example.invalid")
    assert rejected_return.status_code == 200
    assert "example.invalid" not in rejected_return.text
    assert "data-network-objects-return" not in rejected_return.text


def test_network_objects_entry_validation_is_authoritative_and_canonical(client):
    """Classify every tag with server-owned Source Group validation rules.

    Args:
        client: HTTP test client used to exercise the application.
    """
    login(client)
    page = client.get("/network-objects")
    csrf = _csrf(page)
    referenced = _create_group(client, csrf, "Application clients", "192.0.2.0/24")
    assert referenced.status_code == 201
    referenced_id = referenced.json()["source_group"]["id"]

    response = client.post(
        "/network-objects/source-groups/validate-entries",
        data={
            "csrf": csrf,
            "group_name": "Validated clients",
            "group_entries": [
                "192.0.2.42",
                "192.0.2.42/24",
                "2001:db8::42",
                "2001:db8::42/64",
                f"group:{referenced_id}",
                "192.0.2.0/24",
                "not-an-address",
            ],
        },
        headers={"X-Atlaso-Grid": "1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["valid"] is False
    assert [entry["kind"] for entry in payload["entries"][:5]] == [
        "ipv4-address",
        "ipv4-cidr",
        "ipv6-address",
        "ipv6-cidr",
        "source-group",
    ]
    assert payload["entries"][1]["state"] == "needs_attention"
    assert payload["entries"][1]["canonical"] == "192.0.2.0/24"
    assert payload["entries"][3]["canonical"] == "2001:db8::/64"
    assert payload["entries"][5]["state"] == "needs_attention"
    assert "Duplicate" in payload["entries"][5]["message"]
    assert payload["entries"][6]["state"] == "invalid"

    reserved = client.post(
        "/network-objects/source-groups/validate-entries",
        data={"csrf": csrf, "group_name": "Reserved", "group_entries": "any"},
    )
    assert reserved.status_code == 200
    assert reserved.json()["entries"][0]["state"] == "invalid"
    assert "Any source switch" in reserved.json()["entries"][0]["message"]

    switched_any = client.post(
        "/network-objects/source-groups/validate-entries",
        data={
            "csrf": csrf,
            "group_name": "Application clients",
            "group_entries": "any",
            "any_source": "1",
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    assert switched_any.status_code == 200
    assert switched_any.json()["entries"] == [
        {
            "state": "valid",
            "canonical": "any",
            "kind": "reserved",
            "message": "Any source is selected.",
        }
    ]
    assert switched_any.json()["valid"] is False
    assert switched_any.json()["errors"] == [
        "Source Group name 'Application clients' is already used."
    ]


def test_network_objects_create_update_preserves_identifier_and_shared_apply_semantics(client):
    """Keep stable IDs and the existing Firewall/WAN render behavior after edits.

    Args:
        client: HTTP test client used to exercise the application.
    """
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


def test_network_objects_validation_returns_actionable_wizard_detail(client):
    """Expose Source Group validation text through the shared wizard error field.

    Args:
        client: HTTP test client used to exercise the application.
    """
    login(client)
    csrf = _csrf(client.get("/network-objects"))

    response = _create_group(client, csrf, "Broken nesting", "group:custom:missing")

    assert response.status_code == 422
    payload = response.json()
    assert payload["detail"] == " ".join(payload["errors"])
    assert "missing" in payload["detail"].lower()


def test_network_objects_rejects_updates_that_invalidate_nat_consumers(client):
    """Keep a shared Source Group valid for every referencing NAT rule.

    Args:
        client: HTTP test client used to exercise the application.
    """
    login(client)
    csrf = _csrf(client.get("/network-objects"))
    created = _create_group(client, csrf, "NAT clients", "192.0.2.0/24").json()["source_group"]

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NatRule, Setting
    from atlaso.app.services.firewall import FIREWALL_SOURCE_GROUPS_SETTING_KEY

    with SessionLocal() as db:
        db.add(
            NatRule(
                name="nat-clients-egress",
                source=f"group:{created['id']}",
                outbound_interface="eth1",
                enabled=True,
            )
        )
        db.commit()

    validation = client.post(
        "/network-objects/source-groups/validate-entries",
        data={
            "csrf": csrf,
            "group_id": created["id"],
            "group_name": created["name"],
            "group_entries": "2001:db8::/64",
        },
        headers={"X-Atlaso-Grid": "1"},
    )

    assert validation.status_code == 200
    assert validation.json()["valid"] is False
    assert "NAT rule nat-clients-egress" in validation.json()["errors"][0]
    assert "IPv4" in validation.json()["errors"][0]

    response = client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": created["id"],
            "group_name": created["name"],
            "group_entries": "2001:db8::/64",
            "description": created["description"],
        },
        headers={"X-Atlaso-Grid": "1"},
    )

    assert response.status_code == 422
    assert "NAT rule nat-clients-egress" in response.json()["detail"]
    assert "IPv4" in response.json()["detail"]
    with SessionLocal() as db:
        setting = db.execute(
            select(Setting).where(Setting.key == FIREWALL_SOURCE_GROUPS_SETTING_KEY)
        ).scalar_one()
        groups = json.loads(setting.value)["groups"]
        persisted = next(group for group in groups if group["id"] == created["id"])
        assert persisted["entries"] == ["192.0.2.0/24"]


def test_network_objects_mutations_return_refreshed_consumer_rows(client):
    """Return every row whose nested-group usage changed after a mutation.

    Args:
        client: HTTP test client used to exercise the application.
    """
    login(client)
    csrf = _csrf(client.get("/network-objects"))
    parent = _create_group(client, csrf, "Parent clients", "192.0.2.0/24").json()["source_group"]

    nested_response = _create_group(client, csrf, "Nested clients", f"group:{parent['id']}")
    parent_row = next(row for row in nested_response.json()["source_groups"] if row["id"] == parent["id"])
    nested = nested_response.json()["source_group"]
    assert parent_row["consumer_count"] == 1

    updated = client.post(
        "/network-objects/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": nested["id"],
            "group_name": nested["name"],
            "group_entries": "198.51.100.0/24",
            "description": nested["description"],
        },
        headers={"X-Atlaso-Grid": "1"},
    )
    parent_row = next(row for row in updated.json()["source_groups"] if row["id"] == parent["id"])
    assert parent_row["consumer_count"] == 0


def test_network_objects_validation_is_attributed_to_exact_group_names():
    """Avoid marking a valid row from a longer group's matching name prefix."""
    from atlaso.app.services.network_objects import source_group_rows

    groups = [
        {"id": "custom:app", "name": "App", "entries": ["192.0.2.0/24"]},
        {"id": "custom:app-prod", "name": "App Prod", "entries": ["not-a-cidr"]},
    ]

    rows = source_group_rows(groups, {}, [], [])
    app = next(row for row in rows if row["id"] == "custom:app")
    app_prod = next(row for row in rows if row["id"] == "custom:app-prod")

    assert app["validation_state"] == "valid"
    assert app["validation_errors"] == []
    assert app_prod["validation_state"] == "needs attention"
    assert app_prod["validation_errors"] == [
        "App Prod must be 'any' or valid IPv4/IPv6 addresses or CIDRs."
    ]


def test_network_objects_page_reports_existing_nat_consumer_validation(client):
    """Show legacy NAT incompatibility in both page and exact Source Group row.

    Args:
        client: HTTP test client used to exercise the application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import NatRule, Setting
    from atlaso.app.services.firewall import FIREWALL_SOURCE_GROUPS_SETTING_KEY

    with SessionLocal() as db:
        db.merge(
            Setting(
                key=FIREWALL_SOURCE_GROUPS_SETTING_KEY,
                value=json.dumps(
                    {
                        "groups": [
                            {
                                "id": "custom:legacy-ipv6",
                                "name": "Legacy IPv6",
                                "entries": ["2001:db8::/64"],
                            }
                        ],
                        "assignments": {},
                    }
                ),
            )
        )
        db.add(
            NatRule(
                name="legacy-ipv6-egress",
                source="group:custom:legacy-ipv6",
                outbound_interface="eth1",
                enabled=True,
            )
        )
        db.commit()

    login(client)
    page = client.get("/network-objects")

    assert page.status_code == 200
    assert "needs attention" in page.text
    assert 'aria-label="Network Object validation errors"' in page.text
    match = re.search(
        r'id="network-object-source-groups-table"[^>]+data-source-groups=\'([^\']*)\'',
        page.text,
        re.S,
    )
    assert match is not None
    rows = json.loads(html.unescape(match.group(1)))
    legacy = next(row for row in rows if row["id"] == "custom:legacy-ipv6")
    assert legacy["validation_state"] == "needs attention"
    assert legacy["validation_errors"] == [
        "NAT rule legacy-ipv6-egress: NAT v1 supports IPv4 source CIDRs only."
    ]


def test_network_objects_page_reports_orphaned_rule_references(client):
    """Expose missing Source Groups even when no collection row can own the error.

    Args:
        client: HTTP test client used to exercise the application.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import FirewallRule, NatRule

    with SessionLocal() as db:
        db.add(
            FirewallRule(
                name="orphaned-firewall-source",
                source="group:custom:removed",
                destination="any",
            )
        )
        db.add(
            NatRule(
                name="orphaned-nat-source",
                source="group:custom:removed",
                outbound_interface="eth1",
                enabled=True,
            )
        )
        db.commit()

    login(client)
    page = client.get("/network-objects")

    assert page.status_code == 200
    assert "needs attention" in page.text
    assert "Firewall rule orphaned-firewall-source: Source references a Source Group" in page.text
    assert "NAT rule orphaned-nat-source: NAT source references a Source Group" in page.text


def test_network_objects_delete_conflict_lists_every_consumer_and_rechecks_on_post(client):
    """Block deletion for nested, operator, managed, and NAT consumers.

    Args:
        client: HTTP test client used to exercise the application.
    """
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
    """Delete unused groups and retain safe legacy bookmark/form compatibility.

    Args:
        client: HTTP test client used to exercise the application.
    """
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

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import FirewallSettings

    with SessionLocal() as db:
        settings = db.query(FirewallSettings).first()
        assert settings is not None
        settings.default_input_policy = "invalid"
        db.commit()

    legacy_autosave = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "update",
            "group_id": group_id,
            "group_name": "Autosaved temporary networks",
            "group_entries": "203.0.113.0/24",
        },
        headers={"X-Atlaso-Autosave": "1"},
        follow_redirects=False,
    )
    assert legacy_autosave.status_code == 200
    assert legacy_autosave.headers["content-type"].startswith("application/json")
    legacy_payload = legacy_autosave.json()
    assert legacy_payload["valid"] is False
    assert "Default input policy must be accept or drop." in legacy_payload["validation_errors"]
    assert legacy_payload["config_path"] == "/etc/atlaso/nftables.d/atlaso.nft"
    assert "table inet atlaso" in legacy_payload["config_preview"]

    refreshed_after_autosave = client.get("/network-objects")
    match = re.search(
        r'id="network-object-source-groups-table"[^>]+data-source-groups=\'([^\']*)\'',
        refreshed_after_autosave.text,
        re.S,
    )
    assert match is not None
    autosaved_rows = json.loads(html.unescape(match.group(1)))
    autosaved = next(row for row in autosaved_rows if row["id"] == group_id)
    assert autosaved["name"] == "Autosaved temporary networks"
    assert autosaved["description"] == "Temporary clients description"

    legacy_rename = client.post(
        "/firewall/source-groups",
        data={
            "csrf": csrf,
            "action": "rename",
            "group_id": group_id,
            "group_name": "Renamed temporary networks",
        },
        follow_redirects=False,
    )
    assert legacy_rename.status_code == 303
    renamed_page = client.get("/network-objects")
    match = re.search(
        r'id="network-object-source-groups-table"[^>]+data-source-groups=\'([^\']*)\'',
        renamed_page.text,
        re.S,
    )
    assert match is not None
    renamed_rows = json.loads(html.unescape(match.group(1)))
    renamed = next(row for row in renamed_rows if row["id"] == group_id)
    assert renamed["name"] == "Renamed temporary networks"
    assert renamed["entries"] == ["203.0.113.0/24"]
    assert renamed["description"] == "Temporary clients description"

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


def test_network_objects_read_only_page_keeps_grid_without_wizard(client):
    """Keep the read-only Tabulator host while omitting mutation controls.

    Args:
        client: HTTP test client used to exercise the application.
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
    page = client.get("/network-objects")

    assert page.status_code == 200
    assert 'id="network-object-source-groups-table"' in page.text
    assert 'data-can-write="false"' in page.text
    assert 'id="network-object-source-group-dialog"' not in page.text
    assert "+ Add Source Group here" not in page.text


def test_network_objects_writer_lock_serializes_consumer_mutations():
    """Block a second Source Group consumer transaction until the first completes."""
    from atlaso.app.database import SessionLocal
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock

    started = threading.Event()
    acquired = threading.Event()

    def acquire_second_lock() -> None:
        with SessionLocal() as second:
            started.set()
            acquire_network_objects_write_lock(second)
            acquired.set()
            second.rollback()

    with SessionLocal() as first:
        acquire_network_objects_write_lock(first)
        worker = threading.Thread(target=acquire_second_lock)
        worker.start()
        assert started.wait(1)
        assert not acquired.wait(0.1)
        first.rollback()
        assert acquired.wait(2)
        worker.join(timeout=2)
        assert not worker.is_alive()


def test_network_objects_writer_lock_upgrades_an_existing_sqlite_read_transaction():
    """Acquire SQLite writer serialization after the caller has already queried."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Setting
    from atlaso.app.services.network_objects import acquire_network_objects_write_lock

    with SessionLocal() as db:
        db.execute(select(Setting).limit(1)).first()
        acquire_network_objects_write_lock(db)
        db.rollback()


def test_settings_restore_locks_network_objects_before_archive_validation(monkeypatch):
    """Serialize archive validation and replacement with Source Group writers.

    Args:
        monkeypatch: Pytest fixture used to observe lock and validation ordering.
    """
    import atlaso.app.services.settings_archive as settings_archive
    from atlaso.app.database import SessionLocal

    events: list[str] = []

    def acquire_lock(_db) -> None:
        """Record acquisition of the shared transaction lock.

        Args:
            _db: Database session supplied by the restore service.
        """
        events.append("lock")

    def reject_archive(_archive) -> None:
        """Reject the candidate after recording validation order.

        Args:
            _archive: Candidate archive supplied by the restore service.
        """
        events.append("validate")
        raise ValueError("invalid archive")

    monkeypatch.setattr(settings_archive, "acquire_network_objects_write_lock", acquire_lock)
    monkeypatch.setattr(settings_archive, "_validate_archive", reject_archive)

    with SessionLocal() as db, pytest.raises(ValueError, match="invalid archive"):
        settings_archive.restore_settings_archive(db, {})

    assert events == ["lock", "validate"]
