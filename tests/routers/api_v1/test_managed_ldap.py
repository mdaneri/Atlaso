"""Test Managed LDAP API v1 transports."""

import json

from atlaso.app.models import LdapOrganization, LdapUser
from atlaso.app.services.ldap import mark_ldap_apply_complete


def api_token(client, scopes: list[str]) -> str:
    """Return api token.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
        scopes: Normalized authorization scopes granted or required by the operation.
    """
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "LDAP tests", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_ldap_api_manages_isolated_organizations_users_groups_and_vcf_mapping(client):
    """Verify that ldap api manages isolated organizations users groups and vcf mapping.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token = api_token(client, ["read:ldap", "write:ldap"])
    headers = {"Authorization": f"Bearer {token}"}

    settings = client.get("/api/v1/ldap/settings", headers=headers)
    assert settings.status_code == 200
    assert settings.json()["port"] == 636
    assert settings.json()["ldaps_enabled"] is True
    assert settings.json()["ldap_enabled"] is False
    assert settings.json()["ldap_port"] == 389

    org_a = client.post(
        "/api/v1/ldap/organizations", headers=headers, json={"name": "Org A"}
    )
    org_b = client.post(
        "/api/v1/ldap/organizations", headers=headers, json={"name": "Org B"}
    )
    assert org_a.status_code == 201, org_a.text
    assert org_b.status_code == 201, org_b.text
    assert org_a.json()["suffix_dn"] != org_b.json()["suffix_dn"]
    assert org_a.json()["raw_bind_password"]
    assert org_a.json()["raw_bind_password"] not in json.dumps(
        client.get("/api/v1/ldap/organizations", headers=headers).json()
    )
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal

    with SessionLocal() as db:
        stored = db.execute(
            select(LdapOrganization).where(LdapOrganization.id == org_a.json()["id"])
        ).scalar_one()
        assert stored.bind_password_encrypted
        assert org_a.json()["raw_bind_password"] not in stored.bind_password_encrypted

    user_payload = {
        "uid": "operator",
        "given_name": "VCF",
        "surname": "Operator",
        "display_name": "VCF Operator",
        "email": "operator@example.invalid",
        "enabled": True,
        "password": "VeryStrong1!Directory",
    }
    user_a = client.post(
        f"/api/v1/ldap/organizations/{org_a.json()['id']}/users",
        headers=headers,
        json=user_payload,
    )
    user_b = client.post(
        f"/api/v1/ldap/organizations/{org_b.json()['id']}/users",
        headers=headers,
        json=user_payload,
    )
    assert user_a.status_code == 201, user_a.text
    assert user_b.status_code == 201, user_b.text
    assert user_a.json()["dn"] != user_b.json()["dn"]
    assert user_a.json()["password_status"] == "pending_apply"

    group = client.post(
        f"/api/v1/ldap/organizations/{org_a.json()['id']}/groups",
        headers=headers,
        json={
            "name": "Organization Administrators",
            "description": "VCF organization role import candidate",
            "enabled": True,
            "members": [{"type": "user", "id": user_a.json()["id"]}],
        },
    )
    assert group.status_code == 201, group.text
    assert group.json()["members"][0]["dn"] == user_a.json()["dn"]

    bundle = client.get(
        f"/api/v1/ldap/organizations/{org_a.json()['id']}/vcf-bundle", headers=headers
    )
    assert bundle.status_code == 200
    user_attributes = bundle.json()["vcfAutomation91"]["definedSettings"][
        "userAttributes"
    ]
    assert user_attributes["serviceAccount"] == "employeeType"
    assert "password" not in bundle.json()["vcfAutomation91"]["definedSettings"]

    health = client.get("/api/v1/ldap/health", headers=headers)
    assert health.status_code == 200
    assert health.json()["ldaps_only"] is True
    assert health.json()["ldaps_enabled"] is True
    assert health.json()["ldap_enabled"] is False
    assert health.json()["organization_count"] == 2


def test_ldap_api_rejects_cross_organization_membership_and_nested_cycle(client):
    """Verify that ldap api rejects cross organization membership and nested cycle.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    token = api_token(client, ["read:ldap", "write:ldap"])
    headers = {"Authorization": f"Bearer {token}"}
    org_a = client.post(
        "/api/v1/ldap/organizations", headers=headers, json={"name": "Cycle A"}
    ).json()
    org_b = client.post(
        "/api/v1/ldap/organizations", headers=headers, json={"name": "Cycle B"}
    ).json()
    user_b = client.post(
        f"/api/v1/ldap/organizations/{org_b['id']}/users",
        headers=headers,
        json={"uid": "foreign", "enabled": False},
    ).json()

    cross_org = client.post(
        f"/api/v1/ldap/organizations/{org_a['id']}/groups",
        headers=headers,
        json={
            "name": "Cross Org",
            "enabled": True,
            "members": [{"type": "user", "id": user_b["id"]}],
        },
    )
    assert cross_org.status_code == 400

    leaf = client.post(
        f"/api/v1/ldap/organizations/{org_a['id']}/groups",
        headers=headers,
        json={"name": "Leaf", "enabled": False, "members": []},
    )
    parent = client.post(
        f"/api/v1/ldap/organizations/{org_a['id']}/groups",
        headers=headers,
        json={
            "name": "Parent",
            "enabled": True,
            "members": [{"type": "group", "id": leaf.json()["id"]}],
        },
    )
    assert parent.status_code == 201
    cycle = client.put(
        f"/api/v1/ldap/groups/{leaf.json()['id']}",
        headers=headers,
        json={
            "name": "Leaf",
            "enabled": True,
            "members": [{"type": "group", "id": parent.json()["id"]}],
        },
    )
    assert cycle.status_code == 400
    assert "cycle" in cycle.json()["detail"].lower()


def test_ldap_uid_change_marks_applied_password_not_staged(client):
    """Verify that ldap uid change marks applied password not staged.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal

    token = api_token(client, ["read:ldap", "write:ldap"])
    headers = {"Authorization": f"Bearer {token}"}
    organization = client.post(
        "/api/v1/ldap/organizations", headers=headers, json={"name": "Rename Org"}
    ).json()
    created = client.post(
        f"/api/v1/ldap/organizations/{organization['id']}/users",
        headers=headers,
        json={
            "uid": "before-rename",
            "enabled": True,
            "password": "VeryStrong1!Directory",
        },
    )
    assert created.status_code == 201, created.text

    with SessionLocal() as db:
        user = db.execute(
            select(LdapUser).where(LdapUser.id == created.json()["id"])
        ).scalar_one()
        mark_ldap_apply_complete([user])
        db.commit()

    renamed = client.put(
        f"/api/v1/ldap/users/{created.json()['id']}",
        headers=headers,
        json={"uid": "after-rename", "enabled": True},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["uid"] == "after-rename"
    assert renamed.json()["password_status"] == "not_staged"

    with SessionLocal() as db:
        user = db.execute(
            select(LdapUser).where(LdapUser.id == created.json()["id"])
        ).scalar_one()
        assert user.password_applied_at is None


def test_ldap_api_settings_reject_management_and_accept_addressed_access_interface(
    client,
):
    """Verify that ldap api settings reject management and accept addressed access interface.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        interface.role = "management"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "dhcp"
        interface.ip_cidr = None
        interface.host_ip_cidr = "192.168.167.219/24"
        db.commit()

    token = api_token(client, ["read:ldap", "write:ldap"])
    response = client.patch(
        "/api/v1/ldap/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "enabled": False,
            "hostname": "ldap.atlaso.internal",
            "listen_interfaces": ["eth0"],
            "listen_addresses": [],
            "port": 636,
            "password_policy": {},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["listen_interfaces"] == []
    assert payload["listen_addresses"] == []

    with SessionLocal() as db:
        interface = db.execute(
            select(PhysicalInterface).where(PhysicalInterface.name == "eth0")
        ).scalar_one()
        interface.role = "access"
        db.commit()

    response = client.patch(
        "/api/v1/ldap/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "enabled": False,
            "hostname": "ldap.atlaso.internal",
            "listen_interfaces": ["eth0"],
            "listen_addresses": [],
            "ldaps_enabled": True,
            "port": 1636,
            "ldap_enabled": True,
            "ldap_port": 1389,
            "password_policy": {},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["listen_interfaces"] == ["eth0"]
    assert payload["listen_addresses"] == ["192.168.167.219"]
    assert payload["port"] == 1636
    assert payload["ldap_enabled"] is True
    assert payload["ldap_port"] == 1389


def test_ldap_api_missing_settings_uses_appliance_domain(client):
    """Derive a lazily created LDAP hostname from the canonical appliance FQDN.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
    from sqlalchemy import delete, select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import ApplianceSettings, LdapSettings

    with SessionLocal() as db:
        appliance = db.execute(select(ApplianceSettings)).scalar_one()
        appliance.fqdn = "atlaso.lab.internal"
        db.execute(delete(LdapSettings))
        db.commit()

    token = api_token(client, ["read:ldap", "write:ldap"])
    response = client.patch(
        "/api/v1/ldap/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "enabled": False,
            "listen_interfaces": [],
            "listen_addresses": [],
            "port": 636,
            "password_policy": {},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["hostname"] == "ldap.lab.internal"
