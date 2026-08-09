"""Test ldap behavior."""

import io
import json
import tarfile

from atlaso.app.models import LdapGroup, LdapGroupMembership, LdapOrganization, LdapSettings, LdapUser
from atlaso.app.services.ldap import (
    clear_pending_ldap_password,
    decrypt_recovery_payload,
    encrypt_recovery_payload,
    ldap_apply_payload,
    manual_vcf_bundle,
    validate_group_cycles,
    validate_ldap_state,
    validate_ldap_password,
    validate_ldap_recovery_payload,
    vcf_ldap_settings,
    mark_ldap_apply_complete,
)


def api_token(client, scopes: list[str]) -> str:
    """Return api token."""
    response = client.post(
        "/api/v1/auth/login?username=admin&password=atlaso-admin",
        json={"name": "LDAP tests", "scopes": scopes},
    )
    assert response.status_code == 200, response.text
    return response.json()["raw_token"]


def test_ldap_api_manages_isolated_organizations_users_groups_and_vcf_mapping(client):
    """Verify that ldap api manages isolated organizations users groups and vcf mapping."""
    token = api_token(client, ["read:ldap", "write:ldap"])
    headers = {"Authorization": f"Bearer {token}"}

    settings = client.get("/api/v1/ldap/settings", headers=headers)
    assert settings.status_code == 200
    assert settings.json()["port"] == 636
    assert settings.json()["ldaps_enabled"] is True
    assert settings.json()["ldap_enabled"] is False
    assert settings.json()["ldap_port"] == 389

    org_a = client.post("/api/v1/ldap/organizations", headers=headers, json={"name": "Org A"})
    org_b = client.post("/api/v1/ldap/organizations", headers=headers, json={"name": "Org B"})
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
        stored = db.execute(select(LdapOrganization).where(LdapOrganization.id == org_a.json()["id"])).scalar_one()
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
    user_a = client.post(f"/api/v1/ldap/organizations/{org_a.json()['id']}/users", headers=headers, json=user_payload)
    user_b = client.post(f"/api/v1/ldap/organizations/{org_b.json()['id']}/users", headers=headers, json=user_payload)
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

    bundle = client.get(f"/api/v1/ldap/organizations/{org_a.json()['id']}/vcf-bundle", headers=headers)
    assert bundle.status_code == 200
    user_attributes = bundle.json()["vcfAutomation91"]["definedSettings"]["userAttributes"]
    assert user_attributes["serviceAccount"] == "employeeType"
    assert "password" not in bundle.json()["vcfAutomation91"]["definedSettings"]

    health = client.get("/api/v1/ldap/health", headers=headers)
    assert health.status_code == 200
    assert health.json()["ldaps_only"] is True
    assert health.json()["ldaps_enabled"] is True
    assert health.json()["ldap_enabled"] is False
    assert health.json()["organization_count"] == 2


def test_ldap_api_rejects_cross_organization_membership_and_nested_cycle(client):
    """Verify that ldap api rejects cross organization membership and nested cycle."""
    token = api_token(client, ["read:ldap", "write:ldap"])
    headers = {"Authorization": f"Bearer {token}"}
    org_a = client.post("/api/v1/ldap/organizations", headers=headers, json={"name": "Cycle A"}).json()
    org_b = client.post("/api/v1/ldap/organizations", headers=headers, json={"name": "Cycle B"}).json()
    user_b = client.post(
        f"/api/v1/ldap/organizations/{org_b['id']}/users",
        headers=headers,
        json={"uid": "foreign", "enabled": False},
    ).json()

    cross_org = client.post(
        f"/api/v1/ldap/organizations/{org_a['id']}/groups",
        headers=headers,
        json={"name": "Cross Org", "enabled": True, "members": [{"type": "user", "id": user_b["id"]}]},
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
        json={"name": "Parent", "enabled": True, "members": [{"type": "group", "id": leaf.json()["id"]}]},
    )
    assert parent.status_code == 201
    cycle = client.put(
        f"/api/v1/ldap/groups/{leaf.json()['id']}",
        headers=headers,
        json={"name": "Leaf", "enabled": True, "members": [{"type": "group", "id": parent.json()["id"]}]},
    )
    assert cycle.status_code == 400
    assert "cycle" in cycle.json()["detail"].lower()


def test_ldap_uid_change_marks_applied_password_not_staged(client):
    """Verify that ldap uid change marks applied password not staged."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal

    token = api_token(client, ["read:ldap", "write:ldap"])
    headers = {"Authorization": f"Bearer {token}"}
    organization = client.post("/api/v1/ldap/organizations", headers=headers, json={"name": "Rename Org"}).json()
    created = client.post(
        f"/api/v1/ldap/organizations/{organization['id']}/users",
        headers=headers,
        json={"uid": "before-rename", "enabled": True, "password": "VeryStrong1!Directory"},
    )
    assert created.status_code == 201, created.text

    with SessionLocal() as db:
        user = db.execute(select(LdapUser).where(LdapUser.id == created.json()["id"])).scalar_one()
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
        user = db.execute(select(LdapUser).where(LdapUser.id == created.json()["id"])).scalar_one()
        assert user.password_applied_at is None


def test_ldap_password_policy_and_renderer_never_expose_unstaged_hashes():
    """Verify that ldap password policy and renderer never expose unstaged hashes."""
    settings = LdapSettings()
    assert validate_ldap_password("short", "operator", settings)
    assert validate_ldap_password("VeryStrong1!Directory", "operator", settings) == []

    organization = LdapOrganization(
        id=1,
        name="Org A",
        slug="org-a",
        suffix_dn="dc=org-a,dc=ldap,dc=atlaso,dc=internal",
        bind_dn="uid=vcf-bind,ou=service-accounts,dc=org-a,dc=ldap,dc=atlaso,dc=internal",
        bind_password_encrypted="encrypted-value",
    )
    user = LdapUser(
        id=1,
        organization=organization,
        organization_id=1,
        uid="operator",
        surname="Operator",
        display_name="Operator",
        enabled=False,
    )
    organization.users = [user]
    organization.groups = []
    payload = ldap_apply_payload(settings, [organization], include_secrets=False)
    rendered = json.dumps(payload)
    assert "encrypted-value" not in rendered
    assert "userPassword" not in rendered
    assert vcf_ldap_settings(settings, organization, include_password=False)["definedSettings"]["userAttributes"]["serviceAccount"] == "employeeType"

    settings.ldaps_enabled = False
    settings.ldap_enabled = True
    settings.ldap_port = 1389
    plaintext_vcf = vcf_ldap_settings(settings, organization, include_password=False)
    assert plaintext_vcf["definedSettings"]["ssl"] is False
    assert plaintext_vcf["definedSettings"]["port"] == 1389
    bundle = manual_vcf_bundle(settings, organization, root_ca_pem="test-ca")
    assert bundle["endpoint"]["url"] == "ldap://ldap.atlaso.internal:1389"
    assert bundle["endpoint"]["rootCaFilename"] == ""
    assert bundle["rootCaPem"] == ""


def test_ldap_nested_group_cycle_detection():
    """Verify that ldap nested group cycle detection."""
    organization = LdapOrganization(id=1, name="Org", slug="org", suffix_dn="dc=org,dc=example")
    first = LdapGroup(id=1, organization=organization, organization_id=1, name="First")
    second = LdapGroup(id=2, organization=organization, organization_id=1, name="Second")
    first.members = [LdapGroupMembership(group=first, member_group=second, member_group_id=2)]
    second.members = [LdapGroupMembership(group=second, member_group=first, member_group_id=1)]
    assert "cycle" in validate_group_cycles([first, second])[0].lower()


def test_plaintext_only_ldap_does_not_require_ca_but_requires_one_external_protocol():
    """Verify that plaintext only ldap does not require ca but requires one external protocol."""
    settings = LdapSettings(
        enabled=True,
        hostname="ldap.atlaso.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        ldaps_enabled=False,
        port=636,
        ldap_enabled=True,
        ldap_port=389,
        min_password_length=14,
        max_failures=5,
        lockout_minutes=15,
        password_history=5,
        password_max_age_days=0,
    )
    organization = LdapOrganization(
        name="Org A",
        slug="org-a",
        suffix_dn="dc=org-a,dc=ldap,dc=atlaso,dc=internal",
        bind_dn="uid=vcf-bind,ou=service-accounts,dc=org-a,dc=ldap,dc=atlaso,dc=internal",
        bind_password_encrypted="encrypted",
    )
    organization.users = []
    organization.groups = []

    errors, _warnings = validate_ldap_state(
        settings,
        [organization],
        available_interfaces={"eth2"},
        ca_ready=False,
    )

    assert not any("CA" in error for error in errors)
    settings.ldap_enabled = False
    errors, _warnings = validate_ldap_state(
        settings,
        [organization],
        available_interfaces={"eth2"},
        ca_ready=False,
    )
    assert "Enable at least one LDAP or LDAPS listener before enabling the service." in errors


def test_ldap_validation_aggregates_users_with_missing_staged_passwords():
    """Verify that ldap validation aggregates users with missing staged passwords."""
    settings = LdapSettings(
        enabled=False,
        hostname="ldap.atlaso.internal",
        listen_interface="",
        listen_address="",
        ldaps_enabled=True,
        port=636,
        ldap_enabled=False,
        ldap_port=389,
        min_password_length=14,
        max_failures=5,
        lockout_minutes=15,
        password_history=5,
        password_max_age_days=0,
    )
    organization = LdapOrganization(
        id=1,
        name="Synthetic Org",
        slug="synthetic",
        suffix_dn="dc=synthetic,dc=ldap,dc=atlaso,dc=internal",
        bind_dn="uid=vcf-bind,ou=service-accounts,dc=synthetic,dc=ldap,dc=atlaso,dc=internal",
        bind_password_encrypted="encrypted",
    )
    organization.users = [
        LdapUser(id=index, organization_id=1, uid=f"test.user-{index}", enabled=True)
        for index in range(1, 6)
    ]
    organization.groups = []
    for user in organization.users:
        clear_pending_ldap_password(user)

    errors, _warnings = validate_ldap_state(settings, [organization])

    password_errors = [error for error in errors if "staged password" in error]
    assert len(password_errors) == 1
    assert "5 enabled users need staged passwords" in password_errors[0]
    assert "test.user-1, test.user-2, test.user-3, and 2 more" in password_errors[0]
    assert "Recover missing passwords" in password_errors[0]


def test_ldap_recovery_envelope_and_manifest_validation():
    """Verify that ldap recovery envelope and manifest validation."""
    payload_buffer = io.BytesIO()
    with tarfile.open(fileobj=payload_buffer, mode="w:gz") as archive:
        manifest = json.dumps(
            {
                "format": "atlaso-ldap-slapcat-v1",
                "databases": [{"index": 1, "suffix": "dc=org-a,dc=example", "filename": "database-1.ldif"}],
            }
        ).encode()
        manifest_info = tarfile.TarInfo("manifest.json")
        manifest_info.size = len(manifest)
        archive.addfile(manifest_info, io.BytesIO(manifest))
        ldif = b"dn: dc=org-a,dc=example\n"
        ldif_info = tarfile.TarInfo("database-1.ldif")
        ldif_info.size = len(ldif)
        archive.addfile(ldif_info, io.BytesIO(ldif))
    payload = payload_buffer.getvalue()
    assert validate_ldap_recovery_payload(payload)["format"] == "atlaso-ldap-slapcat-v1"

    encrypted = encrypt_recovery_payload(payload, "A sufficiently long recovery passphrase")
    assert payload not in encrypted
    assert decrypt_recovery_payload(encrypted, "A sufficiently long recovery passphrase") == payload


def test_ldap_api_settings_reject_management_and_accept_addressed_access_interface(client):
    """Verify that ldap api settings reject management and accept addressed access interface."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface

    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
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
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
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


def test_ldap_dns_reconciliation_does_not_change_ldap_snapshot_timestamp(client):
    """Verify that ldap dns reconciliation does not change ldap snapshot timestamp."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import LdapSettings, PhysicalInterface
    from atlaso.app.ui import ldap_context

    with SessionLocal() as db:
        interface = db.execute(select(PhysicalInterface).where(PhysicalInterface.name == "eth0")).scalar_one()
        interface.role = "access"
        interface.mode = "access"
        interface.admin_state = "up"
        interface.oper_state = "up"
        interface.ipv4_method = "dhcp"
        interface.ip_cidr = None
        interface.host_ip_cidr = "192.168.167.219/24"
        settings = db.execute(select(LdapSettings)).scalar_one()
        settings.enabled = True
        settings.listen_interface = "eth0"
        settings.listen_address = "192.168.167.219"
        db.commit()

        ldap_context(db, reconcile=True)
        first_updated_at = settings.updated_at
        first_preview = ldap_context(db, reconcile=True)["ldap_apply_config"]
        db.refresh(settings)
        second_updated_at = settings.updated_at
        second_preview = ldap_context(db, reconcile=True)["ldap_apply_config"]

    assert second_updated_at == first_updated_at
    assert second_preview == first_preview
