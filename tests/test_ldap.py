"""Test ldap behavior."""

import io
import json
import tarfile

from atlaso.app.models import (
    LdapGroup,
    LdapGroupMembership,
    LdapOrganization,
    LdapSettings,
    LdapUser,
)
from atlaso.app.services.ldap import (
    clear_pending_ldap_password,
    decrypt_recovery_payload,
    encrypt_recovery_payload,
    ldap_apply_payload,
    manual_vcf_bundle,
    validate_group_cycles,
    validate_ldap_password,
    validate_ldap_recovery_payload,
    validate_ldap_state,
    vcf_ldap_settings,
)


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


def test_ldap_dns_reconciliation_does_not_change_ldap_snapshot_timestamp(client):
    """Verify that ldap dns reconciliation does not change ldap snapshot timestamp.

    Args:
        client: HTTP test client used to exercise the Atlaso application.
    """
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
